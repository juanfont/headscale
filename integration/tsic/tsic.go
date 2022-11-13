package tsic

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"

	"github.com/cenkalti/backoff/v4"
	"github.com/juanfont/headscale"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"tailscale.com/ipn/ipnstate"
)

const (
	tsicHashLength    = 6
	dockerContextPath = "../."
)

var (
	errTailscalePingFailed     = errors.New("ping failed")
	errTailscaleNotLoggedIn    = errors.New("tailscale not logged in")
	errTailscaleWrongPeerCount = errors.New("wrong peer count")
	errTailscaleNotConnected   = errors.New("tailscale not connected")
)

type TailscaleInContainer struct {
	version  string
	hostname string

	pool      *dockertest.Pool
	container *dockertest.Resource
	network   *dockertest.Network

	// "cache"
	ips  []netip.Addr
	fqdn string
}

func New(
	pool *dockertest.Pool,
	version string,
	network *dockertest.Network,
) (*TailscaleInContainer, error) {
	hash, err := headscale.GenerateRandomStringDNSSafe(tsicHashLength)
	if err != nil {
		return nil, err
	}

	hostname := fmt.Sprintf("ts-%s-%s", strings.ReplaceAll(version, ".", "-"), hash)

	// TODO(kradalby): figure out why we need to "refresh" the network here.
	// network, err = dockertestutil.GetFirstOrCreateNetwork(pool, network.Network.Name)
	// if err != nil {
	// 	return nil, err
	// }

	tailscaleOptions := &dockertest.RunOptions{
		Name:     hostname,
		Networks: []*dockertest.Network{network},
		Cmd: []string{
			"tailscaled", "--tun=tsdev",
		},
	}

	// dockertest isnt very good at handling containers that has already
	// been created, this is an attempt to make sure this container isnt
	// present.
	err = pool.RemoveContainerByName(hostname)
	if err != nil {
		return nil, err
	}

	container, err := pool.BuildAndRunWithBuildOptions(
		createTailscaleBuildOptions(version),
		tailscaleOptions,
		dockertestutil.DockerRestartPolicy,
		dockertestutil.DockerAllowLocalIPv6,
		dockertestutil.DockerAllowNetworkAdministration,
	)
	if err != nil {
		return nil, fmt.Errorf("could not start tailscale container: %w", err)
	}
	log.Printf("Created %s container\n", hostname)

	return &TailscaleInContainer{
		version:  version,
		hostname: hostname,

		pool:      pool,
		container: container,
		network:   network,
	}, nil
}

func (t *TailscaleInContainer) Shutdown() error {
	return t.pool.Purge(t.container)
}

func (t *TailscaleInContainer) Hostname() string {
	return t.hostname
}

func (t *TailscaleInContainer) Version() string {
	return t.version
}

func (t *TailscaleInContainer) Execute(
	command []string,
) (string, error) {
	log.Println("command", command)
	log.Printf("running command for %s\n", t.hostname)
	stdout, stderr, err := dockertestutil.ExecuteCommand(
		t.container,
		command,
		[]string{},
	)
	if err != nil {
		log.Printf("command stderr: %s\n", stderr)

		if stdout != "" {
			log.Printf("command stdout: %s\n", stdout)
		}

		if strings.Contains(stderr, "NeedsLogin") {
			return "", errTailscaleNotLoggedIn
		}

		return "", err
	}

	return stdout, nil
}

func (t *TailscaleInContainer) Up(
	loginServer, authKey string,
) error {
	command := []string{
		"tailscale",
		"up",
		"-login-server",
		loginServer,
		"--authkey",
		authKey,
		"--hostname",
		t.hostname,
	}

	if _, err := t.Execute(command); err != nil {
		return fmt.Errorf("failed to join tailscale client: %w", err)
	}

	return nil
}

func (t *TailscaleInContainer) IPs() ([]netip.Addr, error) {
	if t.ips != nil && len(t.ips) != 0 {
		return t.ips, nil
	}

	ips := make([]netip.Addr, 0)

	command := []string{
		"tailscale",
		"ip",
	}

	result, err := t.Execute(command)
	if err != nil {
		return []netip.Addr{}, fmt.Errorf("failed to join tailscale client: %w", err)
	}

	for _, address := range strings.Split(result, "\n") {
		address = strings.TrimSuffix(address, "\n")
		if len(address) < 1 {
			continue
		}
		ip, err := netip.ParseAddr(address)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

func (t *TailscaleInContainer) Status() (*ipnstate.Status, error) {
	command := []string{
		"tailscale",
		"status",
		"--json",
	}

	result, err := t.Execute(command)
	if err != nil {
		return nil, fmt.Errorf("failed to execute tailscale status command: %w", err)
	}

	var status ipnstate.Status
	err = json.Unmarshal([]byte(result), &status)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tailscale status: %w", err)
	}

	return &status, err
}

func (t *TailscaleInContainer) FQDN() (string, error) {
	if t.fqdn != "" {
		return t.fqdn, nil
	}

	status, err := t.Status()
	if err != nil {
		return "", fmt.Errorf("failed to get FQDN: %w", err)
	}

	return status.Self.DNSName, nil
}

func (t *TailscaleInContainer) WaitForReady() error {
	return t.pool.Retry(func() error {
		status, err := t.Status()
		if err != nil {
			return fmt.Errorf("failed to fetch tailscale status: %w", err)
		}

		if status.CurrentTailnet != nil {
			return nil
		}

		return errTailscaleNotConnected
	})
}

func (t *TailscaleInContainer) WaitForPeers(expected int) error {
	return t.pool.Retry(func() error {
		status, err := t.Status()
		if err != nil {
			return fmt.Errorf("failed to fetch tailscale status: %w", err)
		}

		if peers := status.Peers(); len(peers) != expected {
			return errTailscaleWrongPeerCount
		}

		return nil
	})
}

// TODO(kradalby): Make multiping, go routine magic.
func (t *TailscaleInContainer) Ping(hostnameOrIP string) error {
	return t.pool.Retry(func() error {
		command := []string{
			"tailscale", "ping",
			"--timeout=1s",
			"--c=10",
			"--until-direct=true",
			hostnameOrIP,
		}

		result, err := t.Execute(command)
		if err != nil {
			log.Printf(
				"failed to run ping command from %s to %s, err: %s",
				t.Hostname(),
				hostnameOrIP,
				err,
			)

			return err
		}

		if !strings.Contains(result, "pong") && !strings.Contains(result, "is local") {
			return backoff.Permanent(errTailscalePingFailed)
		}

		return nil
	})
}

func createTailscaleBuildOptions(version string) *dockertest.BuildOptions {
	var tailscaleBuildOptions *dockertest.BuildOptions
	switch version {
	case "head":
		tailscaleBuildOptions = &dockertest.BuildOptions{
			Dockerfile: "Dockerfile.tailscale-HEAD",
			ContextDir: dockerContextPath,
			BuildArgs:  []docker.BuildArg{},
		}
	case "unstable":
		tailscaleBuildOptions = &dockertest.BuildOptions{
			Dockerfile: "Dockerfile.tailscale",
			ContextDir: dockerContextPath,
			BuildArgs: []docker.BuildArg{
				{
					Name:  "TAILSCALE_VERSION",
					Value: "*", // Installs the latest version https://askubuntu.com/a/824926
				},
				{
					Name:  "TAILSCALE_CHANNEL",
					Value: "unstable",
				},
			},
		}
	default:
		tailscaleBuildOptions = &dockertest.BuildOptions{
			Dockerfile: "Dockerfile.tailscale",
			ContextDir: dockerContextPath,
			BuildArgs: []docker.BuildArg{
				{
					Name:  "TAILSCALE_VERSION",
					Value: version,
				},
				{
					Name:  "TAILSCALE_CHANNEL",
					Value: "stable",
				},
			},
		}
	}

	return tailscaleBuildOptions
}
