package tsic

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"

	"github.com/juanfont/headscale"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

const tsicHashLength = 6
const dockerContextPath = "../."

var errTailscalePingFailed = errors.New("ping failed")
var errTailscaleNotLoggedIn = errors.New("tailscale not logged in")

type TailscaleInContainer struct {
	version  string
	Hostname string

	pool      *dockertest.Pool
	container *dockertest.Resource
	network   *dockertest.Network
}

func New(
	pool *dockertest.Pool,
	version string,
	network *dockertest.Network) (*TailscaleInContainer, error) {
	hash, err := headscale.GenerateRandomStringDNSSafe(tsicHashLength)
	if err != nil {
		return nil, err
	}

	hostname := fmt.Sprintf("ts-%s-%s", version, hash)

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
		Hostname: hostname,

		pool:      pool,
		container: container,
		network:   network,
	}, nil
}

func (t *TailscaleInContainer) Shutdown() error {
	return t.pool.Purge(t.container)
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
		t.Hostname,
	}

	log.Println("Join command:", command)
	log.Printf("Running join command for %s\n", t.Hostname)
	stdout, stderr, err := dockertestutil.ExecuteCommand(
		t.container,
		command,
		[]string{},
	)
	if err != nil {
		log.Printf("tailscale join stderr: %s\n", stderr)

		return err
	}
	log.Printf("tailscale join stdout: %s\n", stdout)
	log.Printf("%s joined\n", t.Hostname)

	return nil
}

func (t *TailscaleInContainer) IPs() ([]netip.Addr, error) {
	ips := make([]netip.Addr, 0)

	command := []string{
		"tailscale",
		"ip",
	}

	result, stderr, err := dockertestutil.ExecuteCommand(
		t.container,
		command,
		[]string{},
	)
	if err != nil {
		log.Printf("failed commands stderr: %s\n", stderr)

		if strings.Contains(stderr, "NeedsLogin") {
			return []netip.Addr{}, errTailscaleNotLoggedIn
		}

		return []netip.Addr{}, err
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

func (t *TailscaleInContainer) Ping(ip netip.Addr) error {
	command := []string{
		"tailscale", "ping",
		"--timeout=1s",
		"--c=10",
		"--until-direct=true",
		ip.String(),
	}

	result, _, err := dockertestutil.ExecuteCommand(
		t.container,
		command,
		[]string{},
	)
	if err != nil {
		return err
	}

	if !strings.Contains(result, "pong") || !strings.Contains(result, "is local") {
		return errTailscalePingFailed
	}

	return nil
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
