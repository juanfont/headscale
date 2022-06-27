//go:build integration
// +build integration

package headscale

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"inet.af/netaddr"
)

const (
	DOCKER_EXECUTE_TIMEOUT = 10 * time.Second
)

var (
	errEnvVarEmpty = errors.New("getenv: environment variable empty")

	IpPrefix4 = netaddr.MustParseIPPrefix("100.64.0.0/10")
	IpPrefix6 = netaddr.MustParseIPPrefix("fd7a:115c:a1e0::/48")

	tailscaleVersions = []string{
		"head",
		"unstable",
		"1.26.0",
		"1.24.2",
		"1.22.2",
		"1.20.4",
		"1.18.2",
		"1.16.2",
		"1.14.3",
		"1.12.3",
	}
)

type TestNamespace struct {
	count      int
	tailscales map[string]dockertest.Resource
}

type ExecuteCommandConfig struct {
	timeout time.Duration
}

type ExecuteCommandOption func(*ExecuteCommandConfig) error

func ExecuteCommandTimeout(timeout time.Duration) ExecuteCommandOption {
	return ExecuteCommandOption(func(conf *ExecuteCommandConfig) error {
		conf.timeout = timeout
		return nil
	})
}

func ExecuteCommand(
	resource *dockertest.Resource,
	cmd []string,
	env []string,
	options ...ExecuteCommandOption,
) (string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	execConfig := ExecuteCommandConfig{
		timeout: DOCKER_EXECUTE_TIMEOUT,
	}

	for _, opt := range options {
		if err := opt(&execConfig); err != nil {
			return "", fmt.Errorf("execute-command/options: %w", err)
		}
	}

	type result struct {
		exitCode int
		err      error
	}

	resultChan := make(chan result, 1)

	// Run your long running function in it's own goroutine and pass back it's
	// response into our channel.
	go func() {
		exitCode, err := resource.Exec(
			cmd,
			dockertest.ExecOptions{
				Env:    append(env, "HEADSCALE_LOG_LEVEL=disabled"),
				StdOut: &stdout,
				StdErr: &stderr,
			},
		)
		resultChan <- result{exitCode, err}
	}()

	// Listen on our channel AND a timeout channel - which ever happens first.
	select {
	case res := <-resultChan:
		if res.err != nil {
			return "", res.err
		}

		if res.exitCode != 0 {
			fmt.Println("Command: ", cmd)
			fmt.Println("stdout: ", stdout.String())
			fmt.Println("stderr: ", stderr.String())

			return "", fmt.Errorf("command failed with: %s", stderr.String())
		}

		return stdout.String(), nil
	case <-time.After(execConfig.timeout):

		return "", fmt.Errorf("command timed out after %s", execConfig.timeout)
	}
}

func DockerRestartPolicy(config *docker.HostConfig) {
	// set AutoRemove to true so that stopped container goes away by itself on error *immediately*.
	// when set to false, containers remain until the end of the integration test.
	config.AutoRemove = false
	config.RestartPolicy = docker.RestartPolicy{
		Name: "no",
	}
}

func DockerAllowLocalIPv6(config *docker.HostConfig) {
	if config.Sysctls == nil {
		config.Sysctls = make(map[string]string, 1)
	}
	config.Sysctls["net.ipv6.conf.all.disable_ipv6"] = "0"
}

func DockerAllowNetworkAdministration(config *docker.HostConfig) {
	config.CapAdd = append(config.CapAdd, "NET_ADMIN")
	config.Mounts = append(config.Mounts, docker.HostMount{
		Type:   "bind",
		Source: "/dev/net/tun",
		Target: "/dev/net/tun",
	})
}

func getDockerBuildOptions(version string) *dockertest.BuildOptions {
	var tailscaleBuildOptions *dockertest.BuildOptions
	switch version {
	case "head":
		tailscaleBuildOptions = &dockertest.BuildOptions{
			Dockerfile: "Dockerfile.tailscale-HEAD",
			ContextDir: ".",
			BuildArgs:  []docker.BuildArg{},
		}
	case "unstable":
		tailscaleBuildOptions = &dockertest.BuildOptions{
			Dockerfile: "Dockerfile.tailscale",
			ContextDir: ".",
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
			ContextDir: ".",
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

func getIPs(
	tailscales map[string]dockertest.Resource,
) (map[string][]netaddr.IP, error) {
	ips := make(map[string][]netaddr.IP)
	for hostname, tailscale := range tailscales {
		command := []string{"tailscale", "ip"}

		result, err := ExecuteCommand(
			&tailscale,
			command,
			[]string{},
		)
		if err != nil {
			return nil, err
		}

		for _, address := range strings.Split(result, "\n") {
			address = strings.TrimSuffix(address, "\n")
			if len(address) < 1 {
				continue
			}
			ip, err := netaddr.ParseIP(address)
			if err != nil {
				return nil, err
			}
			ips[hostname] = append(ips[hostname], ip)
		}
	}

	return ips, nil
}

func getDNSNames(
	headscale *dockertest.Resource,
) ([]string, error) {

	listAllResult, err := ExecuteCommand(
		headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	if err != nil {
		return nil, err
	}

	var listAll []v1.Machine
	err = json.Unmarshal([]byte(listAllResult), &listAll)
	if err != nil {
		return nil, err
	}

	hostnames := make([]string, len(listAll))

	for index := range listAll {
		hostnames[index] = listAll[index].GetGivenName()
	}

	return hostnames, nil
}

func getMagicFQDN(
	headscale *dockertest.Resource,
) ([]string, error) {

	listAllResult, err := ExecuteCommand(
		headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--output",
			"json",
		},
		[]string{},
	)
	if err != nil {
		return nil, err
	}

	var listAll []v1.Machine
	err = json.Unmarshal([]byte(listAllResult), &listAll)
	if err != nil {
		return nil, err
	}

	hostnames := make([]string, len(listAll))

	for index := range listAll {
		hostnames[index] = fmt.Sprintf("%s.%s.headscale.net", listAll[index].GetGivenName(), listAll[index].GetNamespace().GetName())
	}

	return hostnames, nil
}

func GetEnvStr(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return v, errEnvVarEmpty
	}

	return v, nil
}

func GetEnvBool(key string) (bool, error) {
	s, err := GetEnvStr(key)
	if err != nil {
		return false, err
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		return false, err
	}

	return v, nil
}
