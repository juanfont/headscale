//go:build integration
// +build integration

package headscale

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"inet.af/netaddr"
)

const DOCKER_EXECUTE_TIMEOUT = 10 * time.Second

var (
	IpPrefix4 = netaddr.MustParseIPPrefix("100.64.0.0/10")
	IpPrefix6 = netaddr.MustParseIPPrefix("fd7a:115c:a1e0::/48")

	tailscaleVersions = []string{"1.22.0", "1.20.4", "1.18.2", "1.16.2", "1.14.3", "1.12.3"}
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
