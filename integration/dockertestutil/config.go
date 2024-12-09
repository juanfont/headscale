package dockertestutil

import (
	"os"

	"github.com/ory/dockertest/v3/docker"
)

func IsRunningInContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err != nil {
		return false
	}

	return true
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
	// Needed since containerd (1.7.24)
	// https://github.com/tailscale/tailscale/issues/14256
	// https://github.com/opencontainers/runc/commit/2ce40b6ad72b4bd4391380cafc5ef1bad1fa0b31
	config.CapAdd = append(config.CapAdd, "NET_ADMIN")
	config.CapAdd = append(config.CapAdd, "NET_RAW")
	config.Devices = append(config.Devices, docker.Device{
		PathOnHost:        "/dev/net/tun",
		PathInContainer:   "/dev/net/tun",
		CgroupPermissions: "rwm",
	})
}
