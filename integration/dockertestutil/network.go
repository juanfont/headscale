package dockertestutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

var (
	ErrContainerNotFound = errors.New("container not found")
	ErrConditionTimeout  = errors.New("condition not met within timeout")
)

// retryDockerOp absorbs eventual-consistency races in libnetwork endpoint cleanup.
// Pulls its backoff bounds from retry.go so every helper that drives a
// docker control-plane call uses the same budget.
func retryDockerOp(ctx context.Context, op func() error) error {
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = DockerOpInitialInterval
	bo.MaxInterval = DockerOpMaxInterval

	_, err := backoff.Retry(ctx, func() (struct{}, error) {
		return struct{}{}, op()
	}, backoff.WithBackOff(bo), backoff.WithMaxElapsedTime(DockerOpMaxElapsedTime))

	return err
}

func GetFirstOrCreateNetwork(pool *dockertest.Pool, name string) (*dockertest.Network, error) {
	return GetFirstOrCreateNetworkWithSubnet(pool, name, "")
}

// GetFirstOrCreateNetworkWithSubnet creates a Docker network with an optional
// custom subnet. When subnet is empty, Docker auto-assigns from its default
// pool. Use RFC 5737 TEST-NET ranges (e.g. "198.51.100.0/24") for networks
// that need to be reachable through Tailscale exit nodes, since Tailscale's
// shrinkDefaultRoute strips RFC1918 ranges from exit node forwarding filters.
func GetFirstOrCreateNetworkWithSubnet(pool *dockertest.Pool, name, subnet string) (*dockertest.Network, error) {
	networks, err := pool.NetworksByName(name)
	if err != nil {
		return nil, fmt.Errorf("looking up network names: %w", err)
	}

	if len(networks) == 0 {
		var opts []func(*docker.CreateNetworkOptions)
		if subnet != "" {
			opts = append(opts, func(config *docker.CreateNetworkOptions) {
				config.IPAM = &docker.IPAMOptions{
					Config: []docker.IPAMConfig{
						{Subnet: subnet},
					},
				}
			})
		}

		_, err = pool.CreateNetwork(name, opts...)
		if err != nil {
			return nil, fmt.Errorf("creating network: %w", err)
		}

		// Create does not give us an updated version of the resource, so we need to
		// get it again.
		networks, err = pool.NetworksByName(name)
		if err != nil {
			return nil, fmt.Errorf("looking up network names: %w", err)
		}
	}

	return &networks[0], nil
}

func AddContainerToNetwork(
	pool *dockertest.Pool,
	network *dockertest.Network,
	testContainer string,
) error {
	containers, err := pool.Client.ListContainers(docker.ListContainersOptions{
		All: true,
		Filters: map[string][]string{
			"name": {testContainer},
		},
	})
	if err != nil {
		return err
	}

	// TODO(kradalby): This doesn't work reliably, but calling the exact same functions
	// seem to work fine...
	// if container, ok := pool.ContainerByName("/" + testContainer); ok {
	// 	err := container.ConnectToNetwork(network)
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	return retryDockerOp(context.Background(), func() error {
		return pool.Client.ConnectNetwork(network.Network.ID, docker.NetworkConnectionOptions{
			Container: containers[0].ID,
		})
	})
}

// DisconnectContainerFromNetwork detaches the container at the docker
// daemon level (cable-pull semantics) and waits for libnetwork to drop
// the endpoint before returning — re-attaching during the
// reprogramming window otherwise fails with "network is unreachable".
func DisconnectContainerFromNetwork(
	pool *dockertest.Pool,
	network *dockertest.Network,
	testContainer string,
) error {
	containerID, err := lookupContainerID(pool, testContainer)
	if err != nil {
		return err
	}

	err = retryDockerOp(context.Background(), func() error {
		return pool.Client.DisconnectNetwork(network.Network.ID, docker.NetworkConnectionOptions{
			Container: containerID,
		})
	})
	if err != nil {
		return err
	}

	err = waitNetworkContainerAbsent(pool, network, testContainer, DockerOpMaxElapsedTime)
	if err != nil {
		return err
	}

	// libnetwork drops the endpoint from its model before the kernel
	// netns has flushed the matching route. Re-attach with the sticky
	// IP otherwise fails with "conflicts with existing route".
	return waitContainerRouteAbsent(pool, containerID, network, DockerOpMaxElapsedTime)
}

// ReconnectContainerToNetwork is the inverse of
// [DisconnectContainerFromNetwork] — re-attaches the container to the
// network so traffic can flow again.
func ReconnectContainerToNetwork(
	pool *dockertest.Pool,
	network *dockertest.Network,
	testContainer string,
) error {
	containerID, err := lookupContainerID(pool, testContainer)
	if err != nil {
		return err
	}

	err = retryDockerOp(context.Background(), func() error {
		connectErr := pool.Client.ConnectNetwork(network.Network.ID, docker.NetworkConnectionOptions{
			Container: containerID,
		})
		if connectErr != nil && isStaleRouteConflict(connectErr) {
			// Defensive cleanup: a route survived the netns flush
			// despite the wait above. Drop subnet routes that point
			// at the disconnected interface so libnetwork can
			// reprogram the sticky IP, then let the retry budget
			// try the ConnectNetwork call again.
			removeContainerSubnetRoutes(pool, containerID, network)
		}

		return connectErr
	})
	if err != nil {
		return err
	}

	return waitNetworkContainerPresent(pool, network, testContainer, DockerOpMaxElapsedTime)
}

// lookupContainerID resolves a container name to its docker ID.
func lookupContainerID(pool *dockertest.Pool, testContainer string) (string, error) {
	containers, err := pool.Client.ListContainers(docker.ListContainersOptions{
		All:     true,
		Filters: map[string][]string{"name": {testContainer}},
	})
	if err != nil {
		return "", err
	}

	if len(containers) == 0 {
		return "", fmt.Errorf("%w: %s", ErrContainerNotFound, testContainer)
	}

	return containers[0].ID, nil
}

// DisconnectAndReconnect calls Disconnect followed by Reconnect; both
// primitives drive their own libnetwork settle waits.
func DisconnectAndReconnect(
	pool *dockertest.Pool,
	network *dockertest.Network,
	testContainer string,
) error {
	err := DisconnectContainerFromNetwork(pool, network, testContainer)
	if err != nil {
		return fmt.Errorf("disconnecting %s from %s: %w", testContainer, network.Network.Name, err)
	}

	err = ReconnectContainerToNetwork(pool, network, testContainer)
	if err != nil {
		return fmt.Errorf("reconnecting %s to %s: %w", testContainer, network.Network.Name, err)
	}

	return nil
}

func waitNetworkContainer(
	pool *dockertest.Pool,
	network *dockertest.Network,
	testContainer string,
	timeout time.Duration,
	want bool,
	match func(docker.Endpoint) bool,
) error {
	return pollUntil(timeout, func() (bool, error) {
		net, err := pool.Client.NetworkInfo(network.Network.ID)
		if err != nil {
			return false, fmt.Errorf("inspecting network %s: %w", network.Network.Name, err)
		}

		found := false
		for _, c := range net.Containers {
			if (c.Name == testContainer || c.Name == "/"+testContainer) && match(c) {
				found = true
				break
			}
		}

		return found == want, nil
	})
}

func waitNetworkContainerAbsent(
	pool *dockertest.Pool,
	network *dockertest.Network,
	testContainer string,
	timeout time.Duration,
) error {
	return waitNetworkContainer(pool, network, testContainer, timeout, false, func(docker.Endpoint) bool { return true })
}

func waitNetworkContainerPresent(
	pool *dockertest.Pool,
	network *dockertest.Network,
	testContainer string,
	timeout time.Duration,
) error {
	return waitNetworkContainer(pool, network, testContainer, timeout, true, func(c docker.Endpoint) bool { return c.IPv4Address != "" })
}

// waitContainerRouteAbsent polls the container's routing table until no
// route remains for the network's IPAM subnet. libnetwork's docker-side
// endpoint teardown is asynchronous from the kernel netns flush, and a
// surviving route blocks a subsequent reconnect at sticky-IP assignment
// with "conflicts with existing route".
func waitContainerRouteAbsent(pool *dockertest.Pool, containerID string, network *dockertest.Network, timeout time.Duration) error {
	subnets := networkSubnets(network)
	if len(subnets) == 0 {
		return nil
	}

	return pollUntil(timeout, func() (bool, error) {
		stdout, err := execStdout(pool, containerID, []string{"ip", "-4", "route", "show"})
		if err != nil {
			return false, fmt.Errorf("inspecting routes in %s: %w", containerID, err)
		}

		for _, subnet := range subnets {
			if strings.Contains(stdout, subnet+" ") || strings.HasSuffix(strings.TrimSpace(stdout), subnet) {
				return false, nil
			}
		}

		return true, nil
	})
}

// removeContainerSubnetRoutes drops residue subnet routes in the
// container's netns — the leftover that libnetwork's async endpoint
// teardown can leave behind.
func removeContainerSubnetRoutes(pool *dockertest.Pool, containerID string, network *dockertest.Network) {
	for _, subnet := range networkSubnets(network) {
		_, err := execStdout(pool, containerID, []string{"ip", "-4", "route", "del", subnet})
		if err != nil {
			log.Printf("removing stale route %s in %s: %v", subnet, containerID, err)
		}
	}
}

// isStaleRouteConflict matches the libnetwork 500 raised when a
// surviving subnet route blocks sticky-IP reprogramming on reconnect.
func isStaleRouteConflict(err error) bool {
	if err == nil {
		return false
	}

	return strings.Contains(err.Error(), "conflicts with existing route")
}

// networkSubnets returns the IPAM-configured subnets for a docker
// network. Empty when IPAM is left to docker defaults.
func networkSubnets(network *dockertest.Network) []string {
	out := make([]string, 0, len(network.Network.IPAM.Config))
	for _, cfg := range network.Network.IPAM.Config {
		if cfg.Subnet != "" {
			out = append(out, cfg.Subnet)
		}
	}

	return out
}

// execStdout runs a one-shot command in containerID and returns stdout.
func execStdout(pool *dockertest.Pool, containerID string, cmd []string) (string, error) {
	exec, err := pool.Client.CreateExec(docker.CreateExecOptions{
		Container:    containerID,
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return "", fmt.Errorf("create exec: %w", err)
	}

	var stdout, stderr bytes.Buffer

	err = pool.Client.StartExec(exec.ID, docker.StartExecOptions{
		OutputStream: &stdout,
		ErrorStream:  &stderr,
	})
	if err != nil {
		return stdout.String(), fmt.Errorf("start exec: %w", err)
	}

	return stdout.String(), nil
}

// pollUntil ticks every DockerOpInitialInterval until check returns
// done=true or timeout elapses. A non-nil check error aborts the loop.
func pollUntil(timeout time.Duration, check func() (done bool, err error)) error {
	deadline := time.Now().Add(timeout)

	ticker := time.NewTicker(DockerOpInitialInterval)
	defer ticker.Stop()

	for {
		done, err := check()
		if err != nil {
			return err
		}

		if done {
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("%w: %s", ErrConditionTimeout, timeout)
		}

		<-ticker.C
	}
}

// RandomFreeHostPort asks the kernel for a free open port that is ready to use.
// (from https://github.com/phayes/freeport)
func RandomFreeHostPort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	//nolint:forcetypeassert
	return listener.Addr().(*net.TCPAddr).Port, nil
}

// CleanUnreferencedNetworks removes networks that are not referenced by any containers.
func CleanUnreferencedNetworks(pool *dockertest.Pool) error {
	filter := "name=hs-"

	networks, err := pool.NetworksByName(filter)
	if err != nil {
		return fmt.Errorf("getting networks by filter %q: %w", filter, err)
	}

	for _, network := range networks {
		if len(network.Network.Containers) == 0 {
			err := pool.RemoveNetwork(&network)
			if err != nil {
				log.Printf("removing network %s: %s", network.Network.Name, err)
			}
		}
	}

	return nil
}

// CleanImagesInCI removes images if running in CI.
// It only removes dangling (untagged) images to avoid forcing rebuilds.
// Tagged images (golang:*, tailscale/tailscale:*, etc.) are automatically preserved.
func CleanImagesInCI(pool *dockertest.Pool) error {
	if !util.IsCI() {
		log.Println("Skipping image cleanup outside of CI")
		return nil
	}

	images, err := pool.Client.ListImages(docker.ListImagesOptions{})
	if err != nil {
		return fmt.Errorf("getting images: %w", err)
	}

	removedCount := 0

	for _, image := range images {
		// Only remove dangling (untagged) images to avoid forcing rebuilds
		// Dangling images have no RepoTags or only have "<none>:<none>"
		if len(image.RepoTags) == 0 || (len(image.RepoTags) == 1 && image.RepoTags[0] == "<none>:<none>") {
			log.Printf("Removing dangling image: %s", image.ID[:12])

			err := pool.Client.RemoveImage(image.ID)
			if err != nil {
				log.Printf("Warning: failed to remove image %s: %v", image.ID[:12], err)
			} else {
				removedCount++
			}
		}
	}

	if removedCount > 0 {
		log.Printf("Removed %d dangling images in CI", removedCount)
	} else {
		log.Println("No dangling images to remove in CI")
	}

	return nil
}

// DockerRestartPolicy sets the restart policy for containers.
func DockerRestartPolicy(config *docker.HostConfig) {
	config.RestartPolicy = docker.RestartPolicy{
		Name: "unless-stopped",
	}
}

// DockerAllowLocalIPv6 allows IPv6 traffic within the container.
func DockerAllowLocalIPv6(config *docker.HostConfig) {
	config.NetworkMode = "default"
	config.Sysctls = map[string]string{
		"net.ipv6.conf.all.disable_ipv6": "0",
	}
}

// DockerAllowNetworkAdministration gives the container network administration capabilities.
func DockerAllowNetworkAdministration(config *docker.HostConfig) {
	config.CapAdd = append(config.CapAdd, "NET_ADMIN")
	config.Privileged = true
}

// DockerMemoryLimit sets memory limit and disables OOM kill for containers.
func DockerMemoryLimit(config *docker.HostConfig) {
	config.Memory = 2 * 1024 * 1024 * 1024 // 2GB in bytes
	config.OOMKillDisable = true
}
