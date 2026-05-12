package dockertestutil

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
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
		err := op()
		if err != nil {
			return struct{}{}, err
		}

		return struct{}{}, nil
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

		if _, err := pool.CreateNetwork(name, opts...); err == nil { //nolint:noinlineerr // intentional inline check
			// Create does not give us an updated version of the resource, so we need to
			// get it again.
			networks, err := pool.NetworksByName(name)
			if err != nil {
				return nil, err
			}

			return &networks[0], nil
		} else {
			return nil, fmt.Errorf("creating network: %w", err)
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

// DisconnectContainerFromNetwork removes the container from network at
// the docker daemon level. Mirrors a physical cable pull: the
// container's network interface for that network disappears and any
// in-flight TCP connections are left half-open, exactly the failure
// mode iptables-based simulations cannot reproduce.
//
// Returns only after libnetwork's view of the network reflects the
// disconnect (the container's endpoint is gone from network.Containers).
// pool.Client.DisconnectNetwork acknowledges the API call as soon as
// the request is accepted, but bridge reprogramming continues for
// several seconds afterwards; callers that immediately re-attach see
// "network is unreachable" from libnetwork's stale state.
func DisconnectContainerFromNetwork(
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

	if len(containers) == 0 {
		return fmt.Errorf("%w: %s", ErrContainerNotFound, testContainer)
	}

	err = retryDockerOp(context.Background(), func() error {
		return pool.Client.DisconnectNetwork(network.Network.ID, docker.NetworkConnectionOptions{
			Container: containers[0].ID,
		})
	})
	if err != nil {
		return err
	}

	return waitNetworkContainerAbsent(pool, network, testContainer, DockerOpMaxElapsedTime)
}

// ReconnectContainerToNetwork is the inverse of
// DisconnectContainerFromNetwork — re-attaches the container to the
// network so traffic can flow again. Returns only after libnetwork
// has assigned the container a fresh IPv4 address on the bridge; the
// raw ConnectNetwork API call returns before the address is wired up.
func ReconnectContainerToNetwork(
	pool *dockertest.Pool,
	network *dockertest.Network,
	testContainer string,
) error {
	err := AddContainerToNetwork(pool, network, testContainer)
	if err != nil {
		return err
	}

	return waitNetworkContainerPresent(pool, network, testContainer, DockerOpMaxElapsedTime)
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

// waitNetworkContainerAbsent polls libnetwork until the container's
// endpoint no longer appears in network.Containers. Returns nil as
// soon as the absence is observed, or an error if the timeout elapses.
func waitNetworkContainerAbsent(
	pool *dockertest.Pool,
	network *dockertest.Network,
	testContainer string,
	timeout time.Duration,
) error {
	return pollUntil(timeout, func() (bool, error) {
		net, err := pool.Client.NetworkInfo(network.Network.ID)
		if err != nil {
			return false, fmt.Errorf("inspecting network %s: %w", network.Network.Name, err)
		}

		for _, c := range net.Containers {
			if c.Name == testContainer || c.Name == "/"+testContainer {
				return false, nil
			}
		}

		return true, nil
	})
}

// waitNetworkContainerPresent polls libnetwork until the container's
// endpoint appears in network.Containers with a non-empty IPv4 address.
// An entry without an address means libnetwork is still reprogramming.
func waitNetworkContainerPresent(
	pool *dockertest.Pool,
	network *dockertest.Network,
	testContainer string,
	timeout time.Duration,
) error {
	return pollUntil(timeout, func() (bool, error) {
		net, err := pool.Client.NetworkInfo(network.Network.ID)
		if err != nil {
			return false, fmt.Errorf("inspecting network %s: %w", network.Network.Name, err)
		}

		for _, c := range net.Containers {
			if (c.Name == testContainer || c.Name == "/"+testContainer) && c.IPv4Address != "" {
				return true, nil
			}
		}

		return false, nil
	})
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
