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

var ErrContainerNotFound = errors.New("container not found")

// retryDockerOp absorbs eventual-consistency races in libnetwork endpoint cleanup.
func retryDockerOp(ctx context.Context, op func() error) error {
	_, err := backoff.Retry(ctx, func() (struct{}, error) {
		err := op()
		if err != nil {
			return struct{}{}, err
		}

		return struct{}{}, nil
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()), backoff.WithMaxElapsedTime(30*time.Second))

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

	return retryDockerOp(context.Background(), func() error {
		return pool.Client.DisconnectNetwork(network.Network.ID, docker.NetworkConnectionOptions{
			Container: containers[0].ID,
			Force:     true,
		})
	})
}

// ReconnectContainerToNetwork is the inverse of
// DisconnectContainerFromNetwork — re-attaches the container to the
// network so traffic can flow again.
func ReconnectContainerToNetwork(
	pool *dockertest.Pool,
	network *dockertest.Network,
	testContainer string,
) error {
	return AddContainerToNetwork(pool, network, testContainer)
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
