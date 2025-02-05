package dockertestutil

import (
	"errors"
	"net"
	"fmt"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

var ErrContainerNotFound = errors.New("container not found")

func GetFirstOrCreateNetwork(pool *dockertest.Pool, name string) (*dockertest.Network, error) {
	networks, err := pool.NetworksByName(name)
	if err != nil {
		return nil, fmt.Errorf("looking up network names: %w", err)
	}
	if len(networks) == 0 {
		if _, err := pool.CreateNetwork(name); err == nil {
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

	err = pool.Client.ConnectNetwork(network.Network.ID, docker.NetworkConnectionOptions{
		Container: containers[0].ID,
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

	return nil
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
