package dockertestutil

import (
	"errors"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

var ErrContainerNotFound = errors.New("container not found")

func GetFirstOrCreateNetwork(pool *dockertest.Pool, name string) (*dockertest.Network, error) {
	networks, err := pool.NetworksByName(name)
	if err != nil || len(networks) == 0 {
		if _, err := pool.CreateNetwork(name); err == nil {
			// Create does not give us an updated version of the resource, so we need to
			// get it again.
			networks, err := pool.NetworksByName(name)
			if err != nil {
				return nil, err
			}

			return &networks[0], nil
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

	// TODO(kradalby): This doesnt work reliably, but calling the exact same functions
	// seem to work fine...
	// if container, ok := pool.ContainerByName("/" + testContainer); ok {
	// 	err := container.ConnectToNetwork(network)
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	return nil
}
