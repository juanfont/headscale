package dockertestutil

import "github.com/ory/dockertest/v3"

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
