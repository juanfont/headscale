package main

import (
	"log"

	"github.com/juanfont/headscale/integration"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/ory/dockertest/v3"
)

func main() {
	log.Printf("creating docker pool")
	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("could not connect to docker: %s", err)
	}

	log.Printf("creating docker network")
	network, err := pool.CreateNetwork("docker-integration-net")
	if err != nil {
		log.Fatalf("failed to create or get network: %s", err)
	}

	for _, version := range integration.AllVersions {
		log.Printf("creating container image for Tailscale (%s)", version)

		tsClient, err := tsic.New(
			pool,
			version,
			network,
		)
		if err != nil {
			log.Fatalf("failed to create tailscale node: %s", err)
		}

		err = tsClient.Shutdown()
		if err != nil {
			log.Fatalf("failed to shut down container: %s", err)
		}
	}

	network.Close()
	err = pool.RemoveNetwork(network)
	if err != nil {
		log.Fatalf("failed to remove network: %s", err)
	}
}
