package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
)

// cleanupBeforeTest performs cleanup operations before running tests.
func cleanupBeforeTest(ctx context.Context) error {
	if err := killTestContainers(ctx); err != nil {
		return fmt.Errorf("failed to kill test containers: %w", err)
	}

	if err := pruneDockerNetworks(ctx); err != nil {
		return fmt.Errorf("failed to prune networks: %w", err)
	}

	return nil
}

// cleanupAfterTest removes the test container after completion.
func cleanupAfterTest(ctx context.Context, cli *client.Client, containerID string) error {
	return cli.ContainerRemove(ctx, containerID, container.RemoveOptions{
		Force: true,
	})
}

// killTestContainers terminates all running test containers.
func killTestContainers(ctx context.Context) error {
	cli, err := createDockerClient()
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer cli.Close()

	containers, err := cli.ContainerList(ctx, container.ListOptions{
		All: true,
	})
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	killed := 0
	for _, cont := range containers {
		shouldKill := false
		for _, name := range cont.Names {
			if strings.Contains(name, "headscale-test-suite") ||
				strings.Contains(name, "hs-") ||
				strings.Contains(name, "ts-") {
				shouldKill = true
				break
			}
		}

		if shouldKill {
			if err := cli.ContainerKill(ctx, cont.ID, "KILL"); err == nil {
				killed++
			}
		}
	}

	return nil
}

// pruneDockerNetworks removes unused Docker networks.
func pruneDockerNetworks(ctx context.Context) error {
	cli, err := createDockerClient()
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer cli.Close()

	_, err = cli.NetworksPrune(ctx, filters.Args{})
	if err != nil {
		return fmt.Errorf("failed to prune networks: %w", err)
	}

	return nil
}

// cleanOldImages removes test-related and old dangling Docker images.
func cleanOldImages(ctx context.Context) error {
	cli, err := createDockerClient()
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer cli.Close()

	images, err := cli.ImageList(ctx, image.ListOptions{
		All: true,
	})
	if err != nil {
		return fmt.Errorf("failed to list images: %w", err)
	}

	removed := 0
	for _, img := range images {
		shouldRemove := false
		for _, tag := range img.RepoTags {
			if strings.Contains(tag, "hs-") ||
				strings.Contains(tag, "headscale-integration") ||
				strings.Contains(tag, "tailscale") {
				shouldRemove = true
				break
			}
		}

		if len(img.RepoTags) == 0 && time.Unix(img.Created, 0).Before(time.Now().Add(-7*24*time.Hour)) {
			shouldRemove = true
		}

		if shouldRemove {
			_, err := cli.ImageRemove(ctx, img.ID, image.RemoveOptions{
				Force: true,
			})
			if err == nil {
				removed++
			}
		}
	}

	return nil
}

// cleanCacheVolume removes the Docker volume used for Go module cache.
func cleanCacheVolume(ctx context.Context) error {
	cli, err := createDockerClient()
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer cli.Close()

	volumeName := "hs-integration-go-cache"
	_ = cli.VolumeRemove(ctx, volumeName, true)

	return nil
}
