package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
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

// killTestContainers terminates and removes all test containers.
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

	removed := 0
	for _, cont := range containers {
		shouldRemove := false
		for _, name := range cont.Names {
			if strings.Contains(name, "headscale-test-suite") ||
				strings.Contains(name, "hs-") ||
				strings.Contains(name, "ts-") ||
				strings.Contains(name, "derp-") {
				shouldRemove = true
				break
			}
		}

		if shouldRemove {
			// First kill the container if it's running
			if cont.State == "running" {
				_ = cli.ContainerKill(ctx, cont.ID, "KILL")
			}

			// Then remove the container with retry logic
			if removeContainerWithRetry(ctx, cli, cont.ID) {
				removed++
			}
		}
	}

	if removed > 0 {
		fmt.Printf("Removed %d test containers\n", removed)
	} else {
		fmt.Println("No test containers found to remove")
	}

	return nil
}

const (
	containerRemoveInitialInterval = 100 * time.Millisecond
	containerRemoveMaxElapsedTime  = 2 * time.Second
)

// removeContainerWithRetry attempts to remove a container with exponential backoff retry logic.
func removeContainerWithRetry(ctx context.Context, cli *client.Client, containerID string) bool {
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = containerRemoveInitialInterval

	_, err := backoff.Retry(ctx, func() (struct{}, error) {
		err := cli.ContainerRemove(ctx, containerID, container.RemoveOptions{
			Force: true,
		})
		if err != nil {
			return struct{}{}, err
		}

		return struct{}{}, nil
	}, backoff.WithBackOff(expBackoff), backoff.WithMaxElapsedTime(containerRemoveMaxElapsedTime))

	return err == nil
}

// pruneDockerNetworks removes unused Docker networks.
func pruneDockerNetworks(ctx context.Context) error {
	cli, err := createDockerClient()
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer cli.Close()

	report, err := cli.NetworksPrune(ctx, filters.Args{})
	if err != nil {
		return fmt.Errorf("failed to prune networks: %w", err)
	}

	if len(report.NetworksDeleted) > 0 {
		fmt.Printf("Removed %d unused networks\n", len(report.NetworksDeleted))
	} else {
		fmt.Println("No unused networks found to remove")
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

	if removed > 0 {
		fmt.Printf("Removed %d test images\n", removed)
	} else {
		fmt.Println("No test images found to remove")
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
	err = cli.VolumeRemove(ctx, volumeName, true)
	if err != nil {
		if errdefs.IsNotFound(err) {
			fmt.Printf("Go module cache volume not found: %s\n", volumeName)
		} else if errdefs.IsConflict(err) {
			fmt.Printf("Go module cache volume is in use and cannot be removed: %s\n", volumeName)
		} else {
			fmt.Printf("Failed to remove Go module cache volume %s: %v\n", volumeName, err)
		}
	} else {
		fmt.Printf("Removed Go module cache volume: %s\n", volumeName)
	}

	return nil
}

// cleanupSuccessfulTestArtifacts removes artifacts from successful test runs to save disk space.
// This function removes large artifacts that are mainly useful for debugging failures:
// - Database dumps (.db files)
// - Profile data (pprof directories)
// - MapResponse data (mapresponses directories)
// - Prometheus metrics files
//
// It preserves:
// - Log files (.log) which are small and useful for verification.
func cleanupSuccessfulTestArtifacts(logsDir string, verbose bool) error {
	entries, err := os.ReadDir(logsDir)
	if err != nil {
		return fmt.Errorf("failed to read logs directory: %w", err)
	}

	var (
		removedFiles, removedDirs int
		totalSize                 int64
	)

	for _, entry := range entries {
		name := entry.Name()
		fullPath := filepath.Join(logsDir, name)

		if entry.IsDir() {
			// Remove pprof and mapresponses directories (typically large)
			// These directories contain artifacts from all containers in the test run
			if name == "pprof" || name == "mapresponses" {
				size, sizeErr := getDirSize(fullPath)
				if sizeErr == nil {
					totalSize += size
				}

				err := os.RemoveAll(fullPath)
				if err != nil {
					if verbose {
						log.Printf("Warning: failed to remove directory %s: %v", name, err)
					}
				} else {
					removedDirs++

					if verbose {
						log.Printf("Removed directory: %s/", name)
					}
				}
			}
		} else {
			// Only process test-related files (headscale and tailscale)
			if !strings.HasPrefix(name, "hs-") && !strings.HasPrefix(name, "ts-") {
				continue
			}

			// Remove database, metrics, and status files, but keep logs
			shouldRemove := strings.HasSuffix(name, ".db") ||
				strings.HasSuffix(name, "_metrics.txt") ||
				strings.HasSuffix(name, "_status.json")

			if shouldRemove {
				info, infoErr := entry.Info()
				if infoErr == nil {
					totalSize += info.Size()
				}

				err := os.Remove(fullPath)
				if err != nil {
					if verbose {
						log.Printf("Warning: failed to remove file %s: %v", name, err)
					}
				} else {
					removedFiles++

					if verbose {
						log.Printf("Removed file: %s", name)
					}
				}
			}
		}
	}

	if removedFiles > 0 || removedDirs > 0 {
		const bytesPerMB = 1024 * 1024
		log.Printf("Cleaned up %d files and %d directories (freed ~%.2f MB)",
			removedFiles, removedDirs, float64(totalSize)/bytesPerMB)
	}

	return nil
}

// getDirSize calculates the total size of a directory.
func getDirSize(path string) (int64, error) {
	var size int64

	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			size += info.Size()
		}

		return nil
	})

	return size, err
}
