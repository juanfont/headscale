package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
)

var (
	ErrTestFailed              = errors.New("test failed")
	ErrUnexpectedContainerWait = errors.New("unexpected end of container wait")
	ErrNoDockerContext         = errors.New("no docker context found")
)

// runTestContainer executes integration tests in a Docker container.
func runTestContainer(ctx context.Context, config *RunConfig) error {
	cli, err := createDockerClient()
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer cli.Close()

	runID := generateRunID()
	containerName := "headscale-test-suite-" + runID
	logsDir := filepath.Join(config.LogsDir, runID)

	if config.Verbose {
		log.Printf("Run ID: %s", runID)
		log.Printf("Container name: %s", containerName)
		log.Printf("Logs directory: %s", logsDir)
	}

	absLogsDir, err := filepath.Abs(logsDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for logs directory: %w", err)
	}

	const dirPerm = 0o755
	if err := os.MkdirAll(absLogsDir, dirPerm); err != nil {
		return fmt.Errorf("failed to create logs directory: %w", err)
	}

	if config.CleanBefore {
		if config.Verbose {
			log.Printf("Running pre-test cleanup...")
		}
		if err := cleanupBeforeTest(ctx); err != nil && config.Verbose {
			log.Printf("Warning: pre-test cleanup failed: %v", err)
		}
	}

	goTestCmd := buildGoTestCommand(config)
	if config.Verbose {
		log.Printf("Command: %s", strings.Join(goTestCmd, " "))
	}

	imageName := "golang:" + config.GoVersion
	if err := ensureImageAvailable(ctx, cli, imageName, config.Verbose); err != nil {
		return fmt.Errorf("failed to ensure image availability: %w", err)
	}

	resp, err := createGoTestContainer(ctx, cli, config, containerName, absLogsDir, goTestCmd)
	if err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}

	if config.Verbose {
		log.Printf("Created container: %s", resp.ID)
	}

	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	log.Printf("Starting test: %s", config.TestPattern)

	exitCode, err := streamAndWait(ctx, cli, resp.ID)

	shouldCleanup := config.CleanAfter && (!config.KeepOnFailure || exitCode == 0)
	if shouldCleanup {
		if config.Verbose {
			log.Printf("Running post-test cleanup...")
		}
		if cleanErr := cleanupAfterTest(ctx, cli, resp.ID); cleanErr != nil && config.Verbose {
			log.Printf("Warning: post-test cleanup failed: %v", cleanErr)
		}
	}

	if err != nil {
		return fmt.Errorf("test execution failed: %w", err)
	}

	if exitCode != 0 {
		return fmt.Errorf("%w: exit code %d", ErrTestFailed, exitCode)
	}

	log.Printf("Test completed successfully!")
	listControlFiles(logsDir)

	return nil
}

// buildGoTestCommand constructs the go test command arguments.
func buildGoTestCommand(config *RunConfig) []string {
	cmd := []string{"go", "test", "./..."}

	if config.TestPattern != "" {
		cmd = append(cmd, "-run", config.TestPattern)
	}

	if config.FailFast {
		cmd = append(cmd, "-failfast")
	}

	cmd = append(cmd, "-timeout", config.Timeout.String())
	cmd = append(cmd, "-v")

	return cmd
}

// createGoTestContainer creates a Docker container configured for running integration tests.
func createGoTestContainer(ctx context.Context, cli *client.Client, config *RunConfig, containerName, logsDir string, goTestCmd []string) (container.CreateResponse, error) {
	pwd, err := os.Getwd()
	if err != nil {
		return container.CreateResponse{}, fmt.Errorf("failed to get working directory: %w", err)
	}

	projectRoot := findProjectRoot(pwd)

	env := []string{
		fmt.Sprintf("HEADSCALE_INTEGRATION_POSTGRES=%d", boolToInt(config.UsePostgres)),
	}

	containerConfig := &container.Config{
		Image:      "golang:" + config.GoVersion,
		Cmd:        goTestCmd,
		Env:        env,
		WorkingDir: projectRoot + "/integration",
		Tty:        true,
	}

	hostConfig := &container.HostConfig{
		AutoRemove: false, // We'll remove manually for better control
		Binds: []string{
			fmt.Sprintf("%s:%s", projectRoot, projectRoot),
			"/var/run/docker.sock:/var/run/docker.sock",
			logsDir + ":/tmp/control",
		},
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeVolume,
				Source: "hs-integration-go-cache",
				Target: "/go",
			},
		},
	}

	return cli.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, containerName)
}

// streamAndWait streams container output and waits for completion.
func streamAndWait(ctx context.Context, cli *client.Client, containerID string) (int, error) {
	out, err := cli.ContainerLogs(ctx, containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
	})
	if err != nil {
		return -1, fmt.Errorf("failed to get container logs: %w", err)
	}
	defer out.Close()

	go func() {
		_, _ = io.Copy(os.Stdout, out)
	}()

	statusCh, errCh := cli.ContainerWait(ctx, containerID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return -1, fmt.Errorf("error waiting for container: %w", err)
		}
	case status := <-statusCh:
		return int(status.StatusCode), nil
	}

	return -1, ErrUnexpectedContainerWait
}

// generateRunID creates a unique timestamp-based run identifier.
func generateRunID() string {
	now := time.Now()
	timestamp := now.Format("20060102-150405")
	return timestamp
}

// findProjectRoot locates the project root by finding the directory containing go.mod.
func findProjectRoot(startPath string) string {
	current := startPath
	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			return startPath
		}
		current = parent
	}
}

// boolToInt converts a boolean to an integer for environment variables.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// DockerContext represents Docker context information.
type DockerContext struct {
	Name      string                 `json:"Name"`
	Metadata  map[string]interface{} `json:"Metadata"`
	Endpoints map[string]interface{} `json:"Endpoints"`
	Current   bool                   `json:"Current"`
}

// createDockerClient creates a Docker client with context detection.
func createDockerClient() (*client.Client, error) {
	contextInfo, err := getCurrentDockerContext()
	if err != nil {
		return client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	}

	var clientOpts []client.Opt
	clientOpts = append(clientOpts, client.WithAPIVersionNegotiation())

	if contextInfo != nil {
		if endpoints, ok := contextInfo.Endpoints["docker"]; ok {
			if endpointMap, ok := endpoints.(map[string]interface{}); ok {
				if host, ok := endpointMap["Host"].(string); ok {
					if runConfig.Verbose {
						log.Printf("Using Docker host from context '%s': %s", contextInfo.Name, host)
					}
					clientOpts = append(clientOpts, client.WithHost(host))
				}
			}
		}
	}

	if len(clientOpts) == 1 {
		clientOpts = append(clientOpts, client.FromEnv)
	}

	return client.NewClientWithOpts(clientOpts...)
}

// getCurrentDockerContext retrieves the current Docker context information.
func getCurrentDockerContext() (*DockerContext, error) {
	cmd := exec.Command("docker", "context", "inspect")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker context: %w", err)
	}

	var contexts []DockerContext
	if err := json.Unmarshal(output, &contexts); err != nil {
		return nil, fmt.Errorf("failed to parse docker context: %w", err)
	}

	if len(contexts) > 0 {
		return &contexts[0], nil
	}

	return nil, ErrNoDockerContext
}

// ensureImageAvailable pulls the specified Docker image to ensure it's available.
func ensureImageAvailable(ctx context.Context, cli *client.Client, imageName string, verbose bool) error {
	if verbose {
		log.Printf("Pulling image %s...", imageName)
	}

	reader, err := cli.ImagePull(ctx, imageName, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("failed to pull image %s: %w", imageName, err)
	}
	defer reader.Close()

	if verbose {
		_, err = io.Copy(os.Stdout, reader)
		if err != nil {
			return fmt.Errorf("failed to read pull output: %w", err)
		}
	} else {
		_, err = io.Copy(io.Discard, reader)
		if err != nil {
			return fmt.Errorf("failed to read pull output: %w", err)
		}
		log.Printf("Image %s pulled successfully", imageName)
	}

	return nil
}

// listControlFiles displays the headscale test artifacts created in the control logs directory.
func listControlFiles(logsDir string) {
	entries, err := os.ReadDir(logsDir)
	if err != nil {
		log.Printf("Logs directory: %s", logsDir)
		return
	}

	var logFiles []string
	var tarFiles []string

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Only show headscale (hs-*) files
		if !strings.HasPrefix(name, "hs-") {
			continue
		}

		switch {
		case strings.HasSuffix(name, ".stderr.log") || strings.HasSuffix(name, ".stdout.log"):
			logFiles = append(logFiles, name)
		case strings.HasSuffix(name, ".pprof.tar") || strings.HasSuffix(name, ".maps.tar") || strings.HasSuffix(name, ".db.tar"):
			tarFiles = append(tarFiles, name)
		}
	}

	log.Printf("Test artifacts saved to: %s", logsDir)

	if len(logFiles) > 0 {
		log.Printf("Headscale logs:")
		for _, file := range logFiles {
			log.Printf("  %s", file)
		}
	}

	if len(tarFiles) > 0 {
		log.Printf("Headscale archives:")
		for _, file := range tarFiles {
			log.Printf("  %s", file)
		}
	}
}
