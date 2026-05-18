package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/juanfont/headscale/integration/dockertestutil"
)

const (
	statusPass = "PASS"
	statusFail = "FAIL"
	statusWarn = "WARN"

	nameDockerDaemon  = "Docker Daemon"
	nameDockerContext = "Docker Context"
	nameDockerSocket  = "Docker Socket"
	nameGolangImage   = "Golang Image"
	nameGoInstall     = "Go Installation"
)

var ErrSystemChecksFailed = errors.New("system checks failed")

// DoctorResult represents the result of a single health check.
type DoctorResult struct {
	Name        string
	Status      string // "PASS", "FAIL", "WARN"
	Message     string
	Suggestions []string
}

// runDoctorCheck performs comprehensive pre-flight checks for integration testing.
func runDoctorCheck(ctx context.Context) error {
	results := []DoctorResult{}

	// Check 1: Docker binary availability
	results = append(results, checkDockerBinary())

	// Check 2: Docker daemon connectivity
	dockerResult := checkDockerDaemon(ctx)
	results = append(results, dockerResult)

	// If Docker is available, run additional checks
	if dockerResult.Status == statusPass {
		results = append(results, checkDockerContext(ctx))
		results = append(results, checkDockerSocket(ctx))
		results = append(results, checkDockerHubCredentials())
		results = append(results, checkGolangImage(ctx))
	}

	// Check 3: Go installation
	results = append(results, checkGoInstallation(ctx))

	// Check 4: Git repository
	results = append(results, checkGitRepository(ctx))

	// Check 5: Required files
	results = append(results, checkRequiredFiles(ctx))

	// Display results
	displayDoctorResults(results)

	// Return error if any critical checks failed
	for _, result := range results {
		if result.Status == statusFail {
			return fmt.Errorf("%w - see details above", ErrSystemChecksFailed)
		}
	}

	log.Printf("✅ All system checks passed - ready to run integration tests!")

	return nil
}

// checkDockerBinary verifies Docker binary is available.
func checkDockerBinary() DoctorResult {
	_, err := exec.LookPath("docker")
	if err != nil {
		return DoctorResult{
			Name:    "Docker Binary",
			Status:  statusFail,
			Message: "Docker binary not found in PATH",
			Suggestions: []string{
				"Install Docker: https://docs.docker.com/get-docker/",
				"For macOS: consider using colima or Docker Desktop",
				"Ensure docker is in your PATH",
			},
		}
	}

	return DoctorResult{
		Name:    "Docker Binary",
		Status:  statusPass,
		Message: "Docker binary found",
	}
}

// checkDockerDaemon verifies Docker daemon is running and accessible.
func checkDockerDaemon(ctx context.Context) DoctorResult {
	cli, err := createDockerClient(ctx)
	if err != nil {
		return DoctorResult{
			Name:    nameDockerDaemon,
			Status:  statusFail,
			Message: fmt.Sprintf("Cannot create Docker client: %v", err),
			Suggestions: []string{
				"Start Docker daemon/service",
				"Check Docker Desktop is running (if using Docker Desktop)",
				"For colima: run 'colima start'",
				"Verify DOCKER_HOST environment variable if set",
			},
		}
	}
	defer cli.Close()

	_, err = cli.Ping(ctx)
	if err != nil {
		return DoctorResult{
			Name:    nameDockerDaemon,
			Status:  statusFail,
			Message: fmt.Sprintf("Cannot ping Docker daemon: %v", err),
			Suggestions: []string{
				"Ensure Docker daemon is running",
				"Check Docker socket permissions",
				"Try: docker info",
			},
		}
	}

	return DoctorResult{
		Name:    nameDockerDaemon,
		Status:  statusPass,
		Message: "Docker daemon is running and accessible",
	}
}

// checkDockerContext verifies Docker context configuration.
func checkDockerContext(ctx context.Context) DoctorResult {
	contextInfo, err := getCurrentDockerContext(ctx)
	if err != nil {
		return DoctorResult{
			Name:    nameDockerContext,
			Status:  statusWarn,
			Message: "Could not detect Docker context, using default settings",
			Suggestions: []string{
				"Check: docker context ls",
				"Consider setting up a specific context if needed",
			},
		}
	}

	if contextInfo == nil {
		return DoctorResult{
			Name:    nameDockerContext,
			Status:  statusPass,
			Message: "Using default Docker context",
		}
	}

	return DoctorResult{
		Name:    nameDockerContext,
		Status:  statusPass,
		Message: "Using Docker context: " + contextInfo.Name,
	}
}

// checkDockerSocket verifies Docker socket accessibility.
func checkDockerSocket(ctx context.Context) DoctorResult {
	cli, err := createDockerClient(ctx)
	if err != nil {
		return DoctorResult{
			Name:    nameDockerSocket,
			Status:  statusFail,
			Message: fmt.Sprintf("Cannot access Docker socket: %v", err),
			Suggestions: []string{
				"Check Docker socket permissions",
				"Add user to docker group: sudo usermod -aG docker $USER",
				"For colima: ensure socket is accessible",
			},
		}
	}
	defer cli.Close()

	info, err := cli.Info(ctx)
	if err != nil {
		return DoctorResult{
			Name:    nameDockerSocket,
			Status:  statusFail,
			Message: fmt.Sprintf("Cannot get Docker info: %v", err),
			Suggestions: []string{
				"Check Docker daemon status",
				"Verify socket permissions",
			},
		}
	}

	return DoctorResult{
		Name:    nameDockerSocket,
		Status:  statusPass,
		Message: fmt.Sprintf("Docker socket accessible (Server: %s)", info.ServerVersion),
	}
}

// checkDockerHubCredentials warns when pulls would be anonymous and
// therefore rate-limited.
func checkDockerHubCredentials() DoctorResult {
	_, _, source := dockertestutil.Credentials()
	if source == dockertestutil.CredentialSourceAnonymous {
		return DoctorResult{
			Name:    "Docker Hub Credentials",
			Status:  "WARN",
			Message: "No Docker Hub credentials found — pulls will be rate-limited (100/6h per IP)",
			Suggestions: []string{
				"Run: docker login",
				"Or export DOCKERHUB_USERNAME and DOCKERHUB_TOKEN",
				"In CI: ensure the docker/login-action step is configured with secrets",
			},
		}
	}

	return DoctorResult{
		Name:    "Docker Hub Credentials",
		Status:  "PASS",
		Message: fmt.Sprintf("Credentials available (source: %s)", source),
	}
}

// checkGolangImage verifies the golang Docker image is available locally or can be pulled.
func checkGolangImage(ctx context.Context) DoctorResult {
	cli, err := createDockerClient(ctx)
	if err != nil {
		return DoctorResult{
			Name:    nameGolangImage,
			Status:  statusFail,
			Message: "Cannot create Docker client for image check",
		}
	}
	defer cli.Close()

	goVersion := detectGoVersion()
	imageName := "golang:" + goVersion

	// First check if image is available locally
	available, err := checkImageAvailableLocally(ctx, cli, imageName)
	if err != nil {
		return DoctorResult{
			Name:    nameGolangImage,
			Status:  statusFail,
			Message: fmt.Sprintf("Cannot check golang image %s: %v", imageName, err),
			Suggestions: []string{
				"Check Docker daemon status",
				"Try: docker images | grep golang",
			},
		}
	}

	if available {
		return DoctorResult{
			Name:    nameGolangImage,
			Status:  statusPass,
			Message: fmt.Sprintf("Golang image %s is available locally", imageName),
		}
	}

	// Image not available locally, try to pull it
	err = ensureImageAvailable(ctx, cli, imageName, false)
	if err != nil {
		return DoctorResult{
			Name:    nameGolangImage,
			Status:  statusFail,
			Message: fmt.Sprintf("Golang image %s not available locally and cannot pull: %v", imageName, err),
			Suggestions: []string{
				"Check internet connectivity",
				"Verify Docker Hub access",
				"Try: docker pull " + imageName,
				"Or run tests offline if image was pulled previously",
			},
		}
	}

	return DoctorResult{
		Name:    nameGolangImage,
		Status:  statusPass,
		Message: fmt.Sprintf("Golang image %s is now available", imageName),
	}
}

// checkGoInstallation verifies Go is installed and working.
func checkGoInstallation(ctx context.Context) DoctorResult {
	_, err := exec.LookPath("go")
	if err != nil {
		return DoctorResult{
			Name:    nameGoInstall,
			Status:  statusFail,
			Message: "Go binary not found in PATH",
			Suggestions: []string{
				"Install Go: https://golang.org/dl/",
				"Ensure go is in your PATH",
			},
		}
	}

	cmd := exec.CommandContext(ctx, "go", "version")

	output, err := cmd.Output()
	if err != nil {
		return DoctorResult{
			Name:    nameGoInstall,
			Status:  statusFail,
			Message: fmt.Sprintf("Cannot get Go version: %v", err),
		}
	}

	version := strings.TrimSpace(string(output))

	return DoctorResult{
		Name:    nameGoInstall,
		Status:  statusPass,
		Message: version,
	}
}

// checkGitRepository verifies we're in a git repository.
func checkGitRepository(ctx context.Context) DoctorResult {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--git-dir")

	err := cmd.Run()
	if err != nil {
		return DoctorResult{
			Name:    "Git Repository",
			Status:  statusFail,
			Message: "Not in a Git repository",
			Suggestions: []string{
				"Run from within the headscale git repository",
				"Clone the repository: git clone https://github.com/juanfont/headscale.git",
			},
		}
	}

	return DoctorResult{
		Name:    "Git Repository",
		Status:  statusPass,
		Message: "Running in Git repository",
	}
}

// checkRequiredFiles verifies required files exist.
func checkRequiredFiles(ctx context.Context) DoctorResult {
	requiredFiles := []string{
		"go.mod",
		"integration/",
		"cmd/hi/",
	}

	var missingFiles []string

	for _, file := range requiredFiles {
		cmd := exec.CommandContext(ctx, "test", "-e", file)

		err := cmd.Run()
		if err != nil {
			missingFiles = append(missingFiles, file)
		}
	}

	if len(missingFiles) > 0 {
		return DoctorResult{
			Name:    "Required Files",
			Status:  statusFail,
			Message: "Missing required files: " + strings.Join(missingFiles, ", "),
			Suggestions: []string{
				"Ensure you're in the headscale project root directory",
				"Check that integration/ directory exists",
				"Verify this is a complete headscale repository",
			},
		}
	}

	return DoctorResult{
		Name:    "Required Files",
		Status:  statusPass,
		Message: "All required files found",
	}
}

// displayDoctorResults shows the results in a formatted way.
func displayDoctorResults(results []DoctorResult) {
	log.Printf("🔍 System Health Check Results")
	log.Printf("================================")

	for _, result := range results {
		var icon string

		switch result.Status {
		case statusPass:
			icon = "✅"
		case statusWarn:
			icon = "⚠️"
		case statusFail:
			icon = "❌"
		default:
			icon = "❓"
		}

		log.Printf("%s %s: %s", icon, result.Name, result.Message)

		if len(result.Suggestions) > 0 {
			for _, suggestion := range result.Suggestions {
				log.Printf("   💡 %s", suggestion)
			}
		}
	}

	log.Printf("================================")
}
