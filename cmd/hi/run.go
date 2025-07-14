package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/creachadair/command"
	"github.com/docker/docker/api/types/container"
)

var ErrTestPatternRequired = errors.New("test pattern is required as first argument or use --test flag")

type RunConfig struct {
	TestPattern   string        `flag:"test,Test pattern to run"`
	Timeout       time.Duration `flag:"timeout,default=120m,Test timeout"`
	FailFast      bool          `flag:"failfast,default=true,Stop on first test failure"`
	UsePostgres   bool          `flag:"postgres,default=false,Use PostgreSQL instead of SQLite"`
	GoVersion     string        `flag:"go-version,Go version to use (auto-detected from go.mod)"`
	CleanBefore   bool          `flag:"clean-before,default=true,Clean resources before test"`
	CleanAfter    bool          `flag:"clean-after,default=true,Clean resources after test"`
	KeepOnFailure bool          `flag:"keep-on-failure,default=false,Keep containers on test failure"`
	LogsDir       string        `flag:"logs-dir,default=control_logs,Control logs directory"`
	Verbose       bool          `flag:"verbose,default=false,Verbose output"`
	Force         bool          `flag:"force,default=false,Kill all containers and force run"`
}

// runIntegrationTest executes the integration test workflow.
func runIntegrationTest(env *command.Env) error {
	args := env.Args
	if len(args) > 0 && runConfig.TestPattern == "" {
		runConfig.TestPattern = args[0]
	}

	if runConfig.TestPattern == "" {
		return ErrTestPatternRequired
	}

	if runConfig.GoVersion == "" {
		runConfig.GoVersion = detectGoVersion()
	}

	// Check for existing runs unless --force is used
	if !runConfig.Force {
		if activeRun, err := checkForActiveRun(env.Context()); err != nil {
			return fmt.Errorf("failed to check for active runs: %w", err)
		} else if activeRun != "" {
			return fmt.Errorf("Another run is already running %s, wait for it to finish or use --force to kill all containers", activeRun)
		}
	} else {
		if runConfig.Verbose {
			log.Printf("Force flag enabled, killing all test containers...")
		}
		if err := killTestContainers(env.Context()); err != nil {
			return fmt.Errorf("failed to force kill containers: %w", err)
		}
	}

	// Run pre-flight checks
	if runConfig.Verbose {
		log.Printf("Running pre-flight system checks...")
	}
	if err := runDoctorCheck(env.Context()); err != nil {
		return fmt.Errorf("pre-flight checks failed: %w", err)
	}

	if runConfig.Verbose {
		log.Printf("Running test: %s", runConfig.TestPattern)
		log.Printf("Go version: %s", runConfig.GoVersion)
		log.Printf("Timeout: %s", runConfig.Timeout)
		log.Printf("Use PostgreSQL: %t", runConfig.UsePostgres)
	}

	return runTestContainer(env.Context(), &runConfig)
}

// detectGoVersion reads the Go version from go.mod file.
func detectGoVersion() string {
	goModPath := filepath.Join("..", "..", "go.mod")

	if _, err := os.Stat("go.mod"); err == nil {
		goModPath = "go.mod"
	} else if _, err := os.Stat("../../go.mod"); err == nil {
		goModPath = "../../go.mod"
	}

	content, err := os.ReadFile(goModPath)
	if err != nil {
		return "1.24"
	}

	lines := splitLines(string(content))
	for _, line := range lines {
		if len(line) > 3 && line[:3] == "go " {
			version := line[3:]
			if idx := indexOf(version, " "); idx != -1 {
				version = version[:idx]
			}

			return version
		}
	}

	return "1.24"
}

// splitLines splits a string into lines without using strings.Split.
func splitLines(s string) []string {
	var lines []string
	var current string

	for _, char := range s {
		if char == '\n' {
			lines = append(lines, current)
			current = ""
		} else {
			current += string(char)
		}
	}

	if current != "" {
		lines = append(lines, current)
	}

	return lines
}

// indexOf finds the first occurrence of substr in s.
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}

	return -1
}

// checkForActiveRun checks if there are any active test containers running.
func checkForActiveRun(ctx context.Context) (string, error) {
	cli, err := createDockerClient()
	if err != nil {
		return "", fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer cli.Close()

	containers, err := cli.ContainerList(ctx, container.ListOptions{
		All: false, // Only running containers
	})
	if err != nil {
		return "", fmt.Errorf("failed to list containers: %w", err)
	}

	for _, cont := range containers {
		for _, name := range cont.Names {
			containerName := strings.TrimPrefix(name, "/")
			if strings.HasPrefix(containerName, "headscale-test-suite-") {
				return containerName, nil
			}
		}
	}

	return "", nil
}
