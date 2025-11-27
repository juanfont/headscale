package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/creachadair/command"
)

var ErrTestPatternRequired = errors.New("test pattern is required as first argument or use --test flag")

// formatRunningTestError creates a detailed error message about a running test.
func formatRunningTestError(info *RunningTestInfo) error {
	var msg strings.Builder
	msg.WriteString("\n")
	msg.WriteString("╔══════════════════════════════════════════════════════════════════╗\n")
	msg.WriteString("║  Another integration test run is already in progress!            ║\n")
	msg.WriteString("╚══════════════════════════════════════════════════════════════════╝\n")
	msg.WriteString("\n")
	msg.WriteString("Running test details:\n")
	msg.WriteString(fmt.Sprintf("  Run ID:      %s\n", info.RunID))
	msg.WriteString(fmt.Sprintf("  Container:   %s\n", info.ContainerName))

	if info.TestPattern != "" {
		msg.WriteString(fmt.Sprintf("  Test:        %s\n", info.TestPattern))
	}

	if !info.StartTime.IsZero() {
		msg.WriteString(fmt.Sprintf("  Started:     %s\n", info.StartTime.Format("2006-01-02 15:04:05")))
		msg.WriteString(fmt.Sprintf("  Running for: %s\n", formatDuration(info.Duration)))
	}

	msg.WriteString("\n")
	msg.WriteString("Please wait for the current test to complete, or stop it with:\n")
	msg.WriteString("  go run ./cmd/hi clean containers\n")
	msg.WriteString("\n")
	msg.WriteString("To monitor the running test:\n")
	msg.WriteString(fmt.Sprintf("  docker logs -f %s\n", info.ContainerName))

	return fmt.Errorf("%w\n%s", ErrAnotherRunInProgress, msg.String())
}

const secondsPerMinute = 60

// formatDuration formats a duration in a human-readable way.
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}

	if d < time.Hour {
		minutes := int(d.Minutes())
		seconds := int(d.Seconds()) % secondsPerMinute

		return fmt.Sprintf("%d minutes, %d seconds", minutes, seconds)
	}

	hours := int(d.Hours())
	minutes := int(d.Minutes()) % secondsPerMinute

	return fmt.Sprintf("%d hours, %d minutes", hours, minutes)
}

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
	Stats         bool          `flag:"stats,default=false,Collect and display container resource usage statistics"`
	HSMemoryLimit float64       `flag:"hs-memory-limit,default=0,Fail test if any Headscale container exceeds this memory limit in MB (0 = disabled)"`
	TSMemoryLimit float64       `flag:"ts-memory-limit,default=0,Fail test if any Tailscale container exceeds this memory limit in MB (0 = disabled)"`
	Force         bool          `flag:"force,default=false,Kill any running test and start a new one"`
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

	// Check if another test run is already in progress
	runningTest, err := checkForRunningTests(env.Context())
	if err != nil && !errors.Is(err, ErrNoRunningTests) {
		log.Printf("Warning: failed to check for running tests: %v", err)
	} else if runningTest != nil {
		if runConfig.Force {
			log.Printf("Force flag set, killing existing test run: %s", runningTest.RunID)

			err = killTestContainers(env.Context())
			if err != nil {
				return fmt.Errorf("failed to kill existing test containers: %w", err)
			}
		} else {
			return formatRunningTestError(runningTest)
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
		return "1.25"
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

	return "1.25"
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
