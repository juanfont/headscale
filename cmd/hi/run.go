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

type RunConfig struct {
	TestPattern   string        `flag:"test,Test pattern to run"`
	Timeout       time.Duration `flag:"timeout,default=120m,Test timeout"`
	FailFast      bool          `flag:"failfast,default=true,Stop on first test failure"`
	UsePostgres   bool          `flag:"postgres,default=false,Use PostgreSQL instead of SQLite"`
	GoVersion     string        `flag:"go-version,Go version to use (auto-detected from go.mod)"`
	CleanBefore   bool          `flag:"clean-before,default=true,Clean stale resources before test"`
	CleanAfter    bool          `flag:"clean-after,default=true,Clean resources after test"`
	KeepOnFailure bool          `flag:"keep-on-failure,default=false,Keep containers on test failure"`
	LogsDir       string        `flag:"logs-dir,default=control_logs,Control logs directory"`
	Verbose       bool          `flag:"verbose,default=false,Verbose output"`
	Stats         bool          `flag:"stats,default=false,Collect and display container resource usage statistics"`
	HSMemoryLimit float64       `flag:"hs-memory-limit,default=0,Fail test if any Headscale container exceeds this memory limit in MB (0 = disabled)"`
	TSMemoryLimit float64       `flag:"ts-memory-limit,default=0,Fail test if any Tailscale container exceeds this memory limit in MB (0 = disabled)"`
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

	// Run pre-flight checks
	if runConfig.Verbose {
		log.Printf("Running pre-flight system checks...")
	}

	err := runDoctorCheck(env.Context())
	if err != nil {
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
	content, err := os.ReadFile("go.mod")
	if err != nil {
		content, err = os.ReadFile(filepath.Join("..", "..", "go.mod"))
		if err != nil {
			return "1.26.1"
		}
	}

	for line := range strings.Lines(string(content)) {
		if rest, ok := strings.CutPrefix(line, "go "); ok {
			if f := strings.Fields(rest); len(f) > 0 {
				return f[0]
			}
		}
	}

	return "1.26.1"
}
