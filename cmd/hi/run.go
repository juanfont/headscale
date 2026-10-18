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

var (
	ErrTestPatternRequired     = errors.New("test pattern is required as first argument or use --test flag")
	ErrUnexpectedTestArguments = errors.New("expected a single test pattern; check flag spelling and shell quoting")
	ErrInvalidTestBinary       = errors.New("test binary must be an executable regular file")
)

type RunConfig struct {
	TestPattern   string        `flag:"test,Test pattern to run"`
	TestBinary    string        `flag:"test-binary,Path to a precompiled integration test binary"`
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

func (c *RunConfig) validate(args []string) error {
	if len(args) > 1 || (len(args) != 0 && c.TestPattern != "") {
		return ErrUnexpectedTestArguments
	}

	if len(args) == 1 {
		c.TestPattern = args[0]
	}

	if c.TestPattern == "" {
		return ErrTestPatternRequired
	}

	if c.TestBinary != "" {
		binary, err := filepath.Abs(c.TestBinary)
		if err != nil {
			return fmt.Errorf("resolving test binary: %w", err)
		}

		info, err := os.Stat(binary)
		if err != nil {
			return fmt.Errorf("reading test binary: %w", err)
		}

		if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("%s: %w", binary, ErrInvalidTestBinary)
		}

		c.TestBinary = binary
	}

	return nil
}

// runIntegrationTest executes the integration test workflow.
func runIntegrationTest(env *command.Env) error {
	err := runConfig.validate(env.Args)
	if err != nil {
		return err
	}

	if runConfig.GoVersion == "" {
		runConfig.GoVersion = detectGoVersion()
	}

	// Run pre-flight checks
	if runConfig.Verbose {
		log.Printf("Running pre-flight system checks...")
	}

	err = runPreflightChecks(env.Context(), false)
	if err != nil {
		return fmt.Errorf("pre-flight checks failed: %w", err)
	}

	if runConfig.Verbose {
		log.Printf("Running test: %s", runConfig.TestPattern)
		log.Printf("Go version: %s", runConfig.GoVersion)
		log.Printf("Timeout: %s", runConfig.Timeout)
		log.Printf("Use PostgreSQL: %t", runConfig.UsePostgres)
	}

	backend := "sqlite"
	if runConfig.UsePostgres {
		backend = "postgres"
	}

	log.Printf("Database backend: %s", backend)

	return runTestContainer(env.Context(), &runConfig)
}

// detectGoVersion reads the Go version from go.mod file.
func detectGoVersion() string {
	content, err := os.ReadFile("go.mod")
	if err != nil {
		content, err = os.ReadFile(filepath.Join("..", "..", "go.mod"))
		if err != nil {
			return "1.27.0"
		}
	}

	for line := range strings.Lines(string(content)) {
		if rest, ok := strings.CutPrefix(line, "go "); ok {
			if f := strings.Fields(rest); len(f) > 0 {
				return f[0]
			}
		}
	}

	return "1.27.0"
}
