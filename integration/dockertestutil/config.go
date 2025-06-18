package dockertestutil

import (
	"os"

	"github.com/ory/dockertest/v3"
)

// GetIntegrationRunID returns the run ID for the current integration test session.
// This is set by the hi tool and passed through environment variables.
func GetIntegrationRunID() string {
	return os.Getenv("HEADSCALE_INTEGRATION_RUN_ID")
}

// DockerAddIntegrationLabels adds integration test labels to Docker RunOptions.
// This allows the hi tool to identify containers belonging to specific test runs.
// This function should be called before passing RunOptions to dockertest functions.
func DockerAddIntegrationLabels(opts *dockertest.RunOptions, testType string) {
	runID := GetIntegrationRunID()
	if runID == "" {
		// If no run ID is set, do nothing for backward compatibility
		return
	}

	if opts.Labels == nil {
		opts.Labels = make(map[string]string)
	}
	opts.Labels["hi.run-id"] = runID
	opts.Labels["hi.test-type"] = testType
}

// IsRunningInContainer checks if the current process is running inside a Docker container.
// This is used by tests to determine if they should run integration tests.
func IsRunningInContainer() bool {
	// Check for the common indicator that we're in a container
	// This could be improved with more robust detection if needed
	_, err := os.Stat("/.dockerenv")
	return err == nil
}