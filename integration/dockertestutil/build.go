package dockertestutil

import (
	"context"
	"os/exec"
	"time"
)

// RunDockerBuildForDiagnostics runs docker build manually to get detailed error output.
// This is used when a docker build fails to provide more detailed diagnostic information
// than what dockertest typically provides.
//
// Returns the build output regardless of success/failure, and an error if the build failed.
func RunDockerBuildForDiagnostics(contextDir, dockerfile string) (string, error) {
	// Use a context with timeout to prevent hanging builds
	const buildTimeout = 10 * time.Minute

	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "build", "--progress=plain", "--no-cache", "-f", dockerfile, contextDir)
	output, err := cmd.CombinedOutput()

	return string(output), err
}
