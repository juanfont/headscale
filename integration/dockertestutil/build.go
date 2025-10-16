package dockertestutil

import (
	"os/exec"
)

// RunDockerBuildForDiagnostics runs docker build manually to get detailed error output.
// This is used when a docker build fails to provide more detailed diagnostic information
// than what dockertest typically provides.
func RunDockerBuildForDiagnostics(contextDir, dockerfile string) string {
	cmd := exec.Command("docker", "build", "-f", dockerfile, contextDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output)
	}
	return ""
}
