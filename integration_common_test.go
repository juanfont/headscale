//go:build integration
// +build integration

package headscale

import (
	"bytes"
	"fmt"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

const DOCKER_EXECUTE_TIMEOUT = 10 * time.Second

func ExecuteCommand(
	resource *dockertest.Resource,
	cmd []string,
	env []string,
) (string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	// TODO(kradalby): Make configurable
	timeout := DOCKER_EXECUTE_TIMEOUT

	type result struct {
		exitCode int
		err      error
	}

	resultChan := make(chan result, 1)

	// Run your long running function in it's own goroutine and pass back it's
	// response into our channel.
	go func() {
		exitCode, err := resource.Exec(
			cmd,
			dockertest.ExecOptions{
				Env:    append(env, "HEADSCALE_LOG_LEVEL=disabled"),
				StdOut: &stdout,
				StdErr: &stderr,
			},
		)
		resultChan <- result{exitCode, err}
	}()

	// Listen on our channel AND a timeout channel - which ever happens first.
	select {
	case res := <-resultChan:
		if res.err != nil {
			return "", res.err
		}

		if res.exitCode != 0 {
			fmt.Println("Command: ", cmd)
			fmt.Println("stdout: ", stdout.String())
			fmt.Println("stderr: ", stderr.String())

			return "", fmt.Errorf("command failed with: %s", stderr.String())
		}

		return stdout.String(), nil
	case <-time.After(timeout):

		return "", fmt.Errorf("command timed out after %s", timeout)
	}
}

func DockerRestartPolicy(config *docker.HostConfig) {
	// set AutoRemove to true so that stopped container goes away by itself
	config.AutoRemove = true
	config.RestartPolicy = docker.RestartPolicy{
		Name: "no",
	}
}
