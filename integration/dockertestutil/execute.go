package dockertestutil

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/ory/dockertest/v3"
)

const dockerExecuteTimeout = time.Second * 10

var (
	ErrDockertestCommandFailed  = errors.New("dockertest command failed")
	ErrDockertestCommandTimeout = errors.New("dockertest command timed out")
)

type ExecuteCommandConfig struct {
	timeout time.Duration
}

type ExecuteCommandOption func(*ExecuteCommandConfig) error

func ExecuteCommandTimeout(timeout time.Duration) ExecuteCommandOption {
	return ExecuteCommandOption(func(conf *ExecuteCommandConfig) error {
		conf.timeout = timeout

		return nil
	})
}

func ExecuteCommand(
	resource *dockertest.Resource,
	cmd []string,
	env []string,
	options ...ExecuteCommandOption,
) (string, string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	execConfig := ExecuteCommandConfig{
		timeout: dockerExecuteTimeout,
	}

	for _, opt := range options {
		if err := opt(&execConfig); err != nil {
			return "", "", fmt.Errorf("execute-command/options: %w", err)
		}
	}

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
			return stdout.String(), stderr.String(), res.err
		}

		if res.exitCode != 0 {
			// Uncomment for debugging
			// log.Println("Command: ", cmd)
			// log.Println("stdout: ", stdout.String())
			// log.Println("stderr: ", stderr.String())

			return stdout.String(), stderr.String(), ErrDockertestCommandFailed
		}

		return stdout.String(), stderr.String(), nil
	case <-time.After(execConfig.timeout):

		return stdout.String(), stderr.String(), ErrDockertestCommandTimeout
	}
}
