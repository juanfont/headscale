package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Exercise the real flag parser: folded YAML shell continuations used to turn
// --postgres into a positional argument, silently selecting SQLite.
func TestRunArguments(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		postgres bool
		wantErr  error
	}{
		{
			name:     "postgres before selector",
			args:     []string{"--postgres=1", "--timeout=15m", "^TestHeadscale$"},
			postgres: true,
		},
		{
			name:     "postgres after selector",
			args:     []string{"^TestHeadscale$", "--postgres", "--timeout=15m"},
			postgres: true,
		},
		{
			name: "sqlite",
			args: []string{"--postgres=0", "--timeout=15m", "--test=^TestHeadscale$"},
		},
		{
			name:    "folded shell continuations",
			args:    []string{"^TestHeadscale$", " --timeout=15m", " --postgres=1"},
			wantErr: ErrUnexpectedTestArguments,
		},
		{
			name:    "extra selector",
			args:    []string{"^TestHeadscale$", "TestNodeCommand"},
			wantErr: ErrUnexpectedTestArguments,
		},
		{
			name:    "positional selector with test flag",
			args:    []string{"--test=^TestHeadscale$", "TestNodeCommand"},
			wantErr: ErrUnexpectedTestArguments,
		},
		{
			name:    "missing selector",
			wantErr: ErrTestPatternRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var config RunConfig

			cmd := command.C{
				Name:     "run",
				SetFlags: command.Flags(flax.MustBind, &config),
				Run:      func(env *command.Env) error { return config.validate(env.Args) },
			}

			err := command.Run(cmd.NewEnv(nil).MergeFlags(true), tt.args)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.postgres, config.UsePostgres)
			assert.Equal(t, "^TestHeadscale$", config.TestPattern)
			assert.Equal(t, 15*time.Minute, config.Timeout)
		})
	}
}

func TestCompiledTestContainer(t *testing.T) {
	t.Setenv("HEADSCALE_INTEGRATION_HEADSCALE_IMAGE", "headscale:ci-test")
	// Neither inherited backend settings nor Go cache mounts should override
	// the requested backend or leak into a compiled test execution.
	t.Setenv("HEADSCALE_INTEGRATION_POSTGRES", "0")
	t.Setenv("HEADSCALE_INTEGRATION_GO_CACHE", "/unused/go")
	t.Setenv("HEADSCALE_INTEGRATION_GO_BUILD_CACHE", "/unused/build")

	binary := filepath.Join(t.TempDir(), "integration.test")
	require.NoError(t, os.WriteFile(binary, []byte("test executable"), 0o700)) //nolint:gosec // The fixture must be executable to validate --test-binary.
	config := RunConfig{
		TestPattern: "^TestAutoApproveMultiNetwork/webauth-user.*$",
		TestBinary:  binary,
		UsePostgres: true,
		Timeout:     15 * time.Minute,
		FailFast:    true,
	}
	require.NoError(t, config.validate(nil))

	type createRequest struct {
		container.Config

		HostConfig container.HostConfig
	}

	requests := make(chan createRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request createRequest

		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		requests <- request

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"test-runner","Warnings":[]}`))
	}))
	t.Cleanup(server.Close)
	cli, err := client.NewClientWithOpts(client.WithHost(server.URL), client.WithVersion("1.44"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, cli.Close()) })

	const runID = "20261007-120000-abcdef"

	logs := t.TempDir()
	_, err = createTestContainer(t.Context(), cli, &config,
		"headscale-test-suite-"+runID, logs, buildTestCommand(&config))
	require.NoError(t, err)

	request := <-requests
	assert.Equal(t, "headscale:ci-test", request.Image)
	assert.Equal(t, []string{
		"/integration.test", "-test.run", config.TestPattern,
		"-test.failfast", "-test.timeout", "15m0s", "-test.v",
	}, []string(request.Cmd))
	assert.Contains(t, request.Env, "HEADSCALE_INTEGRATION_POSTGRES=1")
	assert.NotContains(t, request.Env, "HEADSCALE_INTEGRATION_POSTGRES=0")
	assert.Contains(t, request.Env, "HEADSCALE_INTEGRATION_RUN_ID="+runID)
	assert.NotContains(t, request.Env, "GOCACHE=/cache/go-build")
	assert.Equal(t, runID, request.Labels["hi.run-id"])
	assert.Equal(t, "integration", filepath.Base(request.WorkingDir))
	assert.Contains(t, request.HostConfig.Binds, logs+":/tmp/control")
	assert.NotContains(t, request.HostConfig.Binds, "/unused/go:/go")
	assert.Equal(t, []mount.Mount{{
		Type: mount.TypeBind, Source: binary, Target: "/integration.test", ReadOnly: true,
	}}, request.HostConfig.Mounts)
}

func TestSourceTestCommand(t *testing.T) {
	t.Setenv("HEADSCALE_INTEGRATION_HEADSCALE_IMAGE", "headscale:ci-test")

	config := RunConfig{
		TestPattern: "^TestHeadscale$", GoVersion: "1.27.0", Timeout: time.Minute,
	}
	assert.Equal(t, []string{"go", "test", "./...", "-run", "^TestHeadscale$", "-timeout", "1m0s", "-v"}, buildTestCommand(&config))
	assert.Equal(t, "golang:1.27.0", testRunnerImage(&config))

	config.TestBinary = "/integration.test"

	t.Setenv("HEADSCALE_INTEGRATION_HEADSCALE_IMAGE", "")
	assert.Equal(t, "golang:1.27.0", testRunnerImage(&config))
}

func TestStreamAndWaitDrainsFinalOutput(t *testing.T) {
	output, err := os.CreateTemp(t.TempDir(), "test-output")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, output.Close()) })

	stdout := os.Stdout
	os.Stdout = output

	t.Cleanup(func() { os.Stdout = stdout })

	waitSent := make(chan struct{})
	releaseLogs := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/logs"):
			w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
			w.WriteHeader(http.StatusOK)
			_ = http.NewResponseController(w).Flush()

			select {
			case <-releaseLogs:
				_, _ = w.Write([]byte("--- PASS: TestExample (0.01s)\nPASS\n"))
			case <-r.Context().Done():
			}
		case strings.HasSuffix(r.URL.Path, "/wait"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"StatusCode":0}`))
			_ = http.NewResponseController(w).Flush()

			close(waitSent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	cli, err := client.NewClientWithOpts(client.WithHost(server.URL), client.WithVersion("1.44"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, cli.Close()) })

	type result struct {
		exitCode int
		err      error
	}

	done := make(chan result, 1)

	go func() {
		code, err := streamAndWait(t.Context(), cli, "test-runner")
		done <- result{code, err}
	}()

	<-waitSent

	// Hold back the last log packet after Docker has reported the exit code.
	select {
	case <-done:
		close(releaseLogs)
		t.Fatal("returned before the final test output was delivered")
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseLogs)

	got := <-done
	require.NoError(t, got.err)
	assert.Zero(t, got.exitCode)

	data, err := os.ReadFile(output.Name())
	require.NoError(t, err)
	assert.Equal(t, "--- PASS: TestExample (0.01s)\nPASS\n", string(data))
}
