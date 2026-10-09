package tsic

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Simulate Docker's streamed output without requiring Docker or a shell.
func TestLoginReturnsURLBeforeCLIExit(t *testing.T) {
	const wantURL = "https://headscale.test/register/complete-token"

	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			partialWritten := make(chan struct{})
			completeURL := make(chan struct{})
			authenticate := make(chan struct{})

			t.Cleanup(func() { close(authenticate) })

			login := startLogin([]string{"tailscale", "up"}, func(_ []string, opts dockertest.ExecOptions) (int, error) {
				output := opts.StdErr
				if stream == "stdout" {
					output = opts.StdOut
				}

				_, _ = io.WriteString(output, "To authenticate, visit:\n\thttps://headscale.test/reg")

				close(partialWritten)
				<-completeURL

				_, _ = io.WriteString(output, "ister/complete-token\n\n")

				<-authenticate
				// A later URL must not block output draining or replace the first.
				_, _ = io.WriteString(output, "https://headscale.test/register/another-token\nSuccess.\n")

				return 0, nil
			})

			<-partialWritten

			select {
			case u := <-login.url:
				t.Fatalf("returned incomplete URL: %s", u)
			default:
			}

			close(completeURL)

			u, err := login.waitForURL(time.Second)
			require.NoError(t, err)
			require.Equal(t, wantURL, u.String())

			select {
			case <-login.done:
				t.Fatal("CLI exited before authentication")
			default:
			}

			// Permit natural completion and verify its exit status is retained.
			authenticate <- struct{}{}

			select {
			case <-login.done:
				require.NoError(t, login.err)
				assert.Contains(t, login.output.String(), "Success.")
			case <-time.After(time.Second):
				t.Fatal("CLI did not complete after authentication")
			}
		})
	}
}

func TestLoginCommandFailure(t *testing.T) {
	execErr := io.ErrClosedPipe

	for _, tt := range []struct {
		name     string
		output   string
		exitCode int
		err      error
		wantErr  error
	}{
		{name: "exec error", err: execErr, wantErr: execErr},
		{name: "CLI failure", output: "invalid login option", exitCode: 7, wantErr: dockertestutil.ErrDockertestCommandFailed},
		{name: "no URL", output: "Success.\n", wantErr: util.ErrNoURLFound},
		{name: "incomplete URL", output: "https://headscale.test/register/incomplete", wantErr: util.ErrNoURLFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			login := startLogin(nil, func(_ []string, opts dockertest.ExecOptions) (int, error) {
				_, _ = io.WriteString(opts.StdErr, tt.output)
				return tt.exitCode, tt.err
			})
			_, err := login.waitForURL(time.Second)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Contains(t, err.Error(), tt.output)
		})
	}
}

func TestLoginFailureAfterURL(t *testing.T) {
	finish := make(chan struct{})

	t.Cleanup(func() { close(finish) })

	login := startLogin(nil, func(_ []string, opts dockertest.ExecOptions) (int, error) {
		_, _ = io.WriteString(opts.StdErr, "https://headscale.test/register/token\n")

		<-finish

		_, _ = io.WriteString(opts.StdErr, "authentication rejected\n")

		return 1, nil
	})

	_, err := login.waitForURL(time.Second)
	require.NoError(t, err)

	client := &TailscaleInContainer{hostname: "client", login: login}
	// A URL alone is not a completed login. The caller's wait stays bounded.
	require.ErrorIs(t, client.WaitForRunning(0), context.DeadlineExceeded)

	finish <- struct{}{}

	select {
	case <-login.done:
		for range 2 {
			// All observers must see the failure, not just the first channel reader.
			err = client.WaitForRunning(time.Second)
			require.ErrorIs(t, err, dockertestutil.ErrDockertestCommandFailed)
			assert.Contains(t, err.Error(), "authentication rejected")
		}
	case <-time.After(time.Second):
		t.Fatal("CLI did not finish")
	}
}

func TestLoginURLDeadlineDoesNotStopCLI(t *testing.T) {
	finish := make(chan struct{})

	t.Cleanup(func() { close(finish) })

	login := startLogin(nil, func(_ []string, opts dockertest.ExecOptions) (int, error) {
		<-finish

		_, _ = fmt.Fprintln(opts.StdErr, "https://headscale.test/register/token")

		return 0, nil
	})

	_, err := login.waitForURL(0)
	require.ErrorIs(t, err, dockertestutil.ErrDockertestCommandTimeout)

	finish <- struct{}{}

	select {
	case <-login.done:
		require.NoError(t, login.err)
	case <-time.After(time.Second):
		t.Fatal("CLI did not finish after URL deadline")
	}
}
