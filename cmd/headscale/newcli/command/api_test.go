package command

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

// server answers every request with the given version headers and status.
func server(t *testing.T, version, commit string, status int) string {
	t.Helper()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if version != "" {
			w.Header().Set("Headscale-Version", version)
		}

		if commit != "" {
			w.Header().Set("Headscale-Commit", commit)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"healthy": true, "databaseConnectivity": true, "warnings": [], "new": 1}`))
	}))
	t.Cleanup(s.Close)

	return s.URL
}

func TestVersionCheck(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name                string
		own, ownCommit      string
		server, commit      string
		status              int
		wantErr, wantStderr string
	}{
		{name: "same release", own: "0.30.1", server: "0.30.1", status: 200},
		{name: "another patch release", own: "0.30.1", server: "v0.30.4", status: 200},
		{
			name: "another minor release", own: "0.31.2", ownCommit: "3f2a9c1d", server: "0.30.4", commit: "a491228", status: 200,
			wantErr: "this headscale is 0.31.2 (3f2a9c1), the server is 0.30.4 (a491228).\n" +
				"The CLI and the server must have the same major and minor version.\n" +
				"If you just upgraded, restart the server.",
		},
		{
			name: "another major release, no commits", own: "1.0.0", server: "0.30.4", status: 200,
			wantErr: "this headscale is 1.0.0, the server is 0.30.4.\n" +
				"The CLI and the server must have the same major and minor version.\n" +
				"If you just upgraded, restart the server.",
		},
		{
			name: "builds that are not releases warn on other commits", own: "dev", ownCommit: "3f2a9c1", server: "dev", commit: "a491228", status: 200,
			wantStderr: "warning: this headscale is dev (3f2a9c1), the server is dev (a491228).\n",
		},
		{name: "a release and a dev build are not stopped", own: "0.30.1", ownCommit: "unknown", server: "v0.29.1-0.20261119195522-9eefa579283e", status: 200},
		{name: "dev builds with no commit say nothing", own: "dev", ownCommit: "unknown", server: "dev", status: 200},
		{
			name: "a server with no v0", own: "0.30.1", status: 404,
			wantErr: "the server at hs.example.com is too old for this CLI.\nIt has no /api/headscale/v0.",
		},
		{
			name: "an answer that is not from headscale", own: "0.30.1", status: 502,
			wantErr: "the server at hs.example.com answered 502 Bad Gateway without Headscale-Version.\nIs it headscale?",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stderr bytes.Buffer

			check := &versionCheck{
				next:   http.DefaultTransport,
				own:    &types.VersionInfo{Version: tt.own, Commit: tt.ownCommit},
				target: "hs.example.com",
				warn:   &stderr,
			}

			c, err := clientv0.NewClient(server(t, tt.server, tt.commit, tt.status), clientv0.WithHTTPClient(&http.Client{Transport: check}))
			require.NoError(t, err)

			a := &API{c: c, target: "hs.example.com"}

			// Twice: a warning is printed once per run.
			for range 2 {
				h, err := a.Health(context.Background())
				if tt.wantErr != "" {
					require.EqualError(t, err, tt.wantErr)

					continue
				}

				require.NoError(t, err)
				require.True(t, h.Healthy)
				// A field this build does not know survives for -o json.
				raw, ok := a.answerOf(h)
				require.True(t, ok)
				require.Contains(t, string(raw), `"new": 1`)
			}

			require.Equal(t, tt.wantStderr, stderr.String())
		})
	}
}

// TestConnectError: the message says what was wrong, and names the host
// as the operator knows it.
func TestConnectError(t *testing.T) {
	t.Parallel()

	remote := func(t *testing.T, url string) error {
		t.Helper()

		a, err := connect(&types.Config{CLI: types.CLIConfig{Address: url, APIKey: "key"}}, Env{Stderr: io.Discard, Version: types.GetVersionInfo()})
		require.NoError(t, err)

		_, err = a.Health(t.Context())

		return err
	}

	t.Run("a socket the user may not open fails at once", func(t *testing.T) {
		t.Parallel()

		// A short path: a socket path has a small limit.
		dir, err := os.MkdirTemp("", "hs") //nolint:usetesting // t.TempDir is longer than a socket path may be
		require.NoError(t, err)
		t.Cleanup(func() { os.RemoveAll(dir) })

		path := filepath.Join(dir, "headscale.sock")
		l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
		require.NoError(t, err)
		t.Cleanup(func() { l.Close() })
		require.NoError(t, os.Chmod(path, 0))

		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		_, err = (&socket{path: path}).dial(ctx)
		require.NoError(t, ctx.Err(), "retried until the time was up")
		require.EqualError(t, &connectError{target: path, err: err},
			"cannot connect to "+path+": permission denied.\nRun it as a user that may open the socket, or use HEADSCALE_CLI_ADDRESS.")
	})

	t.Run("a socket that is not there names the cause", func(t *testing.T) {
		t.Parallel()

		a, err := connect(&types.Config{UnixSocket: "/nonexistent/headscale.sock"}, Env{Stderr: io.Discard, Version: types.GetVersionInfo()})
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()

		_, err = a.Health(ctx)
		require.EqualError(t, err, "cannot connect to /nonexistent/headscale.sock: no such file or directory\n"+
			"Is headscale running? To use another server:\n  --config <file>, HEADSCALE_UNIX_SOCKET, or HEADSCALE_CLI_ADDRESS")
	})

	t.Run("a certificate that is not trusted is no stopped server", func(t *testing.T) {
		t.Parallel()

		s := httptest.NewTLSServer(http.NotFoundHandler())
		t.Cleanup(s.Close)

		err := remote(t, s.URL)
		require.ErrorContains(t, err, "cannot connect to "+strings.TrimPrefix(s.URL, "https://")+": tls: failed to verify certificate")
		require.NotContains(t, err.Error(), "Is headscale running?")
	})

	t.Run("the host has no scheme", func(t *testing.T) {
		t.Parallel()

		s := httptest.NewServer(http.NotFoundHandler())
		t.Cleanup(s.Close)

		require.EqualError(t, remote(t, s.URL), "the server at "+strings.TrimPrefix(s.URL, "http://")+" is too old for this CLI.\nIt has no /api/headscale/v0.")
	})
}

// TestFirstWrite: a write that comes first asks GET /version before it, and
// does not reach a server of another version.
func TestFirstWrite(t *testing.T) {
	t.Parallel()

	run := func(t *testing.T, version string, methods ...string) ([]string, error) {
		t.Helper()

		var (
			mu   sync.Mutex
			seen []string
		)

		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()

			seen = append(seen, r.Method+" "+r.URL.Path)
			mu.Unlock()
			w.Header().Set("Headscale-Version", version)
		}))
		t.Cleanup(s.Close)

		c := &http.Client{Transport: &versionCheck{next: http.DefaultTransport, own: &types.VersionInfo{Version: "0.30.1"}, server: s.URL, warn: io.Discard}}

		var err error

		for _, m := range methods {
			req, rerr := http.NewRequestWithContext(t.Context(), m, s.URL+"/x", nil)
			require.NoError(t, rerr)

			var resp *http.Response

			resp, err = c.Do(req)
			if err != nil {
				break
			}

			resp.Body.Close()
		}

		mu.Lock()
		defer mu.Unlock()

		return seen, err
	}

	seen, err := run(t, "0.30.2", http.MethodPost, http.MethodPost)
	require.NoError(t, err)
	require.Equal(t, []string{"GET /api/headscale/v0/version", "POST /x", "POST /x"}, seen)

	seen, err = run(t, "0.30.2", http.MethodGet, http.MethodDelete)
	require.NoError(t, err)
	require.Equal(t, []string{"GET /x", "DELETE /x"}, seen)

	seen, err = run(t, "0.29.0", http.MethodPost)
	require.ErrorContains(t, err, "this headscale is 0.30.1, the server is 0.29.0.")
	require.Equal(t, []string{"GET /api/headscale/v0/version"}, seen)
}
