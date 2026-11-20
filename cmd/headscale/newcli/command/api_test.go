package command

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/cmdline"
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

// TestWalk: a walk asks for its page size, reads every page, and starts
// again once when the server refuses a token, as after a restart.
func TestWalk(t *testing.T) {
	t.Parallel()

	users := func(ids ...string) string {
		rows := make([]string, 0, len(ids))
		for _, id := range ids {
			rows = append(rows, `{"id": "`+id+`", "name": "u`+id+`"}`)
		}

		return `"users": [` + strings.Join(rows, ", ") + `]`
	}

	walkOf := func(t *testing.T, refuse int) ([]clientv0.User, []string, error) {
		t.Helper()

		var (
			mu      sync.Mutex
			asked   []string
			refused int
		)

		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()

			q := r.URL.Query()
			asked = append(asked, q.Get("pageSize")+" "+q.Get("pageToken"))

			switch q.Get("pageToken") {
			case "":
				_, _ = w.Write([]byte(`{` + users("1", "2") + `, "nextPageToken": "t2"}`))
			case "t2":
				if refused < refuse {
					refused++

					w.WriteHeader(http.StatusUnprocessableEntity)
					_, _ = w.Write([]byte(`{"code": "invalid_page_token", "status": 422, "title": "The page token is not valid"}`))

					return
				}

				_, _ = w.Write([]byte(`{` + users("3") + `}`))
			}
		}))
		t.Cleanup(s.Close)

		c, err := clientv0.NewClient(s.URL)
		require.NoError(t, err)

		got, err := (&API{c: c, target: "x", pageSize: 2}).ListUsers(t.Context())

		return got, asked, err
	}

	ids := func(us []clientv0.User) []string {
		out := make([]string, 0, len(us))
		for _, u := range us {
			out = append(out, u.Id)
		}

		return out
	}

	got, asked, err := walkOf(t, 0)
	require.NoError(t, err)
	require.Equal(t, []string{"1", "2", "3"}, ids(got))
	require.Equal(t, []string{"2 ", "2 t2"}, asked)

	got, asked, err = walkOf(t, 1)
	require.NoError(t, err)
	require.Equal(t, []string{"1", "2", "3"}, ids(got), "the restart keeps no row twice")
	require.Equal(t, []string{"2 ", "2 t2", "2 ", "2 t2"}, asked)

	_, _, err = walkOf(t, 2)
	require.EqualError(t, err, "the server restarted while the list was read. Run the command again.")
}

// TestWalkEnds: a token that leads nowhere new is a fault of the server,
// said at once, not a walk that asks until the time is up.
func TestWalkEnds(t *testing.T) {
	t.Parallel()

	for next, want := range map[string]string{
		`"same"`: "the server at x sent a page token it had sent before, so the list would never end. This is a fault of the server.",
		`""`:     "the server at x sent an empty page token. This is a fault of the server.",
		`null`:   "the server at x sent an empty page token. This is a fault of the server.",
	} {
		var asked atomic.Int32

		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			asked.Add(1)

			_, _ = w.Write([]byte(`{"users": [{"id": "1"}], "nextPageToken": ` + next + `}`))
		}))
		t.Cleanup(s.Close)

		c, err := clientv0.NewClient(s.URL)
		require.NoError(t, err)

		_, err = (&API{c: c, target: "x", pageSize: 2}).ListUsers(t.Context())
		require.EqualError(t, err, want, next)
		require.LessOrEqual(t, asked.Load(), int32(2), next)
	}
}

// TestTimeout: cli.timeout bounds each request, not the command, and a
// request that runs out of it says what the CLI knows: a write may have
// been made, a slow page is no stopped server.
func TestTimeout(t *testing.T) {
	t.Parallel()

	const timeout = 300 * time.Millisecond

	// Each page takes half the timeout, so four of them take two.
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Headscale-Version", "dev")

		token := r.URL.Query().Get("pageToken")

		// The server is slow on purpose; a request the CLI gave up on ends
		// the wait.
		wait := func(d time.Duration) {
			select {
			case <-time.After(d):
			case <-r.Context().Done():
			}
		}

		switch {
		case r.Method == http.MethodPatch:
			wait(2 * timeout)
		case r.URL.Path == "/api/headscale/v0/users" && token == "slow":
			wait(2 * timeout)
		case r.URL.Path == "/api/headscale/v0/users":
			wait(timeout / 2)

			next := map[string]string{"": "p2", "p2": "p3", "p3": "p4"}[token]
			if r.URL.Query().Get("pageSize") == "1" && token == "p2" {
				next = "slow"
			}

			if next == "" {
				_, _ = w.Write([]byte(`{"users": [{"id": "` + token + `"}]}`)) //nolint:gosec // a test server echoes its own tokens

				return
			}

			_, _ = w.Write([]byte(`{"users": [{"id": "` + token + `"}], "nextPageToken": "` + next + `"}`)) //nolint:gosec // a test server echoes its own tokens
		}
	}))
	t.Cleanup(s.Close)

	api := func(t *testing.T, size int) *API {
		t.Helper()

		a, err := connect(&types.Config{CLI: types.CLIConfig{Address: s.URL, APIKey: "key", Timeout: timeout}},
			Env{Stderr: io.Discard, Version: types.GetVersionInfo(), PageSize: size})
		require.NoError(t, err)

		return a
	}

	target := strings.TrimPrefix(s.URL, "http://")

	start := time.Now()
	rows, err := api(t, 2).ListUsers(t.Context())
	require.NoError(t, err)
	require.Len(t, rows, 4)
	require.Greater(t, time.Since(start), timeout, "the walk took longer than one timeout and was not cut")

	_, err = api(t, 1).ListUsers(t.Context())
	require.EqualError(t, err, "the server at "+target+" did not send the next page of the list in 300ms.\n"+
		"Run the command again, or wait longer with HEADSCALE_CLI_TIMEOUT or cli.timeout.")

	_, err = api(t, 2).UpdateUser(t.Context(), "3", clientv0.UpdateUserBody{})
	require.EqualError(t, err, "the server at "+target+" did not answer the change: no answer in time.\n"+
		"The change may have been made: look before you run the command again.")
}

// guarded is an entity with a revision, as a node is.
type guarded struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Revision string `json:"revision"`
}

// TestIfMatch: a write on the target carries the target's revision, which
// the command does not pass itself; no other request does, and a server
// that holds another revision is the CLI's sentence.
func TestIfMatch(t *testing.T) {
	t.Parallel()

	var (
		mu   sync.Mutex
		seen []string
	)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()

		seen = append(seen, r.Method+" "+r.URL.Path+" "+r.Header.Get("If-Match"))
		mu.Unlock()

		w.Header().Set("Headscale-Version", "dev")

		switch {
		case r.Method == http.MethodPatch && r.Header.Get("If-Match") != `"r2"`:
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = w.Write([]byte(`{"code": "precondition_failed", "status": 412, "title": "Precondition failed", "object": {"kind": "node", "id": "12", "name": "mynode"}}`))
		case r.Method == http.MethodPatch:
			_, _ = w.Write([]byte(`{"id": "12", "name": "web", "revision": "r3"}`))
		}
	}))
	t.Cleanup(s.Close)

	type in struct {
		Node guarded `arg:"node"`
	}

	send := func(c Ctx, method, path string) error {
		_, err := call[NoOutput](c.API, func(cl *clientv0.Client) (*http.Response, error) {
			req, err := http.NewRequestWithContext(c, method, cl.Server+path, nil)
			if err != nil {
				return nil, err
			}

			return cl.Client.Do(req)
		})

		return err
	}

	lookup := cmdline.LateReader(func(_ context.Context, word string) (guarded, error) {
		return guarded{ID: "12", Name: "mynode", Revision: word}, nil
	})

	tree, err := build("prog", "A program", allowedAliases, []cmdline.Option{lookup}, New(Spec[in, NoOutput]{
		Name: "rename", Short: "S", Long: "S.", Example: []string{"prog rename r2"},
		Run: func(c Ctx, _ in) (NoOutput, error) {
			err := send(c, http.MethodPost, "other")
			if err != nil {
				return NoOutput{}, err
			}

			return NoOutput{}, send(c, http.MethodPatch, "nodes/12")
		},
		Done: func(in, NoOutput, time.Time) string { return "renamed" },
	}))
	require.NoError(t, err)

	file := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(file, nil, 0o600))

	run := func(rev string) (string, string) {
		mu.Lock()
		seen = nil
		mu.Unlock()

		var stdout, stderr bytes.Buffer

		Run(tree, []string{"rename", rev}, Env{
			Stdout: &stdout, Stderr: &stderr, Version: &types.VersionInfo{Version: "dev"},
			Environ: []string{"HEADSCALE_CONFIG=" + file, "HEADSCALE_CLI_ADDRESS=" + s.URL, "HEADSCALE_CLI_API_KEY=key"},
		})

		return stdout.String(), stderr.String()
	}

	stdout, stderr := run("r2")
	require.Empty(t, stderr)
	require.Equal(t, "renamed\n", stdout)
	require.Equal(t, []string{"GET /api/headscale/v0/version ", "POST /other ", `PATCH /nodes/12 "r2"`}, seen)

	_, stderr = run("r1")
	require.Equal(t, "Error: Node 12 (mynode) changed while the command ran. Run it again.\n", stderr)
}

// TestGuardOf: the target is the first argument that is an entity; one
// with no revision guards nothing.
func TestGuardOf(t *testing.T) {
	t.Parallel()

	type routes struct {
		Prefix netip.Prefix `arg:"prefix"`
		Node   guarded      `arg:"node"`
		Other  guarded      `arg:"other"`
	}

	require.Equal(t, &revision{id: "12", rev: "r1"}, guardOf(routes{Node: guarded{ID: "12", Revision: "r1"}, Other: guarded{ID: "13", Revision: "r9"}}))
	require.Nil(t, guardOf(routes{Node: guarded{ID: "12"}, Other: guarded{ID: "13", Revision: "r9"}}), "a target with no revision guards nothing")
	require.Nil(t, guardOf(struct {
		User clientv0.User `arg:"user"`
	}{User: clientv0.User{Id: "3"}}))
	require.Nil(t, guardOf(NoInput{}))
}
