package command

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	gotypes "go/types"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

// TestSent: a test is told every request as it leaves, with its headers:
// the GET /version before a first write, and a write that got no answer.
func TestSent(t *testing.T) {
	t.Parallel()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Headscale-Version", "dev")

		if r.URL.Path == "/api/headscale/v0/version" {
			_, _ = w.Write([]byte(`{}`))

			return
		}

		conn, _, err := http.NewResponseController(w).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	t.Cleanup(s.Close)

	var (
		mu   sync.Mutex
		sent []string
	)

	a, err := connect(&types.Config{CLI: types.CLIConfig{Address: s.URL, APIKey: "key", Timeout: time.Minute}},
		Env{Stderr: io.Discard, Version: types.GetVersionInfo(), Sent: func(req *http.Request) {
			mu.Lock()
			defer mu.Unlock()

			sent = append(sent, req.Method+" "+req.URL.Path+" "+req.Header.Get("Authorization"))
		}})
	require.NoError(t, err)

	_, err = a.UpdateUser(t.Context(), "3", clientv0.UpdateUserBody{})
	require.Error(t, err)

	mu.Lock()
	defer mu.Unlock()

	// GET /version is asked with no credential.
	require.Equal(t, []string{"GET /api/headscale/v0/version ", "PATCH /api/headscale/v0/users/3 Bearer key"}, sent)
}

// TestNotTheAPI: an answer of success that is not JSON, though it carries
// Headscale-Version, is an error, also for a call that reads no body; a 204
// has none.
func TestNotTheAPI(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name, ctype, body string
		status            int
		wantErr           bool
	}{
		{name: "a page of HTML", ctype: "text/html", body: "<html>hi</html>", status: 200, wantErr: true},
		{name: "a 201 with no body", status: 201, wantErr: true},
		{name: "JSON", ctype: "application/json", body: `{"id": "1"}`, status: 201},
		{name: "a 204", status: 204},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Headscale-Version", "dev")

				if tt.ctype != "" {
					w.Header().Set("Content-Type", tt.ctype)
				}

				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			t.Cleanup(s.Close)

			a, err := connect(&types.Config{CLI: types.CLIConfig{Address: s.URL, APIKey: "key", Timeout: time.Minute}},
				Env{Stderr: io.Discard, Version: types.GetVersionInfo()})
			require.NoError(t, err)

			// A write that reads no body, as debug create-node is.
			_, err = a.do(func(c *clientv0.Client) (*http.Response, error) { return c.DeleteNode(t.Context(), "3", nil) })
			if !tt.wantErr {
				require.NoError(t, err)

				return
			}

			require.EqualError(t, err, "the server at "+strings.TrimPrefix(s.URL, "http://")+" sent an answer this CLI cannot read: it is not JSON.")
		})
	}
}

// TestRedirect: no request follows a redirect, whatever its method and its
// status, so nothing reaches the host the answer points to; the error names
// that host by scheme and host only.
func TestRedirect(t *testing.T) {
	t.Parallel()

	calls := map[string]func(ctx context.Context, a *API) error{
		"GET": func(ctx context.Context, a *API) error { _, err := a.Me(ctx); return err },
		"POST": func(ctx context.Context, a *API) error {
			_, err := a.CreateUser(ctx, clientv0.CreateUserBody{Name: "u"})
			return err
		},
		"PATCH": func(ctx context.Context, a *API) error {
			_, err := a.UpdateUser(ctx, "3", clientv0.UpdateUserBody{})
			return err
		},
		"PUT": func(ctx context.Context, a *API) error {
			_, err := a.SetNodeTags(ctx, "3", []string{"tag:a"})
			return err
		},
		"DELETE": func(ctx context.Context, a *API) error { return a.DeleteNode(ctx, "3") },
	}

	for method, call := range calls {
		for _, status := range []int{301, 302, 303, 307, 308} {
			for _, where := range []string{"another host", "the same host", "no Location", "the version"} {
				t.Run(method+" "+strconv.Itoa(status)+" to "+where, func(t *testing.T) {
					t.Parallel()

					var other atomic.Int32

					second := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { other.Add(1) }))
					t.Cleanup(second.Close)

					first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Headscale-Version", "dev")

						if r.URL.Path == "/api/headscale/v0/version" && where != "the version" {
							return
						}

						switch where {
						case "another host", "the version":
							w.Header().Set("Location", second.URL+"/landing"+r.URL.Path)
						case "the same host":
							w.Header().Set("Location", "/landing"+r.URL.Path)
						}

						w.WriteHeader(status)
					}))
					t.Cleanup(first.Close)

					a, err := connect(&types.Config{CLI: types.CLIConfig{Address: first.URL, APIKey: "key", Timeout: time.Minute}},
						Env{Stderr: io.Discard, Version: types.GetVersionInfo()})
					require.NoError(t, err)

					host := strings.TrimPrefix(first.URL, "http://")
					want := "the server at " + host + " answered with a redirect, which this CLI does not follow."

					if where == "another host" || where == "the version" {
						want = "the server at " + host + " answered with a redirect to " + second.URL + ", which this CLI does not follow.\n" +
							"If that is the server, set it as the address: HEADSCALE_CLI_ADDRESS, or cli.address in the config."
					}

					require.EqualError(t, call(t.Context(), a), want)
					require.Zero(t, other.Load(), "a request reached the host the redirect points to")
				})
			}
		}
	}
}

// TestLostAnswer: a request whose answer the server cuts says what the
// CLI knows. A write may have been made from the moment it was sent until
// its answer is read whole, so an answer cut after its headers is a write
// that may have been made too; a dry run and a read changed nothing, and
// none of them is a server the CLI cannot connect to.
func TestLostAnswer(t *testing.T) {
	t.Parallel()

	// start is a server that hangs up on every request but the version:
	// before the headers, or after them and half of the body.
	start := func(t *testing.T, where string) string {
		t.Helper()

		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Headscale-Version", "dev")

			if r.URL.Path == "/api/headscale/v0/version" {
				return
			}

			rc := http.NewResponseController(w)

			if where == "after the headers" {
				w.Header().Set("Content-Length", "100")
				_, _ = w.Write([]byte(`{"id": "3", `))
				_ = rc.Flush()
			}

			conn, _, err := rc.Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}))
		t.Cleanup(s.Close)

		return s.URL
	}

	for _, tt := range []struct {
		name string
		call func(ctx context.Context, a *API) error
		want string
	}{
		{
			name: "a write",
			call: func(ctx context.Context, a *API) error {
				_, err := a.UpdateUser(ctx, "3", clientv0.UpdateUserBody{})

				return err
			},
			want: "the server at {host} did not answer the change: the connection was closed.\n" +
				"The change may have been made: look before you run the command again.",
		},
		{
			name: "a dry run",
			call: func(ctx context.Context, a *API) error {
				_, err := a.DeleteUser(ctx, "3", false, true)

				return err
			},
			want: "the server at {host} did not answer: the connection was closed.\nNothing was changed: run the command again.",
		},
		{
			name: "a read",
			call: func(ctx context.Context, a *API) error {
				_, err := a.Me(ctx)

				return err
			},
			want: "the server at {host} did not answer: the connection was closed.\nRun the command again.",
		},
	} {
		for _, where := range []string{"before the headers", "after the headers"} {
			t.Run(tt.name+" cut "+where, func(t *testing.T) {
				t.Parallel()

				url := start(t, where)

				a, err := connect(&types.Config{CLI: types.CLIConfig{Address: url, APIKey: "key", Timeout: time.Minute}},
					Env{Stderr: io.Discard, Version: types.GetVersionInfo()})
				require.NoError(t, err)

				require.EqualError(t, tt.call(t.Context(), a), strings.ReplaceAll(tt.want, "{host}", strings.TrimPrefix(url, "http://")))
			})
		}
	}
}

// guarded is an entity with a revision, as a node is.
type guarded struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Revision string `json:"revision"`
}

// TestIfMatch: a write on the target sends the revision the builder read
// for it; a write on another entity, and a run with no target, send none.
func TestIfMatch(t *testing.T) {
	t.Parallel()

	a := &API{}
	require.Nil(t, a.ifMatch("12"), "no target")

	a.guard.Store(guardOf(struct {
		Node guarded `arg:"node"`
	}{guarded{ID: "12", Revision: "r2"}}))
	require.Equal(t, new(`"r2"`), a.ifMatch("12"))
	require.Nil(t, a.ifMatch("13"), "another entity")
	require.Nil(t, a.expect("12"), "a revision is no token")

	a.guard.Store(&revision{id: "12", rev: "tok", token: true})
	require.Nil(t, a.ifMatch("12"), "a token is no revision")
}

// TestExpect: a write on the target sends the token the question gave, in
// place of a revision; another entity, and a run before any question, none.
func TestExpect(t *testing.T) {
	t.Parallel()

	a := &API{}
	require.Nil(t, a.expect("3"), "no question yet")

	a.guard.Store(&revision{id: "3", rev: "0123456789abcdef", token: true})
	require.Equal(t, new("0123456789abcdef"), a.expect("3"))
	require.Nil(t, a.expect("4"), "another entity")
}

// TestEveryGuardIsSent: every call of an operation that takes a guard is
// given its parameters, written out in the call, with the guard filled
// from the builder's guard for the entity the call is made on: If-Match
// with ifMatch, expect with expect, each asked for the very ID of the
// path. So a write that the server can guard always is, on the target it
// was asked for. An operation that takes none, such as update-client, gets
// none.
func TestEveryGuardIsSent(t *testing.T) {
	t.Parallel()

	guards := map[string]string{"IfMatch": "ifMatch", "Expect": "expect"}

	gen, err := parser.ParseFile(token.NewFileSet(), "../../../../gen/client/headscale/v0/client.gen.go", nil, 0)
	require.NoError(t, err)

	// takes is the guard field of each Params type that has one.
	takes := map[string]string{}

	ast.Inspect(gen, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}

		st, ok := ts.Type.(*ast.StructType)
		if ok && strings.HasSuffix(ts.Name.Name, "Params") {
			for _, f := range st.Fields.List {
				for _, name := range f.Names {
					if _, ok := guards[name.Name]; ok {
						takes[ts.Name.Name] = name.Name
					}
				}
			}
		}

		return true
	})

	// A write made on an entity sends that entity's guard. A write with no
	// entity, such as the policy, which is one document, sends no If-Match:
	// it is for a client that reads, changes and writes back.
	ops := map[string]guardOp{}

	for _, d := range gen.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || gotypes.ExprString(fn.Recv.List[0].Type) != "*Client" {
			continue
		}

		if o := guardedOp(fn, takes); o.params >= 0 {
			require.True(t, o.id >= 0 || takes[o.typ] == "IfMatch", "%s takes %s and no id to ask it for", fn.Name.Name, takes[o.typ])
			ops[fn.Name.Name] = o
		}
	}

	src, err := parser.ParseFile(token.NewFileSet(), "api.go", nil, 0)
	require.NoError(t, err)

	sent, calls, lits := map[string]int{}, 0, 0

	ast.Inspect(src, func(n ast.Node) bool {
		if lit, ok := n.(*ast.CompositeLit); ok {
			if sel, ok := lit.Type.(*ast.SelectorExpr); ok && takes[sel.Sel.Name] != "" {
				lits++
			}
		}

		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		fn, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || gotypes.ExprString(fn.X) != "c" {
			return true
		}

		o, ok := ops[fn.Sel.Name]
		if !ok {
			return true
		}

		calls++

		field := takes[o.typ]
		where := gotypes.ExprString(call)

		un, _ := call.Args[o.params].(*ast.UnaryExpr)
		require.NotNil(t, un, "%s: the parameters, which take %s, are not written out in the call", where, field)

		lit, _ := un.X.(*ast.CompositeLit)
		require.NotNil(t, lit, "%s: the parameters, which take %s, are not written out in the call", where, field)

		if o.id < 0 {
			require.False(t, setsField(lit, field), "%s has no entity and sends %s", where, field)

			return true
		}

		has := slices.ContainsFunc(lit.Elts, func(e ast.Expr) bool {
			kv, ok := e.(*ast.KeyValueExpr)
			if !ok || gotypes.ExprString(kv.Key) != field {
				return false
			}

			g, _ := kv.Value.(*ast.CallExpr)
			if g == nil || len(g.Args) != 1 {
				return false
			}

			return gotypes.ExprString(g.Fun) == "a."+guards[field] && gotypes.ExprString(g.Args[0]) == gotypes.ExprString(call.Args[o.id])
		})
		require.True(t, has, "%s takes %s and does not send a.%s(%s), the guard of the entity it is made on",
			where, field, guards[field], gotypes.ExprString(call.Args[o.id]))

		sent[field]++

		return true
	})

	require.Equal(t, lits, calls, "parameters that take a guard are made outside the call that sends them")

	for field := range guards {
		require.Positive(t, sent[field], "no operation that takes %s", field)
	}
}

// guardOp is a method of the client that takes a guard: where its id and
// its parameters are among the arguments, and their type; id is -1 for a
// write with no entity, params -1 for a method that takes no guard.
type guardOp struct {
	id, params int
	typ        string
}

// guardedOp is fn as a [guardOp]; takes is the guard field of each Params
// type that has one.
func guardedOp(fn *ast.FuncDecl, takes map[string]string) guardOp {
	o, i := guardOp{id: -1, params: -1}, 0

	for _, f := range fn.Type.Params.List {
		for _, name := range f.Names {
			if star, ok := f.Type.(*ast.StarExpr); ok && takes[gotypes.ExprString(star.X)] != "" {
				o.params, o.typ = i, gotypes.ExprString(star.X)
			}

			if name.Name == "id" {
				o.id = i
			}

			i++
		}
	}

	return o
}

// setsField reports whether lit sets field.
func setsField(lit *ast.CompositeLit, field string) bool {
	return slices.ContainsFunc(lit.Elts, func(e ast.Expr) bool {
		kv, ok := e.(*ast.KeyValueExpr)

		return ok && gotypes.ExprString(kv.Key) == field
	})
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
	require.Nil(t, guardOf(NoInput{}), "no target, no guard")
}

func TestNodeAnswerFieldNames(t *testing.T) {
	t.Parallel()

	const row = `{"hostname":"alpha","hostName":"beta","createdBy":{"loginName":"alice","logInName":"bob"}}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/headscale/v0/nodes" {
			_, _ = io.WriteString(w, `{"nodes":[`+row+`]}`)
			return
		}

		_, _ = io.WriteString(w, row)
	}))
	t.Cleanup(server.Close)

	client, err := clientv0.NewClient(server.URL)
	require.NoError(t, err)

	api := &API{c: client, pageSize: 1}
	list, err := api.ListNodes(t.Context())
	require.NoError(t, err)
	require.Len(t, list, 1)
	node, err := api.GetNode(t.Context(), "1")
	require.NoError(t, err)

	for _, got := range []clientv0.Node{list[0], node} {
		require.Equal(t, "alpha", got.Hostname)
		require.Equal(t, "alice", got.CreatedBy.GetOrEmpty().LoginName)
	}
}
