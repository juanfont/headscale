package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	gotypes "go/types"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/juanfont/headscale/client/shape"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/net/memnet"
)

// versioned is h, but a success that h gives GET /version is the 200 and
// the body of that operation, with h's headers: a fake that only sets the
// version headers passes the probe of a first write, and one that fails
// the probe still does.
func versioned(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/api/headscale/v0/version") {
			h(w, r)

			return
		}

		rec := httptest.NewRecorder()
		h(rec, r)

		maps.Copy(w.Header(), rec.Header())

		code, body := rec.Code, rec.Body.Bytes()
		if code/100 == 2 {
			w.Header().Set("Content-Type", "application/json")

			code, body = http.StatusOK, []byte(
				versionJSON(rec.Header().Get("Headscale-Version")),
			)
		}

		w.WriteHeader(code)
		_, _ = w.Write(body)
	}
}

// rowOf is the object members with every member that T requires and
// members leaves out at a zero value, as a server sends a row.
func rowOf[T any](
	members string,
) string {
	return rowOfType(reflect.TypeFor[T](), members)
}

func rowOfType(t reflect.Type, members string) string {
	var m any

	err := json.Unmarshal([]byte(members), &m)
	if err != nil {
		panic(err)
	}

	b, err := json.Marshal(merged(goodOf(t), m))
	if err != nil {
		panic(err)
	}

	return string(b)
}

// goodOf is an answer of type t with every member it requires at every
// depth, as a server sends it; a list or a map holds one item, a member
// that may be null is not.
func goodOf(t reflect.Type) any {
	if t.Kind() == reflect.Pointer ||
		t.Kind() == reflect.Map && t.Key().Kind() == reflect.Bool &&
			strings.HasPrefix(t.Name(), "Nullable[") {
		t = t.Elem()
	}

	switch {
	case t == reflect.TypeFor[time.Time]():
		return "2026-01-01T00:00:00Z"
	case t.Kind() == reflect.Struct:
		obj := map[string]any{}

		for f := range t.Fields() {
			name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name != "" && name != "-" && f.IsExported() &&
				!strings.Contains(opts, "omitempty") {
				obj[name] = goodOf(f.Type)
			}
		}

		return obj
	case t.Kind() == reflect.Slice:
		return []any{goodOf(t.Elem())}
	case t.Kind() == reflect.Map:
		return map[string]any{"k": goodOf(t.Elem())}
	case t.Kind() == reflect.String:
		return "x"
	case t.Kind() == reflect.Bool:
		return false
	case t.Kind() == reflect.Interface:
		return "x"
	}

	return 0
}

// merged is good with the members of over put in, object by object.
func merged(good, over any) any {
	g, gok := good.(map[string]any)
	o, ook := over.(map[string]any)

	if !gok || !ook {
		return over
	}

	for k, v := range o {
		g[k] = merged(g[k], v)
	}

	return g
}

// versionJSON is the body of GET /version of a server of version.
func versionJSON(version string) string {
	return `{"version": "` + version + `", "commit": "", "buildTime": "", "dirty": false, "go": {"version": "go", "os": "linux", "arch": "amd64"}}`
}

// server answers every request with the given version headers and status.
func server(t *testing.T, version, commit string, status int) string {
	t.Helper()

	s := httptest.NewServer(versioned(func(w http.ResponseWriter, _ *http.Request) {
		if version != "" {
			w.Header().Set("Headscale-Version", version)
		}

		if commit != "" {
			w.Header().Set("Headscale-Commit", commit)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(
			[]byte(
				`{"healthy": true, "databaseConnectivity": true, "warnings": [], "new": 1}`,
			),
		)
	}))
	t.Cleanup(s.Close)

	return s.URL
}

// probeTransport answers every request at once and notes each request and
// the close of each answer.
type probeTransport struct{ events []string }

type noted struct {
	io.Reader

	close func()
}

func (n noted) Close() error { n.close(); return nil }

func (p *probeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	p.events = append(p.events, r.Method)
	body := noted{
		Reader: strings.NewReader(versionJSON("0.30.1")),
		close:  func() { p.events = append(p.events, "close "+r.Method) },
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Headscale-Version": {"0.30.1"}},
		Body:       body,
		Request:    r,
	}, nil
}

// apiOf is the API of a run on url, as connect makes it, of the build own;
// warnings go to stderr.
func apiOf(tb testing.TB, url string, own *types.VersionInfo, stderr io.Writer) *API {
	tb.Helper()

	a, err := connectTest(
		&types.Config{
			CLI: types.CLIConfig{Address: url, APIKey: "key", Timeout: time.Minute},
		},
		Env{Stderr: stderr, Version: own},
	)
	require.NoError(tb, err)

	return a
}

// TestFirstWriteClosesTheProbe: the answer of GET /version is closed before
// the write goes out, which then has the connection.
func TestFirstWriteClosesTheProbe(t *testing.T) {
	t.Parallel()

	p := &probeTransport{}

	a, err := connectTest(
		&types.Config{
			CLI: types.CLIConfig{Address: "http://hs.example.com", APIKey: "key"},
		},
		Env{
			Stderr:    io.Discard,
			Version:   &types.VersionInfo{Version: "0.30.1"},
			Transport: p,
		},
	)
	require.NoError(t, err)

	c := a.ClientInterface.(*clientv0.Client).Client //nolint:forcetypeassert // the generated client

	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"http://hs.example.com/x",
		nil,
	)
	require.NoError(t, err)

	resp, err := c.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(
		t,
		[]string{
			http.MethodGet,
			"close " + http.MethodGet,
			http.MethodPost,
			"close " + http.MethodPost,
		},
		p.events,
	)
}

// TestAnswerFieldNames: an answer is read by the exact member names, also
// inside a nullable object; one that differs in case only is no field.
func TestAnswerFieldNames(t *testing.T) {
	t.Parallel()

	s := httptest.NewServer(versioned(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(
			w,
			rowOf[clientv0.Me](
				`{"credential":{"id":"7","Id":"8","kind":"api_key"},"principal":{"kind":"user","Kind":"node"}}`,
			),
		)
	}))
	t.Cleanup(s.Close)

	got, err := me(t.Context(), bare(t, s.URL, maxPage))
	require.NoError(t, err)

	cred, err := got.Credential.Get()
	require.NoError(t, err)
	require.Equal(
		t,
		[]string{"7", "user"},
		[]string{cred.Id, string(got.Principal.Kind)},
	)
}

// TestPageFieldNames: a row of a walk is read by the exact member names.
func TestPageFieldNames(t *testing.T) {
	t.Parallel()

	s := httptest.NewServer(versioned(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(
			w,
			`{"users":[`+rowOf[clientv0.User](
				`{"id":"1","name":"alpha","Name":"beta","ID":"2"}`,
			)+`]}`,
		)
	}))
	t.Cleanup(s.Close)

	users, err := listUsers(t.Context(), bare(t, s.URL, 1))
	require.NoError(t, err)
	require.Len(t, users, 1)
	require.Equal(t, []string{"1", "alpha"}, []string{users[0].Id, users[0].Name})
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

			a := apiOf(
				t,
				server(t, tt.server, tt.commit, tt.status),
				&types.VersionInfo{Version: tt.own, Commit: tt.ownCommit},
				&stderr,
			)
			a.target = "hs.example.com"

			// Twice: a warning is printed once per run.
			for range 2 {
				h, err := health(context.Background(), a)
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

// TestEmptyAnswer: an answer with no body is NoOutput, as a 204 is, and
// no answer of v0 for a call that reads an object: a create through a
// proxy that answers 204 made its credential, and its secret is lost.
func TestEmptyAnswer(t *testing.T) {
	t.Parallel()

	s := httptest.NewServer(versioned(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Headscale-Version", "dev")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(s.Close)

	a := apiOf(t, s.URL, &types.VersionInfo{Version: "dev"}, io.Discard)
	a.target = "hs.example.com"

	_, err := callOf[NoOutput, anySuccess](
		a,
		func(c *clientv0.Client) (*http.Response, error) { return c.GetMe(t.Context()) },
	)
	require.NoError(t, err)

	_, err = me(t.Context(), a)
	require.EqualError(
		t,
		err,
		"the server at hs.example.com sent an answer this CLI cannot read: it is 204 No Content, not the 200 OK this operation answers.",
	)
}

// TestFaultAfterWrite: a 5xx that answers a write may come after the
// change, so a Secret command says where to find the credential; one that
// answers a read changed nothing.
func TestFaultAfterWrite(t *testing.T) {
	t.Parallel()

	s := httptest.NewServer(versioned(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Headscale-Version", "dev")

		// GET /version before the write must succeed, or nothing is sent.
		if r.URL.Path == "/api/headscale/v0/version" {
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code": "internal", "status": 500, "title": "x"}`))
	}))
	t.Cleanup(s.Close)

	a := apiOf(t, s.URL, &types.VersionInfo{Version: "dev"}, io.Discard)
	a.target = "hs.example.com"

	var fault *faultAfterWriteError

	_, err := createUser(t.Context(), a, "x")
	require.ErrorAs(t, err, &fault)

	var p *ProblemError
	require.ErrorAs(t, err, &p, "the problem is said as before")

	_, err = me(t.Context(), a)
	require.Error(t, err)
	require.NotErrorAs(t, err, &fault)
}

// TestConnectError: the message says what was wrong, and names the host
// as the operator knows it.
func TestConnectError(t *testing.T) {
	t.Parallel()

	remote := func(t *testing.T, url string) error {
		t.Helper()

		a, err := connectTest(
			&types.Config{CLI: types.CLIConfig{Address: url, APIKey: "key"}},
			Env{Stderr: io.Discard, Version: types.GetVersionInfo()},
		)
		require.NoError(t, err)

		_, err = health(t.Context(), a)

		return err
	}

	t.Run("a socket the user may not open fails at once", func(t *testing.T) {
		t.Parallel()

		// A short path: a socket path has a small limit.
		//nolint:usetesting // t.TempDir is longer than a socket path may be
		dir, err := os.MkdirTemp("", "hs")
		require.NoError(t, err)
		t.Cleanup(func() { os.RemoveAll(dir) })

		path := filepath.Join(dir, "headscale.sock")
		l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
		require.NoError(t, err)
		t.Cleanup(func() { l.Close() })
		require.NoError(t, os.Chmod(path, 0))

		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		a, err := connectTest(
			&types.Config{
				UnixSocket: path,
				CLI:        types.CLIConfig{Timeout: 5 * time.Second},
			},
			Env{Stderr: io.Discard, Version: types.GetVersionInfo()},
		)
		require.NoError(t, err)

		_, err = health(ctx, a)
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Skipf("this process may open a socket of mode 0, as root may: %v", err)
		}

		require.NoError(t, ctx.Err(), "retried until the time was up")
		require.EqualError(
			t,
			err,
			"cannot connect to "+path+": permission denied.\nRun it as a user that may open the socket, or use HEADSCALE_CLI_ADDRESS.",
		)
	})

	t.Run("a socket that is not there names the cause", func(t *testing.T) {
		t.Parallel()

		a, err := connectTest(
			&types.Config{UnixSocket: "/nonexistent/headscale.sock"},
			Env{Stderr: io.Discard, Version: types.GetVersionInfo()},
		)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()

		_, err = health(ctx, a)
		require.EqualError(
			t,
			err,
			"cannot connect to /nonexistent/headscale.sock: no such file or directory\n"+
				"Is headscale running? To use another server:\n  --config <file>, HEADSCALE_UNIX_SOCKET, or HEADSCALE_CLI_ADDRESS",
		)
	})

	t.Run("a certificate that is not trusted is no stopped server", func(t *testing.T) {
		t.Parallel()

		s := httptest.NewTLSServer(http.NotFoundHandler())
		t.Cleanup(s.Close)

		err := remote(t, s.URL)
		require.ErrorContains(
			t,
			err,
			"cannot connect to "+strings.TrimPrefix(
				s.URL,
				"https://",
			)+": tls: failed to verify certificate",
		)
		require.NotContains(t, err.Error(), "Is headscale running?")
	})

	t.Run("the host has no scheme", func(t *testing.T) {
		t.Parallel()

		s := httptest.NewServer(http.NotFoundHandler())
		t.Cleanup(s.Close)

		require.EqualError(
			t,
			remote(t, s.URL),
			"the server at "+strings.TrimPrefix(
				s.URL,
				"http://",
			)+" is too old for this CLI.\nIt has no /api/headscale/v0.",
		)
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

		s := httptest.NewServer(versioned(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()

			seen = append(seen, r.Method+" "+r.URL.Path)
			mu.Unlock()
			w.Header().Set("Headscale-Version", version)
		}))
		t.Cleanup(s.Close)

		a := apiOf(t, s.URL, &types.VersionInfo{Version: "0.30.1"}, io.Discard)
		c := a.ClientInterface.(*clientv0.Client).Client //nolint:forcetypeassert // the generated client

		var err error

		for _, m := range methods {
			req, rerr := http.NewRequestWithContext(t.Context(), m, s.URL+"/x", nil)
			require.NoError(t, rerr)

			var resp *http.Response

			resp, err = c.Do(req)
			if err != nil {
				err = a.errorOf(err)

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
	require.Equal(
		t,
		[]string{"GET /api/headscale/v0/version", "POST /x", "POST /x"},
		seen,
	)

	seen, err = run(t, "0.30.2", http.MethodGet, http.MethodDelete)
	require.NoError(t, err)
	require.Equal(t, []string{"GET /x", "DELETE /x"}, seen)

	seen, err = run(t, "0.29.0", http.MethodPost)
	require.ErrorContains(t, err, "this headscale is 0.30.1, the server is 0.29.0.")
	require.Equal(t, []string{"GET /api/headscale/v0/version"}, seen)
}

// TestMount: a server under a path of a proxy is asked GET /version under
// that path too, with or without a closing slash.
func TestMount(t *testing.T) {
	t.Parallel()

	for _, mount := range []string{"/mounted", "/mounted/"} {
		var (
			mu   sync.Mutex
			seen []string
		)

		s := httptest.NewServer(versioned(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()

			seen = append(seen, r.Method+" "+r.URL.Path)
			mu.Unlock()
			w.Header().Set("Headscale-Version", "dev")
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(s.Close)

		a, err := connectTest(
			&types.Config{
				CLI: types.CLIConfig{
					Address: s.URL + mount,
					APIKey:  "key",
					Timeout: time.Minute,
				},
			},
			Env{Stderr: io.Discard, Version: types.GetVersionInfo()},
		)
		require.NoError(t, err)

		err = a.send(
			documented[anySuccess](),
			func(c *clientv0.Client) (*http.Response, error) {
				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					s.URL+"/mounted/x",
					nil,
				)
				if err != nil {
					return nil, err
				}

				return c.Client.Do(req)
			},
		)
		require.NoError(t, err)

		mu.Lock()
		require.Equal(
			t,
			[]string{"GET /mounted/api/headscale/v0/version", "POST /mounted/x"},
			seen,
			mount,
		)
		mu.Unlock()
	}
}

// TestProbeCredential: GET /version before a first write carries the
// write's credential, for a proxy that guards every path.
func TestProbeCredential(t *testing.T) {
	t.Parallel()

	var (
		mu   sync.Mutex
		auth []string
	)

	s := httptest.NewServer(versioned(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()

		auth = append(auth, r.Method+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Headscale-Version", "dev")
	}))
	t.Cleanup(s.Close)

	a := apiOf(t, s.URL, &types.VersionInfo{Version: "dev"}, io.Discard)
	c := a.ClientInterface.(*clientv0.Client).Client //nolint:forcetypeassert // the generated client

	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		s.URL+"/x",
		nil,
	)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer key")

	resp, err := c.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	require.Equal(t, []string{"GET Bearer key", "POST Bearer key"}, auth)
}

// TestProbeRefused: an error answer to GET /version, though it carries
// the CLI's own version, sends no write; the error is that answer's
// problem, and the next write asks again.
func TestProbeRefused(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusServiceUnavailable, http.StatusInternalServerError, http.StatusNotFound, http.StatusUnauthorized} {
		var (
			mu   sync.Mutex
			seen []string
		)

		s := httptest.NewServer(versioned(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()

			seen = append(seen, r.Method+" "+r.URL.Path)
			mu.Unlock()
			w.Header().Set("Headscale-Version", "dev")
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(status)
			_, _ = w.Write(
				[]byte(
					`{"code":"unavailable","title":"x","status":` + strconv.Itoa(
						status,
					) + `}`,
				),
			)
		}))
		t.Cleanup(s.Close)

		a, err := connectTest(
			&types.Config{
				CLI: types.CLIConfig{
					Address: s.URL,
					APIKey:  "key",
					Timeout: time.Minute,
				},
			},
			Env{Stderr: io.Discard, Version: types.GetVersionInfo()},
		)
		require.NoError(t, err)

		for range 2 {
			err = a.send(
				documented[anySuccess](),
				func(c *clientv0.Client) (*http.Response, error) {
					req, err := http.NewRequestWithContext(
						t.Context(),
						http.MethodPost,
						s.URL+"/x",
						nil,
					)
					if err != nil {
						return nil, err
					}

					return c.Client.Do(req)
				},
			)
			_, problem := errors.AsType[*ProblemError](err)
			require.True(t, problem, "%d: %v", status, err)
		}

		mu.Lock()
		require.Equal(
			t,
			[]string{"GET /api/headscale/v0/version", "GET /api/headscale/v0/version"},
			seen,
			status,
		)
		mu.Unlock()
	}
}

// TestProbeNotTheVersion: a success to GET /version that is not that
// operation's answer, though it carries the CLI's own version, sends no
// write.
func TestProbeNotTheVersion(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct{ name, body, want string }{
		{name: "a page of HTML", body: "<html>sign in</html>", want: "it is not JSON."},
		{name: "another object", body: `{"healthy": true}`, want: "it has no buildTime."},
		{name: "a version whose go is empty", body: `{"version": "v", "commit": "", "buildTime": "", "dirty": false, "go": {}}`, want: "it has no go.arch."},
	} {
		var (
			mu   sync.Mutex
			seen []string
		)

		s := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()

				seen = append(seen, r.Method+" "+r.URL.Path)
				mu.Unlock()
				w.Header().Set("Headscale-Version", types.GetVersionInfo().Version)
				_, _ = w.Write([]byte(tt.body))
			}),
		)
		t.Cleanup(s.Close)

		a, err := connectTest(
			&types.Config{
				CLI: types.CLIConfig{
					Address: s.URL,
					APIKey:  "key",
					Timeout: time.Minute,
				},
			},
			Env{Stderr: io.Discard, Version: types.GetVersionInfo()},
		)
		require.NoError(t, err)

		err = a.send(
			documented[anySuccess](),
			func(c *clientv0.Client) (*http.Response, error) {
				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					s.URL+"/x",
					nil,
				)
				if err != nil {
					return nil, err
				}

				return c.Client.Do(req)
			},
		)
		require.ErrorContains(
			t,
			err,
			"the server at "+strings.TrimPrefix(
				s.URL,
				"http://",
			)+" sent an answer this CLI cannot read: "+tt.want,
			tt.name,
		)

		mu.Lock()
		require.Equal(t, []string{"GET /api/headscale/v0/version"}, seen, tt.name)
		mu.Unlock()
	}
}

// anySuccess is the generated answer of an operation that names 200, 201
// and 204 for success, for a case that tests something other than the
// status.
type anySuccess struct {
	JSON200, JSON201 *struct{}
	Headers204       *struct{}
}

// shaped is an object of the API as the client has it: a member the
// document requires, and one it does not.
type shaped struct {
	ID   string  `json:"id"`
	Note *string `json:"note,omitempty"`
}

// TestShape: a success is taken only in the shape the operation's document
// gives: no body for NoOutput, and for any other type a JSON object with
// every member the type requires. A member this build does not know is
// kept.
func TestShape(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name   string
		method string
		none   bool
		dryRun bool
		status int
		body   string
		want   string
		// notWant is a text the refusal must not hold.
		notWant string
	}{
		{name: "an object with every member", status: 200, body: `{"id": "1"}`},
		{name: "a member this build does not know", status: 200, body: `{"id": "1", "new": 1}`},
		{name: "a member this build does not know, beyond float64", status: 200, body: `{"id": "1", "new": 1e309, "deep": [{"n": -1E+400}]}`},
		{name: "a 204 for an object", status: 204, want: "it has no body."},
		{name: "null", status: 200, body: "null", want: "it is not an object."},
		{name: "another object", status: 200, body: `{"healthy": true}`, want: "it has no id."},
		{name: "a problem in a 200", status: 200, body: `{"status": 403, "title": "Access denied"}`, want: "it has no id."},
		{name: "a 204 for no output", none: true, status: 204},
		{name: "a body for no output", none: true, status: 201, body: `{"id": "1"}`, want: "it is not the 204 No Content this operation answers."},
		{name: "a write answered null", method: http.MethodPost, status: 201, body: "null", want: "it is not an object.\nThe change may have been made"},
		// What the type refuses is refused while the request is at hand, so
		// a write keeps the lines of a change that may have been made.
		{name: "a write answered with a member of another type", method: http.MethodPost, status: 201, body: `{"id": 3}`, want: "\nThe change may have been made"},
		{name: "a write answered with a required member null", method: http.MethodPost, status: 201, body: `{"id": null}`, want: "its id is null.\nThe change may have been made"},
		// Left out is absent: a null is no string of its type.
		{name: "a member that may be left out, null", status: 200, body: `{"id": "1", "note": null}`, want: "its note is null."},
		{name: "a dry run answered with a member of another type", method: http.MethodPost, dryRun: true, status: 200, body: `{"id": 3}`, notWant: "The change may have been made"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := httptest.NewServer(
				versioned(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Headscale-Version", "dev")
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tt.status)
					_, _ = w.Write([]byte(tt.body))
				}),
			)
			t.Cleanup(s.Close)

			a, err := connectTest(
				&types.Config{
					CLI: types.CLIConfig{
						Address: s.URL,
						APIKey:  "key",
						Timeout: time.Minute,
					},
				},
				Env{Stderr: io.Discard, Version: types.GetVersionInfo()},
			)
			require.NoError(t, err)

			send := func(c *clientv0.Client) (*http.Response, error) {
				method := tt.method
				if method == "" {
					method = http.MethodGet
				}

				url := s.URL + "/x"
				if tt.dryRun {
					url += "?dryRun=true"
				}

				req, err := http.NewRequestWithContext(t.Context(), method, url, nil)
				if err != nil {
					return nil, err
				}

				return c.Client.Do(req)
			}

			if tt.none {
				_, err = callOf[NoOutput, anySuccess](a, send)
			} else {
				_, err = callOf[shaped, anySuccess](a, send)
			}

			if tt.notWant != "" {
				require.ErrorContains(t, err, "sent an answer this CLI cannot read: ")
				require.NotContains(t, err.Error(), tt.notWant)

				return
			}

			if tt.want == "" {
				require.NoError(t, err)

				return
			}

			require.ErrorContains(t, err, "sent an answer this CLI cannot read: ")
			require.ErrorContains(t, err, tt.want)
		})
	}
}

// noContent is the generated answer of an operation that names only 204.
type noContent struct{ Headers204 *struct{} }

// TestStatus: a success is taken only with a status that the document of
// the operation names, whatever its body; the refusal names both, and a
// write gets the lines of a change that may have been made.
func TestStatus(t *testing.T) {
	t.Parallel()

	const (
		healthy = `{"healthy": true, "databaseConnectivity": true, "warnings": []}`
		written = "\nThe change may have been made: look before you run the command again."
	)

	getHealth := func(a *API) error { _, err := health(t.Context(), a); return err }
	getMe := func(a *API) error { _, err := me(t.Context(), a); return err }
	remove := func(a *API) error {
		_, err := callOf[NoOutput, noContent](
			a,
			func(c *clientv0.Client) (*http.Response, error) {
				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodDelete,
					c.Server+"x",
					nil,
				)
				if err != nil {
					return nil, err
				}

				return c.Client.Do(req)
			},
		)

		return err
	}

	removeNode := func(a *API) error { return deleteNode(t.Context(), a, "3") }
	readNode := func(a *API) error { _, err := getNode(t.Context(), a, "3"); return err }

	for _, tt := range []struct {
		name   string
		call   func(*API) error
		status int
		body   string
		want   string
	}{
		{name: "GET /health, 200", call: getHealth, status: 200, body: healthy},
		{name: "GET /health, 201", call: getHealth, status: 201, body: healthy, want: "it is 201 Created, not the 200 OK this operation answers."},
		{name: "GET /health, 206", call: getHealth, status: 206, body: healthy, want: "it is 206 Partial Content, not the 200 OK this operation answers."},
		{name: "GET /health, warnings null", call: getHealth, status: 200, body: `{"healthy": true, "databaseConnectivity": true, "warnings": null}`, want: "its warnings is null."},
		// An item of a list of a declared type is held to that type.
		{name: "GET /me, a scope null", call: getMe, status: 200, body: rowOf[clientv0.Me](`{"authorization": {"scopes": ["users", null]}}`), want: "its authorization.scopes[1] is null."},
		{name: "GET /me, a scope of another kind", call: getMe, status: 200, body: rowOf[clientv0.Me](`{"authorization": {"scopes": [5]}}`), want: "json: cannot unmarshal number into Me.authorization.scopes.0 of type string."},
		// The details of a warning are free members: null is a value there.
		{name: "GET /health, a warning whose details hold a null", call: getHealth, status: 200, body: `{"healthy": true, "databaseConnectivity": true, "warnings": [{"code": "c", "message": "m", "details": {"reason": null, "deep": {"x": null}}}]}`},
		{name: "GET /health, a warning whose details hold a big number", call: getHealth, status: 200, body: `{"healthy": true, "databaseConnectivity": true, "warnings": [{"code": "c", "message": "m", "details": {"n": 1e400}}]}`},
		{name: "a delete, 204", call: remove, status: 204},
		{name: "a delete, 200", call: remove, status: 200, body: `{}`, want: "it is 200 OK, not the 204 No Content this operation answers." + written},
		{name: "a delete, 202", call: remove, status: 202, body: `{}`, want: "it is 202 Accepted, not the 204 No Content this operation answers." + written},
		{name: "a delete, 206 that is not JSON", call: remove, status: 206, body: "<html>", want: "it is 206 Partial Content, not the 204 No Content this operation answers." + written},
		{name: "DELETE /nodes/3, 204", call: removeNode, status: 204},
		// The values of attributes are strings (map[string]string): a null
		// is not one, though the typed decode would read it as "".
		{name: "GET /nodes/3, an attribute null", call: readNode, status: 200, body: rowOf[clientv0.Node](`{"id": "3", "attributes": {"rack": null}}`), want: `its attributes["rack"] is null.`},
		{name: "GET /nodes/3, an attribute of another kind", call: readNode, status: 200, body: rowOf[clientv0.Node](`{"id": "3", "attributes": {"rack": 5}}`), want: "json: cannot unmarshal number into Go struct field Node.attributes.rack of type string."},
		{name: "GET /nodes/3, an attribute", call: readNode, status: 200, body: rowOf[clientv0.Node](`{"id": "3", "attributes": {"rack": "top"}}`)},
		{name: "DELETE /nodes/3, 200", call: removeNode, status: 200, body: `{"id": "3"}`, want: "it is 200 OK, not the 204 No Content this operation answers." + written},
		{name: "DELETE /nodes/3, 201", call: removeNode, status: 201, body: `{"id": "3"}`, want: "it is 201 Created, not the 204 No Content this operation answers." + written},
		{name: "DELETE /nodes/3, 202", call: removeNode, status: 202, body: `{"id": "3"}`, want: "it is 202 Accepted, not the 204 No Content this operation answers." + written},
		{name: "DELETE /nodes/3, 206", call: removeNode, status: 206, body: `{"id": "3"}`, want: "it is 206 Partial Content, not the 204 No Content this operation answers." + written},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := httptest.NewServer(
				versioned(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Headscale-Version", "dev")
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tt.status)
					_, _ = w.Write([]byte(tt.body))
				}),
			)
			t.Cleanup(s.Close)

			a, err := connectTest(
				&types.Config{
					CLI: types.CLIConfig{
						Address: s.URL,
						APIKey:  "key",
						Timeout: time.Minute,
					},
				},
				Env{Stderr: io.Discard, Version: types.GetVersionInfo()},
			)
			require.NoError(t, err)

			err = tt.call(a)
			if tt.want == "" {
				require.NoError(t, err)

				return
			}

			require.EqualError(
				t,
				err,
				"the server at "+strings.TrimPrefix(
					s.URL,
					"http://",
				)+" sent an answer this CLI cannot read: "+tt.want,
			)
		})
	}
}

// TestPages: every page of every list of the API, found by walking the
// generated client for an answer that is a page, is read by the one rule:
// the rows are a list, each row an object of the row's type with every
// required member there and not null, the token a string. A list of the
// document that the CLI calls (a method of API of the same name) and this
// test does not cover fails here.
func TestPages(t *testing.T) {
	t.Parallel()

	client := reflect.TypeFor[clientv0.ClientWithResponsesInterface]()
	api := reflect.TypeFor[*API]()
	tested := 0

	for m := range client.Methods() {
		op := strings.TrimSuffix(m.Name, "WithResponse")

		answer := m.Type.Out(0).Elem()

		ok200, ok := answer.FieldByName("JSON200")
		if !ok || ok200.Type.Elem().Kind() != reflect.Struct {
			continue
		}

		pageType := ok200.Type.Elem()
		if _, paged := pageType.FieldByName("NextPageToken"); !paged {
			continue
		}

		call, _ := api.MethodByName(op + "All")

		if !call.Func.IsValid() {
			continue // the CLI does not call this list yet
		}

		var items, required string

		var rowType reflect.Type

		for f := range pageType.Fields() {
			if f.Type.Kind() == reflect.Slice {
				items, _, _ = strings.Cut(f.Tag.Get("json"), ",")
				rowType = f.Type.Elem()
			}
		}

		var nonNull string

		for f := range rowType.Fields() {
			name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
			if strings.Contains(opts, "omitempty") {
				continue
			}

			if required == "" {
				required = name
			}

			if nonNull == "" && !strings.HasPrefix(f.Type.Name(), "Nullable[") {
				nonNull = name
			}
		}

		row := rowOfType(rowType, `{}`)
		nulled := rowOfType(rowType, `{"`+nonNull+`": null}`)

		for _, tt := range []struct{ name, body, want string }{
			{"a good page", `{"` + items + `": [` + row + `]}`, ""},
			{"an empty page", `{"` + items + `": []}`, ""},
			{"a member this build does not know", `{"` + items + `": [` + row + `], "new": 1}`, ""},
			{"the rows null", `{"` + items + `": null}`, "its " + items + " is null."},
			{"no rows member", `{}`, "it has no " + items + "."},
			{"the rows an object", `{"` + items + `": {}}`, "its " + items + " is not a list."},
			{"a row null", `{"` + items + `": [null]}`, "its " + items + "[0] is null."},
			{"a row empty", `{"` + items + `": [{}]}`, "it has no " + items + "[0]." + required + "."},
			{"a row whose required member is null", `{"` + items + `": [` + row + `, ` + nulled + `]}`, "its " + items + "[1]." + nonNull + " is null."},
			{"a token not a string", `{"` + items + `": [], "nextPageToken": 3}`, "its nextPageToken is not a string."},
			// A page that is no object is no page, whatever the walk would
			// read of its token.
			{"a list", `[]`, "it is not an object."},
			{"a number", `17`, "it is not an object."},
			{"no body", ``, "it is not JSON."},
			{"not JSON", `{`, "it is not JSON."},
		} {
			t.Run(op+"/"+tt.name, func(t *testing.T) {
				t.Parallel()

				s := httptest.NewServer(
					versioned(func(w http.ResponseWriter, _ *http.Request) {
						w.Header().Set("Headscale-Version", "dev")
						_, _ = w.Write([]byte(tt.body))
					}),
				)
				t.Cleanup(s.Close)

				a, err := connectTest(
					&types.Config{
						CLI: types.CLIConfig{
							Address: s.URL,
							APIKey:  "key",
							Timeout: time.Minute,
						},
					},
					Env{Stderr: io.Discard, Version: types.GetVersionInfo()},
				)
				require.NoError(t, err)

				args := []reflect.Value{
					reflect.ValueOf(a),
					reflect.ValueOf(t.Context()),
				}
				// The variadic request editors are left out.
				for i := 2; i < call.Type.NumIn()-1; i++ {
					args = append(args, reflect.Zero(call.Type.In(i)))
				}

				out := call.Func.Call(args)
				err, _ = reflect.TypeAssert[error](out[1])
				err = a.errorOf(err)

				if tt.want == "" {
					require.NoError(t, err)

					return
				}

				require.EqualError(
					t,
					err,
					"the server at "+strings.TrimPrefix(
						s.URL,
						"http://",
					)+" sent an answer this CLI cannot read: "+tt.want,
				)
			})
		}

		tested++
	}

	require.Positive(t, tested, "no list of the document is called by the CLI")
}

// TestWalk: a walk asks for its page size, reads every page, and starts
// again once when the server refuses a token, as after a restart.
func TestWalk(t *testing.T) {
	t.Parallel()

	users := func(ids ...string) string {
		rows := make([]string, 0, len(ids))
		for _, id := range ids {
			rows = append(
				rows,
				rowOf[clientv0.User](`{"id": "`+id+`", "name": "u`+id+`"}`),
			)
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

		s := httptest.NewServer(versioned(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()

			q := r.URL.Query()
			asked = append(asked, q.Get("pageSize")+" "+q.Get("pageToken"))

			switch q.Get("pageToken") {
			case "":
				_, _ = w.Write(
					[]byte(`{` + users("1", "2") + `, "nextPageToken": "t2"}`),
				)
			case "t2":
				if refused < refuse {
					refused++

					w.WriteHeader(http.StatusUnprocessableEntity)
					_, _ = w.Write(
						[]byte(
							`{"code": "invalid_page_token", "status": 422, "title": "The page token is not valid"}`,
						),
					)

					return
				}

				_, _ = w.Write([]byte(`{` + users("3") + `}`))
			}
		}))
		t.Cleanup(s.Close)

		got, err := listUsers(t.Context(), bare(t, s.URL, 2))

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
	require.Equal(
		t,
		[]string{"1", "2", "3"},
		ids(got),
		"the restart keeps no row twice",
	)
	require.Equal(t, []string{"2 ", "2 t2", "2 ", "2 t2"}, asked)

	_, _, err = walkOf(t, 2)
	require.EqualError(
		t,
		err,
		"the server restarted while the list was read. Run the command again.",
	)
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

		s := httptest.NewServer(versioned(func(w http.ResponseWriter, _ *http.Request) {
			asked.Add(1)

			_, _ = w.Write(
				[]byte(
					`{"users": [` + rowOf[clientv0.User](
						`{"id": "1"}`,
					) + `], "nextPageToken": ` + next + `}`,
				),
			)
		}))
		t.Cleanup(s.Close)

		_, err := listUsers(t.Context(), bare(t, s.URL, 2))
		require.EqualError(t, err, want, next)

		require.LessOrEqual(t, asked.Load(), int32(2), next)
	}
}

// TestTimeout: cli.timeout bounds each request, not the command, and a
// request that runs out of it says what the CLI knows: a write may have
// been made, a slow page is no stopped server. The client and the server
// run in a synctest bubble over an in-memory network, so time passes only
// when both wait: every margin below is exact on a machine of any speed.
func TestTimeout(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		const timeout = 300 * time.Millisecond

		// Each page takes half the timeout, so four of them take two.
		ln := memnet.Listen("hs.test:80")
		//nolint:gosec // an in-memory server, on a fake clock
		s := &http.Server{
			Handler: versioned(func(w http.ResponseWriter, r *http.Request) {
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
				case r.URL.Path == "/api/headscale/v0/version":
					wait(2 * timeout / 3)
				case r.Method == http.MethodPost && r.URL.Path == "/api/headscale/v0/users":
					wait(2 * timeout / 3)

					w.WriteHeader(http.StatusCreated)
					_ = json.NewEncoder(w).
						Encode(clientv0.User{Id: "3", Name: "alice", Nodes: []clientv0.NodeReference{}})
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
						//nolint:gosec // a test server echoes its own tokens
						_, _ = w.Write(
							[]byte(
								`{"users": [` + rowOf[clientv0.User](
									`{"id": "`+token+`"}`,
								) + `]}`,
							),
						)

						return
					}

					//nolint:gosec // a test server echoes its own tokens
					_, _ = w.Write(
						[]byte(
							`{"users": [` + rowOf[clientv0.User](
								`{"id": "`+token+`"}`,
							) + `], "nextPageToken": "` + next + `"}`,
						),
					)
				}
			}),
		}

		go func() { _ = s.Serve(ln) }()

		// Every goroutine of the bubble must end before it does.
		defer s.Close()

		api := func(t *testing.T, size int) *API {
			t.Helper()

			a, err := connectTest(
				&types.Config{
					CLI: types.CLIConfig{
						Address: "http://hs.test",
						APIKey:  "key",
						Timeout: timeout,
					},
				},
				Env{
					Stderr:    io.Discard,
					Version:   types.GetVersionInfo(),
					PageSize:  size,
					Transport: &http.Transport{DialContext: ln.Dial},
				},
			)
			require.NoError(t, err)

			return a
		}

		start := time.Now()
		rows, err := listUsers(t.Context(), api(t, 2))
		require.NoError(t, err)
		require.Len(t, rows, 4)
		require.Equal(
			t,
			2*timeout,
			time.Since(start),
			"the walk took longer than one timeout and was not cut",
		)

		start = time.Now()
		_, err = listUsers(t.Context(), api(t, 1))
		require.EqualError(
			t,
			err,
			"the server at hs.test did not send the next page of the list in 300ms.\n"+
				"Run the command again, or wait longer with HEADSCALE_CLI_TIMEOUT or cli.timeout.",
		)
		require.Equal(
			t,
			2*timeout,
			time.Since(start),
			"two pages, then the slow one cut at its own timeout",
		)

		start = time.Now()
		err = updateUser(t.Context(), api(t, 2))
		require.EqualError(
			t,
			err,
			"the server at hs.test did not answer the change: no answer in time.\n"+
				"The change may have been made: look before you run the command again.",
		)
		require.Equal(
			t,
			2*timeout/3+timeout,
			time.Since(start),
			"the probe, then the change cut at its own timeout",
		)

		start = time.Now()
		user, err := createUser(t.Context(), api(t, 2), "alice")
		require.NoError(t, err, "the probe and the write each get their own timeout")
		require.Equal(t, "3", user.Id)
		require.Equal(
			t,
			4*timeout/3,
			time.Since(start),
			"the probe and the write each took two thirds of the timeout",
		)

		// The same holds for a command, which run connects: a walk and then
		// a write take longer than one timeout together and are not cut.
		tree, err := Build("prog", "A program", New(Spec[NoInput, NoOutput]{
			Name: "sync", Short: "Sync", Long: "Sync.", Example: []string{"prog sync"},
			Run: func(c Ctx, _ NoInput) (NoOutput, error) {
				_, err := listUsers(c, c.API)
				if err != nil {
					return NoOutput{}, err
				}

				_, err = createUser(c, c.API, "alice")

				return NoOutput{}, err
			},
		}))
		require.NoError(t, err)

		file := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(file, nil, 0o600))

		var stderr bytes.Buffer

		start = time.Now()
		code := Run(tree, []string{"sync"}, Env{
			Stdout:    io.Discard,
			Stderr:    &stderr,
			PageSize:  2,
			Transport: &http.Transport{DialContext: ln.Dial},
			Environ: []string{
				"HEADSCALE_CONFIG=" + file,
				"HEADSCALE_CLI_ADDRESS=http://hs.test",
				"HEADSCALE_CLI_API_KEY=key",
				"HEADSCALE_CLI_TIMEOUT=300ms",
			},
		})
		require.Empty(t, stderr.String())
		require.Zero(t, code)
		require.Equal(
			t,
			2*timeout+2*timeout/3,
			time.Since(start),
			"four pages and the write, which the walk's answers spared the probe",
		)
	})
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

		s := httptest.NewServer(versioned(func(w http.ResponseWriter, r *http.Request) {
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
			call: updateUser,
			want: "the server at {host} did not answer the change: the connection was closed.\n" +
				"The change may have been made: look before you run the command again.",
		},
		{
			name: "a dry run",
			call: func(ctx context.Context, a *API) error {
				return deleteUser(ctx, a, "3", true)
			},
			want: "the server at {host} did not answer: the connection was closed.\nNothing was changed: run the command again.",
		},
		{
			name: "a read",
			call: func(ctx context.Context, a *API) error {
				_, err := me(ctx, a)

				return err
			},
			want: "the server at {host} did not answer: the connection was closed.\nRun the command again.",
		},
	} {
		for _, where := range []string{"before the headers", "after the headers"} {
			t.Run(tt.name+" cut "+where, func(t *testing.T) {
				t.Parallel()

				url := start(t, where)

				a, err := connectTest(
					&types.Config{
						CLI: types.CLIConfig{
							Address: url,
							APIKey:  "key",
							Timeout: time.Minute,
						},
					},
					Env{Stderr: io.Discard, Version: types.GetVersionInfo()},
				)
				require.NoError(t, err)

				require.EqualError(
					t,
					tt.call(t.Context(), a),
					strings.ReplaceAll(
						tt.want,
						"{host}",
						strings.TrimPrefix(url, "http://"),
					),
				)
			})
		}
	}
}

// TestRefusedAfterWrite: an answer the version check refuses after the
// write went out, of another minor version or with no Headscale-Version,
// is a change that may have been made; one to a read or a dry run changed
// nothing.
func TestRefusedAfterWrite(t *testing.T) {
	t.Parallel()

	const refused = "this headscale is 0.30.0, the server is 0.31.0.\n" +
		"The CLI and the server must have the same major and minor version.\n" +
		"If you just upgraded, restart the server."

	const mayBe = "\nThe change may have been made: look before you run the command again."

	for _, tt := range []struct {
		name, version string
		call          func(ctx context.Context, a *API) error
		want          string
	}{
		{
			name: "a write, another minor version", version: "0.31.0",
			call: updateUser,
			want: refused + mayBe,
		},
		{
			name: "a write, no version",
			call: updateUser,
			want: "the server at {host} answered 200 OK without Headscale-Version.\nIs it headscale?" + mayBe,
		},
		{
			name: "a dry run", version: "0.31.0",
			call: func(ctx context.Context, a *API) error {
				return deleteUser(ctx, a, "3", true)
			},
			want: refused,
		},
		{
			name: "a read", version: "0.31.0",
			call: func(ctx context.Context, a *API) error {
				_, err := me(ctx, a)

				return err
			},
			want: refused,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := httptest.NewServer(
				versioned(func(w http.ResponseWriter, r *http.Request) {
					// The version a write asks first is the CLI's; the answer
					// after it is not.
					if r.URL.Path == "/api/headscale/v0/version" {
						w.Header().Set("Headscale-Version", "0.30.0")

						return
					}

					if tt.version != "" {
						w.Header().Set("Headscale-Version", tt.version)
					}

					_, _ = w.Write([]byte(`{"id": "3"}`))
				}),
			)
			t.Cleanup(s.Close)

			a, err := connectTest(
				&types.Config{
					CLI: types.CLIConfig{
						Address: s.URL,
						APIKey:  "key",
						Timeout: time.Minute,
					},
				},
				Env{Stderr: io.Discard, Version: &types.VersionInfo{Version: "0.30.0"}},
			)
			require.NoError(t, err)

			err = tt.call(t.Context(), a)
			require.EqualError(
				t,
				err,
				strings.ReplaceAll(
					tt.want,
					"{host}",
					strings.TrimPrefix(s.URL, "http://"),
				),
			)
			require.Equal(t, tt.want != refused, sentWrite(err))
		})
	}
}

// guarded is an entity with a revision, as a node is.
type guarded struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Revision string `json:"revision"`
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

	guards := map[string]string{"IfMatch": "IfMatch", "Expect": "Expect"}

	gen, err := parser.ParseFile(
		token.NewFileSet(),
		"../../../../gen/client/headscale/v0/client.gen.go",
		nil,
		0,
	)
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
		if !ok || fn.Recv == nil ||
			gotypes.ExprString(fn.Recv.List[0].Type) != "*Client" {
			continue
		}

		if o := guardedOp(fn, takes); o.params >= 0 {
			require.True(
				t,
				o.id >= 0 || takes[o.typ] == "IfMatch",
				"%s takes %s and no id to ask it for",
				fn.Name.Name,
				takes[o.typ],
			)
			ops[fn.Name.Name] = o
		}
	}

	// The commands make the calls, each on the generated client.
	files, err := filepath.Glob("../*.go")
	require.NoError(t, err)

	sent, calls, lits := map[string]int{}, 0, 0

	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}

		src, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		require.NoError(t, err)

		ast.Inspect(src, inspectGuards(t, ops, takes, guards, sent, &calls, &lits))
	}

	require.Equal(
		t,
		lits,
		calls,
		"parameters that take a guard are made outside the call that sends them",
	)

	for field := range guards {
		require.Positive(t, sent[field], "no operation that takes %s", field)
	}
}

// inspectGuards checks each call of a command on the generated client
// whose operation takes a guard: see TestEveryGuardIsSent.
func inspectGuards(
	t *testing.T,
	ops map[string]guardOp,
	takes, guards map[string]string,
	sent map[string]int,
	calls, lits *int,
) func(ast.Node) bool {
	t.Helper()

	return func(n ast.Node) bool {
		if lit, ok := n.(*ast.CompositeLit); ok {
			if sel, ok := lit.Type.(*ast.SelectorExpr); ok &&
				takes[sel.Sel.Name] != "" {
				*lits++
			}
		}

		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		fn, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || gotypes.ExprString(fn.X) != "c.API" {
			return true
		}

		o, ok := ops[strings.TrimSuffix(fn.Sel.Name, "WithResponse")]
		if !ok {
			return true
		}

		*calls++

		field := takes[o.typ]
		where := gotypes.ExprString(call)

		un, _ := call.Args[o.params].(*ast.UnaryExpr)
		require.NotNil(
			t,
			un,
			"%s: the parameters, which take %s, are not written out in the call",
			where,
			field,
		)

		lit, _ := un.X.(*ast.CompositeLit)
		require.NotNil(
			t,
			lit,
			"%s: the parameters, which take %s, are not written out in the call",
			where,
			field,
		)

		if o.id < 0 {
			require.False(
				t,
				setsField(lit, field),
				"%s has no entity and sends %s",
				where,
				field,
			)

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

			return gotypes.ExprString(g.Fun) == "c."+guards[field] &&
				gotypes.ExprString(g.Args[0]) == gotypes.ExprString(call.Args[o.id])
		})
		require.True(
			t,
			has,
			"%s takes %s and does not send c.%s(%s), the guard of the entity it is made on",
			where,
			field,
			guards[field],
			gotypes.ExprString(call.Args[o.id]),
		)

		sent[field]++

		return true
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
			if star, ok := f.Type.(*ast.StarExpr); ok &&
				takes[gotypes.ExprString(star.X)] != "" {
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

// TestWriteAnswerRefused: a write whose own answer the version check
// refuses was made or not; the error says so after the version's
// sentence. A refused GET /version sent no write and says only the
// version.
func TestWriteAnswerRefused(t *testing.T) {
	t.Parallel()

	const made = "\nThe change may have been made: look before you run the command again."

	for _, tt := range []struct{ probe, write, want string }{
		{"0.30.2", "0.31.0", "this headscale is 0.30.1, the server is 0.31.0.\n" +
			"The CLI and the server must have the same major and minor version.\n" +
			"If you just upgraded, restart the server." + made},
		{"0.30.2", "", "answered 201 Created without Headscale-Version.\nIs it headscale?" + made},
		{"0.31.0", "0.31.0", "this headscale is 0.30.1, the server is 0.31.0.\n" +
			"The CLI and the server must have the same major and minor version.\n" +
			"If you just upgraded, restart the server."},
	} {
		s := httptest.NewServer(versioned(func(w http.ResponseWriter, r *http.Request) {
			version := tt.write
			if r.Method == http.MethodGet {
				version = tt.probe
			}

			if version != "" {
				w.Header().Set("Headscale-Version", version)
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		}))
		t.Cleanup(s.Close)

		a, err := connectTest(
			&types.Config{
				CLI: types.CLIConfig{
					Address: s.URL,
					APIKey:  "key",
					Timeout: time.Minute,
				},
			},
			Env{Stderr: io.Discard, Version: &types.VersionInfo{Version: "0.30.1"}},
		)
		require.NoError(t, err)

		err = a.send(
			documented[anySuccess](),
			func(c *clientv0.Client) (*http.Response, error) {
				req, err := http.NewRequestWithContext(
					t.Context(),
					http.MethodPost,
					s.URL+"/x",
					nil,
				)
				if err != nil {
					return nil, err
				}

				return c.Client.Do(req)
			},
		)
		require.ErrorContains(t, err, tt.want)

		if !strings.HasSuffix(tt.want, made) {
			require.NotContains(t, err.Error(), "may have been made")
		}
	}
}

// The calls a test makes, each said as the CLI says it: the generated
// client's call, through errorOf, as a command's call is.

func health(ctx context.Context, a *API) (clientv0.Health, error) {
	ctx = reading(ctx, a)

	h, err := clientv0.Got(a.GetHealthWithResponse(ctx))

	return h, a.errorOf(err)
}

func me(ctx context.Context, a *API) (clientv0.Me, error) {
	ctx = reading(ctx, a)

	m, err := clientv0.Got(a.GetMeWithResponse(ctx))

	return m, a.errorOf(err)
}

func listUsers(ctx context.Context, a *API) ([]clientv0.User, error) {
	ctx = reading(ctx, a)

	rows, err := a.ListUsersAll(ctx, &clientv0.ListUsersParams{PageSize: a.PageSize})

	return rows, a.errorOf(err)
}

func listNodes(ctx context.Context, a *API) ([]clientv0.Node, error) {
	ctx = reading(ctx, a)

	rows, err := a.ListNodesAll(ctx, &clientv0.ListNodesParams{PageSize: a.PageSize})

	return rows, a.errorOf(err)
}

func createUser(ctx context.Context, a *API, name string) (clientv0.User, error) {
	ctx = reading(ctx, a)

	u, err := clientv0.Got(
		a.CreateUserWithResponse(ctx, clientv0.CreateUserBody{Name: name}),
	)

	return u, a.errorOf(err)
}

// updateUser is PATCH /users/3.
func updateUser(ctx context.Context, a *API) error {
	ctx = reading(ctx, a)

	_, err := clientv0.Got(
		a.UpdateUserWithApplicationMergePatchPlusJSONBodyWithResponse(
			ctx,
			"3",
			clientv0.UpdateUserBody{},
		),
	)

	return a.errorOf(err)
}

func deleteUser(ctx context.Context, a *API, id string, dryRun bool) error {
	ctx = reading(ctx, a)

	_, err := clientv0.Got(a.DeleteUserWithResponse(
		ctx,
		id,
		&clientv0.DeleteUserParams{WithNodes: new(false), DryRun: new(dryRun)},
	))

	return a.errorOf(err)
}

func getNode(ctx context.Context, a *API, id string) (clientv0.Node, error) {
	ctx = reading(ctx, a)

	n, err := clientv0.Got(a.GetNodeWithResponse(ctx, id))

	return n, a.errorOf(err)
}

func deleteNode(ctx context.Context, a *API, id string) error {
	ctx = reading(ctx, a)

	return a.errorOf(
		clientv0.Done(a.DeleteNodeWithResponse(ctx, id, &clientv0.DeleteNodeParams{})),
	)
}

// bare is an API on url with no version check, as a test of how an answer
// is read makes it: a fake that sends no Headscale-Version still answers.
// Messages name it x.
func bare(tb testing.TB, url string, pageSize int64) *API {
	tb.Helper()

	a := &API{target: "x", PageSize: new(pageSize), read: &reads{}}

	c, err := clientv0.NewClientWithResponses(url)
	require.NoError(tb, err)

	a.ClientWithResponses = c

	return a
}

// The harness of a call of a made-up operation, read as the generated
// client reads an answer and said through errorOf: a test of a sentence
// needs no operation of the document.

// success are the statuses of success of a made-up operation.
type success struct{ statuses []int }

// documented are the statuses of success of the operation whose answer the
// generated client reads as R: R has a field JSON<status> or
// Headers<status> for each.
func documented[R any]() success {
	var out []int

	for f := range reflect.TypeFor[R]().Fields() {
		digits, ok := strings.CutPrefix(f.Name, "JSON")
		if !ok {
			digits, ok = strings.CutPrefix(f.Name, "Headers")
		}

		status, err := strconv.Atoi(digits)
		if ok && err == nil && status/100 == 2 && !slices.Contains(out, status) {
			out = append(out, status)
		}
	}

	return success{statuses: out}
}

// answer makes the request of do and reads its answer: a success of want,
// JSON unless a 204, that check takes; any other as the client's error.
func answer(
	a *API,
	want success,
	do func(*clientv0.Client) (*http.Response, error),
	check func(status int, body []byte) error,
) error {
	//nolint:forcetypeassert // the generated client
	resp, err := do(a.ClientInterface.(*clientv0.Client))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fail := func(err error) error {
		return &clientv0.AnswerError{
			Response: resp,
			Body:     body,
			Want:     want.statuses,
			Err:      err,
		}
	}

	switch {
	case resp.StatusCode/100 != 2:
		re := &clientv0.ResponseError{Response: resp, Body: body}

		var p clientv0.Problem
		if clientv0.DecodeResponse(body, &p) == nil && p.Code != "" {
			re.Problem = &p
		}

		return re
	case !slices.Contains(want.statuses, resp.StatusCode):
		return fail(clientv0.ErrStatus)
	case resp.StatusCode != http.StatusNoContent && !json.Valid(body):
		return fail(&shape.Error{Why: "it is not JSON"})
	}

	if check != nil {
		err := check(resp.StatusCode, body)
		if err != nil {
			return fail(err)
		}
	}

	return nil
}

// send is a request whose answer is a success of want.
func (a *API) send(
	want success,
	do func(*clientv0.Client) (*http.Response, error),
) error {
	err := answer(a, want, do, nil)

	return a.errorOf(err)
}

// callOf is a request whose success of R is read as T: NoOutput a 204,
// any other T an object of its shape.
func callOf[T, R any](
	a *API,
	do func(*clientv0.Client) (*http.Response, error),
) (T, error) {
	var out T

	err := answer(a, documented[R](), do, func(status int, body []byte) error {
		if _, none := any(out).(NoOutput); none {
			if status != http.StatusNoContent {
				return &shape.Error{
					Why: "it is not the 204 No Content this operation answers",
				}
			}

			return nil
		}

		if status == http.StatusNoContent {
			return &shape.Error{Why: "it has no body"}
		}

		err := shape.Check(body, &out)
		if err != nil {
			return err
		}

		err = clientv0.DecodeResponse(body, &out)
		if err == nil && a.read != nil {
			a.read.decoded(&out, body)
		}

		return err
	})

	return out, a.errorOf(err)
}

// page is the request of one page of a walk: its size, and the token of
// the page before; nil for the first.
type page struct {
	size  int64
	token *string
}

// walkOf reads every page of a made-up list whose rows are under items,
// as the generated ListXAll does: once again from the first page when the
// server refuses a token.
func walkOf[Row, R any](
	a *API,
	items string,
	get func(c *clientv0.Client, p page) (*http.Response, error),
) ([]Row, error) {
	pages := func() ([]Row, error) {
		var rows []Row

		p := page{size: *a.PageSize}
		seen := map[string]bool{}

		for {
			var (
				got  []Row
				next *string
			)

			err := answer(
				a,
				documented[R](),
				func(c *clientv0.Client) (*http.Response, error) { return get(c, p) },
				func(_ int, body []byte) error {
					var page map[string]json.RawMessage

					err := json.Unmarshal(body, &page)
					if err != nil {
						return err
					}

					var raws []json.RawMessage
					if json.Unmarshal(page[items], &raws) != nil {
						return &shape.Error{Why: "its " + items + " is not a list"}
					}

					// A made-up page has no type to hold a row to: the row is
					// decoded only.
					got = make([]Row, len(raws))
					for i, raw := range raws {
						err := clientv0.DecodeResponse(raw, &got[i])
						if err != nil {
							return err
						}

						if a.read != nil {
							a.read.decoded(&got[i], raw)
						}
					}

					token, ok := page["nextPageToken"]
					if !ok {
						return nil
					}

					// A null token is no end: only an absent one is.
					next = new("")

					return json.Unmarshal(token, next)
				},
			)

			switch {
			case err != nil:
			case next == nil:
				return append(rows, got...), nil
			case *next == "":
				err = clientv0.ErrEmptyPageToken
			case seen[*next]:
				err = clientv0.ErrRepeatedPageToken
			}

			if err != nil {
				return nil, &clientv0.PageError{Err: err}
			}

			rows = append(rows, got...)
			seen[*next] = true
			p.token = next
		}
	}

	rows, err := pages()

	re, ok := errors.AsType[*clientv0.ResponseError](err)
	if ok && re.Problem != nil &&
		re.Problem.Code == clientv0.ProblemCodeInvalidPageToken {
		rows, err = pages()
	}

	return rows, a.errorOf(err)
}

// reading is ctx with the reads of a, as the run's context carries them:
// what the client reads in a call made with it is there for -o json.
func reading(ctx context.Context, a *API) context.Context {
	if a.read == nil {
		return ctx
	}

	return clientv0.WithDecoded(ctx, a.read.decoded)
}

// TestJSONOfARow: -o json of a row is the bytes of that row in the list
// member of its page, not of an equal object elsewhere in an answer: a
// later page that echoes the row, in a member this build does not know,
// with members of its own, changes nothing.
func TestJSONOfARow(t *testing.T) {
	t.Parallel()

	one := rowOf[clientv0.User](`{"id": "1", "mark": "actual"}`)
	echo := rowOf[clientv0.User](`{"id": "1", "mark": "echo"}`)
	two := rowOf[clientv0.User](`{"id": "2"}`)

	s := httptest.NewServer(versioned(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Query().Get("pageToken") == "" {
			_, _ = w.Write([]byte(`{"users": [` + one + `], "nextPageToken": "p"}`))

			return
		}

		_, _ = w.Write(
			[]byte(`{"users": [` + two + `], "previousUsers": [` + echo + `]}`),
		)
	}))
	t.Cleanup(s.Close)

	a := bare(t, s.URL, 1)

	users, err := listUsers(t.Context(), a)
	require.NoError(t, err)
	require.Len(t, users, 2)

	raw, ok := a.answerOf(users[0])
	require.True(t, ok)
	require.JSONEq(t, one, string(raw))
}
