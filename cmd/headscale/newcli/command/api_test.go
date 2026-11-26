package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	"testing"
	"time"

	"github.com/juanfont/headscale/client/shape"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
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

	got, err := me(t.Context(), bare(t, s.URL))
	require.NoError(t, err)

	cred, err := got.Credential.Get()
	require.NoError(t, err)
	require.Equal(
		t,
		[]string{"7", "user"},
		[]string{cred.Id, string(got.Principal.Kind)},
	)
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
		// What the type refuses is refused while the request is at hand, so
		// a write keeps the lines of a change that may have been made.
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
		written = ""
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
		// The values of attributes are strings (map[string]string): a null
		// is not one, though the typed decode would read it as "".
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

// The calls a test makes, each said as the CLI says it: the generated
// client's call, through errorOf, as a command's call is.

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

// page is the request of one page of a walk: the token of the page
// before; nil for the first.
type page struct {
	token *string
}

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

// bare is an API on url with no version check, as a test of how an answer
// is read makes it: a fake that sends no Headscale-Version still answers.
// Messages name it x.
func bare(tb testing.TB, url string) *API {
	tb.Helper()

	a := &API{target: "x", read: &reads{}}

	c, err := clientv0.NewClientWithResponses(url)
	require.NoError(tb, err)

	a.ClientWithResponses = c

	return a
}

// reading is ctx with the reads of a, as the run's context carries them:
// what the client reads in a call made with it is there for -o json.
func reading(ctx context.Context, a *API) context.Context {
	if a.read == nil {
		return ctx
	}

	return clientv0.WithDecoded(ctx, a.read.decoded)
}

// send is a request whose answer is a success of want.
func (a *API) send(
	want success,
	do func(*clientv0.Client) (*http.Response, error),
) error {
	err := answer(a, want, do, nil)

	return a.errorOf(err)
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

		var p page

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

	return rows, a.errorOf(err)
}
