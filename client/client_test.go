package client_test

import (
	"go/build"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/client"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/stretchr/testify/require"
)

const versionBody = `{"version":"0.30.1","commit":"","buildTime":"","dirty":false,"go":{"version":"","os":"","arch":""}}`

// fake is a server of version that answers every request with status and
// body, GET /version with its own answer, and notes what it was asked.
type fake struct {
	mu    sync.Mutex
	asked []string
}

func (f *fake) serve(
	t *testing.T,
	version, commit string,
	status int,
	body string,
) string {
	t.Helper()

	s := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			f.asked = append(f.asked, r.Method+" "+r.URL.Path)
			f.mu.Unlock()

			if version != "" {
				w.Header().Set("Headscale-Version", version)
			}

			if commit != "" {
				w.Header().Set("Headscale-Commit", commit)
			}

			w.Header().Set("Content-Type", "application/json")

			if strings.HasSuffix(r.URL.Path, "/version") {
				_, _ = w.Write([]byte(versionBody))

				return
			}

			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}),
	)
	t.Cleanup(s.Close)

	return s.URL
}

func newClient(t *testing.T, opts client.Options) *clientv0.ClientWithResponses {
	t.Helper()

	opts.APIKey = "key"
	opts.Timeout = time.Minute

	c, err := client.New(opts)
	require.NoError(t, err)

	return c
}

// TestVersion: a release of another minor version is refused before its
// answer is read; another commit is said once; a write asks GET /version
// first, and only once.
func TestVersion(t *testing.T) {
	t.Parallel()

	t.Run("another minor", func(t *testing.T) {
		t.Parallel()

		var f fake

		c := newClient(
			t,
			client.Options{
				Address: f.serve(t, "0.31.0", "", 200, "{}"),
				Version: "0.30.1",
			},
		)

		_, err := c.GetHealthWithResponse(t.Context())

		var ve *client.VersionError

		require.ErrorAs(t, err, &ve)
		require.Equal(t, "0.31.0", ve.ServerVersion)
	})

	t.Run("no Headscale-Version", func(t *testing.T) {
		t.Parallel()

		var f fake

		c := newClient(
			t,
			client.Options{Address: f.serve(t, "", "", 404, "{}"), Version: "0.30.1"},
		)

		_, err := c.GetHealthWithResponse(t.Context())

		var ve *client.VersionError

		require.ErrorAs(t, err, &ve)
		require.True(t, ve.TooOld)
	})

	t.Run("another commit", func(t *testing.T) {
		t.Parallel()

		var (
			f     fake
			warns []string
		)

		c := newClient(t, client.Options{
			Address: f.serve(t, "dev", "bbbbbbbbb", 204, ""),
			Version: "dev",
			Commit:  "aaaaaaaaa",
			Warn: func(ov, oc, sv, sc string) {
				warns = append(warns, ov+oc+" "+sv+sc)
			},
		})

		require.NoError(
			t,
			clientv0.Done(c.DeleteNodeWithResponse(t.Context(), "1", nil)),
		)
		require.NoError(
			t,
			clientv0.Done(c.DeleteNodeWithResponse(t.Context(), "2", nil)),
		)
		require.Equal(t, []string{"devaaaaaaa devbbbbbbbbb"}, warns)
		require.Equal(
			t,
			[]string{
				"GET /api/headscale/v0/version",
				"DELETE /api/headscale/v0/nodes/1",
				"DELETE /api/headscale/v0/nodes/2",
			},
			f.asked,
		)
	})
}

// TestHooks: Sent hears every request, GET /version before a first write
// too; Answered hears each answer the caller reads, whole.
func TestHooks(t *testing.T) {
	t.Parallel()

	var (
		f              fake
		sent, answered []string
	)

	c := newClient(t, client.Options{
		Address: f.serve(t, "dev", "", 204, ""),
		Version: "dev",
		Sent:    func(r *http.Request) { sent = append(sent, r.Method) },
		Answered: func(r *http.Response, b []byte) {
			answered = append(answered, r.Request.Method+" "+string(b))
		},
	})

	require.NoError(t, clientv0.Done(c.DeleteNodeWithResponse(t.Context(), "1", nil)))
	require.Equal(t, []string{"GET", "DELETE"}, sent)
	require.Equal(t, []string{"DELETE "}, answered)
}

// TestRedirect: a redirect is not followed; it names the scheme and host
// it points to, and no more.
func TestRedirect(t *testing.T) {
	t.Parallel()

	s := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Headscale-Version", "dev")
			http.Redirect(
				w,
				r,
				"https://elsewhere.example/secret?k=1",
				http.StatusFound,
			)
		}),
	)
	t.Cleanup(s.Close)

	c := newClient(t, client.Options{Address: s.URL, Version: "dev"})

	_, err := c.GetHealthWithResponse(t.Context())

	var re *client.RedirectError

	require.ErrorAs(t, err, &re)
	require.Equal(t, "https://elsewhere.example", re.To)
}

// TestWriteSent: a write whose answer is refused may have been made.
func TestWriteSent(t *testing.T) {
	t.Parallel()

	calls := 0
	s := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			if calls == 1 {
				w.Header().Set("Headscale-Version", "dev")
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(versionBody))
			}

			w.WriteHeader(http.StatusNoContent)
		}),
	)
	t.Cleanup(s.Close)

	c := newClient(t, client.Options{Address: s.URL, Version: "dev"})

	err := clientv0.Done(c.DeleteNodeWithResponse(t.Context(), "1", nil))

	var re *client.RequestError

	require.ErrorAs(t, err, &re)
	require.True(t, re.Sent && re.Write)

	var ve *client.VersionError

	require.ErrorAs(t, err, &ve)
}

// TestNoAPIKey: a remote server needs one.
func TestNoAPIKey(t *testing.T) {
	t.Parallel()

	_, err := client.New(client.Options{Address: "headscale.example"})
	require.ErrorIs(t, err, client.ErrNoAPIKey)
}

// TestImports: the client, its shape check and the generated client are
// for anyone to use, so they reach no package of Headscale but each other.
func TestImports(t *testing.T) {
	t.Parallel()

	for _, dir := range []string{".", "shape", "../gen/client/headscale/v0"} {
		pkg, err := build.ImportDir(dir, 0)
		require.NoError(t, err)

		for _, imp := range pkg.Imports {
			if !strings.HasPrefix(imp, "github.com/juanfont/headscale/") {
				continue
			}

			require.Contains(
				t,
				[]string{
					"github.com/juanfont/headscale/gen/client/headscale/v0",
					"github.com/juanfont/headscale/client/shape",
				},
				imp,
				"%s imports %s", dir, imp,
			)
		}
	}
}
