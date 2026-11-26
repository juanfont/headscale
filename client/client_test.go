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
