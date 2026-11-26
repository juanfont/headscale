package command

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/cmdline/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/stretchr/testify/require"
)

type owned struct {
	ID    string         `json:"id"`
	Owner clientv0.Owner `json:"owner"`
}

// TestOwnerFilter: owner=<user> names a user as a target does, before the
// list is read; a tag needs no user.
func TestOwnerFilter(t *testing.T) {
	t.Parallel()

	var (
		mu    sync.Mutex
		asked []string
	)

	s := httptest.NewServer(versioned(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()

		asked = append(asked, r.URL.Path)
		mu.Unlock()

		w.Header().Set("Headscale-Version", "dev")

		switch r.URL.Path {
		case "/api/headscale/v0/users":
			_, _ = w.Write(
				[]byte(
					`{"users": [` + rowOf[clientv0.User](
						`{"id": "3", "name": "alice", "email": ""}`,
					) + `, ` + rowOf[clientv0.User](
						`{"id": "5", "name": "carol", "email": "carol@example.com"}`,
					) + `]}`,
				),
			)
		default:
			// Whole rows: -o json finds a row by the type it reads as.
			_, _ = w.Write([]byte(`{"owned": [` +
				rowOf[owned](
					`{"id": "1", "owner": {"user": {"id": "3", "loginName": "alice"}, "tags": []}}`,
				) + `, ` +
				rowOf[owned](
					`{"id": "2", "owner": {"user": null, "tags": ["tag:ci"]}}`,
				) + `, ` +
				rowOf[owned](
					`{"id": "3", "owner": {"user": {"id": "5", "loginName": "carol@example.com"}, "tags": []}}`,
				) +
				`]}`))
		}
	}))
	t.Cleanup(s.Close)

	tree, err := Build("prog", "A program", NewList(ListSpec[NoInput, owned]{
		Name:    "owned",
		Short:   "S",
		Long:    "S.",
		Example: []string{"prog owned"},
		Columns: table.Columns[owned]{
			{Name: "id", Field: "id", Default: true},
			{Name: "owner", Field: "owner", Default: true},
		},
		NoRows: "No rows.",
		Run: func(c Ctx, _ NoInput) ([]owned, error) {
			return walkOf[owned, anySuccess](
				c.API,
				"owned",
				func(cl *clientv0.Client, _ page) (*http.Response, error) {
					req, err := http.NewRequestWithContext(
						c,
						http.MethodGet,
						cl.Server+"owned",
						nil,
					)
					if err != nil {
						return nil, err
					}

					return cl.Client.Do(req)
				},
			)
		},
	}))
	require.NoError(t, err)

	file := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(file, nil, 0o600))

	for _, tt := range []struct {
		line, stdout, stderr string
		code                 int
	}{
		{line: "owned --filter owner=alice", stdout: "ID  OWNER\n1   alice\n"},
		{line: "owned --filter owner=3", stdout: "ID  OWNER\n1   alice\n"},
		{line: "owned --filter owner=carol@example.com", stdout: "ID  OWNER\n3   carol@example.com\n"},
		{line: "owned --filter owner=tag:ci", stdout: "ID  OWNER\n2   tag:ci\n"},
		{line: "owned --filter owner:example", stdout: "ID  OWNER\n3   carol@example.com\n"},
		{line: "owned --filter owner=alcie", stderr: "Error: no user matches \"alcie\".\n", code: 1},
	} {
		mu.Lock()
		asked = nil
		mu.Unlock()

		var stdout, stderr bytes.Buffer

		code := Run(tree, words(tt.line), Env{
			Stdout: &stdout,
			Stderr: &stderr,
			Now:    time.Now,
			Environ: []string{
				"HEADSCALE_CONFIG=" + file,
				"HEADSCALE_CLI_ADDRESS=" + s.URL,
				"HEADSCALE_CLI_API_KEY=key",
			},
		})
		require.Equal(t, tt.stdout, stdout.String(), tt.line)
		require.Equal(t, tt.stderr, stderr.String(), tt.line)
		require.Equal(t, tt.code, code, tt.line)

		if tt.line == "owned --filter owner=alcie" {
			mu.Lock()
			require.Equal(
				t,
				[]string{"/api/headscale/v0/users"},
				asked,
				"a user that is not there stops before the list",
			)
			mu.Unlock()
		}
	}
}
