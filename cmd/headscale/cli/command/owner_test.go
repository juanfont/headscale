package command

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/cmdline/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/oapi-codegen/nullable"
	"github.com/stretchr/testify/require"
)

// TestOwned: an owner reads as every message writes it.
func TestOwned(t *testing.T) {
	t.Parallel()

	user := clientv0.Owner{
		User: nullable.NewNullableWithValue(
			clientv0.OwnerUser{Id: "3", LoginName: "alice"},
		),
	}
	tags := clientv0.Owner{
		Tags: []string{"tag:ci", "tag:b\nx"},
		User: nullable.NewNullNullable[clientv0.OwnerUser](),
	}

	require.Equal(
		t,
		"owned by User 3 (alice)",
		Owned(nullable.NewNullableWithValue(user)),
	)
	require.Equal(
		t,
		`tagged tag:ci, tag:b\x0ax`,
		Owned(nullable.NewNullableWithValue(tags)),
	)
	require.Equal(t, "with no owner", Owned(nullable.NewNullNullable[clientv0.Owner]()))

	name, tagged := OwnerName(nullable.NewNullableWithValue(user))
	require.Equal(t, "User 3 (alice)", name)
	require.False(t, tagged)

	name, tagged = OwnerName(nullable.NewNullableWithValue(tags))
	require.Equal(t, `tag:ci, tag:b\x0ax`, name)
	require.True(t, tagged)

	name, _ = OwnerName(nullable.NewNullNullable[clientv0.Owner]())
	require.Empty(t, name)
}

type ownerIn struct {
	Owner Owner `arg:"owner"`
}

// TestOwner: an owner is a user, looked up as a target is, or tags; its
// form is checked before any call.
func TestOwner(t *testing.T) {
	t.Parallel()

	var (
		mu    sync.Mutex
		asked int
	)

	s := httptest.NewServer(versioned(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		asked++
		mu.Unlock()

		w.Header().Set("Headscale-Version", "dev")
		_, _ = w.Write(
			[]byte(
				`{"users": [` + rowOf[clientv0.User](
					`{"id": "3", "name": "alice", "loginName": "alice"}`,
				) + `, ` + rowOf[clientv0.User](
					`{"id": "4", "name": "bob", "loginName": "bob"}`,
				) + `]}`,
			),
		)
	}))
	t.Cleanup(s.Close)

	tree, err := Build("prog", "A program", New(Spec[ownerIn, NoOutput]{
		Name: "make", Short: "S", Long: "S.", Example: []string{"prog make alice"},
		Run: noop[ownerIn, NoOutput],
		Done: func(in ownerIn, _ NoOutput, _ time.Time) string {
			if u, ok := in.Owner.User(); ok {
				return "user " + u.Id
			}

			return "tags " + strings.Join(in.Owner.Tags(), " ")
		},
	}))
	require.NoError(t, err)

	file := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(file, nil, 0o600))

	for _, tt := range []struct {
		line, stdout, stderr string
		calls                int
		// argv is the line when a word holds a space.
		argv []string
	}{
		{line: "make alice", stdout: "user 3\n", calls: 1},
		{line: "make 4", stdout: "user 4\n", calls: 1},
		{line: "make tag:ci,tag:build", stdout: "tags tag:ci tag:build\n"},
		{line: "make alcie", stderr: "Error: no user matches \"alcie\".\n", calls: 1},
		{line: "make alice,tag:ci", stderr: "Error: a key needs one owner: one user, or tags, not both.\n"},
		{line: "make alice,bob", stderr: "Error: a key is owned by one user. Got 2: alice, bob.\n"},
		{line: "make tag:ci,,tag:b", stderr: "Error: the owner list has an empty item.\n"},
		{line: "make ''", stderr: "Error: an empty word names no owner.\n"},
		{line: "tags with space", argv: []string{"make", "tag:ci, tag:build"}, stdout: "tags tag:ci tag:build\n"},
		{line: "a user with space", argv: []string{"make", " alice "}, stdout: "user 3\n", calls: 1},
		{line: "an item of space", argv: []string{"make", "tag:ci, ,tag:b"}, stderr: "Error: the owner list has an empty item.\n"},
		{line: "space alone", argv: []string{"make", " "}, stderr: "Error: an empty word names no owner.\n"},
		{line: "make tag:ci,tag:hskey-api-ab12cd345678-s3cret", stderr: "Error: <owner> takes no credential: hskey-api-*** is not sent.\n"},
	} {
		mu.Lock()
		asked = 0
		mu.Unlock()

		var stdout, stderr bytes.Buffer

		argv := words(tt.line)
		if tt.argv != nil {
			argv = tt.argv
		}

		Run(tree, argv, Env{
			Stdout: &stdout,
			Stderr: &stderr,
			Environ: []string{
				"HEADSCALE_CONFIG=" + file,
				"HEADSCALE_CLI_ADDRESS=" + s.URL,
				"HEADSCALE_CLI_API_KEY=key",
			},
		})
		require.Equal(t, tt.stdout, stdout.String(), tt.line)
		require.Equal(t, tt.stderr, stderr.String(), tt.line)

		mu.Lock()
		require.Equal(t, tt.calls, asked, tt.line)
		mu.Unlock()
	}
}

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
