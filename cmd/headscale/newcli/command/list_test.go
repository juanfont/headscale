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

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/stretchr/testify/require"
)

// TestListFlags: the flags the builder gives every list, on the local list
// of testTree (apple with ID 1, and 2 with no name).
func TestListFlags(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		line           string
		screen         bool
		stdout, stderr string
		code           int
	}{
		{line: "items list --columns name", stdout: "NAME\napple\n-\n"},
		{line: "items list --columns name,id", stdout: "NAME   ID\napple  1\n-      2\n"},
		{line: "items list --columns -id", stdout: "NAME\napple\n-\n"},
		{line: "items list --columns +id,-name", stdout: "ID\n1\n2\n"},
		{
			line:   "items list --columns id,+name",
			stderr: "Error: --columns takes a plain list, or only + and - entries. Not both.\n", code: 1,
		},
		{
			line:   "items list --columns id,nam",
			stderr: "Error: unknown column \"nam\". Did you mean \"name\"?\nRun `prog items list --list-columns`.\n", code: 1,
		},
		{
			line:   "items list --columns id,name -o json",
			stderr: "Error: --columns works on tables only. JSON has the whole object.\nTo pick fields: ... -o json | jq '.[] | {id, name}'\n", code: 1,
		},
		{line: "items list --columns ''", stderr: "Error: the column list is empty.\n", code: 1},
		{line: "items list --columns id,name,id", stderr: "Error: --columns names \"id\" twice.\n", code: 1},
		{line: "items list --columns +id,-id", stderr: "Error: --columns names \"id\" twice.\n", code: 1},
		// A bad value stands at its flag, before a later mistake.
		{line: "items list --sort nam --sort id", stderr: "Error: unknown column \"nam\". Did you mean \"name\"?\nRun `prog items list --list-columns`.\n", code: 1},
		{line: "items list --sort id --sort nam", stderr: "Error: --sort is given twice. Only --filter may be repeated.\n", code: 1},
		{line: "items list --bogus --filter x", stderr: "Error: unknown flag --bogus for `items list`.\nRun `prog items list --help`.\n", code: 1},
		{line: "items list --filter count>=1", stderr: "Error: unknown column \"count\".\nRun `prog items list --list-columns`.\n", code: 1},
		{line: "items list --filter id>=1", stderr: "Error: \"id>=1\": there is no >=. The operators are =, :, < and >.\n", code: 1},
		{line: "items list --sort -id", stdout: "ID  NAME\n2   -\n1   apple\n"},
		{line: "items list --sort name", stdout: "ID  NAME\n1   apple\n2   -\n"}, // a row with no name comes last
		{line: "items list --sort -nam", stderr: "Error: unknown column \"nam\". Did you mean \"name\"?\nRun `prog items list --list-columns`.\n", code: 1},
		{line: "items list --filter name=apple", stdout: "ID  NAME\n1   apple\n"},
		{line: "items list --filter name:pp,id=1", stdout: "ID  NAME\n1   apple\n"},
		{line: "items list --filter name:pp --filter id=2", stdout: "ID  NAME\n"},
		{line: "items list --filter id>1 -o json", stdout: "[\n  {\n    \"id\": \"2\",\n    \"name\": \"\"\n  }\n]\n"},
		{line: "items list --filter id>1 --sort -id --columns name", stdout: "NAME\n-\n"},
		{line: "items list --filter colour=red", stderr: "Error: unknown column \"colour\".\nRun `prog items list --list-columns`.\n", code: 1},
		{line: "items list --filter id:1", stderr: "Error: column \"id\" is an ID. It works with =, < and > only.\n", code: 1},
		{line: "items list --filter id", stderr: "Error: \"id\" is not a filter: write a column, then =, :, < or >, then a value.\n", code: 1},
		{line: "items list --filter id=9", stdout: "ID  NAME\n"},
		{line: "items list --filter id=9", screen: true, stdout: "No items.\n"},
		{line: "items list --filter id=9 -o json", screen: true, stdout: "[]\n"},
		//nolint:dupword // a column is often named as its field
		{line: "items list --list-columns", stdout: "COLUMN  FIELD  KIND  DEFAULT  DESCRIPTION\nid      id     id    yes\nname    name   text  yes\n"},
		//nolint:dupword // a column is often named as its field
		{line: "items list --list-columns x", stdout: "COLUMN  FIELD  KIND  DEFAULT  DESCRIPTION\nid      id     id    yes\nname    name   text  yes\n"},
		{
			line:   "items ls --list-columns -o json",
			stdout: "[\n  {\n    \"Name\": \"id\",\n    \"Field\": \"id\",\n    \"Kind\": \"id\",\n    \"Default\": true,\n    \"Help\": \"\"\n  },\n  {\n    \"Name\": \"name\",\n    \"Field\": \"name\",\n    \"Kind\": \"text\",\n    \"Default\": true,\n    \"Help\": \"\"\n  }\n]\n",
		},
		{line: "items list --list-columns -h", stdout: helpOf(t, "items", "list")},
		// Tab offers the columns, after a sign and after a comma.
		{line: "__complete items list --columns id,n", stdout: "id,name\n:6\n"},
		// A column the list names already is not offered again.
		{line: "__complete items list --columns id,", stdout: "id,name\n:6\n"},
		{line: "__complete items list --columns=+name,", stdout: "+name,id\n:6\n"},
		{line: "__complete items list --sort i", stdout: "id\n:4\n"},
		{line: "__complete items list --sort -", stdout: "-id\n-name\n:4\n"},
		{line: "__complete items list --filter n", stdout: "name\n:6\n"},
	} {
		t.Run(tt.line, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer

			code := Run(testTree(t), words(tt.line), Env{Stdout: &stdout, Stderr: &stderr, StdoutTerminal: tt.screen})

			if diff := cmp.Diff(tt.stdout, stdout.String()); diff != "" {
				t.Errorf("stdout (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tt.stderr, stderr.String()); diff != "" {
				t.Errorf("stderr (-want +got):\n%s", diff)
			}

			require.Equal(t, tt.code, code)
		})
	}
}

// words splits at spaces; ” is the empty word.
func words(line string) []string {
	w := strings.Fields(line)
	for i := range w {
		if w[i] == "''" {
			w[i] = ""
		}
	}

	return w
}

func helpOf(t *testing.T, path ...string) string {
	t.Helper()

	var b bytes.Buffer

	require.Equal(t, 0, Run(testTree(t), append(path, "-h"), Env{Stdout: &b}))

	return b.String()
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

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()

		asked = append(asked, r.URL.Path)
		mu.Unlock()

		w.Header().Set("Headscale-Version", "dev")

		switch r.URL.Path {
		case "/api/headscale/v0/users":
			_, _ = w.Write([]byte(`{"users": [{"id": "3", "name": "alice", "email": ""}, {"id": "5", "name": "carol", "email": "carol@example.com"}]}`))
		default:
			_, _ = w.Write([]byte(`{"owned": [
				{"id": "1", "owner": {"user": {"id": "3", "loginName": "alice"}, "tags": []}},
				{"id": "2", "owner": {"user": null, "tags": ["tag:ci"]}},
				{"id": "3", "owner": {"user": {"id": "5", "loginName": "carol@example.com"}, "tags": []}}
			]}`))
		}
	}))
	t.Cleanup(s.Close)

	tree, err := Build("prog", "A program", NewList(ListSpec[NoInput, owned]{
		Name: "owned", Short: "S", Long: "S.", Example: []string{"prog owned"},
		Columns: table.Columns[owned]{{Name: "id", Field: "id", Default: true}, {Name: "owner", Field: "owner", Default: true}},
		NoRows:  "No rows.",
		Run: func(c Ctx, _ NoInput) ([]owned, error) {
			return walk[owned](c.API, "owned", func(cl *clientv0.Client, _ page) (*http.Response, error) {
				req, err := http.NewRequestWithContext(c, http.MethodGet, cl.Server+"owned", nil)
				if err != nil {
					return nil, err
				}

				return cl.Client.Do(req)
			})
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
			Stdout: &stdout, Stderr: &stderr, Now: time.Now,
			Environ: []string{"HEADSCALE_CONFIG=" + file, "HEADSCALE_CLI_ADDRESS=" + s.URL, "HEADSCALE_CLI_API_KEY=key"},
		})
		require.Equal(t, tt.stdout, stdout.String(), tt.line)
		require.Equal(t, tt.stderr, stderr.String(), tt.line)
		require.Equal(t, tt.code, code, tt.line)

		if tt.line == "owned --filter owner=alcie" {
			mu.Lock()
			require.Equal(t, []string{"/api/headscale/v0/users"}, asked, "a user that is not there stops before the list")
			mu.Unlock()
		}
	}
}

// TestFilterHelp: the help of --filter shows the first filter of the list's
// own examples, so the example names columns the list has.
func TestFilterHelp(t *testing.T) {
	t.Parallel()

	tree, err := Build("prog", "A program", NewList(ListSpec[NoInput, item]{
		Name: "items", Short: "S", Long: "S.", Local: true, Columns: itemColumns, NoRows: "No items.",
		Example: []string{"prog items", "prog items --filter 'name:ap' --sort id", "prog items --filter=id=1"},
		Run:     func(Ctx, NoInput) ([]item, error) { return nil, nil },
	}))
	require.NoError(t, err)

	var b bytes.Buffer

	require.Equal(t, 0, Run(tree, []string{"items", "-h"}, Env{Stdout: &b}))
	require.Contains(t, b.String(), "--filter string    Keep the rows that match, such as name:ap; may be repeated\n")
	require.Empty(t, filterExample([]string{"prog items --sort id"}))
}

// TestColumnsOfTheList: the list flags read the columns of the list the
// line reaches. Two lists of one row type, in one tree or in two, each
// have their own, also where a name is the same and its field is not.
func TestColumnsOfTheList(t *testing.T) {
	t.Parallel()

	rows := func(Ctx, NoInput) ([]item, error) { return []item{{"1", "apple"}, {"2", "pear"}}, nil }
	list := func(name string, cols table.Columns[item]) Node {
		return NewList(ListSpec[NoInput, item]{
			Name: name, Short: "S", Long: "S.", Example: []string{"prog " + name}, Local: true,
			Columns: cols, NoRows: "No items.", Run: rows,
		})
	}

	// In "keys", the column "name" shows the ID.
	keys := table.Columns[item]{{Name: "name", Field: "id", Default: true}}

	one, err := Build("prog", "A program", list("items", itemColumns), list("keys", keys))
	require.NoError(t, err)

	other, err := Build("prog", "A program", list("keys", keys))
	require.NoError(t, err)

	for _, tt := range []struct {
		tree           *Tree
		line           string
		stdout, stderr string
	}{
		{tree: one, line: "items --filter name=apple", stdout: "ID  NAME\n1   apple\n"},
		{tree: one, line: "keys --filter name=1", stdout: "NAME\n1\n"},
		{tree: one, line: "keys --sort -name", stdout: "NAME\n2\n1\n"},
		{tree: one, line: "keys --columns id", stderr: "Error: unknown column \"id\".\nRun `prog keys --list-columns`.\n"},
		{tree: one, line: "__complete keys --columns ''", stdout: "name\n:4\n"},
		{tree: one, line: "__complete items --columns ''", stdout: "id\nname\n:4\n"},
		{tree: other, line: "keys --filter name=2", stdout: "NAME\n2\n"},
	} {
		var stdout, stderr bytes.Buffer

		Run(tt.tree, words(tt.line), Env{Stdout: &stdout, Stderr: &stderr})
		require.Equal(t, tt.stdout, stdout.String(), tt.line)
		require.Equal(t, tt.stderr, stderr.String(), tt.line)
	}
}
