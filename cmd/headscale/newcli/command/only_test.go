package command

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	"github.com/stretchr/testify/require"
)

// stated is a row with a state, such as a key.
type stated struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
}

var statedColumns = table.Columns[stated]{
	{Name: "id", Field: "id", Default: true},
	{Name: "name", Field: "name", Default: true},
	{Name: "state", Field: "state"},
}

// onlyTree has a list that hides every row that is not valid, and one
// that hides nothing.
func onlyTree(tb testing.TB, rows ...stated) *Tree {
	tb.Helper()

	tree, err := Build("prog", "A program",
		NewList(ListSpec[NoInput, stated]{
			Name: "keys", Short: "List keys", Long: "List the valid keys; --all shows every key.", Example: []string{"prog keys"},
			Local: true, Columns: statedColumns, NoRows: "No keys.", Only: "state=valid",
			Run: func(Ctx, NoInput) ([]stated, error) { return rows, nil },
		}),
		NewList(ListSpec[NoInput, stated]{
			Name: "all", Short: "List all", Long: "List all.", Example: []string{"prog all"},
			Local: true, Columns: statedColumns, NoRows: "No keys.",
			Run: func(Ctx, NoInput) ([]stated, error) { return rows, nil },
		}),
	)
	require.NoError(tb, err)

	return tree
}

// TestOnly: a list's default filter, which --all and a filter on its
// column remove, in the table and in JSON alike.
func TestOnly(t *testing.T) {
	t.Parallel()

	rows := []stated{{"1", "a", "valid"}, {"2", "b", "revoked"}, {"3", "c", "expired"}, {"4", "d", "valid"}}

	for _, tt := range []struct {
		line           string
		screen         bool
		rows           []stated
		stdout, stderr string
		code           int
	}{
		{line: "keys", stdout: "ID  NAME\n1   a\n4   d\n"},
		{line: "keys --all", stdout: "ID  NAME  STATE\n1   a     valid\n2   b     revoked\n3   c     expired\n4   d     valid\n"},
		{line: "keys --all --sort state --filter id>1", stdout: "ID  NAME  STATE\n3   c     expired\n2   b     revoked\n4   d     valid\n"},
		{line: "keys --filter state=revoked", stdout: "ID  NAME\n2   b\n"},
		{line: "keys --filter state:i", stdout: "ID  NAME\n1   a\n3   c\n4   d\n"},
		{line: "keys --filter name=b", stdout: "ID  NAME\n"},
		{line: "keys --filter name=b --all", stdout: "ID  NAME  STATE\n2   b     revoked\n"},
		{line: "keys --all --columns id", stdout: "ID\n1\n2\n3\n4\n"},
		{line: "keys --all --columns -name", stdout: "ID  STATE\n1   valid\n2   revoked\n3   expired\n4   valid\n"},
		{line: "keys --columns +state", stdout: "ID  NAME  STATE\n1   a     valid\n4   d     valid\n"},
		{line: "keys -o json --filter id<3", stdout: "[\n  {\n    \"id\": \"1\",\n    \"name\": \"a\",\n    \"state\": \"valid\"\n  }\n]\n"},
		{line: "keys -o json --filter id=2 --all", stdout: "[\n  {\n    \"id\": \"2\",\n    \"name\": \"b\",\n    \"state\": \"revoked\"\n  }\n]\n"},
		{line: "keys --filter id>4", screen: true, stdout: "No keys.\n"},
		{line: "keys --filter id>1 --filter id<4", screen: true, stdout: "No keys. --all shows 2 more.\n"},
		{line: "keys", screen: true, rows: rows[1:3], stdout: "No keys. --all shows 2 more.\n"},
		{line: "keys --filter id=2", screen: true, stdout: "No keys. --all shows 1 more.\n"},
		{line: "keys --all", screen: true, rows: []stated{}, stdout: "No keys.\n"},
		{line: "keys --list-columns", stdout: "COLUMN  FIELD  KIND  DEFAULT  DESCRIPTION\nid      id     id    yes\nname    name   text  yes\nstate   state  text  no       the list shows only state=valid, --all every row and this column\n"},
		{line: "keys --all=maybe", stderr: "Error: --all takes true or false, not \"maybe\".\n", code: 1},
		{line: "all --all", stderr: "Error: --all does not apply to `all`.\nRun `prog all --help`.\n", code: 1},
		{line: "all", stdout: "ID  NAME\n1   a\n2   b\n3   c\n4   d\n"},
	} {
		t.Run(tt.line, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer

			given := rows
			if tt.rows != nil {
				given = tt.rows
			}

			code := Run(onlyTree(t, given...), words(tt.line), Env{Stdout: &stdout, Stderr: &stderr, StdoutTerminal: tt.screen})

			if diff := cmp.Diff(tt.stdout, stdout.String()); diff != "" {
				t.Errorf("stdout (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tt.stderr, stderr.String()); diff != "" {
				t.Errorf("stderr (-want +got):\n%s", diff)
			}

			require.Equal(t, tt.code, code)
		})
	}

	t.Run("the help names the filter that --all removes", func(t *testing.T) {
		t.Parallel()

		var b bytes.Buffer

		require.Equal(t, 0, Run(onlyTree(t), []string{"keys", "-h"}, Env{Stdout: &b}))
		require.Contains(t, b.String(), "      --all              Show every row, not only state=valid\n")
	})

	t.Run("an --all of a command's own says only its own help", func(t *testing.T) {
		t.Parallel()

		type ownAll struct {
			All bool `flag:"all" help:"Do it for all"`
		}

		tree, err := Build("prog", "A program", New(Spec[ownAll, NoOutput]{
			Name: "do", Short: "Do", Long: "Do.", Example: []string{"prog do"}, Local: true, Run: noop[ownAll, NoOutput],
		}))
		require.NoError(t, err)

		var b bytes.Buffer

		require.Equal(t, 0, Run(tree, []string{"do", "-h"}, Env{Stdout: &b}))
		require.Contains(t, b.String(), "--all    Do it for all\n")
	})
}
