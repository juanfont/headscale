package command

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/cmdline/table"
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
		// Tab reads the columns of the list it reached, past a mistake before it.
		{line: "__complete --bogus items list --columns i", stdout: "id\n:4\n"},
		{line: "__complete items list --bogus --sort n", stdout: "name\n:4\n"},
		// --sort takes - and no +.
		{line: "__complete items list --sort +", stdout: ":4\n"},
		{line: "__complete items list --sort +na", stdout: ":4\n"},
		// 003-cmdline E6 (kit Q35): Tab completes the item after the last
		// comma by its own sign, never by the items before, so it goes on in
		// a list that mixes plain names with + and -, and Run refuses that
		// list. Tab leaves out only what is wrong in the item itself: a sign
		// the flag does not take (--sort + above), a column the list names
		// already (below).
		{line: "__complete items list --columns=id,-na", stdout: "id,-name\n:6\n"},
		{line: "items list --columns=id,-name", stderr: "Error: --columns takes a plain list, or only + and - entries. Not both.\n", code: 1},
		{line: "__complete items list --columns=name,+i", stdout: "name,+id\n:6\n"},
		{line: "__complete items list --columns=+name,i", stdout: "+name,id\n:6\n"},
		{line: "__complete items list --columns=+name,+i", stdout: "+name,+id\n:6\n"},
		{line: "__complete items list --columns=-name,-i", stdout: "-name,-id\n:6\n"},
		{line: "__complete items list --columns=-i", stdout: "-id\n:4\n"},
		// The jq hint names the columns shown, the defaults with + and -.
		{line: "items list --columns -id -o json", stderr: "Error: --columns works on tables only. JSON has the whole object.\nTo pick fields: ... -o json | jq '.[] | {name}'\n", code: 1},
		{line: "items list --columns +id -o json", stderr: "Error: --columns works on tables only. JSON has the whole object.\nTo pick fields: ... -o json | jq '.[] | {id, name}'\n", code: 1},
		// A repeated item counts once; a column both added and taken away is a mistake.
		{line: "items list --columns id,name,id", stdout: "ID  NAME\n1   apple\n2   -\n"},
		{line: "items list --columns +name,+name", stdout: "ID  NAME\n1   apple\n2   -\n"},
		{line: "items list --columns id,id -o json", stderr: "Error: --columns works on tables only. JSON has the whole object.\nTo pick fields: ... -o json | jq '.[] | {id}'\n", code: 1},
		{line: "items list --columns +id,-id", stderr: "Error: --columns names \"id\" twice.\n", code: 1},
		// One sign at most: Pick would find no column for the rest.
		{line: "items list --columns ++id", stderr: "Error: unknown column \"+id\". Did you mean \"id\"?\nRun `prog items list --list-columns`.\n", code: 1},
		{line: "items list --columns -+name", stderr: "Error: unknown column \"+name\". Did you mean \"name\"?\nRun `prog items list --list-columns`.\n", code: 1},
		// A bad value stands at its flag, before a later mistake.
		{line: "items list --sort nam --sort id", stderr: "Error: unknown column \"nam\". Did you mean \"name\"?\nRun `prog items list --list-columns`.\n", code: 1},
		{line: "items list --sort id --sort nam", stderr: "Error: --sort is given twice. Only --filter may be repeated.\n", code: 1},
		{line: "items list --bogus --filter x", stderr: "Error: unknown flag --bogus for `items list`.\nRun `prog items list --help`.\n", code: 1},
		{line: "items list --filter count>=1", stderr: "Error: unknown column \"count\".\nRun `prog items list --list-columns`.\n", code: 1},
		{line: "items list --filter id>=1", stderr: "Error: \"id>=1\": there is no >=. The operators are =, :, < and >.\n", code: 1},
		{line: "items list --sort -id", stdout: "ID  NAME\n2   -\n1   apple\n"},
		{line: "items list --sort name", stdout: "ID  NAME\n2   -\n1   apple\n"},
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
		{line: "items list --list-columns", stdout: "COLUMN  FIELD  KIND  DEFAULT  DESCRIPTION\nid      id     id    yes\nname    name   text  yes\n"},
		{line: "items list --list-columns x", stdout: "COLUMN  FIELD  KIND  DEFAULT  DESCRIPTION\nid      id     id    yes\nname    name   text  yes\n"},
		{
			line:   "items ls --list-columns -o json",
			stdout: "[\n  {\n    \"Name\": \"id\",\n    \"Field\": \"id\",\n    \"Kind\": \"id\",\n    \"Default\": true,\n    \"Help\": \"\"\n  },\n  {\n    \"Name\": \"name\",\n    \"Field\": \"name\",\n    \"Kind\": \"text\",\n    \"Default\": true,\n    \"Help\": \"\"\n  }\n]\n",
		},
		{line: "items list --list-columns -h", stdout: helpOf(t, "items", "list")},
		// Tab offers the columns, after a sign and after a comma.
		{line: "__complete items list --columns id,n", stdout: "id,name\n:6\n"},
		{line: "__complete items list --sort -", stdout: "-id\n-name\n:4\n"},
		{line: "__complete items list --filter n", stdout: "name\n:6\n"},
	} {
		t.Run(tt.line, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer

			code := Run(
				testTree(t),
				words(tt.line),
				Env{Stdout: &stdout, Stderr: &stderr, StdoutTerminal: tt.screen},
			)

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

// TestListOneClock: the conditions of a list read one clock, even one that
// moves between readings.
func TestListOneClock(t *testing.T) {
	t.Parallel()

	type row struct {
		Seen time.Time `json:"lastSeen"`
	}

	start := time.Now()
	cols := table.Columns[row]{{Name: "last-seen", Field: "lastSeen"}}

	older, err := cols.ParseFilter("last-seen>1h")
	require.NoError(t, err)
	newer, err := cols.ParseFilter("last-seen<1h")
	require.NoError(t, err)

	// Each reading moves the clock a minute; the row is 59m30s old at first.
	tick := start
	c := &run{now: func() time.Time {
		tick = tick.Add(time.Minute)

		return tick
	}}

	kept, err := listOf(
		c,
		cols,
		[]row{{Seen: start.Add(time.Minute - 59*time.Minute - 30*time.Second)}},
		[]table.Filter[row]{newer, older},
		"",
	)
	require.NoError(t, err)
	require.Empty(t, kept)
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

// TestTabAfterSealedItems: Tab offers no name after an item of --columns or
// --filter that the run refuses, since no name typed after it makes a line
// the run takes; nor for a prefix with a tab or a line break, which the
// answer to the shell cannot carry. A list that mixes plain names with + and
// - entries goes on (kit Q35).
func TestTabAfterSealedItems(t *testing.T) {
	for _, tt := range []struct{ line, words string }{
		{"__complete items list --filter=0,na", ""},
		{"__complete items list --filter 0,na", ""},
		{"__complete items list --filter=,na", ""},
		{"__complete items list --columns=0,", ""},
		{"__complete items list --columns typo,na", ""},
		{"__complete items list --columns ++id,na", ""},
		{"__complete items list --columns +id,-id,na", ""},
		{"__complete items list --filter=id=1,na", "id=1,name\n"},
		{"__complete items list --filter id=1,na", "id=1,name\n"},
		{"__complete items list --columns=id,-na", "id,-name\n"},
		{"__complete items list --columns +id,-na", "+id,-name\n"},
	} {
		var stdout bytes.Buffer

		require.Equal(
			t,
			0,
			Run(testTree(t), words(tt.line), Env{Stdout: &stdout}),
			tt.line,
		)
		// The last line is the directive.
		words, _, _ := strings.Cut(stdout.String(), ":")
		require.Equal(t, tt.words, words, tt.line)
	}

	for _, protocol := range []string{"__complete", "__completeNoDesc"} {
		for _, argv := range [][]string{
			{"--filter", "id=1,\nna"},
			{"--filter", "id=1\r,na"},
			{"--columns", "id,\t-na"},
			{"--sort", "\tna"},
		} {
			var stdout bytes.Buffer

			argv = append([]string{protocol, "items", "list"}, argv...)
			require.Equal(t, 0, Run(testTree(t), argv, Env{Stdout: &stdout}), argv)
			require.True(t, strings.HasPrefix(stdout.String(), ":"), argv)
		}
	}
}

// TestFilterHelp: the help of --filter shows the first filter of the list's
// own examples, so the example names columns the list has.
func TestFilterHelp(t *testing.T) {
	t.Parallel()

	tree, err := testBuild("prog", "A program", NewList(ListSpec[testS, NoInput, item]{
		Name:    "items",
		Short:   "S",
		Long:    "S.",
		Local:   true,
		Columns: itemColumns,
		NoRows:  "No items.",
		Example: []string{
			"prog items",
			"prog items --filter 'name:ap' --sort id",
			"prog items --filter=id=1",
		},
		Run: func(Ctx[testS], NoInput) ([]item, error) { return nil, nil },
	}))
	require.NoError(t, err)

	var b bytes.Buffer

	require.Equal(t, 0, Run(tree, []string{"items", "-h"}, Env{Stdout: &b}))
	require.Contains(
		t,
		b.String(),
		"--filter string    Keep the rows that match, such as name:ap; may be repeated\n",
	)
	require.Empty(t, filterExample([]string{"prog items --sort id"}))
}

// TestColumnsOfTheList: the list flags read the columns of the list the
// line reaches. Two lists of one row type, in one tree or in two, each
// have their own, also where a name is the same and its field is not.
func TestColumnsOfTheList(t *testing.T) {
	t.Parallel()

	rows := func(Ctx[testS], NoInput) ([]item, error) { return []item{{"1", "apple"}, {"2", "pear"}}, nil }
	list := func(name string, cols table.Columns[item]) Node {
		return NewList(ListSpec[testS, NoInput, item]{
			Name:    name,
			Short:   "S",
			Long:    "S.",
			Example: []string{"prog " + name},
			Local:   true,
			Columns: cols,
			NoRows:  "No items.",
			Run:     rows,
		})
	}

	// In "keys", the column "name" shows the ID.
	keys := table.Columns[item]{{Name: "name", Field: "id", Default: true}}

	one, err := testBuild(
		"prog",
		"A program",
		list("items", itemColumns),
		list("keys", keys),
	)
	require.NoError(t, err)

	other, err := testBuild("prog", "A program", list("keys", keys))
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

// TestNoColumnLeft: a --columns that takes away every column the table
// would show is a mistake of the line, refused before any call, with -o json
// as without.
func TestNoColumnLeft(t *testing.T) {
	const refused = "Error: --columns leaves no column to show.\n"

	for _, tt := range []struct {
		tree           *Tree
		line           string
		stdout, stderr string
		code           int
	}{
		{tree: testTree(t), line: "items list --columns -id,-name", stderr: refused, code: 1},
		{tree: testTree(t), line: "items list --columns -name,-id", stderr: refused, code: 1},
		{tree: testTree(t), line: "items list --columns -id,-name -o json", stderr: refused, code: 1},
		{tree: testTree(t), line: "items list --columns -id", stdout: "NAME\napple\n-\n"},
	} {
		var stdout, stderr bytes.Buffer

		code := Run(tt.tree, words(tt.line), Env{Stdout: &stdout, Stderr: &stderr})
		require.Equal(
			t,
			[]any{tt.code, tt.stdout, tt.stderr},
			[]any{code, stdout.String(), stderr.String()},
			tt.line,
		)
	}
}
