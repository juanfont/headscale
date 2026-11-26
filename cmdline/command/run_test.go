package command

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

// TestReuseDeclarations: a declaration changed after the build does not
// change the tree.
func TestReuseDeclarations(t *testing.T) {
	t.Parallel()

	s := spec()
	s.Aliases = []string{"ls"}
	children := []Node{New(s)}
	tree, err := testBuild(
		"prog",
		"Items",
		Group{Name: "items", Short: "Items", Commands: children},
	)
	require.NoError(t, err)

	s.Name = "lost"
	s.Aliases[0] = "other"
	s.Example[0] = "changed"
	children[0] = New(s)

	var stdout, stderr bytes.Buffer

	require.Equal(
		t,
		1,
		Run(tree, []string{"items", "gte"}, Env{Stdout: &stdout, Stderr: &stderr}),
	)
	require.Contains(t, stderr.String(), `Did you mean "items get"?`)

	got := tree.Commands()
	require.Len(t, got, 1)
	require.Equal(t, []string{"prog items get"}, got[0].Example)
	require.Equal(t, []string{"ls"}, got[0].Aliases)
}

// TestReuseListColumns: columns changed after the build do not change what
// a list filters and shows.
func TestReuseListColumns(t *testing.T) {
	t.Parallel()

	cols := slices.Clone(itemColumns)
	list := NewList(ListSpec[testS, NoInput, item]{
		Name:    "list",
		Short:   "List items",
		Long:    "List items.",
		Example: []string{"prog list"},
		NoRows:  "No items.",
		Local:   true,
		Columns: cols,
		Run: func(Ctx[testS], NoInput) ([]item, error) {
			return []item{{ID: "1", Name: "2"}, {ID: "2", Name: "1"}}, nil
		},
	})
	tree, err := testBuild("prog", "Items", list)
	require.NoError(t, err)

	cols[1].Field = "id"

	var stdout, stderr bytes.Buffer

	require.Equal(
		t,
		0,
		Run(
			tree,
			[]string{"list", "--filter=name=1", "--columns=id"},
			Env{Stdout: &stdout, Stderr: &stderr},
		),
		stderr.String(),
	)
	require.Equal(t, "ID\n2\n", stdout.String())
}

var errBroken = errors.New("it broke")

// testTree is a tree of local commands that shows every way the builder
// prints.
func testTree(t *testing.T) *Tree {
	t.Helper()

	tree, err := testBuild(
		"prog",
		"A program",
		Group{
			Name:     "items",
			Short:    "Manage items",
			OldNames: []string{"item"},
			Commands: []Node{
				NewList(ListSpec[testS, NoInput, item]{
					Name:    "list",
					Short:   "List items",
					Long:    "List items.",
					Example: []string{"prog items list"},
					Aliases: []string{"ls"},
					Local:   true,
					Columns: itemColumns,
					NoRows:  "No items.",
					Run:     func(Ctx[testS], NoInput) ([]item, error) { return []item{{"1", "apple"}, {"2", ""}}, nil },
				}),
				New(Spec[testS, getIn, item]{
					Name:    "get",
					Short:   "Show an item",
					Long:    "Show an item.",
					Example: []string{"prog items get apple"},
					Local:   true,
					Columns: itemColumns,
					Run: func(c Ctx[testS], in getIn) (item, error) {
						c.Note("a note")

						return item{ID: "1", Name: in.Name}, nil
					},
				}),
				New(Spec[testS, getIn, item]{
					Name:    "rename",
					Short:   "Rename an item",
					Long:    "Rename an item.",
					Example: []string{"prog items rename apple"},
					Local:   true,
					Run:     func(_ Ctx[testS], in getIn) (item, error) { return item{ID: "1", Name: in.Name}, nil },
					Done:    func(in getIn, out item, _ time.Time) string { return "Item " + out.ID + " is " + in.Name + "." },
				}),
				New(Spec[testS, NoInput, NoOutput]{
					Name:    "break",
					Short:   "Fail",
					Long:    "Fail.",
					Example: []string{"prog items break"},
					Local:   true,
					Run:     func(Ctx[testS], NoInput) (NoOutput, error) { return NoOutput{}, errBroken },
				}),
			},
		},
	)
	require.NoError(t, err)

	return tree
}

func TestRun(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		line           string
		stdout, stderr string
		code           int
	}{
		{line: "items list", stdout: "ID  NAME\n1   apple\n2   -\n"},
		{line: "items ls -o json", stdout: "[\n  {\n    \"id\": \"1\",\n    \"name\": \"apple\"\n  },\n  {\n    \"id\": \"2\",\n    \"name\": \"\"\n  }\n]\n"},
		{line: "items get apple", stdout: "ID:    1\nName:  apple\n", stderr: "a note\n"},
		{line: "items get apple -o json", stdout: "{\n  \"id\": \"1\",\n  \"name\": \"apple\"\n}\n"},
		{line: "items rename pear", stdout: "Item 1 is pear.\n"},
		{line: "items rename pear -o json", stdout: "{\n  \"id\": \"1\",\n  \"name\": \"pear\"\n}\n"},
		{line: "items break", stderr: "Error: it broke\n", code: 1},
		{line: "items get", stderr: "Error: `items get` needs at least 1 argument, got 0.\n\n  prog items get <name> [extra]\n", code: 1},
		{line: "items get a b c", stderr: "Error: `items get` takes at most 2 arguments, got 3.\n\n  prog items get <name> [extra]\n", code: 1},
		{line: "items list x", stderr: "Error: `items list` takes no arguments, got 1.\n\n  prog items list\n", code: 1},
		{line: "items get a --count x", stderr: "Error: \"x\" is not a valid --count: strconv.ParseInt: parsing \"x\": invalid syntax.\n", code: 1},
		{line: "items lst", stderr: "Error: unknown command \"items lst\". Did you mean \"items list\"?\nRun `prog items --help`.\n", code: 1},
		{line: "item list", stderr: "Error: unknown command \"item\". It is now \"items\".\nRun `prog items --help`.\n", code: 1},
		{line: "items --count 1", stderr: "Error: --count does not apply to `items`.\nRun `prog items --help`.\n", code: 1},
		{line: "items list -n 1", stderr: "Error: --count does not apply to `items list`.\nRun `prog items list --help`.\n", code: 1},
		{line: "items list -x", stderr: "Error: unknown flag -x for `items list`.\nRun `prog items list --help`.\n", code: 1},
		{line: "nodse list", stderr: "Error: unknown command \"nodse\".\nRun `prog --help`.\n", code: 1},
		{line: "--bogus items list", stderr: "Error: unknown flag --bogus for `prog`.\nRun `prog --help`.\n", code: 1},
		{line: "items list --bogus -h", stderr: "Error: unknown flag --bogus for `items list`.\nRun `prog items list --help`.\n", code: 1},
		{line: "items list -o", stderr: "Error: --output needs a value.\nRun `prog items list --help`.\n", code: 1},
		{line: "items list -o=", stderr: "Error: \"\" is not a valid --output: the only format is json.\n", code: 1},
		{line: "items list -o yaml", stderr: "Error: \"yaml\" is not a valid --output: the only format is json.\n", code: 1},
		{line: "items list -o a -o b", stderr: "Error: \"a\" is not a valid --output: the only format is json.\n", code: 1},
		{line: "items list -o json -o json", stderr: "Error: --output is given twice. Only --filter may be repeated.\n", code: 1},
		{line: "--help=1", stderr: "Error: --help takes true or false, not \"1\".\n", code: 1},
		{line: "items list --help=false", stdout: "ID  NAME\n1   apple\n2   -\n"},
		{line: "items -o json", stdout: `Manage items

Commands:

  list                    List items (alias: ls)
  get <name> [extra]      Show an item
  rename <name> [extra]   Rename an item
  break                   Fail

Examples:

  prog items list
  prog items get apple
  prog items rename apple
  prog items break
`},
	} {
		t.Run(tt.line, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer

			code := Run(
				testTree(t),
				strings.Fields(tt.line),
				Env{Stdout: &stdout, Stderr: &stderr, Now: time.Now},
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

// TestNothingToChange: a set needs one of the flags it changes; a set with
// no such flag replaces its argument, and a wrong count comes first.
func TestNothingToChange(t *testing.T) {
	t.Parallel()

	type setIn struct {
		Name  string      `arg:"name"`
		New   Opt[string] `flag:"new-name" help:"New name"`
		Email Opt[string] `flag:"email"    help:"New email"`
		Force bool        `flag:"force"    help:"Do not ask"`
	}

	type replaceIn struct {
		Name string `arg:"name"`
	}

	done := func(setIn, NoOutput, time.Time) string { return "set" }
	tree, err := testBuild(
		"prog",
		"A program",
		Group{Name: "items", Short: "Items", Commands: []Node{
			New(
				Spec[testS, setIn, NoOutput]{
					Name:        "set",
					Short:       "S",
					Long:        "S.",
					Example:     []string{"prog items set a --email x"},
					Local:       true,
					NeedsChange: true,
					Run:         noop[setIn, NoOutput],
					Done:        done,
				},
			),
			// A set that does not say NeedsChange takes a line with no flag.
			New(
				Spec[testS, setIn, NoOutput]{
					Name:    "replace",
					Short:   "S",
					Long:    "S.",
					Example: []string{"prog items replace a"},
					Local:   true,
					Run:     noop[setIn, NoOutput],
					Done:    done,
				},
			),
			Group{Name: "tags", Short: "Tags", Commands: []Node{
				New(
					Spec[testS, replaceIn, NoOutput]{
						Name:    "set",
						Short:   "S",
						Long:    "S.",
						Example: []string{"prog items tags set a"},
						Local:   true,
						Run:     noop[replaceIn, NoOutput],
					},
				),
			}},
		}},
	)
	require.NoError(t, err)

	for line, want := range map[string]string{
		"items set a":              "Error: nothing to change. Give at least one of\n  --new-name, --email\n",
		"items set a --force":      "Error: nothing to change. Give at least one of\n  --new-name, --email\n",
		"items set":                "Error: `items set` needs 1 argument, got 0.\n\n  prog items set <name>\n",
		"items set a --new-name=":  "",
		"items set a --email x":    "",
		"items tags set a":         "",
		"items replace a":          "",
		"items set a -h --force=x": "Error: --force takes true or false, not \"x\".\n",
	} {
		var stdout, stderr bytes.Buffer

		Run(tree, strings.Fields(line), Env{Stdout: &stdout, Stderr: &stderr})
		require.Equal(t, want, stderr.String(), line)
	}
}

// TestNeedsChangeNeedsAFlag: NeedsChange on a command with no Opt flag is
// a wrong spec.
func TestNeedsChangeNeedsAFlag(t *testing.T) {
	t.Parallel()

	type in struct {
		Name string `arg:"name"`
	}

	_, err := testBuild("prog", "A program", New(Spec[testS, in, NoOutput]{
		Name:        "set",
		Short:       "S",
		Long:        "S.",
		Example:     []string{"prog set a"},
		Local:       true,
		NeedsChange: true,
		Run:         noop[in, NoOutput],
	}))
	require.EqualError(t, err, "set: NeedsChange and no Opt flag that changes a field")
}

// TestVisibleText: a Done text and everything on stderr show control
// characters of the server as escapes; JSON escapes them itself.
func TestVisibleText(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer

	require.Equal(
		t,
		0,
		Run(
			testTree(t),
			[]string{"items", "rename", "a\x1b[31m\u202e"},
			Env{Stdout: &stdout, Stderr: &stderr},
		),
	)
	require.Equal(t, `Item 1 is a\x1b[31m\u202e.`+"\n", stdout.String())

	stdout.Reset()
	require.Equal(
		t,
		0,
		Run(
			testTree(t),
			[]string{"items", "rename", "a\x1b\u202e\u0085", "-o", "json"},
			Env{Stdout: &stdout, Stderr: &stderr},
		),
	)
	require.Contains(t, stdout.String(), `"name": "a\u001b\u202e\u0085"`)

	// The last filter keeps the sentence's own breaks and the backslashes
	// that the text of the server already has doubled.
	var b bytes.Buffer

	_, err := visible{&b}.Write([]byte("Error: \x1b[2J\u202e \\\\x\n\tnext\n"))
	require.NoError(t, err)
	require.Equal(t, `Error: \x1b[2J\u202e \\x`+"\n\tnext\n", b.String())
}
