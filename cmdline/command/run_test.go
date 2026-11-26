package command

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
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

// TestReuseSheetColumns: the columns of a sheet changed after the build do
// not change what it shows.
func TestReuseSheetColumns(t *testing.T) {
	t.Parallel()

	s := spec()
	s.Columns = slices.Clone(itemColumns)
	s.Run = func(Ctx[testS], NoInput) (item, error) { return item{ID: "1", Name: "apple"}, nil }
	tree, err := testBuild("prog", "Items", New(s))
	require.NoError(t, err)

	show := func() string {
		var stdout, stderr bytes.Buffer

		require.Equal(
			t,
			0,
			Run(tree, []string{"get"}, Env{Stdout: &stdout, Stderr: &stderr}),
			stderr.String(),
		)

		return stdout.String()
	}

	before := show()
	s.Columns[1].Field = "id"

	require.Equal(t, before, show())
}

// TestReuseFold: the fold of a column changed after the build does not
// change what the list shows.
func TestReuseFold(t *testing.T) {
	t.Parallel()

	fold := map[string][]string{"both": {"1", "2"}}
	declared := slices.Clone(itemColumns)
	declared[0].Fold = fold
	cols := cloneColumns(declared)
	fold["both"][0] = "x"
	fold["other"] = nil

	require.Equal(t, map[string][]string{"both": {"1", "2"}}, cols[0].Fold)
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

// TestEdgeKnowsEverySpelling: every spelling that the server's
// authentication accepts is masked at the edge, in any case and inside a
// word, so a spelling the server learns fails here until the edge knows it.
func TestEdgeKnowsEverySpelling(t *testing.T) {
	t.Parallel()

	const id, secret = "c9f2aa000001", "S3cr3tS3cr3t"

	for _, p := range types.CredentialPrefixes() {
		for _, w := range []string{p + id + "-" + secret, strings.ToUpper(p + id + "-" + secret), `"x` + p + id + "-" + secret + `?ephemeral=true".`} {
			out := strings.ToLower(masked(w))
			require.NotContains(t, out, strings.ToLower(secret), w)
			require.NotContains(t, out, id, w)
		}
	}
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

// TestPrompt: a command with Confirm asks on stderr and goes on only on y
// or yes; no is "Aborted." and exit 1, no terminal is an error that names
// --force, and --force or a Prompt with no question asks nothing.
func TestPrompt(t *testing.T) {
	t.Parallel()

	ask := true
	tree, err := testBuild("prog", "A program", New(Spec[testS, getIn, NoOutput]{
		Name:    "delete",
		Short:   "Delete an item",
		Long:    "Delete an item.",
		Example: []string{"prog delete apple"},
		Local:   true,
		Confirm: func(_ Ctx[testS], in getIn) (Prompt, error) {
			if !ask || in.Name == "pear" {
				return Prompt{}, nil
			}

			return Prompt{
				Question: "Delete Item 1 (" + in.Name + ")?",
				Action:   "delete Item 1 (" + in.Name + ")",
			}, nil
		},
		Run:  func(Ctx[testS], getIn) (NoOutput, error) { return NoOutput{}, nil },
		Done: func(in getIn, _ NoOutput, _ time.Time) string { return "Item 1 (" + in.Name + ") deleted." },
	}))
	require.NoError(t, err)

	for _, tt := range []struct {
		name, args, stdin string
		terminal          bool
		stdout, stderr    string
		code              int
	}{
		{name: "yes", args: "delete apple", stdin: "y\n", terminal: true, stdout: "Item 1 (apple) deleted.\n", stderr: "Delete Item 1 (apple)? [y/N] "},
		{name: "yes in words", args: "delete apple", stdin: " YES \n", terminal: true, stdout: "Item 1 (apple) deleted.\n", stderr: "Delete Item 1 (apple)? [y/N] "},
		{name: "no", args: "delete apple", stdin: "n\n", terminal: true, stderr: "Delete Item 1 (apple)? [y/N] Aborted.\n", code: 1},
		{name: "enter is no", args: "delete apple", stdin: "\n", terminal: true, stderr: "Delete Item 1 (apple)? [y/N] Aborted.\n", code: 1},
		{name: "no answer is no", args: "delete apple", terminal: true, stderr: "Delete Item 1 (apple)? [y/N] Aborted.\n", code: 1},
		{
			name: "no terminal", args: "delete apple", stdin: "y\n",
			stderr: "Error: confirmation needed, but there is no terminal.\nRun again with --force to delete Item 1 (apple).\n", code: 1,
		},
		{name: "--force asks nothing", args: "delete apple --force", stdout: "Item 1 (apple) deleted.\n"},
		{name: "--force=false asks", args: "delete --force=false apple", stdin: "y\n", terminal: true, stdout: "Item 1 (apple) deleted.\n", stderr: "Delete Item 1 (apple)? [y/N] "},
		{name: "a prompt with no question asks nothing", args: "delete pear", stdout: "Item 1 (pear) deleted.\n"},
		{name: "--force where nothing is asked", args: "delete pear --force", stdout: "Item 1 (pear) deleted.\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer

			code := Run(
				tree,
				strings.Fields(tt.args),
				Env{
					Stdin:    strings.NewReader(tt.stdin),
					Stdout:   &stdout,
					Stderr:   &stderr,
					Terminal: tt.terminal,
				},
			)
			require.Equal(t, tt.stdout, stdout.String())
			require.Equal(t, tt.stderr, stderr.String())
			require.Equal(t, tt.code, code)
		})
	}
}

// TestConfirmUnseen: a question that cannot be written to stderr is not
// answered by what stdin holds: nothing runs.
func TestConfirmUnseen(t *testing.T) {
	t.Parallel()

	ran := false
	tree, err := testBuild("prog", "A program", New(Spec[testS, NoInput, NoOutput]{
		Name:    "delete",
		Short:   "S",
		Long:    "S.",
		Example: []string{"prog delete"},
		Local:   true,
		Confirm: func(Ctx[testS], NoInput) (Prompt, error) {
			return Prompt{Question: "Delete it?", Action: "delete it"}, nil
		},
		Run:  func(Ctx[testS], NoInput) (NoOutput, error) { ran = true; return NoOutput{}, nil },
		Done: func(NoInput, NoOutput, time.Time) string { return "deleted" },
	}))
	require.NoError(t, err)

	var stdout bytes.Buffer

	code := Run(
		tree,
		[]string{"delete"},
		Env{
			Stdin:    strings.NewReader("y\n"),
			Stdout:   &stdout,
			Stderr:   fullWriter{},
			Terminal: true,
		},
	)
	require.Equal(t, 1, code)
	require.False(t, ran)
	require.Empty(t, stdout.String())
}

// TestValid: Valid refuses a line before any call or lookup, with its own
// sentence; a line it takes runs.
func TestValid(t *testing.T) {
	t.Parallel()

	ran := false
	tree, err := testBuild("prog", "A program", New(Spec[testS, getIn, NoOutput]{
		Name:    "get",
		Short:   "Get",
		Long:    "Get.",
		Example: []string{"prog get a"},
		Local:   true,
		Valid: func(in getIn) error {
			if in.Name != "a" {
				//nolint:err113 // a sentence of the test
				return errors.New(strconv.Quote(in.Name) + " is not a.")
			}

			return nil
		},
		Run: func(Ctx[testS], getIn) (NoOutput, error) { ran = true; return NoOutput{}, nil },
	}))
	require.NoError(t, err)

	var stderr bytes.Buffer

	require.Equal(
		t,
		1,
		Run(tree, []string{"get", "b"}, Env{Stdout: io.Discard, Stderr: &stderr}),
	)
	require.Equal(t, "Error: \"b\" is not a.\n", stderr.String())
	require.False(t, ran)

	require.Equal(
		t,
		0,
		Run(tree, []string{"get", "a"}, Env{Stdout: io.Discard, Stderr: io.Discard}),
	)
	require.True(t, ran)
}

// refusedError is a refusal of the server, as the test program reads one.
type refusedError struct{}

func (refusedError) Error() string { return "refused" }

// TestAbout: a refusal of the server is told what the command knows of
// it (Program.About): the target as its lookup read it, the word it was
// typed as, and the expiry the command sent; any other error is not.
func TestAbout(t *testing.T) {
	t.Parallel()

	type in struct {
		Node   guarded               `arg:"node"`
		Expiry Opt[Expiry[NowNever]] `flag:"expiry" help:"x"`
	}

	now := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)

	type told struct {
		target Object
		expiry time.Time
	}

	for _, tt := range []struct {
		line string
		err  error
		want []told
	}{
		{"set mynode", refusedError{}, []told{{Object{"node", "12", "mynode"}, time.Time{}}}},
		{"set mynode --expiry 2024-01-01", refusedError{}, []told{{Object{"node", "12", "mynode"}, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}}},
		{"set mynode", errBroken, nil},
	} {
		var got []told

		p := testProgram()
		p.Name, p.Short = "prog", "A program"
		p.Refusal = func(err error) string {
			if errors.As(err, new(refusedError)) {
				return "refused"
			}

			return ""
		}
		p.About = func(_ error, target Object, expiry time.Time) {
			got = append(got, told{target, expiry})
		}
		p.Entities = []Entity{EntityOf(
			"node",
			func(context.Context, string) (guarded, error) {
				return guarded{ID: "12", Name: "mynode", Revision: "r1"}, nil
			},
			nil,
			func(g guarded) string { return g.Name },
			func(context.Context, string) (guarded, error) { return guarded{}, nil },
		)}

		tree, err := Build(p, New(Spec[testS, in, NoOutput]{
			Name:    "set",
			Short:   "S",
			Long:    "S.",
			Example: []string{"prog set mynode"},
			Local:   true,
			Run:     func(Ctx[testS], in) (NoOutput, error) { return NoOutput{}, tt.err },
			Done:    func(in, NoOutput, time.Time) string { return "" },
		}))
		require.NoError(t, err)

		Run(
			tree,
			strings.Fields(tt.line),
			Env{
				Stdout: io.Discard,
				Stderr: io.Discard,
				Now:    func() time.Time { return now },
			},
		)
		require.Equal(t, tt.want, got, tt.line)
	}
}
