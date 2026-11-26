package command

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/cmdline/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/stretchr/testify/require"
)

type item struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type getIn struct {
	Name  string      `arg:"name"   help:"<name> is any word."`
	Extra Opt[string] `arg:"extra"`
	Count int         `flag:"count" help:"How many"            short:"n"`
}

var itemColumns = table.Columns[item]{
	{Name: "id", Field: "id", Default: true},
	{Name: "name", Field: "name", Default: true},
}

func noop[In, Out any](Ctx[testS], In) (Out, error) {
	var out Out

	return out, nil
}

// spec is a complete local spec that a case breaks one field of.
func spec() Spec[testS, NoInput, item] {
	return Spec[testS, NoInput, item]{
		Name:    "get",
		Short:   "Show an item",
		Long:    "Show an item.",
		Example: []string{"prog items get"},
		Local:   true,
		Columns: itemColumns,
		Run:     noop[NoInput, item],
	}
}

func TestBuildChecks(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		nodes []Node
		want  string
	}{
		{"no short", []Node{New(func() Spec[testS, NoInput, item] { s := spec(); s.Short = ""; return s }())}, "get: no Short"},
		{"no long", []Node{New(func() Spec[testS, NoInput, item] { s := spec(); s.Long = ""; return s }())}, "get: no Long"},
		{"no example", []Node{New(func() Spec[testS, NoInput, item] { s := spec(); s.Example = nil; return s }())}, "get: no Example"},
		{"no run", []Node{New(func() Spec[testS, NoInput, item] { s := spec(); s.Run = nil; return s }())}, "get: no Run"},
		{"an alias that is not allowed", []Node{New(func() Spec[testS, NoInput, item] { s := spec(); s.Aliases = []string{"show"}; return s }())}, `get: alias "show" is none of [ls rm approve]`},
		{
			"a result with nothing to show it",
			[]Node{New(func() Spec[testS, NoInput, item] { s := spec(); s.Columns = nil; return s }())},
			"get: a result and neither Columns nor Done to show it",
		},
		{
			"a column of a field the type does not have",
			[]Node{New(func() Spec[testS, NoInput, item] {
				s := spec()
				s.Columns = table.Columns[item]{{Name: "x", Field: "nam"}}

				return s
			}())},
			`get: column "x": unknown field "nam" in command.item`,
		},
		{
			"a block of no map",
			[]Node{New(func() Spec[testS, NoInput, item] {
				s := spec()
				s.Blocks = table.Blocks[item]{{Title: "X", Field: "name"}}

				return s
			}())},
			`get: block "X": field "name": string is no map with text keys`,
		},
		{
			"a block with no sheet",
			[]Node{New(func() Spec[testS, NoInput, item] {
				s := spec()
				s.Columns, s.Blocks = nil, table.Blocks[item]{{Title: "X", Field: "name"}}
				s.Done = func(NoInput, item, time.Time) string { return "done" }

				return s
			}())},
			"get: blocks and no Columns: a block follows the lines of a sheet\nblock \"X\": field \"name\": string is no map with text keys",
		},
		{
			"both Columns and Done",
			[]Node{New(func() Spec[testS, NoInput, item] {
				s := spec()
				s.Done = func(NoInput, item, time.Time) string { return "done" }

				return s
			}())},
			"get: both Columns and Done; Done is printed in place of the sheet",
		},
		{
			"Verbatim with Columns",
			[]Node{New(func() Spec[testS, NoInput, item] {
				s := spec()
				s.Verbatim = func(o item) string { return o.Name }

				return s
			}())},
			"get: " + errVerbatim.Error(),
		},
		{
			"Verbatim with Done",
			[]Node{New(func() Spec[testS, NoInput, item] {
				s := spec()
				s.Columns, s.Done = nil, func(NoInput, item, time.Time) string { return "done" }
				s.Verbatim = func(o item) string { return o.Name }

				return s
			}())},
			"get: " + errVerbatim.Error(),
		},
		{
			"Verbatim with Secret",
			[]Node{New(func() Spec[testS, NoInput, item] {
				s := spec()
				s.Columns = nil
				s.Verbatim = func(o item) string { return o.Name }
				s.Secret = func(o item) string { return o.Name }

				return s
			}())},
			// The checks of Secret say their own besides.
			"get: " + errVerbatim.Error() + "\n" +
				"a result that holds a secret, a field key or secret at any depth, is printed by Secret, and only such a result has Secret\n" +
				"get: a Secret needs list and delete beside it, which the sentence of a lost secret names",
		},
		{
			"Verbatim of no result",
			[]Node{New(Spec[testS, NoInput, NoOutput]{
				Name: "get", Short: "S", Long: "S.", Example: []string{"prog get"}, Local: true, Run: noop[NoInput, NoOutput],
				Verbatim: func(NoOutput) string { return "" },
			})},
			"get: " + errVerbatim.Error(),
		},
		{
			"a list with no default column",
			[]Node{NewList(ListSpec[testS, NoInput, item]{
				Name: "list", Short: "List", Long: "List.", Example: []string{"prog list"}, Local: true,
				Columns: table.Columns[item]{{Name: "id", Field: "id"}}, NoRows: "No items.", Run: noop[NoInput, []item],
			})},
			"list: a list with no Default column",
		},
		{
			"a list with no columns",
			[]Node{NewList(ListSpec[testS, NoInput, item]{Name: "list", Short: "List", Long: "List.", Example: []string{"prog list"}, Local: true, NoRows: "No items.", Run: noop[NoInput, []item]})},
			"list: a list with no columns",
		},
		{
			"a list with no sentence for no rows",
			[]Node{NewList(ListSpec[testS, NoInput, item]{Name: "list", Short: "List", Long: "List.", Example: []string{"prog list"}, Local: true, Columns: itemColumns, Run: noop[NoInput, []item]})},
			"list: a list with no NoRows sentence",
		},
		{
			"a list cut to the terminal that does not say so",
			[]Node{NewList(ListSpec[testS, NoInput, clientv0.User]{
				Name: "list", Short: "List", Long: "List.", Example: []string{"prog list"}, Local: true, NoRows: "No users.", Run: noop[NoInput, []clientv0.User],
				Columns: table.Columns[clientv0.User]{{Name: "nodes", Field: "nodes", List: table.Cut, Default: true}},
			})},
			`list: column "nodes" is cut to the width of the terminal, and Long does not say so: "NODES is truncated to fit your terminal", with the way to read all of it`,
		},
		{
			"a default filter that does not read",
			[]Node{NewList(ListSpec[testS, NoInput, stated]{
				Name: "list", Short: "List", Long: "List; --all shows all.", Example: []string{"prog list"}, Local: true, NoRows: "No keys.", Run: noop[NoInput, []stated],
				Columns: statedColumns, Only: "status=valid",
			})},
			`list: the filter Only "status=valid": unknown column "status". Did you mean "state"?`,
		},
		{
			"a default filter on a column that is shown",
			[]Node{NewList(ListSpec[testS, NoInput, stated]{
				Name: "list", Short: "List", Long: "List; --all shows all.", Example: []string{"prog list"}, Local: true, NoRows: "No keys.", Run: noop[NoInput, []stated],
				Columns: statedColumns, Only: "name=a",
			})},
			`list: the filter Only "name=a": column "name" is a Default column: --all adds the column of Only to the defaults`,
		},
		{
			"a default filter the help does not explain",
			[]Node{NewList(ListSpec[testS, NoInput, stated]{
				Name: "list", Short: "List", Long: "List.", Example: []string{"prog list"}, Local: true, NoRows: "No keys.", Run: noop[NoInput, []stated],
				Columns: statedColumns, Only: "state=valid",
			})},
			"list: a list with Only hides rows, and Long does not say what --all shows",
		},
		{
			"a delete that does not ask",
			[]Node{New(Spec[testS, getIn, NoOutput]{Name: "delete", Short: "Delete", Long: "Delete.", Example: []string{"prog delete a"}, Local: true, Run: noop[getIn, NoOutput]})},
			"delete: a delete with no Confirm: every delete asks first",
		},
		{"a group with no short", []Node{Group{Name: "items", Commands: []Node{New(spec())}}}, "items: no Short"},
		{
			"a short letter with two meanings",
			[]Node{
				New(Spec[testS, getIn, NoOutput]{Name: "get", Short: "Get", Long: "Get.", Example: []string{"prog get a"}, Local: true, Run: noop[getIn, NoOutput]}),
				New(Spec[testS, struct {
					Number int `flag:"number" help:"A number" short:"n"`
				}, NoOutput]{Name: "other", Short: "Other", Long: "Other.", Example: []string{"prog other"}, Local: true, Run: noop[struct {
					Number int `flag:"number" help:"A number" short:"n"`
				}, NoOutput]}),
			},
			"other: -n is --number here and --count elsewhere",
		},
		{
			"a command with its own --version",
			[]Node{New(Spec[testS, struct {
				Version bool `flag:"version" help:"V"`
			}, NoOutput]{Name: "get", Short: "Get", Long: "Get.", Example: []string{"prog get"}, Local: true, Run: noop[struct {
				Version bool `flag:"version" help:"V"`
			}, NoOutput]})},
			"get: flag --version is the root's",
		},
		{
			"an old name that is a command",
			[]Node{New(func() Spec[testS, NoInput, item] { s := spec(); s.OldNames = []string{"get"}; return s }())},
			`get: old name "get" is a command`,
		},
		{
			"an old name of two commands",
			[]Node{
				New(func() Spec[testS, NoInput, item] { s := spec(); s.OldNames = []string{"show"}; return s }()),
				New(func() Spec[testS, NoInput, item] {
					s := spec()
					s.Name = "other"
					s.OldNames = []string{"show"}

					return s
				}()),
			},
			`other: old name "show" is also the old name of get`,
		},
		{
			"a flag with no help",
			[]Node{New(Spec[testS, struct {
				Number int `flag:"number"`
			}, NoOutput]{Name: "get", Short: "Get", Long: "Get.", Example: []string{"prog get"}, Local: true, Run: noop[struct {
				Number int `flag:"number"`
			}, NoOutput]})},
			"get: flag --number has no help",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := testBuild("prog", "A program", tt.nodes...)
			require.EqualError(t, err, tt.want)
		})
	}
}

// TestDerivedFlags: --output and --config follow from the spec.
func TestDerivedFlags(t *testing.T) {
	t.Parallel()

	tree, err := testBuild(
		"prog",
		"A program",
		New(
			Spec[testS, NoInput, NoOutput]{
				Name:    "local",
				Short:   "L",
				Long:    "L.",
				Example: []string{"prog local"},
				Local:   true,
				Run:     noop[NoInput, NoOutput],
			},
		),
		New(
			Spec[testS, NoInput, item]{
				Name:    "object",
				Short:   "O",
				Long:    "O.",
				Example: []string{"prog object"},
				Local:   true,
				Columns: itemColumns,
				Run:     noop[NoInput, item],
			},
		),
		New(
			Spec[testS, NoInput, NoOutput]{
				Name:        "config",
				Short:       "C",
				Long:        "C.",
				Example:     []string{"prog config"},
				Local:       true,
				ReadsConfig: true,
				Run:         noop[NoInput, NoOutput],
			},
		),
		New(
			Spec[testS, NoInput, NoOutput]{
				Name:    "server",
				Short:   "S",
				Long:    "S.",
				Example: []string{"prog server"},
				Run:     noop[NoInput, NoOutput],
			},
		),
		New(Spec[testS, NoInput, NoOutput]{
			Name:        "maybe",
			Short:       "M",
			Long:        "M.",
			Example:     []string{"prog maybe"},
			Local:       true,
			NeedsServer: func(NoInput) bool { return false },
			Run:         noop[NoInput, NoOutput],
		}),
		New(
			Spec[testS, NoInput, NoOutput]{
				Name:    "tool",
				Short:   "T",
				Long:    "T.",
				Example: []string{"prog tool"},
				NoJSON:  true,
				Run:     noop[NoInput, NoOutput],
				Done:    func(NoInput, NoOutput, time.Time) string { return "t" },
			},
		),
		New(
			Spec[testS, NoInput, Said]{
				Name:    "said",
				Short:   "S",
				Long:    "S.",
				Example: []string{"prog said"},
				Local:   true,
				Run:     noop[NoInput, Said],
				Done:    func(NoInput, Said, time.Time) string { return "s" },
			},
		),
	)
	require.NoError(t, err)

	flags := map[string][]string{}

	for _, c := range tree.parser.Root().Commands {
		for _, f := range c.Flags {
			flags[c.Name] = append(flags[c.Name], f.Name)
		}
	}

	require.Equal(t, map[string][]string{
		"local":  {"help"},
		"object": {"output", "help"},
		"config": {"config", "help"},
		"server": {"output", "config", "help"},
		"maybe":  {"output", "config", "help"},
		"tool":   {"config", "help"},
		"said":   {"help"},
	}, flags)

	// What Said holds is printed by Done alone, and a test tool prints one
	// sentence: a spec that would print another way does not build.
	done := func(NoInput, Said, time.Time) string { return "" }
	saidCols := table.Columns[Said]{{Name: "what", Field: "What", Default: true}}

	for name, n := range map[string]Node{
		"Said with no Done":    New(Spec[testS, NoInput, Said]{Name: "x", Short: "X", Long: "X.", Example: []string{"prog x"}, Run: noop[NoInput, Said]}),
		"Said with Columns":    New(Spec[testS, NoInput, Said]{Name: "x", Short: "X", Long: "X.", Example: []string{"prog x"}, Run: noop[NoInput, Said], Columns: saidCols}),
		"NoJSON with no Done":  New(Spec[testS, NoInput, NoOutput]{Name: "x", Short: "X", Long: "X.", Example: []string{"prog x"}, NoJSON: true, Run: noop[NoInput, NoOutput]}),
		"NoJSON with Columns":  New(Spec[testS, NoInput, item]{Name: "x", Short: "X", Long: "X.", Example: []string{"prog x"}, NoJSON: true, Run: noop[NoInput, item], Columns: itemColumns}),
		"Said and Done builds": New(Spec[testS, NoInput, Said]{Name: "x", Short: "X", Long: "X.", Example: []string{"prog x"}, Run: noop[NoInput, Said], Done: done}),
	} {
		_, err := testBuild("prog", "A program", n)

		switch {
		case name == "Said and Done builds":
			require.NoError(t, err, name)
		case strings.HasPrefix(name, "Said"):
			require.ErrorContains(t, err, errSaid.Error(), name)
		default:
			require.ErrorContains(t, err, errNoJSON.Error(), name)
		}
	}
}

// TestSaid: a write with no answer body names what it answered in Done;
// it counts as no output, as NoOutput does.
func TestSaid(t *testing.T) {
	t.Parallel()

	tree, err := testBuild("prog", "A program", New(Spec[testS, NoInput, Said]{
		Name:    "answer",
		Short:   "A",
		Long:    "A.",
		Example: []string{"prog answer"},
		Local:   true,
		Run:     func(Ctx[testS], NoInput) (Said, error) { return Said{What: "Registration of \"newlaptop\""}, nil },
		Done:    func(_ NoInput, out Said, _ time.Time) string { return out.What + " rejected." },
	}))
	require.NoError(t, err)

	var stdout, stderr bytes.Buffer

	require.Equal(
		t,
		0,
		Run(tree, []string{"answer"}, Env{Stdout: &stdout, Stderr: &stderr}),
		stderr.String(),
	)
	require.Equal(t, "Registration of \"newlaptop\" rejected.\n", stdout.String())

	// It has no object to print, so a Local command has no --output.
	stdout.Reset()
	require.Equal(
		t,
		1,
		Run(
			tree,
			[]string{"answer", "-o", "json"},
			Env{Stdout: &stdout, Stderr: &stderr},
		),
	)
	require.Empty(t, stdout.String())
}

// TestSessionOfTheProgram: a spec made for another session than the
// program's is refused when the tree is built, with its path: it would
// run with that session's zero value.
func TestSessionOfTheProgram(t *testing.T) {
	t.Parallel()

	p := Program[int]{
		Name:    "prog",
		Short:   "A program",
		Version: func(context.Context) string { return "prog" },
		Session: func(Ctx[int], bool) (int, error) { return 1, nil },
	}

	_, err := Build(p, New(Spec[string, NoInput, NoOutput]{
		Name:    "run",
		Short:   "Run",
		Long:    "Run.",
		Example: []string{"prog run"},
		Run:     func(Ctx[string], NoInput) (NoOutput, error) { return NoOutput{}, nil },
		Done:    func(NoInput, NoOutput, time.Time) string { return "" },
	}))
	require.ErrorContains(
		t,
		err,
		"run: a spec of session string in a program of session int",
	)
}

// TestNoVersion: a program with no Version has no --version; its commands
// run all the same.
func TestNoVersion(t *testing.T) {
	t.Parallel()

	p := Program[string]{Name: "prog", Short: "A program"}

	tree, err := Build(p, New(Spec[string, NoInput, NoOutput]{
		Name:    "run",
		Short:   "Run",
		Long:    "Run.",
		Example: []string{"prog run"},
		Local:   true,
		Run:     func(Ctx[string], NoInput) (NoOutput, error) { return NoOutput{}, nil },
		Done:    func(NoInput, NoOutput, time.Time) string { return "" },
	}))
	require.NoError(t, err)

	var stderr strings.Builder

	require.Equal(
		t,
		0,
		Run(tree, []string{"run"}, Env{Stdout: io.Discard, Stderr: io.Discard}),
	)
	require.Equal(
		t,
		1,
		Run(tree, []string{"--version"}, Env{Stdout: io.Discard, Stderr: &stderr}),
	)
	require.Contains(t, stderr.String(), "unknown flag --version")
}
