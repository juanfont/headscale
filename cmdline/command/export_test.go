package command

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/juanfont/headscale/cmdline"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

// KitModel is the kit's tree of thirteen commands, built with this builder:
// a kit row that names a command the real tree lacks waits for it. Its
// nodes list is the one of hs, so the kit's rows on columns run on
// Headscale's own columns.
func KitModel(tb testing.TB, hs *Tree) *Tree {
	tb.Helper()

	list := hs.leaves["nodes list"]
	require.NotNil(tb, list, "Headscale has no nodes list")

	// The kit's commands and Headscale's list run with no session: their
	// sessions are not checked against each other.
	p := testProgram()
	p.Name, p.Short, p.Aliases = "headscale", "Headscale control server", corpusAliases()
	e := erase(p)
	e.sessionType = nil

	t, err := buildOf(e, kitTree(list)...)
	require.NoError(tb, err)

	return t
}

// Outcome is what the builder makes of argv, as the kit compares it.
func Outcome(t *Tree, argv []string) string { return outcome(t, argv).String() }

// Valid is the mistake Run finds in argv before any call: the parser's,
// the builder's, or a value that its type refuses. nil for a line that
// would run, and for help.
func Valid(t *Tree, argv []string) error {
	line, step, err := t.check(argv)
	if err != nil || step != stepRun {
		return err
	}

	return t.leaves[strings.Join(line.Command.Path, " ")].valid(line, t.cred())
}

// Want writes an expected outcome as Outcome writes one.
func Want(
	kind string,
	path, args []string,
	flags map[string][]string,
	word string,
) string {
	return result{kind: kind, path: path, args: args, flags: flags, word: word}.String()
}

// Golden compares got with the record at path.
func Golden(tb testing.TB, path, got string) {
	tb.Helper()
	golden(tb, path, got)
}

// Paths is every command and group of the tree, by path.
func Paths(t *Tree) []string {
	var (
		out  []string
		walk func(*cmdline.Info)
	)

	walk = func(c *cmdline.Info) {
		if len(c.Path) > 0 {
			out = append(out, strings.Join(c.Path, " "))
		}

		for _, s := range c.Commands {
			walk(s)
		}
	}
	walk(t.parser.Root())

	return out
}

// Texts is every text a person wrote for the help and the reference page:
// the root's line, the help of each group and command, its long text and
// examples, and the help of each flag, argument and column.
func Texts(t *Tree) []string {
	out := []string{t.short}

	var walk func(*cmdline.Info)

	walk = func(c *cmdline.Info) {
		out = append(out, c.Help)

		for _, f := range c.Flags {
			out = append(out, f.Help)
		}

		for _, a := range c.Args {
			out = append(out, a.Help)
		}

		if l, ok := t.leaves[strings.Join(c.Path, " ")]; ok {
			out = append(out, l.long, l.noRows, l.filter)
			out = append(out, l.example...)

			for _, ci := range l.info {
				out = append(out, ci.Help)
			}
		}

		for _, s := range c.Commands {
			walk(s)
		}
	}
	walk(t.parser.Root())

	return out
}

// Defaults is the "(default …)" the help appends for each flag of the tree
// that has a default.
func Defaults(t *Tree) []string {
	var (
		out  []string
		walk func(*cmdline.Info)
	)

	walk = func(c *cmdline.Info) {
		for _, f := range c.Flags {
			if f.Default != "" {
				out = append(out, " (default "+f.Default+")")
			}
		}

		for _, s := range c.Commands {
			walk(s)
		}
	}
	walk(t.parser.Root())

	return out
}

// build is a tree with the aliases it may use and the entities it looks
// up, of a program with no session: the tests of the grammar need trees
// with other aliases than a real program's, and a test of the retry a type
// of its own. A test tree is checked as a real one is.
func build(
	name, short string,
	aliases []string,
	ents []Entity,
	nodes ...Node,
) (*Tree, error) {
	p := testProgram()
	p.Name, p.Short, p.Aliases, p.Entities = name, short, aliases, ents

	return buildOf(erase(p), nodes...)
}

// testS is the session of a test tree: none, since a tree of the tests
// calls no server.
type testS = any

// errAuthReq is Headscale's refusal of a result that holds an auth
// request, which the test program declares as Headscale does.
var errAuthReq = errors.New(
	"a result or a row holds an auth request, whose id is the secret of the request: no command prints one",
)

// testProgram is the program of a test tree: Headscale's data, and no
// session.
func testProgram() Program[testS] {
	return Program[testS]{
		Version: func(context.Context) string { return "headscale version test" },
		Credentials: Credentials{
			Prefix: "hskey-",
			Kinds:  []string{"auth", "api", "authreq", "client", "oauthtok", "reg"},
			Fronts: types.SecretFronts(),
		},
		OpenFields: map[reflect.Type]string{
			reflect.TypeFor[clientv0.HealthMessage](): "Details",
		},
		Unprintable: map[reflect.Type]error{
			reflect.TypeFor[clientv0.AuthRequest](): errAuthReq,
		},
		MayBeMade: func(err error) bool { _, ok := errors.AsType[*madeError](err); return ok },
		Aliases:   []string{"ls", "rm", "approve"},
		ConfigEnv: "HEADSCALE_CONFIG",
		MaxFile:   16 << 20,
		Server:    "a running headscale",
	}
}

// testBuild is Build with the test program, named name and short.
//
//nolint:unparam // the name of a tree, which a test may change
func testBuild(name, short string, nodes ...Node) (*Tree, error) {
	p := testProgram()
	p.Name, p.Short = name, short

	return Build(p, nodes...)
}

// masked is s as the test program's edge writes it.
func masked(s string) string {
	cr := testProgram().Credentials

	return cr.masked(s)
}

// testCred is the rule at the edge of the test program.
func testCred() *Credentials {
	cr := testProgram().Credentials

	return &cr
}
