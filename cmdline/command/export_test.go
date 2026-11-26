package command

import (
	"context"
	"strings"
	"testing"

	"github.com/juanfont/headscale/cmdline"
)

// KitModel is the kit's tree of twelve commands, built with this builder:
// a kit row that names a command the real tree lacks waits for it.
func KitModel(tb testing.TB) *Tree {
	tb.Helper()

	return corpusTree(tb, "")
}

// Outcome is what the builder makes of argv, as the kit compares it.
func Outcome(t *Tree, argv []string) string { return outcome(t, argv).String() }

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

// testProgram is the program of a test tree: Headscale's data, and no
// session.
func testProgram() Program[testS] {
	return Program[testS]{
		Version:   func(context.Context) string { return "headscale version test" },
		Aliases:   []string{"ls", "rm", "approve"},
		ConfigEnv: "HEADSCALE_CONFIG",
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
