package command

import (
	"strings"
	"testing"

	"github.com/juanfont/headscale/cmdline"
	"github.com/stretchr/testify/require"
)

// KitModel is the kit's tree of twelve commands, built with this builder:
// a kit row that names a command the real tree lacks waits for it. Its
// nodes list is the one of hs, so the kit's rows on columns run on
// Headscale's own columns.
func KitModel(tb testing.TB, hs *Tree) *Tree {
	tb.Helper()

	list := hs.leaves["nodes list"]
	require.NotNil(tb, list, "Headscale has no nodes list")

	t, err := build("headscale", "Headscale control server", corpusAliases(), nil, kitTree(list)...)
	require.NoError(tb, err)

	return t
}

// Outcome is what the builder makes of argv, as the kit compares it.
func Outcome(t *Tree, argv []string) string { return outcome(t, argv).String() }

// Want writes an expected outcome as Outcome writes one.
func Want(kind string, path, args []string, flags map[string][]string, word string) string {
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
