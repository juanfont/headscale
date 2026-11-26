package command_test

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/juanfont/headscale/cmd/headscale/newcli"
	"github.com/juanfont/headscale/cmdline/command"
	"github.com/stretchr/testify/require"
)

// TestHelpExamples: every example a help prints, read from the help as a
// person copies it, is a line the tree runs, and none is masked. Help goes
// through the edge that masks credentials like all output, so an example
// in the form of a credential shows as hskey-<kind>-*** and is refused
// when copied: such a value lives in the shell variable $id, which the
// test sets as a shell would.
func TestHelpExamples(t *testing.T) {
	t.Parallel()

	tree := newcli.Tree()
	id := "hskey-authreq-" + strings.Repeat("0a", 12)

	for _, path := range command.Paths(tree) {
		var out, errb bytes.Buffer
		require.Equal(
			t,
			0,
			command.Run(
				tree,
				append(strings.Fields(path), "--help"),
				command.Env{Stdout: &out, Stderr: &errb},
			),
			errb.String(),
		)

		_, examples, ok := strings.Cut(out.String(), "\nExamples:\n\n")
		require.True(t, ok, "%s --help shows no example", path)

		examples, _, _ = strings.Cut(examples, "\n\n")

		for e := range strings.Lines(examples) {
			e = strings.TrimSpace(e)
			require.NotContains(t, e, "***", "%s --help: the example is masked", path)

			argv := exampleArgv(t, e, id)
			got := command.Outcome(tree, argv)
			require.True(
				t,
				strings.HasPrefix(got, "run "),
				"%s --help: %q gives %s",
				path,
				e,
				got,
			)
			require.NoError(t, command.Valid(tree, argv), "%s --help: %q", path, e)
		}
	}
}

// TestHelpWritesNoValue: no help, the root's included, writes out a
// default or a limit, in any text it prints: Short, Long, the help of a
// flag or an argument, an example. Such a value goes stale when the code
// changes it; the text names the setting or the flag instead.
func TestHelpWritesNoValue(t *testing.T) {
	t.Parallel()

	for _, written := range []string{"7 days by default", "Defaults to 1h", "at most 100", "2m when unset", "within 15 seconds", "1 MiB", "(default 5d)"} {
		require.Regexp(t, writtenValue, written)
	}

	for _, fine := range []string{"--expiry 30d", "a duration from now (90d)", "exits 1", "0.0.0.0/0"} {
		require.NotRegexp(t, writtenValue, fine)
	}

	tree := newcli.Tree()

	// What a person wrote, before any formatting: a text cannot pass for
	// a generated "(default …)".
	for _, text := range command.Texts(tree) {
		require.NotRegexp(
			t,
			writtenValue,
			text,
			"%q: name the setting or the flag, not its value, which can change",
			text,
		)
	}

	// And what the help prints, the builder's own words too, with only the
	// "(default …)" the help appends from a flag's value taken out.
	for _, path := range append([]string{""}, command.Paths(tree)...) {
		var out, errb bytes.Buffer
		require.Equal(
			t,
			0,
			command.Run(
				tree,
				append(strings.Fields(path), "--help"),
				command.Env{Stdout: &out, Stderr: &errb},
			),
			errb.String(),
		)
		require.NotRegexp(
			t,
			writtenValue,
			withoutDefaults(tree, out.String()),
			"headscale %s --help: name the setting or the flag, not its value, which can change",
			path,
		)
	}
}

// writtenValue is a default or a limit written out: "7 days by default",
// "in 1 hour", "2m when unset", "defaults to 1h", "at most 100". "(default "
// is the help's own annotation of a flag, which no author writes.
var writtenValue = regexp.MustCompile(
	`(?i)\(default |\b\d+ ?(seconds?|minutes?|hours?|days?|weeks?|months?|years?|bytes|[KMG]i?B)\b|\b\d+\w* (by default|when unset)\b|\b(defaults? to|at most|up to|no more than|at least|limit of|maximum of) \d`,
)

// withoutDefaults is s without each "(default …)" the help appends for a
// flag of the tree, exactly as it appends it.
func withoutDefaults(tree *command.Tree, s string) string {
	for _, d := range command.Defaults(tree) {
		s = strings.ReplaceAll(s, d, "")
	}

	return s
}

// exampleArgv is the argv after headscale of an example, as a shell splits
// it with $id set to id: up to a pipe, after the variables it sets.
func exampleArgv(tb testing.TB, e, id string) []string {
	tb.Helper()

	e, _, _ = strings.Cut(e, " |")

	var (
		words []string
		cur   strings.Builder
		quote byte
		in    bool
	)

	for i := 0; i < len(e); i++ {
		switch c := e[i]; {
		case c == '$' && quote != '\'':
			require.True(
				tb,
				strings.HasPrefix(e[i:], "$id"),
				"%q: a shell variable other than $id",
				e,
			)
			cur.WriteString(id)

			i += len("$id") - 1
			in = true
		case quote != 0 && c == quote:
			quote = 0
		case quote != 0:
			cur.WriteByte(c)
		case c == '\'' || c == '"':
			quote, in = c, true
		case c == ' ':
			if in {
				words = append(words, cur.String())
				cur.Reset()
			}

			in = false
		default:
			cur.WriteByte(c)

			in = true
		}
	}

	if in {
		words = append(words, cur.String())
	}

	for len(words) > 0 && words[0] != "headscale" {
		require.Contains(tb, words[0], "=", "%q: no headscale", e)
		words = words[1:]
	}

	require.NotEmpty(tb, words, "%q: no headscale", e)

	return words[1:]
}
