package command

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestCommandHelp(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		args []string
		want string
	}{
		// A local object is not the API's.
		{[]string{"items", "get", "-h"}, `Show an item.

Usage:

  prog items get <name> [extra] [flags]

  <name> is any word.

Examples:

  prog items get apple

Flags:

  -n, --count int       How many
  -o, --output string   Output format: json
  -h, --help            Show this help
`},
		// The help comes before the argument count.
		{[]string{"-h", "items", "ls", "x"}, `List items.

Usage:

  prog items list [flags]

Aliases: ls

Examples:

  prog items list

Flags:

      --columns string   Columns to show: a list, or +name and -name to change the default
      --list-columns     List the columns, the API field behind each, and exit
      --filter string    Keep the rows that match; may be repeated
      --sort string      Column to sort by; -name sorts in reverse
  -o, --output string    Output format: json (the API object)
  -h, --help             Show this help
`},
	} {
		var stdout bytes.Buffer

		require.Equal(t, 0, Run(testTree(t), tt.args, Env{Stdout: &stdout}))

		if diff := cmp.Diff(tt.want, stdout.String()); diff != "" {
			t.Errorf("%v (-want +got):\n%s", tt.args, diff)
		}
	}
}

// TestHelpDefault: a flag's default is said once, in its tag, and the help
// prints it.
func TestHelpDefault(t *testing.T) {
	t.Parallel()

	type in struct {
		Expiry Expiry[NoWords] `default:"1h" flag:"expiry" help:"When it ends"`
	}

	tree, err := Build("prog", "A program", New(Spec[in, NoOutput]{
		Name: "make", Short: "Make", Long: "Make.", Example: []string{"prog make"}, Local: true, Run: noop[in, NoOutput],
	}))
	require.NoError(t, err)

	var b bytes.Buffer

	require.Equal(t, 0, Run(tree, []string{"make", "-h"}, Env{Stdout: &b}))
	require.Contains(t, b.String(), "      --expiry string   When it ends (default 1h)\n")
}

// TestRootHelpSections: a command that needs no server unless a flag says
// so is local, and one that talks to the server unless a flag says not,
// such as a read with the database bypass, is a server command.
func TestRootHelpSections(t *testing.T) {
	t.Parallel()

	type in struct {
		Flip bool `flag:"flip" help:"Flip"`
	}

	cmd := func(name string, needs func(in) bool) Node {
		return New(Spec[in, NoOutput]{
			Name: name, Short: "S " + name, Long: "S.", Example: []string{"prog " + name}, Local: true, NeedsServer: needs, Run: noop[in, NoOutput],
		})
	}

	tree, err := Build("prog", "A program",
		cmd("local", nil),
		cmd("when-flipped", func(i in) bool { return i.Flip }),
		cmd("unless-flipped", func(i in) bool { return !i.Flip }),
	)
	require.NoError(t, err)

	var b bytes.Buffer

	require.Equal(t, 0, Run(tree, nil, Env{Stdout: &b}))
	require.Contains(t, b.String(), "Local commands (no server needed):\n\n  local            S local\n  when-flipped     S when-flipped\n\nServer commands (talk to a running headscale):\n\n  unless-flipped   S unless-flipped\n")
}
