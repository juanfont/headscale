package command

import (
	"bytes"
	"syscall"
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

// fullWriter is a stdout that takes nothing, as /dev/full.
type fullWriter struct{}

func (fullWriter) Write([]byte) (int, error) { return 0, syscall.ENOSPC }

// TestHelpWriteFails: help that cannot be written fails the run, at the
// root, a group and a command.
func TestHelpWriteFails(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{{"--help"}, {"items", "--help"}, {"items", "list", "--help"}} {
		var stderr bytes.Buffer

		require.Equal(
			t,
			1,
			Run(testTree(t), args, Env{Stdout: fullWriter{}, Stderr: &stderr}),
			args,
		)
		require.Contains(t, stderr.String(), "no space left on device", args)
	}
}
