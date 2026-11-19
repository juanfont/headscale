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

  -o, --output string   Output format: json (the API object)
  -h, --help            Show this help
`},
	} {
		var stdout bytes.Buffer

		require.Equal(t, 0, Run(testTree(t), tt.args, Env{Stdout: &stdout}))

		if diff := cmp.Diff(tt.want, stdout.String()); diff != "" {
			t.Errorf("%v (-want +got):\n%s", tt.args, diff)
		}
	}
}
