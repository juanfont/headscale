package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServerFixHintsParse checks that the commands the server prints to fix a
// node parse on this CLI, without running them, and that a command without
// --identifier does not. Every parse happens in a child process, so the
// package's shared commands are never touched.
func TestServerFixHintsParse(t *testing.T) {
	before := flagState(rootCmd)

	parse := func(t *testing.T, hint string) (string, error) {
		t.Helper()

		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHintParseProcess$") //nolint:gosec // this test binary

		cmd.Env = append(os.Environ(), "HEADSCALE_TEST_HINT="+hint)

		out, err := cmd.CombinedOutput()

		return string(out), err
	}

	for _, hint := range []string{
		types.RenameNodeCommand(5),
		types.ExpireNodeCommand(5),
	} {
		t.Run(hint, func(t *testing.T) {
			require.NotEmpty(t, hint, "an empty hint would skip in the child")

			out, err := parse(t, hint)
			require.NoError(t, err, "%s", out)
		})
	}

	t.Run("missing identifier", func(t *testing.T) {
		out, err := parse(t, "headscale nodes rename <name>")
		require.Error(t, err)
		assert.Contains(t, out, `required flag(s) "identifier" not set`)
	})

	assert.Equal(t, before, flagState(rootCmd), "the hints changed a flag of the shared commands")
}

// TestHintParseProcess is the child of TestServerFixHintsParse.
func TestHintParseProcess(t *testing.T) {
	hint := os.Getenv("HEADSCALE_TEST_HINT")
	if hint == "" {
		t.Skip("run by TestServerFixHintsParse")
	}

	args := strings.Fields(strings.ReplaceAll(hint, "<name>", "new-name"))
	require.Equal(t, "headscale", args[0])

	cmd, rest, err := rootCmd.Find(args[1:])
	require.NoError(t, err)
	require.NotEqual(t, rootCmd, cmd, "hint names no subcommand")
	require.NoError(t, cmd.ParseFlags(rest))
	require.NoError(t, cmd.ValidateRequiredFlags())
	require.NoError(t, cmd.ValidateArgs(cmd.Flags().Args()))
}

// flagState renders every flag of the command tree, local and persistent,
// with its value and whether it was set.
func flagState(root *cobra.Command) string {
	var b strings.Builder

	var walk func(*cobra.Command)

	walk = func(c *cobra.Command) {
		for i, set := range []*pflag.FlagSet{c.Flags(), c.PersistentFlags()} {
			set.VisitAll(func(f *pflag.Flag) {
				fmt.Fprintf(&b, "%s %d --%s=%s changed=%v\n", c.CommandPath(), i, f.Name, f.Value, f.Changed)
			})
		}

		for _, sub := range c.Commands() {
			walk(sub)
		}
	}

	walk(root)

	return b.String()
}
