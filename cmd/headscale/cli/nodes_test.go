package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// flagOnlyNodeCommands are the `nodes` subcommands that configure everything
// through flags and therefore must reject any positional arguments. Route
// lists, for example, are passed via the --routes flag, so
// `headscale nodes approve-routes -i 2 0.0.0.0/0` is a user error and must
// fail loudly instead of silently ignoring the stray argument and printing
// "Node updated".
//
// rename is deliberately excluded: it takes the new name as a positional
// argument (`nodes rename NEW_NAME`).
func flagOnlyNodeCommands() []*cobra.Command {
	return []*cobra.Command{
		registerNodeCmd,
		listNodesCmd,
		listNodeRoutesCmd,
		expireNodeCmd,
		deleteNodeCmd,
		backfillNodeIPsCmd,
		tagCmd,
		approveRoutesCmd,
	}
}

func TestFlagOnlyNodeCommandsRejectPositionalArgs(t *testing.T) {
	for _, cmd := range flagOnlyNodeCommands() {
		cmd := cmd
		t.Run(cmd.Name(), func(t *testing.T) {
			err := cmd.Args(cmd, []string{"0.0.0.0/0,::/0"})
			if err == nil {
				t.Fatalf("expected error for positional argument on %q, got nil", cmd.Name())
			}
		})
	}
}

// TestApproveRoutesRejectsPositionalArgs reproduces the issue scenario
// directly: `headscale nodes approve-routes -i 2 "0.0.0.0/0,::/0"`.
// The stray positional argument must be rejected by cobra before RunE runs
// (and thus before any API call is attempted).
func TestApproveRoutesRejectsPositionalArgs(t *testing.T) {
	err := approveRoutesCmd.Args(approveRoutesCmd, []string{"0.0.0.0/0,::/0"})
	if err == nil {
		t.Fatal("expected approve-routes to reject positional argument, got nil")
	}

	// cobra.NoArgs produces a message naming the offending argument.
	if !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestRenameNodeAcceptsPositionalArg guards against over-applying the fix:
// `nodes rename NEW_NAME` legitimately takes a positional argument.
func TestRenameNodeAcceptsPositionalArg(t *testing.T) {
	if renameNodeCmd.Args != nil {
		if err := renameNodeCmd.Args(renameNodeCmd, []string{"new-name"}); err != nil {
			t.Fatalf("rename should accept a positional argument, got: %v", err)
		}
	}
}
