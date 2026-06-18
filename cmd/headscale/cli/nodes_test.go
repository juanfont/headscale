package cli

import "testing"

const (
	nodesName         = "nodes"
	listRoutesName    = "list-routes"
	approveRoutesName = "approve-routes"
)

func TestListRoutesReachableUnderBothParents(t *testing.T) {
	tests := []struct {
		name string
		path []string
	}{
		{"under nodes", []string{nodesName, listRoutesName}},
		{"under nodes approve-routes", []string{nodesName, approveRoutesName, listRoutesName}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, _, err := rootCmd.Find(tt.path)
			if err != nil {
				t.Fatalf("rootCmd.Find(%v): %v", tt.path, err)
			}

			if cmd.Name() != listRoutesName {
				t.Fatalf("expected %s, got %q", listRoutesName, cmd.Name())
			}
		})
	}
}

func TestApproveRoutesIdentifierIsLocalNotPersistent(t *testing.T) {
	// PersistentFlags + mustMarkRequired propagates the required-validation
	// to subcommands, which breaks `nodes approve-routes list-routes` with
	// no -i (the documented "list all" path).
	if approveRoutesCmd.PersistentFlags().Lookup("identifier") != nil {
		t.Fatal("approveRoutesCmd: identifier must be a local Flag, not Persistent")
	}

	if approveRoutesCmd.Flags().Lookup("identifier") == nil {
		t.Fatal("approveRoutesCmd: identifier flag missing")
	}
}

func TestApproveRoutesRejectsExtraPositionalArgs(t *testing.T) {
	// Before NoArgs, `nodes approve-routes <typo> -i 12 -r ""` silently
	// invoked the destructive empty-routes path on node 12.
	if approveRoutesCmd.Args == nil {
		t.Fatal("approveRoutesCmd.Args must be set to NoArgs")
	}

	err := approveRoutesCmd.Args(approveRoutesCmd, []string{"unexpected"})
	if err == nil {
		t.Fatal("expected approveRoutesCmd to reject extra positional args")
	}
}
