package cli

import (
	"fmt"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeCommand(t *testing.T) {
	// Test the main node command
	assert.NotNil(t, nodeCmd)
	assert.Equal(t, "nodes", nodeCmd.Use)
	assert.Equal(t, "Manage the nodes of Headscale", nodeCmd.Short)
	
	// Test aliases
	expectedAliases := []string{"node", "machine", "machines", "m"}
	assert.Equal(t, expectedAliases, nodeCmd.Aliases)
	
	// Test that node command has subcommands
	subcommands := nodeCmd.Commands()
	assert.Greater(t, len(subcommands), 0, "Node command should have subcommands")
	
	// Verify expected subcommands exist
	subcommandNames := make([]string, len(subcommands))
	for i, cmd := range subcommands {
		subcommandNames[i] = cmd.Use
	}
	
	expectedSubcommands := []string{"list", "register", "delete", "expire", "rename", "move", "routes", "tags", "backfill-ips"}
	for _, expected := range expectedSubcommands {
		found := false
		for _, actual := range subcommandNames {
			if actual == expected || 
			   (expected == "routes" && actual == "list-routes") ||
			   (expected == "tags" && actual == "tag") ||
			   (expected == "backfill-ips" && actual == "backfill-node-ips") {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected subcommand related to '%s' not found", expected)
	}
}

func TestRegisterNodeCommand(t *testing.T) {
	assert.NotNil(t, registerNodeCmd)
	assert.Equal(t, "register", registerNodeCmd.Use)
	assert.Equal(t, "Register a node to your headscale instance", registerNodeCmd.Short)
	assert.Equal(t, []string{"r"}, registerNodeCmd.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, registerNodeCmd.Run)
	
	// Test required flags
	flags := registerNodeCmd.Flags()
	assert.NotNil(t, flags.Lookup("user"))
	assert.NotNil(t, flags.Lookup("key"))
	
	// Test flag shortcuts
	userFlag := flags.Lookup("user")
	assert.Equal(t, "u", userFlag.Shorthand)
	
	keyFlag := flags.Lookup("key")
	assert.Equal(t, "k", keyFlag.Shorthand)
	
	// Test deprecated namespace flag
	namespaceFlag := flags.Lookup("namespace")
	assert.NotNil(t, namespaceFlag)
	assert.True(t, namespaceFlag.Hidden)
	assert.Equal(t, deprecateNamespaceMessage, namespaceFlag.Deprecated)
}

func TestListNodesCommand(t *testing.T) {
	assert.NotNil(t, listNodesCmd)
	assert.Equal(t, "list", listNodesCmd.Use)
	assert.Equal(t, "List nodes", listNodesCmd.Short)
	assert.Equal(t, []string{"ls", "show"}, listNodesCmd.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, listNodesCmd.Run)
	
	// Test flags
	flags := listNodesCmd.Flags()
	assert.NotNil(t, flags.Lookup("user"))
	assert.NotNil(t, flags.Lookup("tags"))
	
	// Test flag shortcuts
	userFlag := flags.Lookup("user")
	assert.Equal(t, "u", userFlag.Shorthand)
	
	tagsFlag := flags.Lookup("tags")
	assert.Equal(t, "t", tagsFlag.Shorthand)
	
	// Test deprecated namespace flag
	namespaceFlag := flags.Lookup("namespace")
	assert.NotNil(t, namespaceFlag)
	assert.True(t, namespaceFlag.Hidden)
	assert.Equal(t, deprecateNamespaceMessage, namespaceFlag.Deprecated)
}

func TestListNodeRoutesCommand(t *testing.T) {
	assert.NotNil(t, listNodeRoutesCmd)
	assert.Equal(t, "list-routes", listNodeRoutesCmd.Use)
	assert.Equal(t, "List node routes", listNodeRoutesCmd.Short)
	assert.Equal(t, []string{"routes"}, listNodeRoutesCmd.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, listNodeRoutesCmd.Run)
	
	// Test flags
	flags := listNodeRoutesCmd.Flags()
	assert.NotNil(t, flags.Lookup("identifier"))
	
	// Test flag shortcuts
	identifierFlag := flags.Lookup("identifier")
	assert.Equal(t, "i", identifierFlag.Shorthand)
}

func TestExpireNodeCommand(t *testing.T) {
	assert.NotNil(t, expireNodeCmd)
	assert.Equal(t, "expire", expireNodeCmd.Use)
	assert.Equal(t, "Expire (log out) a node", expireNodeCmd.Short)
	assert.Equal(t, []string{"logout", "exp", "e"}, expireNodeCmd.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, expireNodeCmd.Run)
	
	// Test that Args validation function is set
	assert.NotNil(t, expireNodeCmd.Args)
}

func TestRenameNodeCommand(t *testing.T) {
	assert.NotNil(t, renameNodeCmd)
	assert.Equal(t, "rename", renameNodeCmd.Use)
	assert.Equal(t, "Rename a node", renameNodeCmd.Short)
	assert.Equal(t, []string{"mv"}, renameNodeCmd.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, renameNodeCmd.Run)
	
	// Test that Args validation function is set
	assert.NotNil(t, renameNodeCmd.Args)
}

func TestDeleteNodeCommand(t *testing.T) {
	assert.NotNil(t, deleteNodeCmd)
	assert.Equal(t, "delete", deleteNodeCmd.Use)
	assert.Equal(t, "Delete a node", deleteNodeCmd.Short)
	assert.Equal(t, []string{"remove", "rm"}, deleteNodeCmd.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, deleteNodeCmd.Run)
	
	// Test that Args validation function is set
	assert.NotNil(t, deleteNodeCmd.Args)
}

func TestMoveNodeCommand(t *testing.T) {
	assert.NotNil(t, moveNodeCmd)
	assert.Equal(t, "move", moveNodeCmd.Use)
	assert.Equal(t, "Move node to another user", moveNodeCmd.Short)
	
	// Test that Run function is set
	assert.NotNil(t, moveNodeCmd.Run)
	
	// Test that Args validation function is set
	assert.NotNil(t, moveNodeCmd.Args)
}

func TestBackfillNodeIPsCommand(t *testing.T) {
	assert.NotNil(t, backfillNodeIPsCmd)
	assert.Equal(t, "backfill-node-ips", backfillNodeIPsCmd.Use)
	assert.Equal(t, "Backfill the IPs of all the nodes in case you have to restore the database from a backup", backfillNodeIPsCmd.Short)
	
	// Test that Run function is set
	assert.NotNil(t, backfillNodeIPsCmd.Run)
	
	// Test flags
	flags := backfillNodeIPsCmd.Flags()
	assert.NotNil(t, flags.Lookup("confirm"))
}

func TestTagCommand(t *testing.T) {
	assert.NotNil(t, tagCmd)
	assert.Equal(t, "tag", tagCmd.Use)
	assert.Equal(t, "Manage the tags of Headscale", tagCmd.Short)
	
	// Test that tag command has subcommands
	subcommands := tagCmd.Commands()
	assert.Greater(t, len(subcommands), 0, "Tag command should have subcommands")
}

func TestApproveRoutesCommand(t *testing.T) {
	assert.NotNil(t, approveRoutesCmd)
	assert.Equal(t, "approve-routes", approveRoutesCmd.Use)
	assert.Equal(t, "Approve subnets advertised by a node", approveRoutesCmd.Short)
	
	// Test that Run function is set
	assert.NotNil(t, approveRoutesCmd.Run)
	
	// Test that Args validation function is set
	assert.NotNil(t, approveRoutesCmd.Args)
}


func TestNodeCommandFlags(t *testing.T) {
	// Test register node command flags
	ValidateCommandFlags(t, registerNodeCmd, []string{"user", "key", "namespace"})
	
	// Test list nodes command flags
	ValidateCommandFlags(t, listNodesCmd, []string{"user", "tags", "namespace"})
	
	// Test list node routes command flags
	ValidateCommandFlags(t, listNodeRoutesCmd, []string{"identifier"})
	
	// Test backfill command flags
	ValidateCommandFlags(t, backfillNodeIPsCmd, []string{"confirm"})
}

func TestNodeCommandIntegration(t *testing.T) {
	// Test that node command is properly integrated into root command
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use == "nodes" {
			found = true
			break
		}
	}
	assert.True(t, found, "Node command should be added to root command")
}

func TestNodeSubcommandIntegration(t *testing.T) {
	// Test that key subcommands are properly added to node command
	subcommands := nodeCmd.Commands()
	
	expectedCommands := map[string]bool{
		"list":               false,
		"register":           false,
		"list-routes":        false,
		"expire":             false,
		"rename":             false,
		"delete":             false,
		"move":               false,
		"backfill-node-ips":  false,
		"tag":                false,
		"approve-routes":     false,
	}
	
	for _, subcmd := range subcommands {
		if _, exists := expectedCommands[subcmd.Use]; exists {
			expectedCommands[subcmd.Use] = true
		}
	}
	
	for cmdName, found := range expectedCommands {
		assert.True(t, found, "Subcommand '%s' should be added to node command", cmdName)
	}
}

func TestNodeCommandAliases(t *testing.T) {
	// Test that all aliases are properly set
	testCases := []struct {
		command         *cobra.Command
		expectedAliases []string
	}{
		{
			command:         nodeCmd,
			expectedAliases: []string{"node", "machine", "machines", "m"},
		},
		{
			command:         registerNodeCmd,
			expectedAliases: []string{"r"},
		},
		{
			command:         listNodesCmd,
			expectedAliases: []string{"ls", "show"},
		},
		{
			command:         listNodeRoutesCmd,
			expectedAliases: []string{"routes"},
		},
		{
			command:         expireNodeCmd,
			expectedAliases: []string{"logout", "exp", "e"},
		},
		{
			command:         renameNodeCmd,
			expectedAliases: []string{"mv"},
		},
		{
			command:         deleteNodeCmd,
			expectedAliases: []string{"remove", "rm"},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.command.Use, func(t *testing.T) {
			assert.Equal(t, tc.expectedAliases, tc.command.Aliases)
		})
	}
}

func TestNodeCommandDeprecatedFlags(t *testing.T) {
	// Test deprecated namespace flags
	commands := []*cobra.Command{registerNodeCmd, listNodesCmd}
	
	for _, cmd := range commands {
		t.Run(cmd.Use+"_namespace_deprecated", func(t *testing.T) {
			namespaceFlag := cmd.Flags().Lookup("namespace")
			require.NotNil(t, namespaceFlag, "Command %s should have deprecated namespace flag", cmd.Use)
			assert.True(t, namespaceFlag.Hidden, "Namespace flag should be hidden")
			assert.Equal(t, deprecateNamespaceMessage, namespaceFlag.Deprecated)
		})
	}
}

func TestNodeCommandRequiredFlags(t *testing.T) {
	// Test that register command has required flags
	flags := registerNodeCmd.Flags()
	
	userFlag := flags.Lookup("user")
	require.NotNil(t, userFlag)
	
	keyFlag := flags.Lookup("key")
	require.NotNil(t, keyFlag)
	
	// Check if flags have required annotation (set by MarkFlagRequired)
	checkRequired := func(flag *pflag.Flag, flagName string) {
		if flag.Annotations != nil {
			_, hasRequired := flag.Annotations[cobra.BashCompOneRequiredFlag]
			assert.True(t, hasRequired, "%s flag should be marked as required", flagName)
		}
	}
	
	checkRequired(userFlag, "user")
	checkRequired(keyFlag, "key")
}

func TestNodeCommandsHaveRunFunctions(t *testing.T) {
	// All node commands should have run functions
	commands := []*cobra.Command{
		registerNodeCmd,
		listNodesCmd,
		listNodeRoutesCmd,
		expireNodeCmd,
		renameNodeCmd,
		deleteNodeCmd,
		moveNodeCmd,
		backfillNodeIPsCmd,
		approveRoutesCmd,
	}
	
	for _, cmd := range commands {
		t.Run(cmd.Use, func(t *testing.T) {
			assert.NotNil(t, cmd.Run, "Command %s should have a Run function", cmd.Use)
		})
	}
}

func TestNodeCommandArgsValidation(t *testing.T) {
	// Commands that require arguments should have Args validation
	commandsWithArgs := []*cobra.Command{
		expireNodeCmd,
		renameNodeCmd,
		deleteNodeCmd,
		moveNodeCmd,
		approveRoutesCmd,
	}
	
	for _, cmd := range commandsWithArgs {
		t.Run(cmd.Use+"_has_args_validation", func(t *testing.T) {
			assert.NotNil(t, cmd.Args, "Command %s should have Args validation function", cmd.Use)
		})
	}
}

func TestNodeCommandCompleteness(t *testing.T) {
	// Test that node command covers expected node operations
	subcommands := nodeCmd.Commands()
	
	operations := map[string]bool{
		"create":     false, // register command
		"read":       false, // list command
		"update":     false, // rename, move, expire commands
		"delete":     false, // delete command
		"routes":     false, // route-related commands
		"tags":       false, // tag-related commands
		"backfill":   false, // maintenance commands
	}
	
	for _, subcmd := range subcommands {
		switch {
		case subcmd.Use == "register":
			operations["create"] = true
		case subcmd.Use == "list":
			operations["read"] = true
		case subcmd.Use == "rename" || subcmd.Use == "move" || subcmd.Use == "expire":
			operations["update"] = true
		case subcmd.Use == "delete":
			operations["delete"] = true
		case subcmd.Use == "list-routes" || subcmd.Use == "approve-routes":
			operations["routes"] = true
		case subcmd.Use == "tag":
			operations["tags"] = true
		case subcmd.Use == "backfill-node-ips":
			operations["backfill"] = true
		}
	}
	
	for op, found := range operations {
		assert.True(t, found, "Node command should support %s operation", op)
	}
}

func TestNodeCommandConsistency(t *testing.T) {
	// Test that node commands follow consistent patterns
	
	// Commands that modify nodes should have meaningful aliases
	modifyCommands := map[*cobra.Command]string{
		expireNodeCmd: "logout", // should have logout alias
		renameNodeCmd: "mv",     // should have mv alias
		deleteNodeCmd: "rm",     // should have rm alias
	}
	
	for cmd, expectedAlias := range modifyCommands {
		t.Run(cmd.Use+"_has_"+expectedAlias+"_alias", func(t *testing.T) {
			found := false
			for _, alias := range cmd.Aliases {
				if alias == expectedAlias {
					found = true
					break
				}
			}
			assert.True(t, found, "Command %s should have %s alias", cmd.Use, expectedAlias)
		})
	}
}

func TestNodeCommandDocumentation(t *testing.T) {
	// Test that important commands have proper documentation
	commands := []*cobra.Command{
		nodeCmd,
		registerNodeCmd,
		listNodesCmd,
		deleteNodeCmd,
		backfillNodeIPsCmd,
	}
	
	for _, cmd := range commands {
		t.Run(cmd.Use+"_has_documentation", func(t *testing.T) {
			assert.NotEmpty(t, cmd.Short, "Command %s should have Short description", cmd.Use)
			
			// Long description is optional but recommended for complex commands
			if cmd.Use == "backfill-node-ips" {
				assert.NotEmpty(t, cmd.Long, "Complex command %s should have Long description", cmd.Use)
			}
		})
	}
}

func TestNodeFlagShortcuts(t *testing.T) {
	// Test that flag shortcuts are consistently assigned
	flagTests := []struct {
		command  *cobra.Command
		flagName string
		shortcut string
	}{
		{registerNodeCmd, "user", "u"},
		{registerNodeCmd, "key", "k"},
		{listNodesCmd, "user", "u"},
		{listNodesCmd, "tags", "t"},
		{listNodeRoutesCmd, "identifier", "i"},
	}
	
	for _, test := range flagTests {
		t.Run(fmt.Sprintf("%s_%s_shortcut", test.command.Use, test.flagName), func(t *testing.T) {
			flag := test.command.Flags().Lookup(test.flagName)
			require.NotNil(t, flag, "Flag %s should exist on command %s", test.flagName, test.command.Use)
			assert.Equal(t, test.shortcut, flag.Shorthand, "Flag %s should have shortcut %s", test.flagName, test.shortcut)
		})
	}
}