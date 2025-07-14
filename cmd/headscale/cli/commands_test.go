package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCommandStructure tests that all expected commands exist and are properly configured
func TestCommandStructure(t *testing.T) {
	// Test version command
	assert.NotNil(t, versionCmd)
	assert.Equal(t, "version", versionCmd.Use)
	assert.Equal(t, "Print the version.", versionCmd.Short)
	assert.Equal(t, "The version of headscale.", versionCmd.Long)
	assert.NotNil(t, versionCmd.Run)

	// Test generate command
	assert.NotNil(t, generateCmd)
	assert.Equal(t, "generate", generateCmd.Use)
	assert.Equal(t, "Generate commands", generateCmd.Short)
	assert.Contains(t, generateCmd.Aliases, "gen")

	// Test generate private-key subcommand
	assert.NotNil(t, generatePrivateKeyCmd)
	assert.Equal(t, "private-key", generatePrivateKeyCmd.Use)
	assert.Equal(t, "Generate a private key for the headscale server", generatePrivateKeyCmd.Short)
	assert.NotNil(t, generatePrivateKeyCmd.Run)

	// Test that generate has private-key as subcommand
	found := false
	for _, subcmd := range generateCmd.Commands() {
		if subcmd.Name() == "private-key" {
			found = true
			break
		}
	}
	assert.True(t, found, "private-key should be a subcommand of generate")
}

// TestNodeCommandStructure tests the node command hierarchy
func TestNodeCommandStructure(t *testing.T) {
	assert.NotNil(t, nodeCmd)
	assert.Equal(t, "nodes", nodeCmd.Use)
	assert.Equal(t, "Manage the nodes of Headscale", nodeCmd.Short)
	assert.Contains(t, nodeCmd.Aliases, "node")
	assert.Contains(t, nodeCmd.Aliases, "machine")
	assert.Contains(t, nodeCmd.Aliases, "machines")

	// Test some key subcommands exist
	subcommands := make(map[string]bool)
	for _, subcmd := range nodeCmd.Commands() {
		subcommands[subcmd.Name()] = true
	}

	expectedSubcommands := []string{"list", "register", "delete", "expire", "rename", "move", "tag", "approve-routes", "list-routes", "backfillips"}
	for _, expected := range expectedSubcommands {
		assert.True(t, subcommands[expected], "Node command should have %s subcommand", expected)
	}
}

// TestUserCommandStructure tests the user command hierarchy  
func TestUserCommandStructure(t *testing.T) {
	assert.NotNil(t, userCmd)
	assert.Equal(t, "users", userCmd.Use)
	assert.Equal(t, "Manage the users of Headscale", userCmd.Short)
	assert.Contains(t, userCmd.Aliases, "user")
	assert.Contains(t, userCmd.Aliases, "namespace")
	assert.Contains(t, userCmd.Aliases, "namespaces")

	// Test some key subcommands exist
	subcommands := make(map[string]bool)
	for _, subcmd := range userCmd.Commands() {
		subcommands[subcmd.Name()] = true
	}

	expectedSubcommands := []string{"list", "create", "rename", "destroy"}
	for _, expected := range expectedSubcommands {
		assert.True(t, subcommands[expected], "User command should have %s subcommand", expected)
	}
}

// TestRootCommandStructure tests the root command setup
func TestRootCommandStructure(t *testing.T) {
	assert.NotNil(t, rootCmd)
	assert.Equal(t, "headscale", rootCmd.Use)
	assert.Equal(t, "headscale - a Tailscale control server", rootCmd.Short)
	assert.Contains(t, rootCmd.Long, "headscale is an open source implementation")

	// Check that persistent flags are set up
	outputFlag := rootCmd.PersistentFlags().Lookup("output")
	assert.NotNil(t, outputFlag)
	assert.Equal(t, "o", outputFlag.Shorthand)

	configFlag := rootCmd.PersistentFlags().Lookup("config")
	assert.NotNil(t, configFlag)
	assert.Equal(t, "c", configFlag.Shorthand)

	forceFlag := rootCmd.PersistentFlags().Lookup("force")
	assert.NotNil(t, forceFlag)
}

// TestCommandAliases tests that command aliases work correctly
func TestCommandAliases(t *testing.T) {
	tests := []struct {
		command string
		aliases []string
	}{
		{
			command: "nodes",
			aliases: []string{"node", "machine", "machines"},
		},
		{
			command: "users", 
			aliases: []string{"user", "namespace", "namespaces"},
		},
		{
			command: "generate",
			aliases: []string{"gen"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			// Find the command by name
			cmd, _, err := rootCmd.Find([]string{tt.command})
			require.NoError(t, err)
			
			// Check each alias
			for _, alias := range tt.aliases {
				aliasCmd, _, err := rootCmd.Find([]string{alias})
				require.NoError(t, err)
				assert.Equal(t, cmd, aliasCmd, "Alias %s should resolve to the same command as %s", alias, tt.command)
			}
		})
	}
}

// TestDeprecationMessages tests that deprecation constants are defined
func TestDeprecationMessages(t *testing.T) {
	assert.Equal(t, "use --user", deprecateNamespaceMessage)
}

// TestCommandFlagsExist tests that important flags exist on commands
func TestCommandFlagsExist(t *testing.T) {
	// Test that list commands have user flag
	listNodesCmd, _, err := rootCmd.Find([]string{"nodes", "list"})
	require.NoError(t, err)
	userFlag := listNodesCmd.Flags().Lookup("user")
	assert.NotNil(t, userFlag)
	assert.Equal(t, "u", userFlag.Shorthand)

	// Test that delete commands have identifier flag
	deleteNodeCmd, _, err := rootCmd.Find([]string{"nodes", "delete"})
	require.NoError(t, err)
	identifierFlag := deleteNodeCmd.Flags().Lookup("identifier")
	assert.NotNil(t, identifierFlag)
	assert.Equal(t, "i", identifierFlag.Shorthand)

	// Test that commands have force flag available (inherited from root)
	forceFlag := deleteNodeCmd.InheritedFlags().Lookup("force")
	assert.NotNil(t, forceFlag)
}

// TestCommandRunFunctions tests that commands have run functions defined
func TestCommandRunFunctions(t *testing.T) {
	commandsWithRun := []string{
		"version",
		"generate private-key",
	}

	for _, cmdPath := range commandsWithRun {
		t.Run(cmdPath, func(t *testing.T) {
			cmd, _, err := rootCmd.Find(strings.Split(cmdPath, " "))
			require.NoError(t, err)
			assert.NotNil(t, cmd.Run, "Command %s should have a Run function", cmdPath)
		})
	}
}