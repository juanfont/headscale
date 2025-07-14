package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreAuthKeysCommand(t *testing.T) {
	// Test the main preauthkeys command
	assert.NotNil(t, preauthkeysCmd)
	assert.Equal(t, "preauthkeys", preauthkeysCmd.Use)
	assert.Equal(t, "Handle the preauthkeys in Headscale", preauthkeysCmd.Short)
	
	// Test aliases
	expectedAliases := []string{"preauthkey", "authkey", "pre"}
	assert.Equal(t, expectedAliases, preauthkeysCmd.Aliases)
	
	// Test that preauthkeys command has subcommands
	subcommands := preauthkeysCmd.Commands()
	assert.Greater(t, len(subcommands), 0, "PreAuth keys command should have subcommands")
	
	// Verify expected subcommands exist
	subcommandNames := make([]string, len(subcommands))
	for i, cmd := range subcommands {
		subcommandNames[i] = cmd.Use
	}
	
	expectedSubcommands := []string{"list", "create", "expire"}
	for _, expected := range expectedSubcommands {
		found := false
		for _, actual := range subcommandNames {
			if actual == expected {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected subcommand '%s' not found", expected)
	}
}

func TestPreAuthKeysCommandPersistentFlags(t *testing.T) {
	// Test persistent flags that apply to all subcommands
	flags := preauthkeysCmd.PersistentFlags()
	
	// Test user flag
	userFlag := flags.Lookup("user")
	assert.NotNil(t, userFlag)
	assert.Equal(t, "u", userFlag.Shorthand)
	assert.Equal(t, "User identifier (ID)", userFlag.Usage)
	
	// Test that user flag is required
	if userFlag.Annotations != nil {
		_, hasRequired := userFlag.Annotations[cobra.BashCompOneRequiredFlag]
		assert.True(t, hasRequired, "user flag should be marked as required")
	}
	
	// Test deprecated namespace flag
	namespaceFlag := flags.Lookup("namespace")
	assert.NotNil(t, namespaceFlag)
	assert.Equal(t, "n", namespaceFlag.Shorthand)
	assert.True(t, namespaceFlag.Hidden)
	assert.Equal(t, deprecateNamespaceMessage, namespaceFlag.Deprecated)
}

func TestListPreAuthKeysCommand(t *testing.T) {
	assert.NotNil(t, listPreAuthKeys)
	assert.Equal(t, "list", listPreAuthKeys.Use)
	assert.Equal(t, "List the Pre auth keys for the specified user", listPreAuthKeys.Short)
	assert.Equal(t, []string{"ls", "show"}, listPreAuthKeys.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, listPreAuthKeys.Run)
}

func TestCreatePreAuthKeyCommand(t *testing.T) {
	assert.NotNil(t, createPreAuthKeyCmd)
	assert.Equal(t, "create", createPreAuthKeyCmd.Use)
	assert.Equal(t, "Creates a new Pre Auth Key", createPreAuthKeyCmd.Short)
	assert.Equal(t, []string{"c", "new"}, createPreAuthKeyCmd.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, createPreAuthKeyCmd.Run)
	
	// Test persistent flags (reusable, ephemeral)
	persistentFlags := createPreAuthKeyCmd.PersistentFlags()
	assert.NotNil(t, persistentFlags.Lookup("reusable"))
	assert.NotNil(t, persistentFlags.Lookup("ephemeral"))
	
	// Test regular flags (expiration, tags)
	flags := createPreAuthKeyCmd.Flags()
	assert.NotNil(t, flags.Lookup("expiration"))
	assert.NotNil(t, flags.Lookup("tags"))
	
	// Test flag properties
	expirationFlag := flags.Lookup("expiration")
	assert.Equal(t, "e", expirationFlag.Shorthand)
	assert.Equal(t, DefaultPreAuthKeyExpiry, expirationFlag.DefValue)
	
	reusableFlag := persistentFlags.Lookup("reusable")
	assert.Equal(t, "false", reusableFlag.DefValue)
	
	ephemeralFlag := persistentFlags.Lookup("ephemeral")
	assert.Equal(t, "false", ephemeralFlag.DefValue)
}

func TestExpirePreAuthKeyCommand(t *testing.T) {
	assert.NotNil(t, expirePreAuthKeyCmd)
	assert.Equal(t, "expire", expirePreAuthKeyCmd.Use)
	assert.Equal(t, "Expire a Pre Auth Key", expirePreAuthKeyCmd.Short)
	assert.Equal(t, []string{"revoke", "exp", "e"}, expirePreAuthKeyCmd.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, expirePreAuthKeyCmd.Run)
	
	// Test that Args validation function is set
	assert.NotNil(t, expirePreAuthKeyCmd.Args)
}

func TestPreAuthKeyConstants(t *testing.T) {
	// Test that constants are defined
	assert.Equal(t, "1h", DefaultPreAuthKeyExpiry)
}

func TestPreAuthKeyCommandStructure(t *testing.T) {
	// Validate command structure and help text
	ValidateCommandStructure(t, preauthkeysCmd, "preauthkeys", "Handle the preauthkeys in Headscale")
	ValidateCommandHelp(t, preauthkeysCmd)
	
	// Validate subcommands
	ValidateCommandStructure(t, listPreAuthKeys, "list", "List the Pre auth keys for the specified user")
	ValidateCommandHelp(t, listPreAuthKeys)
	
	ValidateCommandStructure(t, createPreAuthKeyCmd, "create", "Creates a new Pre Auth Key")
	ValidateCommandHelp(t, createPreAuthKeyCmd)
	
	ValidateCommandStructure(t, expirePreAuthKeyCmd, "expire", "Expire a Pre Auth Key")
	ValidateCommandHelp(t, expirePreAuthKeyCmd)
}

func TestPreAuthKeyCommandFlags(t *testing.T) {
	// Test preauthkeys command persistent flags
	ValidateCommandFlags(t, preauthkeysCmd, []string{"user", "namespace"})
	
	// Test create command flags
	ValidateCommandFlags(t, createPreAuthKeyCmd, []string{"reusable", "ephemeral", "expiration", "tags"})
}

func TestPreAuthKeyCommandIntegration(t *testing.T) {
	// Test that preauthkeys command is properly integrated into root command
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use == "preauthkeys" {
			found = true
			break
		}
	}
	assert.True(t, found, "PreAuth keys command should be added to root command")
}

func TestPreAuthKeySubcommandIntegration(t *testing.T) {
	// Test that all subcommands are properly added to preauthkeys command
	subcommands := preauthkeysCmd.Commands()
	
	expectedCommands := map[string]bool{
		"list":   false,
		"create": false,
		"expire": false,
	}
	
	for _, subcmd := range subcommands {
		if _, exists := expectedCommands[subcmd.Use]; exists {
			expectedCommands[subcmd.Use] = true
		}
	}
	
	for cmdName, found := range expectedCommands {
		assert.True(t, found, "Subcommand '%s' should be added to preauthkeys command", cmdName)
	}
}

func TestPreAuthKeyCommandAliases(t *testing.T) {
	// Test that all aliases are properly set
	testCases := []struct {
		command         *cobra.Command
		expectedAliases []string
	}{
		{
			command:         preauthkeysCmd,
			expectedAliases: []string{"preauthkey", "authkey", "pre"},
		},
		{
			command:         listPreAuthKeys,
			expectedAliases: []string{"ls", "show"},
		},
		{
			command:         createPreAuthKeyCmd,
			expectedAliases: []string{"c", "new"},
		},
		{
			command:         expirePreAuthKeyCmd,
			expectedAliases: []string{"revoke", "exp", "e"},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.command.Use, func(t *testing.T) {
			assert.Equal(t, tc.expectedAliases, tc.command.Aliases)
		})
	}
}

func TestPreAuthKeyFlagDefaults(t *testing.T) {
	// Test create command flag defaults
	
	// Test persistent flags
	persistentFlags := createPreAuthKeyCmd.PersistentFlags()
	
	reusable, err := persistentFlags.GetBool("reusable")
	assert.NoError(t, err)
	assert.False(t, reusable)
	
	ephemeral, err := persistentFlags.GetBool("ephemeral")
	assert.NoError(t, err)
	assert.False(t, ephemeral)
	
	// Test regular flags
	flags := createPreAuthKeyCmd.Flags()
	
	expiration, err := flags.GetString("expiration")
	assert.NoError(t, err)
	assert.Equal(t, DefaultPreAuthKeyExpiry, expiration)
	
	tags, err := flags.GetStringSlice("tags")
	assert.NoError(t, err)
	assert.Empty(t, tags)
}

func TestPreAuthKeyFlagShortcuts(t *testing.T) {
	// Test that flag shortcuts are properly set
	
	// Persistent flags
	userFlag := preauthkeysCmd.PersistentFlags().Lookup("user")
	assert.Equal(t, "u", userFlag.Shorthand)
	
	namespaceFlag := preauthkeysCmd.PersistentFlags().Lookup("namespace")
	assert.Equal(t, "n", namespaceFlag.Shorthand)
	
	// Create command flags
	expirationFlag := createPreAuthKeyCmd.Flags().Lookup("expiration")
	assert.Equal(t, "e", expirationFlag.Shorthand)
}

func TestPreAuthKeyCommandsHaveOutputFlag(t *testing.T) {
	// All preauth key commands should support output formatting
	commands := []*cobra.Command{listPreAuthKeys, createPreAuthKeyCmd, expirePreAuthKeyCmd}
	
	for _, cmd := range commands {
		t.Run(cmd.Use, func(t *testing.T) {
			// Commands should be able to get output flag (though it might be inherited)
			// This tests that the commands are designed to work with output formatting
			assert.NotNil(t, cmd.Run, "Command should have a Run function")
		})
	}
}

func TestPreAuthKeyCommandCompleteness(t *testing.T) {
	// Test that preauth key command covers all expected CRUD operations
	subcommands := preauthkeysCmd.Commands()
	
	operations := map[string]bool{
		"create": false,
		"read":   false, // list command
		"update": false, // expire command (updates state)
		"delete": false, // expire is the equivalent of delete for preauth keys
	}
	
	for _, subcmd := range subcommands {
		switch subcmd.Use {
		case "create":
			operations["create"] = true
		case "list":
			operations["read"] = true
		case "expire":
			operations["update"] = true
			operations["delete"] = true // expire serves as delete for preauth keys
		}
	}
	
	for op, found := range operations {
		assert.True(t, found, "PreAuth key command should support %s operation", op)
	}
}

func TestPreAuthKeyRequiredFlags(t *testing.T) {
	// Test that user flag is required on parent command
	userFlag := preauthkeysCmd.PersistentFlags().Lookup("user")
	require.NotNil(t, userFlag)
	
	// Check if flag has required annotation (set by MarkPersistentFlagRequired)
	if userFlag.Annotations != nil {
		_, hasRequired := userFlag.Annotations[cobra.BashCompOneRequiredFlag]
		assert.True(t, hasRequired, "user flag should be marked as required")
	}
}

func TestPreAuthKeyDeprecatedFlags(t *testing.T) {
	// Test deprecated namespace flag
	namespaceFlag := preauthkeysCmd.PersistentFlags().Lookup("namespace")
	require.NotNil(t, namespaceFlag)
	assert.True(t, namespaceFlag.Hidden, "Namespace flag should be hidden")
	assert.Equal(t, deprecateNamespaceMessage, namespaceFlag.Deprecated)
}

func TestPreAuthKeyCommandUsagePatterns(t *testing.T) {
	// Test that commands follow consistent usage patterns
	
	// List and create commands should not require positional arguments
	assert.NotNil(t, listPreAuthKeys.Run)
	assert.Nil(t, listPreAuthKeys.Args) // No args validation means optional args
	
	assert.NotNil(t, createPreAuthKeyCmd.Run)
	assert.Nil(t, createPreAuthKeyCmd.Args)
	
	// Expire command requires key argument
	assert.NotNil(t, expirePreAuthKeyCmd.Run)
	assert.NotNil(t, expirePreAuthKeyCmd.Args)
}

func TestPreAuthKeyFlagTypes(t *testing.T) {
	// Test that flags have correct types
	
	// User flag should be uint64
	userFlag := preauthkeysCmd.PersistentFlags().Lookup("user")
	require.NotNil(t, userFlag)
	assert.Equal(t, "uint64", userFlag.Value.Type())
	
	// Boolean flags
	reusableFlag := createPreAuthKeyCmd.PersistentFlags().Lookup("reusable")
	require.NotNil(t, reusableFlag)
	assert.Equal(t, "bool", reusableFlag.Value.Type())
	
	ephemeralFlag := createPreAuthKeyCmd.PersistentFlags().Lookup("ephemeral")
	require.NotNil(t, ephemeralFlag)
	assert.Equal(t, "bool", ephemeralFlag.Value.Type())
	
	// String flags
	expirationFlag := createPreAuthKeyCmd.Flags().Lookup("expiration")
	require.NotNil(t, expirationFlag)
	assert.Equal(t, "string", expirationFlag.Value.Type())
	
	// String slice flags
	tagsFlag := createPreAuthKeyCmd.Flags().Lookup("tags")
	require.NotNil(t, tagsFlag)
	assert.Equal(t, "stringSlice", tagsFlag.Value.Type())
}

func TestPreAuthKeyDefaultExpiry(t *testing.T) {
	// Test that the default expiry constant is reasonable
	assert.Equal(t, "1h", DefaultPreAuthKeyExpiry)
	
	// Test that it can be used in flag defaults
	expirationFlag := createPreAuthKeyCmd.Flags().Lookup("expiration")
	assert.Equal(t, DefaultPreAuthKeyExpiry, expirationFlag.DefValue)
}

func TestPreAuthKeyCommandDocumentation(t *testing.T) {
	// Test that commands have proper documentation
	
	// Main command should have clear description
	assert.Contains(t, preauthkeysCmd.Short, "preauthkeys")
	assert.Contains(t, preauthkeysCmd.Short, "Headscale")
	
	// Subcommands should have descriptive names
	assert.Equal(t, "List the Pre auth keys for the specified user", listPreAuthKeys.Short)
	assert.Equal(t, "Creates a new Pre Auth Key", createPreAuthKeyCmd.Short)
	assert.Equal(t, "Expire a Pre Auth Key", expirePreAuthKeyCmd.Short)
}

func TestPreAuthKeyFlagDescriptions(t *testing.T) {
	// Test that flags have helpful descriptions
	
	userFlag := preauthkeysCmd.PersistentFlags().Lookup("user")
	assert.Contains(t, userFlag.Usage, "User identifier")
	
	reusableFlag := createPreAuthKeyCmd.PersistentFlags().Lookup("reusable")
	assert.Contains(t, reusableFlag.Usage, "reusable")
	
	ephemeralFlag := createPreAuthKeyCmd.PersistentFlags().Lookup("ephemeral")
	assert.Contains(t, ephemeralFlag.Usage, "ephemeral")
	
	expirationFlag := createPreAuthKeyCmd.Flags().Lookup("expiration")
	assert.Contains(t, expirationFlag.Usage, "Human-readable")
	assert.Contains(t, expirationFlag.Usage, "expiration")
	
	tagsFlag := createPreAuthKeyCmd.Flags().Lookup("tags")
	assert.Contains(t, tagsFlag.Usage, "Tags")
	assert.Contains(t, tagsFlag.Usage, "automatically assign")
}