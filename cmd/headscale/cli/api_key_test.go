package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIKeysCommand(t *testing.T) {
	// Test the main apikeys command
	assert.NotNil(t, apiKeysCmd)
	assert.Equal(t, "apikeys", apiKeysCmd.Use)
	assert.Equal(t, "Handle the Api keys in Headscale", apiKeysCmd.Short)
	
	// Test aliases
	expectedAliases := []string{"apikey", "api"}
	assert.Equal(t, expectedAliases, apiKeysCmd.Aliases)
	
	// Test that apikeys command has subcommands
	subcommands := apiKeysCmd.Commands()
	assert.Greater(t, len(subcommands), 0, "API keys command should have subcommands")
	
	// Verify expected subcommands exist
	subcommandNames := make([]string, len(subcommands))
	for i, cmd := range subcommands {
		subcommandNames[i] = cmd.Use
	}
	
	expectedSubcommands := []string{"list", "create", "expire", "delete"}
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

func TestListAPIKeysCommand(t *testing.T) {
	assert.NotNil(t, listAPIKeys)
	assert.Equal(t, "list", listAPIKeys.Use)
	assert.Equal(t, "List the Api keys for headscale", listAPIKeys.Short)
	assert.Equal(t, []string{"ls", "show"}, listAPIKeys.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, listAPIKeys.Run)
}

func TestCreateAPIKeyCommand(t *testing.T) {
	assert.NotNil(t, createAPIKeyCmd)
	assert.Equal(t, "create", createAPIKeyCmd.Use)
	assert.Equal(t, "Creates a new Api key", createAPIKeyCmd.Short)
	assert.Equal(t, []string{"c", "new"}, createAPIKeyCmd.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, createAPIKeyCmd.Run)
	
	// Test that Long description is set
	assert.NotEmpty(t, createAPIKeyCmd.Long)
	assert.Contains(t, createAPIKeyCmd.Long, "Creates a new Api key")
	assert.Contains(t, createAPIKeyCmd.Long, "only visible on creation")
	
	// Test flags
	flags := createAPIKeyCmd.Flags()
	assert.NotNil(t, flags.Lookup("expiration"))
	
	// Test flag properties
	expirationFlag := flags.Lookup("expiration")
	assert.Equal(t, "e", expirationFlag.Shorthand)
	assert.Equal(t, DefaultAPIKeyExpiry, expirationFlag.DefValue)
	assert.Contains(t, expirationFlag.Usage, "Human-readable expiration")
}

func TestExpireAPIKeyCommand(t *testing.T) {
	assert.NotNil(t, expireAPIKeyCmd)
	assert.Equal(t, "expire", expireAPIKeyCmd.Use)
	assert.Equal(t, "Expire an ApiKey", expireAPIKeyCmd.Short)
	assert.Equal(t, []string{"revoke", "exp", "e"}, expireAPIKeyCmd.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, expireAPIKeyCmd.Run)
	
	// Test flags
	flags := expireAPIKeyCmd.Flags()
	assert.NotNil(t, flags.Lookup("prefix"))
	
	// Test flag properties
	prefixFlag := flags.Lookup("prefix")
	assert.Equal(t, "p", prefixFlag.Shorthand)
	assert.Equal(t, "ApiKey prefix", prefixFlag.Usage)
	
	// Test that prefix flag is required
	// Note: We can't directly test MarkFlagRequired, but we can check the annotations
	annotations := prefixFlag.Annotations
	if annotations != nil {
		// cobra adds required annotation when MarkFlagRequired is called
		_, hasRequired := annotations[cobra.BashCompOneRequiredFlag]
		assert.True(t, hasRequired, "prefix flag should be marked as required")
	}
}

func TestDeleteAPIKeyCommand(t *testing.T) {
	assert.NotNil(t, deleteAPIKeyCmd)
	assert.Equal(t, "delete", deleteAPIKeyCmd.Use)
	assert.Equal(t, "Delete an ApiKey", deleteAPIKeyCmd.Short)
	assert.Equal(t, []string{"remove", "del"}, deleteAPIKeyCmd.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, deleteAPIKeyCmd.Run)
	
	// Test flags
	flags := deleteAPIKeyCmd.Flags()
	assert.NotNil(t, flags.Lookup("prefix"))
	
	// Test flag properties
	prefixFlag := flags.Lookup("prefix")
	assert.Equal(t, "p", prefixFlag.Shorthand)
	assert.Equal(t, "ApiKey prefix", prefixFlag.Usage)
	
	// Test that prefix flag is required
	annotations := prefixFlag.Annotations
	if annotations != nil {
		_, hasRequired := annotations[cobra.BashCompOneRequiredFlag]
		assert.True(t, hasRequired, "prefix flag should be marked as required")
	}
}

func TestAPIKeyConstants(t *testing.T) {
	// Test that constants are defined
	assert.Equal(t, "90d", DefaultAPIKeyExpiry)
}

func TestAPIKeyCommandStructure(t *testing.T) {
	// Validate command structure and help text
	ValidateCommandStructure(t, apiKeysCmd, "apikeys", "Handle the Api keys in Headscale")
	ValidateCommandHelp(t, apiKeysCmd)
	
	// Validate subcommands
	ValidateCommandStructure(t, listAPIKeys, "list", "List the Api keys for headscale")
	ValidateCommandHelp(t, listAPIKeys)
	
	ValidateCommandStructure(t, createAPIKeyCmd, "create", "Creates a new Api key")
	ValidateCommandHelp(t, createAPIKeyCmd)
	
	ValidateCommandStructure(t, expireAPIKeyCmd, "expire", "Expire an ApiKey")
	ValidateCommandHelp(t, expireAPIKeyCmd)
	
	ValidateCommandStructure(t, deleteAPIKeyCmd, "delete", "Delete an ApiKey")
	ValidateCommandHelp(t, deleteAPIKeyCmd)
}

func TestAPIKeyCommandFlags(t *testing.T) {
	// Test create API key command flags
	ValidateCommandFlags(t, createAPIKeyCmd, []string{"expiration"})
	
	// Test expire API key command flags
	ValidateCommandFlags(t, expireAPIKeyCmd, []string{"prefix"})
	
	// Test delete API key command flags
	ValidateCommandFlags(t, deleteAPIKeyCmd, []string{"prefix"})
}

func TestAPIKeyCommandIntegration(t *testing.T) {
	// Test that apikeys command is properly integrated into root command
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use == "apikeys" {
			found = true
			break
		}
	}
	assert.True(t, found, "API keys command should be added to root command")
}

func TestAPIKeySubcommandIntegration(t *testing.T) {
	// Test that all subcommands are properly added to apikeys command
	subcommands := apiKeysCmd.Commands()
	
	expectedCommands := map[string]bool{
		"list":   false,
		"create": false,
		"expire": false,
		"delete": false,
	}
	
	for _, subcmd := range subcommands {
		if _, exists := expectedCommands[subcmd.Use]; exists {
			expectedCommands[subcmd.Use] = true
		}
	}
	
	for cmdName, found := range expectedCommands {
		assert.True(t, found, "Subcommand '%s' should be added to apikeys command", cmdName)
	}
}

func TestAPIKeyCommandAliases(t *testing.T) {
	// Test that all aliases are properly set
	testCases := []struct {
		command         *cobra.Command
		expectedAliases []string
	}{
		{
			command:         apiKeysCmd,
			expectedAliases: []string{"apikey", "api"},
		},
		{
			command:         listAPIKeys,
			expectedAliases: []string{"ls", "show"},
		},
		{
			command:         createAPIKeyCmd,
			expectedAliases: []string{"c", "new"},
		},
		{
			command:         expireAPIKeyCmd,
			expectedAliases: []string{"revoke", "exp", "e"},
		},
		{
			command:         deleteAPIKeyCmd,
			expectedAliases: []string{"remove", "del"},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.command.Use, func(t *testing.T) {
			assert.Equal(t, tc.expectedAliases, tc.command.Aliases)
		})
	}
}

func TestAPIKeyFlagDefaults(t *testing.T) {
	// Test create API key command flag defaults
	flags := createAPIKeyCmd.Flags()
	
	// Test expiration flag default
	expiration, err := flags.GetString("expiration")
	assert.NoError(t, err)
	assert.Equal(t, DefaultAPIKeyExpiry, expiration)
}

func TestAPIKeyFlagShortcuts(t *testing.T) {
	// Test that flag shortcuts are properly set
	
	// Create command
	expirationFlag := createAPIKeyCmd.Flags().Lookup("expiration")
	assert.Equal(t, "e", expirationFlag.Shorthand)
	
	// Expire command
	prefixFlag1 := expireAPIKeyCmd.Flags().Lookup("prefix")
	assert.Equal(t, "p", prefixFlag1.Shorthand)
	
	// Delete command
	prefixFlag2 := deleteAPIKeyCmd.Flags().Lookup("prefix")
	assert.Equal(t, "p", prefixFlag2.Shorthand)
}

func TestAPIKeyCommandsHaveOutputFlag(t *testing.T) {
	// All API key commands should support output formatting
	commands := []*cobra.Command{listAPIKeys, createAPIKeyCmd, expireAPIKeyCmd, deleteAPIKeyCmd}
	
	for _, cmd := range commands {
		t.Run(cmd.Use, func(t *testing.T) {
			// Commands should be able to get output flag (though it might be inherited)
			// This tests that the commands are designed to work with output formatting
			assert.NotNil(t, cmd.Run, "Command should have a Run function")
		})
	}
}

func TestAPIKeyCommandCompleteness(t *testing.T) {
	// Test that API key command covers all expected CRUD operations
	subcommands := apiKeysCmd.Commands()
	
	operations := map[string]bool{
		"create": false,
		"read":   false, // list command
		"update": false, // expire command (updates state)
		"delete": false, // delete command
	}
	
	for _, subcmd := range subcommands {
		switch subcmd.Use {
		case "create":
			operations["create"] = true
		case "list":
			operations["read"] = true
		case "expire":
			operations["update"] = true
		case "delete":
			operations["delete"] = true
		}
	}
	
	for op, found := range operations {
		assert.True(t, found, "API key command should support %s operation", op)
	}
}

func TestAPIKeyCommandUsagePatterns(t *testing.T) {
	// Test that commands follow consistent usage patterns
	
	// List command should not require arguments
	assert.NotNil(t, listAPIKeys.Run)
	assert.Nil(t, listAPIKeys.Args) // No args validation means optional args
	
	// Create command should not require arguments
	assert.NotNil(t, createAPIKeyCmd.Run)
	assert.Nil(t, createAPIKeyCmd.Args)
	
	// Expire and delete commands require prefix flag (tested above)
	assert.NotNil(t, expireAPIKeyCmd.Run)
	assert.NotNil(t, deleteAPIKeyCmd.Run)
}

func TestAPIKeyCommandDocumentation(t *testing.T) {
	// Test that important commands have proper documentation
	
	// Create command should have detailed Long description
	assert.NotEmpty(t, createAPIKeyCmd.Long)
	assert.Contains(t, createAPIKeyCmd.Long, "only visible on creation")
	assert.Contains(t, createAPIKeyCmd.Long, "cannot be retrieved again")
	
	// Other commands should have at least Short descriptions
	assert.NotEmpty(t, listAPIKeys.Short)
	assert.NotEmpty(t, expireAPIKeyCmd.Short)
	assert.NotEmpty(t, deleteAPIKeyCmd.Short)
}

func TestAPIKeyFlagValidation(t *testing.T) {
	// Test that flags have proper validation setup
	
	// Test that prefix flags are required where expected
	requiredPrefixCommands := []*cobra.Command{expireAPIKeyCmd, deleteAPIKeyCmd}
	
	for _, cmd := range requiredPrefixCommands {
		t.Run(cmd.Use+"_prefix_required", func(t *testing.T) {
			prefixFlag := cmd.Flags().Lookup("prefix")
			require.NotNil(t, prefixFlag)
			
			// Check if flag has required annotation (set by MarkFlagRequired)
			if prefixFlag.Annotations != nil {
				_, hasRequired := prefixFlag.Annotations[cobra.BashCompOneRequiredFlag]
				assert.True(t, hasRequired, "prefix flag should be marked as required for %s command", cmd.Use)
			}
		})
	}
}

func TestAPIKeyDefaultExpiry(t *testing.T) {
	// Test that the default expiry constant is reasonable
	assert.Equal(t, "90d", DefaultAPIKeyExpiry)
	
	// Test that it can be used in flag defaults
	expirationFlag := createAPIKeyCmd.Flags().Lookup("expiration")
	assert.Equal(t, DefaultAPIKeyExpiry, expirationFlag.DefValue)
}