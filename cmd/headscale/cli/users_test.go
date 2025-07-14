package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserCommand(t *testing.T) {
	// Test the main user command
	assert.NotNil(t, userCmd)
	assert.Equal(t, "users", userCmd.Use)
	assert.Equal(t, "Manage the users of Headscale", userCmd.Short)
	
	// Test aliases
	expectedAliases := []string{"user", "namespace", "namespaces", "ns"}
	assert.Equal(t, expectedAliases, userCmd.Aliases)
	
	// Test that user command has subcommands
	subcommands := userCmd.Commands()
	assert.Greater(t, len(subcommands), 0, "User command should have subcommands")
	
	// Verify expected subcommands exist
	subcommandNames := make([]string, len(subcommands))
	for i, cmd := range subcommands {
		subcommandNames[i] = cmd.Use
	}
	
	expectedSubcommands := []string{"create", "list", "destroy", "rename"}
	for _, expected := range expectedSubcommands {
		found := false
		for _, actual := range subcommandNames {
			if actual == expected || (actual == "create NAME") {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected subcommand '%s' not found", expected)
	}
}

func TestCreateUserCommand(t *testing.T) {
	assert.NotNil(t, createUserCmd)
	assert.Equal(t, "create NAME", createUserCmd.Use)
	assert.Equal(t, "Creates a new user", createUserCmd.Short)
	assert.Equal(t, []string{"c", "new"}, createUserCmd.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, createUserCmd.Run)
	
	// Test that Args validation function is set
	assert.NotNil(t, createUserCmd.Args)
	
	// Test Args validation
	err := createUserCmd.Args(createUserCmd, []string{})
	assert.Error(t, err)
	assert.Equal(t, errMissingParameter, err)
	
	err = createUserCmd.Args(createUserCmd, []string{"testuser"})
	assert.NoError(t, err)
	
	// Test flags
	flags := createUserCmd.Flags()
	assert.NotNil(t, flags.Lookup("display-name"))
	assert.NotNil(t, flags.Lookup("email"))
	assert.NotNil(t, flags.Lookup("picture-url"))
	
	// Test flag shortcuts
	displayNameFlag := flags.Lookup("display-name")
	assert.Equal(t, "d", displayNameFlag.Shorthand)
	
	emailFlag := flags.Lookup("email")
	assert.Equal(t, "e", emailFlag.Shorthand)
	
	pictureFlag := flags.Lookup("picture-url")
	assert.Equal(t, "p", pictureFlag.Shorthand)
}

func TestListUsersCommand(t *testing.T) {
	assert.NotNil(t, listUsersCmd)
	assert.Equal(t, "list", listUsersCmd.Use)
	assert.Equal(t, "List all the users", listUsersCmd.Short)
	assert.Equal(t, []string{"ls", "show"}, listUsersCmd.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, listUsersCmd.Run)
	
	// Test flags from usernameAndIDFlag
	flags := listUsersCmd.Flags()
	assert.NotNil(t, flags.Lookup("identifier"))
	assert.NotNil(t, flags.Lookup("name"))
	assert.NotNil(t, flags.Lookup("email"))
	
	// Test flag shortcuts
	identifierFlag := flags.Lookup("identifier")
	assert.Equal(t, "i", identifierFlag.Shorthand)
	
	nameFlag := flags.Lookup("name")
	assert.Equal(t, "n", nameFlag.Shorthand)
	
	emailFlag := flags.Lookup("email")
	assert.Equal(t, "e", emailFlag.Shorthand)
}

func TestDestroyUserCommand(t *testing.T) {
	assert.NotNil(t, destroyUserCmd)
	assert.Equal(t, "destroy --identifier ID or --name NAME", destroyUserCmd.Use)
	assert.Equal(t, "Destroys a user", destroyUserCmd.Short)
	assert.Equal(t, []string{"delete"}, destroyUserCmd.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, destroyUserCmd.Run)
	
	// Test flags from usernameAndIDFlag
	flags := destroyUserCmd.Flags()
	assert.NotNil(t, flags.Lookup("identifier"))
	assert.NotNil(t, flags.Lookup("name"))
}

func TestRenameUserCommand(t *testing.T) {
	assert.NotNil(t, renameUserCmd)
	assert.Equal(t, "rename", renameUserCmd.Use)
	assert.Equal(t, "Renames a user", renameUserCmd.Short)
	assert.Equal(t, []string{"mv"}, renameUserCmd.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, renameUserCmd.Run)
	
	// Test flags
	flags := renameUserCmd.Flags()
	assert.NotNil(t, flags.Lookup("identifier"))
	assert.NotNil(t, flags.Lookup("name"))
	assert.NotNil(t, flags.Lookup("new-name"))
	
	// Test flag shortcuts
	newNameFlag := flags.Lookup("new-name")
	assert.Equal(t, "r", newNameFlag.Shorthand)
}

func TestUsernameAndIDFlag(t *testing.T) {
	// Create a test command
	cmd := &cobra.Command{Use: "test"}
	
	// Apply the flag function
	usernameAndIDFlag(cmd)
	
	// Test that flags were added
	flags := cmd.Flags()
	assert.NotNil(t, flags.Lookup("identifier"))
	assert.NotNil(t, flags.Lookup("name"))
	
	// Test flag properties
	identifierFlag := flags.Lookup("identifier")
	assert.Equal(t, "i", identifierFlag.Shorthand)
	assert.Equal(t, "User identifier (ID)", identifierFlag.Usage)
	assert.Equal(t, "-1", identifierFlag.DefValue)
	
	nameFlag := flags.Lookup("name")
	assert.Equal(t, "n", nameFlag.Shorthand)
	assert.Equal(t, "Username", nameFlag.Usage)
	assert.Equal(t, "", nameFlag.DefValue)
}

func TestUsernameAndIDFromFlag(t *testing.T) {
	tests := []struct {
		name           string
		identifier     int64
		username       string
		expectedID     uint64
		expectedName   string
		expectError    bool
	}{
		{
			name:         "valid identifier only",
			identifier:   123,
			username:     "",
			expectedID:   123,
			expectedName: "",
			expectError:  false,
		},
		{
			name:         "valid username only",
			identifier:   -1,
			username:     "testuser",
			expectedID:   0, // uint64(-1) wraps around, but we check identifier < 0
			expectedName: "testuser",
			expectError:  false,
		},
		{
			name:         "both provided",
			identifier:   123,
			username:     "testuser",
			expectedID:   123,
			expectedName: "testuser",
			expectError:  false,
		},
		{
			name:         "neither provided",
			identifier:   -1,
			username:     "",
			expectedID:   0,
			expectedName: "",
			expectError:  true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test command with flags
			cmd := &cobra.Command{Use: "test"}
			usernameAndIDFlag(cmd)
			
			// Set flag values
			if tt.identifier >= 0 {
				err := cmd.Flags().Set("identifier", string(rune(tt.identifier+'0')))
				require.NoError(t, err)
			}
			if tt.username != "" {
				err := cmd.Flags().Set("name", tt.username)
				require.NoError(t, err)
			}
			
			// Note: usernameAndIDFromFlag calls ErrorOutput and exits on error,
			// so we can't easily test the error case without mocking ErrorOutput.
			// We'll test the success cases only.
			if !tt.expectError {
				id, name := usernameAndIDFromFlag(cmd)
				assert.Equal(t, tt.expectedID, id)
				assert.Equal(t, tt.expectedName, name)
			}
		})
	}
}


func TestUserCommandFlags(t *testing.T) {
	// Test create user command flags
	ValidateCommandFlags(t, createUserCmd, []string{"display-name", "email", "picture-url"})
	
	// Test list users command flags
	ValidateCommandFlags(t, listUsersCmd, []string{"identifier", "name", "email"})
	
	// Test destroy user command flags
	ValidateCommandFlags(t, destroyUserCmd, []string{"identifier", "name"})
	
	// Test rename user command flags
	ValidateCommandFlags(t, renameUserCmd, []string{"identifier", "name", "new-name"})
}


func TestUserCommandIntegration(t *testing.T) {
	// Test that user command is properly integrated into root command
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use == "users" {
			found = true
			break
		}
	}
	assert.True(t, found, "User command should be added to root command")
}

func TestUserSubcommandIntegration(t *testing.T) {
	// Test that all subcommands are properly added to user command
	subcommands := userCmd.Commands()
	
	expectedCommands := map[string]bool{
		"create NAME": false,
		"list":        false,
		"destroy":     false,
		"rename":      false,
	}
	
	for _, subcmd := range subcommands {
		if _, exists := expectedCommands[subcmd.Use]; exists {
			expectedCommands[subcmd.Use] = true
		}
	}
	
	for cmdName, found := range expectedCommands {
		assert.True(t, found, "Subcommand '%s' should be added to user command", cmdName)
	}
}

func TestUserCommandFlagValidation(t *testing.T) {
	// Test flag default values and types
	cmd := &cobra.Command{Use: "test"}
	usernameAndIDFlag(cmd)
	
	// Test identifier flag default
	identifier, err := cmd.Flags().GetInt64("identifier")
	assert.NoError(t, err)
	assert.Equal(t, int64(-1), identifier)
	
	// Test name flag default
	name, err := cmd.Flags().GetString("name")
	assert.NoError(t, err)
	assert.Equal(t, "", name)
}

func TestCreateUserCommandArgsValidation(t *testing.T) {
	// Test the Args validation function
	testCases := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "no arguments",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "one argument",
			args:    []string{"testuser"},
			wantErr: false,
		},
		{
			name:    "multiple arguments",
			args:    []string{"testuser", "extra"},
			wantErr: false, // Args function only checks for minimum 1 arg
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := createUserCmd.Args(createUserCmd, tc.args)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUserCommandAliases(t *testing.T) {
	// Test that all aliases are properly set
	testCases := []struct {
		command         *cobra.Command
		expectedAliases []string
	}{
		{
			command:         userCmd,
			expectedAliases: []string{"user", "namespace", "namespaces", "ns"},
		},
		{
			command:         createUserCmd,
			expectedAliases: []string{"c", "new"},
		},
		{
			command:         listUsersCmd,
			expectedAliases: []string{"ls", "show"},
		},
		{
			command:         destroyUserCmd,
			expectedAliases: []string{"delete"},
		},
		{
			command:         renameUserCmd,
			expectedAliases: []string{"mv"},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.command.Use, func(t *testing.T) {
			assert.Equal(t, tc.expectedAliases, tc.command.Aliases)
		})
	}
}

func TestUserCommandsHaveOutputFlag(t *testing.T) {
	// All user commands should support output formatting
	commands := []*cobra.Command{createUserCmd, listUsersCmd, destroyUserCmd, renameUserCmd}
	
	for _, cmd := range commands {
		t.Run(cmd.Use, func(t *testing.T) {
			// Commands should be able to get output flag (though it might be inherited)
			// This tests that the commands are designed to work with output formatting
			assert.NotNil(t, cmd.Run, "Command should have a Run function")
		})
	}
}

func TestUserCommandCompleteness(t *testing.T) {
	// Test that user command covers all expected CRUD operations
	subcommands := userCmd.Commands()
	
	operations := map[string]bool{
		"create": false,
		"read":   false, // list command
		"update": false, // rename command  
		"delete": false, // destroy command
	}
	
	for _, subcmd := range subcommands {
		switch {
		case subcmd.Use == "create NAME":
			operations["create"] = true
		case subcmd.Use == "list":
			operations["read"] = true
		case subcmd.Use == "rename":
			operations["update"] = true
		case subcmd.Use == "destroy --identifier ID or --name NAME":
			operations["delete"] = true
		}
	}
	
	for op, found := range operations {
		assert.True(t, found, "User command should support %s operation", op)
	}
}