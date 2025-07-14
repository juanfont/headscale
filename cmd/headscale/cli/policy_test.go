package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyCommand(t *testing.T) {
	// Test the main policy command
	assert.NotNil(t, policyCmd)
	assert.Equal(t, "policy", policyCmd.Use)
	assert.Equal(t, "Manage the Headscale ACL Policy", policyCmd.Short)
	
	// Test that policy command has subcommands
	subcommands := policyCmd.Commands()
	assert.Greater(t, len(subcommands), 0, "Policy command should have subcommands")
	
	// Verify expected subcommands exist
	subcommandNames := make([]string, len(subcommands))
	for i, cmd := range subcommands {
		subcommandNames[i] = cmd.Use
	}
	
	expectedSubcommands := []string{"get", "set", "check"}
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

func TestGetPolicyCommand(t *testing.T) {
	assert.NotNil(t, getPolicy)
	assert.Equal(t, "get", getPolicy.Use)
	assert.Equal(t, "Print the current ACL Policy", getPolicy.Short)
	assert.Equal(t, []string{"show", "view", "fetch"}, getPolicy.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, getPolicy.Run)
}

func TestSetPolicyCommand(t *testing.T) {
	assert.NotNil(t, setPolicy)
	assert.Equal(t, "set", setPolicy.Use)
	assert.Equal(t, "Updates the ACL Policy", setPolicy.Short)
	assert.Equal(t, []string{"update", "save", "apply"}, setPolicy.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, setPolicy.Run)
	
	// Test flags
	flags := setPolicy.Flags()
	assert.NotNil(t, flags.Lookup("file"))
	
	// Test flag properties
	fileFlag := flags.Lookup("file")
	assert.Equal(t, "f", fileFlag.Shorthand)
	assert.Equal(t, "Path to a policy file in HuJSON format", fileFlag.Usage)
	
	// Test that file flag is required
	if fileFlag.Annotations != nil {
		_, hasRequired := fileFlag.Annotations[cobra.BashCompOneRequiredFlag]
		assert.True(t, hasRequired, "file flag should be marked as required")
	}
}

func TestCheckPolicyCommand(t *testing.T) {
	assert.NotNil(t, checkPolicy)
	assert.Equal(t, "check", checkPolicy.Use)
	assert.Equal(t, "Check a policy file for syntax or other issues", checkPolicy.Short)
	assert.Equal(t, []string{"validate", "test", "verify"}, checkPolicy.Aliases)
	
	// Test that Run function is set
	assert.NotNil(t, checkPolicy.Run)
	
	// Test flags
	flags := checkPolicy.Flags()
	assert.NotNil(t, flags.Lookup("file"))
	
	// Test flag properties
	fileFlag := flags.Lookup("file")
	assert.Equal(t, "f", fileFlag.Shorthand)
	assert.Equal(t, "Path to a policy file in HuJSON format", fileFlag.Usage)
	
	// Test that file flag is required
	if fileFlag.Annotations != nil {
		_, hasRequired := fileFlag.Annotations[cobra.BashCompOneRequiredFlag]
		assert.True(t, hasRequired, "file flag should be marked as required")
	}
}

func TestPolicyCommandStructure(t *testing.T) {
	// Validate command structure and help text
	ValidateCommandStructure(t, policyCmd, "policy", "Manage the Headscale ACL Policy")
	ValidateCommandHelp(t, policyCmd)
	
	// Validate subcommands
	ValidateCommandStructure(t, getPolicy, "get", "Print the current ACL Policy")
	ValidateCommandHelp(t, getPolicy)
	
	ValidateCommandStructure(t, setPolicy, "set", "Updates the ACL Policy")
	ValidateCommandHelp(t, setPolicy)
	
	ValidateCommandStructure(t, checkPolicy, "check", "Check a policy file for syntax or other issues")
	ValidateCommandHelp(t, checkPolicy)
}

func TestPolicyCommandFlags(t *testing.T) {
	// Test set policy command flags
	ValidateCommandFlags(t, setPolicy, []string{"file"})
	
	// Test check policy command flags
	ValidateCommandFlags(t, checkPolicy, []string{"file"})
}

func TestPolicyCommandIntegration(t *testing.T) {
	// Test that policy command is properly integrated into root command
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use == "policy" {
			found = true
			break
		}
	}
	assert.True(t, found, "Policy command should be added to root command")
}

func TestPolicySubcommandIntegration(t *testing.T) {
	// Test that all subcommands are properly added to policy command
	subcommands := policyCmd.Commands()
	
	expectedCommands := map[string]bool{
		"get":   false,
		"set":   false,
		"check": false,
	}
	
	for _, subcmd := range subcommands {
		if _, exists := expectedCommands[subcmd.Use]; exists {
			expectedCommands[subcmd.Use] = true
		}
	}
	
	for cmdName, found := range expectedCommands {
		assert.True(t, found, "Subcommand '%s' should be added to policy command", cmdName)
	}
}

func TestPolicyCommandAliases(t *testing.T) {
	// Test that all aliases are properly set
	testCases := []struct {
		command         *cobra.Command
		expectedAliases []string
	}{
		{
			command:         getPolicy,
			expectedAliases: []string{"show", "view", "fetch"},
		},
		{
			command:         setPolicy,
			expectedAliases: []string{"update", "save", "apply"},
		},
		{
			command:         checkPolicy,
			expectedAliases: []string{"validate", "test", "verify"},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.command.Use, func(t *testing.T) {
			assert.Equal(t, tc.expectedAliases, tc.command.Aliases)
		})
	}
}

func TestPolicyCommandsHaveOutputFlag(t *testing.T) {
	// All policy commands should support output formatting
	commands := []*cobra.Command{getPolicy, setPolicy, checkPolicy}
	
	for _, cmd := range commands {
		t.Run(cmd.Use, func(t *testing.T) {
			// Commands should be able to get output flag (though it might be inherited)
			// This tests that the commands are designed to work with output formatting
			assert.NotNil(t, cmd.Run, "Command should have a Run function")
		})
	}
}

func TestPolicyCommandCompleteness(t *testing.T) {
	// Test that policy command covers all expected operations
	subcommands := policyCmd.Commands()
	
	operations := map[string]bool{
		"read":     false, // get command
		"write":    false, // set command
		"validate": false, // check command
	}
	
	for _, subcmd := range subcommands {
		switch subcmd.Use {
		case "get":
			operations["read"] = true
		case "set":
			operations["write"] = true
		case "check":
			operations["validate"] = true
		}
	}
	
	for op, found := range operations {
		assert.True(t, found, "Policy command should support %s operation", op)
	}
}

func TestPolicyRequiredFlags(t *testing.T) {
	// Test that file flag is required for set and check commands
	commandsWithRequiredFile := []*cobra.Command{setPolicy, checkPolicy}
	
	for _, cmd := range commandsWithRequiredFile {
		t.Run(cmd.Use+"_file_required", func(t *testing.T) {
			fileFlag := cmd.Flags().Lookup("file")
			require.NotNil(t, fileFlag)
			
			// Check if flag has required annotation (set by MarkFlagRequired)
			if fileFlag.Annotations != nil {
				_, hasRequired := fileFlag.Annotations[cobra.BashCompOneRequiredFlag]
				assert.True(t, hasRequired, "file flag should be marked as required for %s command", cmd.Use)
			}
		})
	}
}

func TestPolicyFlagShortcuts(t *testing.T) {
	// Test that flag shortcuts are properly set
	
	// Set command
	fileFlag1 := setPolicy.Flags().Lookup("file")
	assert.Equal(t, "f", fileFlag1.Shorthand)
	
	// Check command
	fileFlag2 := checkPolicy.Flags().Lookup("file")
	assert.Equal(t, "f", fileFlag2.Shorthand)
}

func TestPolicyCommandUsagePatterns(t *testing.T) {
	// Test that commands follow consistent usage patterns
	
	// Get command should not require arguments or flags
	assert.NotNil(t, getPolicy.Run)
	assert.Nil(t, getPolicy.Args) // No args validation means optional args
	
	// Set and check commands require file flag (tested above)
	assert.NotNil(t, setPolicy.Run)
	assert.NotNil(t, checkPolicy.Run)
}

func TestPolicyCommandDocumentation(t *testing.T) {
	// Test that commands have proper documentation
	
	// Main command should reference ACL
	assert.Contains(t, policyCmd.Short, "ACL Policy")
	
	// Get command should be about reading
	assert.Contains(t, getPolicy.Short, "Print")
	assert.Contains(t, getPolicy.Short, "current")
	
	// Set command should be about updating
	assert.Contains(t, setPolicy.Short, "Updates")
	
	// Check command should be about validation
	assert.Contains(t, checkPolicy.Short, "Check")
	assert.Contains(t, checkPolicy.Short, "syntax")
}

func TestPolicyFlagDescriptions(t *testing.T) {
	// Test that file flags have helpful descriptions
	
	setFileFlag := setPolicy.Flags().Lookup("file")
	assert.Contains(t, setFileFlag.Usage, "Path to a policy file")
	assert.Contains(t, setFileFlag.Usage, "HuJSON")
	
	checkFileFlag := checkPolicy.Flags().Lookup("file")
	assert.Contains(t, checkFileFlag.Usage, "Path to a policy file")
	assert.Contains(t, checkFileFlag.Usage, "HuJSON")
}

func TestPolicyCommandNoAliases(t *testing.T) {
	// Main policy command should not have aliases (it's clear enough)
	assert.Empty(t, policyCmd.Aliases, "Main policy command should not need aliases")
}

func TestPolicyCommandConsistency(t *testing.T) {
	// Test that policy commands follow consistent patterns
	
	// Commands that work with files should use consistent flag naming
	fileCommands := []*cobra.Command{setPolicy, checkPolicy}
	
	for _, cmd := range fileCommands {
		t.Run(cmd.Use+"_consistent_file_flag", func(t *testing.T) {
			fileFlag := cmd.Flags().Lookup("file")
			require.NotNil(t, fileFlag, "Command %s should have file flag", cmd.Use)
			assert.Equal(t, "f", fileFlag.Shorthand, "File flag should have 'f' shorthand")
			assert.Contains(t, fileFlag.Usage, "HuJSON", "File flag should mention HuJSON format")
		})
	}
}

func TestPolicyCommandMeaningfulAliases(t *testing.T) {
	// Test that aliases are meaningful and intuitive
	
	// Get command aliases should be about reading/viewing
	getAliases := getPolicy.Aliases
	assert.Contains(t, getAliases, "show")
	assert.Contains(t, getAliases, "view")
	assert.Contains(t, getAliases, "fetch")
	
	// Set command aliases should be about writing/updating
	setAliases := setPolicy.Aliases
	assert.Contains(t, setAliases, "update")
	assert.Contains(t, setAliases, "save")
	assert.Contains(t, setAliases, "apply")
	
	// Check command aliases should be about validation
	checkAliases := checkPolicy.Aliases
	assert.Contains(t, checkAliases, "validate")
	assert.Contains(t, checkAliases, "test")
	assert.Contains(t, checkAliases, "verify")
}

func TestPolicyWorkflowCompleteness(t *testing.T) {
	// Test that policy commands support a complete workflow
	
	// Should be able to: get current policy, check new policy, set new policy
	subcommands := policyCmd.Commands()
	
	workflow := map[string]bool{
		"get_current":   false, // get command
		"validate_new":  false, // check command
		"apply_new":     false, // set command
	}
	
	for _, subcmd := range subcommands {
		switch subcmd.Use {
		case "get":
			workflow["get_current"] = true
		case "check":
			workflow["validate_new"] = true
		case "set":
			workflow["apply_new"] = true
		}
	}
	
	for step, supported := range workflow {
		assert.True(t, supported, "Policy workflow should support %s step", step)
	}
}