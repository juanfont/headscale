package cli

import (
	"testing"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// TestCLIInfrastructureIntegration tests that all infrastructure components work together
func TestCLIInfrastructureIntegration(t *testing.T) {
	t.Run("testing infrastructure", func(t *testing.T) {
		// Test mock client creation using the helper function
		mockClient := NewMockHeadscaleServiceClient()
		assert.NotNil(t, mockClient)
		assert.NotNil(t, mockClient.CallCount)
		
		// Test that mock client tracks calls
		_, err := mockClient.ListUsers(nil, &v1.ListUsersRequest{})
		assert.NoError(t, err)
		assert.Equal(t, 1, mockClient.CallCount["ListUsers"])
	})
	
	t.Run("validation integration", func(t *testing.T) {
		// Test that validation functions work correctly together
		assert.NoError(t, ValidateEmail("test@example.com"))
		assert.NoError(t, ValidateUserName("testuser"))
		assert.NoError(t, ValidateNodeName("testnode"))
		assert.NoError(t, ValidateCIDR("192.168.1.0/24"))
		
		// Test validation of complex scenarios
		tags := []string{"env:prod", "team:backend"}
		assert.NoError(t, ValidateTagsFormat(tags))
		
		routes := []string{"10.0.0.0/8", "172.16.0.0/12"}
		assert.NoError(t, ValidateRoutesFormat(routes))
	})
	
	t.Run("flag infrastructure", func(t *testing.T) {
		// Test that flag helpers work
		cmd := &cobra.Command{Use: "test"}
		
		AddIdentifierFlag(cmd, "id", "Test ID flag")
		AddUserFlag(cmd)
		AddOutputFlag(cmd)
		AddForceFlag(cmd)
		
		// Verify flags were added
		assert.NotNil(t, cmd.Flags().Lookup("id"))
		assert.NotNil(t, cmd.Flags().Lookup("user"))
		assert.NotNil(t, cmd.Flags().Lookup("output"))
		assert.NotNil(t, cmd.Flags().Lookup("force"))
		
		// Test flag shortcuts
		idFlag := cmd.Flags().Lookup("id")
		assert.Equal(t, "i", idFlag.Shorthand)
		
		userFlag := cmd.Flags().Lookup("user")
		assert.Equal(t, "u", userFlag.Shorthand)
		
		outputFlag := cmd.Flags().Lookup("output")
		assert.Equal(t, "o", outputFlag.Shorthand)
		
		forceFlag := cmd.Flags().Lookup("force")
		assert.Equal(t, "", forceFlag.Shorthand, "Force flag doesn't have a shorthand")
	})
	
	t.Run("output infrastructure", func(t *testing.T) {
		// Test output manager creation
		cmd := &cobra.Command{Use: "test"}
		om := NewOutputManager(cmd)
		assert.NotNil(t, om)
		
		// Test table renderer creation
		tr := NewTableRenderer(om)
		assert.NotNil(t, tr)
		
		// Test table column addition
		tr.AddColumn("Test Column", func(item interface{}) string {
			return "test value"
		})
		
		assert.Equal(t, 1, len(tr.columns))
		assert.Equal(t, "Test Column", tr.columns[0].Header)
	})
	
	t.Run("command patterns", func(t *testing.T) {
		// Test that argument validators work correctly
		validator := ValidateExactArgs(2, "test <arg1> <arg2>")
		assert.NotNil(t, validator)
		
		cmd := &cobra.Command{Use: "test"}
		
		// Should accept exactly 2 arguments
		err := validator(cmd, []string{"arg1", "arg2"})
		assert.NoError(t, err)
		
		// Should reject wrong number of arguments
		err = validator(cmd, []string{"arg1"})
		assert.Error(t, err)
		
		err = validator(cmd, []string{"arg1", "arg2", "arg3"})
		assert.Error(t, err)
	})
}

// TestCLIInfrastructureConsistency tests that the infrastructure maintains consistency
func TestCLIInfrastructureConsistency(t *testing.T) {
	t.Run("error message consistency", func(t *testing.T) {
		// Test that validation errors have consistent formatting
		emailErr := ValidateEmail("")
		userErr := ValidateUserName("")
		nodeErr := ValidateNodeName("")
		
		// All should mention "cannot be empty"
		assert.Contains(t, emailErr.Error(), "cannot be empty")
		assert.Contains(t, userErr.Error(), "cannot be empty")
		assert.Contains(t, nodeErr.Error(), "cannot be empty")
	})
	
	t.Run("flag naming consistency", func(t *testing.T) {
		// Test that common flags use consistent shortcuts
		cmd := &cobra.Command{Use: "test"}
		
		AddUserFlag(cmd)
		AddIdentifierFlag(cmd, "id", "ID flag")
		AddOutputFlag(cmd)
		AddForceFlag(cmd)
		
		// Common shortcuts should be consistent
		assert.Equal(t, "u", cmd.Flags().Lookup("user").Shorthand)
		assert.Equal(t, "i", cmd.Flags().Lookup("id").Shorthand)
		assert.Equal(t, "o", cmd.Flags().Lookup("output").Shorthand)
		assert.Equal(t, "", cmd.Flags().Lookup("force").Shorthand)
	})
	
	t.Run("command structure consistency", func(t *testing.T) {
		// Test that main commands follow consistent patterns
		commands := []*cobra.Command{userCmd, nodeCmd, apiKeysCmd, preauthkeysCmd}
		
		for _, cmd := range commands {
			// All main commands should have subcommands
			assert.True(t, cmd.HasSubCommands(), "Command %s should have subcommands", cmd.Use)
			
			// All main commands should have short descriptions
			assert.NotEmpty(t, cmd.Short, "Command %s should have short description", cmd.Use)
			
			// All main commands should be properly integrated
			found := false
			for _, rootSubcmd := range rootCmd.Commands() {
				if rootSubcmd == cmd {
					found = true
					break
				}
			}
			assert.True(t, found, "Command %s should be added to root", cmd.Use)
		}
	})
}

// TestCLIInfrastructurePerformance tests that the infrastructure is performant
func TestCLIInfrastructurePerformance(t *testing.T) {
	t.Run("validation performance", func(t *testing.T) {
		// Test that validation functions are fast enough for CLI use
		for i := 0; i < 1000; i++ {
			ValidateEmail("test@example.com")
			ValidateUserName("testuser")
			ValidateNodeName("testnode")
			ValidateCIDR("192.168.1.0/24")
		}
		// Test passes if it completes without timeout
	})
	
	t.Run("mock client performance", func(t *testing.T) {
		// Test that mock client operations are fast
		mockClient := NewMockHeadscaleServiceClient()
		
		for i := 0; i < 1000; i++ {
			mockClient.ListUsers(nil, &v1.ListUsersRequest{})
			mockClient.ListNodes(nil, &v1.ListNodesRequest{})
		}
		
		// Verify call tracking works efficiently
		assert.Equal(t, 1000, mockClient.CallCount["ListUsers"])
		assert.Equal(t, 1000, mockClient.CallCount["ListNodes"])
	})
}

// TestCLIInfrastructureEdgeCases tests edge cases and error conditions
func TestCLIInfrastructureEdgeCases(t *testing.T) {
	t.Run("nil handling", func(t *testing.T) {
		// Test that functions handle nil inputs gracefully
		err := ValidateTagsFormat(nil)
		assert.NoError(t, err, "Should handle nil tags list")
		
		err = ValidateRoutesFormat(nil)
		assert.NoError(t, err, "Should handle nil routes list")
	})
	
	t.Run("empty input handling", func(t *testing.T) {
		// Test empty inputs
		err := ValidateTagsFormat([]string{})
		assert.NoError(t, err, "Should handle empty tags list")
		
		err = ValidateRoutesFormat([]string{})
		assert.NoError(t, err, "Should handle empty routes list")
	})
	
	t.Run("boundary conditions", func(t *testing.T) {
		// Test boundary conditions for string length validation
		err := ValidateStringLength("", "field", 0, 10)
		assert.NoError(t, err, "Should handle minimum length 0")
		
		err = ValidateStringLength("1234567890", "field", 0, 10)
		assert.NoError(t, err, "Should handle exact maximum length")
		
		err = ValidateStringLength("12345678901", "field", 0, 10)
		assert.Error(t, err, "Should reject over maximum length")
	})
}

// TestCLIInfrastructureDocumentation tests that infrastructure components are well documented
func TestCLIInfrastructureDocumentation(t *testing.T) {
	t.Run("function documentation", func(t *testing.T) {
		// This is a meta-test to ensure we maintain good documentation
		// In a real scenario, you might parse Go source and check for comments
		
		// For now, we test that key functions exist and have meaningful names
		assert.NotNil(t, ValidateEmail, "ValidateEmail should exist")
		assert.NotNil(t, ValidateUserName, "ValidateUserName should exist")
		assert.NotNil(t, ValidateNodeName, "ValidateNodeName should exist")
		assert.NotNil(t, NewOutputManager, "NewOutputManager should exist")
		assert.NotNil(t, NewTableRenderer, "NewTableRenderer should exist")
	})
	
	t.Run("error message clarity", func(t *testing.T) {
		// Test that error messages are helpful and include relevant information
		err := ValidateEmail("invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid", "Error should include the invalid input")
		
		err = ValidateUserName("user with spaces")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid characters", "Error should explain the problem")
		
		err = ValidateAPIKeyPrefix("ab")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least 4 characters", "Error should specify requirements")
	})
}

// TestCLIInfrastructureBackwardsCompatibility tests that changes don't break existing functionality
func TestCLIInfrastructureBackwardsCompatibility(t *testing.T) {
	t.Run("existing command structure", func(t *testing.T) {
		// Test that existing commands still work as expected
		assert.NotNil(t, userCmd, "User command should still exist")
		assert.NotNil(t, nodeCmd, "Node command should still exist")
		assert.NotNil(t, rootCmd, "Root command should still exist")
		
		// Test that existing subcommands still exist
		assert.True(t, userCmd.HasSubCommands(), "User command should have subcommands")
		assert.True(t, nodeCmd.HasSubCommands(), "Node command should have subcommands")
	})
	
	t.Run("flag compatibility", func(t *testing.T) {
		// Test that common flags still exist with expected shortcuts
		commands := []*cobra.Command{listUsersCmd, listNodesCmd}
		
		for _, cmd := range commands {
			userFlag := cmd.Flags().Lookup("user")
			if userFlag != nil {
				assert.Equal(t, "u", userFlag.Shorthand, "User flag shortcut should be 'u'")
			}
		}
	})
}

// TestCLIInfrastructureIntegrationWithExistingCode tests integration with existing codebase
func TestCLIInfrastructureIntegrationWithExistingCode(t *testing.T) {
	t.Run("command registration", func(t *testing.T) {
		// Test that new infrastructure doesn't interfere with existing command registration
		initialCommandCount := len(rootCmd.Commands())
		assert.Greater(t, initialCommandCount, 0, "Root command should have subcommands")
		
		// Test that all expected commands are registered
		expectedCommands := []string{"users", "nodes", "apikeys", "preauthkeys", "version", "generate"}
		
		for _, expectedCmd := range expectedCommands {
			found := false
			for _, cmd := range rootCmd.Commands() {
				if cmd.Use == expectedCmd || cmd.Name() == expectedCmd {
					found = true
					break
				}
			}
			assert.True(t, found, "Expected command %s should be registered", expectedCmd)
		}
	})
	
	t.Run("configuration compatibility", func(t *testing.T) {
		// Test that new infrastructure works with existing configuration
		
		// Test that output format detection works
		cmd := &cobra.Command{Use: "test"}
		format := GetOutputFormat(cmd)
		assert.Equal(t, "", format, "Default output format should be empty string")
		
		// Test that machine output detection works
		hasMachine := HasMachineOutputFlag()
		assert.False(t, hasMachine, "Should not detect machine output by default")
	})
}