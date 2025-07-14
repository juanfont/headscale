package cli

import (
	"testing"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// TestRefactoredUserCommands tests the refactored user commands
func TestRefactoredUserCommands(t *testing.T) {
	t.Run("create user refactored", func(t *testing.T) {
		cmd := createUserRefactored()
		assert.NotNil(t, cmd)
		assert.Equal(t, "create NAME", cmd.Use)
		assert.Equal(t, "Creates a new user", cmd.Short)
		assert.Contains(t, cmd.Aliases, "c")
		assert.Contains(t, cmd.Aliases, "new")
		
		// Test flags
		assert.NotNil(t, cmd.Flags().Lookup("display-name"))
		assert.NotNil(t, cmd.Flags().Lookup("email"))
		assert.NotNil(t, cmd.Flags().Lookup("picture-url"))
		assert.NotNil(t, cmd.Flags().Lookup("output"))
		
		// Test Args validation
		assert.NotNil(t, cmd.Args)
	})
	
	t.Run("list users refactored", func(t *testing.T) {
		cmd := listUsersRefactored()
		assert.NotNil(t, cmd)
		assert.Equal(t, "list", cmd.Use)
		assert.Equal(t, "List all users", cmd.Short)
		assert.Contains(t, cmd.Aliases, "ls")
		assert.Contains(t, cmd.Aliases, "show")
		
		// Test flags
		assert.NotNil(t, cmd.Flags().Lookup("identifier"))
		assert.NotNil(t, cmd.Flags().Lookup("name"))
		assert.NotNil(t, cmd.Flags().Lookup("email"))
		assert.NotNil(t, cmd.Flags().Lookup("output"))
	})
	
	t.Run("delete user refactored", func(t *testing.T) {
		cmd := deleteUserRefactored()
		assert.NotNil(t, cmd)
		assert.Equal(t, "delete", cmd.Use)
		assert.Equal(t, "Delete a user", cmd.Short)
		assert.Contains(t, cmd.Aliases, "remove")
		assert.Contains(t, cmd.Aliases, "rm")
		assert.Contains(t, cmd.Aliases, "destroy")
		
		// Test flags
		assert.NotNil(t, cmd.Flags().Lookup("force"))
		assert.NotNil(t, cmd.Flags().Lookup("output"))
		
		// Test Args validation
		assert.NotNil(t, cmd.Args)
	})
	
	t.Run("rename user refactored", func(t *testing.T) {
		cmd := renameUserRefactored()
		assert.NotNil(t, cmd)
		assert.Equal(t, "rename <current-name|id> <new-name>", cmd.Use)
		assert.Equal(t, "Rename a user", cmd.Short)
		assert.Contains(t, cmd.Aliases, "mv")
		
		// Test flags
		assert.NotNil(t, cmd.Flags().Lookup("output"))
		
		// Test Args validation
		assert.NotNil(t, cmd.Args)
	})
}

// TestRefactoredUserLogicFunctions tests the business logic functions
func TestRefactoredUserLogicFunctions(t *testing.T) {
	t.Run("createUserLogic", func(t *testing.T) {
		mockClient := NewMockClientWrapper()
		cmd := &cobra.Command{}
		AddOutputFlag(cmd)
		
		// Test valid user creation with a new username that doesn't exist
		args := []string{"newuser"}
		result, err := createUserLogic(mockClient, cmd, args)
		
		assert.NoError(t, err)
		assert.NotNil(t, result)
		// Note: We can't easily check call counts with the wrapper, but we can verify the result
	})
	
	t.Run("createUserLogic with invalid username", func(t *testing.T) {
		mockClient := NewMockClientWrapper()
		cmd := &cobra.Command{}
		
		// Test with invalid username (empty)
		args := []string{""}
		_, err := createUserLogic(mockClient, cmd, args)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be empty")
	})
	
	t.Run("createUserLogic with email validation", func(t *testing.T) {
		mockClient := NewMockClientWrapper()
		cmd := &cobra.Command{}
		cmd.Flags().String("email", "invalid-email", "")
		
		args := []string{"testuser"}
		_, err := createUserLogic(mockClient, cmd, args)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid email")
	})
	
	t.Run("listUsersLogic", func(t *testing.T) {
		mockClient := NewMockClientWrapper()
		cmd := &cobra.Command{}
		
		result, err := listUsersLogic(mockClient, cmd)
		
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
	
	t.Run("listUsersLogic with filtering", func(t *testing.T) {
		mockClient := NewMockClientWrapper()
		cmd := &cobra.Command{}
		AddIdentifierFlag(cmd, "identifier", "Test ID")
		cmd.Flags().Set("identifier", "123")
		
		result, err := listUsersLogic(mockClient, cmd)
		
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
	
	t.Run("getUserLogic", func(t *testing.T) {
		mockClient := NewMockClientWrapper()
		cmd := &cobra.Command{}
		// Simulate parsed args
		cmd.ParseFlags([]string{"testuser"})
		cmd.SetArgs([]string{"testuser"})
		
		result, err := getUserLogic(mockClient, cmd)
		
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
	
	t.Run("deleteUserLogic", func(t *testing.T) {
		mockClient := NewMockClientWrapper()
		cmd := &cobra.Command{}
		// Simulate parsed args
		cmd.ParseFlags([]string{"testuser"})
		cmd.SetArgs([]string{"testuser"})
		
		result, err := deleteUserLogic(mockClient, cmd)
		
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
	
	t.Run("renameUserLogic", func(t *testing.T) {
		mockClient := NewMockClientWrapper()
		cmd := &cobra.Command{}
		
		args := []string{"olduser", "newuser"}
		result, err := renameUserLogic(mockClient, cmd, args)
		
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
	
	t.Run("renameUserLogic with invalid new name", func(t *testing.T) {
		mockClient := NewMockClientWrapper()
		cmd := &cobra.Command{}
		
		// Test with invalid new username
		args := []string{"olduser", ""}
		_, err := renameUserLogic(mockClient, cmd, args)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be empty")
	})
}

// TestSetupUsersTableRefactored tests the table setup function
func TestSetupUsersTableRefactored(t *testing.T) {
	om := &OutputManager{}
	tr := NewTableRenderer(om)
	
	setupUsersTableRefactored(tr)
	
	// Check that columns were added
	assert.Equal(t, 5, len(tr.columns))
	assert.Equal(t, "ID", tr.columns[0].Header)
	assert.Equal(t, "Name", tr.columns[1].Header)
	assert.Equal(t, "Display Name", tr.columns[2].Header)
	assert.Equal(t, "Email", tr.columns[3].Header)
	assert.Equal(t, "Created", tr.columns[4].Header)
	
	// Test column extraction with mock data
	testUser := &v1.User{
		Id:          123,
		Name:        "testuser",
		DisplayName: "Test User",
		Email:       "test@example.com",
	}
	
	assert.Equal(t, "123", tr.columns[0].Extract(testUser))
	assert.Equal(t, "testuser", tr.columns[1].Extract(testUser))
	assert.Equal(t, "Test User", tr.columns[2].Extract(testUser))
	assert.Equal(t, "test@example.com", tr.columns[3].Extract(testUser))
}

// TestRefactoredCommandHierarchy tests the command hierarchy
func TestRefactoredCommandHierarchy(t *testing.T) {
	cmd := createRefactoredUserCommand()
	
	assert.NotNil(t, cmd)
	assert.Equal(t, "users-refactored", cmd.Use)
	assert.Equal(t, "Manage users using new infrastructure (demo)", cmd.Short)
	assert.Contains(t, cmd.Aliases, "ur")
	assert.True(t, cmd.Hidden, "Demo command should be hidden")
	
	// Check subcommands
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 4)
	
	subcommandNames := make([]string, len(subcommands))
	for i, subcmd := range subcommands {
		subcommandNames[i] = subcmd.Name()
	}
	
	assert.Contains(t, subcommandNames, "create")
	assert.Contains(t, subcommandNames, "list")
	assert.Contains(t, subcommandNames, "delete")
	assert.Contains(t, subcommandNames, "rename")
}

// TestRefactoredCommandValidation tests argument validation
func TestRefactoredCommandValidation(t *testing.T) {
	t.Run("create command args", func(t *testing.T) {
		cmd := createUserRefactored()
		
		// Should require exactly 1 argument
		err := cmd.Args(cmd, []string{})
		assert.Error(t, err)
		
		err = cmd.Args(cmd, []string{"user1"})
		assert.NoError(t, err)
		
		err = cmd.Args(cmd, []string{"user1", "extra"})
		assert.Error(t, err)
	})
	
	t.Run("delete command args", func(t *testing.T) {
		cmd := deleteUserRefactored()
		
		// Should require at least 1 argument
		err := cmd.Args(cmd, []string{})
		assert.Error(t, err)
		
		err = cmd.Args(cmd, []string{"user1"})
		assert.NoError(t, err)
	})
	
	t.Run("rename command args", func(t *testing.T) {
		cmd := renameUserRefactored()
		
		// Should require exactly 2 arguments
		err := cmd.Args(cmd, []string{})
		assert.Error(t, err)
		
		err = cmd.Args(cmd, []string{"oldname"})
		assert.Error(t, err)
		
		err = cmd.Args(cmd, []string{"oldname", "newname"})
		assert.NoError(t, err)
		
		err = cmd.Args(cmd, []string{"oldname", "newname", "extra"})
		assert.Error(t, err)
	})
}

// TestRefactoredCommandComparisonWithOriginal tests that refactored commands provide same functionality
func TestRefactoredCommandComparisonWithOriginal(t *testing.T) {
	t.Run("command structure compatibility", func(t *testing.T) {
		originalCreate := createUserCmd
		refactoredCreate := createUserRefactored()
		
		// Both should have the same basic structure
		assert.Equal(t, originalCreate.Short, refactoredCreate.Short)
		assert.Equal(t, originalCreate.Use, refactoredCreate.Use)
		
		// Both should have similar flags
		originalFlags := originalCreate.Flags()
		refactoredFlags := refactoredCreate.Flags()
		
		// Check key flags exist in both
		flagsToCheck := []string{"display-name", "email", "picture-url", "output"}
		for _, flagName := range flagsToCheck {
			originalFlag := originalFlags.Lookup(flagName)
			refactoredFlag := refactoredFlags.Lookup(flagName)
			
			if originalFlag != nil {
				assert.NotNil(t, refactoredFlag, "Flag %s should exist in refactored version", flagName)
				assert.Equal(t, originalFlag.Shorthand, refactoredFlag.Shorthand, "Flag %s shorthand should match", flagName)
			}
		}
	})
	
	t.Run("improved error handling", func(t *testing.T) {
		// Test that refactored version has better validation
		mockClient := NewMockClientWrapper()
		cmd := &cobra.Command{}
		
		// Test email validation improvement
		cmd.Flags().String("email", "invalid-email", "")
		args := []string{"testuser"}
		
		_, err := createUserLogic(mockClient, cmd, args)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid email")
		
		// Original version would not catch this until server call
		// Refactored version catches it early with better error message
	})
}

// BenchmarkRefactoredUserCommands benchmarks the refactored commands
func BenchmarkRefactoredUserCommands(b *testing.B) {
	mockClient := NewMockClientWrapper()
	cmd := &cobra.Command{}
	AddOutputFlag(cmd)
	
	b.Run("createUserLogic", func(b *testing.B) {
		args := []string{"testuser"}
		for i := 0; i < b.N; i++ {
			createUserLogic(mockClient, cmd, args)
		}
	})
	
	b.Run("listUsersLogic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			listUsersLogic(mockClient, cmd)
		}
	})
}