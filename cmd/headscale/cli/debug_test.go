package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDebugCommand(t *testing.T) {
	// Test that the debug command exists and is properly configured
	assert.NotNil(t, debugCmd)
	assert.Equal(t, "debug", debugCmd.Use)
	assert.Equal(t, "debug and testing commands", debugCmd.Short)
	assert.Equal(t, "debug contains extra commands used for debugging and testing headscale", debugCmd.Long)
}

func TestDebugCommandInRootCommand(t *testing.T) {
	// Test that debug is available as a subcommand of root
	cmd, _, err := rootCmd.Find([]string{"debug"})
	require.NoError(t, err)
	assert.Equal(t, "debug", cmd.Name())
	assert.Equal(t, debugCmd, cmd)
}

func TestCreateNodeCommand(t *testing.T) {
	// Test that the create-node command exists and is properly configured
	assert.NotNil(t, createNodeCmd)
	assert.Equal(t, "create-node", createNodeCmd.Use)
	assert.Equal(t, "Create a node that can be registered with `nodes register <>` command", createNodeCmd.Short)
	assert.NotNil(t, createNodeCmd.Run)
}

func TestCreateNodeCommandInDebugCommand(t *testing.T) {
	// Test that create-node is available as a subcommand of debug
	cmd, _, err := rootCmd.Find([]string{"debug", "create-node"})
	require.NoError(t, err)
	assert.Equal(t, "create-node", cmd.Name())
	assert.Equal(t, createNodeCmd, cmd)
}

func TestCreateNodeCommandFlags(t *testing.T) {
	// Test that create-node has the required flags

	// Test name flag
	nameFlag := createNodeCmd.Flags().Lookup("name")
	assert.NotNil(t, nameFlag)
	assert.Equal(t, "", nameFlag.Shorthand) // No shorthand for name
	assert.Equal(t, "", nameFlag.DefValue)

	// Test user flag
	userFlag := createNodeCmd.Flags().Lookup("user")
	assert.NotNil(t, userFlag)
	assert.Equal(t, "u", userFlag.Shorthand)

	// Test key flag
	keyFlag := createNodeCmd.Flags().Lookup("key")
	assert.NotNil(t, keyFlag)
	assert.Equal(t, "k", keyFlag.Shorthand)

	// Test route flag
	routeFlag := createNodeCmd.Flags().Lookup("route")
	assert.NotNil(t, routeFlag)
	assert.Equal(t, "r", routeFlag.Shorthand)

}

func TestCreateNodeCommandRequiredFlags(t *testing.T) {
	// Test that required flags are marked as required
	// We can't easily test the actual requirement enforcement without executing the command
	// But we can test that the flags exist and have the expected properties

	// These flags should be required based on the init() function
	requiredFlags := []string{"name", "user", "key"}

	for _, flagName := range requiredFlags {
		flag := createNodeCmd.Flags().Lookup(flagName)
		assert.NotNil(t, flag, "Required flag %s should exist", flagName)
	}
}

func TestErrorType(t *testing.T) {
	// Test the Error type implementation
	err := errPreAuthKeyMalformed
	assert.Equal(t, "key is malformed. expected 64 hex characters with `nodekey` prefix", err.Error())
	assert.Equal(t, "key is malformed. expected 64 hex characters with `nodekey` prefix", string(err))

	// Test that it implements the error interface
	var genericErr error = err
	assert.Equal(t, "key is malformed. expected 64 hex characters with `nodekey` prefix", genericErr.Error())
}

func TestErrorConstants(t *testing.T) {
	// Test that error constants are defined properly
	assert.Equal(t, Error("key is malformed. expected 64 hex characters with `nodekey` prefix"), errPreAuthKeyMalformed)
}

func TestDebugCommandStructure(t *testing.T) {
	// Test that debug has create-node as a subcommand
	found := false
	for _, subcmd := range debugCmd.Commands() {
		if subcmd.Name() == "create-node" {
			found = true
			break
		}
	}
	assert.True(t, found, "create-node should be a subcommand of debug")
}

func TestCreateNodeCommandHelp(t *testing.T) {
	// Test that the command has proper help text
	assert.NotEmpty(t, createNodeCmd.Short)
	assert.Contains(t, createNodeCmd.Short, "Create a node")
	assert.Contains(t, createNodeCmd.Short, "nodes register")
}

func TestCreateNodeCommandFlagDescriptions(t *testing.T) {
	// Test that flags have appropriate usage descriptions
	nameFlag := createNodeCmd.Flags().Lookup("name")
	assert.Equal(t, "Name", nameFlag.Usage)

	userFlag := createNodeCmd.Flags().Lookup("user")
	assert.Equal(t, "User", userFlag.Usage)

	keyFlag := createNodeCmd.Flags().Lookup("key")
	assert.Equal(t, "Key", keyFlag.Usage)

	routeFlag := createNodeCmd.Flags().Lookup("route")
	assert.Contains(t, routeFlag.Usage, "routes to advertise")

}

// Note: We can't easily test the actual execution of create-node because:
// 1. It depends on gRPC client configuration
// 2. It calls SuccessOutput/ErrorOutput which exit the process
// 3. It requires valid registration keys and user setup
//
// In a real refactor, we would:
// 1. Extract the business logic to testable functions
// 2. Use dependency injection for the gRPC client
// 3. Return errors instead of calling ErrorOutput/SuccessOutput
// 4. Add validation functions that can be tested independently
//
// For now, we test the command structure and flag configuration.
