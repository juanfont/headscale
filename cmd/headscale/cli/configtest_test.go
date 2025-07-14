package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigTestCommand(t *testing.T) {
	// Test that the configtest command exists and is properly configured
	assert.NotNil(t, configTestCmd)
	assert.Equal(t, "configtest", configTestCmd.Use)
	assert.Equal(t, "Test the configuration.", configTestCmd.Short)
	assert.Equal(t, "Run a test of the configuration and exit.", configTestCmd.Long)
	assert.NotNil(t, configTestCmd.Run)
}

func TestConfigTestCommandInRootCommand(t *testing.T) {
	// Test that configtest is available as a subcommand of root
	cmd, _, err := rootCmd.Find([]string{"configtest"})
	require.NoError(t, err)
	assert.Equal(t, "configtest", cmd.Name())
	assert.Equal(t, configTestCmd, cmd)
}

func TestConfigTestCommandHelp(t *testing.T) {
	// Test that the command has proper help text
	assert.NotEmpty(t, configTestCmd.Short)
	assert.NotEmpty(t, configTestCmd.Long)
	assert.Contains(t, configTestCmd.Short, "configuration")
	assert.Contains(t, configTestCmd.Long, "test")
	assert.Contains(t, configTestCmd.Long, "configuration")
}

// Note: We can't easily test the actual execution of configtest because:
// 1. It depends on configuration files being present
// 2. It calls log.Fatal() which would exit the test process
// 3. It tries to initialize a full Headscale server
// 
// In a real refactor, we would:
// 1. Extract the configuration validation logic to a testable function
// 2. Return errors instead of calling log.Fatal()
// 3. Accept configuration as a parameter instead of loading from global state
//
// For now, we test the command structure and that it's properly wired up.