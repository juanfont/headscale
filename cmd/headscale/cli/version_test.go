package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionCommand(t *testing.T) {
	// Test that version command exists
	assert.NotNil(t, versionCmd)
	assert.Equal(t, "version", versionCmd.Use)
	assert.Equal(t, "Print the version.", versionCmd.Short)
	assert.Equal(t, "The version of headscale.", versionCmd.Long)
}

func TestVersionCommandStructure(t *testing.T) {
	// Test command is properly added to root
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use == "version" {
			found = true
			break
		}
	}
	assert.True(t, found, "version command should be added to root command")
}

func TestVersionCommandFlags(t *testing.T) {
	// Version command should inherit output flag from root as persistent flag
	outputFlag := versionCmd.Flag("output")
	if outputFlag == nil {
		// Try persistent flags from root
		outputFlag = rootCmd.PersistentFlags().Lookup("output")
	}
	assert.NotNil(t, outputFlag, "version command should have access to output flag")
}

func TestVersionCommandRun(t *testing.T) {
	// Test that Run function is set
	assert.NotNil(t, versionCmd.Run)

	// We can't easily test the actual execution without mocking SuccessOutput
	// but we can verify the function exists and has the right signature
}
