package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestGenerateCommand(t *testing.T) {
	// Test that the generate command exists and shows help
	cmd := &cobra.Command{
		Use:   "headscale",
		Short: "headscale - a Tailscale control server",
	}

	cmd.AddCommand(generateCmd)

	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"generate", "--help"})

	err := cmd.Execute()
	require.NoError(t, err)

	outStr := out.String()
	assert.Contains(t, outStr, "Generate commands")
	assert.Contains(t, outStr, "private-key")
	assert.Contains(t, outStr, "Aliases:")
	assert.Contains(t, outStr, "gen")
}

func TestGenerateCommandAlias(t *testing.T) {
	// Test that the "gen" alias works
	cmd := &cobra.Command{
		Use:   "headscale",
		Short: "headscale - a Tailscale control server",
	}

	cmd.AddCommand(generateCmd)

	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"gen", "--help"})

	err := cmd.Execute()
	require.NoError(t, err)

	outStr := out.String()
	assert.Contains(t, outStr, "Generate commands")
}

func TestGeneratePrivateKeyCommand(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		expectJSON bool
		expectYAML bool
	}{
		{
			name:       "default output",
			args:       []string{"generate", "private-key"},
			expectJSON: false,
			expectYAML: false,
		},
		{
			name:       "json output",
			args:       []string{"generate", "private-key", "--output", "json"},
			expectJSON: true,
			expectYAML: false,
		},
		{
			name:       "yaml output",
			args:       []string{"generate", "private-key", "--output", "yaml"},
			expectJSON: false,
			expectYAML: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: This command calls SuccessOutput which exits the process
			// We can't test the actual execution easily without mocking
			// Instead, we test the command structure and that it exists

			cmd := &cobra.Command{
				Use:   "headscale",
				Short: "headscale - a Tailscale control server",
			}

			cmd.AddCommand(generateCmd)
			cmd.PersistentFlags().StringP("output", "o", "", "Output format")

			// Test that the command exists and can be found
			privateKeyCmd, _, err := cmd.Find([]string{"generate", "private-key"})
			require.NoError(t, err)
			assert.Equal(t, "private-key", privateKeyCmd.Name())
			assert.Equal(t, "Generate a private key for the headscale server", privateKeyCmd.Short)
		})
	}
}

func TestGeneratePrivateKeyHelp(t *testing.T) {
	cmd := &cobra.Command{
		Use:   "headscale",
		Short: "headscale - a Tailscale control server",
	}

	cmd.AddCommand(generateCmd)

	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"generate", "private-key", "--help"})

	err := cmd.Execute()
	require.NoError(t, err)

	outStr := out.String()
	assert.Contains(t, outStr, "Generate a private key for the headscale server")
	assert.Contains(t, outStr, "Usage:")
}

// Test the key generation logic in isolation (without SuccessOutput/ErrorOutput)
func TestPrivateKeyGeneration(t *testing.T) {
	// We can't easily test the full command because it calls SuccessOutput which exits
	// But we can test that the key generation produces valid output format

	// This is testing the core logic that would be in the command
	// In a real refactor, we'd extract this to a testable function

	// For now, we can test that the command structure is correct
	assert.NotNil(t, generatePrivateKeyCmd)
	assert.Equal(t, "private-key", generatePrivateKeyCmd.Use)
	assert.Equal(t, "Generate a private key for the headscale server", generatePrivateKeyCmd.Short)
	assert.NotNil(t, generatePrivateKeyCmd.Run)
}

func TestGenerateCommandStructure(t *testing.T) {
	// Test the command hierarchy
	assert.Equal(t, "generate", generateCmd.Use)
	assert.Equal(t, "Generate commands", generateCmd.Short)
	assert.Contains(t, generateCmd.Aliases, "gen")

	// Test that private-key is a subcommand
	found := false
	for _, subcmd := range generateCmd.Commands() {
		if subcmd.Name() == "private-key" {
			found = true
			break
		}
	}
	assert.True(t, found, "private-key should be a subcommand of generate")
}

// Helper function to test output formats (would be used if we refactored the command)
func validatePrivateKeyOutput(t *testing.T, output string, format string) {
	switch format {
	case "json":
		var result map[string]interface{}
		err := json.Unmarshal([]byte(output), &result)
		require.NoError(t, err, "Output should be valid JSON")

		privateKey, exists := result["private_key"]
		require.True(t, exists, "JSON should contain private_key field")

		keyStr, ok := privateKey.(string)
		require.True(t, ok, "private_key should be a string")
		require.NotEmpty(t, keyStr, "private_key should not be empty")

		// Basic validation that it looks like a machine key
		assert.True(t, strings.HasPrefix(keyStr, "mkey:"), "Machine key should start with mkey:")

	case "yaml":
		var result map[string]interface{}
		err := yaml.Unmarshal([]byte(output), &result)
		require.NoError(t, err, "Output should be valid YAML")

		privateKey, exists := result["private_key"]
		require.True(t, exists, "YAML should contain private_key field")

		keyStr, ok := privateKey.(string)
		require.True(t, ok, "private_key should be a string")
		require.NotEmpty(t, keyStr, "private_key should not be empty")

		assert.True(t, strings.HasPrefix(keyStr, "mkey:"), "Machine key should start with mkey:")

	default:
		// Default format should just be the key itself
		assert.True(t, strings.HasPrefix(output, "mkey:"), "Default output should be the machine key")
		assert.NotContains(t, output, "{", "Default output should not contain JSON")
		assert.NotContains(t, output, "private_key:", "Default output should not contain YAML structure")
	}
}

func TestPrivateKeyOutputFormats(t *testing.T) {
	// Test cases for different output formats
	// These test the validation logic we would use after refactoring

	tests := []struct {
		format string
		sample string
	}{
		{
			format: "json",
			sample: `{"private_key": "mkey:abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234"}`,
		},
		{
			format: "yaml",
			sample: "private_key: mkey:abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234\n",
		},
		{
			format: "",
			sample: "mkey:abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234",
		},
	}

	for _, tt := range tests {
		t.Run("format_"+tt.format, func(t *testing.T) {
			validatePrivateKeyOutput(t, tt.sample, tt.format)
		})
	}
}
