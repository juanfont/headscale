package integration

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
)

func TestGenerateCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"generate-user"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cligenerate"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	t.Run("test_generate_help", func(t *testing.T) {
		// Test generate command help
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"generate",
				"--help",
			},
		)
		assertNoErr(t, err)

		// Help text should contain expected information
		assert.Contains(t, result, "generate", "help should mention generate command")
		assert.Contains(t, result, "Generate commands", "help should contain command description")
		assert.Contains(t, result, "private-key", "help should mention private-key subcommand")
	})

	t.Run("test_generate_alias", func(t *testing.T) {
		// Test generate command alias (gen)
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"gen",
				"--help",
			},
		)
		assertNoErr(t, err)

		// Should work with alias
		assert.Contains(t, result, "generate", "alias should work and show generate help")
		assert.Contains(t, result, "private-key", "alias help should mention private-key subcommand")
	})

	t.Run("test_generate_private_key_help", func(t *testing.T) {
		// Test generate private-key command help
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"generate",
				"private-key",
				"--help",
			},
		)
		assertNoErr(t, err)

		// Help text should contain expected information
		assert.Contains(t, result, "private-key", "help should mention private-key command")
		assert.Contains(t, result, "Generate a private key", "help should contain command description")
	})
}

func TestGeneratePrivateKeyCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"generate-key-user"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cligenkey"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	t.Run("test_generate_private_key_basic", func(t *testing.T) {
		// Test basic private key generation
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"generate",
				"private-key",
			},
		)
		assertNoErr(t, err)

		// Should output a private key
		assert.NotEmpty(t, result, "private key generation should produce output")

		// Private key should start with expected prefix
		trimmed := strings.TrimSpace(result)
		assert.True(t, strings.HasPrefix(trimmed, "privkey:"),
			"private key should start with 'privkey:' prefix, got: %s", trimmed)

		// Should be reasonable length (64+ hex characters after prefix)
		assert.True(t, len(trimmed) > 70,
			"private key should be reasonable length, got length: %d", len(trimmed))
	})

	t.Run("test_generate_private_key_json", func(t *testing.T) {
		// Test private key generation with JSON output
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"generate",
				"private-key",
				"--output", "json",
			},
		)
		assertNoErr(t, err)

		// Should produce valid JSON output
		var keyData map[string]interface{}
		err = json.Unmarshal([]byte(result), &keyData)
		assert.NoError(t, err, "private key generation should produce valid JSON output")

		// Should contain private_key field
		privateKey, exists := keyData["private_key"]
		assert.True(t, exists, "JSON output should contain 'private_key' field")
		assert.NotEmpty(t, privateKey, "private_key field should not be empty")

		// Private key should be a string with correct format
		privateKeyStr, ok := privateKey.(string)
		assert.True(t, ok, "private_key should be a string")
		assert.True(t, strings.HasPrefix(privateKeyStr, "privkey:"),
			"private key should start with 'privkey:' prefix")
	})

	t.Run("test_generate_private_key_yaml", func(t *testing.T) {
		// Test private key generation with YAML output
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"generate",
				"private-key",
				"--output", "yaml",
			},
		)
		assertNoErr(t, err)

		// Should produce YAML output
		assert.NotEmpty(t, result, "YAML output should not be empty")
		assert.Contains(t, result, "private_key:", "YAML output should contain private_key field")
		assert.Contains(t, result, "privkey:", "YAML output should contain private key with correct prefix")
	})

	t.Run("test_generate_private_key_multiple_calls", func(t *testing.T) {
		// Test that multiple calls generate different keys
		var keys []string

		for i := 0; i < 3; i++ {
			result, err := headscale.Execute(
				[]string{
					"headscale",
					"generate",
					"private-key",
				},
			)
			assertNoErr(t, err)

			trimmed := strings.TrimSpace(result)
			keys = append(keys, trimmed)
			assert.True(t, strings.HasPrefix(trimmed, "privkey:"),
				"each generated private key should have correct prefix")
		}

		// All keys should be different
		assert.NotEqual(t, keys[0], keys[1], "generated keys should be different")
		assert.NotEqual(t, keys[1], keys[2], "generated keys should be different")
		assert.NotEqual(t, keys[0], keys[2], "generated keys should be different")
	})
}

func TestGeneratePrivateKeyCommandValidation(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"generate-validation-user"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cligenvalidation"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	t.Run("test_generate_private_key_with_extra_args", func(t *testing.T) {
		// Test private key generation with unexpected extra arguments
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"generate",
				"private-key",
				"extra",
				"args",
			},
		)

		// Should either succeed (ignoring extra args) or fail gracefully
		if err == nil {
			// If successful, should still produce valid key
			trimmed := strings.TrimSpace(result)
			assert.True(t, strings.HasPrefix(trimmed, "privkey:"),
				"should produce valid private key even with extra args")
		} else {
			// If failed, should be a reasonable error, not a panic
			assert.NotContains(t, err.Error(), "panic", "should not panic on extra arguments")
		}
	})

	t.Run("test_generate_private_key_invalid_output_format", func(t *testing.T) {
		// Test private key generation with invalid output format
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"generate",
				"private-key",
				"--output", "invalid-format",
			},
		)

		// Should handle invalid output format gracefully
		// Might succeed with default format or fail gracefully
		if err == nil {
			assert.NotEmpty(t, result, "should produce some output even with invalid format")
		} else {
			assert.NotContains(t, err.Error(), "panic", "should not panic on invalid output format")
		}
	})

	t.Run("test_generate_private_key_with_config_flag", func(t *testing.T) {
		// Test that private key generation works with config flag
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"--config", "/etc/headscale/config.yaml",
				"generate",
				"private-key",
			},
		)
		assertNoErr(t, err)

		// Should still generate valid private key
		trimmed := strings.TrimSpace(result)
		assert.True(t, strings.HasPrefix(trimmed, "privkey:"),
			"should generate valid private key with config flag")
	})
}

func TestGenerateCommandEdgeCases(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"generate-edge-user"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cligenedge"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	t.Run("test_generate_without_subcommand", func(t *testing.T) {
		// Test generate command without subcommand
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"generate",
			},
		)

		// Should show help or list available subcommands
		if err == nil {
			assert.Contains(t, result, "private-key", "should show available subcommands")
		} else {
			// If it errors, should be a usage error, not a crash
			assert.NotContains(t, err.Error(), "panic", "should not panic when no subcommand provided")
		}
	})

	t.Run("test_generate_nonexistent_subcommand", func(t *testing.T) {
		// Test generate command with non-existent subcommand
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"generate",
				"nonexistent-command",
			},
		)

		// Should fail gracefully for non-existent subcommand
		assert.Error(t, err, "should fail for non-existent subcommand")
		if err != nil {
			assert.NotContains(t, err.Error(), "panic", "should not panic on non-existent subcommand")
		}
	})

	t.Run("test_generate_key_format_consistency", func(t *testing.T) {
		// Test that generated keys are consistently formatted
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"generate",
				"private-key",
			},
		)
		assertNoErr(t, err)

		trimmed := strings.TrimSpace(result)

		// Check format consistency
		assert.True(t, strings.HasPrefix(trimmed, "privkey:"),
			"private key should start with 'privkey:' prefix")

		// Should be hex characters after prefix
		keyPart := strings.TrimPrefix(trimmed, "privkey:")
		assert.True(t, len(keyPart) == 64,
			"private key should be 64 hex characters after prefix, got length: %d", len(keyPart))

		// Should only contain valid hex characters
		for _, char := range keyPart {
			assert.True(t,
				(char >= '0' && char <= '9') ||
					(char >= 'a' && char <= 'f') ||
					(char >= 'A' && char <= 'F'),
				"private key should only contain hex characters, found: %c", char)
		}
	})

	t.Run("test_generate_alias_consistency", func(t *testing.T) {
		// Test that 'gen' alias produces same results as 'generate'
		result1, err1 := headscale.Execute(
			[]string{
				"headscale",
				"generate",
				"private-key",
			},
		)
		assertNoErr(t, err1)

		result2, err2 := headscale.Execute(
			[]string{
				"headscale",
				"gen",
				"private-key",
			},
		)
		assertNoErr(t, err2)

		// Both should produce valid keys (though different values)
		trimmed1 := strings.TrimSpace(result1)
		trimmed2 := strings.TrimSpace(result2)

		assert.True(t, strings.HasPrefix(trimmed1, "privkey:"),
			"generate command should produce valid key")
		assert.True(t, strings.HasPrefix(trimmed2, "privkey:"),
			"gen alias should produce valid key")

		// Keys should be different (they're randomly generated)
		assert.NotEqual(t, trimmed1, trimmed2,
			"different calls should produce different keys")
	})
}
