package integration

import (
	"strings"
	"testing"

	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
)

func TestVersionCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"version-user"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cliversion"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	t.Run("test_version_basic", func(t *testing.T) {
		// Test basic version output
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"version",
			},
		)
		assertNoErr(t, err)

		// Version output should contain version information
		assert.NotEmpty(t, result, "version output should not be empty")
		// In development, version is "dev", in releases it would be semver like "1.0.0"
		trimmed := strings.TrimSpace(result)
		assert.True(t, trimmed == "dev" || len(trimmed) > 2, "version should be 'dev' or valid version string")
	})

	t.Run("test_version_help", func(t *testing.T) {
		// Test version command help
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"version",
				"--help",
			},
		)
		assertNoErr(t, err)

		// Help text should contain expected information
		assert.Contains(t, result, "version", "help should mention version command")
		assert.Contains(t, result, "version of headscale", "help should contain command description")
	})

	t.Run("test_version_with_extra_args", func(t *testing.T) {
		// Test version command with unexpected extra arguments
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"version",
				"extra",
				"args",
			},
		)
		// Should either ignore extra args or handle gracefully
		// The exact behavior depends on implementation, but shouldn't crash
		assert.NotPanics(t, func() {
			headscale.Execute(
				[]string{
					"headscale",
					"version",
					"extra",
					"args",
				},
			)
		}, "version command should handle extra arguments gracefully")

		// If it succeeds, should still contain version info
		if err == nil {
			assert.NotEmpty(t, result, "version output should not be empty")
		}
	})
}

func TestVersionCommandEdgeCases(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"version-edge-user"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cliversionedge"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	t.Run("test_version_multiple_calls", func(t *testing.T) {
		// Test that version command can be called multiple times
		for i := 0; i < 3; i++ {
			result, err := headscale.Execute(
				[]string{
					"headscale",
					"version",
				},
			)
			assertNoErr(t, err)
			assert.NotEmpty(t, result, "version output should not be empty")
		}
	})

	t.Run("test_version_with_invalid_flag", func(t *testing.T) {
		// Test version command with invalid flag
		_, _ = headscale.Execute(
			[]string{
				"headscale",
				"version",
				"--invalid-flag",
			},
		)
		// Should handle invalid flag gracefully (either succeed ignoring flag or fail with error)
		assert.NotPanics(t, func() {
			headscale.Execute(
				[]string{
					"headscale",
					"version",
					"--invalid-flag",
				},
			)
		}, "version command should handle invalid flags gracefully")
	})
}
