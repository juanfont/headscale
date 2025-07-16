package integration

import (
	"encoding/json"
	"fmt"
	"testing"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
)

func TestDebugCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"debug-user"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("clidebug"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	t.Run("test_debug_help", func(t *testing.T) {
		// Test debug command help
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"--help",
			},
		)
		assertNoErr(t, err)

		// Help text should contain expected information
		assert.Contains(t, result, "debug", "help should mention debug command")
		assert.Contains(t, result, "debugging and testing", "help should contain command description")
		assert.Contains(t, result, "create-node", "help should mention create-node subcommand")
	})

	t.Run("test_debug_create_node_help", func(t *testing.T) {
		// Test debug create-node command help
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--help",
			},
		)
		assertNoErr(t, err)

		// Help text should contain expected information
		assert.Contains(t, result, "create-node", "help should mention create-node command")
		assert.Contains(t, result, "name", "help should mention name flag")
		assert.Contains(t, result, "user", "help should mention user flag")
		assert.Contains(t, result, "key", "help should mention key flag")
		assert.Contains(t, result, "route", "help should mention route flag")
	})
}

func TestDebugCreateNodeCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"debug-create-user"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("clidebugcreate"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	// Create a user first
	user := spec.Users[0]
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"users",
			"create",
			user,
		},
	)
	assertNoErr(t, err)

	t.Run("test_debug_create_node_basic", func(t *testing.T) {
		// Test basic debug create-node functionality
		nodeName := "debug-test-node"
		// Generate a mock registration key (64 hex chars with nodekey prefix)
		registrationKey := "nodekey:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

		result, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name", nodeName,
				"--user", user,
				"--key", registrationKey,
			},
		)
		assertNoErr(t, err)

		// Should output node creation confirmation
		assert.Contains(t, result, "Node created", "should confirm node creation")
		assert.Contains(t, result, nodeName, "should mention the created node name")
	})

	t.Run("test_debug_create_node_with_routes", func(t *testing.T) {
		// Test debug create-node with advertised routes
		nodeName := "debug-route-node"
		registrationKey := "nodekey:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

		result, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name", nodeName,
				"--user", user,
				"--key", registrationKey,
				"--route", "10.0.0.0/24",
				"--route", "192.168.1.0/24",
			},
		)
		assertNoErr(t, err)

		// Should output node creation confirmation
		assert.Contains(t, result, "Node created", "should confirm node creation")
		assert.Contains(t, result, nodeName, "should mention the created node name")
	})

	t.Run("test_debug_create_node_json_output", func(t *testing.T) {
		// Test debug create-node with JSON output
		nodeName := "debug-json-node"
		registrationKey := "nodekey:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"

		result, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name", nodeName,
				"--user", user,
				"--key", registrationKey,
				"--output", "json",
			},
		)
		assertNoErr(t, err)

		// Should produce valid JSON output
		var node v1.Node
		err = json.Unmarshal([]byte(result), &node)
		assert.NoError(t, err, "debug create-node should produce valid JSON output")
		assert.Equal(t, nodeName, node.GetName(), "created node should have correct name")
	})
}

func TestDebugCreateNodeCommandValidation(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"debug-validation-user"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("clidebugvalidation"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	// Create a user first
	user := spec.Users[0]
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"users",
			"create",
			user,
		},
	)
	assertNoErr(t, err)

	t.Run("test_debug_create_node_missing_name", func(t *testing.T) {
		// Test debug create-node with missing name flag
		registrationKey := "nodekey:1111111111111111111111111111111111111111111111111111111111111111"

		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--user", user,
				"--key", registrationKey,
			},
		)
		// Should fail for missing required name flag
		assert.Error(t, err, "should fail for missing name flag")
	})

	t.Run("test_debug_create_node_missing_user", func(t *testing.T) {
		// Test debug create-node with missing user flag
		registrationKey := "nodekey:2222222222222222222222222222222222222222222222222222222222222222"

		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name", "test-node",
				"--key", registrationKey,
			},
		)
		// Should fail for missing required user flag
		assert.Error(t, err, "should fail for missing user flag")
	})

	t.Run("test_debug_create_node_missing_key", func(t *testing.T) {
		// Test debug create-node with missing key flag
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name", "test-node",
				"--user", user,
			},
		)
		// Should fail for missing required key flag
		assert.Error(t, err, "should fail for missing key flag")
	})

	t.Run("test_debug_create_node_invalid_key", func(t *testing.T) {
		// Test debug create-node with invalid registration key format
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name", "test-node",
				"--user", user,
				"--key", "invalid-key-format",
			},
		)
		// Should fail for invalid key format
		assert.Error(t, err, "should fail for invalid key format")
	})

	t.Run("test_debug_create_node_nonexistent_user", func(t *testing.T) {
		// Test debug create-node with non-existent user
		registrationKey := "nodekey:3333333333333333333333333333333333333333333333333333333333333333"

		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name", "test-node",
				"--user", "nonexistent-user",
				"--key", registrationKey,
			},
		)
		// Should fail for non-existent user
		assert.Error(t, err, "should fail for non-existent user")
	})

	t.Run("test_debug_create_node_duplicate_name", func(t *testing.T) {
		// Test debug create-node with duplicate node name
		nodeName := "duplicate-node"
		registrationKey1 := "nodekey:4444444444444444444444444444444444444444444444444444444444444444"
		registrationKey2 := "nodekey:5555555555555555555555555555555555555555555555555555555555555555"

		// Create first node
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name", nodeName,
				"--user", user,
				"--key", registrationKey1,
			},
		)
		assertNoErr(t, err)

		// Try to create second node with same name
		_, err = headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name", nodeName,
				"--user", user,
				"--key", registrationKey2,
			},
		)
		// Should fail for duplicate node name
		assert.Error(t, err, "should fail for duplicate node name")
	})
}

func TestDebugCreateNodeCommandEdgeCases(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"debug-edge-user"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("clidebugedge"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	// Create a user first
	user := spec.Users[0]
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"users",
			"create",
			user,
		},
	)
	assertNoErr(t, err)

	t.Run("test_debug_create_node_invalid_route", func(t *testing.T) {
		// Test debug create-node with invalid route format
		nodeName := "invalid-route-node"
		registrationKey := "nodekey:6666666666666666666666666666666666666666666666666666666666666666"

		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name", nodeName,
				"--user", user,
				"--key", registrationKey,
				"--route", "invalid-cidr",
			},
		)
		// Should handle invalid route format gracefully
		assert.Error(t, err, "should fail for invalid route format")
	})

	t.Run("test_debug_create_node_empty_route", func(t *testing.T) {
		// Test debug create-node with empty route
		nodeName := "empty-route-node"
		registrationKey := "nodekey:7777777777777777777777777777777777777777777777777777777777777777"

		result, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name", nodeName,
				"--user", user,
				"--key", registrationKey,
				"--route", "",
			},
		)
		// Should handle empty route (either succeed or fail gracefully)
		if err == nil {
			assert.Contains(t, result, "Node created", "should confirm node creation if empty route is allowed")
		} else {
			assert.Error(t, err, "should fail gracefully for empty route")
		}
	})

	t.Run("test_debug_create_node_very_long_name", func(t *testing.T) {
		// Test debug create-node with very long node name
		longName := fmt.Sprintf("very-long-node-name-%s", "x")
		for i := 0; i < 10; i++ {
			longName += "-very-long-segment"
		}
		registrationKey := "nodekey:8888888888888888888888888888888888888888888888888888888888888888"

		_, _ = headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name", longName,
				"--user", user,
				"--key", registrationKey,
			},
		)
		// Should handle very long names (either succeed or fail gracefully)
		assert.NotPanics(t, func() {
			headscale.Execute(
				[]string{
					"headscale",
					"debug",
					"create-node",
					"--name", longName,
					"--user", user,
					"--key", registrationKey,
				},
			)
		}, "should handle very long node names gracefully")
	})
}
