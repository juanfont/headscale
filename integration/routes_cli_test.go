package integration

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRouteCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users:        []string{"route-user"},
		NodesPerUser: 1,
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{tsic.WithAcceptRoutes()},
		hsic.WithTestName("cliroutes"),
	)
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	// Wait for setup to complete
	err = scenario.WaitForTailscaleSync()
	assertNoErr(t, err)

	// Wait for node to be registered
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var listNodes []*v1.Node
		err := executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--output",
				"json",
			},
			&listNodes,
		)
		assert.NoError(c, err)
		assert.Len(c, listNodes, 1)
	}, 30*time.Second, 1*time.Second)

	// Get the node ID for route operations
	var listNodes []*v1.Node
	err = executeAndUnmarshal(headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--output",
			"json",
		},
		&listNodes,
	)
	assertNoErr(t, err)
	require.Len(t, listNodes, 1)
	nodeID := listNodes[0].GetId()

	t.Run("test_route_advertisement", func(t *testing.T) {
		// Get the first tailscale client
		allClients, err := scenario.ListTailscaleClients()
		assertNoErr(t, err)
		require.NotEmpty(t, allClients, "should have at least one client")
		client := allClients[0]

		// Advertise a route
		_, _, err = client.Execute([]string{
			"tailscale",
			"set",
			"--advertise-routes=10.0.0.0/24",
		})
		assertNoErr(t, err)

		// Wait for route to appear in Headscale
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			var updatedNodes []*v1.Node
			err := executeAndUnmarshal(headscale,
				[]string{
					"headscale",
					"nodes",
					"list",
					"--output",
					"json",
				},
				&updatedNodes,
			)
			assert.NoError(c, err)
			assert.Len(c, updatedNodes, 1)
			assert.Greater(c, len(updatedNodes[0].GetAvailableRoutes()), 0, "node should have available routes")
		}, 30*time.Second, 1*time.Second)
	})

	t.Run("test_route_approval", func(t *testing.T) {
		// List available routes
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"nodes",
				"list-routes",
				"--identifier",
				fmt.Sprintf("%d", nodeID),
			},
		)
		assertNoErr(t, err)

		// Approve a route
		_, err = headscale.Execute(
			[]string{
				"headscale",
				"nodes",
				"approve-routes",
				"--identifier",
				fmt.Sprintf("%d", nodeID),
				"--routes",
				"10.0.0.0/24",
			},
		)
		assertNoErr(t, err)

		// Verify route is approved
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			var updatedNodes []*v1.Node
			err := executeAndUnmarshal(headscale,
				[]string{
					"headscale",
					"nodes",
					"list",
					"--output",
					"json",
				},
				&updatedNodes,
			)
			assert.NoError(c, err)
			assert.Len(c, updatedNodes, 1)
			assert.Contains(c, updatedNodes[0].GetApprovedRoutes(), "10.0.0.0/24", "route should be approved")
		}, 30*time.Second, 1*time.Second)
	})

	t.Run("test_route_removal", func(t *testing.T) {
		// Remove approved routes
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"nodes",
				"approve-routes",
				"--identifier",
				fmt.Sprintf("%d", nodeID),
				"--routes",
				"", // Empty string removes all routes
			},
		)
		assertNoErr(t, err)

		// Verify routes are removed
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			var updatedNodes []*v1.Node
			err := executeAndUnmarshal(headscale,
				[]string{
					"headscale",
					"nodes",
					"list",
					"--output",
					"json",
				},
				&updatedNodes,
			)
			assert.NoError(c, err)
			assert.Len(c, updatedNodes, 1)
			assert.Empty(c, updatedNodes[0].GetApprovedRoutes(), "approved routes should be empty")
		}, 30*time.Second, 1*time.Second)
	})

	t.Run("test_route_json_output", func(t *testing.T) {
		// Test JSON output for route commands
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"nodes",
				"list-routes",
				"--identifier",
				fmt.Sprintf("%d", nodeID),
				"--output",
				"json",
			},
		)
		assertNoErr(t, err)

		// Verify JSON output is valid
		var routes interface{}
		err = json.Unmarshal([]byte(result), &routes)
		assert.NoError(t, err, "route command should produce valid JSON output")
	})
}

func TestRouteCommandEdgeCases(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"route-test-user"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cliroutesedge"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	t.Run("test_route_commands_with_invalid_node", func(t *testing.T) {
		// Test route commands with non-existent node ID
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"nodes",
				"list-routes",
				"--identifier",
				"999999",
			},
		)
		// Should handle error gracefully
		assert.Error(t, err, "should fail for non-existent node")
	})

	t.Run("test_route_approval_invalid_routes", func(t *testing.T) {
		// Test route approval with invalid CIDR
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"nodes",
				"approve-routes",
				"--identifier",
				"1",
				"--routes",
				"invalid-cidr",
			},
		)
		// Should handle invalid CIDR gracefully
		assert.Error(t, err, "should fail for invalid CIDR")
	})
}

func TestRouteCommandHelp(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"help-user"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cliroutehelp"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	t.Run("test_list_routes_help", func(t *testing.T) {
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"nodes",
				"list-routes",
				"--help",
			},
		)
		assertNoErr(t, err)
		
		// Verify help text contains expected information
		assert.Contains(t, result, "list-routes", "help should mention list-routes command")
		assert.Contains(t, result, "identifier", "help should mention identifier flag")
	})

	t.Run("test_approve_routes_help", func(t *testing.T) {
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"nodes",
				"approve-routes",
				"--help",
			},
		)
		assertNoErr(t, err)
		
		// Verify help text contains expected information
		assert.Contains(t, result, "approve-routes", "help should mention approve-routes command")
		assert.Contains(t, result, "identifier", "help should mention identifier flag")
		assert.Contains(t, result, "routes", "help should mention routes flag")
	})
}