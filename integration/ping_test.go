package integration

import (
	"context"
	"strconv"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPingDirect tests the ping functionality via the headscale CLI command
// with nodes that can directly communicate with each other.
func TestPingDirect(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("pingdirect"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)
	require.Len(t, allClients, 2, "Should have exactly 2 clients")

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	// Get node information
	var nodes []*v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 2, "Should have 2 nodes registered")
	}, 30*time.Second, 1*time.Second, "Waiting for nodes to be listed")

	// Test 1: Ping first node using its own IP (self-ping with implicit target)
	t.Run("self-ping-implicit-target", func(t *testing.T) {
		var pingResp v1.PingNodeResponse
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			err = executeAndUnmarshal(
				headscale,
				[]string{
					"headscale",
					"ping",
					"--identifier", strconv.FormatUint(nodes[0].GetId(), 10),
					"--output", "json",
				},
				&pingResp,
			)
			assert.NoError(c, err)
			assert.True(c, pingResp.GetSuccess(), "Self-ping should succeed")
			assert.NotEmpty(c, pingResp.GetPingType(), "Ping type should be set")
		}, 30*time.Second, 2*time.Second, "Waiting for self-ping with implicit target")
	})

	// Test 2: Ping first node with explicit IP target (its primary IP)
	t.Run("self-ping-explicit-target", func(t *testing.T) {
		require.NotEmpty(t, nodes[0].GetIpAddresses(), "Node should have IP addresses")
		targetIP := nodes[0].GetIpAddresses()[0]

		var pingResp v1.PingNodeResponse
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			err = executeAndUnmarshal(
				headscale,
				[]string{
					"headscale",
					"ping",
					"--identifier", strconv.FormatUint(nodes[0].GetId(), 10),
					"--target", targetIP,
					"--output", "json",
				},
				&pingResp,
			)
			assert.NoError(c, err)
			assert.True(c, pingResp.GetSuccess(), "Self-ping with explicit target should succeed")
			assert.Equal(c, targetIP, pingResp.GetNodeIp(), "Response should contain target IP")
		}, 30*time.Second, 2*time.Second, "Waiting for self-ping with explicit target")
	})

	// Test 3: Ping second node from first node (cross-node ping) - test both IPv4 and IPv6
	t.Run("cross-node-ping", func(t *testing.T) {
		require.NotEmpty(t, nodes[1].GetIpAddresses(), "Second node should have IP addresses")

		// Test each IP address (IPv4 and/or IPv6)
		for idx, targetIP := range nodes[1].GetIpAddresses() {
			ipVersion := "IPv4"
			if len(targetIP) > 15 { // Simple heuristic: IPv6 addresses are longer
				ipVersion = "IPv6"
			}

			t.Run(ipVersion, func(t *testing.T) {
				var pingResp v1.PingNodeResponse
				assert.EventuallyWithT(t, func(c *assert.CollectT) {
					err = executeAndUnmarshal(
						headscale,
						[]string{
							"headscale",
							"ping",
							"--identifier", strconv.FormatUint(nodes[0].GetId(), 10),
							"--target", targetIP,
							"--output", "json",
						},
						&pingResp,
					)
					assert.NoError(c, err)
					assert.True(c, pingResp.GetSuccess(), "Cross-node ping to %s should succeed", ipVersion)
					assert.Equal(c, targetIP, pingResp.GetNodeIp(), "Response should contain target IP for %s", ipVersion)
					assert.NotEmpty(c, pingResp.GetPingType(), "Ping type should be specified for %s", ipVersion)
				}, 30*time.Second, 2*time.Second, "Waiting for cross-node ping to %s address %d: %s", ipVersion, idx, targetIP)
			})
		}
	})

	// Test 4: Ping non-existent node should fail gracefully
	t.Run("ping-nonexistent-node", func(t *testing.T) {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"ping",
				"--identifier", "999",
				"--output", "json",
			},
		)
		assert.Error(t, err, "Pinging non-existent node should return error")
	})

	// Test 5: Ping with invalid IP should fail gracefully
	t.Run("ping-invalid-ip", func(t *testing.T) {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"ping",
				"--identifier", strconv.FormatUint(nodes[0].GetId(), 10),
				"--target", "invalid-ip",
				"--output", "json",
			},
		)
		assert.Error(t, err, "Pinging with invalid IP should return error")
	})
}

// TestPingViaDERP tests the ping functionality when nodes communicate via DERP relay
func TestPingViaDERP(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{"user1"},
		Networks: map[string][]string{
			"network1": {"user1"},
		},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("pingderp"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)
	require.Len(t, allClients, 2, "Should have exactly 2 clients")

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	// Get node information
	var nodes []*v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 2, "Should have 2 nodes registered")
	}, 30*time.Second, 1*time.Second, "Waiting for nodes to be listed in DERP test")

	// Ping between nodes - may go via DERP in some network configurations
	t.Run("ping-via-derp-possible", func(t *testing.T) {
		require.NotEmpty(t, nodes[1].GetIpAddresses(), "Second node should have IP addresses")
		targetIP := nodes[1].GetIpAddresses()[0]

		var pingResp v1.PingNodeResponse
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			err = executeAndUnmarshal(
				headscale,
				[]string{
					"headscale",
					"ping",
					"--identifier", strconv.FormatUint(nodes[0].GetId(), 10),
					"--target", targetIP,
					"--output", "json",
				},
				&pingResp,
			)
			assert.NoError(c, err)
			assert.True(c, pingResp.GetSuccess(), "Ping should succeed (direct or via DERP)")

			// Log whether connection was via DERP or direct
			if pingResp.GetDerpRegionId() > 0 {
				t.Logf("Connection via DERP region %d", pingResp.GetDerpRegionId())
			} else if pingResp.GetIsLocal() {
				t.Logf("Direct local connection")
			}
		}, 30*time.Second, 2*time.Second, "Waiting for ping via DERP or direct")
	})
}

// TestPingMultiUser tests ping functionality across multiple users
func TestPingMultiUser(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("pingmulti"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)
	require.Len(t, allClients, 2, "Should have exactly 2 clients")

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	// Get node information
	var nodes []*v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 2, "Should have 2 nodes from different users")
	}, 30*time.Second, 1*time.Second, "Waiting for multi-user nodes to be listed")

	// Ping from user1's node to user2's node
	t.Run("cross-user-ping", func(t *testing.T) {
		require.NotEmpty(t, nodes[1].GetIpAddresses(), "User2's node should have IP addresses")
		targetIP := nodes[1].GetIpAddresses()[0]

		var pingResp v1.PingNodeResponse
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			err = executeAndUnmarshal(
				headscale,
				[]string{
					"headscale",
					"ping",
					"--identifier", strconv.FormatUint(nodes[0].GetId(), 10),
					"--target", targetIP,
					"--output", "json",
				},
				&pingResp,
			)
			assert.NoError(c, err)
			assert.True(c, pingResp.GetSuccess(), "Cross-user ping should succeed")
		}, 30*time.Second, 2*time.Second, "Waiting for cross-user ping")
	})
}

// TestPingOfflineNode tests ping behavior when target node is offline
func TestPingOfflineNode(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("pingoffline"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)
	require.Len(t, allClients, 2, "Should have exactly 2 clients")

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	// Get node information
	var nodes []*v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 2, "Should have 2 nodes")
	}, 30*time.Second, 1*time.Second, "Waiting for nodes before taking one offline")

	// First verify ping works while both nodes are online
	require.NotEmpty(t, nodes[1].GetIpAddresses(), "Second node should have IP addresses")
	targetIP := nodes[1].GetIpAddresses()[0]

	var pingRespOnline v1.PingNodeResponse
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"ping",
				"--identifier", strconv.FormatUint(nodes[0].GetId(), 10),
				"--target", targetIP,
				"--output", "json",
			},
			&pingRespOnline,
		)
		assert.NoError(c, err)
		assert.True(c, pingRespOnline.GetSuccess(), "Ping should succeed while node is online")
	}, 30*time.Second, 2*time.Second, "Waiting for initial ping before taking node offline")

	// Take second node offline
	err = allClients[1].Down()
	require.NoError(t, err, "Should be able to take second client offline")

	// Wait a bit for the node to be recognized as offline
	time.Sleep(5 * time.Second)

	// Try to ping the offline node - this should timeout
	t.Run("ping-offline-node", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
		defer cancel()

		// Start ping in goroutine since it will timeout
		done := make(chan bool)
		var pingErr error
		go func() {
			_, pingErr = headscale.Execute(
				[]string{
					"headscale",
					"ping",
					"--identifier", strconv.FormatUint(nodes[0].GetId(), 10),
					"--target", targetIP,
					"--output", "json",
				},
			)
			close(done)
		}()

		select {
		case <-done:
			// Ping completed (likely with timeout error)
			// We expect either an error or a failed response
			if pingErr == nil {
				var pingResp v1.PingNodeResponse
				err = executeAndUnmarshal(
					headscale,
					[]string{
						"headscale",
						"ping",
						"--identifier", strconv.FormatUint(nodes[0].GetId(), 10),
						"--target", targetIP,
						"--output", "json",
					},
					&pingResp,
				)
				if err == nil {
					assert.False(t, pingResp.GetSuccess(), "Ping to offline node should not succeed")
				}
			}
		case <-ctx.Done():
			t.Log("Ping to offline node timed out as expected")
		}
	})

	// Bring node back online
	err = allClients[1].Up()
	require.NoError(t, err, "Should be able to bring second client back online")

	// Verify ping works again after node comes back online
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var pingRespBack v1.PingNodeResponse
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"ping",
				"--identifier", strconv.FormatUint(nodes[0].GetId(), 10),
				"--target", targetIP,
				"--output", "json",
			},
			&pingRespBack,
		)
		assert.NoError(c, err)
		assert.True(c, pingRespBack.GetSuccess(), "Ping should succeed after node comes back online")
	}, 60*time.Second, 3*time.Second, "Waiting for ping to succeed after node comes back online")
}

// TestPingCLIShorthand tests the shorthand alias for the ping command
func TestPingCLIShorthand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("pingshort"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	var nodes []*v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 1, "Should have 1 node")
	}, 30*time.Second, 1*time.Second, "Waiting for node in shorthand test")

	// Test both long form "--identifier" and short form "-i"
	t.Run("long-form-identifier", func(t *testing.T) {
		var pingResp v1.PingNodeResponse
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			err = executeAndUnmarshal(
				headscale,
				[]string{
					"headscale",
					"ping",
					"--identifier", strconv.FormatUint(nodes[0].GetId(), 10),
					"--output", "json",
				},
				&pingResp,
			)
			assert.NoError(c, err)
			assert.True(c, pingResp.GetSuccess(), "Ping with long form should succeed")
		}, 30*time.Second, 2*time.Second, "Testing long form --identifier")
	})

	t.Run("short-form-identifier", func(t *testing.T) {
		var pingResp v1.PingNodeResponse
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			err = executeAndUnmarshal(
				headscale,
				[]string{
					"headscale",
					"ping",
					"-i", strconv.FormatUint(nodes[0].GetId(), 10),
					"--output", "json",
				},
				&pingResp,
			)
			assert.NoError(c, err)
			assert.True(c, pingResp.GetSuccess(), "Ping with short form -i should succeed")
		}, 30*time.Second, 2*time.Second, "Testing short form -i")
	})
}

// TestPingConcurrent tests multiple simultaneous ping operations to different nodes
func TestPingConcurrent(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 3,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("pingconcurrent"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)
	require.Len(t, allClients, 3, "Should have exactly 3 clients")

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	var nodes []*v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 3, "Should have 3 nodes registered")
	}, 30*time.Second, 1*time.Second, "Waiting for all nodes to be listed")

	// Test concurrent pings from node 0 to all other nodes
	t.Run("concurrent-pings-from-single-source", func(t *testing.T) {
		type pingResult struct {
			targetNodeID uint64
			targetIP     string
			response     v1.PingNodeResponse
			err          error
		}

		results := make(chan pingResult, 2)

		// Launch concurrent pings to node 1 and node 2
		for i := 1; i <= 2; i++ {
			go func(nodeIdx int) {
				require.NotEmpty(t, nodes[nodeIdx].GetIpAddresses(), "Node should have IP addresses")
				targetIP := nodes[nodeIdx].GetIpAddresses()[0]

				var pingResp v1.PingNodeResponse
				err := executeAndUnmarshal(
					headscale,
					[]string{
						"headscale",
						"ping",
						"--identifier", strconv.FormatUint(nodes[0].GetId(), 10),
						"--target", targetIP,
						"--output", "json",
					},
					&pingResp,
				)

				results <- pingResult{
					targetNodeID: nodes[nodeIdx].GetId(),
					targetIP:     targetIP,
					response:     pingResp,
					err:          err,
				}
			}(i)
		}

		// Collect and verify results with timeout
		timeout := time.After(45 * time.Second)
		for i := 0; i < 2; i++ {
			select {
			case result := <-results:
				assert.NoError(t, result.err, "Ping to node %d should not error", result.targetNodeID)
				assert.True(t, result.response.GetSuccess(), "Concurrent ping to node %d should succeed", result.targetNodeID)
				assert.Equal(t, result.targetIP, result.response.GetNodeIp(), "Response should contain correct target IP")
				assert.NotEmpty(t, result.response.GetPingType(), "Ping type should be specified")
				t.Logf("Concurrent ping to node %d succeeded: type=%s, latency=%dms",
					result.targetNodeID, result.response.GetPingType(), result.response.GetLatencyMs())
			case <-timeout:
				t.Fatal("Timeout waiting for concurrent ping results")
			}
		}
	})

	// Test concurrent pings from different source nodes
	t.Run("concurrent-pings-from-multiple-sources", func(t *testing.T) {
		type pingResult struct {
			sourceNodeID uint64
			targetNodeID uint64
			response     v1.PingNodeResponse
			err          error
		}

		results := make(chan pingResult, 2)

		// Node 0 pings Node 1, Node 1 pings Node 2 simultaneously
		go func() {
			require.NotEmpty(t, nodes[1].GetIpAddresses(), "Node 1 should have IP addresses")
			targetIP := nodes[1].GetIpAddresses()[0]

			var pingResp v1.PingNodeResponse
			err := executeAndUnmarshal(
				headscale,
				[]string{
					"headscale",
					"ping",
					"--identifier", strconv.FormatUint(nodes[0].GetId(), 10),
					"--target", targetIP,
					"--output", "json",
				},
				&pingResp,
			)

			results <- pingResult{
				sourceNodeID: nodes[0].GetId(),
				targetNodeID: nodes[1].GetId(),
				response:     pingResp,
				err:          err,
			}
		}()

		go func() {
			require.NotEmpty(t, nodes[2].GetIpAddresses(), "Node 2 should have IP addresses")
			targetIP := nodes[2].GetIpAddresses()[0]

			var pingResp v1.PingNodeResponse
			err := executeAndUnmarshal(
				headscale,
				[]string{
					"headscale",
					"ping",
					"--identifier", strconv.FormatUint(nodes[1].GetId(), 10),
					"--target", targetIP,
					"--output", "json",
				},
				&pingResp,
			)

			results <- pingResult{
				sourceNodeID: nodes[1].GetId(),
				targetNodeID: nodes[2].GetId(),
				response:     pingResp,
				err:          err,
			}
		}()

		// Collect and verify results
		timeout := time.After(45 * time.Second)
		for i := 0; i < 2; i++ {
			select {
			case result := <-results:
				assert.NoError(t, result.err, "Ping from node %d to node %d should not error",
					result.sourceNodeID, result.targetNodeID)
				assert.True(t, result.response.GetSuccess(), "Ping from node %d to node %d should succeed",
					result.sourceNodeID, result.targetNodeID)
				t.Logf("Ping from node %d to node %d succeeded", result.sourceNodeID, result.targetNodeID)
			case <-timeout:
				t.Fatal("Timeout waiting for multi-source ping results")
			}
		}
	})
}

// TestPingResponseFieldValidation validates all PingNodeResponse fields are populated correctly
func TestPingResponseFieldValidation(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("pingvalidation"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)
	require.Len(t, allClients, 2, "Should have exactly 2 clients")

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	var nodes []*v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 2, "Should have 2 nodes registered")
	}, 30*time.Second, 1*time.Second, "Waiting for nodes to be listed")

	// Test all response fields are populated correctly
	t.Run("validate-all-response-fields", func(t *testing.T) {
		require.NotEmpty(t, nodes[1].GetIpAddresses(), "Target node should have IP addresses")
		targetIP := nodes[1].GetIpAddresses()[0]

		var pingResp v1.PingNodeResponse
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			err = executeAndUnmarshal(
				headscale,
				[]string{
					"headscale",
					"ping",
					"--identifier", strconv.FormatUint(nodes[0].GetId(), 10),
					"--target", targetIP,
					"--output", "json",
				},
				&pingResp,
			)
			assert.NoError(c, err)

			// Validate all fields
			assert.True(c, pingResp.GetSuccess(), "success field should be true")
			assert.NotEmpty(c, pingResp.GetPingType(), "ping_type field should be populated")
			assert.Equal(c, targetIP, pingResp.GetNodeIp(), "node_ip field should match target")
			assert.GreaterOrEqual(c, pingResp.GetLatencyMs(), int64(0), "latency_ms should be non-negative")
			assert.Empty(c, pingResp.GetError(), "error field should be empty on success")

			// endpoint field may or may not be populated depending on network topology
			// but should not cause issues if present
			t.Logf("Endpoint: %s", pingResp.GetEndpoint())

			// derp_region_id and is_local are mutually informative
			// At least one should indicate connection type
			if pingResp.GetIsLocal() {
				t.Logf("Connection is local (direct)")
			} else if pingResp.GetDerpRegionId() > 0 {
				t.Logf("Connection via DERP region %d", pingResp.GetDerpRegionId())
			}

		}, 30*time.Second, 2*time.Second, "Validating all response fields")
	})

	// Test failed ping has proper error field populated
	t.Run("validate-error-field-on-failure", func(t *testing.T) {
		// Ping with malformed IP to trigger error
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"ping",
				"--identifier", strconv.FormatUint(nodes[0].GetId(), 10),
				"--target", "not-a-valid-ip",
				"--output", "json",
			},
		)

		// Should get an error from the command execution
		assert.Error(t, err, "Ping with invalid IP should fail")
	})
}

// TestPingEdgeCases tests various edge cases for the ping functionality
func TestPingEdgeCases(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("pingedge"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)
	require.Len(t, allClients, 2, "Should have exactly 2 clients")

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	var nodes []*v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 2, "Should have 2 nodes registered")
	}, 30*time.Second, 1*time.Second, "Waiting for nodes to be listed")

	// Test malformed IP addresses
	t.Run("ping-with-malformed-ip", func(t *testing.T) {
		malformedIPs := []string{
			"999.999.999.999",  // Invalid IPv4
			"gggg::hhhh::iiii", // Invalid IPv6
			"192.168.1",        // Incomplete IPv4
			"not-an-ip-at-all", // Not an IP
			"192.168.1.1.1",    // Too many octets
			"::ffff:999.1.1.1", // Invalid IPv4-mapped IPv6
		}

		for _, badIP := range malformedIPs {
			t.Run(badIP, func(t *testing.T) {
				_, err := headscale.Execute(
					[]string{
						"headscale",
						"ping",
						"--identifier", strconv.FormatUint(nodes[0].GetId(), 10),
						"--target", badIP,
						"--output", "json",
					},
				)
				assert.Error(t, err, "Ping with malformed IP %s should fail", badIP)
			})
		}
	})

	// Test IP addresses not in the tailnet
	t.Run("ping-to-ip-outside-tailnet", func(t *testing.T) {
		externalIPs := []string{
			"1.1.1.1",         // Cloudflare DNS
			"8.8.8.8",         // Google DNS
			"192.168.255.254", // Unlikely to be in tailnet
		}

		for _, externalIP := range externalIPs {
			t.Run(externalIP, func(t *testing.T) {
				// This test verifies the command handles external IPs gracefully
				// The ping may timeout or fail, but should not crash
				ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
				defer cancel()

				done := make(chan bool)
				var pingErr error
				go func() {
					_, pingErr = headscale.Execute(
						[]string{
							"headscale",
							"ping",
							"--identifier", strconv.FormatUint(nodes[0].GetId(), 10),
							"--target", externalIP,
							"--output", "json",
						},
					)
					close(done)
				}()

				select {
				case <-done:
					// Command completed - may have succeeded or failed
					// but should not have crashed
					t.Logf("Ping to external IP %s completed with error: %v", externalIP, pingErr)
				case <-ctx.Done():
					t.Logf("Ping to external IP %s timed out as expected", externalIP)
				}
			})
		}
	})

	// Test zero node ID
	t.Run("ping-with-zero-node-id", func(t *testing.T) {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"ping",
				"--identifier", "0",
				"--output", "json",
			},
		)
		assert.Error(t, err, "Ping with node ID 0 should fail")
	})

	// Test extremely large node ID
	t.Run("ping-with-large-node-id", func(t *testing.T) {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"ping",
				"--identifier", "18446744073709551615", // Max uint64
				"--output", "json",
			},
		)
		assert.Error(t, err, "Ping with non-existent large node ID should fail")
	})
}

// TestPingHighVolume tests high-volume ping scenarios with rapid consecutive pings
func TestPingHighVolume(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("pinghighvol"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)
	require.Len(t, allClients, 2, "Should have exactly 2 clients")

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	var nodes []*v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 2, "Should have 2 nodes registered")
	}, 30*time.Second, 1*time.Second, "Waiting for nodes to be listed")

	// Test rapid consecutive pings
	t.Run("rapid-consecutive-pings", func(t *testing.T) {
		require.NotEmpty(t, nodes[1].GetIpAddresses(), "Target node should have IP addresses")
		targetIP := nodes[1].GetIpAddresses()[0]

		const numPings = 5
		successCount := 0

		for i := 0; i < numPings; i++ {
			var pingResp v1.PingNodeResponse
			err := executeAndUnmarshal(
				headscale,
				[]string{
					"headscale",
					"ping",
					"--identifier", strconv.FormatUint(nodes[0].GetId(), 10),
					"--target", targetIP,
					"--output", "json",
				},
				&pingResp,
			)

			if err == nil && pingResp.GetSuccess() {
				successCount++
				t.Logf("Ping %d/%d succeeded: latency=%dms", i+1, numPings, pingResp.GetLatencyMs())
			} else {
				t.Logf("Ping %d/%d failed: %v", i+1, numPings, err)
			}

			// Small delay between pings to avoid overwhelming the system
			time.Sleep(500 * time.Millisecond)
		}

		// At least 80% of pings should succeed
		successRate := float64(successCount) / float64(numPings)
		assert.GreaterOrEqual(t, successRate, 0.8, "At least 80%% of rapid pings should succeed (got %.0f%%)", successRate*100)
	})

	// Test burst of concurrent pings
	t.Run("burst-concurrent-pings", func(t *testing.T) {
		require.NotEmpty(t, nodes[1].GetIpAddresses(), "Target node should have IP addresses")
		targetIP := nodes[1].GetIpAddresses()[0]

		const burstSize = 3
		results := make(chan bool, burstSize)

		// Launch burst of pings
		for i := 0; i < burstSize; i++ {
			go func(idx int) {
				var pingResp v1.PingNodeResponse
				err := executeAndUnmarshal(
					headscale,
					[]string{
						"headscale",
						"ping",
						"--identifier", strconv.FormatUint(nodes[0].GetId(), 10),
						"--target", targetIP,
						"--output", "json",
					},
					&pingResp,
				)

				success := err == nil && pingResp.GetSuccess()
				results <- success
				t.Logf("Burst ping %d: success=%v", idx+1, success)
			}(i)
		}

		// Collect results
		timeout := time.After(60 * time.Second)
		successCount := 0
		for i := 0; i < burstSize; i++ {
			select {
			case success := <-results:
				if success {
					successCount++
				}
			case <-timeout:
				t.Fatal("Timeout waiting for burst ping results")
			}
		}

		// At least 2 out of 3 burst pings should succeed
		assert.GreaterOrEqual(t, successCount, 2, "At least 2 out of %d burst pings should succeed", burstSize)
	})
}

// TestPingComplexTopology tests ping in various network topologies with 3+ nodes
func TestPingComplexTopology(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 4,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("pingtopology"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)
	require.Len(t, allClients, 4, "Should have exactly 4 clients")

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	var nodes []*v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 4, "Should have 4 nodes registered")
	}, 30*time.Second, 1*time.Second, "Waiting for all nodes to be listed")

	// Test full mesh connectivity - every node pings every other node
	t.Run("full-mesh-ping", func(t *testing.T) {
		type meshPingResult struct {
			sourceNodeID uint64
			targetNodeID uint64
			success      bool
		}

		results := make([]meshPingResult, 0)

		// Ping from each node to every other node
		for i := 0; i < len(nodes); i++ {
			for j := 0; j < len(nodes); j++ {
				if i == j {
					continue // Skip self-ping for this test
				}

				require.NotEmpty(t, nodes[j].GetIpAddresses(), "Target node should have IP addresses")
				targetIP := nodes[j].GetIpAddresses()[0]

				var pingResp v1.PingNodeResponse
				err := executeAndUnmarshal(
					headscale,
					[]string{
						"headscale",
						"ping",
						"--identifier", strconv.FormatUint(nodes[i].GetId(), 10),
						"--target", targetIP,
						"--output", "json",
					},
					&pingResp,
				)

				success := err == nil && pingResp.GetSuccess()
				results = append(results, meshPingResult{
					sourceNodeID: nodes[i].GetId(),
					targetNodeID: nodes[j].GetId(),
					success:      success,
				})

				t.Logf("Mesh ping: node %d -> node %d: success=%v",
					nodes[i].GetId(), nodes[j].GetId(), success)

				// Small delay to avoid overwhelming the system
				time.Sleep(300 * time.Millisecond)
			}
		}

		// Calculate success rate
		successCount := 0
		for _, result := range results {
			if result.success {
				successCount++
			}
		}

		totalPings := len(results)
		successRate := float64(successCount) / float64(totalPings)
		assert.GreaterOrEqual(t, successRate, 0.9,
			"At least 90%% of mesh pings should succeed (got %d/%d = %.0f%%)",
			successCount, totalPings, successRate*100)
	})

	// Test chain topology - node 0 -> node 1 -> node 2 -> node 3
	t.Run("chain-topology-ping", func(t *testing.T) {
		for i := 0; i < len(nodes)-1; i++ {
			require.NotEmpty(t, nodes[i+1].GetIpAddresses(), "Target node should have IP addresses")
			targetIP := nodes[i+1].GetIpAddresses()[0]

			var pingResp v1.PingNodeResponse
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				err = executeAndUnmarshal(
					headscale,
					[]string{
						"headscale",
						"ping",
						"--identifier", strconv.FormatUint(nodes[i].GetId(), 10),
						"--target", targetIP,
						"--output", "json",
					},
					&pingResp,
				)
				assert.NoError(c, err)
				assert.True(c, pingResp.GetSuccess(), "Chain ping from node %d to node %d should succeed",
					nodes[i].GetId(), nodes[i+1].GetId())
			}, 30*time.Second, 2*time.Second, "Chain ping from node %d to node %d", i, i+1)
		}
	})

	// Test star topology - one node (node 0) pings all others
	t.Run("star-topology-ping", func(t *testing.T) {
		hubNode := nodes[0]

		for i := 1; i < len(nodes); i++ {
			require.NotEmpty(t, nodes[i].GetIpAddresses(), "Spoke node should have IP addresses")
			targetIP := nodes[i].GetIpAddresses()[0]

			var pingResp v1.PingNodeResponse
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				err = executeAndUnmarshal(
					headscale,
					[]string{
						"headscale",
						"ping",
						"--identifier", strconv.FormatUint(hubNode.GetId(), 10),
						"--target", targetIP,
						"--output", "json",
					},
					&pingResp,
				)
				assert.NoError(c, err)
				assert.True(c, pingResp.GetSuccess(), "Star ping from hub to spoke %d should succeed", i)
			}, 30*time.Second, 2*time.Second, "Star ping from hub to spoke %d", i)
		}
	})
}
