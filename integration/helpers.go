package integration

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/google/go-cmp/cmp"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

const (
	// derpPingTimeout defines the timeout for individual DERP ping operations
	// Used in DERP connectivity tests to verify relay server communication.
	derpPingTimeout = 2 * time.Second

	// derpPingCount defines the number of ping attempts for DERP connectivity tests
	// Higher count provides better reliability assessment of DERP connectivity.
	derpPingCount = 10

	// TimestampFormat is the standard timestamp format used across all integration tests
	// Format: "2006-01-02T15-04-05.999999999" provides high precision timestamps
	// suitable for debugging and log correlation in integration tests.
	TimestampFormat = "2006-01-02T15-04-05.999999999"

	// TimestampFormatRunID is used for generating unique run identifiers
	// Format: "20060102-150405" provides compact date-time for file/directory names.
	TimestampFormatRunID = "20060102-150405"
)

// NodeSystemStatus represents the status of a node across different systems
type NodeSystemStatus struct {
	Batcher          bool
	BatcherConnCount int
	MapResponses     bool
	NodeStore        bool
}

// requireNoErrHeadscaleEnv validates that headscale environment creation succeeded.
// Provides specific error context for headscale environment setup failures.
func requireNoErrHeadscaleEnv(t *testing.T, err error) {
	t.Helper()
	require.NoError(t, err, "failed to create headscale environment")
}

// requireNoErrGetHeadscale validates that headscale server retrieval succeeded.
// Provides specific error context for headscale server access failures.
func requireNoErrGetHeadscale(t *testing.T, err error) {
	t.Helper()
	require.NoError(t, err, "failed to get headscale")
}

// requireNoErrListClients validates that client listing operations succeeded.
// Provides specific error context for client enumeration failures.
func requireNoErrListClients(t *testing.T, err error) {
	t.Helper()
	require.NoError(t, err, "failed to list clients")
}

// requireNoErrListClientIPs validates that client IP retrieval succeeded.
// Provides specific error context for client IP address enumeration failures.
func requireNoErrListClientIPs(t *testing.T, err error) {
	t.Helper()
	require.NoError(t, err, "failed to get client IPs")
}

// requireNoErrSync validates that client synchronization operations succeeded.
// Provides specific error context for client sync failures across the network.
func requireNoErrSync(t *testing.T, err error) {
	t.Helper()
	require.NoError(t, err, "failed to have all clients sync up")
}

// requireNoErrListFQDN validates that FQDN listing operations succeeded.
// Provides specific error context for DNS name enumeration failures.
func requireNoErrListFQDN(t *testing.T, err error) {
	t.Helper()
	require.NoError(t, err, "failed to list FQDNs")
}

// requireNoErrLogout validates that tailscale node logout operations succeeded.
// Provides specific error context for client logout failures.
func requireNoErrLogout(t *testing.T, err error) {
	t.Helper()
	require.NoError(t, err, "failed to log out tailscale nodes")
}

// collectExpectedNodeIDs extracts node IDs from a list of TailscaleClients for validation purposes
func collectExpectedNodeIDs(t *testing.T, clients []TailscaleClient) []types.NodeID {
	t.Helper()

	expectedNodes := make([]types.NodeID, 0, len(clients))
	for _, client := range clients {
		status := client.MustStatus()
		nodeID, err := strconv.ParseUint(string(status.Self.ID), 10, 64)
		require.NoError(t, err)
		expectedNodes = append(expectedNodes, types.NodeID(nodeID))
	}
	return expectedNodes
}

// validateInitialConnection performs comprehensive validation after initial client login.
// Validates that all nodes are online and have proper NetInfo/DERP configuration,
// essential for ensuring successful initial connection state in relogin tests.
func validateInitialConnection(t *testing.T, headscale ControlServer, expectedNodes []types.NodeID) {
	t.Helper()

	requireAllClientsOnline(t, headscale, expectedNodes, true, "all clients should be connected after initial login", 120*time.Second)
	requireAllClientsNetInfoAndDERP(t, headscale, expectedNodes, "all clients should have NetInfo and DERP after initial login", 3*time.Minute)
}

// validateLogoutComplete performs comprehensive validation after client logout.
// Ensures all nodes are properly offline across all headscale systems,
// critical for validating clean logout state in relogin tests.
func validateLogoutComplete(t *testing.T, headscale ControlServer, expectedNodes []types.NodeID) {
	t.Helper()

	requireAllClientsOnline(t, headscale, expectedNodes, false, "all nodes should be offline after logout", 120*time.Second)
}

// validateReloginComplete performs comprehensive validation after client relogin.
// Validates that all nodes are back online with proper NetInfo/DERP configuration,
// ensuring successful relogin state restoration in integration tests.
func validateReloginComplete(t *testing.T, headscale ControlServer, expectedNodes []types.NodeID) {
	t.Helper()

	requireAllClientsOnline(t, headscale, expectedNodes, true, "all clients should be connected after relogin", 120*time.Second)
	requireAllClientsNetInfoAndDERP(t, headscale, expectedNodes, "all clients should have NetInfo and DERP after relogin", 3*time.Minute)
}

// requireAllClientsOnline validates that all nodes are online/offline across all headscale systems
// requireAllClientsOnline verifies all expected nodes are in the specified online state across all systems
func requireAllClientsOnline(t *testing.T, headscale ControlServer, expectedNodes []types.NodeID, expectedOnline bool, message string, timeout time.Duration) {
	t.Helper()

	startTime := time.Now()
	stateStr := "offline"
	if expectedOnline {
		stateStr = "online"
	}
	t.Logf("requireAllSystemsOnline: Starting %s validation for %d nodes at %s - %s", stateStr, len(expectedNodes), startTime.Format(TimestampFormat), message)

	if expectedOnline {
		// For online validation, use the existing logic with full timeout
		requireAllClientsOnlineWithSingleTimeout(t, headscale, expectedNodes, expectedOnline, message, timeout)
	} else {
		// For offline validation, use staged approach with component-specific timeouts
		requireAllClientsOfflineStaged(t, headscale, expectedNodes, message, timeout)
	}

	endTime := time.Now()
	t.Logf("requireAllSystemsOnline: Completed %s validation for %d nodes at %s - Duration: %s - %s", stateStr, len(expectedNodes), endTime.Format(TimestampFormat), endTime.Sub(startTime), message)
}

// requireAllClientsOnlineWithSingleTimeout is the original validation logic for online state
func requireAllClientsOnlineWithSingleTimeout(t *testing.T, headscale ControlServer, expectedNodes []types.NodeID, expectedOnline bool, message string, timeout time.Duration) {
	t.Helper()

	var prevReport string
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		// Get batcher state
		debugInfo, err := headscale.DebugBatcher()
		assert.NoError(c, err, "Failed to get batcher debug info")
		if err != nil {
			return
		}

		// Get map responses
		mapResponses, err := headscale.GetAllMapReponses()
		assert.NoError(c, err, "Failed to get map responses")
		if err != nil {
			return
		}

		// Get nodestore state
		nodeStore, err := headscale.DebugNodeStore()
		assert.NoError(c, err, "Failed to get nodestore debug info")
		if err != nil {
			return
		}

		// Validate that all expected nodes are present in nodeStore
		for _, nodeID := range expectedNodes {
			_, exists := nodeStore[nodeID]
			assert.True(c, exists, "Expected node %d not found in nodeStore", nodeID)
		}

		// Check that we have map responses for expected nodes
		mapResponseCount := len(mapResponses)
		expectedCount := len(expectedNodes)
		assert.GreaterOrEqual(c, mapResponseCount, expectedCount, "MapResponses insufficient - expected at least %d responses, got %d", expectedCount, mapResponseCount)

		// Build status map for each node
		nodeStatus := make(map[types.NodeID]NodeSystemStatus)

		// Initialize all expected nodes
		for _, nodeID := range expectedNodes {
			nodeStatus[nodeID] = NodeSystemStatus{}
		}

		// Check batcher state for expected nodes
		for _, nodeID := range expectedNodes {
			nodeIDStr := fmt.Sprintf("%d", nodeID)
			if nodeInfo, exists := debugInfo.ConnectedNodes[nodeIDStr]; exists {
				if status, exists := nodeStatus[nodeID]; exists {
					status.Batcher = nodeInfo.Connected
					status.BatcherConnCount = nodeInfo.ActiveConnections
					nodeStatus[nodeID] = status
				}
			} else {
				// Node not found in batcher, mark as disconnected
				if status, exists := nodeStatus[nodeID]; exists {
					status.Batcher = false
					status.BatcherConnCount = 0
					nodeStatus[nodeID] = status
				}
			}
		}

		// Check map responses using buildExpectedOnlineMap
		onlineFromMaps := make(map[types.NodeID]bool)
		onlineMap := integrationutil.BuildExpectedOnlineMap(mapResponses)

		// For single node scenarios, we can't validate peer visibility since there are no peers
		if len(expectedNodes) == 1 {
			// For single node, just check that we have map responses for the node
			for nodeID := range nodeStatus {
				if _, exists := onlineMap[nodeID]; exists {
					onlineFromMaps[nodeID] = true
				} else {
					onlineFromMaps[nodeID] = false
				}
			}
		} else {
			// Multi-node scenario: check peer visibility
			for nodeID := range nodeStatus {
				// Initialize as offline - will be set to true only if visible in all relevant peer maps
				onlineFromMaps[nodeID] = false

				// Count how many peer maps should show this node
				expectedPeerMaps := 0
				foundOnlinePeerMaps := 0

				for id, peerMap := range onlineMap {
					if id == nodeID {
						continue // Skip self-references
					}
					expectedPeerMaps++

					if online, exists := peerMap[nodeID]; exists && online {
						foundOnlinePeerMaps++
					}
				}

				// Node is considered online if it appears online in all peer maps
				// (or if there are no peer maps to check)
				if expectedPeerMaps == 0 || foundOnlinePeerMaps == expectedPeerMaps {
					onlineFromMaps[nodeID] = true
				}
			}
		}
		assert.Lenf(c, onlineFromMaps, expectedCount, "MapResponses missing nodes in status check")

		// Update status with map response data
		for nodeID, online := range onlineFromMaps {
			if status, exists := nodeStatus[nodeID]; exists {
				status.MapResponses = online
				nodeStatus[nodeID] = status
			}
		}

		// Check nodestore state for expected nodes
		for _, nodeID := range expectedNodes {
			if node, exists := nodeStore[nodeID]; exists {
				if status, exists := nodeStatus[nodeID]; exists {
					// Check if node is online in nodestore
					status.NodeStore = node.IsOnline != nil && *node.IsOnline
					nodeStatus[nodeID] = status
				}
			}
		}

		// Verify all systems show nodes in expected state and report failures
		allMatch := true
		var failureReport strings.Builder

		ids := types.NodeIDs(maps.Keys(nodeStatus))
		slices.Sort(ids)
		for _, nodeID := range ids {
			status := nodeStatus[nodeID]
			systemsMatch := (status.Batcher == expectedOnline) &&
				(status.MapResponses == expectedOnline) &&
				(status.NodeStore == expectedOnline)

			if !systemsMatch {
				allMatch = false
				stateStr := "offline"
				if expectedOnline {
					stateStr = "online"
				}
				failureReport.WriteString(fmt.Sprintf("node:%d is not fully %s (timestamp: %s):\n", nodeID, stateStr, time.Now().Format(TimestampFormat)))
				failureReport.WriteString(fmt.Sprintf("  - batcher: %t (expected: %t)\n", status.Batcher, expectedOnline))
				failureReport.WriteString(fmt.Sprintf("    - conn count: %d\n", status.BatcherConnCount))
				failureReport.WriteString(fmt.Sprintf("  - mapresponses: %t (expected: %t, down with at least one peer)\n", status.MapResponses, expectedOnline))
				failureReport.WriteString(fmt.Sprintf("  - nodestore: %t (expected: %t)\n", status.NodeStore, expectedOnline))
			}
		}

		if !allMatch {
			if diff := cmp.Diff(prevReport, failureReport.String()); diff != "" {
				t.Logf("Node state validation report changed at %s:", time.Now().Format(TimestampFormat))
				t.Logf("Previous report:\n%s", prevReport)
				t.Logf("Current report:\n%s", failureReport.String())
				t.Logf("Report diff:\n%s", diff)
				prevReport = failureReport.String()
			}

			failureReport.WriteString(fmt.Sprintf("validation_timestamp: %s\n", time.Now().Format(TimestampFormat)))
			// Note: timeout_remaining not available in this context

			assert.Fail(c, failureReport.String())
		}

		stateStr := "offline"
		if expectedOnline {
			stateStr = "online"
		}
		assert.True(c, allMatch, fmt.Sprintf("Not all %d nodes are %s across all systems (batcher, mapresponses, nodestore)", len(expectedNodes), stateStr))
	}, timeout, 2*time.Second, message)
}

// requireAllClientsOfflineStaged validates offline state with staged timeouts for different components
func requireAllClientsOfflineStaged(t *testing.T, headscale ControlServer, expectedNodes []types.NodeID, message string, totalTimeout time.Duration) {
	t.Helper()

	// Stage 1: Verify batcher disconnection (should be immediate)
	t.Logf("Stage 1: Verifying batcher disconnection for %d nodes", len(expectedNodes))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		debugInfo, err := headscale.DebugBatcher()
		assert.NoError(c, err, "Failed to get batcher debug info")
		if err != nil {
			return
		}

		allBatcherOffline := true
		for _, nodeID := range expectedNodes {
			nodeIDStr := fmt.Sprintf("%d", nodeID)
			if nodeInfo, exists := debugInfo.ConnectedNodes[nodeIDStr]; exists && nodeInfo.Connected {
				allBatcherOffline = false
				assert.False(c, nodeInfo.Connected, "Node %d should not be connected in batcher", nodeID)
			}
		}
		assert.True(c, allBatcherOffline, "All nodes should be disconnected from batcher")
	}, 15*time.Second, 1*time.Second, "batcher disconnection validation")

	// Stage 2: Verify nodestore offline status (up to 15 seconds due to disconnect detection delay)
	t.Logf("Stage 2: Verifying nodestore offline status for %d nodes (allowing for 10s disconnect detection delay)", len(expectedNodes))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		nodeStore, err := headscale.DebugNodeStore()
		assert.NoError(c, err, "Failed to get nodestore debug info")
		if err != nil {
			return
		}

		allNodeStoreOffline := true
		for _, nodeID := range expectedNodes {
			if node, exists := nodeStore[nodeID]; exists {
				isOnline := node.IsOnline != nil && *node.IsOnline
				if isOnline {
					allNodeStoreOffline = false
					assert.False(c, isOnline, "Node %d should be offline in nodestore", nodeID)
				}
			}
		}
		assert.True(c, allNodeStoreOffline, "All nodes should be offline in nodestore")
	}, 20*time.Second, 1*time.Second, "nodestore offline validation")

	// Stage 3: Verify map response propagation (longest delay due to peer update timing)
	t.Logf("Stage 3: Verifying map response propagation for %d nodes (allowing for peer map update delays)", len(expectedNodes))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		mapResponses, err := headscale.GetAllMapReponses()
		assert.NoError(c, err, "Failed to get map responses")
		if err != nil {
			return
		}

		onlineMap := integrationutil.BuildExpectedOnlineMap(mapResponses)
		allMapResponsesOffline := true

		if len(expectedNodes) == 1 {
			// Single node: check if it appears in map responses
			for nodeID := range onlineMap {
				if slices.Contains(expectedNodes, nodeID) {
					allMapResponsesOffline = false
					assert.False(c, true, "Node %d should not appear in map responses", nodeID)
				}
			}
		} else {
			// Multi-node: check peer visibility
			for _, nodeID := range expectedNodes {
				for id, peerMap := range onlineMap {
					if id == nodeID {
						continue // Skip self-references
					}
					if online, exists := peerMap[nodeID]; exists && online {
						allMapResponsesOffline = false
						assert.False(c, online, "Node %d should not be visible in node %d's map response", nodeID, id)
					}
				}
			}
		}
		assert.True(c, allMapResponsesOffline, "All nodes should be absent from peer map responses")
	}, 60*time.Second, 2*time.Second, "map response propagation validation")

	t.Logf("All stages completed: nodes are fully offline across all systems")
}

// requireAllClientsNetInfoAndDERP validates that all nodes have NetInfo in the database
// and a valid DERP server based on the NetInfo. This function follows the pattern of
// requireAllClientsOnline by using hsic.DebugNodeStore to get the database state.
func requireAllClientsNetInfoAndDERP(t *testing.T, headscale ControlServer, expectedNodes []types.NodeID, message string, timeout time.Duration) {
	t.Helper()

	startTime := time.Now()
	t.Logf("requireAllClientsNetInfoAndDERP: Starting NetInfo/DERP validation for %d nodes at %s - %s", len(expectedNodes), startTime.Format(TimestampFormat), message)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		// Get nodestore state
		nodeStore, err := headscale.DebugNodeStore()
		assert.NoError(c, err, "Failed to get nodestore debug info")
		if err != nil {
			return
		}

		// Validate that all expected nodes are present in nodeStore
		for _, nodeID := range expectedNodes {
			_, exists := nodeStore[nodeID]
			assert.True(c, exists, "Expected node %d not found in nodeStore during NetInfo validation", nodeID)
		}

		// Check each expected node
		for _, nodeID := range expectedNodes {
			node, exists := nodeStore[nodeID]
			assert.True(c, exists, "Node %d not found in nodestore during NetInfo validation", nodeID)
			if !exists {
				continue
			}

			// Validate that the node has Hostinfo
			assert.NotNil(c, node.Hostinfo, "Node %d (%s) should have Hostinfo for NetInfo validation", nodeID, node.Hostname)
			if node.Hostinfo == nil {
				t.Logf("Node %d (%s) missing Hostinfo at %s", nodeID, node.Hostname, time.Now().Format(TimestampFormat))
				continue
			}

			// Validate that the node has NetInfo
			assert.NotNil(c, node.Hostinfo.NetInfo, "Node %d (%s) should have NetInfo in Hostinfo for DERP connectivity", nodeID, node.Hostname)
			if node.Hostinfo.NetInfo == nil {
				t.Logf("Node %d (%s) missing NetInfo at %s", nodeID, node.Hostname, time.Now().Format(TimestampFormat))
				continue
			}

			// Validate that the node has a valid DERP server (PreferredDERP should be > 0)
			preferredDERP := node.Hostinfo.NetInfo.PreferredDERP
			assert.Greater(c, preferredDERP, 0, "Node %d (%s) should have a valid DERP server (PreferredDERP > 0) for relay connectivity, got %d", nodeID, node.Hostname, preferredDERP)

			t.Logf("Node %d (%s) has valid NetInfo with DERP server %d at %s", nodeID, node.Hostname, preferredDERP, time.Now().Format(TimestampFormat))
		}
	}, timeout, 5*time.Second, message)

	endTime := time.Now()
	duration := endTime.Sub(startTime)
	t.Logf("requireAllClientsNetInfoAndDERP: Completed NetInfo/DERP validation for %d nodes at %s - Duration: %v - %s", len(expectedNodes), endTime.Format(TimestampFormat), duration, message)
}

// assertLastSeenSet validates that a node has a non-nil LastSeen timestamp.
// Critical for ensuring node activity tracking is functioning properly.
func assertLastSeenSet(t *testing.T, node *v1.Node) {
	assert.NotNil(t, node)
	assert.NotNil(t, node.GetLastSeen())
}

func assertLastSeenSetWithCollect(c *assert.CollectT, node *v1.Node) {
	assert.NotNil(c, node)
	assert.NotNil(c, node.GetLastSeen())
}

// assertTailscaleNodesLogout verifies that all provided Tailscale clients
// are in the logged-out state (NeedsLogin).
func assertTailscaleNodesLogout(t assert.TestingT, clients []TailscaleClient) {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}

	for _, client := range clients {
		status, err := client.Status()
		assert.NoError(t, err, "failed to get status for client %s", client.Hostname())
		assert.Equal(t, "NeedsLogin", status.BackendState,
			"client %s should be logged out", client.Hostname())
	}
}

// pingAllHelper performs ping tests between all clients and addresses, returning success count.
// This is used to validate network connectivity in integration tests.
// Returns the total number of successful ping operations.
func pingAllHelper(t *testing.T, clients []TailscaleClient, addrs []string, opts ...tsic.PingOption) int {
	t.Helper()
	success := 0

	for _, client := range clients {
		for _, addr := range addrs {
			err := client.Ping(addr, opts...)
			if err != nil {
				t.Errorf("failed to ping %s from %s: %s", addr, client.Hostname(), err)
			} else {
				success++
			}
		}
	}

	return success
}

// pingDerpAllHelper performs DERP-based ping tests between all clients and addresses.
// This specifically tests connectivity through DERP relay servers, which is important
// for validating NAT traversal and relay functionality. Returns success count.
func pingDerpAllHelper(t *testing.T, clients []TailscaleClient, addrs []string) int {
	t.Helper()
	success := 0

	for _, client := range clients {
		for _, addr := range addrs {
			if isSelfClient(client, addr) {
				continue
			}

			err := client.Ping(
				addr,
				tsic.WithPingTimeout(derpPingTimeout),
				tsic.WithPingCount(derpPingCount),
				tsic.WithPingUntilDirect(false),
			)
			if err != nil {
				t.Logf("failed to ping %s from %s: %s", addr, client.Hostname(), err)
			} else {
				success++
			}
		}
	}

	return success
}

// isSelfClient determines if the given address belongs to the client itself.
// Used to avoid self-ping operations in connectivity tests by checking
// hostname and IP address matches.
func isSelfClient(client TailscaleClient, addr string) bool {
	if addr == client.Hostname() {
		return true
	}

	ips, err := client.IPs()
	if err != nil {
		return false
	}

	for _, ip := range ips {
		if ip.String() == addr {
			return true
		}
	}

	return false
}

// assertClientsState validates the status and netmap of a list of clients for general connectivity.
// Runs parallel validation of status, netcheck, and netmap for all clients to ensure
// they have proper network configuration for all-to-all connectivity tests.
func assertClientsState(t *testing.T, clients []TailscaleClient) {
	t.Helper()

	var wg sync.WaitGroup

	for _, client := range clients {
		wg.Add(1)
		c := client // Avoid loop pointer
		go func() {
			defer wg.Done()
			assertValidStatus(t, c)
			assertValidNetcheck(t, c)
			assertValidNetmap(t, c)
		}()
	}

	t.Logf("waiting for client state checks to finish")
	wg.Wait()
}

// assertValidNetmap validates that a client's netmap has all required fields for proper operation.
// Checks self node and all peers for essential networking data including hostinfo, addresses,
// endpoints, and DERP configuration. Skips validation for Tailscale versions below 1.56.
// This test is not suitable for ACL/partial connection tests.
func assertValidNetmap(t *testing.T, client TailscaleClient) {
	t.Helper()

	if !util.TailscaleVersionNewerOrEqual("1.56", client.Version()) {
		t.Logf("%q has version %q, skipping netmap check...", client.Hostname(), client.Version())

		return
	}

	t.Logf("Checking netmap of %q", client.Hostname())

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		netmap, err := client.Netmap()
		assert.NoError(c, err, "getting netmap for %q", client.Hostname())

		assert.Truef(c, netmap.SelfNode.Hostinfo().Valid(), "%q does not have Hostinfo", client.Hostname())
		if hi := netmap.SelfNode.Hostinfo(); hi.Valid() {
			assert.LessOrEqual(c, 1, netmap.SelfNode.Hostinfo().Services().Len(), "%q does not have enough services, got: %v", client.Hostname(), netmap.SelfNode.Hostinfo().Services())
		}

		assert.NotEmptyf(c, netmap.SelfNode.AllowedIPs(), "%q does not have any allowed IPs", client.Hostname())
		assert.NotEmptyf(c, netmap.SelfNode.Addresses(), "%q does not have any addresses", client.Hostname())

		assert.Truef(c, netmap.SelfNode.Online().Get(), "%q is not online", client.Hostname())

		assert.Falsef(c, netmap.SelfNode.Key().IsZero(), "%q does not have a valid NodeKey", client.Hostname())
		assert.Falsef(c, netmap.SelfNode.Machine().IsZero(), "%q does not have a valid MachineKey", client.Hostname())
		assert.Falsef(c, netmap.SelfNode.DiscoKey().IsZero(), "%q does not have a valid DiscoKey", client.Hostname())

		for _, peer := range netmap.Peers {
			assert.NotEqualf(c, "127.3.3.40:0", peer.LegacyDERPString(), "peer (%s) has no home DERP in %q's netmap, got: %s", peer.ComputedName(), client.Hostname(), peer.LegacyDERPString())
			assert.NotEqualf(c, 0, peer.HomeDERP(), "peer (%s) has no home DERP in %q's netmap, got: %d", peer.ComputedName(), client.Hostname(), peer.HomeDERP())

			assert.Truef(c, peer.Hostinfo().Valid(), "peer (%s) of %q does not have Hostinfo", peer.ComputedName(), client.Hostname())
			if hi := peer.Hostinfo(); hi.Valid() {
				assert.LessOrEqualf(c, 3, peer.Hostinfo().Services().Len(), "peer (%s) of %q does not have enough services, got: %v", peer.ComputedName(), client.Hostname(), peer.Hostinfo().Services())

				// Netinfo is not always set
				// assert.Truef(c, hi.NetInfo().Valid(), "peer (%s) of %q does not have NetInfo", peer.ComputedName(), client.Hostname())
				if ni := hi.NetInfo(); ni.Valid() {
					assert.NotEqualf(c, 0, ni.PreferredDERP(), "peer (%s) has no home DERP in %q's netmap, got: %s", peer.ComputedName(), client.Hostname(), peer.Hostinfo().NetInfo().PreferredDERP())
				}
			}

			assert.NotEmptyf(c, peer.Endpoints(), "peer (%s) of %q does not have any endpoints", peer.ComputedName(), client.Hostname())
			assert.NotEmptyf(c, peer.AllowedIPs(), "peer (%s) of %q does not have any allowed IPs", peer.ComputedName(), client.Hostname())
			assert.NotEmptyf(c, peer.Addresses(), "peer (%s) of %q does not have any addresses", peer.ComputedName(), client.Hostname())

			assert.Truef(c, peer.Online().Get(), "peer (%s) of %q is not online", peer.ComputedName(), client.Hostname())

			assert.Falsef(c, peer.Key().IsZero(), "peer (%s) of %q does not have a valid NodeKey", peer.ComputedName(), client.Hostname())
			assert.Falsef(c, peer.Machine().IsZero(), "peer (%s) of %q does not have a valid MachineKey", peer.ComputedName(), client.Hostname())
			assert.Falsef(c, peer.DiscoKey().IsZero(), "peer (%s) of %q does not have a valid DiscoKey", peer.ComputedName(), client.Hostname())
		}
	}, 10*time.Second, 200*time.Millisecond, "Waiting for valid netmap for %q", client.Hostname())
}

// assertValidStatus validates that a client's status has all required fields for proper operation.
// Checks self and peer status for essential data including hostinfo, tailscale IPs, endpoints,
// and network map presence. This test is not suitable for ACL/partial connection tests.
func assertValidStatus(t *testing.T, client TailscaleClient) {
	t.Helper()
	status, err := client.Status(true)
	if err != nil {
		t.Fatalf("getting status for %q: %s", client.Hostname(), err)
	}

	assert.NotEmptyf(t, status.Self.HostName, "%q does not have HostName set, likely missing Hostinfo", client.Hostname())
	assert.NotEmptyf(t, status.Self.OS, "%q does not have OS set, likely missing Hostinfo", client.Hostname())
	assert.NotEmptyf(t, status.Self.Relay, "%q does not have a relay, likely missing Hostinfo/Netinfo", client.Hostname())

	assert.NotEmptyf(t, status.Self.TailscaleIPs, "%q does not have Tailscale IPs", client.Hostname())

	// This seem to not appear until version 1.56
	if status.Self.AllowedIPs != nil {
		assert.NotEmptyf(t, status.Self.AllowedIPs, "%q does not have any allowed IPs", client.Hostname())
	}

	assert.NotEmptyf(t, status.Self.Addrs, "%q does not have any endpoints", client.Hostname())

	assert.Truef(t, status.Self.Online, "%q is not online", client.Hostname())

	assert.Truef(t, status.Self.InNetworkMap, "%q is not in network map", client.Hostname())

	// This isn't really relevant for Self as it won't be in its own socket/wireguard.
	// assert.Truef(t, status.Self.InMagicSock, "%q is not tracked by magicsock", client.Hostname())
	// assert.Truef(t, status.Self.InEngine, "%q is not in wireguard engine", client.Hostname())

	for _, peer := range status.Peer {
		assert.NotEmptyf(t, peer.HostName, "peer (%s) of %q does not have HostName set, likely missing Hostinfo", peer.DNSName, client.Hostname())
		assert.NotEmptyf(t, peer.OS, "peer (%s) of %q does not have OS set, likely missing Hostinfo", peer.DNSName, client.Hostname())
		assert.NotEmptyf(t, peer.Relay, "peer (%s) of %q does not have a relay, likely missing Hostinfo/Netinfo", peer.DNSName, client.Hostname())

		assert.NotEmptyf(t, peer.TailscaleIPs, "peer (%s) of %q does not have Tailscale IPs", peer.DNSName, client.Hostname())

		// This seem to not appear until version 1.56
		if peer.AllowedIPs != nil {
			assert.NotEmptyf(t, peer.AllowedIPs, "peer (%s) of %q does not have any allowed IPs", peer.DNSName, client.Hostname())
		}

		// Addrs does not seem to appear in the status from peers.
		// assert.NotEmptyf(t, peer.Addrs, "peer (%s) of %q does not have any endpoints", peer.DNSName, client.Hostname())

		assert.Truef(t, peer.Online, "peer (%s) of %q is not online", peer.DNSName, client.Hostname())

		assert.Truef(t, peer.InNetworkMap, "peer (%s) of %q is not in network map", peer.DNSName, client.Hostname())
		assert.Truef(t, peer.InMagicSock, "peer (%s) of %q is not tracked by magicsock", peer.DNSName, client.Hostname())

		// TODO(kradalby): InEngine is only true when a proper tunnel is set up,
		// there might be some interesting stuff to test here in the future.
		// assert.Truef(t, peer.InEngine, "peer (%s) of %q is not in wireguard engine", peer.DNSName, client.Hostname())
	}
}

// assertValidNetcheck validates that a client has a proper DERP relay configured.
// Ensures the client has discovered and selected a DERP server for relay functionality,
// which is essential for NAT traversal and connectivity in restricted networks.
func assertValidNetcheck(t *testing.T, client TailscaleClient) {
	t.Helper()
	report, err := client.Netcheck()
	if err != nil {
		t.Fatalf("getting status for %q: %s", client.Hostname(), err)
	}

	assert.NotEqualf(t, 0, report.PreferredDERP, "%q does not have a DERP relay", client.Hostname())
}

// assertCommandOutputContains executes a command with exponential backoff retry until the output
// contains the expected string or timeout is reached (10 seconds).
// This implements eventual consistency patterns and should be used instead of time.Sleep
// before executing commands that depend on network state propagation.
//
// Timeout: 10 seconds with exponential backoff
// Use cases: DNS resolution, route propagation, policy updates.
func assertCommandOutputContains(t *testing.T, c TailscaleClient, command []string, contains string) {
	t.Helper()

	_, err := backoff.Retry(t.Context(), func() (struct{}, error) {
		stdout, stderr, err := c.Execute(command)
		if err != nil {
			return struct{}{}, fmt.Errorf("executing command, stdout: %q stderr: %q, err: %w", stdout, stderr, err)
		}

		if !strings.Contains(stdout, contains) {
			return struct{}{}, fmt.Errorf("executing command, expected string %q not found in %q", contains, stdout)
		}

		return struct{}{}, nil
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()), backoff.WithMaxElapsedTime(10*time.Second))

	assert.NoError(t, err)
}

// dockertestMaxWait returns the maximum wait time for Docker-based test operations.
// Uses longer timeouts in CI environments to account for slower resource allocation
// and higher system load during automated testing.
func dockertestMaxWait() time.Duration {
	wait := 300 * time.Second //nolint

	if util.IsCI() {
		wait = 600 * time.Second //nolint
	}

	return wait
}

// didClientUseWebsocketForDERP analyzes client logs to determine if WebSocket was used for DERP.
// Searches for WebSocket connection indicators in client logs to validate
// DERP relay communication method for debugging connectivity issues.
func didClientUseWebsocketForDERP(t *testing.T, client TailscaleClient) bool {
	t.Helper()

	buf := &bytes.Buffer{}
	err := client.WriteLogs(buf, buf)
	if err != nil {
		t.Fatalf("failed to fetch client logs: %s: %s", client.Hostname(), err)
	}

	count, err := countMatchingLines(buf, func(line string) bool {
		return strings.Contains(line, "websocket: connected to ")
	})
	if err != nil {
		t.Fatalf("failed to process client logs: %s: %s", client.Hostname(), err)
	}

	return count > 0
}

// countMatchingLines counts lines in a reader that match the given predicate function.
// Uses optimized buffering for log analysis and provides flexible line-by-line
// filtering for log parsing and pattern matching in integration tests.
func countMatchingLines(in io.Reader, predicate func(string) bool) (int, error) {
	count := 0
	scanner := bufio.NewScanner(in)
	{
		const logBufferInitialSize = 1024 << 10 // preallocate 1 MiB
		buff := make([]byte, logBufferInitialSize)
		scanner.Buffer(buff, len(buff))
		scanner.Split(bufio.ScanLines)
	}

	for scanner.Scan() {
		if predicate(scanner.Text()) {
			count += 1
		}
	}

	return count, scanner.Err()
}

// wildcard returns a wildcard alias (*) for use in policy v2 configurations.
// Provides a convenient helper for creating permissive policy rules.
func wildcard() policyv2.Alias {
	return policyv2.Wildcard
}

// usernamep returns a pointer to a Username as an Alias for policy v2 configurations.
// Used in ACL rules to reference specific users in network access policies.
func usernamep(name string) policyv2.Alias {
	return ptr.To(policyv2.Username(name))
}

// hostp returns a pointer to a Host as an Alias for policy v2 configurations.
// Used in ACL rules to reference specific hosts in network access policies.
func hostp(name string) policyv2.Alias {
	return ptr.To(policyv2.Host(name))
}

// groupp returns a pointer to a Group as an Alias for policy v2 configurations.
// Used in ACL rules to reference user groups in network access policies.
func groupp(name string) policyv2.Alias {
	return ptr.To(policyv2.Group(name))
}

// tagp returns a pointer to a Tag as an Alias for policy v2 configurations.
// Used in ACL rules to reference node tags in network access policies.
func tagp(name string) policyv2.Alias {
	return ptr.To(policyv2.Tag(name))
}

// prefixp returns a pointer to a Prefix from a CIDR string for policy v2 configurations.
// Converts CIDR notation to policy prefix format for network range specifications.
func prefixp(cidr string) policyv2.Alias {
	prefix := netip.MustParsePrefix(cidr)
	return ptr.To(policyv2.Prefix(prefix))
}

// aliasWithPorts creates an AliasWithPorts structure from an alias and port ranges.
// Combines network targets with specific port restrictions for fine-grained
// access control in policy v2 configurations.
func aliasWithPorts(alias policyv2.Alias, ports ...tailcfg.PortRange) policyv2.AliasWithPorts {
	return policyv2.AliasWithPorts{
		Alias: alias,
		Ports: ports,
	}
}

// usernameOwner returns a Username as an Owner for use in TagOwners policies.
// Specifies which users can assign and manage specific tags in ACL configurations.
func usernameOwner(name string) policyv2.Owner {
	return ptr.To(policyv2.Username(name))
}

// groupOwner returns a Group as an Owner for use in TagOwners policies.
// Specifies which groups can assign and manage specific tags in ACL configurations.
func groupOwner(name string) policyv2.Owner {
	return ptr.To(policyv2.Group(name))
}

// usernameApprover returns a Username as an AutoApprover for subnet route policies.
// Specifies which users can automatically approve subnet route advertisements.
func usernameApprover(name string) policyv2.AutoApprover {
	return ptr.To(policyv2.Username(name))
}

// groupApprover returns a Group as an AutoApprover for subnet route policies.
// Specifies which groups can automatically approve subnet route advertisements.
func groupApprover(name string) policyv2.AutoApprover {
	return ptr.To(policyv2.Group(name))
}

// tagApprover returns a Tag as an AutoApprover for subnet route policies.
// Specifies which tagged nodes can automatically approve subnet route advertisements.
func tagApprover(name string) policyv2.AutoApprover {
	return ptr.To(policyv2.Tag(name))
}

// oidcMockUser creates a MockUser for OIDC authentication testing.
// Generates consistent test user data with configurable email verification status
// for validating OIDC integration flows in headscale authentication tests.
func oidcMockUser(username string, emailVerified bool) mockoidc.MockUser {
	return mockoidc.MockUser{
		Subject:           username,
		PreferredUsername: username,
		Email:             username + "@headscale.net",
		EmailVerified:     emailVerified,
	}
}

// GetUserByName retrieves a user by name from the headscale server.
// This is a common pattern used when creating preauth keys or managing users.
func GetUserByName(headscale ControlServer, username string) (*v1.User, error) {
	users, err := headscale.ListUsers()
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	for _, u := range users {
		if u.GetName() == username {
			return u, nil
		}
	}

	return nil, fmt.Errorf("user %s not found", username)
}

// FindNewClient finds a client that is in the new list but not in the original list.
// This is useful when dynamically adding nodes during tests and needing to identify
// which client was just added.
func FindNewClient(original, updated []TailscaleClient) (TailscaleClient, error) {
	for _, client := range updated {
		isOriginal := false
		for _, origClient := range original {
			if client.Hostname() == origClient.Hostname() {
				isOriginal = true
				break
			}
		}
		if !isOriginal {
			return client, nil
		}
	}
	return nil, fmt.Errorf("no new client found")
}

// AddAndLoginClient adds a new tailscale client to a user and logs it in.
// This combines the common pattern of:
// 1. Creating a new node
// 2. Finding the new node in the client list
// 3. Getting the user to create a preauth key
// 4. Logging in the new node
func (s *Scenario) AddAndLoginClient(
	t *testing.T,
	username string,
	version string,
	headscale ControlServer,
	tsOpts ...tsic.Option,
) (TailscaleClient, error) {
	t.Helper()

	// Get the original client list
	originalClients, err := s.ListTailscaleClients(username)
	if err != nil {
		return nil, fmt.Errorf("failed to list original clients: %w", err)
	}

	// Create the new node
	err = s.CreateTailscaleNodesInUser(username, version, 1, tsOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create tailscale node: %w", err)
	}

	// Wait for the new node to appear in the client list
	var newClient TailscaleClient

	_, err = backoff.Retry(t.Context(), func() (struct{}, error) {
		updatedClients, err := s.ListTailscaleClients(username)
		if err != nil {
			return struct{}{}, fmt.Errorf("failed to list updated clients: %w", err)
		}

		if len(updatedClients) != len(originalClients)+1 {
			return struct{}{}, fmt.Errorf("expected %d clients, got %d", len(originalClients)+1, len(updatedClients))
		}

		newClient, err = FindNewClient(originalClients, updatedClients)
		if err != nil {
			return struct{}{}, fmt.Errorf("failed to find new client: %w", err)
		}

		return struct{}{}, nil
	}, backoff.WithBackOff(backoff.NewConstantBackOff(500*time.Millisecond)), backoff.WithMaxElapsedTime(10*time.Second))
	if err != nil {
		return nil, fmt.Errorf("timeout waiting for new client: %w", err)
	}

	// Get the user and create preauth key
	user, err := GetUserByName(headscale, username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	authKey, err := s.CreatePreAuthKey(user.GetId(), true, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create preauth key: %w", err)
	}

	// Login the new client
	err = newClient.Login(headscale.GetEndpoint(), authKey.GetKey())
	if err != nil {
		return nil, fmt.Errorf("failed to login new client: %w", err)
	}

	return newClient, nil
}

// MustAddAndLoginClient is like AddAndLoginClient but fails the test on error.
func (s *Scenario) MustAddAndLoginClient(
	t *testing.T,
	username string,
	version string,
	headscale ControlServer,
	tsOpts ...tsic.Option,
) TailscaleClient {
	t.Helper()

	client, err := s.AddAndLoginClient(t, username, version, headscale, tsOpts...)
	require.NoError(t, err)
	return client
}
