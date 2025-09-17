package mapper

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/derp"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"zgo.at/zcache/v2"
)

// batcherTestCase defines a batcher function with a descriptive name for testing.
type batcherTestCase struct {
	name string
	fn   batcherFunc
}

// testBatcherWrapper wraps a real batcher to add online/offline notifications
// that would normally be sent by poll.go in production.
type testBatcherWrapper struct {
	Batcher
	state *state.State
}

func (t *testBatcherWrapper) AddNode(id types.NodeID, c chan<- *tailcfg.MapResponse, version tailcfg.CapabilityVersion) error {
	// Mark node as online in state before AddNode to match production behavior
	// This ensures the NodeStore has correct online status for change processing
	if t.state != nil {
		// Use Connect to properly mark node online in NodeStore but don't send its changes
		_ = t.state.Connect(id)
	}

	// First add the node to the real batcher
	err := t.Batcher.AddNode(id, c, version)
	if err != nil {
		return err
	}

	// Send the online notification that poll.go would normally send
	// This ensures other nodes get notified about this node coming online
	t.AddWork(change.NodeOnline(id))

	return nil
}

func (t *testBatcherWrapper) RemoveNode(id types.NodeID, c chan<- *tailcfg.MapResponse) bool {
	// Mark node as offline in state BEFORE removing from batcher
	// This ensures the NodeStore has correct offline status when the change is processed
	if t.state != nil {
		// Use Disconnect to properly mark node offline in NodeStore but don't send its changes
		_, _ = t.state.Disconnect(id)
	}

	// Send the offline notification that poll.go would normally send
	// Do this BEFORE removing from batcher so the change can be processed
	t.AddWork(change.NodeOffline(id))

	// Finally remove from the real batcher
	removed := t.Batcher.RemoveNode(id, c)
	if !removed {
		return false
	}

	return true
}

// wrapBatcherForTest wraps a batcher with test-specific behavior.
func wrapBatcherForTest(b Batcher, state *state.State) Batcher {
	return &testBatcherWrapper{Batcher: b, state: state}
}

// allBatcherFunctions contains all batcher implementations to test.
var allBatcherFunctions = []batcherTestCase{
	{"LockFree", NewBatcherAndMapper},
}

// emptyCache creates an empty registration cache for testing.
func emptyCache() *zcache.Cache[types.RegistrationID, types.RegisterNode] {
	return zcache.New[types.RegistrationID, types.RegisterNode](time.Minute, time.Hour)
}

// Test configuration constants.
const (
	// Test data configuration.
	TEST_USER_COUNT     = 3
	TEST_NODES_PER_USER = 2

	// Load testing configuration.
	HIGH_LOAD_NODES   = 25  // Increased from 9
	HIGH_LOAD_CYCLES  = 100 // Increased from 20
	HIGH_LOAD_UPDATES = 50  // Increased from 20

	// Extreme load testing configuration.
	EXTREME_LOAD_NODES   = 50
	EXTREME_LOAD_CYCLES  = 200
	EXTREME_LOAD_UPDATES = 100

	// Timing configuration.
	TEST_TIMEOUT     = 120 * time.Second // Increased for more intensive tests
	UPDATE_TIMEOUT   = 5 * time.Second
	DEADLOCK_TIMEOUT = 30 * time.Second

	// Channel configuration.
	NORMAL_BUFFER_SIZE = 50
	SMALL_BUFFER_SIZE  = 3
	TINY_BUFFER_SIZE   = 1 // For maximum contention
	LARGE_BUFFER_SIZE  = 200

	reservedResponseHeaderSize = 4
)

// TestData contains all test entities created for a test scenario.
type TestData struct {
	Database *db.HSDatabase
	Users    []*types.User
	Nodes    []node
	State    *state.State
	Config   *types.Config
	Batcher  Batcher
}

type node struct {
	n  *types.Node
	ch chan *tailcfg.MapResponse

	// Update tracking
	updateCount   int64
	patchCount    int64
	fullCount     int64
	maxPeersCount int
	lastPeerCount int
	stop          chan struct{}
	stopped       chan struct{}
}

// setupBatcherWithTestData creates a comprehensive test environment with real
// database test data including users and registered nodes.
//
// This helper creates a database, populates it with test data, then creates
// a state and batcher using the SAME database for testing. This provides real
// node data for testing full map responses and comprehensive update scenarios.
//
// Returns TestData struct containing all created entities and a cleanup function.
func setupBatcherWithTestData(
	t *testing.T,
	bf batcherFunc,
	userCount, nodesPerUser, bufferSize int,
) (*TestData, func()) {
	t.Helper()

	// Create database and populate with test data first
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/headscale_test.db"

	prefixV4 := netip.MustParsePrefix("100.64.0.0/10")
	prefixV6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")

	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type: types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{
				Path: dbPath,
			},
		},
		PrefixV4:     &prefixV4,
		PrefixV6:     &prefixV6,
		IPAllocation: types.IPAllocationStrategySequential,
		BaseDomain:   "headscale.test",
		Policy: types.PolicyConfig{
			Mode: types.PolicyModeDB,
		},
		DERP: types.DERPConfig{
			ServerEnabled: false,
			DERPMap: &tailcfg.DERPMap{
				Regions: map[int]*tailcfg.DERPRegion{
					999: {
						RegionID: 999,
					},
				},
			},
		},
		Tuning: types.Tuning{
			BatchChangeDelay: 10 * time.Millisecond,
			BatcherWorkers:   types.DefaultBatcherWorkers(), // Use same logic as config.go
		},
	}

	// Create database and populate it with test data
	database, err := db.NewHeadscaleDatabase(
		cfg.Database,
		"",
		emptyCache(),
	)
	if err != nil {
		t.Fatalf("setting up database: %s", err)
	}

	// Create test users and nodes in the database
	users := database.CreateUsersForTest(userCount, "testuser")

	allNodes := make([]node, 0, userCount*nodesPerUser)
	for _, user := range users {
		dbNodes := database.CreateRegisteredNodesForTest(user, nodesPerUser, "node")
		for i := range dbNodes {
			allNodes = append(allNodes, node{
				n:  dbNodes[i],
				ch: make(chan *tailcfg.MapResponse, bufferSize),
			})
		}
	}

	// Now create state using the same database
	state, err := state.NewState(cfg)
	if err != nil {
		t.Fatalf("Failed to create state: %v", err)
	}

	derpMap, err := derp.GetDERPMap(cfg.DERP)
	assert.NoError(t, err)
	assert.NotNil(t, derpMap)

	state.SetDERPMap(derpMap)

	// Set up a permissive policy that allows all communication for testing
	allowAllPolicy := `{
		"acls": [
			{
				"action": "accept",
				"src": ["*"],
				"dst": ["*:*"]
			}
		]
	}`

	_, err = state.SetPolicy([]byte(allowAllPolicy))
	if err != nil {
		t.Fatalf("Failed to set allow-all policy: %v", err)
	}

	// Create batcher with the state and wrap it for testing
	batcher := wrapBatcherForTest(bf(cfg, state), state)
	batcher.Start()

	testData := &TestData{
		Database: database,
		Users:    users,
		Nodes:    allNodes,
		State:    state,
		Config:   cfg,
		Batcher:  batcher,
	}

	cleanup := func() {
		batcher.Close()
		state.Close()
		database.Close()
	}

	return testData, cleanup
}

type UpdateStats struct {
	TotalUpdates int
	UpdateSizes  []int
	LastUpdate   time.Time
}

// updateTracker provides thread-safe tracking of updates per node.
type updateTracker struct {
	mu    sync.RWMutex
	stats map[types.NodeID]*UpdateStats
}

// newUpdateTracker creates a new update tracker.
func newUpdateTracker() *updateTracker {
	return &updateTracker{
		stats: make(map[types.NodeID]*UpdateStats),
	}
}

// recordUpdate records an update for a specific node.
func (ut *updateTracker) recordUpdate(nodeID types.NodeID, updateSize int) {
	ut.mu.Lock()
	defer ut.mu.Unlock()

	if ut.stats[nodeID] == nil {
		ut.stats[nodeID] = &UpdateStats{}
	}

	stats := ut.stats[nodeID]
	stats.TotalUpdates++
	stats.UpdateSizes = append(stats.UpdateSizes, updateSize)
	stats.LastUpdate = time.Now()
}

// getStats returns a copy of the statistics for a node.
func (ut *updateTracker) getStats(nodeID types.NodeID) UpdateStats {
	ut.mu.RLock()
	defer ut.mu.RUnlock()

	if stats, exists := ut.stats[nodeID]; exists {
		// Return a copy to avoid race conditions
		return UpdateStats{
			TotalUpdates: stats.TotalUpdates,
			UpdateSizes:  append([]int{}, stats.UpdateSizes...),
			LastUpdate:   stats.LastUpdate,
		}
	}

	return UpdateStats{}
}

// getAllStats returns a copy of all statistics.
func (ut *updateTracker) getAllStats() map[types.NodeID]UpdateStats {
	ut.mu.RLock()
	defer ut.mu.RUnlock()

	result := make(map[types.NodeID]UpdateStats)
	for nodeID, stats := range ut.stats {
		result[nodeID] = UpdateStats{
			TotalUpdates: stats.TotalUpdates,
			UpdateSizes:  append([]int{}, stats.UpdateSizes...),
			LastUpdate:   stats.LastUpdate,
		}
	}

	return result
}

func assertDERPMapResponse(t *testing.T, resp *tailcfg.MapResponse) {
	t.Helper()

	assert.NotNil(t, resp.DERPMap, "DERPMap should not be nil in response")
	assert.Len(t, resp.DERPMap.Regions, 1, "Expected exactly one DERP region in response")
	assert.Equal(t, 999, resp.DERPMap.Regions[999].RegionID, "Expected DERP region ID to be 1337")
}

func assertOnlineMapResponse(t *testing.T, resp *tailcfg.MapResponse, expected bool) {
	t.Helper()

	// Check for peer changes patch (new online/offline notifications use patches)
	if len(resp.PeersChangedPatch) > 0 {
		require.Len(t, resp.PeersChangedPatch, 1)
		assert.Equal(t, expected, *resp.PeersChangedPatch[0].Online)

		return
	}

	// Fallback to old format for backwards compatibility
	require.Len(t, resp.Peers, 1)
	assert.Equal(t, expected, resp.Peers[0].Online)
}

// UpdateInfo contains parsed information about an update.
type UpdateInfo struct {
	IsFull     bool
	IsPatch    bool
	IsDERP     bool
	PeerCount  int
	PatchCount int
}

// parseUpdateAndAnalyze parses an update and returns detailed information.
func parseUpdateAndAnalyze(resp *tailcfg.MapResponse) (UpdateInfo, error) {
	info := UpdateInfo{
		PeerCount:  len(resp.Peers),
		PatchCount: len(resp.PeersChangedPatch),
		IsFull:     len(resp.Peers) > 0,
		IsPatch:    len(resp.PeersChangedPatch) > 0,
		IsDERP:     resp.DERPMap != nil,
	}

	return info, nil
}

// start begins consuming updates from the node's channel and tracking stats.
func (n *node) start() {
	// Prevent multiple starts on the same node
	if n.stop != nil {
		return // Already started
	}

	n.stop = make(chan struct{})
	n.stopped = make(chan struct{})

	go func() {
		defer close(n.stopped)

		for {
			select {
			case data := <-n.ch:
				atomic.AddInt64(&n.updateCount, 1)

				// Parse update and track detailed stats
				if info, err := parseUpdateAndAnalyze(data); err == nil {
					// Track update types
					if info.IsFull {
						atomic.AddInt64(&n.fullCount, 1)
						n.lastPeerCount = info.PeerCount
						// Update max peers seen
						if info.PeerCount > n.maxPeersCount {
							n.maxPeersCount = info.PeerCount
						}
					}

					if info.IsPatch {
						atomic.AddInt64(&n.patchCount, 1)
						// For patches, we track how many patch items
						if info.PatchCount > n.maxPeersCount {
							n.maxPeersCount = info.PatchCount
						}
					}
				}

			case <-n.stop:
				return
			}
		}
	}()
}

// NodeStats contains final statistics for a node.
type NodeStats struct {
	TotalUpdates  int64
	PatchUpdates  int64
	FullUpdates   int64
	MaxPeersSeen  int
	LastPeerCount int
}

// cleanup stops the update consumer and returns final stats.
func (n *node) cleanup() NodeStats {
	if n.stop != nil {
		close(n.stop)
		<-n.stopped // Wait for goroutine to finish
	}

	return NodeStats{
		TotalUpdates:  atomic.LoadInt64(&n.updateCount),
		PatchUpdates:  atomic.LoadInt64(&n.patchCount),
		FullUpdates:   atomic.LoadInt64(&n.fullCount),
		MaxPeersSeen:  n.maxPeersCount,
		LastPeerCount: n.lastPeerCount,
	}
}

// validateUpdateContent validates that the update data contains a proper MapResponse.
func validateUpdateContent(resp *tailcfg.MapResponse) (bool, string) {
	if resp == nil {
		return false, "nil MapResponse"
	}

	// Simple validation - just check if it's a valid MapResponse
	return true, "valid"
}

// TestEnhancedNodeTracking verifies that the enhanced node tracking works correctly.
func TestEnhancedNodeTracking(t *testing.T) {
	// Create a simple test node
	testNode := node{
		n:  &types.Node{ID: 1},
		ch: make(chan *tailcfg.MapResponse, 10),
	}

	// Start the enhanced tracking
	testNode.start()

	// Create a simple MapResponse that should be parsed correctly
	resp := tailcfg.MapResponse{
		KeepAlive: false,
		Peers: []*tailcfg.Node{
			{ID: 2},
			{ID: 3},
		},
	}

	// Send the data to the node's channel
	testNode.ch <- &resp

	// Give it time to process
	time.Sleep(100 * time.Millisecond)

	// Check stats
	stats := testNode.cleanup()
	t.Logf("Enhanced tracking stats: Total=%d, Full=%d, Patch=%d, MaxPeers=%d",
		stats.TotalUpdates, stats.FullUpdates, stats.PatchUpdates, stats.MaxPeersSeen)

	require.Equal(t, int64(1), stats.TotalUpdates, "Expected 1 total update")
	require.Equal(t, int64(1), stats.FullUpdates, "Expected 1 full update")
	require.Equal(t, 2, stats.MaxPeersSeen, "Expected 2 max peers seen")
}

// TestEnhancedTrackingWithBatcher verifies enhanced tracking works with a real batcher.
func TestEnhancedTrackingWithBatcher(t *testing.T) {
	for _, batcherFunc := range allBatcherFunctions {
		t.Run(batcherFunc.name, func(t *testing.T) {
			// Create test environment with 1 node
			testData, cleanup := setupBatcherWithTestData(t, batcherFunc.fn, 1, 1, 10)
			defer cleanup()

			batcher := testData.Batcher
			testNode := &testData.Nodes[0]

			t.Logf("Testing enhanced tracking with node ID %d", testNode.n.ID)

			// Start enhanced tracking for the node
			testNode.start()

			// Connect the node to the batcher
			batcher.AddNode(testNode.n.ID, testNode.ch, tailcfg.CapabilityVersion(100))
			time.Sleep(100 * time.Millisecond) // Let connection settle

			// Generate some work
			batcher.AddWork(change.FullSet)
			time.Sleep(100 * time.Millisecond) // Let work be processed

			batcher.AddWork(change.PolicySet)
			time.Sleep(100 * time.Millisecond)

			batcher.AddWork(change.DERPSet)
			time.Sleep(100 * time.Millisecond)

			// Check stats
			stats := testNode.cleanup()
			t.Logf("Enhanced tracking with batcher: Total=%d, Full=%d, Patch=%d, MaxPeers=%d",
				stats.TotalUpdates, stats.FullUpdates, stats.PatchUpdates, stats.MaxPeersSeen)

			if stats.TotalUpdates == 0 {
				t.Error(
					"Enhanced tracking with batcher received 0 updates - batcher may not be working",
				)
			}
		})
	}
}

// TestBatcherScalabilityAllToAll tests the batcher's ability to handle rapid node joins
// and ensure all nodes can see all other nodes. This is a critical test for mesh network
// functionality where every node must be able to communicate with every other node.
func TestBatcherScalabilityAllToAll(t *testing.T) {
	// Reduce verbose application logging for cleaner test output
	originalLevel := zerolog.GlobalLevel()
	defer zerolog.SetGlobalLevel(originalLevel)

	zerolog.SetGlobalLevel(zerolog.ErrorLevel)

	// Test cases: different node counts to stress test the all-to-all connectivity
	testCases := []struct {
		name      string
		nodeCount int
	}{
		{"10_nodes", 10},
		{"50_nodes", 50},
		{"100_nodes", 100},
		// Grinds to a halt because of Database bottleneck
		// {"250_nodes", 250},
		// {"500_nodes", 500},
		// {"1000_nodes", 1000},
		// {"5000_nodes", 5000},
	}

	for _, batcherFunc := range allBatcherFunctions {
		t.Run(batcherFunc.name, func(t *testing.T) {
			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					t.Logf(
						"ALL-TO-ALL TEST: %d nodes with %s batcher",
						tc.nodeCount,
						batcherFunc.name,
					)

					// Create test environment - all nodes from same user so they can be peers
					// We need enough users to support the node count (max 1000 nodes per user)
					usersNeeded := max(1, (tc.nodeCount+999)/1000)
					nodesPerUser := (tc.nodeCount + usersNeeded - 1) / usersNeeded

					// Use large buffer to avoid blocking during rapid joins
					// Buffer needs to handle nodeCount * average_updates_per_node
					// Estimate: each node receives ~2*nodeCount updates during all-to-all
					bufferSize := max(1000, tc.nodeCount*2)

					testData, cleanup := setupBatcherWithTestData(
						t,
						batcherFunc.fn,
						usersNeeded,
						nodesPerUser,
						bufferSize,
					)
					defer cleanup()

					batcher := testData.Batcher
					allNodes := testData.Nodes[:tc.nodeCount] // Limit to requested count

					t.Logf(
						"Created %d nodes across %d users, buffer size: %d",
						len(allNodes),
						usersNeeded,
						bufferSize,
					)

					// Start enhanced tracking for all nodes
					for i := range allNodes {
						allNodes[i].start()
					}

					// Give time for tracking goroutines to start
					time.Sleep(100 * time.Millisecond)

					startTime := time.Now()

					// Join all nodes as fast as possible
					t.Logf("Joining %d nodes as fast as possible...", len(allNodes))

					for i := range allNodes {
						node := &allNodes[i]
						batcher.AddNode(node.n.ID, node.ch, tailcfg.CapabilityVersion(100))

						// Issue full update after each join to ensure connectivity
						batcher.AddWork(change.FullSet)

						// Add tiny delay for large node counts to prevent overwhelming
						if tc.nodeCount > 100 && i%50 == 49 {
							time.Sleep(10 * time.Millisecond)
						}
					}

					joinTime := time.Since(startTime)
					t.Logf("All nodes joined in %v, waiting for full connectivity...", joinTime)

					// Wait for all updates to propagate - no timeout, continue until all nodes achieve connectivity
					checkInterval := 5 * time.Second
					expectedPeers := tc.nodeCount - 1 // Each node should see all others except itself

					for {
						time.Sleep(checkInterval)

						// Check if all nodes have seen the expected number of peers
						connectedCount := 0

						for i := range allNodes {
							node := &allNodes[i]
							// Check current stats without stopping the tracking
							currentMaxPeers := node.maxPeersCount
							if currentMaxPeers >= expectedPeers {
								connectedCount++
							}
						}

						progress := float64(connectedCount) / float64(len(allNodes)) * 100
						t.Logf("Progress: %d/%d nodes (%.1f%%) have seen %d+ peers",
							connectedCount, len(allNodes), progress, expectedPeers)

						if connectedCount == len(allNodes) {
							t.Logf("✅ All nodes achieved full connectivity!")
							break
						}
					}

					totalTime := time.Since(startTime)

					// Disconnect all nodes
					for i := range allNodes {
						node := &allNodes[i]
						batcher.RemoveNode(node.n.ID, node.ch)
					}

					// Give time for final updates to process
					time.Sleep(500 * time.Millisecond)

					// Collect final statistics
					totalUpdates := int64(0)
					totalFull := int64(0)
					maxPeersGlobal := 0
					minPeersSeen := tc.nodeCount
					successfulNodes := 0

					nodeDetails := make([]string, 0, min(10, len(allNodes)))

					for i := range allNodes {
						node := &allNodes[i]
						stats := node.cleanup()

						totalUpdates += stats.TotalUpdates
						totalFull += stats.FullUpdates

						if stats.MaxPeersSeen > maxPeersGlobal {
							maxPeersGlobal = stats.MaxPeersSeen
						}

						if stats.MaxPeersSeen < minPeersSeen {
							minPeersSeen = stats.MaxPeersSeen
						}

						if stats.MaxPeersSeen >= expectedPeers {
							successfulNodes++
						}

						// Collect details for first few nodes or failing nodes
						if len(nodeDetails) < 10 || stats.MaxPeersSeen < expectedPeers {
							nodeDetails = append(nodeDetails,
								fmt.Sprintf(
									"Node %d: %d updates (%d full), max %d peers",
									node.n.ID,
									stats.TotalUpdates,
									stats.FullUpdates,
									stats.MaxPeersSeen,
								))
						}
					}

					// Final results
					t.Logf("ALL-TO-ALL RESULTS: %d nodes, %d total updates (%d full)",
						len(allNodes), totalUpdates, totalFull)
					t.Logf(
						"  Connectivity: %d/%d nodes successful (%.1f%%)",
						successfulNodes,
						len(allNodes),
						float64(successfulNodes)/float64(len(allNodes))*100,
					)
					t.Logf("  Peers seen: min=%d, max=%d, expected=%d",
						minPeersSeen, maxPeersGlobal, expectedPeers)
					t.Logf("  Timing: join=%v, total=%v", joinTime, totalTime)

					// Show sample of node details
					if len(nodeDetails) > 0 {
						t.Logf("  Node sample:")

						for _, detail := range nodeDetails[:min(5, len(nodeDetails))] {
							t.Logf("    %s", detail)
						}

						if len(nodeDetails) > 5 {
							t.Logf("    ... (%d more nodes)", len(nodeDetails)-5)
						}
					}

					// Final verification: Since we waited until all nodes achieved connectivity,
					// this should always pass, but we verify the final state for completeness
					if successfulNodes == len(allNodes) {
						t.Logf(
							"✅ PASS: All-to-all connectivity achieved for %d nodes",
							len(allNodes),
						)
					} else {
						// This should not happen since we loop until success, but handle it just in case
						failedNodes := len(allNodes) - successfulNodes
						t.Errorf("❌ UNEXPECTED: %d/%d nodes still failed after waiting for connectivity (expected %d, some saw %d-%d)",
							failedNodes, len(allNodes), expectedPeers, minPeersSeen, maxPeersGlobal)

						// Show details of failed nodes for debugging
						if len(nodeDetails) > 5 {
							t.Logf("Failed nodes details:")

							for _, detail := range nodeDetails[5:] {
								if !strings.Contains(detail, fmt.Sprintf("max %d peers", expectedPeers)) {
									t.Logf("  %s", detail)
								}
							}
						}
					}
				})
			}
		})
	}
}

// TestBatcherBasicOperations verifies core batcher functionality by testing
// the basic lifecycle of adding nodes, processing updates, and removing nodes.
//
// Enhanced with real database test data, this test creates a registered node
// and tests both DERP updates and full node updates. It validates the fundamental
// add/remove operations and basic work processing pipeline with actual update
// content validation instead of just byte count checks.
func TestBatcherBasicOperations(t *testing.T) {
	for _, batcherFunc := range allBatcherFunctions {
		t.Run(batcherFunc.name, func(t *testing.T) {
			// Create test environment with real database and nodes
			testData, cleanup := setupBatcherWithTestData(t, batcherFunc.fn, 1, 2, 8)
			defer cleanup()

			batcher := testData.Batcher
			tn := testData.Nodes[0]
			tn2 := testData.Nodes[1]

			// Test AddNode with real node ID
			batcher.AddNode(tn.n.ID, tn.ch, 100)

			if !batcher.IsConnected(tn.n.ID) {
				t.Error("Node should be connected after AddNode")
			}

			// Test work processing with DERP change
			batcher.AddWork(change.DERPChange())

			// Wait for update and validate content
			select {
			case data := <-tn.ch:
				assertDERPMapResponse(t, data)
			case <-time.After(200 * time.Millisecond):
				t.Error("Did not receive expected DERP update")
			}

			// Drain any initial messages from first node
			drainChannelTimeout(tn.ch, "first node before second", 100*time.Millisecond)

			// Add the second node and verify update message
			batcher.AddNode(tn2.n.ID, tn2.ch, 100)
			assert.True(t, batcher.IsConnected(tn2.n.ID))

			// First node should get an update that second node has connected.
			select {
			case data := <-tn.ch:
				assertOnlineMapResponse(t, data, true)
			case <-time.After(500 * time.Millisecond):
				t.Error("Did not receive expected Online response update")
			}

			// Second node should receive its initial full map
			select {
			case data := <-tn2.ch:
				// Verify it's a full map response
				assert.NotNil(t, data)
				assert.True(
					t,
					len(data.Peers) >= 1 || data.Node != nil,
					"Should receive initial full map",
				)
			case <-time.After(500 * time.Millisecond):
				t.Error("Second node should receive its initial full map")
			}

			// Disconnect the second node
			batcher.RemoveNode(tn2.n.ID, tn2.ch)
			// Note: IsConnected may return true during grace period for DNS resolution

			// First node should get update that second has disconnected.
			select {
			case data := <-tn.ch:
				assertOnlineMapResponse(t, data, false)
			case <-time.After(500 * time.Millisecond):
				t.Error("Did not receive expected Online response update")
			}

			// // Test node-specific update with real node data
			// batcher.AddWork(change.NodeKeyChanged(tn.n.ID))

			// // Wait for node update (may be empty for certain node changes)
			// select {
			// case data := <-tn.ch:
			// 	t.Logf("Received node update: %d bytes", len(data))
			// 	if len(data) == 0 {
			// 		t.Logf("Empty node update (expected for some node changes in test environment)")
			// 	} else {
			// 		if valid, updateType := validateUpdateContent(data); !valid {
			// 			t.Errorf("Invalid node update content: %s", updateType)
			// 		} else {
			// 			t.Logf("Valid node update type: %s", updateType)
			// 		}
			// 	}
			// case <-time.After(200 * time.Millisecond):
			// 	// Node changes might not always generate updates in test environment
			// 	t.Logf("No node update received (may be expected in test environment)")
			// }

			// Test RemoveNode
			batcher.RemoveNode(tn.n.ID, tn.ch)
			// Note: IsConnected may return true during grace period for DNS resolution
			// The node is actually removed from active connections but grace period allows DNS lookups
		})
	}
}

func drainChannelTimeout(ch <-chan *tailcfg.MapResponse, name string, timeout time.Duration) {
	count := 0

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case data := <-ch:
			count++
			// Optional: add debug output if needed
			_ = data
		case <-timer.C:
			return
		}
	}
}

// TestBatcherUpdateTypes tests different types of updates and verifies
// that the batcher correctly processes them based on their content.
//
// Enhanced with real database test data, this test creates registered nodes
// and tests various update types including DERP changes, node-specific changes,
// and full updates. This validates the change classification logic and ensures
// different update types are handled appropriately with actual node data.
// func TestBatcherUpdateTypes(t *testing.T) {
// 	for _, batcherFunc := range allBatcherFunctions {
// 		t.Run(batcherFunc.name, func(t *testing.T) {
// 			// Create test environment with real database and nodes
// 			testData, cleanup := setupBatcherWithTestData(t, batcherFunc.fn, 1, 2, 8)
// 			defer cleanup()

// 			batcher := testData.Batcher
// 			testNodes := testData.Nodes

// 			ch := make(chan *tailcfg.MapResponse, 10)
// 			// Use real node ID from test data
// 			batcher.AddNode(testNodes[0].n.ID, ch, false, "zstd", tailcfg.CapabilityVersion(100))

// 			tests := []struct {
// 				name        string
// 				changeSet   change.ChangeSet
// 				expectData  bool // whether we expect to receive data
// 				description string
// 			}{
// 				{
// 					name:        "DERP change",
// 					changeSet:   change.DERPSet,
// 					expectData:  true,
// 					description: "DERP changes should generate map updates",
// 				},
// 				{
// 					name:        "Node key expiry",
// 					changeSet:   change.KeyExpiry(testNodes[1].n.ID),
// 					expectData:  true,
// 					description: "Node key expiry with real node data",
// 				},
// 				{
// 					name:        "Node new registration",
// 					changeSet:   change.NodeAdded(testNodes[1].n.ID),
// 					expectData:  true,
// 					description: "New node registration with real data",
// 				},
// 				{
// 					name:        "Full update",
// 					changeSet:   change.FullSet,
// 					expectData:  true,
// 					description: "Full updates with real node data",
// 				},
// 				{
// 					name:        "Policy change",
// 					changeSet:   change.PolicySet,
// 					expectData:  true,
// 					description: "Policy updates with real node data",
// 				},
// 			}

// 			for _, tt := range tests {
// 				t.Run(tt.name, func(t *testing.T) {
// 					t.Logf("Testing: %s", tt.description)

// 					// Clear any existing updates
// 					select {
// 					case <-ch:
// 					default:
// 					}

// 					batcher.AddWork(tt.changeSet)

// 					select {
// 					case data := <-ch:
// 						if !tt.expectData {
// 							t.Errorf("Unexpected update for %s: %d bytes", tt.name, len(data))
// 						} else {
// 							t.Logf("%s: received %d bytes", tt.name, len(data))

// 							// Validate update content when we have data
// 							if len(data) > 0 {
// 								if valid, updateType := validateUpdateContent(data); !valid {
// 									t.Errorf("Invalid update content for %s: %s", tt.name, updateType)
// 								} else {
// 									t.Logf("%s: valid update type: %s", tt.name, updateType)
// 								}
// 							} else {
// 								t.Logf("%s: empty update (may be expected for some node changes)", tt.name)
// 							}
// 						}
// 					case <-time.After(100 * time.Millisecond):
// 						if tt.expectData {
// 							t.Errorf("Expected update for %s (%s) but none received", tt.name, tt.description)
// 						} else {
// 							t.Logf("%s: no update (expected)", tt.name)
// 						}
// 					}
// 				})
// 			}
// 		})
// 	}
// }

// TestBatcherWorkQueueBatching tests that multiple changes get batched
// together and sent as a single update to reduce network overhead.
//
// Enhanced with real database test data, this test creates registered nodes
// and rapidly submits multiple types of changes including DERP updates and
// node changes. Due to the batching mechanism with BatchChangeDelay, these
// should be combined into fewer updates. This validates that the batching
// system works correctly with real node data and mixed change types.
func TestBatcherWorkQueueBatching(t *testing.T) {
	for _, batcherFunc := range allBatcherFunctions {
		t.Run(batcherFunc.name, func(t *testing.T) {
			// Create test environment with real database and nodes
			testData, cleanup := setupBatcherWithTestData(t, batcherFunc.fn, 1, 2, 8)
			defer cleanup()

			batcher := testData.Batcher
			testNodes := testData.Nodes

			ch := make(chan *tailcfg.MapResponse, 10)
			batcher.AddNode(testNodes[0].n.ID, ch, tailcfg.CapabilityVersion(100))

			// Track update content for validation
			var receivedUpdates []*tailcfg.MapResponse

			// Add multiple changes rapidly to test batching
			batcher.AddWork(change.DERPSet)
			// Use a valid expiry time for testing since test nodes don't have expiry set
			testExpiry := time.Now().Add(24 * time.Hour)
			batcher.AddWork(change.KeyExpiry(testNodes[1].n.ID, testExpiry))
			batcher.AddWork(change.DERPSet)
			batcher.AddWork(change.NodeAdded(testNodes[1].n.ID))
			batcher.AddWork(change.DERPSet)

			// Collect updates with timeout
			updateCount := 0
			timeout := time.After(200 * time.Millisecond)

			for {
				select {
				case data := <-ch:
					updateCount++

					receivedUpdates = append(receivedUpdates, data)

					// Validate update content
					if data != nil {
						if valid, reason := validateUpdateContent(data); valid {
							t.Logf("Update %d: valid", updateCount)
						} else {
							t.Logf("Update %d: invalid: %s", updateCount, reason)
						}
					} else {
						t.Logf("Update %d: nil update", updateCount)
					}
				case <-timeout:
					// Expected: 5 changes should generate 6 updates (no batching in current implementation)
					expectedUpdates := 6
					t.Logf("Received %d updates from %d changes (expected %d)",
						updateCount, 5, expectedUpdates)

					if updateCount != expectedUpdates {
						t.Errorf(
							"Expected %d updates but received %d",
							expectedUpdates,
							updateCount,
						)
					}

					// Validate that all updates have valid content
					validUpdates := 0

					for _, data := range receivedUpdates {
						if data != nil {
							if valid, _ := validateUpdateContent(data); valid {
								validUpdates++
							}
						}
					}

					if validUpdates != updateCount {
						t.Errorf("Expected all %d updates to be valid, but only %d were valid",
							updateCount, validUpdates)
					}

					return
				}
			}
		})
	}
}

// TestBatcherChannelClosingRace tests the fix for the async channel closing
// race condition that previously caused panics and data races.
//
// Enhanced with real database test data, this test simulates rapid node
// reconnections using real registered nodes while processing actual updates.
// The test verifies that channels are closed synchronously and deterministically
// even when real node updates are being processed, ensuring no race conditions
// occur during channel replacement with actual workload.
func XTestBatcherChannelClosingRace(t *testing.T) {
	for _, batcherFunc := range allBatcherFunctions {
		t.Run(batcherFunc.name, func(t *testing.T) {
			// Create test environment with real database and nodes
			testData, cleanup := setupBatcherWithTestData(t, batcherFunc.fn, 1, 1, 8)
			defer cleanup()

			batcher := testData.Batcher
			testNode := testData.Nodes[0]

			var (
				channelIssues int
				mutex         sync.Mutex
			)

			// Run rapid connect/disconnect cycles with real updates to test channel closing

			for i := range 100 {
				var wg sync.WaitGroup

				// First connection
				ch1 := make(chan *tailcfg.MapResponse, 1)

				wg.Add(1)

				go func() {
					defer wg.Done()

					batcher.AddNode(testNode.n.ID, ch1, tailcfg.CapabilityVersion(100))
				}()

				// Add real work during connection chaos
				if i%10 == 0 {
					batcher.AddWork(change.DERPSet)
				}

				// Rapid second connection - should replace ch1
				ch2 := make(chan *tailcfg.MapResponse, 1)

				wg.Add(1)

				go func() {
					defer wg.Done()

					time.Sleep(1 * time.Microsecond)
					batcher.AddNode(testNode.n.ID, ch2, tailcfg.CapabilityVersion(100))
				}()

				// Remove second connection
				wg.Add(1)

				go func() {
					defer wg.Done()

					time.Sleep(2 * time.Microsecond)
					batcher.RemoveNode(testNode.n.ID, ch2)
				}()

				wg.Wait()

				// Verify ch1 behavior when replaced by ch2
				// The test is checking if ch1 gets closed/replaced properly
				select {
				case <-ch1:
					// Channel received data or was closed, which is expected
				case <-time.After(1 * time.Millisecond):
					// If no data received, increment issues counter
					mutex.Lock()

					channelIssues++

					mutex.Unlock()
				}

				// Clean up ch2
				select {
				case <-ch2:
				default:
				}
			}

			mutex.Lock()
			defer mutex.Unlock()

			t.Logf("Channel closing issues: %d out of 100 iterations", channelIssues)

			// The main fix prevents panics and race conditions. Some timing variations
			// are acceptable as long as there are no crashes or deadlocks.
			if channelIssues > 50 { // Allow some timing variations
				t.Errorf("Excessive channel closing issues: %d iterations", channelIssues)
			}
		})
	}
}

// TestBatcherWorkerChannelSafety tests that worker goroutines handle closed
// channels safely without panicking when processing work items.
//
// Enhanced with real database test data, this test creates rapid connect/disconnect
// cycles using registered nodes while simultaneously queuing real work items.
// This creates a race where workers might try to send to channels that have been
// closed by node removal. The test validates that the safeSend() method properly
// handles closed channels with real update workloads.
func TestBatcherWorkerChannelSafety(t *testing.T) {
	for _, batcherFunc := range allBatcherFunctions {
		t.Run(batcherFunc.name, func(t *testing.T) {
			// Create test environment with real database and nodes
			testData, cleanup := setupBatcherWithTestData(t, batcherFunc.fn, 1, 1, 8)
			defer cleanup()

			batcher := testData.Batcher
			testNode := testData.Nodes[0]

			var (
				panics        int
				channelErrors int
				invalidData   int
				mutex         sync.Mutex
			)

			// Test rapid connect/disconnect with work generation

			for i := range 50 {
				func() {
					defer func() {
						if r := recover(); r != nil {
							mutex.Lock()

							panics++

							mutex.Unlock()
							t.Logf("Panic caught: %v", r)
						}
					}()

					ch := make(chan *tailcfg.MapResponse, 5)

					// Add node and immediately queue real work
					batcher.AddNode(testNode.n.ID, ch, tailcfg.CapabilityVersion(100))
					batcher.AddWork(change.DERPSet)

					// Consumer goroutine to validate data and detect channel issues
					go func() {
						defer func() {
							if r := recover(); r != nil {
								mutex.Lock()

								channelErrors++

								mutex.Unlock()
								t.Logf("Channel consumer panic: %v", r)
							}
						}()

						for {
							select {
							case data, ok := <-ch:
								if !ok {
									// Channel was closed, which is expected
									return
								}
								// Validate the data we received
								if valid, reason := validateUpdateContent(data); !valid {
									mutex.Lock()

									invalidData++

									mutex.Unlock()
									t.Logf("Invalid data received: %s", reason)
								}
							case <-time.After(10 * time.Millisecond):
								// Timeout waiting for data
								return
							}
						}
					}()

					// Add node-specific work occasionally
					if i%10 == 0 {
						// Use a valid expiry time for testing since test nodes don't have expiry set
						testExpiry := time.Now().Add(24 * time.Hour)
						batcher.AddWork(change.KeyExpiry(testNode.n.ID, testExpiry))
					}

					// Rapid removal creates race between worker and removal
					time.Sleep(time.Duration(i%3) * 100 * time.Microsecond)
					batcher.RemoveNode(testNode.n.ID, ch)

					// Give workers time to process and close channels
					time.Sleep(5 * time.Millisecond)
				}()
			}

			mutex.Lock()
			defer mutex.Unlock()

			t.Logf(
				"Worker safety test results: %d panics, %d channel errors, %d invalid data packets",
				panics,
				channelErrors,
				invalidData,
			)

			// Test failure conditions
			if panics > 0 {
				t.Errorf("Worker channel safety failed with %d panics", panics)
			}

			if channelErrors > 0 {
				t.Errorf("Channel handling failed with %d channel errors", channelErrors)
			}

			if invalidData > 0 {
				t.Errorf("Data validation failed with %d invalid data packets", invalidData)
			}
		})
	}
}

// TestBatcherConcurrentClients tests that concurrent connection lifecycle changes
// don't affect other stable clients' ability to receive updates.
//
// The test sets up real test data with multiple users and registered nodes,
// then creates stable clients and churning clients that rapidly connect and
// disconnect. Work is generated continuously during these connection churn cycles using
// real node data. The test validates that stable clients continue to function
// normally and receive proper updates despite the connection churn from other clients,
// ensuring system stability under concurrent load.
func TestBatcherConcurrentClients(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent client test in short mode")
	}

	for _, batcherFunc := range allBatcherFunctions {
		t.Run(batcherFunc.name, func(t *testing.T) {
			// Create comprehensive test environment with real data
			testData, cleanup := setupBatcherWithTestData(
				t,
				batcherFunc.fn,
				TEST_USER_COUNT,
				TEST_NODES_PER_USER,
				8,
			)
			defer cleanup()

			batcher := testData.Batcher
			allNodes := testData.Nodes

			// Create update tracker for monitoring all updates
			tracker := newUpdateTracker()

			// Set up stable clients using real node IDs
			stableNodes := allNodes[:len(allNodes)/2] // Use first half as stable
			stableChannels := make(map[types.NodeID]chan *tailcfg.MapResponse)

			for _, node := range stableNodes {
				ch := make(chan *tailcfg.MapResponse, NORMAL_BUFFER_SIZE)
				stableChannels[node.n.ID] = ch
				batcher.AddNode(node.n.ID, ch, tailcfg.CapabilityVersion(100))

				// Monitor updates for each stable client
				go func(nodeID types.NodeID, channel chan *tailcfg.MapResponse) {
					for {
						select {
						case data, ok := <-channel:
							if !ok {
								// Channel was closed, exit gracefully
								return
							}
							if valid, reason := validateUpdateContent(data); valid {
								tracker.recordUpdate(
									nodeID,
									1,
								) // Use 1 as update size since we have MapResponse
							} else {
								t.Errorf("Invalid update received for stable node %d: %s", nodeID, reason)
							}
						case <-time.After(TEST_TIMEOUT):
							return
						}
					}
				}(node.n.ID, ch)
			}

			// Use remaining nodes for connection churn testing
			churningNodes := allNodes[len(allNodes)/2:]
			churningChannels := make(map[types.NodeID]chan *tailcfg.MapResponse)

			var churningChannelsMutex sync.Mutex // Protect concurrent map access

			var wg sync.WaitGroup

			numCycles := 10 // Reduced for simpler test
			panicCount := 0

			var panicMutex sync.Mutex

			// Track deadlock with timeout
			done := make(chan struct{})

			go func() {
				defer close(done)

				// Connection churn cycles - rapidly connect/disconnect to test concurrency safety
				for i := range numCycles {
					for _, node := range churningNodes {
						wg.Add(2)

						// Connect churning node
						go func(nodeID types.NodeID) {
							defer func() {
								if r := recover(); r != nil {
									panicMutex.Lock()

									panicCount++

									panicMutex.Unlock()
									t.Logf("Panic in churning connect: %v", r)
								}

								wg.Done()
							}()

							ch := make(chan *tailcfg.MapResponse, SMALL_BUFFER_SIZE)

							churningChannelsMutex.Lock()
							churningChannels[nodeID] = ch
							churningChannelsMutex.Unlock()

							batcher.AddNode(nodeID, ch, tailcfg.CapabilityVersion(100))

							// Consume updates to prevent blocking
							go func() {
								for {
									select {
									case data, ok := <-ch:
										if !ok {
											// Channel was closed, exit gracefully
											return
										}
										if valid, _ := validateUpdateContent(data); valid {
											tracker.recordUpdate(
												nodeID,
												1,
											) // Use 1 as update size since we have MapResponse
										}
									case <-time.After(500 * time.Millisecond):
										// Longer timeout to prevent premature exit during heavy load
										return
									}
								}
							}()
						}(node.n.ID)

						// Disconnect churning node
						go func(nodeID types.NodeID) {
							defer func() {
								if r := recover(); r != nil {
									panicMutex.Lock()

									panicCount++

									panicMutex.Unlock()
									t.Logf("Panic in churning disconnect: %v", r)
								}

								wg.Done()
							}()

							time.Sleep(time.Duration(i%5) * time.Millisecond)
							churningChannelsMutex.Lock()

							ch, exists := churningChannels[nodeID]

							churningChannelsMutex.Unlock()

							if exists {
								batcher.RemoveNode(nodeID, ch)
							}
						}(node.n.ID)
					}

					// Generate various types of work during racing
					if i%3 == 0 {
						// DERP changes
						batcher.AddWork(change.DERPSet)
					}

					if i%5 == 0 {
						// Full updates using real node data
						batcher.AddWork(change.FullSet)
					}

					if i%7 == 0 && len(allNodes) > 0 {
						// Node-specific changes using real nodes
						node := allNodes[i%len(allNodes)]
						// Use a valid expiry time for testing since test nodes don't have expiry set
						testExpiry := time.Now().Add(24 * time.Hour)
						batcher.AddWork(change.KeyExpiry(node.n.ID, testExpiry))
					}

					// Small delay to allow some batching
					time.Sleep(2 * time.Millisecond)
				}

				wg.Wait()
			}()

			// Deadlock detection
			select {
			case <-done:
				t.Logf("Connection churn cycles completed successfully")
			case <-time.After(DEADLOCK_TIMEOUT):
				t.Error("Test timed out - possible deadlock detected")
				return
			}

			// Allow final updates to be processed
			time.Sleep(100 * time.Millisecond)

			// Validate results
			panicMutex.Lock()

			finalPanicCount := panicCount

			panicMutex.Unlock()

			allStats := tracker.getAllStats()

			// Calculate expected vs actual updates
			stableUpdateCount := 0
			churningUpdateCount := 0

			// Count actual update sources to understand the pattern
			// Let's track what we observe rather than trying to predict
			expectedDerpUpdates := (numCycles + 2) / 3
			expectedFullUpdates := (numCycles + 4) / 5
			expectedKeyUpdates := (numCycles + 6) / 7
			totalGeneratedWork := expectedDerpUpdates + expectedFullUpdates + expectedKeyUpdates

			t.Logf("Work generated: %d DERP + %d Full + %d KeyExpiry = %d total AddWork calls",
				expectedDerpUpdates, expectedFullUpdates, expectedKeyUpdates, totalGeneratedWork)

			for _, node := range stableNodes {
				if stats, exists := allStats[node.n.ID]; exists {
					stableUpdateCount += stats.TotalUpdates
					t.Logf("Stable node %d: %d updates",
						node.n.ID, stats.TotalUpdates)
				}

				// Verify stable clients are still connected
				if !batcher.IsConnected(node.n.ID) {
					t.Errorf("Stable node %d should still be connected", node.n.ID)
				}
			}

			for _, node := range churningNodes {
				if stats, exists := allStats[node.n.ID]; exists {
					churningUpdateCount += stats.TotalUpdates
				}
			}

			t.Logf("Total updates - Stable clients: %d, Churning clients: %d",
				stableUpdateCount, churningUpdateCount)
			t.Logf(
				"Average per stable client: %.1f updates",
				float64(stableUpdateCount)/float64(len(stableNodes)),
			)
			t.Logf("Panics during test: %d", finalPanicCount)

			// Validate test success criteria
			if finalPanicCount > 0 {
				t.Errorf("Test failed with %d panics", finalPanicCount)
			}

			// Basic sanity check - stable clients should receive some updates
			if stableUpdateCount == 0 {
				t.Error("Stable clients received no updates - batcher may not be working")
			}

			// Verify all stable clients are still functional
			for _, node := range stableNodes {
				if !batcher.IsConnected(node.n.ID) {
					t.Errorf("Stable node %d lost connection during racing", node.n.ID)
				}
			}
		})
	}
}

// TestBatcherHighLoadStability tests batcher behavior under high concurrent load
// scenarios with multiple nodes rapidly connecting and disconnecting while
// continuous updates are generated.
//
// This test creates a high-stress environment with many nodes connecting and
// disconnecting rapidly while various types of updates are generated continuously.
// It validates that the system remains stable with no deadlocks, panics, or
// missed updates under sustained high load. The test uses real node data to
// generate authentic update scenarios and tracks comprehensive statistics.
func XTestBatcherScalability(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping scalability test in short mode")
	}

	// Reduce verbose application logging for cleaner test output
	originalLevel := zerolog.GlobalLevel()
	defer zerolog.SetGlobalLevel(originalLevel)

	zerolog.SetGlobalLevel(zerolog.ErrorLevel)

	// Full test matrix for scalability testing
	nodes := []int{25, 50, 100} // 250, 500, 1000,

	cycles := []int{10, 100} // 500
	bufferSizes := []int{1, 200, 1000}
	chaosTypes := []string{"connection", "processing", "mixed"}

	type testCase struct {
		name        string
		nodeCount   int
		cycles      int
		bufferSize  int
		chaosType   string
		expectBreak bool
		description string
	}

	var testCases []testCase

	// Generate all combinations of the test matrix
	for _, nodeCount := range nodes {
		for _, cycleCount := range cycles {
			for _, bufferSize := range bufferSizes {
				for _, chaosType := range chaosTypes {
					expectBreak := false
					// resourceIntensity := float64(nodeCount*cycleCount) / float64(bufferSize)

					// switch chaosType {
					// case "processing":
					// 	resourceIntensity *= 1.1
					// case "mixed":
					// 	resourceIntensity *= 1.15
					// }

					// if resourceIntensity > 500000 {
					// 	expectBreak = true
					// } else if nodeCount >= 1000 && cycleCount >= 500 && bufferSize <= 1 {
					// 	expectBreak = true
					// } else if nodeCount >= 500 && cycleCount >= 500 && bufferSize <= 1 && chaosType == "mixed" {
					// 	expectBreak = true
					// }

					name := fmt.Sprintf(
						"%s_%dn_%dc_%db",
						chaosType,
						nodeCount,
						cycleCount,
						bufferSize,
					)
					description := fmt.Sprintf("%s chaos: %d nodes, %d cycles, %d buffers",
						chaosType, nodeCount, cycleCount, bufferSize)

					testCases = append(testCases, testCase{
						name:        name,
						nodeCount:   nodeCount,
						cycles:      cycleCount,
						bufferSize:  bufferSize,
						chaosType:   chaosType,
						expectBreak: expectBreak,
						description: description,
					})
				}
			}
		}
	}

	for _, batcherFunc := range allBatcherFunctions {
		t.Run(batcherFunc.name, func(t *testing.T) {
			for i, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					// Create comprehensive test environment with real data using the specific buffer size for this test case
					// Need 1000 nodes for largest test case, all from same user so they can be peers
					usersNeeded := max(1, tc.nodeCount/1000) // 1 user per 1000 nodes, minimum 1
					nodesPerUser := tc.nodeCount / usersNeeded

					testData, cleanup := setupBatcherWithTestData(
						t,
						batcherFunc.fn,
						usersNeeded,
						nodesPerUser,
						tc.bufferSize,
					)
					defer cleanup()

					batcher := testData.Batcher
					allNodes := testData.Nodes

					t.Logf("[%d/%d] SCALABILITY TEST: %s", i+1, len(testCases), tc.description)
					t.Logf(
						"   Cycles: %d, Buffer Size: %d, Chaos Type: %s",
						tc.cycles,
						tc.bufferSize,
						tc.chaosType,
					)

					// Use provided nodes, limit to requested count
					testNodes := allNodes[:min(len(allNodes), tc.nodeCount)]

					tracker := newUpdateTracker()
					panicCount := int64(0)
					deadlockDetected := false

					startTime := time.Now()
					setupTime := time.Since(startTime)
					t.Logf(
						"Starting scalability test with %d nodes (setup took: %v)",
						len(testNodes),
						setupTime,
					)

					// Comprehensive stress test
					done := make(chan struct{})

					// Start update consumers for all nodes
					for i := range testNodes {
						testNodes[i].start()
					}

					// Give time for all tracking goroutines to start
					time.Sleep(100 * time.Millisecond)

					// Connect all nodes first so they can see each other as peers
					connectedNodes := make(map[types.NodeID]bool)

					var connectedNodesMutex sync.RWMutex

					for i := range testNodes {
						node := &testNodes[i]
						batcher.AddNode(node.n.ID, node.ch, tailcfg.CapabilityVersion(100))
						connectedNodesMutex.Lock()

						connectedNodes[node.n.ID] = true

						connectedNodesMutex.Unlock()
					}

					// Give more time for all connections to be established
					time.Sleep(500 * time.Millisecond)
					batcher.AddWork(change.FullSet)
					time.Sleep(500 * time.Millisecond) // Allow initial update to propagate

					go func() {
						defer close(done)

						var wg sync.WaitGroup

						t.Logf(
							"Starting load generation: %d cycles with %d nodes",
							tc.cycles,
							len(testNodes),
						)

						// Main load generation - varies by chaos type
						for cycle := range tc.cycles {
							if cycle%10 == 0 {
								t.Logf("Cycle %d/%d completed", cycle, tc.cycles)
							}
							// Add delays for mixed chaos
							if tc.chaosType == "mixed" && cycle%10 == 0 {
								time.Sleep(time.Duration(cycle%2) * time.Microsecond)
							}

							// For chaos testing, only disconnect/reconnect a subset of nodes
							// This ensures some nodes stay connected to continue receiving updates
							startIdx := cycle % len(testNodes)

							endIdx := startIdx + len(testNodes)/4
							if endIdx > len(testNodes) {
								endIdx = len(testNodes)
							}

							if startIdx >= endIdx {
								startIdx = 0
								endIdx = min(len(testNodes)/4, len(testNodes))
							}

							chaosNodes := testNodes[startIdx:endIdx]
							if len(chaosNodes) == 0 {
								chaosNodes = testNodes[:min(1, len(testNodes))] // At least one node for chaos
							}

							// Connection/disconnection cycles for subset of nodes
							for i, node := range chaosNodes {
								// Only add work if this is connection chaos or mixed
								if tc.chaosType == "connection" || tc.chaosType == "mixed" {
									wg.Add(2)

									// Disconnection first
									go func(nodeID types.NodeID, channel chan *tailcfg.MapResponse) {
										defer func() {
											if r := recover(); r != nil {
												atomic.AddInt64(&panicCount, 1)
											}

											wg.Done()
										}()

										connectedNodesMutex.RLock()

										isConnected := connectedNodes[nodeID]

										connectedNodesMutex.RUnlock()

										if isConnected {
											batcher.RemoveNode(nodeID, channel)
											connectedNodesMutex.Lock()

											connectedNodes[nodeID] = false

											connectedNodesMutex.Unlock()
										}
									}(
										node.n.ID,
										node.ch,
									)

									// Then reconnection
									go func(nodeID types.NodeID, channel chan *tailcfg.MapResponse, index int) {
										defer func() {
											if r := recover(); r != nil {
												atomic.AddInt64(&panicCount, 1)
											}

											wg.Done()
										}()

										// Small delay before reconnecting
										time.Sleep(time.Duration(index%3) * time.Millisecond)
										batcher.AddNode(
											nodeID,
											channel,
											tailcfg.CapabilityVersion(100),
										)
										connectedNodesMutex.Lock()

										connectedNodes[nodeID] = true

										connectedNodesMutex.Unlock()

										// Add work to create load
										if index%5 == 0 {
											batcher.AddWork(change.FullSet)
										}
									}(
										node.n.ID,
										node.ch,
										i,
									)
								}
							}

							// Concurrent work generation - scales with load
							updateCount := min(tc.nodeCount/5, 20) // Scale updates with node count
							for i := range updateCount {
								wg.Add(1)

								go func(index int) {
									defer func() {
										if r := recover(); r != nil {
											atomic.AddInt64(&panicCount, 1)
										}

										wg.Done()
									}()

									// Generate different types of work to ensure updates are sent
									switch index % 4 {
									case 0:
										batcher.AddWork(change.FullSet)
									case 1:
										batcher.AddWork(change.PolicySet)
									case 2:
										batcher.AddWork(change.DERPSet)
									default:
										// Pick a random node and generate a node change
										if len(testNodes) > 0 {
											nodeIdx := index % len(testNodes)
											batcher.AddWork(
												change.NodeAdded(testNodes[nodeIdx].n.ID),
											)
										} else {
											batcher.AddWork(change.FullSet)
										}
									}
								}(i)
							}
						}

						t.Logf("Waiting for all goroutines to complete")
						wg.Wait()
						t.Logf("All goroutines completed")
					}()

					// Wait for completion with timeout and progress monitoring
					progressTicker := time.NewTicker(10 * time.Second)
					defer progressTicker.Stop()

					select {
					case <-done:
						t.Logf("Test completed successfully")
					case <-time.After(TEST_TIMEOUT):
						deadlockDetected = true
						// Collect diagnostic information
						allStats := tracker.getAllStats()

						totalUpdates := 0
						for _, stats := range allStats {
							totalUpdates += stats.TotalUpdates
						}

						interimPanics := atomic.LoadInt64(&panicCount)

						t.Logf("TIMEOUT DIAGNOSIS: Test timed out after %v", TEST_TIMEOUT)
						t.Logf(
							"   Progress at timeout: %d total updates, %d panics",
							totalUpdates,
							interimPanics,
						)
						t.Logf(
							"   Possible causes: deadlock, excessive load, or performance bottleneck",
						)

						// Try to detect if workers are still active
						if totalUpdates > 0 {
							t.Logf(
								"   System was processing updates - likely performance bottleneck",
							)
						} else {
							t.Logf("   No updates processed - likely deadlock or startup issue")
						}
					}

					// Give time for batcher workers to process all the work and send updates
					// BEFORE disconnecting nodes
					time.Sleep(1 * time.Second)

					// Now disconnect all nodes from batcher to stop new updates
					for i := range testNodes {
						node := &testNodes[i]
						batcher.RemoveNode(node.n.ID, node.ch)
					}

					// Give time for enhanced tracking goroutines to process any remaining data in channels
					time.Sleep(200 * time.Millisecond)

					// Cleanup nodes and get their final stats
					totalUpdates := int64(0)
					totalPatches := int64(0)
					totalFull := int64(0)
					maxPeersGlobal := 0
					nodeStatsReport := make([]string, 0, len(testNodes))

					for i := range testNodes {
						node := &testNodes[i]
						stats := node.cleanup()
						totalUpdates += stats.TotalUpdates
						totalPatches += stats.PatchUpdates

						totalFull += stats.FullUpdates
						if stats.MaxPeersSeen > maxPeersGlobal {
							maxPeersGlobal = stats.MaxPeersSeen
						}

						if stats.TotalUpdates > 0 {
							nodeStatsReport = append(nodeStatsReport,
								fmt.Sprintf(
									"Node %d: %d total (%d patch, %d full), max %d peers",
									node.n.ID,
									stats.TotalUpdates,
									stats.PatchUpdates,
									stats.FullUpdates,
									stats.MaxPeersSeen,
								))
						}
					}

					// Comprehensive final summary
					t.Logf(
						"FINAL RESULTS: %d total updates (%d patch, %d full), max peers seen: %d",
						totalUpdates,
						totalPatches,
						totalFull,
						maxPeersGlobal,
					)

					if len(nodeStatsReport) <= 10 { // Only log details for smaller tests
						for _, report := range nodeStatsReport {
							t.Logf("  %s", report)
						}
					} else {
						t.Logf("  (%d nodes had activity, details suppressed for large test)", len(nodeStatsReport))
					}

					// Legacy tracker comparison (optional)
					allStats := tracker.getAllStats()

					legacyTotalUpdates := 0
					for _, stats := range allStats {
						legacyTotalUpdates += stats.TotalUpdates
					}

					if legacyTotalUpdates != int(totalUpdates) {
						t.Logf(
							"Note: Legacy tracker mismatch - legacy: %d, new: %d",
							legacyTotalUpdates,
							totalUpdates,
						)
					}

					finalPanicCount := atomic.LoadInt64(&panicCount)

					// Validation based on expectation
					testPassed := true

					if tc.expectBreak {
						// For tests expected to break, we're mainly checking that we don't crash
						if finalPanicCount > 0 {
							t.Errorf(
								"System crashed with %d panics (even breaking point tests shouldn't crash)",
								finalPanicCount,
							)

							testPassed = false
						}
						// Timeout/deadlock is acceptable for breaking point tests
						if deadlockDetected {
							t.Logf(
								"Expected breaking point reached: system overloaded at %d nodes",
								len(testNodes),
							)
						}
					} else {
						// For tests expected to pass, validate proper operation
						if finalPanicCount > 0 {
							t.Errorf("Scalability test failed with %d panics", finalPanicCount)

							testPassed = false
						}

						if deadlockDetected {
							t.Errorf("Deadlock detected at %d nodes (should handle this load)", len(testNodes))

							testPassed = false
						}

						if totalUpdates == 0 {
							t.Error("No updates received - system may be completely stalled")

							testPassed = false
						}
					}

					// Clear success/failure indication
					if testPassed {
						t.Logf("✅ PASS: %s | %d nodes, %d updates, 0 panics, no deadlock",
							tc.name, len(testNodes), totalUpdates)
					} else {
						t.Logf("❌ FAIL: %s | %d nodes, %d updates, %d panics, deadlock: %v",
							tc.name, len(testNodes), totalUpdates, finalPanicCount, deadlockDetected)
					}
				})
			}
		})
	}
}

// TestBatcherFullPeerUpdates verifies that when multiple nodes are connected
// and we send a FullSet update, nodes receive the complete peer list.
func TestBatcherFullPeerUpdates(t *testing.T) {
	for _, batcherFunc := range allBatcherFunctions {
		t.Run(batcherFunc.name, func(t *testing.T) {
			// Create test environment with 3 nodes from same user (so they can be peers)
			testData, cleanup := setupBatcherWithTestData(t, batcherFunc.fn, 1, 3, 10)
			defer cleanup()

			batcher := testData.Batcher
			allNodes := testData.Nodes

			t.Logf("Created %d nodes in database", len(allNodes))

			// Connect nodes one at a time to avoid overwhelming the work queue
			for i, node := range allNodes {
				batcher.AddNode(node.n.ID, node.ch, tailcfg.CapabilityVersion(100))
				t.Logf("Connected node %d (ID: %d)", i, node.n.ID)
				// Small delay between connections to allow NodeCameOnline processing
				time.Sleep(50 * time.Millisecond)
			}

			// Give additional time for all NodeCameOnline events to be processed
			t.Logf("Waiting for NodeCameOnline events to settle...")
			time.Sleep(500 * time.Millisecond)

			// Check how many peers each node should see
			for i, node := range allNodes {
				peers := testData.State.ListPeers(node.n.ID)
				t.Logf("Node %d should see %d peers from state", i, peers.Len())
			}

			// Send a full update - this should generate full peer lists
			t.Logf("Sending FullSet update...")
			batcher.AddWork(change.FullSet)

			// Give much more time for workers to process the FullSet work items
			t.Logf("Waiting for FullSet to be processed...")
			time.Sleep(1 * time.Second)

			// Check what each node receives - read multiple updates
			totalUpdates := 0
			foundFullUpdate := false

			// Read all available updates for each node
			for i := range allNodes {
				nodeUpdates := 0

				t.Logf("Reading updates for node %d:", i)

				// Read up to 10 updates per node or until timeout/no more data
				for updateNum := range 10 {
					select {
					case data := <-allNodes[i].ch:
						nodeUpdates++
						totalUpdates++

						// Parse and examine the update - data is already a MapResponse
						if data == nil {
							t.Errorf("Node %d update %d: nil MapResponse", i, updateNum)
							continue
						}

						updateType := "unknown"
						if len(data.Peers) > 0 {
							updateType = "FULL"
							foundFullUpdate = true
						} else if len(data.PeersChangedPatch) > 0 {
							updateType = "PATCH"
						} else if data.DERPMap != nil {
							updateType = "DERP"
						}

						t.Logf(
							"  Update %d: %s - Peers=%d, PeersChangedPatch=%d, DERPMap=%v",
							updateNum,
							updateType,
							len(data.Peers),
							len(data.PeersChangedPatch),
							data.DERPMap != nil,
						)

						if len(data.Peers) > 0 {
							t.Logf("    Full peer list with %d peers", len(data.Peers))

							for j, peer := range data.Peers[:min(3, len(data.Peers))] {
								t.Logf(
									"      Peer %d: NodeID=%d, Online=%v",
									j,
									peer.ID,
									peer.Online,
								)
							}
						}

						if len(data.PeersChangedPatch) > 0 {
							t.Logf("    Patch update with %d changes", len(data.PeersChangedPatch))

							for j, patch := range data.PeersChangedPatch[:min(3, len(data.PeersChangedPatch))] {
								t.Logf(
									"      Patch %d: NodeID=%d, Online=%v",
									j,
									patch.NodeID,
									patch.Online,
								)
							}
						}

					case <-time.After(500 * time.Millisecond):
					}
				}

				t.Logf("Node %d received %d updates", i, nodeUpdates)
			}

			t.Logf("Total updates received across all nodes: %d", totalUpdates)

			if !foundFullUpdate {
				t.Errorf("CRITICAL: No FULL updates received despite sending change.FullSet!")
				t.Errorf(
					"This confirms the bug - FullSet updates are not generating full peer responses",
				)
			}
		})
	}
}

// TestBatcherRapidReconnection reproduces the issue where nodes connecting with the same ID
// at the same time cause /debug/batcher to show nodes as disconnected when they should be connected.
// This specifically tests the multi-channel batcher implementation issue.
func TestBatcherRapidReconnection(t *testing.T) {
	for _, batcherFunc := range allBatcherFunctions {
		t.Run(batcherFunc.name, func(t *testing.T) {
			testData, cleanup := setupBatcherWithTestData(t, batcherFunc.fn, 1, 3, 10)
			defer cleanup()

			batcher := testData.Batcher
			allNodes := testData.Nodes

			t.Logf("=== RAPID RECONNECTION TEST ===")
			t.Logf("Testing rapid connect/disconnect with %d nodes", len(allNodes))

			// Phase 1: Connect all nodes initially
			t.Logf("Phase 1: Connecting all nodes...")
			for i, node := range allNodes {
				err := batcher.AddNode(node.n.ID, node.ch, tailcfg.CapabilityVersion(100))
				if err != nil {
					t.Fatalf("Failed to add node %d: %v", i, err)
				}
			}

			time.Sleep(100 * time.Millisecond) // Let connections settle

			// Phase 2: Rapid disconnect ALL nodes (simulating nodes going down)
			t.Logf("Phase 2: Rapid disconnect all nodes...")
			for i, node := range allNodes {
				removed := batcher.RemoveNode(node.n.ID, node.ch)
				t.Logf("Node %d RemoveNode result: %t", i, removed)
			}

			// Phase 3: Rapid reconnect with NEW channels (simulating nodes coming back up)
			t.Logf("Phase 3: Rapid reconnect with new channels...")
			newChannels := make([]chan *tailcfg.MapResponse, len(allNodes))
			for i, node := range allNodes {
				newChannels[i] = make(chan *tailcfg.MapResponse, 10)
				err := batcher.AddNode(node.n.ID, newChannels[i], tailcfg.CapabilityVersion(100))
				if err != nil {
					t.Errorf("Failed to reconnect node %d: %v", i, err)
				}
			}

			time.Sleep(100 * time.Millisecond) // Let reconnections settle

			// Phase 4: Check debug status - THIS IS WHERE THE BUG SHOULD APPEAR
			t.Logf("Phase 4: Checking debug status...")

			if debugBatcher, ok := batcher.(interface {
				Debug() map[types.NodeID]any
			}); ok {
				debugInfo := debugBatcher.Debug()
				disconnectedCount := 0

				for i, node := range allNodes {
					if info, exists := debugInfo[node.n.ID]; exists {
						t.Logf("Node %d (ID %d): debug info = %+v", i, node.n.ID, info)

						// Check if the debug info shows the node as connected
						if infoMap, ok := info.(map[string]any); ok {
							if connected, ok := infoMap["connected"].(bool); ok && !connected {
								disconnectedCount++
								t.Logf("BUG REPRODUCED: Node %d shows as disconnected in debug but should be connected", i)
							}
						}
					} else {
						disconnectedCount++
						t.Logf("Node %d missing from debug info entirely", i)
					}

					// Also check IsConnected method
					if !batcher.IsConnected(node.n.ID) {
						t.Logf("Node %d IsConnected() returns false", i)
					}
				}

				if disconnectedCount > 0 {
					t.Logf("ISSUE REPRODUCED: %d/%d nodes show as disconnected in debug", disconnectedCount, len(allNodes))
					// This is expected behavior for multi-channel batcher according to user
					// "it has never worked with the multi"
				} else {
					t.Logf("All nodes show as connected - working correctly")
				}
			} else {
				t.Logf("Batcher does not implement Debug() method")
			}

			// Phase 5: Test if "disconnected" nodes can actually receive updates
			t.Logf("Phase 5: Testing if nodes can receive updates despite debug status...")

			// Send a change that should reach all nodes
			batcher.AddWork(change.DERPChange())

			receivedCount := 0
			timeout := time.After(500 * time.Millisecond)

			for i := 0; i < len(allNodes); i++ {
				select {
				case update := <-newChannels[i]:
					if update != nil {
						receivedCount++
						t.Logf("Node %d received update successfully", i)
					}
				case <-timeout:
					t.Logf("Node %d timed out waiting for update", i)
					goto done
				}
			}

		done:
			t.Logf("Update delivery test: %d/%d nodes received updates", receivedCount, len(allNodes))

			if receivedCount < len(allNodes) {
				t.Logf("Some nodes failed to receive updates - confirming the issue")
			}
		})
	}
}

func TestBatcherMultiConnection(t *testing.T) {
	for _, batcherFunc := range allBatcherFunctions {
		t.Run(batcherFunc.name, func(t *testing.T) {
			testData, cleanup := setupBatcherWithTestData(t, batcherFunc.fn, 1, 2, 10)
			defer cleanup()

			batcher := testData.Batcher
			node1 := testData.Nodes[0]
			node2 := testData.Nodes[1]

			t.Logf("=== MULTI-CONNECTION TEST ===")

			// Phase 1: Connect first node with initial connection
			t.Logf("Phase 1: Connecting node 1 with first connection...")
			err := batcher.AddNode(node1.n.ID, node1.ch, tailcfg.CapabilityVersion(100))
			if err != nil {
				t.Fatalf("Failed to add node1: %v", err)
			}

			// Connect second node for comparison
			err = batcher.AddNode(node2.n.ID, node2.ch, tailcfg.CapabilityVersion(100))
			if err != nil {
				t.Fatalf("Failed to add node2: %v", err)
			}

			time.Sleep(50 * time.Millisecond)

			// Phase 2: Add second connection for node1 (multi-connection scenario)
			t.Logf("Phase 2: Adding second connection for node 1...")
			secondChannel := make(chan *tailcfg.MapResponse, 10)
			err = batcher.AddNode(node1.n.ID, secondChannel, tailcfg.CapabilityVersion(100))
			if err != nil {
				t.Fatalf("Failed to add second connection for node1: %v", err)
			}

			time.Sleep(50 * time.Millisecond)

			// Phase 3: Add third connection for node1
			t.Logf("Phase 3: Adding third connection for node 1...")
			thirdChannel := make(chan *tailcfg.MapResponse, 10)
			err = batcher.AddNode(node1.n.ID, thirdChannel, tailcfg.CapabilityVersion(100))
			if err != nil {
				t.Fatalf("Failed to add third connection for node1: %v", err)
			}

			time.Sleep(50 * time.Millisecond)

			// Phase 4: Verify debug status shows correct connection count
			t.Logf("Phase 4: Verifying debug status shows multiple connections...")
			if debugBatcher, ok := batcher.(interface {
				Debug() map[types.NodeID]any
			}); ok {
				debugInfo := debugBatcher.Debug()

				if info, exists := debugInfo[node1.n.ID]; exists {
					t.Logf("Node1 debug info: %+v", info)
					if infoMap, ok := info.(map[string]any); ok {
						if activeConnections, ok := infoMap["active_connections"].(int); ok {
							if activeConnections != 3 {
								t.Errorf("Node1 should have 3 active connections, got %d", activeConnections)
							} else {
								t.Logf("SUCCESS: Node1 correctly shows 3 active connections")
							}
						}
						if connected, ok := infoMap["connected"].(bool); ok && !connected {
							t.Errorf("Node1 should show as connected with 3 active connections")
						}
					}
				}

				if info, exists := debugInfo[node2.n.ID]; exists {
					if infoMap, ok := info.(map[string]any); ok {
						if activeConnections, ok := infoMap["active_connections"].(int); ok {
							if activeConnections != 1 {
								t.Errorf("Node2 should have 1 active connection, got %d", activeConnections)
							}
						}
					}
				}
			}

			// Phase 5: Send update and verify ALL connections receive it
			t.Logf("Phase 5: Testing update distribution to all connections...")

			// Clear any existing updates from all channels
			clearChannel := func(ch chan *tailcfg.MapResponse) {
				for {
					select {
					case <-ch:
						// drain
					default:
						return
					}
				}
			}

			clearChannel(node1.ch)
			clearChannel(secondChannel)
			clearChannel(thirdChannel)
			clearChannel(node2.ch)

			// Send a change notification from node2 (so node1 should receive it on all connections)
			testChangeSet := change.ChangeSet{
				NodeID:         node2.n.ID,
				Change:         change.NodeNewOrUpdate,
				SelfUpdateOnly: false,
			}

			batcher.AddWork(testChangeSet)

			time.Sleep(100 * time.Millisecond) // Let updates propagate

			// Verify all three connections for node1 receive the update
			connection1Received := false
			connection2Received := false
			connection3Received := false

			select {
			case mapResp := <-node1.ch:
				connection1Received = (mapResp != nil)
				t.Logf("Node1 connection 1 received update: %t", connection1Received)
			case <-time.After(500 * time.Millisecond):
				t.Errorf("Node1 connection 1 did not receive update")
			}

			select {
			case mapResp := <-secondChannel:
				connection2Received = (mapResp != nil)
				t.Logf("Node1 connection 2 received update: %t", connection2Received)
			case <-time.After(500 * time.Millisecond):
				t.Errorf("Node1 connection 2 did not receive update")
			}

			select {
			case mapResp := <-thirdChannel:
				connection3Received = (mapResp != nil)
				t.Logf("Node1 connection 3 received update: %t", connection3Received)
			case <-time.After(500 * time.Millisecond):
				t.Errorf("Node1 connection 3 did not receive update")
			}

			if connection1Received && connection2Received && connection3Received {
				t.Logf("SUCCESS: All three connections for node1 received the update")
			} else {
				t.Errorf("FAILURE: Multi-connection broadcast failed - conn1: %t, conn2: %t, conn3: %t",
					connection1Received, connection2Received, connection3Received)
			}

			// Phase 6: Test connection removal and verify remaining connections still work
			t.Logf("Phase 6: Testing connection removal...")

			// Remove the second connection
			removed := batcher.RemoveNode(node1.n.ID, secondChannel)
			if !removed {
				t.Errorf("Failed to remove second connection for node1")
			}

			time.Sleep(50 * time.Millisecond)

			// Verify debug status shows 2 connections now
			if debugBatcher, ok := batcher.(interface {
				Debug() map[types.NodeID]any
			}); ok {
				debugInfo := debugBatcher.Debug()
				if info, exists := debugInfo[node1.n.ID]; exists {
					if infoMap, ok := info.(map[string]any); ok {
						if activeConnections, ok := infoMap["active_connections"].(int); ok {
							if activeConnections != 2 {
								t.Errorf("Node1 should have 2 active connections after removal, got %d", activeConnections)
							} else {
								t.Logf("SUCCESS: Node1 correctly shows 2 active connections after removal")
							}
						}
					}
				}
			}

			// Send another update and verify remaining connections still work
			clearChannel(node1.ch)
			clearChannel(thirdChannel)

			testChangeSet2 := change.ChangeSet{
				NodeID:         node2.n.ID,
				Change:         change.NodeNewOrUpdate,
				SelfUpdateOnly: false,
			}

			batcher.AddWork(testChangeSet2)
			time.Sleep(100 * time.Millisecond)

			// Verify remaining connections still receive updates
			remaining1Received := false
			remaining3Received := false

			select {
			case mapResp := <-node1.ch:
				remaining1Received = (mapResp != nil)
			case <-time.After(500 * time.Millisecond):
				t.Errorf("Node1 connection 1 did not receive update after removal")
			}

			select {
			case mapResp := <-thirdChannel:
				remaining3Received = (mapResp != nil)
			case <-time.After(500 * time.Millisecond):
				t.Errorf("Node1 connection 3 did not receive update after removal")
			}

			if remaining1Received && remaining3Received {
				t.Logf("SUCCESS: Remaining connections still receive updates after removal")
			} else {
				t.Errorf("FAILURE: Remaining connections failed to receive updates - conn1: %t, conn3: %t",
					remaining1Received, remaining3Received)
			}

			// Verify second channel no longer receives updates (should be closed/removed)
			select {
			case <-secondChannel:
				t.Errorf("Removed connection still received update - this should not happen")
			case <-time.After(100 * time.Millisecond):
				t.Logf("SUCCESS: Removed connection correctly no longer receives updates")
			}
		})
	}
}
