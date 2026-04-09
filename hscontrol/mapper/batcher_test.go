package mapper

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
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
)

var errNodeNotFoundAfterAdd = errors.New("node not found after adding to batcher")

type batcherFunc func(cfg *types.Config, state *state.State) *Batcher

// batcherTestCase defines a batcher function with a descriptive name for testing.
type batcherTestCase struct {
	name string
	fn   batcherFunc
}

// testBatcherWrapper wraps a real batcher to add online/offline notifications
// that would normally be sent by poll.go in production.
type testBatcherWrapper struct {
	*Batcher

	state *state.State

	// connectGens tracks per-node connect generations so RemoveNode can pass
	// the correct generation to State.Disconnect(), matching production behavior.
	connectGens sync.Map // types.NodeID → uint64
}

func (t *testBatcherWrapper) AddNode(id types.NodeID, c chan<- *tailcfg.MapResponse, version tailcfg.CapabilityVersion, stop func()) error {
	// Mark node as online in state before AddNode to match production behavior
	// This ensures the NodeStore has correct online status for change processing
	if t.state != nil {
		// Use Connect to properly mark node online in NodeStore and track the
		// generation so RemoveNode can pass it to Disconnect().
		_, gen := t.state.Connect(id)
		t.connectGens.Store(id, gen)
	}

	// First add the node to the real batcher
	err := t.Batcher.AddNode(id, c, version, stop)
	if err != nil {
		return err
	}

	// Send the online notification that poll.go would normally send
	// This ensures other nodes get notified about this node coming online
	node, ok := t.state.GetNodeByID(id)
	if !ok {
		return fmt.Errorf("%w: %d", errNodeNotFoundAfterAdd, id)
	}

	t.AddWork(change.NodeOnlineFor(node))

	return nil
}

func (t *testBatcherWrapper) RemoveNode(id types.NodeID, c chan<- *tailcfg.MapResponse) bool {
	// Mark node as offline in state BEFORE removing from batcher
	// This ensures the NodeStore has correct offline status when the change is processed
	if t.state != nil {
		var gen uint64

		if v, ok := t.connectGens.LoadAndDelete(id); ok {
			if g, ok := v.(uint64); ok {
				gen = g
			}
		}

		_, _ = t.state.Disconnect(id, gen)
	}

	// Send the offline notification that poll.go would normally send
	// Do this BEFORE removing from batcher so the change can be processed
	node, ok := t.state.GetNodeByID(id)
	if ok {
		t.AddWork(change.NodeOfflineFor(node))
	}

	// Finally remove from the real batcher
	return t.Batcher.RemoveNode(id, c)
}

// wrapBatcherForTest wraps a batcher with test-specific behavior.
func wrapBatcherForTest(b *Batcher, state *state.State) *testBatcherWrapper {
	return &testBatcherWrapper{Batcher: b, state: state}
}

// allBatcherFunctions contains all batcher implementations to test.
var allBatcherFunctions = []batcherTestCase{
	{"Default", NewBatcherAndMapper},
}

// Test configuration constants.
const (
	// Test data configuration.
	testUserCount    = 3
	testNodesPerUser = 2

	// Timing configuration.
	testTimeout     = 120 * time.Second // Increased for more intensive tests
	updateTimeout   = 5 * time.Second
	deadlockTimeout = 30 * time.Second

	// Channel configuration.
	normalBufferSize = 50
	smallBufferSize  = 3
	tinyBufferSize   = 1 // For maximum contention
	largeBufferSize  = 200
)

// TestData contains all test entities created for a test scenario.
type TestData struct {
	Database *db.HSDatabase
	Users    []*types.User
	Nodes    []node
	State    *state.State
	Config   *types.Config
	Batcher  *testBatcherWrapper
}

type node struct {
	n  *types.Node
	ch chan *tailcfg.MapResponse

	// Update tracking (all accessed atomically for thread safety)
	updateCount   int64
	patchCount    int64
	fullCount     int64
	maxPeersCount atomic.Int64
	lastPeerCount atomic.Int64
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
	t testing.TB,
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
			BatchChangeDelay:      10 * time.Millisecond,
			BatcherWorkers:        types.DefaultBatcherWorkers(), // Use same logic as config.go
			NodeStoreBatchSize:    state.TestBatchSize,
			NodeStoreBatchTimeout: state.TestBatchTimeout,
		},
	}

	// Create database and populate it with test data
	database, err := db.NewHeadscaleDatabase(cfg)
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
	require.NoError(t, err)
	require.NotNil(t, derpMap)

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
//
//nolint:unused
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
	assert.Equal(t, 999, resp.DERPMap.Regions[999].RegionID, "Expected DERP region ID to be 999")
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
func parseUpdateAndAnalyze(resp *tailcfg.MapResponse) UpdateInfo {
	return UpdateInfo{
		PeerCount:  len(resp.Peers),
		PatchCount: len(resp.PeersChangedPatch),
		IsFull:     len(resp.Peers) > 0,
		IsPatch:    len(resp.PeersChangedPatch) > 0,
		IsDERP:     resp.DERPMap != nil,
	}
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
				info := parseUpdateAndAnalyze(data)
				{
					// Track update types
					if info.IsFull {
						atomic.AddInt64(&n.fullCount, 1)
						n.lastPeerCount.Store(int64(info.PeerCount))
						// Update max peers seen using compare-and-swap for thread safety
						for {
							current := n.maxPeersCount.Load()
							if int64(info.PeerCount) <= current {
								break
							}

							if n.maxPeersCount.CompareAndSwap(current, int64(info.PeerCount)) {
								break
							}
						}
					}

					if info.IsPatch {
						atomic.AddInt64(&n.patchCount, 1)
						// For patches, we track how many patch items using compare-and-swap
						for {
							current := n.maxPeersCount.Load()
							if int64(info.PatchCount) <= current {
								break
							}

							if n.maxPeersCount.CompareAndSwap(current, int64(info.PatchCount)) {
								break
							}
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
		MaxPeersSeen:  int(n.maxPeersCount.Load()),
		LastPeerCount: int(n.lastPeerCount.Load()),
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

	// Wait for tracking goroutine to process the update
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.GreaterOrEqual(c, atomic.LoadInt64(&testNode.updateCount), int64(1), "should have processed the update")
	}, time.Second, 10*time.Millisecond, "waiting for update to be processed")

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
			_ = batcher.AddNode(testNode.n.ID, testNode.ch, tailcfg.CapabilityVersion(100), nil)

			// Wait for connection to be established
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.True(c, batcher.IsConnected(testNode.n.ID), "node should be connected")
			}, time.Second, 10*time.Millisecond, "waiting for node connection")

			// Generate work and wait for updates to be processed
			batcher.AddWork(change.FullUpdate())
			batcher.AddWork(change.PolicyChange())
			batcher.AddWork(change.DERPMap())

			// Wait for updates to be processed (at least 1 update received)
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.GreaterOrEqual(c, atomic.LoadInt64(&testNode.updateCount), int64(1), "should have received updates")
			}, time.Second, 10*time.Millisecond, "waiting for updates to be processed")

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
		{"10_nodes", 10},   // Quick baseline test
		{"100_nodes", 100}, // Full scalability test ~2 minutes
		// Large-scale tests commented out - uncomment for scalability testing
		// {"1000_nodes", 1000},  // ~12 minutes
		// {"2000_nodes", 2000},  // ~60+ minutes
		// {"5000_nodes", 5000},  // Not recommended - database bottleneck
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
					// For very large tests (>1000 nodes), limit buffer to avoid excessive memory
					bufferSize := max(1000, min(tc.nodeCount*2, 10000))

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

					// Yield to allow tracking goroutines to start
					runtime.Gosched()

					startTime := time.Now()

					// Join all nodes as fast as possible
					t.Logf("Joining %d nodes as fast as possible...", len(allNodes))

					for i := range allNodes {
						node := &allNodes[i]
						_ = batcher.AddNode(node.n.ID, node.ch, tailcfg.CapabilityVersion(100), nil)

						// Issue full update after each join to ensure connectivity
						batcher.AddWork(change.FullUpdate())

						// Yield to scheduler for large node counts to prevent overwhelming the work queue
						if tc.nodeCount > 100 && i%50 == 49 {
							runtime.Gosched()
						}
					}

					joinTime := time.Since(startTime)
					t.Logf("All nodes joined in %v, waiting for full connectivity...", joinTime)

					// Wait for all updates to propagate until all nodes achieve connectivity
					expectedPeers := tc.nodeCount - 1 // Each node should see all others except itself

					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						connectedCount := 0

						for i := range allNodes {
							node := &allNodes[i]

							currentMaxPeers := int(node.maxPeersCount.Load())
							if currentMaxPeers >= expectedPeers {
								connectedCount++
							}
						}

						progress := float64(connectedCount) / float64(len(allNodes)) * 100
						t.Logf("Progress: %d/%d nodes (%.1f%%) have seen %d+ peers",
							connectedCount, len(allNodes), progress, expectedPeers)

						assert.Equal(c, len(allNodes), connectedCount, "all nodes should achieve full connectivity")
					}, 5*time.Minute, 5*time.Second, "waiting for full connectivity")

					t.Logf("All nodes achieved full connectivity")

					totalTime := time.Since(startTime)

					// Disconnect all nodes
					for i := range allNodes {
						node := &allNodes[i]
						batcher.RemoveNode(node.n.ID, node.ch)
					}

					// Wait for all nodes to be disconnected
					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						for i := range allNodes {
							assert.False(c, batcher.IsConnected(allNodes[i].n.ID), "node should be disconnected")
						}
					}, 5*time.Second, 50*time.Millisecond, "waiting for nodes to disconnect")

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
							"PASS: All-to-all connectivity achieved for %d nodes",
							len(allNodes),
						)
					} else {
						// This should not happen since we loop until success, but handle it just in case
						failedNodes := len(allNodes) - successfulNodes
						t.Errorf("UNEXPECTED: %d/%d nodes still failed after waiting for connectivity (expected %d, some saw %d-%d)",
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
			tn := &testData.Nodes[0]
			tn2 := &testData.Nodes[1]

			// Test AddNode with real node ID
			_ = batcher.AddNode(tn.n.ID, tn.ch, 100, nil)

			if !batcher.IsConnected(tn.n.ID) {
				t.Error("Node should be connected after AddNode")
			}

			// Test work processing with DERP change
			batcher.AddWork(change.DERPMap())

			// Wait for update and validate content
			select {
			case data := <-tn.ch:
				assertDERPMapResponse(t, data)
			case <-time.After(200 * time.Millisecond):
				t.Error("Did not receive expected DERP update")
			}

			// Drain any initial messages from first node
			drainChannelTimeout(tn.ch, 100*time.Millisecond)

			// Add the second node and verify update message
			_ = batcher.AddNode(tn2.n.ID, tn2.ch, 100, nil)
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

func drainChannelTimeout(ch <-chan *tailcfg.MapResponse, timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-ch:
			// Drain message
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
// 					changeSet:   change.DERPMapResponse(),
// 					expectData:  true,
// 					description: "DERP changes should generate map updates",
// 				},
// 				{
// 					name:        "Node key expiry",
// 					changeSet:   change.KeyExpiryFor(testNodes[1].n.ID),
// 					expectData:  true,
// 					description: "Node key expiry with real node data",
// 				},
// 				{
// 					name:        "Node new registration",
// 					changeSet:   change.NodeAddedResponse(testNodes[1].n.ID),
// 					expectData:  true,
// 					description: "New node registration with real data",
// 				},
// 				{
// 					name:        "Full update",
// 					changeSet:   change.FullUpdateResponse(),
// 					expectData:  true,
// 					description: "Full updates with real node data",
// 				},
// 				{
// 					name:        "Policy change",
// 					changeSet:   change.PolicyChangeResponse(),
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
			_ = batcher.AddNode(testNodes[0].n.ID, ch, tailcfg.CapabilityVersion(100), nil)

			// Track update content for validation
			var receivedUpdates []*tailcfg.MapResponse

			// Add multiple changes rapidly to test batching
			batcher.AddWork(change.DERPMap())
			// Use a valid expiry time for testing since test nodes don't have expiry set
			testExpiry := time.Now().Add(24 * time.Hour)
			batcher.AddWork(change.KeyExpiryFor(testNodes[1].n.ID, testExpiry))
			batcher.AddWork(change.DERPMap())
			batcher.AddWork(change.NodeAdded(testNodes[1].n.ID))
			batcher.AddWork(change.DERPMap())

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
					// Expected: 5 explicit changes + 1 initial from AddNode + 1 NodeOnline from wrapper = 7 updates
					expectedUpdates := 7
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
			testNode := &testData.Nodes[0]

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
					_ = batcher.AddNode(testNode.n.ID, ch, tailcfg.CapabilityVersion(100), nil)
					batcher.AddWork(change.DERPMap())

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
						batcher.AddWork(change.KeyExpiryFor(testNode.n.ID, testExpiry))
					}

					// Rapid removal creates race between worker and removal
					for range i % 3 {
						runtime.Gosched() // Introduce timing variability
					}

					batcher.RemoveNode(testNode.n.ID, ch)

					// Yield to allow workers to process and close channels
					runtime.Gosched()
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
//
//nolint:gocyclo // complex concurrent test scenario
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
				testUserCount,
				testNodesPerUser,
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

			for i := range stableNodes {
				node := &stableNodes[i]
				ch := make(chan *tailcfg.MapResponse, normalBufferSize)
				stableChannels[node.n.ID] = ch
				_ = batcher.AddNode(node.n.ID, ch, tailcfg.CapabilityVersion(100), nil)

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
						case <-time.After(testTimeout):
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
					for j := range churningNodes {
						node := &churningNodes[j]

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

							ch := make(chan *tailcfg.MapResponse, smallBufferSize)

							churningChannelsMutex.Lock()

							churningChannels[nodeID] = ch

							churningChannelsMutex.Unlock()

							_ = batcher.AddNode(nodeID, ch, tailcfg.CapabilityVersion(100), nil)

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

							for range i % 5 {
								runtime.Gosched() // Introduce timing variability
							}

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
						batcher.AddWork(change.DERPMap())
					}

					if i%5 == 0 {
						// Full updates using real node data
						batcher.AddWork(change.FullUpdate())
					}

					if i%7 == 0 && len(allNodes) > 0 {
						// Node-specific changes using real nodes
						node := &allNodes[i%len(allNodes)]
						// Use a valid expiry time for testing since test nodes don't have expiry set
						testExpiry := time.Now().Add(24 * time.Hour)
						batcher.AddWork(change.KeyExpiryFor(node.n.ID, testExpiry))
					}

					// Yield to allow some batching
					runtime.Gosched()
				}

				wg.Wait()
			}()

			// Deadlock detection
			select {
			case <-done:
				t.Logf("Connection churn cycles completed successfully")
			case <-time.After(deadlockTimeout):
				t.Error("Test timed out - possible deadlock detected")
				return
			}

			// Yield to allow any in-flight updates to complete
			runtime.Gosched()

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

			for i := range stableNodes {
				node := &stableNodes[i]
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

			for i := range churningNodes {
				node := &churningNodes[i]
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
			for i := range stableNodes {
				node := &stableNodes[i]
				if !batcher.IsConnected(node.n.ID) {
					t.Errorf("Stable node %d lost connection during racing", node.n.ID)
				}
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

			// Connect nodes one at a time and wait for each to be connected
			for i := range allNodes {
				node := &allNodes[i]
				_ = batcher.AddNode(node.n.ID, node.ch, tailcfg.CapabilityVersion(100), nil)
				t.Logf("Connected node %d (ID: %d)", i, node.n.ID)

				// Wait for node to be connected
				assert.EventuallyWithT(t, func(c *assert.CollectT) {
					assert.True(c, batcher.IsConnected(node.n.ID), "node should be connected")
				}, time.Second, 10*time.Millisecond, "waiting for node connection")
			}

			// Wait for all NodeCameOnline events to be processed
			t.Logf("Waiting for NodeCameOnline events to settle...")
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				for i := range allNodes {
					assert.True(c, batcher.IsConnected(allNodes[i].n.ID), "all nodes should be connected")
				}
			}, 5*time.Second, 50*time.Millisecond, "waiting for all nodes to connect")

			// Check how many peers each node should see
			for i := range allNodes {
				node := &allNodes[i]
				peers := testData.State.ListPeers(node.n.ID)
				t.Logf("Node %d should see %d peers from state", i, peers.Len())
			}

			// Send a full update - this should generate full peer lists
			t.Logf("Sending FullSet update...")
			batcher.AddWork(change.FullUpdate())

			// Wait for FullSet work items to be processed
			t.Logf("Waiting for FullSet to be processed...")
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				// Check that some data is available in at least one channel
				found := false

				for i := range allNodes {
					if len(allNodes[i].ch) > 0 {
						found = true
						break
					}
				}

				assert.True(c, found, "no updates received yet")
			}, 5*time.Second, 50*time.Millisecond, "waiting for FullSet updates")

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
				t.Errorf("CRITICAL: No FULL updates received despite sending change.FullUpdateResponse()!")
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

			// Connect all nodes initially.
			t.Logf("Connecting all nodes...")

			for i := range allNodes {
				node := &allNodes[i]

				err := batcher.AddNode(node.n.ID, node.ch, tailcfg.CapabilityVersion(100), nil)
				if err != nil {
					t.Fatalf("Failed to add node %d: %v", i, err)
				}
			}

			// Wait for all connections to settle
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				for i := range allNodes {
					assert.True(c, batcher.IsConnected(allNodes[i].n.ID), "node should be connected")
				}
			}, 5*time.Second, 50*time.Millisecond, "waiting for connections to settle")

			// Rapid disconnect ALL nodes (simulating nodes going down).
			t.Logf("Rapid disconnect all nodes...")

			for i := range allNodes {
				node := &allNodes[i]
				removed := batcher.RemoveNode(node.n.ID, node.ch)
				t.Logf("Node %d RemoveNode result: %t", i, removed)
			}

			// Rapid reconnect with NEW channels (simulating nodes coming back up).
			t.Logf("Rapid reconnect with new channels...")

			newChannels := make([]chan *tailcfg.MapResponse, len(allNodes))
			for i := range allNodes {
				node := &allNodes[i]
				newChannels[i] = make(chan *tailcfg.MapResponse, 10)

				err := batcher.AddNode(node.n.ID, newChannels[i], tailcfg.CapabilityVersion(100), nil)
				if err != nil {
					t.Errorf("Failed to reconnect node %d: %v", i, err)
				}
			}

			// Wait for all reconnections to settle
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				for i := range allNodes {
					assert.True(c, batcher.IsConnected(allNodes[i].n.ID), "node should be reconnected")
				}
			}, 5*time.Second, 50*time.Millisecond, "waiting for reconnections to settle")

			// Check debug status after reconnection.
			t.Logf("Checking debug status...")

			debugInfo := batcher.Debug()
			disconnectedCount := 0

			for i := range allNodes {
				node := &allNodes[i]
				if info, exists := debugInfo[node.n.ID]; exists {
					t.Logf("Node %d (ID %d): debug info = %+v", i, node.n.ID, info)

					if !info.Connected {
						disconnectedCount++

						t.Logf("BUG REPRODUCED: Node %d shows as disconnected in debug but should be connected", i)
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
			} else {
				t.Logf("All nodes show as connected - working correctly")
			}

			// Test if "disconnected" nodes can actually receive updates.
			t.Logf("Testing if nodes can receive updates despite debug status...")

			// Send a change that should reach all nodes
			batcher.AddWork(change.DERPMap())

			receivedCount := 0
			timeout := time.After(500 * time.Millisecond)

			for i := range allNodes {
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

//nolint:gocyclo // complex multi-connection test scenario
func TestBatcherMultiConnection(t *testing.T) {
	for _, batcherFunc := range allBatcherFunctions {
		t.Run(batcherFunc.name, func(t *testing.T) {
			testData, cleanup := setupBatcherWithTestData(t, batcherFunc.fn, 1, 2, 10)
			defer cleanup()

			batcher := testData.Batcher
			node1 := &testData.Nodes[0]
			node2 := &testData.Nodes[1]

			t.Logf("=== MULTI-CONNECTION TEST ===")

			// Connect first node with initial connection.
			t.Logf("Connecting node 1 with first connection...")

			err := batcher.AddNode(node1.n.ID, node1.ch, tailcfg.CapabilityVersion(100), nil)
			if err != nil {
				t.Fatalf("Failed to add node1: %v", err)
			}

			// Connect second node for comparison
			err = batcher.AddNode(node2.n.ID, node2.ch, tailcfg.CapabilityVersion(100), nil)
			if err != nil {
				t.Fatalf("Failed to add node2: %v", err)
			}

			// Wait for initial connections
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.True(c, batcher.IsConnected(node1.n.ID), "node1 should be connected")
				assert.True(c, batcher.IsConnected(node2.n.ID), "node2 should be connected")
			}, time.Second, 10*time.Millisecond, "waiting for initial connections")

			// Add second connection for node1 (multi-connection scenario).
			t.Logf("Adding second connection for node 1...")

			secondChannel := make(chan *tailcfg.MapResponse, 10)

			err = batcher.AddNode(node1.n.ID, secondChannel, tailcfg.CapabilityVersion(100), nil)
			if err != nil {
				t.Fatalf("Failed to add second connection for node1: %v", err)
			}

			// Yield to allow connection to be processed
			runtime.Gosched()

			// Add third connection for node1.
			t.Logf("Adding third connection for node 1...")

			thirdChannel := make(chan *tailcfg.MapResponse, 10)

			err = batcher.AddNode(node1.n.ID, thirdChannel, tailcfg.CapabilityVersion(100), nil)
			if err != nil {
				t.Fatalf("Failed to add third connection for node1: %v", err)
			}

			// Yield to allow connection to be processed
			runtime.Gosched()

			// Verify debug status shows correct connection count.
			t.Logf("Verifying debug status shows multiple connections...")

			debugInfo := batcher.Debug()

			if info, exists := debugInfo[node1.n.ID]; exists {
				t.Logf("Node1 debug info: %+v", info)

				if info.ActiveConnections != 3 {
					t.Errorf("Node1 should have 3 active connections, got %d", info.ActiveConnections)
				} else {
					t.Logf("SUCCESS: Node1 correctly shows 3 active connections")
				}

				if !info.Connected {
					t.Errorf("Node1 should show as connected with 3 active connections")
				}
			}

			if info, exists := debugInfo[node2.n.ID]; exists {
				if info.ActiveConnections != 1 {
					t.Errorf("Node2 should have 1 active connection, got %d", info.ActiveConnections)
				}
			}

			// Send update and verify ALL connections receive it.
			t.Logf("Testing update distribution to all connections...")

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
			testChangeSet := change.NodeAdded(node2.n.ID)

			batcher.AddWork(testChangeSet)

			// Wait for updates to propagate to at least one channel
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.Positive(c, len(node1.ch)+len(secondChannel)+len(thirdChannel), "should have received updates")
			}, 5*time.Second, 50*time.Millisecond, "waiting for updates to propagate")

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

			// Test connection removal and verify remaining connections still work.
			t.Logf("Testing connection removal...")

			// Remove the second connection
			removed := batcher.RemoveNode(node1.n.ID, secondChannel)
			if !removed {
				t.Errorf("Failed to remove second connection for node1")
			}

			// Yield to allow removal to be processed
			runtime.Gosched()

			// Verify debug status shows 2 connections now
			debugInfo2 := batcher.Debug()
			if info, exists := debugInfo2[node1.n.ID]; exists {
				if info.ActiveConnections != 2 {
					t.Errorf("Node1 should have 2 active connections after removal, got %d", info.ActiveConnections)
				} else {
					t.Logf("SUCCESS: Node1 correctly shows 2 active connections after removal")
				}
			}

			// Send another update and verify remaining connections still work
			clearChannel(node1.ch)
			clearChannel(thirdChannel)

			testChangeSet2 := change.NodeAdded(node2.n.ID)

			batcher.AddWork(testChangeSet2)

			// Wait for updates to propagate to remaining channels
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.Positive(c, len(node1.ch)+len(thirdChannel), "should have received updates")
			}, 5*time.Second, 50*time.Millisecond, "waiting for updates to propagate")

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

			// Drain secondChannel of any messages received before removal
			// (the test wrapper sends NodeOffline before removal, which may have reached this channel)
			clearChannel(secondChannel)

			// Verify second channel no longer receives new updates after being removed
			select {
			case <-secondChannel:
				t.Errorf("Removed connection still received update - this should not happen")
			case <-time.After(100 * time.Millisecond):
				t.Logf("SUCCESS: Removed connection correctly no longer receives updates")
			}
		})
	}
}

// TestNodeDeletedWhileChangesPending reproduces issue #2924 where deleting a node
// from state while there are pending changes for that node in the batcher causes
// "node not found" errors. The race condition occurs when:
// 1. Node is connected and changes are queued for it
// 2. Node is deleted from state (NodeStore) but not from batcher
// 3. Batcher worker tries to generate map response for deleted node
// 4. Mapper fails to find node in state, causing repeated "node not found" errors.
func TestNodeDeletedWhileChangesPending(t *testing.T) {
	for _, batcherFunc := range allBatcherFunctions {
		t.Run(batcherFunc.name, func(t *testing.T) {
			// Create test environment with 3 nodes
			testData, cleanup := setupBatcherWithTestData(t, batcherFunc.fn, 1, 3, normalBufferSize)
			defer cleanup()

			batcher := testData.Batcher
			st := testData.State
			node1 := &testData.Nodes[0]
			node2 := &testData.Nodes[1]
			node3 := &testData.Nodes[2]

			t.Logf("Testing issue #2924: Node1=%d, Node2=%d, Node3=%d",
				node1.n.ID, node2.n.ID, node3.n.ID)

			// Helper to drain channels
			drainCh := func(ch chan *tailcfg.MapResponse) {
				for {
					select {
					case <-ch:
						// drain
					default:
						return
					}
				}
			}

			// Start update consumers for all nodes
			node1.start()
			node2.start()
			node3.start()

			defer node1.cleanup()
			defer node2.cleanup()
			defer node3.cleanup()

			// Connect all nodes to the batcher
			require.NoError(t, batcher.AddNode(node1.n.ID, node1.ch, tailcfg.CapabilityVersion(100), nil))
			require.NoError(t, batcher.AddNode(node2.n.ID, node2.ch, tailcfg.CapabilityVersion(100), nil))
			require.NoError(t, batcher.AddNode(node3.n.ID, node3.ch, tailcfg.CapabilityVersion(100), nil))

			// Wait for all nodes to be connected
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.True(c, batcher.IsConnected(node1.n.ID), "node1 should be connected")
				assert.True(c, batcher.IsConnected(node2.n.ID), "node2 should be connected")
				assert.True(c, batcher.IsConnected(node3.n.ID), "node3 should be connected")
			}, 5*time.Second, 50*time.Millisecond, "waiting for nodes to connect")

			// Get initial work errors count
			lfb := unwrapBatcher(batcher)
			initialWorkErrors := lfb.WorkErrors()
			t.Logf("Initial work errors: %d", initialWorkErrors)

			// Clear channels to prepare for the test
			drainCh(node1.ch)
			drainCh(node2.ch)
			drainCh(node3.ch)

			// Get node view for deletion
			nodeToDelete, ok := st.GetNodeByID(node3.n.ID)
			require.True(t, ok, "node3 should exist in state")

			// Delete the node from state - this returns a NodeRemoved change
			// In production, this change is sent to batcher via app.Change()
			nodeChange, err := st.DeleteNode(nodeToDelete)
			require.NoError(t, err, "should be able to delete node from state")
			t.Logf("Deleted node %d from state, change: %s", node3.n.ID, nodeChange.Reason)

			// Verify node is deleted from state
			_, exists := st.GetNodeByID(node3.n.ID)
			require.False(t, exists, "node3 should be deleted from state")

			// Send the NodeRemoved change to batcher (this is what app.Change() does)
			// With the fix, this should clean up node3 from batcher's internal state
			batcher.AddWork(nodeChange)

			// Wait for the batcher to process the removal and clean up the node
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.False(c, batcher.IsConnected(node3.n.ID), "node3 should be disconnected from batcher")
			}, 5*time.Second, 50*time.Millisecond, "waiting for node removal to be processed")

			t.Logf("Node %d connected in batcher after NodeRemoved: %v", node3.n.ID, batcher.IsConnected(node3.n.ID))

			// Now queue changes that would have caused errors before the fix
			// With the fix, these should NOT cause "node not found" errors
			// because node3 was cleaned up when NodeRemoved was processed
			batcher.AddWork(change.FullUpdate())
			batcher.AddWork(change.PolicyChange())

			// Wait for work to be processed and verify no errors occurred
			// With the fix, no new errors should occur because the deleted node
			// was cleaned up from batcher state when NodeRemoved was processed
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				finalWorkErrors := lfb.WorkErrors()
				newErrors := finalWorkErrors - initialWorkErrors
				assert.Zero(c, newErrors, "Fix for #2924: should have no work errors after node deletion")
			}, 5*time.Second, 100*time.Millisecond, "waiting for work processing to complete without errors")

			// Verify remaining nodes still work correctly
			drainCh(node1.ch)
			drainCh(node2.ch)
			batcher.AddWork(change.NodeAdded(node1.n.ID))

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				// Node 1 and 2 should receive updates
				stats1 := NodeStats{TotalUpdates: atomic.LoadInt64(&node1.updateCount)}
				stats2 := NodeStats{TotalUpdates: atomic.LoadInt64(&node2.updateCount)}
				assert.Positive(c, stats1.TotalUpdates, "node1 should have received updates")
				assert.Positive(c, stats2.TotalUpdates, "node2 should have received updates")
			}, 5*time.Second, 100*time.Millisecond, "waiting for remaining nodes to receive updates")
		})
	}
}

func TestRemoveNodeChannelAlreadyRemoved(t *testing.T) {
	for _, batcherFunc := range allBatcherFunctions {
		t.Run(batcherFunc.name, func(t *testing.T) {
			t.Run("marks disconnected when removed channel was last active connection", func(t *testing.T) {
				testData, cleanup := setupBatcherWithTestData(t, batcherFunc.fn, 1, 1, normalBufferSize)
				defer cleanup()

				lfb := unwrapBatcher(testData.Batcher)

				nodeID := testData.Nodes[0].n.ID
				ch := make(chan *tailcfg.MapResponse, normalBufferSize)
				require.NoError(t, lfb.AddNode(nodeID, ch, tailcfg.CapabilityVersion(100), nil))

				assert.EventuallyWithT(t, func(c *assert.CollectT) {
					assert.True(c, lfb.IsConnected(nodeID), "node should be connected after AddNode")
				}, 5*time.Second, 50*time.Millisecond, "waiting for node to be connected")

				nodeConn, exists := lfb.nodes.Load(nodeID)
				require.True(t, exists, "node connection should exist")
				require.True(t, nodeConn.removeConnectionByChannel(ch), "manual channel removal should succeed")

				removed := lfb.RemoveNode(nodeID, ch)
				assert.False(t, removed, "RemoveNode should report no remaining active connections")

				assert.EventuallyWithT(t, func(c *assert.CollectT) {
					assert.False(c, lfb.IsConnected(nodeID), "node should be disconnected after last connection is gone")
				}, 5*time.Second, 50*time.Millisecond, "waiting for node to be disconnected")

				close(ch)
			})

			t.Run("keeps connected when another connection is still active", func(t *testing.T) {
				testData, cleanup := setupBatcherWithTestData(t, batcherFunc.fn, 1, 1, normalBufferSize)
				defer cleanup()

				lfb := unwrapBatcher(testData.Batcher)

				nodeID := testData.Nodes[0].n.ID
				ch1 := make(chan *tailcfg.MapResponse, normalBufferSize)
				ch2 := make(chan *tailcfg.MapResponse, normalBufferSize)

				require.NoError(t, lfb.AddNode(nodeID, ch1, tailcfg.CapabilityVersion(100), nil))
				require.NoError(t, lfb.AddNode(nodeID, ch2, tailcfg.CapabilityVersion(100), nil))

				assert.EventuallyWithT(t, func(c *assert.CollectT) {
					assert.True(c, lfb.IsConnected(nodeID), "node should be connected after AddNode")
				}, 5*time.Second, 50*time.Millisecond, "waiting for node to be connected")

				nodeConn, exists := lfb.nodes.Load(nodeID)
				require.True(t, exists, "node connection should exist")
				require.True(t, nodeConn.removeConnectionByChannel(ch1), "manual channel removal should succeed")

				removed := lfb.RemoveNode(nodeID, ch1)
				assert.True(t, removed, "RemoveNode should report node still has active connections")
				assert.True(t, lfb.IsConnected(nodeID), "node should still be connected while another connection exists")
				assert.Equal(t, 1, nodeConn.getActiveConnectionCount(), "exactly one active connection should remain")

				close(ch1)
			})
		})
	}
}

// unwrapBatcher extracts the underlying *Batcher from the test wrapper.
func unwrapBatcher(b *testBatcherWrapper) *Batcher {
	return b.Batcher
}
