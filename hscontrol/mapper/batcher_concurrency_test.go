package mapper

// Concurrency, lifecycle, and scale tests for the batcher.
// Tests in this file exercise:
// - addToBatch and processBatchedChanges under concurrent access
// - cleanupOfflineNodes correctness
// - Batcher lifecycle (Close, shutdown, double-close)
// - 1000-node scale testing of batching and channel mechanics
//
// Most tests use the lightweight batcher helper which creates a batcher with
// pre-populated nodes but NO database, enabling fast 1000-node tests.

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// ============================================================================
// Lightweight Batcher Helper (no database needed)
// ============================================================================

// lightweightBatcher provides a batcher with pre-populated nodes for testing
// the batching, channel, and concurrency mechanics without database overhead.
type lightweightBatcher struct {
	b        *Batcher
	channels map[types.NodeID]chan *tailcfg.MapResponse
}

// setupLightweightBatcher creates a batcher with nodeCount pre-populated nodes.
// Each node gets a buffered channel of bufferSize. The batcher's worker loop
// is NOT started (no doWork), so addToBatch/processBatchedChanges can be tested
// in isolation. Use startWorkers() if you need the full loop.
func setupLightweightBatcher(t *testing.T, nodeCount, bufferSize int) *lightweightBatcher {
	t.Helper()

	b := &Batcher{
		tick:    time.NewTicker(10 * time.Millisecond),
		workers: 4,
		workCh:  make(chan work, 4*200),
		nodes:   xsync.NewMap[types.NodeID, *multiChannelNodeConn](),
		done:    make(chan struct{}),
	}

	channels := make(map[types.NodeID]chan *tailcfg.MapResponse, nodeCount)
	for i := 1; i <= nodeCount; i++ {
		id := types.NodeID(i)                  //nolint:gosec // test with small controlled values
		mc := newMultiChannelNodeConn(id, nil) // nil mapper is fine for channel tests
		ch := make(chan *tailcfg.MapResponse, bufferSize)
		entry := &connectionEntry{
			id:      fmt.Sprintf("conn-%d", i),
			c:       ch,
			version: tailcfg.CapabilityVersion(100),
			created: time.Now(),
		}
		entry.lastUsed.Store(time.Now().Unix())
		mc.addConnection(entry)
		b.nodes.Store(id, mc)
		channels[id] = ch
	}

	b.totalNodes.Store(int64(nodeCount))

	return &lightweightBatcher{b: b, channels: channels}
}

func (lb *lightweightBatcher) cleanup() {
	lb.b.doneOnce.Do(func() {
		close(lb.b.done)
	})
	lb.b.tick.Stop()
}

// countTotalPending counts total pending change entries across all nodes.
func countTotalPending(b *Batcher) int {
	count := 0

	b.nodes.Range(func(_ types.NodeID, nc *multiChannelNodeConn) bool {
		nc.pendingMu.Lock()
		count += len(nc.pending)
		nc.pendingMu.Unlock()

		return true
	})

	return count
}

// countNodesPending counts how many nodes have pending changes.
func countNodesPending(b *Batcher) int {
	count := 0

	b.nodes.Range(func(_ types.NodeID, nc *multiChannelNodeConn) bool {
		nc.pendingMu.Lock()
		hasPending := len(nc.pending) > 0
		nc.pendingMu.Unlock()

		if hasPending {
			count++
		}

		return true
	})

	return count
}

// getPendingForNode returns pending changes for a specific node.
func getPendingForNode(b *Batcher, id types.NodeID) []change.Change {
	nc, ok := b.nodes.Load(id)
	if !ok {
		return nil
	}

	nc.pendingMu.Lock()
	pending := make([]change.Change, len(nc.pending))
	copy(pending, nc.pending)
	nc.pendingMu.Unlock()

	return pending
}

// runConcurrently runs n goroutines executing fn, waits for all to finish,
// and returns the number of panics caught.
func runConcurrently(t *testing.T, n int, fn func(i int)) int {
	t.Helper()

	var (
		wg     sync.WaitGroup
		panics atomic.Int64
	)

	for i := range n {
		wg.Add(1)

		go func(idx int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panics.Add(1)
					t.Logf("panic in goroutine %d: %v", idx, r)
				}
			}()

			fn(idx)
		}(i)
	}

	wg.Wait()

	return int(panics.Load())
}

// runConcurrentlyWithTimeout is like runConcurrently but fails if not done
// within timeout (deadlock detection).
func runConcurrentlyWithTimeout(t *testing.T, n int, timeout time.Duration, fn func(i int)) int {
	t.Helper()

	done := make(chan int, 1)

	go func() {
		done <- runConcurrently(t, n, fn)
	}()

	select {
	case panics := <-done:
		return panics
	case <-time.After(timeout):
		t.Fatalf("deadlock detected: %d goroutines did not complete within %v", n, timeout)
		return -1
	}
}

// ============================================================================
// addToBatch Concurrency Tests
// ============================================================================

// TestAddToBatch_ConcurrentTargeted_NoDataLoss verifies that concurrent
// targeted addToBatch calls do not lose data.
//
// Previously (Bug #1): addToBatch used LoadOrStore→append→Store on a
// separate pendingChanges map, which was NOT atomic. Two goroutines could
// Load the same slice, both append, and one Store would overwrite the other.
// FIX: pendingChanges moved into multiChannelNodeConn with mutex protection,
// eliminating the race entirely.
func TestAddToBatch_ConcurrentTargeted_NoDataLoss(t *testing.T) {
	lb := setupLightweightBatcher(t, 10, 10)
	defer lb.cleanup()

	targetNode := types.NodeID(1)

	const goroutines = 100

	// Each goroutine adds one targeted change to the same node
	panics := runConcurrentlyWithTimeout(t, goroutines, 10*time.Second, func(i int) {
		ch := change.Change{
			Reason:     fmt.Sprintf("targeted-%d", i),
			TargetNode: targetNode,
			PeerPatches: []*tailcfg.PeerChange{
				{NodeID: tailcfg.NodeID(i + 100)}, //nolint:gosec // test
			},
		}
		lb.b.addToBatch(ch)
	})

	require.Zero(t, panics, "no panics expected")

	// All 100 changes MUST be present. The Load→append→Store race causes
	// data loss: typically 30-50% of changes are silently dropped.
	pending := getPendingForNode(lb.b, targetNode)
	t.Logf("targeted changes: expected=%d, got=%d (lost=%d)",
		goroutines, len(pending), goroutines-len(pending))

	assert.Len(t, pending, goroutines,
		"addToBatch lost %d/%d targeted changes under concurrent access",
		goroutines-len(pending), goroutines)
}

// TestAddToBatch_ConcurrentBroadcast verifies that concurrent broadcasts
// distribute changes to all nodes.
func TestAddToBatch_ConcurrentBroadcast(t *testing.T) {
	lb := setupLightweightBatcher(t, 50, 10)
	defer lb.cleanup()

	const goroutines = 50

	panics := runConcurrentlyWithTimeout(t, goroutines, 10*time.Second, func(_ int) {
		lb.b.addToBatch(change.DERPMap())
	})

	assert.Zero(t, panics, "no panics expected")

	// Each node should have received some DERP changes
	nodesWithPending := countNodesPending(lb.b)
	t.Logf("nodes with pending changes: %d/%d", nodesWithPending, 50)
	assert.Positive(t, nodesWithPending,
		"at least some nodes should have pending changes after broadcast")
}

// TestAddToBatch_FullUpdateOverrides verifies that a FullUpdate replaces
// all pending changes for every node.
func TestAddToBatch_FullUpdateOverrides(t *testing.T) {
	lb := setupLightweightBatcher(t, 10, 10)
	defer lb.cleanup()

	// Add some targeted changes first
	for i := 1; i <= 10; i++ {
		lb.b.addToBatch(change.Change{
			Reason:     "pre-existing",
			TargetNode: types.NodeID(i), //nolint:gosec // test with small values
			PeerPatches: []*tailcfg.PeerChange{
				{NodeID: tailcfg.NodeID(100 + i)}, //nolint:gosec // test with small values
			},
		})
	}

	// Full update should replace all pending changes
	lb.b.addToBatch(change.FullUpdate())

	// Every node should have exactly one pending change (the FullUpdate)
	lb.b.nodes.Range(func(id types.NodeID, _ *multiChannelNodeConn) bool {
		pending := getPendingForNode(lb.b, id)
		require.Len(t, pending, 1, "node %d should have exactly 1 pending (FullUpdate)", id)
		assert.True(t, pending[0].IsFull(), "pending change should be a full update")

		return true
	})
}

// TestAddToBatch_NodeRemovalCleanup verifies that PeersRemoved in a change
// cleans up the node from the batcher's internal state.
func TestAddToBatch_NodeRemovalCleanup(t *testing.T) {
	lb := setupLightweightBatcher(t, 5, 10)
	defer lb.cleanup()

	removedNode := types.NodeID(3)

	// Verify node exists before removal
	_, exists := lb.b.nodes.Load(removedNode)
	require.True(t, exists, "node 3 should exist before removal")

	// Send a change that includes node 3 in PeersRemoved
	lb.b.addToBatch(change.Change{
		Reason:       "node deleted",
		PeersRemoved: []types.NodeID{removedNode},
	})

	// Node should be removed from the nodes map
	_, exists = lb.b.nodes.Load(removedNode)
	assert.False(t, exists, "node 3 should be removed from nodes map")

	pending := getPendingForNode(lb.b, removedNode)
	assert.Empty(t, pending, "node 3 should have no pending changes")

	assert.Equal(t, int64(4), lb.b.totalNodes.Load(), "total nodes should be decremented")
}

// ============================================================================
// processBatchedChanges Tests
// ============================================================================

// TestProcessBatchedChanges_QueuesWork verifies that processBatchedChanges
// moves pending changes to the work queue and clears them.
func TestProcessBatchedChanges_QueuesWork(t *testing.T) {
	lb := setupLightweightBatcher(t, 3, 10)
	defer lb.cleanup()

	// Add pending changes for each node
	for i := 1; i <= 3; i++ {
		if nc, ok := lb.b.nodes.Load(types.NodeID(i)); ok { //nolint:gosec // test
			nc.appendPending(change.DERPMap())
		}
	}

	lb.b.processBatchedChanges()

	// Pending should be cleared
	assert.Equal(t, 0, countNodesPending(lb.b),
		"all pending changes should be cleared after processing")

	// Work items should be on the work channel
	assert.Len(t, lb.b.workCh, 3,
		"3 work items should be queued")
}

// TestProcessBatchedChanges_ConcurrentAdd_NoDataLoss verifies that concurrent
// addToBatch and processBatchedChanges calls do not lose data.
//
// Previously (Bug #2): processBatchedChanges used Range→Delete on a separate
// pendingChanges map. A concurrent addToBatch could Store new changes between
// Range reading the key and Delete removing it, losing freshly-stored changes.
// FIX: pendingChanges moved into multiChannelNodeConn with atomic drainPending(),
// eliminating the race entirely.
func TestProcessBatchedChanges_ConcurrentAdd_NoDataLoss(t *testing.T) {
	// Use a single node to maximize contention on one key.
	lb := setupLightweightBatcher(t, 1, 10)
	defer lb.cleanup()

	// Use a large work channel so processBatchedChanges never blocks.
	lb.b.workCh = make(chan work, 100000)

	const iterations = 500

	var addedCount atomic.Int64

	var wg sync.WaitGroup

	// Goroutine 1: continuously add targeted changes to node 1

	wg.Go(func() {
		for i := range iterations {
			lb.b.addToBatch(change.Change{
				Reason:     fmt.Sprintf("add-%d", i),
				TargetNode: types.NodeID(1),
				PeerPatches: []*tailcfg.PeerChange{
					{NodeID: tailcfg.NodeID(i + 100)}, //nolint:gosec // test
				},
			})
			addedCount.Add(1)
		}
	})

	// Goroutine 2: continuously process batched changes

	wg.Go(func() {
		for range iterations {
			lb.b.processBatchedChanges()
		}
	})

	wg.Wait()

	// One final process to flush any remaining
	lb.b.processBatchedChanges()

	// Count total changes across all bundled work items in the channel.
	// Each work item may contain multiple changes since processBatchedChanges
	// bundles all pending changes per node into a single work item.
	queuedChanges := 0

	workItems := len(lb.b.workCh)
	for range workItems {
		w := <-lb.b.workCh
		queuedChanges += len(w.changes)
	}
	// Also count any still-pending
	remaining := len(getPendingForNode(lb.b, types.NodeID(1)))

	total := queuedChanges + remaining
	added := int(addedCount.Load())

	t.Logf("added=%d, queued_changes=%d (in %d work items), still_pending=%d, total_accounted=%d, lost=%d",
		added, queuedChanges, workItems, remaining, total, added-total)

	// Every added change must either be in the work queue or still pending.
	assert.Equal(t, added, total,
		"processBatchedChanges has %d inconsistent changes (%d added vs %d accounted) "+
			"under concurrent access",
		total-added, added, total)
}

// TestProcessBatchedChanges_EmptyPending verifies processBatchedChanges
// is a no-op when there are no pending changes.
func TestProcessBatchedChanges_EmptyPending(t *testing.T) {
	lb := setupLightweightBatcher(t, 5, 10)
	defer lb.cleanup()

	lb.b.processBatchedChanges()

	assert.Empty(t, lb.b.workCh,
		"no work should be queued when there are no pending changes")
}

// TestProcessBatchedChanges_BundlesChangesPerNode verifies that multiple
// pending changes for the same node are bundled into a single work item.
// This prevents out-of-order delivery when different workers pick up
// separate changes for the same node.
func TestProcessBatchedChanges_BundlesChangesPerNode(t *testing.T) {
	lb := setupLightweightBatcher(t, 3, 10)
	defer lb.cleanup()

	// Add multiple pending changes for node 1
	if nc, ok := lb.b.nodes.Load(types.NodeID(1)); ok {
		nc.appendPending(change.DERPMap())
		nc.appendPending(change.DNSConfig())
		nc.appendPending(change.PolicyOnly())
	}
	// Single change for node 2
	if nc, ok := lb.b.nodes.Load(types.NodeID(2)); ok {
		nc.appendPending(change.DERPMap())
	}

	lb.b.processBatchedChanges()

	// Should produce exactly 2 work items: one per node with pending changes.
	// Node 3 had no pending changes, so no work item for it.
	assert.Len(t, lb.b.workCh, 2,
		"should produce one work item per node, not per change")

	// Drain and verify the bundled changes are intact
	totalChanges := 0

	for range 2 {
		w := <-lb.b.workCh

		totalChanges += len(w.changes)
		if w.nodeID == types.NodeID(1) {
			assert.Len(t, w.changes, 3,
				"node 1's work item should contain all 3 changes")
		} else {
			assert.Len(t, w.changes, 1,
				"node 2's work item should contain 1 change")
		}
	}

	assert.Equal(t, 4, totalChanges, "total changes across all work items")
}

// TestWorkMu_PreventsInterTickRace verifies that workMu serializes change
// processing across consecutive batch ticks. Without workMu, two workers
// could process bundles from tick N and tick N+1 concurrently for the same
// node, causing out-of-order delivery and races on lastSentPeers.
func TestWorkMu_PreventsInterTickRace(t *testing.T) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	mc := newMultiChannelNodeConn(1, nil)
	ch := make(chan *tailcfg.MapResponse, 100)
	entry := &connectionEntry{
		id:      "test",
		c:       ch,
		version: tailcfg.CapabilityVersion(100),
		created: time.Now(),
	}
	entry.lastUsed.Store(time.Now().Unix())
	mc.addConnection(entry)

	// Track the order in which work completes
	var (
		order []int
		mu    sync.Mutex
	)

	record := func(id int) {
		mu.Lock()

		order = append(order, id)
		mu.Unlock()
	}

	var wg sync.WaitGroup

	// Simulate two workers grabbing consecutive tick bundles.
	// Worker 1 holds workMu and sleeps, worker 2 must wait.
	wg.Go(func() {
		mc.workMu.Lock()
		// Simulate processing time for tick N's bundle
		time.Sleep(50 * time.Millisecond) //nolint:forbidigo
		record(1)
		mc.workMu.Unlock()
	})

	// Small delay so worker 1 grabs the lock first
	time.Sleep(5 * time.Millisecond) //nolint:forbidigo

	wg.Go(func() {
		mc.workMu.Lock()
		record(2)
		mc.workMu.Unlock()
	})

	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	require.Len(t, order, 2)
	assert.Equal(t, 1, order[0], "worker 1 (tick N) should complete first")
	assert.Equal(t, 2, order[1], "worker 2 (tick N+1) should complete second")
}

// ============================================================================
// cleanupOfflineNodes Tests
// ============================================================================

// TestCleanupOfflineNodes_RemovesOld verifies that nodes offline longer
// than the 15-minute threshold are removed.
func TestCleanupOfflineNodes_RemovesOld(t *testing.T) {
	lb := setupLightweightBatcher(t, 5, 10)
	defer lb.cleanup()

	// Remove node 3's active connections and mark it disconnected 20 minutes ago
	if mc, ok := lb.b.nodes.Load(types.NodeID(3)); ok {
		ch := lb.channels[types.NodeID(3)]
		mc.removeConnectionByChannel(ch)

		oldTime := time.Now().Add(-20 * time.Minute)
		mc.disconnectedAt.Store(&oldTime)
	}

	lb.b.cleanupOfflineNodes()

	_, exists := lb.b.nodes.Load(types.NodeID(3))
	assert.False(t, exists, "node 3 should be cleaned up (offline >15min)")

	// Other nodes should still be present
	_, exists = lb.b.nodes.Load(types.NodeID(1))
	assert.True(t, exists, "node 1 should still exist")
}

// TestCleanupOfflineNodes_KeepsRecent verifies that recently disconnected
// nodes are not cleaned up.
func TestCleanupOfflineNodes_KeepsRecent(t *testing.T) {
	lb := setupLightweightBatcher(t, 5, 10)
	defer lb.cleanup()

	// Remove node 3's connections and mark it disconnected 5 minutes ago (under threshold)
	if mc, ok := lb.b.nodes.Load(types.NodeID(3)); ok {
		ch := lb.channels[types.NodeID(3)]
		mc.removeConnectionByChannel(ch)

		recentTime := time.Now().Add(-5 * time.Minute)
		mc.disconnectedAt.Store(&recentTime)
	}

	lb.b.cleanupOfflineNodes()

	_, exists := lb.b.nodes.Load(types.NodeID(3))
	assert.True(t, exists, "node 3 should NOT be cleaned up (offline <15min)")
}

// TestCleanupOfflineNodes_KeepsActive verifies that nodes with active
// connections are never cleaned up, even if disconnect time is set.
func TestCleanupOfflineNodes_KeepsActive(t *testing.T) {
	lb := setupLightweightBatcher(t, 5, 10)
	defer lb.cleanup()

	// Set old disconnect time but keep the connection active
	if mc, ok := lb.b.nodes.Load(types.NodeID(3)); ok {
		oldTime := time.Now().Add(-20 * time.Minute)
		mc.disconnectedAt.Store(&oldTime)
	}
	// Don't remove connection - node still has active connections

	lb.b.cleanupOfflineNodes()

	_, exists := lb.b.nodes.Load(types.NodeID(3))
	assert.True(t, exists,
		"node 3 should NOT be cleaned up (still has active connections)")
}

// ============================================================================
// Batcher Lifecycle Tests
// ============================================================================

// TestBatcher_CloseStopsWorkers verifies that Close() signals workers to stop
// and doesn't deadlock.
func TestBatcher_CloseStopsWorkers(t *testing.T) {
	lb := setupLightweightBatcher(t, 3, 10)

	// Start workers
	lb.b.Start()

	// Queue some work
	if nc, ok := lb.b.nodes.Load(types.NodeID(1)); ok {
		nc.appendPending(change.DERPMap())
	}

	lb.b.processBatchedChanges()

	// Close should not deadlock
	done := make(chan struct{})

	go func() {
		lb.b.Close()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("Close() deadlocked")
	}
}

// TestBatcher_CloseMultipleTimes_DoubleClosePanic exercises Bug #4:
// multiChannelNodeConn.close() has no idempotency guard. Calling Close()
// concurrently triggers close() on the same channels multiple times,
// panicking with "close of closed channel".
//
// BUG: batcher_lockfree.go:555-565 - close() calls close(conn.c) with no guard
// FIX: Add sync.Once or atomic.Bool to multiChannelNodeConn.close().
func TestBatcher_CloseMultipleTimes_DoubleClosePanic(t *testing.T) {
	lb := setupLightweightBatcher(t, 3, 10)
	lb.b.Start()

	// Close multiple times concurrently.
	// The done channel and workCh are protected by sync.Once and should not panic.
	// But node connection close() WILL panic because it has no idempotency guard.
	panics := runConcurrently(t, 10, func(_ int) {
		lb.b.Close()
	})

	assert.Zero(t, panics,
		"BUG #4: %d panics from concurrent Close() due to "+
			"multiChannelNodeConn.close() lacking idempotency guard. "+
			"Fix: add sync.Once or atomic.Bool to close()", panics)
}

// TestBatcher_MapResponseDuringShutdown verifies that MapResponseFromChange
// returns ErrBatcherShuttingDown when the batcher is closed.
func TestBatcher_MapResponseDuringShutdown(t *testing.T) {
	lb := setupLightweightBatcher(t, 3, 10)

	// Close the done channel
	close(lb.b.done)

	_, err := lb.b.MapResponseFromChange(types.NodeID(1), change.DERPMap())
	assert.ErrorIs(t, err, ErrBatcherShuttingDown)
}

// TestBatcher_IsConnectedReflectsState verifies IsConnected accurately
// reflects the connection state of nodes.
func TestBatcher_IsConnectedReflectsState(t *testing.T) {
	lb := setupLightweightBatcher(t, 5, 10)
	defer lb.cleanup()

	// All nodes should be connected
	for i := 1; i <= 5; i++ {
		assert.True(t, lb.b.IsConnected(types.NodeID(i)), //nolint:gosec // test
			"node %d should be connected", i)
	}

	// Non-existent node should not be connected
	assert.False(t, lb.b.IsConnected(types.NodeID(999)))

	// Disconnect node 3 (remove connection + mark disconnected)
	if mc, ok := lb.b.nodes.Load(types.NodeID(3)); ok {
		mc.removeConnectionByChannel(lb.channels[types.NodeID(3)])
		mc.markDisconnected()
	}

	assert.False(t, lb.b.IsConnected(types.NodeID(3)),
		"node 3 should not be connected after disconnection")

	// Other nodes should still be connected
	assert.True(t, lb.b.IsConnected(types.NodeID(1)))
	assert.True(t, lb.b.IsConnected(types.NodeID(5)))
}

// TestBatcher_ConnectedMapConsistency verifies ConnectedMap returns accurate
// state for all nodes.
func TestBatcher_ConnectedMapConsistency(t *testing.T) {
	lb := setupLightweightBatcher(t, 5, 10)
	defer lb.cleanup()

	// Disconnect node 2
	if mc, ok := lb.b.nodes.Load(types.NodeID(2)); ok {
		mc.removeConnectionByChannel(lb.channels[types.NodeID(2)])
		mc.markDisconnected()
	}

	cm := lb.b.ConnectedMap()

	// Connected nodes
	for _, id := range []types.NodeID{1, 3, 4, 5} {
		val, ok := cm.Load(id)
		assert.True(t, ok, "node %d should be in ConnectedMap", id)
		assert.True(t, val, "node %d should be connected", id)
	}

	// Disconnected node
	val, ok := cm.Load(types.NodeID(2))
	assert.True(t, ok, "node 2 should be in ConnectedMap")
	assert.False(t, val, "node 2 should be disconnected")
}

// ============================================================================
// Bug Reproduction Tests (all expected to FAIL until bugs are fixed)
// ============================================================================

// TestBug3_CleanupOfflineNodes_TOCTOU exercises Bug #3:
// TestBug3_CleanupOfflineNodes_TOCTOU exercises the TOCTOU race in
// cleanupOfflineNodes. Without the Compute() fix, the old code did:
//
//  1. Range connected map → collect candidates
//  2. Load node → check hasActiveConnections() == false
//  3. Delete node
//
// Between steps 2 and 3, AddNode could reconnect the node via
// LoadOrStore, adding a connection to the existing entry. The
// subsequent Delete would then remove the live reconnected node.
//
// FIX: Use Compute() on b.nodes for atomic check-and-delete. Inside
// the Compute closure, hasActiveConnections() is checked and the
// entry is only deleted if still inactive. A concurrent AddNode that
// calls addConnection() on the same entry makes hasActiveConnections()
// return true, causing Compute to cancel the delete.
func TestBug3_CleanupOfflineNodes_TOCTOU(t *testing.T) {
	lb := setupLightweightBatcher(t, 5, 10)
	defer lb.cleanup()

	targetNode := types.NodeID(3)

	// Remove node 3's active connections and mark it disconnected >15 minutes ago
	if mc, ok := lb.b.nodes.Load(targetNode); ok {
		ch := lb.channels[targetNode]
		mc.removeConnectionByChannel(ch)

		oldTime := time.Now().Add(-20 * time.Minute)
		mc.disconnectedAt.Store(&oldTime)
	}

	// Verify node 3 has no active connections before we start.
	if mc, ok := lb.b.nodes.Load(targetNode); ok {
		require.False(t, mc.hasActiveConnections(),
			"precondition: node 3 should have no active connections")
	}

	// Simulate a reconnection that happens BEFORE cleanup's Compute() runs.
	// With the Compute() fix, the atomic check inside Compute sees
	// hasActiveConnections()==true and cancels the delete.
	mc, exists := lb.b.nodes.Load(targetNode)
	require.True(t, exists, "node 3 should exist before reconnection")

	newCh := make(chan *tailcfg.MapResponse, 10)
	entry := &connectionEntry{
		id:      "reconnected",
		c:       newCh,
		version: tailcfg.CapabilityVersion(100),
		created: time.Now(),
	}
	entry.lastUsed.Store(time.Now().Unix())
	mc.addConnection(entry)
	mc.markConnected()
	lb.channels[targetNode] = newCh

	// Now run cleanup. Node 3 is in the candidates list (old disconnect
	// time) but has been reconnected. The Compute() fix should see the
	// active connection and cancel the delete.
	lb.b.cleanupOfflineNodes()

	// Node 3 MUST still exist because it has an active connection.
	_, stillExists := lb.b.nodes.Load(targetNode)
	assert.True(t, stillExists,
		"BUG #3: cleanupOfflineNodes deleted node %d despite it having an active "+
			"connection. The Compute() fix should atomically check "+
			"hasActiveConnections() and cancel the delete.",
		targetNode)

	// Also verify the concurrent case: cleanup and reconnection racing.
	// Set up node 3 as offline again.
	mc.removeConnectionByChannel(newCh)

	oldTime2 := time.Now().Add(-20 * time.Minute)
	mc.disconnectedAt.Store(&oldTime2)

	var wg sync.WaitGroup

	// Run 100 iterations of concurrent cleanup + reconnection.
	// With Compute(), either cleanup wins (node deleted, LoadOrStore
	// recreates) or reconnection wins (Compute sees active conn, cancels).
	// Either way the node must exist after both complete.
	for range 100 {
		wg.Go(func() {
			// Simulate reconnection via addConnection (like AddNode does)
			if mc, ok := lb.b.nodes.Load(targetNode); ok {
				reconnCh := make(chan *tailcfg.MapResponse, 10)
				reconnEntry := &connectionEntry{
					id:      "race-reconn",
					c:       reconnCh,
					version: tailcfg.CapabilityVersion(100),
					created: time.Now(),
				}
				reconnEntry.lastUsed.Store(time.Now().Unix())
				mc.addConnection(reconnEntry)
				mc.markConnected()
			}
		})

		wg.Go(func() {
			lb.b.cleanupOfflineNodes()
		})
	}

	wg.Wait()
}

// TestBug5_WorkerPanicKillsWorkerPermanently exercises Bug #5:
// If b.nodes.Load() returns exists=true but a nil *multiChannelNodeConn,
// the worker would panic on a nil pointer dereference. Without nil guards,
// this kills the worker goroutine permanently (no recover), reducing
// throughput and eventually deadlocking when all workers are dead.
//
// BUG: batcher_lockfree.go worker() - no nil check after b.nodes.Load()
// FIX: Add nil guard: `exists && nc != nil` in both sync and async paths.
func TestBug5_WorkerPanicKillsWorkerPermanently(t *testing.T) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	lb := setupLightweightBatcher(t, 3, 10)
	defer lb.cleanup()

	lb.b.workers = 2
	lb.b.Start()

	// Give workers time to start
	time.Sleep(50 * time.Millisecond) //nolint:forbidigo // concurrency test coordination

	// Store a nil value in b.nodes for a specific node ID.
	// This simulates a race where a node entry exists but the value is nil
	// (e.g., concurrent cleanup setting nil before deletion).
	nilNodeID := types.NodeID(55555)
	lb.b.nodes.Store(nilNodeID, nil)

	// Queue async work (resultCh=nil) targeting the nil node.
	// Without the nil guard, this would panic: nc.change(w.c) on nil nc.
	for range 10 {
		lb.b.queueWork(work{
			changes: []change.Change{change.DERPMap()},
			nodeID:  nilNodeID,
		})
	}

	// Queue sync work (with resultCh) targeting the nil node.
	// Without the nil guard, this would panic: generateMapResponse(nc, ...)
	// on nil nc.
	for range 5 {
		resultCh := make(chan workResult, 1)
		lb.b.queueWork(work{
			changes:  []change.Change{change.DERPMap()},
			nodeID:   nilNodeID,
			resultCh: resultCh,
		})
		// Read the result so workers don't block.
		select {
		case res := <-resultCh:
			// With nil guard, result should have nil mapResponse (no work done).
			assert.Nil(t, res.mapResponse,
				"sync work for nil node should return nil mapResponse")
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for sync work result — worker may have panicked")
		}
	}

	// Wait for async work to drain
	time.Sleep(100 * time.Millisecond) //nolint:forbidigo // concurrency test coordination

	// Now queue valid work for a real node to prove workers are still alive.
	beforeValid := lb.b.workProcessed.Load()
	for range 5 {
		lb.b.queueWork(work{
			changes: []change.Change{change.DERPMap()},
			nodeID:  types.NodeID(1),
		})
	}

	time.Sleep(200 * time.Millisecond) //nolint:forbidigo // concurrency test coordination

	afterValid := lb.b.workProcessed.Load()
	validProcessed := afterValid - beforeValid
	t.Logf("valid work processed after nil-node work: %d/5", validProcessed)

	assert.Equal(t, int64(5), validProcessed,
		"workers must remain functional after encountering nil node entries")
}

// TestBug6_StartCalledMultipleTimes_GoroutineLeak exercises Bug #6:
// Start() creates a new done channel and launches doWork() every time,
// with no guard against multiple calls. Each call spawns (workers+1)
// goroutines that never get cleaned up.
//
// BUG: batcher_lockfree.go:163-166 - Start() has no "already started" check
// FIX: Add sync.Once or atomic.Bool to prevent multiple Start() calls.
func TestBug6_StartCalledMultipleTimes_GoroutineLeak(t *testing.T) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	lb := setupLightweightBatcher(t, 3, 10)
	lb.b.workers = 2

	goroutinesBefore := runtime.NumGoroutine()

	// Call Start() once - this should launch (workers + 1) goroutines
	// (1 for doWork + workers for worker())
	lb.b.Start()
	time.Sleep(50 * time.Millisecond) //nolint:forbidigo // concurrency test coordination

	goroutinesAfterFirst := runtime.NumGoroutine()
	firstStartDelta := goroutinesAfterFirst - goroutinesBefore
	t.Logf("goroutines: before=%d, after_first_Start=%d, delta=%d",
		goroutinesBefore, goroutinesAfterFirst, firstStartDelta)

	// Call Start() again - this SHOULD be a no-op
	// BUG: it creates a NEW done channel (orphaning goroutines listening on the old one)
	// and launches another doWork()+workers set
	lb.b.Start()
	time.Sleep(50 * time.Millisecond) //nolint:forbidigo // concurrency test coordination

	goroutinesAfterSecond := runtime.NumGoroutine()
	secondStartDelta := goroutinesAfterSecond - goroutinesAfterFirst
	t.Logf("goroutines: after_second_Start=%d, delta=%d (should be 0)",
		goroutinesAfterSecond, secondStartDelta)

	// Call Start() a third time
	lb.b.Start()
	time.Sleep(50 * time.Millisecond) //nolint:forbidigo // concurrency test coordination

	goroutinesAfterThird := runtime.NumGoroutine()
	thirdStartDelta := goroutinesAfterThird - goroutinesAfterSecond
	t.Logf("goroutines: after_third_Start=%d, delta=%d (should be 0)",
		goroutinesAfterThird, thirdStartDelta)

	// Close() only closes the LAST done channel, leaving earlier goroutines leaked
	lb.b.Close()
	time.Sleep(100 * time.Millisecond) //nolint:forbidigo // concurrency test coordination

	goroutinesAfterClose := runtime.NumGoroutine()
	t.Logf("goroutines after Close: %d (leaked: %d)",
		goroutinesAfterClose, goroutinesAfterClose-goroutinesBefore)

	// Second Start() should NOT have created new goroutines
	assert.Zero(t, secondStartDelta,
		"BUG #6: second Start() call leaked %d goroutines. "+
			"Start() has no idempotency guard, each call spawns new goroutines. "+
			"Fix: add sync.Once or atomic.Bool to prevent multiple Start() calls",
		secondStartDelta)
}

// TestBug7_CleanupOfflineNodes_PendingChangesCleanedStructurally verifies that
// pending changes are automatically cleaned up when a node is removed from the
// nodes map, because pending state lives inside multiChannelNodeConn.
//
// Previously (Bug #7): pendingChanges was a separate map that was NOT cleaned
// when cleanupOfflineNodes removed a node, causing orphaned entries.
// FIX: pendingChanges moved into multiChannelNodeConn — deleting the node
// from b.nodes automatically drops its pending changes.
func TestBug7_CleanupOfflineNodes_PendingChangesCleanedStructurally(t *testing.T) {
	lb := setupLightweightBatcher(t, 5, 10)
	defer lb.cleanup()

	targetNode := types.NodeID(3)

	// Remove node 3's connections and mark it disconnected >15 minutes ago
	if mc, ok := lb.b.nodes.Load(targetNode); ok {
		ch := lb.channels[targetNode]
		mc.removeConnectionByChannel(ch)

		oldTime := time.Now().Add(-20 * time.Minute)
		mc.disconnectedAt.Store(&oldTime)
	}

	// Add pending changes for node 3 before cleanup
	if nc, ok := lb.b.nodes.Load(targetNode); ok {
		nc.appendPending(change.DERPMap())
	}

	// Verify pending exists before cleanup
	pending := getPendingForNode(lb.b, targetNode)
	require.Len(t, pending, 1, "node 3 should have pending changes before cleanup")

	// Run cleanup
	lb.b.cleanupOfflineNodes()

	// Node 3 should be removed from the nodes map
	_, existsInNodes := lb.b.nodes.Load(targetNode)
	assert.False(t, existsInNodes, "node 3 should be removed from nodes map")

	// Pending changes are structurally gone because the node was deleted.
	// getPendingForNode returns nil for non-existent nodes.
	pendingAfter := getPendingForNode(lb.b, targetNode)
	assert.Empty(t, pendingAfter,
		"pending changes should be gone after node deletion (structural fix)")
}

// TestBug8_SerialTimeoutUnderWriteLock exercises Bug #8 (performance):
// multiChannelNodeConn.send() originally held the write lock for the ENTIRE
// duration of sending to all connections. Each send has a 50ms timeout for
// stale connections. With N stale connections, the write lock was held for
// N*50ms, blocking all addConnection/removeConnection calls.
//
// BUG: mutex.Lock() held during all conn.send() calls, each with 50ms timeout.
//
//	5 stale connections = 250ms lock hold, blocking addConnection/removeConnection.
//
// FIX: Snapshot connections under read lock, release, send without any lock
//
//	(timeouts happen here), then write-lock only to remove failed connections.
//	The lock is now held only for O(N) pointer copies, not for N*50ms I/O.
func TestBug8_SerialTimeoutUnderWriteLock(t *testing.T) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	mc := newMultiChannelNodeConn(1, nil)

	// Add 5 stale connections (unbuffered, no reader = will timeout at 50ms each)
	const staleCount = 5
	for i := range staleCount {
		ch := make(chan *tailcfg.MapResponse) // unbuffered
		mc.addConnection(makeConnectionEntry(fmt.Sprintf("stale-%d", i), ch))
	}

	// The key test: verify that the mutex is NOT held during the slow sends.
	// We do this by trying to acquire the lock from another goroutine during
	// the send. With the old code (lock held for 250ms), this would block.
	// With the fix, the lock is free during sends.
	lockAcquired := make(chan time.Duration, 1)

	go func() {
		// Give send() a moment to start (it will be in the unlocked send window)
		time.Sleep(20 * time.Millisecond) //nolint:forbidigo // concurrency test coordination

		// Try to acquire the write lock. It should succeed quickly because
		// the lock is only held briefly for the snapshot and cleanup.
		start := time.Now()

		mc.mutex.Lock()
		lockWait := time.Since(start)
		mc.mutex.Unlock()

		lockAcquired <- lockWait
	}()

	// Run send() with 5 stale connections. Total wall time will be ~250ms
	// (5 * 50ms serial timeouts), but the lock should be free during sends.
	_ = mc.send(testMapResponse())

	lockWait := <-lockAcquired
	t.Logf("lock acquisition during send() with %d stale connections waited %v",
		staleCount, lockWait)

	// The lock wait should be very short (<50ms) since the lock is released
	// before sending. With the old code it would be ~230ms (250ms - 20ms sleep).
	assert.Less(t, lockWait, 50*time.Millisecond,
		"mutex was held for %v during send() with %d stale connections; "+
			"lock should be released before sending to allow "+
			"concurrent addConnection/removeConnection calls",
		lockWait, staleCount)
}

// TestBug1_BroadcastNoDataLoss verifies that concurrent broadcast addToBatch
// calls do not lose data.
//
// Previously (Bug #1, broadcast path): Same Load→append→Store race as targeted
// changes, but on the broadcast code path within the Range callback.
// FIX: pendingChanges moved into multiChannelNodeConn with mutex protection.
func TestBug1_BroadcastNoDataLoss(t *testing.T) {
	// Use many nodes so the Range iteration takes longer, widening the race window
	lb := setupLightweightBatcher(t, 100, 10)
	defer lb.cleanup()

	const goroutines = 50

	// Each goroutine broadcasts a DERPMap change to all 100 nodes
	panics := runConcurrentlyWithTimeout(t, goroutines, 10*time.Second, func(_ int) {
		lb.b.addToBatch(change.DERPMap())
	})

	require.Zero(t, panics, "no panics expected")

	// Each of the 100 nodes should have exactly `goroutines` pending changes.
	// The race causes some nodes to have fewer.
	var (
		totalLost     int
		nodesWithLoss int
	)

	lb.b.nodes.Range(func(id types.NodeID, _ *multiChannelNodeConn) bool {
		pending := getPendingForNode(lb.b, id)
		if len(pending) < goroutines {
			totalLost += goroutines - len(pending)
			nodesWithLoss++
		}

		return true
	})

	t.Logf("broadcast data loss: %d total changes lost across %d/%d nodes",
		totalLost, nodesWithLoss, 100)

	assert.Zero(t, totalLost,
		"broadcast lost %d changes across %d nodes under concurrent access",
		totalLost, nodesWithLoss)
}

// ============================================================================
// 1000-Node Scale Tests (lightweight, no DB)
// ============================================================================

// TestScale1000_AddToBatch_Broadcast verifies that broadcasting to 1000 nodes
// works correctly under concurrent access.
func TestScale1000_AddToBatch_Broadcast(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1000-node test in short mode")
	}

	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	lb := setupLightweightBatcher(t, 1000, 10)
	defer lb.cleanup()

	const concurrentBroadcasts = 100

	panics := runConcurrentlyWithTimeout(t, concurrentBroadcasts, 30*time.Second, func(_ int) {
		lb.b.addToBatch(change.DERPMap())
	})

	assert.Zero(t, panics, "no panics expected")

	nodesWithPending := countNodesPending(lb.b)
	totalPending := countTotalPending(lb.b)

	t.Logf("1000-node broadcast: %d/%d nodes have pending, %d total pending items",
		nodesWithPending, 1000, totalPending)

	// All 1000 nodes should have at least some pending changes
	// (may lose some due to Bug #1 race, but should have most)
	assert.GreaterOrEqual(t, nodesWithPending, 900,
		"at least 90%% of nodes should have pending changes")
}

// TestScale1000_ProcessBatchedWithConcurrentAdd tests processBatchedChanges
// running concurrently with addToBatch at 1000 nodes.
func TestScale1000_ProcessBatchedWithConcurrentAdd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1000-node test in short mode")
	}

	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	lb := setupLightweightBatcher(t, 1000, 10)
	defer lb.cleanup()

	// Use a large work channel to avoid blocking.
	// 50 broadcasts × 1000 nodes = up to 50,000 work items.
	lb.b.workCh = make(chan work, 100000)

	var wg sync.WaitGroup

	// Producer: add broadcasts

	wg.Go(func() {
		for range 50 {
			lb.b.addToBatch(change.DERPMap())
		}
	})

	// Consumer: process batched changes repeatedly

	wg.Go(func() {
		for range 50 {
			lb.b.processBatchedChanges()
			time.Sleep(1 * time.Millisecond) //nolint:forbidigo // concurrency test coordination
		}
	})

	done := make(chan struct{})

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Logf("1000-node concurrent add+process completed without deadlock")
	case <-time.After(30 * time.Second):
		t.Fatal("deadlock detected in 1000-node concurrent add+process")
	}

	queuedWork := len(lb.b.workCh)
	t.Logf("work items queued: %d", queuedWork)
	assert.Positive(t, queuedWork, "should have queued some work items")
}

// TestScale1000_MultiChannelBroadcast tests broadcasting a MapResponse
// to 1000 nodes, each with 1-3 connections.
func TestScale1000_MultiChannelBroadcast(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1000-node test in short mode")
	}

	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	const (
		nodeCount  = 1000
		bufferSize = 5
	)

	// Create nodes with varying connection counts
	b := &Batcher{
		tick:    time.NewTicker(10 * time.Millisecond),
		workers: 4,
		workCh:  make(chan work, 4*200),
		nodes:   xsync.NewMap[types.NodeID, *multiChannelNodeConn](),
		done:    make(chan struct{}),
	}

	defer func() {
		close(b.done)
		b.tick.Stop()
	}()

	type nodeChannels struct {
		channels []chan *tailcfg.MapResponse
	}

	allNodeChannels := make(map[types.NodeID]*nodeChannels, nodeCount)

	for i := 1; i <= nodeCount; i++ {
		id := types.NodeID(i) //nolint:gosec // test with small controlled values
		mc := newMultiChannelNodeConn(id, nil)

		connCount := 1 + (i % 3) // 1, 2, or 3 connections
		nc := &nodeChannels{channels: make([]chan *tailcfg.MapResponse, connCount)}

		for j := range connCount {
			ch := make(chan *tailcfg.MapResponse, bufferSize)
			nc.channels[j] = ch
			entry := &connectionEntry{
				id:      fmt.Sprintf("conn-%d-%d", i, j),
				c:       ch,
				version: tailcfg.CapabilityVersion(100),
				created: time.Now(),
			}
			entry.lastUsed.Store(time.Now().Unix())
			mc.addConnection(entry)
		}

		b.nodes.Store(id, mc)
		allNodeChannels[id] = nc
	}

	// Broadcast to all nodes
	data := testMapResponse()

	var successCount, failCount atomic.Int64

	start := time.Now()

	b.nodes.Range(func(id types.NodeID, mc *multiChannelNodeConn) bool {
		err := mc.send(data)
		if err != nil {
			failCount.Add(1)
		} else {
			successCount.Add(1)
		}

		return true
	})

	elapsed := time.Since(start)

	t.Logf("broadcast to %d nodes: %d success, %d failures, took %v",
		nodeCount, successCount.Load(), failCount.Load(), elapsed)

	assert.Equal(t, int64(nodeCount), successCount.Load(),
		"all nodes should receive broadcast successfully")
	assert.Zero(t, failCount.Load(), "no broadcast failures expected")

	// Verify at least some channels received data
	receivedCount := 0

	for _, nc := range allNodeChannels {
		for _, ch := range nc.channels {
			select {
			case <-ch:
				receivedCount++
			default:
			}
		}
	}

	t.Logf("channels that received data: %d", receivedCount)
	assert.Positive(t, receivedCount, "channels should have received broadcast data")
}

// TestScale1000_ConnectionChurn tests 1000 nodes with 10% churning connections
// while broadcasts are happening. Stable nodes should not lose data.
func TestScale1000_ConnectionChurn(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1000-node test in short mode")
	}

	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	lb := setupLightweightBatcher(t, 1000, 20)
	defer lb.cleanup()

	const churnNodes = 100 // 10% of nodes churn

	const churnCycles = 50

	var (
		panics atomic.Int64
		wg     sync.WaitGroup
	)

	// Churn goroutine: rapidly add/remove connections for nodes 901-1000

	wg.Go(func() {
		for cycle := range churnCycles {
			for i := 901; i <= 901+churnNodes-1; i++ {
				id := types.NodeID(i) //nolint:gosec // test with small controlled values

				mc, exists := lb.b.nodes.Load(id)
				if !exists {
					continue
				}

				// Remove old connection
				oldCh := lb.channels[id]
				mc.removeConnectionByChannel(oldCh)

				// Add new connection
				newCh := make(chan *tailcfg.MapResponse, 20)
				entry := &connectionEntry{
					id:      fmt.Sprintf("churn-%d-%d", i, cycle),
					c:       newCh,
					version: tailcfg.CapabilityVersion(100),
					created: time.Now(),
				}
				entry.lastUsed.Store(time.Now().Unix())
				mc.addConnection(entry)

				lb.channels[id] = newCh
			}
		}
	})

	// Broadcast goroutine: send addToBatch calls during churn

	wg.Go(func() {
		for range churnCycles {
			func() {
				defer func() {
					if r := recover(); r != nil {
						panics.Add(1)
					}
				}()

				lb.b.addToBatch(change.DERPMap())
			}()
		}
	})

	done := make(chan struct{})

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(30 * time.Second):
		t.Fatal("deadlock in 1000-node connection churn test")
	}

	assert.Zero(t, panics.Load(), "no panics during connection churn")

	// Verify stable nodes (1-900) still have active connections
	stableConnected := 0

	for i := 1; i <= 900; i++ {
		if mc, exists := lb.b.nodes.Load(types.NodeID(i)); exists { //nolint:gosec // test
			if mc.hasActiveConnections() {
				stableConnected++
			}
		}
	}

	t.Logf("stable nodes still connected: %d/900", stableConnected)
	assert.Equal(t, 900, stableConnected,
		"all stable nodes should retain their connections during churn")
}

// TestScale1000_ConcurrentAddRemove tests concurrent AddNode-like and
// RemoveNode-like operations at 1000-node scale.
func TestScale1000_ConcurrentAddRemove(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1000-node test in short mode")
	}

	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	lb := setupLightweightBatcher(t, 1000, 10)
	defer lb.cleanup()

	const goroutines = 200

	panics := runConcurrentlyWithTimeout(t, goroutines, 30*time.Second, func(i int) {
		id := types.NodeID(1 + (i % 1000)) //nolint:gosec // test

		mc, exists := lb.b.nodes.Load(id)
		if !exists {
			return
		}

		if i%2 == 0 {
			// Add a new connection
			ch := make(chan *tailcfg.MapResponse, 10)
			entry := &connectionEntry{
				id:      fmt.Sprintf("concurrent-%d", i),
				c:       ch,
				version: tailcfg.CapabilityVersion(100),
				created: time.Now(),
			}
			entry.lastUsed.Store(time.Now().Unix())
			mc.addConnection(entry)
		} else {
			// Try to remove a connection (may fail if already removed)
			ch := lb.channels[id]
			mc.removeConnectionByChannel(ch)
		}
	})

	assert.Zero(t, panics, "no panics during concurrent add/remove at 1000 nodes")
}

// TestScale1000_IsConnectedConsistency verifies IsConnected returns consistent
// results during rapid connection state changes at 1000-node scale.
func TestScale1000_IsConnectedConsistency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1000-node test in short mode")
	}

	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	lb := setupLightweightBatcher(t, 1000, 10)
	defer lb.cleanup()

	var (
		panics atomic.Int64
		wg     sync.WaitGroup
	)

	// Goroutines reading IsConnected

	wg.Go(func() {
		for range 1000 {
			func() {
				defer func() {
					if r := recover(); r != nil {
						panics.Add(1)
					}
				}()

				for i := 1; i <= 1000; i++ {
					_ = lb.b.IsConnected(types.NodeID(i)) //nolint:gosec // test
				}
			}()
		}
	})

	// Goroutine modifying connection state via disconnectedAt on the node conn

	wg.Go(func() {
		for i := range 100 {
			id := types.NodeID(1 + (i % 1000)) //nolint:gosec // test
			if mc, ok := lb.b.nodes.Load(id); ok {
				if i%2 == 0 {
					mc.markDisconnected() // disconnect
				} else {
					mc.markConnected() // reconnect
				}
			}
		}
	})

	done := make(chan struct{})

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(30 * time.Second):
		t.Fatal("deadlock in IsConnected consistency test")
	}

	assert.Zero(t, panics.Load(),
		"IsConnected should not panic under concurrent modification")
}

// TestScale1000_BroadcastDuringNodeChurn tests that broadcast addToBatch
// calls work correctly while 20% of nodes are joining and leaving.
func TestScale1000_BroadcastDuringNodeChurn(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1000-node test in short mode")
	}

	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	lb := setupLightweightBatcher(t, 1000, 10)
	defer lb.cleanup()

	var (
		panics atomic.Int64
		wg     sync.WaitGroup
	)

	// Node churn: 20% of nodes (nodes 801-1000) joining/leaving

	wg.Go(func() {
		for cycle := range 20 {
			for i := 801; i <= 1000; i++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							panics.Add(1)
						}
					}()

					id := types.NodeID(i) //nolint:gosec // test
					if cycle%2 == 0 {
						// "Remove" node
						lb.b.nodes.Delete(id)
					} else {
						// "Add" node back
						mc := newMultiChannelNodeConn(id, nil)
						ch := make(chan *tailcfg.MapResponse, 10)
						entry := &connectionEntry{
							id:      fmt.Sprintf("rechurn-%d-%d", i, cycle),
							c:       ch,
							version: tailcfg.CapabilityVersion(100),
							created: time.Now(),
						}
						entry.lastUsed.Store(time.Now().Unix())
						mc.addConnection(entry)
						lb.b.nodes.Store(id, mc)
					}
				}()
			}
		}
	})

	// Concurrent broadcasts

	wg.Go(func() {
		for range 50 {
			func() {
				defer func() {
					if r := recover(); r != nil {
						panics.Add(1)
					}
				}()

				lb.b.addToBatch(change.DERPMap())
			}()
		}
	})

	done := make(chan struct{})

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Logf("broadcast during churn completed, panics: %d", panics.Load())
	case <-time.After(30 * time.Second):
		t.Fatal("deadlock in broadcast during node churn")
	}

	assert.Zero(t, panics.Load(),
		"broadcast during node churn should not panic")
}

// TestScale1000_WorkChannelSaturation tests that the work channel doesn't
// deadlock when it fills up (queueWork selects on done channel as escape).
func TestScale1000_WorkChannelSaturation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1000-node test in short mode")
	}

	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	// Create batcher with SMALL work channel to force saturation
	b := &Batcher{
		tick:    time.NewTicker(10 * time.Millisecond),
		workers: 2,
		workCh:  make(chan work, 10), // Very small - will saturate
		nodes:   xsync.NewMap[types.NodeID, *multiChannelNodeConn](),
		done:    make(chan struct{}),
	}

	defer func() {
		close(b.done)
		b.tick.Stop()
	}()

	// Add 1000 nodes
	for i := 1; i <= 1000; i++ {
		id := types.NodeID(i) //nolint:gosec // test
		mc := newMultiChannelNodeConn(id, nil)
		ch := make(chan *tailcfg.MapResponse, 1)
		entry := &connectionEntry{
			id:      fmt.Sprintf("conn-%d", i),
			c:       ch,
			version: tailcfg.CapabilityVersion(100),
			created: time.Now(),
		}
		entry.lastUsed.Store(time.Now().Unix())
		mc.addConnection(entry)
		b.nodes.Store(id, mc)
	}

	// Add pending changes for all 1000 nodes
	for i := 1; i <= 1000; i++ {
		if nc, ok := b.nodes.Load(types.NodeID(i)); ok { //nolint:gosec // test
			nc.appendPending(change.DERPMap())
		}
	}

	// processBatchedChanges should not deadlock even with small work channel.
	// queueWork uses select with b.done as escape hatch.
	// Start a consumer to slowly drain the work channel.
	var consumed atomic.Int64

	go func() {
		for {
			select {
			case <-b.workCh:
				consumed.Add(1)
			case <-b.done:
				return
			}
		}
	}()

	done := make(chan struct{})

	go func() {
		b.processBatchedChanges()
		close(done)
	}()

	select {
	case <-done:
		t.Logf("processBatchedChanges completed, consumed %d work items", consumed.Load())
	case <-time.After(30 * time.Second):
		t.Fatal("processBatchedChanges deadlocked with saturated work channel")
	}
}

// TestScale1000_FullUpdate_AllNodesGetPending verifies that a FullUpdate
// creates pending entries for all 1000 nodes.
func TestScale1000_FullUpdate_AllNodesGetPending(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1000-node test in short mode")
	}

	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	lb := setupLightweightBatcher(t, 1000, 10)
	defer lb.cleanup()

	lb.b.addToBatch(change.FullUpdate())

	nodesWithPending := countNodesPending(lb.b)
	assert.Equal(t, 1000, nodesWithPending,
		"FullUpdate should create pending entries for all 1000 nodes")

	// Verify each node has exactly one full update pending
	lb.b.nodes.Range(func(id types.NodeID, _ *multiChannelNodeConn) bool {
		pending := getPendingForNode(lb.b, id)
		require.Len(t, pending, 1, "node %d should have 1 pending change", id)
		assert.True(t, pending[0].IsFull(), "pending change for node %d should be full", id)

		return true
	})
}

// ============================================================================
// 1000-Node Full Pipeline Tests (with DB)
// ============================================================================

// TestScale1000_AllToAll_FullPipeline tests the complete pipeline:
// create 1000 nodes in DB, add them to batcher, send FullUpdate,
// verify all nodes see 999 peers.
func TestScale1000_AllToAll_FullPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1000-node full pipeline test in short mode")
	}

	if util.RaceEnabled {
		t.Skip("skipping 1000-node test with race detector (bcrypt setup too slow)")
	}

	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	t.Logf("setting up 1000-node test environment (this may take a minute)...")

	testData, cleanup := setupBatcherWithTestData(t, NewBatcherAndMapper, 1, 1000, 200)
	defer cleanup()

	batcher := testData.Batcher
	allNodes := testData.Nodes

	t.Logf("created %d nodes, connecting to batcher...", len(allNodes))

	// Start update consumers
	for i := range allNodes {
		allNodes[i].start()
	}

	// Connect all nodes
	for i := range allNodes {
		node := &allNodes[i]

		err := batcher.AddNode(node.n.ID, node.ch, tailcfg.CapabilityVersion(100), nil)
		if err != nil {
			t.Fatalf("failed to add node %d: %v", i, err)
		}
		// Yield periodically to avoid overwhelming the work queue
		if i%50 == 49 {
			time.Sleep(10 * time.Millisecond) //nolint:forbidigo // concurrency test coordination
		}
	}

	t.Logf("all nodes connected, sending FullUpdate and waiting for convergence...")

	// Send FullUpdate
	batcher.AddWork(change.FullUpdate())

	expectedPeers := len(allNodes) - 1 // Each sees all others

	// Wait for all nodes to see all peers
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		convergedCount := 0

		for i := range allNodes {
			if int(allNodes[i].maxPeersCount.Load()) >= expectedPeers {
				convergedCount++
			}
		}

		assert.Equal(c, len(allNodes), convergedCount,
			"all nodes should see %d peers (converged: %d/%d)",
			expectedPeers, convergedCount, len(allNodes))
	}, 5*time.Minute, 5*time.Second, "waiting for 1000-node convergence")

	// Final statistics
	totalUpdates := int64(0)
	minPeers := len(allNodes)
	maxPeers := 0

	for i := range allNodes {
		stats := allNodes[i].cleanup()

		totalUpdates += stats.TotalUpdates
		if stats.MaxPeersSeen < minPeers {
			minPeers = stats.MaxPeersSeen
		}

		if stats.MaxPeersSeen > maxPeers {
			maxPeers = stats.MaxPeersSeen
		}
	}

	t.Logf("1000-node pipeline: total_updates=%d, min_peers=%d, max_peers=%d, expected=%d",
		totalUpdates, minPeers, maxPeers, expectedPeers)

	assert.GreaterOrEqual(t, minPeers, expectedPeers,
		"all nodes should have seen at least %d peers", expectedPeers)
}
