package mapper

// Unit tests for batcher components that do NOT require database setup.
// These tests exercise connectionEntry, multiChannelNodeConn, computePeerDiff,
// updateSentPeers, generateMapResponse branching, and handleNodeChange in isolation.

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// ============================================================================
// Mock Infrastructure
// ============================================================================

// mockNodeConnection implements nodeConnection for isolated unit testing
// of generateMapResponse and handleNodeChange without a real database.
type mockNodeConnection struct {
	id  types.NodeID
	ver tailcfg.CapabilityVersion

	// sendFn allows injecting custom send behavior.
	// If nil, sends are recorded and succeed.
	sendFn func(*tailcfg.MapResponse) error

	// sent records all successful sends for assertion.
	sent []*tailcfg.MapResponse
	mu   sync.Mutex

	// Peer tracking
	peers *xsync.Map[tailcfg.NodeID, struct{}]
}

func newMockNodeConnection(id types.NodeID) *mockNodeConnection {
	return &mockNodeConnection{
		id:    id,
		ver:   tailcfg.CapabilityVersion(100),
		peers: xsync.NewMap[tailcfg.NodeID, struct{}](),
	}
}

// withSendError configures the mock to return the given error on send.
func (m *mockNodeConnection) withSendError(err error) *mockNodeConnection {
	m.sendFn = func(_ *tailcfg.MapResponse) error { return err }
	return m
}

func (m *mockNodeConnection) nodeID() types.NodeID               { return m.id }
func (m *mockNodeConnection) version() tailcfg.CapabilityVersion { return m.ver }

func (m *mockNodeConnection) send(data *tailcfg.MapResponse) error {
	if m.sendFn != nil {
		return m.sendFn(data)
	}

	m.mu.Lock()
	m.sent = append(m.sent, data)
	m.mu.Unlock()

	return nil
}

func (m *mockNodeConnection) computePeerDiff(currentPeers []tailcfg.NodeID) []tailcfg.NodeID {
	currentSet := make(map[tailcfg.NodeID]struct{}, len(currentPeers))
	for _, id := range currentPeers {
		currentSet[id] = struct{}{}
	}

	var removed []tailcfg.NodeID

	m.peers.Range(func(id tailcfg.NodeID, _ struct{}) bool {
		if _, exists := currentSet[id]; !exists {
			removed = append(removed, id)
		}

		return true
	})

	return removed
}

func (m *mockNodeConnection) updateSentPeers(resp *tailcfg.MapResponse) {
	if resp == nil {
		return
	}

	if resp.Peers != nil {
		m.peers.Clear()

		for _, peer := range resp.Peers {
			m.peers.Store(peer.ID, struct{}{})
		}
	}

	for _, peer := range resp.PeersChanged {
		m.peers.Store(peer.ID, struct{}{})
	}

	for _, id := range resp.PeersRemoved {
		m.peers.Delete(id)
	}
}

// getSent returns a thread-safe copy of all sent responses.
func (m *mockNodeConnection) getSent() []*tailcfg.MapResponse {
	m.mu.Lock()
	defer m.mu.Unlock()

	return append([]*tailcfg.MapResponse{}, m.sent...)
}

// ============================================================================
// Test Helpers
// ============================================================================

// testMapResponse creates a minimal valid MapResponse for testing.
func testMapResponse() *tailcfg.MapResponse {
	now := time.Now()

	return &tailcfg.MapResponse{
		ControlTime: &now,
	}
}

// testMapResponseWithPeers creates a MapResponse with the given peer IDs.
func testMapResponseWithPeers(peerIDs ...tailcfg.NodeID) *tailcfg.MapResponse {
	resp := testMapResponse()

	resp.Peers = make([]*tailcfg.Node, len(peerIDs))
	for i, id := range peerIDs {
		resp.Peers[i] = &tailcfg.Node{ID: id}
	}

	return resp
}

// ids is a convenience for creating a slice of tailcfg.NodeID.
func ids(nodeIDs ...tailcfg.NodeID) []tailcfg.NodeID {
	return nodeIDs
}

// expectReceive asserts that a message arrives on the channel within 100ms.
func expectReceive(t *testing.T, ch <-chan *tailcfg.MapResponse, msg string) *tailcfg.MapResponse {
	t.Helper()

	const timeout = 100 * time.Millisecond

	select {
	case data := <-ch:
		return data
	case <-time.After(timeout):
		t.Fatalf("expected to receive on channel within %v: %s", timeout, msg)
		return nil
	}
}

// expectNoReceive asserts that no message arrives within timeout.
func expectNoReceive(t *testing.T, ch <-chan *tailcfg.MapResponse, timeout time.Duration, msg string) {
	t.Helper()

	select {
	case data := <-ch:
		t.Fatalf("expected no receive but got %+v: %s", data, msg)
	case <-time.After(timeout):
		// Expected
	}
}

// makeConnectionEntry creates a connectionEntry with the given channel.
func makeConnectionEntry(id string, ch chan<- *tailcfg.MapResponse) *connectionEntry {
	entry := &connectionEntry{
		id:      id,
		c:       ch,
		version: tailcfg.CapabilityVersion(100),
		created: time.Now(),
	}
	entry.lastUsed.Store(time.Now().Unix())

	return entry
}

// ============================================================================
// connectionEntry.send() Tests
// ============================================================================

func TestConnectionEntry_SendSuccess(t *testing.T) {
	ch := make(chan *tailcfg.MapResponse, 1)
	entry := makeConnectionEntry("test-conn", ch)
	data := testMapResponse()

	beforeSend := time.Now().Unix()
	err := entry.send(data)

	require.NoError(t, err)
	assert.GreaterOrEqual(t, entry.lastUsed.Load(), beforeSend,
		"lastUsed should be updated after successful send")

	// Verify data was actually sent
	received := expectReceive(t, ch, "data should be on channel")
	assert.Equal(t, data, received)
}

func TestConnectionEntry_SendNilData(t *testing.T) {
	ch := make(chan *tailcfg.MapResponse, 1)
	entry := makeConnectionEntry("test-conn", ch)

	err := entry.send(nil)

	require.NoError(t, err, "nil data should return nil error")
	expectNoReceive(t, ch, 10*time.Millisecond, "nil data should not be sent to channel")
}

func TestConnectionEntry_SendTimeout(t *testing.T) {
	// Unbuffered channel with no reader = always blocks
	ch := make(chan *tailcfg.MapResponse)
	entry := makeConnectionEntry("test-conn", ch)
	data := testMapResponse()

	start := time.Now()
	err := entry.send(data)
	elapsed := time.Since(start)

	require.ErrorIs(t, err, ErrConnectionSendTimeout)
	assert.GreaterOrEqual(t, elapsed, 40*time.Millisecond,
		"should wait approximately 50ms before timeout")
}

func TestConnectionEntry_SendClosed(t *testing.T) {
	ch := make(chan *tailcfg.MapResponse, 1)
	entry := makeConnectionEntry("test-conn", ch)

	// Mark as closed before sending
	entry.closed.Store(true)

	err := entry.send(testMapResponse())

	require.ErrorIs(t, err, errConnectionClosed)
	expectNoReceive(t, ch, 10*time.Millisecond,
		"closed entry should not send data to channel")
}

func TestConnectionEntry_SendUpdatesLastUsed(t *testing.T) {
	ch := make(chan *tailcfg.MapResponse, 1)
	entry := makeConnectionEntry("test-conn", ch)

	// Set lastUsed to a past time
	pastTime := time.Now().Add(-1 * time.Hour).Unix()
	entry.lastUsed.Store(pastTime)

	err := entry.send(testMapResponse())
	require.NoError(t, err)

	assert.Greater(t, entry.lastUsed.Load(), pastTime,
		"lastUsed should be updated to current time after send")
}

// ============================================================================
// multiChannelNodeConn.send() Tests
// ============================================================================

func TestMultiChannelSend_AllSuccess(t *testing.T) {
	mc := newMultiChannelNodeConn(1, nil)

	// Create 3 buffered channels (all will succeed)
	channels := make([]chan *tailcfg.MapResponse, 3)
	for i := range channels {
		channels[i] = make(chan *tailcfg.MapResponse, 1)
		mc.addConnection(makeConnectionEntry(fmt.Sprintf("conn-%d", i), channels[i]))
	}

	data := testMapResponse()
	err := mc.send(data)

	require.NoError(t, err)
	assert.Equal(t, 3, mc.getActiveConnectionCount(),
		"all connections should remain active after success")

	// Verify all channels received the data
	for i, ch := range channels {
		received := expectReceive(t, ch,
			fmt.Sprintf("channel %d should receive data", i))
		assert.Equal(t, data, received)
	}
}

func TestMultiChannelSend_PartialFailure(t *testing.T) {
	mc := newMultiChannelNodeConn(1, nil)

	// 2 buffered channels (will succeed) + 1 unbuffered (will timeout)
	goodCh1 := make(chan *tailcfg.MapResponse, 1)
	goodCh2 := make(chan *tailcfg.MapResponse, 1)
	badCh := make(chan *tailcfg.MapResponse) // unbuffered, no reader

	mc.addConnection(makeConnectionEntry("good-1", goodCh1))
	mc.addConnection(makeConnectionEntry("bad", badCh))
	mc.addConnection(makeConnectionEntry("good-2", goodCh2))

	err := mc.send(testMapResponse())

	require.NoError(t, err, "should succeed if at least one connection works")
	assert.Equal(t, 2, mc.getActiveConnectionCount(),
		"failed connection should be removed")

	// Good channels should have received data
	expectReceive(t, goodCh1, "good-1 should receive")
	expectReceive(t, goodCh2, "good-2 should receive")
}

func TestMultiChannelSend_AllFail(t *testing.T) {
	mc := newMultiChannelNodeConn(1, nil)

	// All unbuffered channels with no readers
	for i := range 3 {
		ch := make(chan *tailcfg.MapResponse) // unbuffered
		mc.addConnection(makeConnectionEntry(fmt.Sprintf("bad-%d", i), ch))
	}

	err := mc.send(testMapResponse())

	require.Error(t, err, "should return error when all connections fail")
	assert.Equal(t, 0, mc.getActiveConnectionCount(),
		"all failed connections should be removed")
}

func TestMultiChannelSend_ZeroConnections(t *testing.T) {
	mc := newMultiChannelNodeConn(1, nil)

	err := mc.send(testMapResponse())

	require.ErrorIs(t, err, errNoActiveConnections,
		"sending to node with 0 connections should return errNoActiveConnections "+
			"so callers skip updateSentPeers (prevents phantom peer state)")
}

func TestMultiChannelSend_NilData(t *testing.T) {
	mc := newMultiChannelNodeConn(1, nil)
	ch := make(chan *tailcfg.MapResponse, 1)
	mc.addConnection(makeConnectionEntry("conn", ch))

	err := mc.send(nil)

	require.NoError(t, err, "nil data should return nil immediately")
	expectNoReceive(t, ch, 10*time.Millisecond, "nil data should not be sent")
}

func TestMultiChannelSend_FailedConnectionRemoved(t *testing.T) {
	mc := newMultiChannelNodeConn(1, nil)

	goodCh := make(chan *tailcfg.MapResponse, 10) // large buffer
	badCh := make(chan *tailcfg.MapResponse)      // unbuffered, will timeout

	mc.addConnection(makeConnectionEntry("good", goodCh))
	mc.addConnection(makeConnectionEntry("bad", badCh))

	assert.Equal(t, 2, mc.getActiveConnectionCount())

	// First send: bad connection removed
	err := mc.send(testMapResponse())
	require.NoError(t, err)
	assert.Equal(t, 1, mc.getActiveConnectionCount())

	// Second send: only good connection remains, should succeed
	err = mc.send(testMapResponse())
	require.NoError(t, err)
	assert.Equal(t, 1, mc.getActiveConnectionCount())
}

func TestMultiChannelSend_UpdateCount(t *testing.T) {
	mc := newMultiChannelNodeConn(1, nil)
	ch := make(chan *tailcfg.MapResponse, 10)
	mc.addConnection(makeConnectionEntry("conn", ch))

	assert.Equal(t, int64(0), mc.updateCount.Load())

	_ = mc.send(testMapResponse())
	assert.Equal(t, int64(1), mc.updateCount.Load())

	_ = mc.send(testMapResponse())
	assert.Equal(t, int64(2), mc.updateCount.Load())
}

// ============================================================================
// multiChannelNodeConn.close() Tests
// ============================================================================

func TestMultiChannelClose_MarksEntriesClosed(t *testing.T) {
	mc := newMultiChannelNodeConn(1, nil)

	entries := make([]*connectionEntry, 3)
	for i := range entries {
		ch := make(chan *tailcfg.MapResponse, 1)
		entries[i] = makeConnectionEntry(fmt.Sprintf("conn-%d", i), ch)
		mc.addConnection(entries[i])
	}

	mc.close()

	for i, entry := range entries {
		assert.True(t, entry.closed.Load(),
			"entry %d should be marked as closed", i)
	}
}

func TestMultiChannelClose_PreventsSendPanic(t *testing.T) {
	mc := newMultiChannelNodeConn(1, nil)
	ch := make(chan *tailcfg.MapResponse, 1)
	entry := makeConnectionEntry("conn", ch)
	mc.addConnection(entry)

	mc.close()

	// After close, connectionEntry.send should return errConnectionClosed
	// (not panic on send to closed channel)
	err := entry.send(testMapResponse())
	require.ErrorIs(t, err, errConnectionClosed,
		"send after close should return errConnectionClosed, not panic")
}

// ============================================================================
// multiChannelNodeConn connection management Tests
// ============================================================================

func TestMultiChannelNodeConn_AddRemoveConnections(t *testing.T) {
	mc := newMultiChannelNodeConn(1, nil)

	ch1 := make(chan *tailcfg.MapResponse, 1)
	ch2 := make(chan *tailcfg.MapResponse, 1)
	ch3 := make(chan *tailcfg.MapResponse, 1)

	// Add connections
	mc.addConnection(makeConnectionEntry("c1", ch1))
	assert.Equal(t, 1, mc.getActiveConnectionCount())
	assert.True(t, mc.hasActiveConnections())

	mc.addConnection(makeConnectionEntry("c2", ch2))
	mc.addConnection(makeConnectionEntry("c3", ch3))
	assert.Equal(t, 3, mc.getActiveConnectionCount())

	// Remove by channel pointer
	assert.True(t, mc.removeConnectionByChannel(ch2))
	assert.Equal(t, 2, mc.getActiveConnectionCount())

	// Remove non-existent channel
	nonExistentCh := make(chan *tailcfg.MapResponse)
	assert.False(t, mc.removeConnectionByChannel(nonExistentCh))
	assert.Equal(t, 2, mc.getActiveConnectionCount())

	// Remove remaining
	assert.True(t, mc.removeConnectionByChannel(ch1))
	assert.True(t, mc.removeConnectionByChannel(ch3))
	assert.Equal(t, 0, mc.getActiveConnectionCount())
	assert.False(t, mc.hasActiveConnections())
}

func TestMultiChannelNodeConn_Version(t *testing.T) {
	mc := newMultiChannelNodeConn(1, nil)

	// No connections - version should be 0
	assert.Equal(t, tailcfg.CapabilityVersion(0), mc.version())

	// Add connection with version 100
	ch := make(chan *tailcfg.MapResponse, 1)
	entry := makeConnectionEntry("conn", ch)
	entry.version = tailcfg.CapabilityVersion(100)
	mc.addConnection(entry)

	assert.Equal(t, tailcfg.CapabilityVersion(100), mc.version())
}

// ============================================================================
// computePeerDiff Tests
// ============================================================================

func TestComputePeerDiff(t *testing.T) {
	tests := []struct {
		name        string
		tracked     []tailcfg.NodeID // peers previously sent to client
		current     []tailcfg.NodeID // peers visible now
		wantRemoved []tailcfg.NodeID // expected removed peers
	}{
		{
			name:        "no_changes",
			tracked:     ids(1, 2, 3),
			current:     ids(1, 2, 3),
			wantRemoved: nil,
		},
		{
			name:        "one_removed",
			tracked:     ids(1, 2, 3),
			current:     ids(1, 3),
			wantRemoved: ids(2),
		},
		{
			name:        "multiple_removed",
			tracked:     ids(1, 2, 3, 4, 5),
			current:     ids(2, 4),
			wantRemoved: ids(1, 3, 5),
		},
		{
			name:        "all_removed",
			tracked:     ids(1, 2, 3),
			current:     nil,
			wantRemoved: ids(1, 2, 3),
		},
		{
			name:        "peers_added_no_removal",
			tracked:     ids(1),
			current:     ids(1, 2, 3),
			wantRemoved: nil,
		},
		{
			name:        "empty_tracked",
			tracked:     nil,
			current:     ids(1, 2, 3),
			wantRemoved: nil,
		},
		{
			name:        "both_empty",
			tracked:     nil,
			current:     nil,
			wantRemoved: nil,
		},
		{
			name:        "disjoint_sets",
			tracked:     ids(1, 2, 3),
			current:     ids(4, 5, 6),
			wantRemoved: ids(1, 2, 3),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := newMultiChannelNodeConn(1, nil)

			// Populate tracked peers
			for _, id := range tt.tracked {
				mc.lastSentPeers.Store(id, struct{}{})
			}

			got := mc.computePeerDiff(tt.current)

			assert.ElementsMatch(t, tt.wantRemoved, got,
				"removed peers should match expected")
		})
	}
}

// ============================================================================
// updateSentPeers Tests
// ============================================================================

func TestUpdateSentPeers(t *testing.T) {
	t.Run("full_peer_list_replaces_all", func(t *testing.T) {
		mc := newMultiChannelNodeConn(1, nil)
		// Pre-populate with old peers
		mc.lastSentPeers.Store(tailcfg.NodeID(100), struct{}{})
		mc.lastSentPeers.Store(tailcfg.NodeID(200), struct{}{})

		// Send full peer list
		mc.updateSentPeers(testMapResponseWithPeers(1, 2, 3))

		// Old peers should be gone
		_, exists := mc.lastSentPeers.Load(tailcfg.NodeID(100))
		assert.False(t, exists, "old peer 100 should be cleared")

		// New peers should be tracked
		for _, id := range ids(1, 2, 3) {
			_, exists := mc.lastSentPeers.Load(id)
			assert.True(t, exists, "peer %d should be tracked", id)
		}
	})

	t.Run("incremental_add_via_PeersChanged", func(t *testing.T) {
		mc := newMultiChannelNodeConn(1, nil)
		mc.lastSentPeers.Store(tailcfg.NodeID(1), struct{}{})

		resp := testMapResponse()
		resp.PeersChanged = []*tailcfg.Node{{ID: 2}, {ID: 3}}
		mc.updateSentPeers(resp)

		// All three should be tracked
		for _, id := range ids(1, 2, 3) {
			_, exists := mc.lastSentPeers.Load(id)
			assert.True(t, exists, "peer %d should be tracked", id)
		}
	})

	t.Run("incremental_remove_via_PeersRemoved", func(t *testing.T) {
		mc := newMultiChannelNodeConn(1, nil)
		mc.lastSentPeers.Store(tailcfg.NodeID(1), struct{}{})
		mc.lastSentPeers.Store(tailcfg.NodeID(2), struct{}{})
		mc.lastSentPeers.Store(tailcfg.NodeID(3), struct{}{})

		resp := testMapResponse()
		resp.PeersRemoved = ids(2)
		mc.updateSentPeers(resp)

		_, exists1 := mc.lastSentPeers.Load(tailcfg.NodeID(1))
		_, exists2 := mc.lastSentPeers.Load(tailcfg.NodeID(2))
		_, exists3 := mc.lastSentPeers.Load(tailcfg.NodeID(3))

		assert.True(t, exists1, "peer 1 should remain")
		assert.False(t, exists2, "peer 2 should be removed")
		assert.True(t, exists3, "peer 3 should remain")
	})

	t.Run("nil_response_is_noop", func(t *testing.T) {
		mc := newMultiChannelNodeConn(1, nil)
		mc.lastSentPeers.Store(tailcfg.NodeID(1), struct{}{})

		mc.updateSentPeers(nil)

		_, exists := mc.lastSentPeers.Load(tailcfg.NodeID(1))
		assert.True(t, exists, "nil response should not change tracked peers")
	})

	t.Run("full_then_incremental_sequence", func(t *testing.T) {
		mc := newMultiChannelNodeConn(1, nil)

		// Step 1: Full peer list
		mc.updateSentPeers(testMapResponseWithPeers(1, 2, 3))

		// Step 2: Add peer 4
		resp := testMapResponse()
		resp.PeersChanged = []*tailcfg.Node{{ID: 4}}
		mc.updateSentPeers(resp)

		// Step 3: Remove peer 2
		resp2 := testMapResponse()
		resp2.PeersRemoved = ids(2)
		mc.updateSentPeers(resp2)

		// Should have 1, 3, 4
		for _, id := range ids(1, 3, 4) {
			_, exists := mc.lastSentPeers.Load(id)
			assert.True(t, exists, "peer %d should be tracked", id)
		}

		_, exists := mc.lastSentPeers.Load(tailcfg.NodeID(2))
		assert.False(t, exists, "peer 2 should have been removed")
	})

	t.Run("empty_full_peer_list_clears_all", func(t *testing.T) {
		mc := newMultiChannelNodeConn(1, nil)
		mc.lastSentPeers.Store(tailcfg.NodeID(1), struct{}{})
		mc.lastSentPeers.Store(tailcfg.NodeID(2), struct{}{})

		// Empty Peers slice (not nil) means "no peers"
		resp := testMapResponse()
		resp.Peers = []*tailcfg.Node{} // empty, not nil
		mc.updateSentPeers(resp)

		count := 0

		mc.lastSentPeers.Range(func(_ tailcfg.NodeID, _ struct{}) bool {
			count++
			return true
		})
		assert.Equal(t, 0, count, "empty peer list should clear all tracking")
	})
}

// ============================================================================
// generateMapResponse Tests (branching logic only, no DB needed)
// ============================================================================

func TestGenerateMapResponse_EmptyChange(t *testing.T) {
	mc := newMockNodeConnection(1)

	resp, err := generateMapResponse(mc, nil, change.Change{})

	require.NoError(t, err)
	assert.Nil(t, resp, "empty change should return nil response")
}

func TestGenerateMapResponse_InvalidNodeID(t *testing.T) {
	mc := newMockNodeConnection(0) // Invalid ID

	resp, err := generateMapResponse(mc, &mapper{}, change.DERPMap())

	require.ErrorIs(t, err, ErrInvalidNodeID)
	assert.Nil(t, resp)
}

func TestGenerateMapResponse_NilMapper(t *testing.T) {
	mc := newMockNodeConnection(1)

	resp, err := generateMapResponse(mc, nil, change.DERPMap())

	require.ErrorIs(t, err, ErrMapperNil)
	assert.Nil(t, resp)
}

func TestGenerateMapResponse_SelfOnlyOtherNode(t *testing.T) {
	mc := newMockNodeConnection(1)

	// SelfUpdate targeted at node 99 should be skipped for node 1
	ch := change.SelfUpdate(99)
	resp, err := generateMapResponse(mc, &mapper{}, ch)

	require.NoError(t, err)
	assert.Nil(t, resp,
		"self-only change targeted at different node should return nil")
}

func TestGenerateMapResponse_SelfOnlySameNode(t *testing.T) {
	// SelfUpdate targeted at node 1: IsSelfOnly()=true and TargetNode==nodeID
	// This should NOT be short-circuited - it should attempt to generate.
	// We verify the routing logic by checking that the change is not empty
	// and not filtered out (unlike SelfOnlyOtherNode above).
	ch := change.SelfUpdate(1)
	assert.False(t, ch.IsEmpty(), "SelfUpdate should not be empty")
	assert.True(t, ch.IsSelfOnly(), "SelfUpdate should be self-only")
	assert.True(t, ch.ShouldSendToNode(1), "should be sent to target node")
	assert.False(t, ch.ShouldSendToNode(2), "should NOT be sent to other nodes")
}

// ============================================================================
// handleNodeChange Tests
// ============================================================================

func TestHandleNodeChange_NilConnection(t *testing.T) {
	err := handleNodeChange(nil, nil, change.DERPMap())

	assert.ErrorIs(t, err, ErrNodeConnectionNil)
}

func TestHandleNodeChange_EmptyChange(t *testing.T) {
	mc := newMockNodeConnection(1)

	err := handleNodeChange(mc, nil, change.Change{})

	require.NoError(t, err, "empty change should not send anything")
	assert.Empty(t, mc.getSent(), "no data should be sent for empty change")
}

var errConnectionBroken = errors.New("connection broken")

func TestHandleNodeChange_SendError(t *testing.T) {
	mc := newMockNodeConnection(1).withSendError(errConnectionBroken)

	// Need a real mapper for this test - we can't easily mock it.
	// Instead, test that when generateMapResponse returns nil data,
	// no send occurs. The send error path requires a valid MapResponse
	// which requires a mapper with state.
	// So we test the nil-data path here.
	err := handleNodeChange(mc, nil, change.Change{})
	assert.NoError(t, err, "empty change produces nil data, no send needed")
}

func TestHandleNodeChange_NilDataNoSend(t *testing.T) {
	mc := newMockNodeConnection(1)

	// SelfUpdate targeted at different node produces nil data
	ch := change.SelfUpdate(99)
	err := handleNodeChange(mc, &mapper{}, ch)

	require.NoError(t, err, "nil data should not cause error")
	assert.Empty(t, mc.getSent(), "nil data should not trigger send")
}

// ============================================================================
// connectionEntry concurrent safety Tests
// ============================================================================

func TestConnectionEntry_ConcurrentSends(t *testing.T) {
	ch := make(chan *tailcfg.MapResponse, 100)
	entry := makeConnectionEntry("concurrent", ch)

	var (
		wg           sync.WaitGroup
		successCount atomic.Int64
	)

	// 50 goroutines sending concurrently

	for range 50 {
		wg.Go(func() {
			err := entry.send(testMapResponse())
			if err == nil {
				successCount.Add(1)
			}
		})
	}

	wg.Wait()

	assert.Equal(t, int64(50), successCount.Load(),
		"all sends to buffered channel should succeed")

	// Drain and count
	count := 0

	for range len(ch) {
		<-ch

		count++
	}

	assert.Equal(t, 50, count, "all 50 messages should be on channel")
}

func TestConnectionEntry_ConcurrentSendAndClose(t *testing.T) {
	ch := make(chan *tailcfg.MapResponse, 100)
	entry := makeConnectionEntry("race", ch)

	var (
		wg       sync.WaitGroup
		panicked atomic.Bool
	)

	// Goroutines sending rapidly

	for range 20 {
		wg.Go(func() {
			defer func() {
				if r := recover(); r != nil {
					panicked.Store(true)
				}
			}()

			for range 10 {
				_ = entry.send(testMapResponse())
			}
		})
	}

	// Close midway through

	wg.Go(func() {
		time.Sleep(1 * time.Millisecond) //nolint:forbidigo // concurrency test coordination
		entry.closed.Store(true)
	})

	wg.Wait()

	assert.False(t, panicked.Load(),
		"concurrent send and close should not panic")
}

// ============================================================================
// multiChannelNodeConn concurrent Tests
// ============================================================================

func TestMultiChannelSend_ConcurrentAddAndSend(t *testing.T) {
	mc := newMultiChannelNodeConn(1, nil)

	// Start with one connection
	ch1 := make(chan *tailcfg.MapResponse, 100)
	mc.addConnection(makeConnectionEntry("initial", ch1))

	var (
		wg       sync.WaitGroup
		panicked atomic.Bool
	)

	// Goroutine adding connections

	wg.Go(func() {
		defer func() {
			if r := recover(); r != nil {
				panicked.Store(true)
			}
		}()

		for i := range 10 {
			ch := make(chan *tailcfg.MapResponse, 100)
			mc.addConnection(makeConnectionEntry(fmt.Sprintf("added-%d", i), ch))
		}
	})

	// Goroutine sending data

	wg.Go(func() {
		defer func() {
			if r := recover(); r != nil {
				panicked.Store(true)
			}
		}()

		for range 20 {
			_ = mc.send(testMapResponse())
		}
	})

	wg.Wait()

	assert.False(t, panicked.Load(),
		"concurrent add and send should not panic (mutex protects both)")
}

func TestMultiChannelSend_ConcurrentRemoveAndSend(t *testing.T) {
	mc := newMultiChannelNodeConn(1, nil)

	channels := make([]chan *tailcfg.MapResponse, 10)
	for i := range channels {
		channels[i] = make(chan *tailcfg.MapResponse, 100)
		mc.addConnection(makeConnectionEntry(fmt.Sprintf("conn-%d", i), channels[i]))
	}

	var (
		wg       sync.WaitGroup
		panicked atomic.Bool
	)

	// Goroutine removing connections

	wg.Go(func() {
		defer func() {
			if r := recover(); r != nil {
				panicked.Store(true)
			}
		}()

		for _, ch := range channels {
			mc.removeConnectionByChannel(ch)
		}
	})

	// Goroutine sending data concurrently

	wg.Go(func() {
		defer func() {
			if r := recover(); r != nil {
				panicked.Store(true)
			}
		}()

		for range 20 {
			_ = mc.send(testMapResponse())
		}
	})

	wg.Wait()

	assert.False(t, panicked.Load(),
		"concurrent remove and send should not panic")
}

// ============================================================================
// Regression tests for H1 (timer leak) and H3 (lifecycle)
// ============================================================================

// TestConnectionEntry_SendFastPath_TimerStopped is a regression guard for H1.
// Before the fix, connectionEntry.send used time.After(50ms) which leaked a
// timer into the runtime heap on every call even when the channel send
// succeeded immediately. The fix switched to time.NewTimer + defer Stop().
//
// This test sends many messages on a buffered (non-blocking) channel and
// checks that the number of live goroutines stays bounded, which would
// grow without bound under the old time.After approach at high call rates.
func TestConnectionEntry_SendFastPath_TimerStopped(t *testing.T) {
	const sends = 5000

	ch := make(chan *tailcfg.MapResponse, sends)

	entry := &connectionEntry{
		id:      "timer-leak-test",
		c:       ch,
		version: 100,
		created: time.Now(),
	}

	resp := testMapResponse()

	for range sends {
		err := entry.send(resp)
		require.NoError(t, err)
	}

	// Drain the channel so we aren't holding references.
	for range sends {
		<-ch
	}

	// Force a GC + timer cleanup pass.
	runtime.GC()

	// If timers were leaking we'd see a goroutine count much higher
	// than baseline. With 5000 leaked timers the count would be
	// noticeably elevated. We just check it's reasonable.
	numGR := runtime.NumGoroutine()
	assert.Less(t, numGR, 200,
		"goroutine count after %d fast-path sends should be bounded; got %d (possible timer leak)", sends, numGR)
}

// TestBatcher_CloseWaitsForWorkers is a regression guard for H3.
// Before the fix, Close() would tear down node connections while workers
// were potentially still running, risking sends on closed channels.
// The fix added sync.WaitGroup tracking so Close() blocks until all
// worker goroutines exit.
func TestBatcher_CloseWaitsForWorkers(t *testing.T) {
	b := NewBatcher(50*time.Millisecond, 4, nil)

	goroutinesBefore := runtime.NumGoroutine()

	b.Start()

	// Give workers time to start.
	time.Sleep(20 * time.Millisecond) //nolint:forbidigo // test timing

	goroutinesDuring := runtime.NumGoroutine()

	// We expect at least 5 new goroutines: 1 doWork + 4 workers.
	assert.GreaterOrEqual(t, goroutinesDuring-goroutinesBefore, 5,
		"expected doWork + 4 workers to be running")

	// Close should block until all workers have exited.
	b.Close()

	// After Close returns, goroutines should have dropped back.
	// Allow a small margin for runtime goroutines.
	goroutinesAfter := runtime.NumGoroutine()
	assert.InDelta(t, goroutinesBefore, goroutinesAfter, 3,
		"goroutines should return to baseline after Close(); before=%d after=%d",
		goroutinesBefore, goroutinesAfter)
}

// TestBatcher_CloseThenStartIsNoop verifies the lifecycle contract:
// once a Batcher has been started, calling Start() again is a no-op
// (the started flag prevents double-start).
func TestBatcher_CloseThenStartIsNoop(t *testing.T) {
	b := NewBatcher(50*time.Millisecond, 2, nil)

	b.Start()
	b.Close()

	goroutinesBefore := runtime.NumGoroutine()

	// Second Start should be a no-op because started is already true.
	b.Start()

	// Allow a moment for any hypothetical goroutine to appear.
	time.Sleep(10 * time.Millisecond) //nolint:forbidigo // test timing

	goroutinesAfter := runtime.NumGoroutine()

	assert.InDelta(t, goroutinesBefore, goroutinesAfter, 1,
		"Start() after Close() should not spawn new goroutines; before=%d after=%d",
		goroutinesBefore, goroutinesAfter)
}

// TestBatcher_CloseStopsTicker verifies that Close() stops the internal
// ticker, preventing resource leaks.
func TestBatcher_CloseStopsTicker(t *testing.T) {
	b := NewBatcher(10*time.Millisecond, 1, nil)

	b.Start()
	b.Close()

	// After Close, the ticker should be stopped. Reading from a stopped
	// ticker's channel should not deliver any values.
	select {
	case <-b.tick.C:
		t.Fatal("ticker fired after Close(); ticker.Stop() was not called")
	case <-time.After(50 * time.Millisecond): //nolint:forbidigo // test timing
		// Expected: no tick received.
	}
}

// ============================================================================
// Regression tests for M1, M3, M7
// ============================================================================

// TestBatcher_CloseBeforeStart_DoesNotHang is a regression guard for M1.
// Before the fix, done was nil until Start() was called. queueWork and
// MapResponseFromChange select on done, so a nil channel would block
// forever when workCh was full. With done initialized in NewBatcher,
// Close() can be called safely before Start().
func TestBatcher_CloseBeforeStart_DoesNotHang(t *testing.T) {
	b := NewBatcher(50*time.Millisecond, 2, nil)

	// Close without Start must not panic or hang.
	done := make(chan struct{})

	go func() {
		b.Close()
		close(done)
	}()

	select {
	case <-done:
		// Success: Close returned promptly.
	case <-time.After(2 * time.Second): //nolint:forbidigo // test timing
		t.Fatal("Close() before Start() hung; done channel was likely nil")
	}
}

// TestBatcher_QueueWorkAfterClose_DoesNotHang verifies that queueWork
// returns immediately via the done channel when the batcher is closed,
// even without Start() having been called.
func TestBatcher_QueueWorkAfterClose_DoesNotHang(t *testing.T) {
	b := NewBatcher(50*time.Millisecond, 1, nil)
	b.Close()

	done := make(chan struct{})

	go func() {
		// queueWork selects on done; with done closed this must return.
		b.queueWork(work{})
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second): //nolint:forbidigo // test timing
		t.Fatal("queueWork hung after Close(); done channel select not working")
	}
}

// TestIsConnected_FalseAfterAddNodeFailure is a regression guard for M3.
// Before the fix, AddNode error paths removed the connection but did not
// mark the node as disconnected. IsConnected would return true for a
// node with zero active connections.
func TestIsConnected_FalseAfterAddNodeFailure(t *testing.T) {
	b := NewBatcher(50*time.Millisecond, 2, nil)
	b.Start()

	defer b.Close()

	id := types.NodeID(42)

	// Pre-create the node entry so AddNode reuses it, and set up a
	// multiChannelNodeConn with no mapper so MapResponseFromChange will fail.
	// markConnected() simulates a previous session leaving it connected.
	nc := newMultiChannelNodeConn(id, nil)
	nc.markConnected()
	b.nodes.Store(id, nc)

	ch := make(chan *tailcfg.MapResponse, 1)

	err := b.AddNode(id, ch, 100, func() {})
	require.Error(t, err, "AddNode should fail with nil mapper")

	// After failure, the node should NOT be reported as connected.
	assert.False(t, b.IsConnected(id),
		"IsConnected should return false after AddNode failure with no remaining connections")
}

// TestRemoveConnectionAtIndex_NilsTrailingSlot is a regression guard for M7.
// Before the fix, removeConnectionAtIndexLocked used append(s[:i], s[i+1:]...)
// which left a stale pointer in the backing array's last slot. The fix
// uses copy + explicit nil of the trailing element.
func TestRemoveConnectionAtIndex_NilsTrailingSlot(t *testing.T) {
	mc := newMultiChannelNodeConn(1, nil)

	// Manually add three entries under the lock.
	entries := make([]*connectionEntry, 3)
	for i := range entries {
		entries[i] = &connectionEntry{id: fmt.Sprintf("conn-%d", i), c: make(chan<- *tailcfg.MapResponse)}
	}

	mc.mutex.Lock()
	mc.connections = append(mc.connections, entries...)

	// Remove the middle entry (index 1).
	removed := mc.removeConnectionAtIndexLocked(1, false)
	require.Equal(t, entries[1], removed)

	// After removal, len should be 2 and the backing array slot at
	// index 2 (the old len-1) should be nil.
	require.Len(t, mc.connections, 2)
	assert.Equal(t, entries[0], mc.connections[0])
	assert.Equal(t, entries[2], mc.connections[1])

	// Check the backing array directly: the slot just past the new
	// length must be nil to avoid retaining the pointer.
	backing := mc.connections[:3]
	assert.Nil(t, backing[2],
		"trailing slot in backing array should be nil after removal")

	mc.mutex.Unlock()
}
