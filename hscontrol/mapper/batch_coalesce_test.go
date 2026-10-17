package mapper

import (
	"slices"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestProcessBatchedChangesCoalescesWhenInFlight verifies that at most one
// batched bundle per node is queued at a time. While a node's bundle is in
// flight, a new tick's changes must stay in pending (coalesced) rather than
// being queued as a second bundle that a non-FIFO worker could deliver out of
// order.
func TestProcessBatchedChangesCoalescesWhenInFlight(t *testing.T) {
	b := NewBatcher(50*time.Millisecond, 2, nil) // not started: no ticker, no workers

	id := types.NodeID(1)
	nc := newMultiChannelNodeConn(id, nil)
	nc.addConnection(makeConnectionEntry("conn-1", make(chan *tailcfg.MapResponse, 1)))
	b.nodes.Store(id, nc)

	// A bundle is in flight: the new change must be retained, not queued.
	nc.inFlight.Store(true)
	nc.appendPending(change.PolicyChange())
	b.processBatchedChanges()

	nc.pendingMu.Lock()
	retained := len(nc.pending)
	nc.pendingMu.Unlock()
	assert.Equal(t, 1, retained, "pending must be retained while a bundle is in flight")

	// No bundle in flight: the pending change is queued and the node marked
	// in-flight.
	nc.inFlight.Store(false)
	b.processBatchedChanges()

	nc.pendingMu.Lock()
	drained := len(nc.pending)
	nc.pendingMu.Unlock()
	assert.Equal(t, 0, drained, "pending must be drained once queued")
	assert.True(t, nc.inFlight.Load(), "queued bundle must mark the node in-flight")

	require.NotNil(t, b)
}

// TestProcessBatchedChangesSkipsNodesWithoutConnection drains a node that
// kept its batcher entry after its last stream closed. Rendering its changes
// is wasted, since send drops the result and its next stream opens with a
// full map, so no work may be queued for it.
func TestProcessBatchedChangesSkipsNodesWithoutConnection(t *testing.T) {
	b := NewBatcher(50*time.Millisecond, 2, nil) // not started: no ticker, no workers

	id := types.NodeID(1)
	nc := newMultiChannelNodeConn(id, nil)
	b.nodes.Store(id, nc)

	nc.appendPending(change.PolicyChange())
	b.processBatchedChanges()

	nc.pendingMu.Lock()
	pending := len(nc.pending)
	nc.pendingMu.Unlock()
	assert.Equal(t, 0, pending, "a node without a connection must not accumulate pending changes")
	assert.Empty(t, b.workCh, "no work may be queued for a node without a connection")
	assert.False(t, nc.inFlight.Load())
}

// TestAppendPendingStaysBoundedWhileInFlight appends a churn of joins,
// deletions and policy changes to a node whose bundle stays in flight, as
// when the workers fall behind. Below the cap, pending must stay as small as
// its coalesced form instead of growing by one entry per change, and
// draining it must render what coalescing the whole backlog at once would.
func TestAppendPendingStaysBoundedWhileInFlight(t *testing.T) {
	id := types.NodeID(1)
	nc := newMultiChannelNodeConn(id, nil)
	nc.inFlight.Store(true)

	var all []change.Change

	for i := range 3000 {
		peer := types.NodeID(i%50 + 2) //nolint:gosec // test

		cs := []change.Change{change.NodeAdded(peer), change.NodeOnline(peer), change.PolicyChange()}
		if i%100 == 0 {
			// The removal this node gets as a peer of the deleted one.
			cs = append(cs, change.NodeRemoved(types.NodeID(i+1000), id)[1]) //nolint:gosec // test
		}

		for _, c := range cs {
			nc.appendPending(c)
		}

		all = append(all, cs...)
	}

	nc.pendingMu.Lock()
	pending := slices.Clone(nc.pending)
	nc.pendingMu.Unlock()

	assert.Less(t, len(pending), 100, "pending must not grow with every change")
	assert.False(t, pending[0].IsFull(), "test sanity: the backlog stays below the cap")

	coalesce := func(cs []change.Change) []change.Change {
		return change.CoalescePeerDeltas(id, change.DedupePolicyChanges(cs))
	}
	assert.Equal(t, coalesce(all), coalesce(pending))
}

// TestAppendPendingBoundsFoldedPatches queues patch-only updates for one peer
// while a node's bundle stays in flight. Folding keeps each patch, so it must
// count them: a backlog folded into one change still grows by every patch,
// and only a collapse to a full map bounds it.
func TestAppendPendingBoundsFoldedPatches(t *testing.T) {
	id := types.NodeID(1)
	nc := newMultiChannelNodeConn(id, nil)
	nc.inFlight.Store(true)

	for i := range 10000 {
		if i%2 == 0 {
			nc.appendPending(change.NodeOnline(2))
		} else {
			nc.appendPending(change.NodeOffline(2))
		}
	}

	nc.pendingMu.Lock()
	pending := slices.Clone(nc.pending)
	nc.pendingMu.Unlock()

	require.NotEmpty(t, pending)
	assert.True(t, pending[0].IsFull(), "a backlog past the cap must collapse to a full map")
	assert.LessOrEqual(t, countPatches(pending), maxPendingSize, "pending must not keep every patch")
}
