package mapper

import (
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
