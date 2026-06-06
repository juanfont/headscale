package mapper

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestAddNodeReconnectNotOrphanedByCleanup ensures a node reconnecting via
// AddNode is not deleted from b.nodes by a concurrent cleanupOfflineNodes pass.
// AddNode must register the connection atomically with the get-or-create, so
// the offline-cleanup Compute either sees the active connection (and cancels)
// or runs first and AddNode recreates the entry — never leaving a live
// connection orphaned outside b.nodes.
func TestAddNodeReconnectNotOrphanedByCleanup(t *testing.T) {
	testData, cleanup := setupBatcherWithTestData(t, NewBatcherAndMapper, 1, 1, normalBufferSize)
	defer cleanup()

	b := testData.Batcher.Batcher
	node := &testData.Nodes[0]

	testData.State.Connect(node.n.ID)

	go func() {
		for range node.ch {
		}
	}()

	require.NoError(t, b.AddNode(node.n.ID, node.ch, tailcfg.CapabilityVersion(100), nil))

	// Model a long-offline conn awaiting cleanup or a rapid reconnect.
	nc, ok := b.nodes.Load(node.n.ID)
	require.True(t, ok)

	nc.removeConnectionByChannel(node.ch)

	past := time.Now().Add(-(offlineNodeCleanupThreshold + time.Minute))
	nc.disconnectedAt.Store(&past)
	require.False(t, nc.hasActiveConnections())

	var wg sync.WaitGroup

	wg.Go(func() {
		_ = b.AddNode(node.n.ID, node.ch, tailcfg.CapabilityVersion(100), nil)
	})

	wg.Go(func() {
		b.cleanupOfflineNodes()
	})

	wg.Wait()

	assert.True(t, b.IsConnected(node.n.ID),
		"reconnecting node was orphaned: live connection absent from b.nodes")
}
