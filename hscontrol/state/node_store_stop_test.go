package state

import (
	"sync"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
)

// TestNodeStoreWriteDuringStopNoPanic ensures a write racing with Stop does not
// panic with "send on closed channel". During graceful shutdown a grace-period
// Disconnect (or a scheduled HA probe result) can still issue a NodeStore write
// after Stop has run; that write must be either applied or cleanly dropped,
// never crash the process.
func TestNodeStoreWriteDuringStopNoPanic(t *testing.T) {
	const iterations = 200

	for range iterations {
		store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)
		store.Start()

		var wg sync.WaitGroup

		wg.Go(func() {
			node := createConcurrentTestNode(types.NodeID(1), "grace-period-node")
			store.PutNode(node)
		})

		wg.Go(func() {
			store.Stop()
		})

		wg.Wait()
	}
}
