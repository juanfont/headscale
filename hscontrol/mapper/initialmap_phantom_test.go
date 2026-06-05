package mapper

import (
	"testing"

	"tailscale.com/tailcfg"
)

// TestSyncInitialMapNoPhantomPeersOnTimeout ensures the synchronous initial-map
// path does not record peers as sent until the map is actually delivered. When
// the AddNode channel send times out, the client received nothing, so
// lastSentPeers must stay empty; otherwise future computePeerDiff calculations
// miss peer additions or removals after reconnect.
func TestSyncInitialMapNoPhantomPeersOnTimeout(t *testing.T) {
	testData, cleanup := setupBatcherWithTestData(t, NewBatcherAndMapper, 1, 2, normalBufferSize)
	defer cleanup()

	batcher := testData.Batcher.Batcher
	state := testData.State

	peerNode := &testData.Nodes[0]
	targetNode := &testData.Nodes[1]

	state.Connect(peerNode.n.ID)

	err := batcher.AddNode(peerNode.n.ID, peerNode.ch, tailcfg.CapabilityVersion(100), nil)
	if err != nil {
		t.Fatalf("adding peer node: %v", err)
	}

	go func() {
		for range peerNode.ch {
		}
	}()

	state.Connect(targetNode.n.ID)

	// Unbuffered channel that nobody reads: AddNode blocks on the initial-map
	// send and times out.
	unreadCh := make(chan *tailcfg.MapResponse)

	err = batcher.AddNode(targetNode.n.ID, unreadCh, tailcfg.CapabilityVersion(100), nil)
	if err == nil {
		t.Fatal("expected initial-map send timeout error, got nil")
	}

	nc, exists := batcher.nodes.Load(targetNode.n.ID)
	if !exists || nc == nil {
		t.Fatalf("expected node %d to be retained in b.nodes", targetNode.n.ID)
	}

	if nc.hasActiveConnections() {
		t.Fatalf("expected node %d to have no active connections after timeout", targetNode.n.ID)
	}

	var phantom []tailcfg.NodeID

	nc.lastSentPeers.Range(func(id tailcfg.NodeID, _ struct{}) bool {
		phantom = append(phantom, id)
		return true
	})

	if len(phantom) != 0 {
		t.Errorf("lastSentPeers must be empty after a failed initial-map delivery, got %d: %v",
			len(phantom), phantom)
	}
}
