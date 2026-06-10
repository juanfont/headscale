package mapper

import (
	"errors"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types/change"
	"tailscale.com/tailcfg"
)

// TestUnreadyConnectionDefersBroadcastsUntilInitialMap pins the ordering fix
// for the "initial MapResponse lacked Node" client failure: a connection
// registered by [Batcher.AddNode] but still waiting for its initial map must
// not receive broadcast deltas — a delta as the stream's first frame makes the
// Tailscale client tear down the poll. The change is requeued, not dropped,
// because the in-flight initial map may have been generated from a snapshot
// older than the change.
func TestUnreadyConnectionDefersBroadcastsUntilInitialMap(t *testing.T) {
	testData, cleanup := setupBatcherWithTestData(t, NewBatcherAndMapper, 1, 2, normalBufferSize)
	defer cleanup()

	batcher := testData.Batcher.Batcher
	peerNode := &testData.Nodes[0]
	targetNode := &testData.Nodes[1]

	// Register the target's connection by hand in the state AddNode leaves it
	// in between registering the channel and delivering the initial map.
	nc := newMultiChannelNodeConn(targetNode.n.ID, batcher.mapper)
	entry := &connectionEntry{
		id:      "test-unready",
		c:       targetNode.ch,
		version: tailcfg.CapabilityVersion(100),
		created: time.Now(),
	}
	entry.pendingInitial.Store(true)
	nc.addConnection(entry)
	batcher.nodes.Store(targetNode.n.ID, nc)

	// A broadcast lands while the initial map is still in flight: nothing may
	// reach the channel, and the caller must be told to retry
	// (the worker prepends such changes back onto pending).
	retryChange := change.NodeAdded(peerNode.n.ID)

	err := nc.change(retryChange)
	if !errors.Is(err, errNoReadyConnections) {
		t.Fatalf("change on unready connection: want errNoReadyConnections, got %v", err)
	}

	select {
	case resp := <-targetNode.ch:
		t.Fatalf("unready connection received a frame before its initial map: %+v", resp)
	default:
	}

	// Once the initial map is delivered, the retried change goes out.
	entry.pendingInitial.Store(false)

	err = nc.change(retryChange)
	if err != nil {
		t.Fatalf("change on ready connection: %v", err)
	}

	select {
	case resp := <-targetNode.ch:
		if len(resp.PeersChanged) == 0 {
			t.Fatalf("expected PeersChanged delta after readiness, got %+v", resp)
		}
	default:
		t.Fatal("ready connection did not receive the retried change")
	}
}

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
