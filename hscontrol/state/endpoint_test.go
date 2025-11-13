package state

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestEndpointStorageInNodeStore verifies that endpoints sent in MapRequest via ApplyPeerChange
// are correctly stored in the NodeStore and can be retrieved for sending to peers.
// This test reproduces the issue reported in https://github.com/juanfont/headscale/issues/2846
func TestEndpointStorageInNodeStore(t *testing.T) {
	// Create two test nodes
	node1 := createTestNode(1, 1, "test-user", "node1")
	node2 := createTestNode(2, 1, "test-user", "node2")

	// Create NodeStore with allow-all peers function
	store := NewNodeStore(nil, allowAllPeersFunc)

	store.Start()
	defer store.Stop()

	// Add both nodes to NodeStore
	store.PutNode(node1)
	store.PutNode(node2)

	// Create a MapRequest with endpoints for node1
	endpoints := []netip.AddrPort{
		netip.MustParseAddrPort("192.168.1.1:41641"),
		netip.MustParseAddrPort("10.0.0.1:41641"),
	}

	mapReq := tailcfg.MapRequest{
		NodeKey:   node1.NodeKey,
		DiscoKey:  node1.DiscoKey,
		Endpoints: endpoints,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "node1",
		},
	}

	// Simulate what UpdateNodeFromMapRequest does: create PeerChange and apply it
	peerChange := node1.PeerChangeFromMapRequest(mapReq)

	// Verify PeerChange has endpoints
	require.NotNil(t, peerChange.Endpoints, "PeerChange should contain endpoints")
	assert.Len(t, peerChange.Endpoints, len(endpoints),
		"PeerChange should have same number of endpoints as MapRequest")

	// Apply the PeerChange via NodeStore.UpdateNode
	updatedNode, ok := store.UpdateNode(node1.ID, func(n *types.Node) {
		n.ApplyPeerChange(&peerChange)
	})
	require.True(t, ok, "UpdateNode should succeed")
	require.True(t, updatedNode.Valid(), "Updated node should be valid")

	// Verify endpoints are in the updated node view
	storedEndpoints := updatedNode.Endpoints().AsSlice()
	assert.Len(t, storedEndpoints, len(endpoints),
		"NodeStore should have same number of endpoints as sent")

	if len(storedEndpoints) == len(endpoints) {
		for i, ep := range endpoints {
			assert.Equal(t, ep, storedEndpoints[i],
				"Endpoint %d should match", i)
		}
	}

	// Verify we can retrieve the node again and endpoints are still there
	retrievedNode, found := store.GetNode(node1.ID)
	require.True(t, found, "node1 should exist in NodeStore")

	retrievedEndpoints := retrievedNode.Endpoints().AsSlice()
	assert.Len(t, retrievedEndpoints, len(endpoints),
		"Retrieved node should have same number of endpoints")

	// Verify that when we get node1 as a peer of node2, it has endpoints
	// This is the critical part that was failing in the bug report
	peers := store.ListPeers(node2.ID)
	require.Positive(t, peers.Len(), "node2 should have at least one peer")

	// Find node1 in the peer list
	var node1Peer types.NodeView

	foundPeer := false

	for _, peer := range peers.All() {
		if peer.ID() == node1.ID {
			node1Peer = peer
			foundPeer = true

			break
		}
	}

	require.True(t, foundPeer, "node1 should be in node2's peer list")

	// Check that node1's endpoints are available in the peer view
	peerEndpoints := node1Peer.Endpoints().AsSlice()
	assert.Len(t, peerEndpoints, len(endpoints),
		"Peer view should have same number of endpoints as sent")

	if len(peerEndpoints) == len(endpoints) {
		for i, ep := range endpoints {
			assert.Equal(t, ep, peerEndpoints[i],
				"Peer endpoint %d should match", i)
		}
	}
}
