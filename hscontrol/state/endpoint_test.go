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
	store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

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

// TestEndpointBroadcastWorthy verifies the gate that decides whether an
// endpoint-only delta is worth fanning out to peers as an incremental
// PeersChangedPatch. A delta that only adds STUN-derived endpoints (or only
// removes endpoints) is suppressed: it is churny and unlikely to be useful,
// and disco's callMeMaybe re-derives STUN paths anyway. Only deltas that
// introduce a genuinely useful (non-STUN) endpoint are broadcast-worthy.
func TestEndpointBroadcastWorthy(t *testing.T) {
	local := netip.MustParseAddrPort("192.168.1.5:41641")
	local2 := netip.MustParseAddrPort("192.168.1.6:41641")
	stun := netip.MustParseAddrPort("203.0.113.7:41641")
	stun2 := netip.MustParseAddrPort("203.0.113.8:41641")
	portmap := netip.MustParseAddrPort("198.51.100.9:41641")

	tests := []struct {
		name    string
		stored  []netip.AddrPort
		newEPs  []netip.AddrPort
		newType []tailcfg.EndpointType
		want    bool
	}{
		{
			name:    "adds only a STUN endpoint - suppress",
			stored:  []netip.AddrPort{local},
			newEPs:  []netip.AddrPort{local, stun},
			newType: []tailcfg.EndpointType{tailcfg.EndpointLocal, tailcfg.EndpointSTUN},
			want:    false,
		},
		{
			name:    "adds only STUN4LocalPort - suppress",
			stored:  []netip.AddrPort{local},
			newEPs:  []netip.AddrPort{local, stun},
			newType: []tailcfg.EndpointType{tailcfg.EndpointLocal, tailcfg.EndpointSTUN4LocalPort},
			want:    false,
		},
		{
			name:    "adds a useful local endpoint - broadcast",
			stored:  []netip.AddrPort{stun},
			newEPs:  []netip.AddrPort{stun, local},
			newType: []tailcfg.EndpointType{tailcfg.EndpointSTUN, tailcfg.EndpointLocal},
			want:    true,
		},
		{
			name:    "adds a useful portmapped endpoint - broadcast",
			stored:  []netip.AddrPort{local},
			newEPs:  []netip.AddrPort{local, portmap},
			newType: []tailcfg.EndpointType{tailcfg.EndpointLocal, tailcfg.EndpointPortmapped},
			want:    true,
		},
		{
			name:    "pure shrink, no additions - suppress",
			stored:  []netip.AddrPort{local, local2},
			newEPs:  []netip.AddrPort{local},
			newType: []tailcfg.EndpointType{tailcfg.EndpointLocal},
			want:    false,
		},
		{
			name:   "nil types (older client) adding endpoint - broadcast",
			stored: []netip.AddrPort{local},
			newEPs: []netip.AddrPort{local, local2},
			want:   true,
		},
		{
			name:    "only STUN endpoints churn (replace one STUN with another) - suppress",
			stored:  []netip.AddrPort{local, stun},
			newEPs:  []netip.AddrPort{local, stun2},
			newType: []tailcfg.EndpointType{tailcfg.EndpointLocal, tailcfg.EndpointSTUN},
			want:    false,
		},
		{
			name:    "mixed add: one STUN and one useful - broadcast",
			stored:  []netip.AddrPort{local},
			newEPs:  []netip.AddrPort{local, stun, local2},
			newType: []tailcfg.EndpointType{tailcfg.EndpointLocal, tailcfg.EndpointSTUN, tailcfg.EndpointLocal},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := endpointBroadcastWorthy(tt.stored, tt.newEPs, tt.newType)
			assert.Equal(t, tt.want, got)
		})
	}
}
