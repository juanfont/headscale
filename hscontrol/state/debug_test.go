package state

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
)

func TestNodeStoreDebugString(t *testing.T) {
	tests := []struct {
		name     string
		setupFn  func() *NodeStore
		contains []string
	}{
		{
			name: "empty nodestore",
			setupFn: func() *NodeStore {
				return NewNodeStore(nil, nil, nil, allowAllPeersFunc)
			},
			contains: []string{
				"=== NodeStore Debug Information ===",
				"Total Nodes: 0",
				"Users with Nodes: 0",
				"NodeKey Index: 0 entries",
			},
		},
		{
			name: "nodestore with data",
			setupFn: func() *NodeStore {
				node1 := createTestNode(1, 1, "user1", "node1")
				node2 := createTestNode(2, 2, "user2", "node2")

				store := NewNodeStore(nil, nil, nil, allowAllPeersFunc)
				store.Start()

				_ = store.PutNode(node1)
				_ = store.PutNode(node2)

				return store
			},
			contains: []string{
				"Total Nodes: 2",
				"Users with Nodes: 2",
				"Peer Relationships:",
				"NodeKey Index: 2 entries",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := tt.setupFn()
			if store.writeQueue != nil {
				defer store.Stop()
			}

			debugStr := store.DebugString()

			for _, expected := range tt.contains {
				assert.Contains(t, debugStr, expected,
					"Debug string should contain: %s\nActual debug:\n%s", expected, debugStr)
			}
		})
	}
}

func TestDebugRegistrationCache(t *testing.T) {
	// Create a minimal NodeStore for testing debug methods
	store := NewNodeStore(nil, nil, nil, allowAllPeersFunc)

	debugStr := store.DebugString()

	// Should contain basic debug information
	assert.Contains(t, debugStr, "=== NodeStore Debug Information ===")
	assert.Contains(t, debugStr, "Total Nodes: 0")
	assert.Contains(t, debugStr, "Users with Nodes: 0")
	assert.Contains(t, debugStr, "NodeKey Index: 0 entries")
	assert.Contains(t, debugStr, "Total WG Peers: 0")
	// Empty store should not show WG Peer Connections section
	assert.NotContains(t, debugStr, "WG Peer Connections:")
}

func TestNodeStoreDebugStringWithWGPeers(t *testing.T) {
	// Create NodeStore with regular nodes and WG peers
	node1 := createTestNode(1, 1, "user1", "node1")
	node2 := createTestNode(2, 1, "user1", "node2")

	store := NewNodeStore(nil, nil, nil, allowAllPeersFunc)
	store.Start()
	defer store.Stop()

	store.PutNode(node1)
	store.PutNode(node2)

	// WG peer 100: connected to node 1 only
	wgPeer1 := createTestWGPeer(100, 1, "user1", "wg-peer1")
	store.PutWGPeer(wgPeer1)

	// WG peer 101: connected to both nodes
	wgPeer2 := createTestWGPeer(101, 1, "user1", "wg-peer2")
	store.PutWGPeer(wgPeer2)

	// Create connections
	ipv4Masq1 := netip.MustParseAddr("10.0.0.1")
	ipv4Masq2 := netip.MustParseAddr("10.0.0.2")
	ipv6Masq1 := netip.MustParseAddr("ff20:4::20")

	conn1 := &types.WireGuardConnection{
		NodeID:       1,
		WGPeerID:     100,
		IPv4MasqAddr: &ipv4Masq1,
	}
	conn2 := &types.WireGuardConnection{
		NodeID:       1,
		WGPeerID:     101,
		IPv4MasqAddr: &ipv4Masq1,
		IPv6MasqAddr: &ipv6Masq1,
	}
	conn3 := &types.WireGuardConnection{
		NodeID:       2,
		WGPeerID:     101,
		IPv4MasqAddr: &ipv4Masq2,
	}

	store.PutConnection(conn1)
	store.PutConnection(conn2)
	store.PutConnection(conn3)

	debugStr := store.DebugString()

	assert.Contains(t, debugStr, "Total WG Peers: 2")

	// Verify WG Peer Connections section exists with detailed connection info
	assert.Contains(t, debugStr, "WG Peer Connections:")
	assert.Contains(t, debugStr, "Node 1 (node1) -> 2 WG peer(s):")
	assert.Contains(t, debugStr, "Node 2 (node2) -> 1 WG peer(s):")

	// Verify connection details show peer names and masquerade addresses
	assert.Contains(t, debugStr, "WG Peer 100 (wg-peer1)")
	assert.Contains(t, debugStr, "IPv4: 10.0.0.1")
	assert.Contains(t, debugStr, "WG Peer 101 (wg-peer2)")
	assert.Contains(t, debugStr, "IPv4: 10.0.0.2")
	assert.Contains(t, debugStr, "IPv6: ff20:4::20")
}
