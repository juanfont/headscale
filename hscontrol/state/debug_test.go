package state

import (
	"testing"

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
				return NewNodeStore(nil, nil, allowAllPeersFunc)
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

				store := NewNodeStore(nil, nil, allowAllPeersFunc)
				store.Start()

				store.PutNode(node1)
				store.PutNode(node2)

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
	store := NewNodeStore(nil, nil, allowAllPeersFunc)

	debugStr := store.DebugString()

	// Should contain basic debug information
	assert.Contains(t, debugStr, "=== NodeStore Debug Information ===")
	assert.Contains(t, debugStr, "Total Nodes: 0")
	assert.Contains(t, debugStr, "Users with Nodes: 0")
	assert.Contains(t, debugStr, "NodeKey Index: 0 entries")
	assert.Contains(t, debugStr, "Total WG Peers: 0")
	assert.Contains(t, debugStr, "WG Peer Visibility:")
}

func TestNodeStoreDebugStringWithWGPeers(t *testing.T) {
	// Create NodeStore with regular nodes and WG peers
	node1 := createTestNode(1, 1, "user1", "node1")
	node2 := createTestNode(2, 1, "user1", "node2")

	store := NewNodeStore(nil, nil, allowAllPeersFunc)
	store.Start()
	defer store.Stop()

	store.PutNode(node1)
	store.PutNode(node2)

	// WG peer 100: visible to node 1 only
	wgPeer1 := createTestWGPeer(100, 1, "user1", "wg-peer1", []uint64{1})
	store.PutWGPeer(wgPeer1)

	// WG peer 101: visible to both nodes
	wgPeer2 := createTestWGPeer(101, 1, "user1", "wg-peer2", []uint64{1, 2})
	store.PutWGPeer(wgPeer2)

	debugStr := store.DebugString()

	assert.Contains(t, debugStr, "Total WG Peers: 2")

	assert.Contains(t, debugStr, "WG Peer Visibility:")
	assert.Contains(t, debugStr, "Node 1 (node1): can see 2 WG peers")
	assert.Contains(t, debugStr, "Node 2 (node2): can see 1 WG peers")

	assert.Contains(t, debugStr, "WG Peer Details:")

	assert.Contains(t, debugStr, "ID: 100, Name: \"wg-peer1\"")
	assert.Contains(t, debugStr, "Visible to 1 nodes: [1]")

	assert.Contains(t, debugStr, "ID: 101, Name: \"wg-peer2\"")
	assert.Contains(t, debugStr, "Visible to 2 nodes: [1 2]")
}
