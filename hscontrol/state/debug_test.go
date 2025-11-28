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
				return NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)
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

				store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)
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
	store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	debugStr := store.DebugString()

	// Should contain basic debug information
	assert.Contains(t, debugStr, "=== NodeStore Debug Information ===")
	assert.Contains(t, debugStr, "Total Nodes: 0")
	assert.Contains(t, debugStr, "Users with Nodes: 0")
	assert.Contains(t, debugStr, "NodeKey Index: 0 entries")
}
