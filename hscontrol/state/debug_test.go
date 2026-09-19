package state

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestNodeStoreDebugRegistrationCache(t *testing.T) {
	// Create a minimal NodeStore for testing debug methods
	store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	debugStr := store.DebugString()

	// Should contain basic debug information
	assert.Contains(t, debugStr, "=== NodeStore Debug Information ===")
	assert.Contains(t, debugStr, "Total Nodes: 0")
	assert.Contains(t, debugStr, "Users with Nodes: 0")
	assert.Contains(t, debugStr, "NodeKey Index: 0 entries")
}

// TestStateDebugRegistrationCache exercises [State.DebugRegistrationCache]
// itself (the previous test of that name actually exercised
// [NodeStore.DebugString], a different type entirely). Regression coverage
// for #2714: entries must be JSON-safe, which the raw [types.AuthRequest]
// is not, since it carries an unexported channel field.
func TestStateDebugRegistrationCache(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// Empty cache.
	info := s.DebugRegistrationCache()
	assert.Equal(t, 0, info["current_len"])
	assert.Empty(t, info["entries"])

	// A plain (non-registration, non-SSH-check) pending auth request.
	plainID := types.MustAuthID()
	s.SetAuthCacheEntry(plainID, types.NewAuthRequest())

	// A node-registration request.
	regID := types.MustAuthID()
	s.SetAuthCacheEntry(regID, types.NewRegisterAuthRequest(&types.RegistrationData{}))

	// An SSH check-mode request.
	sshID := types.MustAuthID()
	s.SetAuthCacheEntry(sshID, types.NewSSHCheckAuthRequest(1, 2))

	info = s.DebugRegistrationCache()
	assert.Equal(t, 3, info["current_len"])

	entries, ok := info["entries"].([]map[string]any)
	require.True(t, ok, "entries should be a []map[string]any")
	require.Len(t, entries, 3)

	byID := make(map[string]map[string]any, len(entries))
	for _, e := range entries {
		byID[e["auth_id"].(string)] = e
	}

	assert.Equal(t, "plain", byID[string(plainID)]["type"])
	assert.Equal(t, "registration", byID[string(regID)]["type"])
	assert.Equal(t, "ssh-check", byID[string(sshID)]["type"])
}
