package state

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
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
	cache := expirable.NewLRU[types.AuthID, *types.AuthRequest](
		defaultRegisterCacheMaxEntries,
		nil,
		time.Hour,
	)
	state := &State{
		authCache: cache,
	}

	expiry := time.Now().UTC().Add(time.Hour)
	registrationID := types.MustAuthID()
	registrationRequest := types.NewRegisterAuthRequest(&types.RegistrationData{
		Hostname: "test-node",
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "test-node",
		},
		Endpoints: []netip.AddrPort{
			netip.MustParseAddrPort("192.0.2.1:41641"),
		},
		Expiry: &expiry,
	})
	registrationRequest.SetPendingConfirmation(&types.PendingRegistrationConfirmation{
		UserID:     1,
		NodeExpiry: &expiry,
		CSRF:       "secret-token",
	})
	cache.Add(registrationID, registrationRequest)

	sshCheckID := types.MustAuthID()
	cache.Add(sshCheckID, types.NewSSHCheckAuthRequest(types.NodeID(1), types.NodeID(2)))

	debugInfo := state.DebugRegistrationCache()
	_, err := json.Marshal(debugInfo)
	require.NoError(t, err)

	assert.Equal(t, "expirable-lru", debugInfo.Type)
	assert.Equal(t, 2, debugInfo.CurrentLen)
	require.Len(t, debugInfo.Entries, 2)

	entries := map[string]DebugRegistrationCacheEntry{}
	for _, entry := range debugInfo.Entries {
		entries[entry.ID] = entry
	}

	registrationEntry := entries[registrationID.String()]
	assert.Equal(t, "registration", registrationEntry.Kind)
	require.NotNil(t, registrationEntry.Registration)
	assert.Equal(t, "test-node", registrationEntry.Registration.Hostname)
	assert.True(t, registrationEntry.Registration.HasHostinfo)
	assert.Equal(t, []string{"192.0.2.1:41641"}, registrationEntry.Registration.Endpoints)
	require.NotNil(t, registrationEntry.PendingConfirmation)
	assert.Equal(t, uint(1), registrationEntry.PendingConfirmation.UserID)
	assert.True(t, registrationEntry.PendingConfirmation.HasCSRF)

	sshCheckEntry := entries[sshCheckID.String()]
	assert.Equal(t, "ssh_check", sshCheckEntry.Kind)
	require.NotNil(t, sshCheckEntry.SSHCheck)
	assert.Equal(t, types.NodeID(1), sshCheckEntry.SSHCheck.SrcNodeID)
	assert.Equal(t, types.NodeID(2), sshCheckEntry.SSHCheck.DstNodeID)
}
