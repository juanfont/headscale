package state

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestNetInfoFromMapRequest(t *testing.T) {
	nodeID := types.NodeID(1)

	tests := []struct {
		name            string
		currentHostinfo *tailcfg.Hostinfo
		reqHostinfo     *tailcfg.Hostinfo
		expectNetInfo   *tailcfg.NetInfo
	}{
		{
			name:            "no current NetInfo - return nil",
			currentHostinfo: nil,
			reqHostinfo: &tailcfg.Hostinfo{
				Hostname: "test-node",
			},
			expectNetInfo: nil,
		},
		{
			name: "current has NetInfo, request has NetInfo - use request",
			currentHostinfo: &tailcfg.Hostinfo{
				NetInfo: &tailcfg.NetInfo{PreferredDERP: 1},
			},
			reqHostinfo: &tailcfg.Hostinfo{
				Hostname: "test-node",
				NetInfo:  &tailcfg.NetInfo{PreferredDERP: 2},
			},
			expectNetInfo: &tailcfg.NetInfo{PreferredDERP: 2},
		},
		{
			name: "current has NetInfo, request has no NetInfo - use current",
			currentHostinfo: &tailcfg.Hostinfo{
				NetInfo: &tailcfg.NetInfo{PreferredDERP: 3},
			},
			reqHostinfo: &tailcfg.Hostinfo{
				Hostname: "test-node",
			},
			expectNetInfo: &tailcfg.NetInfo{PreferredDERP: 3},
		},
		{
			name: "current has NetInfo, no request Hostinfo - use current",
			currentHostinfo: &tailcfg.Hostinfo{
				NetInfo: &tailcfg.NetInfo{PreferredDERP: 4},
			},
			reqHostinfo:   nil,
			expectNetInfo: &tailcfg.NetInfo{PreferredDERP: 4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NetInfoFromMapRequest(nodeID, tt.currentHostinfo, tt.reqHostinfo)

			if tt.expectNetInfo == nil {
				assert.Nil(t, result, "expected nil NetInfo")
			} else {
				require.NotNil(t, result, "expected non-nil NetInfo")
				assert.Equal(t, tt.expectNetInfo.PreferredDERP, result.PreferredDERP, "DERP mismatch")
			}
		})
	}
}

func TestNetInfoPreservationInRegistrationFlow(t *testing.T) {
	nodeID := types.NodeID(1)

	// This test reproduces the bug in registration flows where NetInfo was lost
	// because we used the wrong hostinfo reference when calling NetInfoFromMapRequest
	t.Run("registration_flow_bug_reproduction", func(t *testing.T) {
		// Simulate existing node with NetInfo (before re-registration)
		existingNodeHostinfo := &tailcfg.Hostinfo{
			Hostname: "test-node",
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 5},
		}

		// Simulate new registration request (no NetInfo)
		newRegistrationHostinfo := &tailcfg.Hostinfo{
			Hostname: "test-node",
			OS:       "linux",
			// NetInfo is nil - this is what comes from the registration request
		}

		// Simulate what was happening in the bug: we passed the "current node being modified"
		// hostinfo (which has no NetInfo) instead of the existing node's hostinfo
		nodeBeingModifiedHostinfo := &tailcfg.Hostinfo{
			Hostname: "test-node",
			// NetInfo is nil because this node is being modified/reset
		}

		// BUG: Using the node being modified (no NetInfo) instead of existing node (has NetInfo)
		buggyResult := NetInfoFromMapRequest(nodeID, nodeBeingModifiedHostinfo, newRegistrationHostinfo)
		assert.Nil(t, buggyResult, "Bug: Should return nil when using wrong hostinfo reference")

		// CORRECT: Using the existing node's hostinfo (has NetInfo)
		correctResult := NetInfoFromMapRequest(nodeID, existingNodeHostinfo, newRegistrationHostinfo)
		assert.NotNil(t, correctResult, "Fix: Should preserve NetInfo when using correct hostinfo reference")
		assert.Equal(t, 5, correctResult.PreferredDERP, "Should preserve the DERP region from existing node")
	})
}

// Simple helper function for tests
func createTestNodeSimple(id types.NodeID) *types.Node {
	user := types.User{
		Name: "test-user",
	}

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	node := &types.Node{
		ID:         id,
		Hostname:   "test-node",
		UserID:     uint(id),
		User:       user,
		MachineKey: machineKey.Public(),
		NodeKey:    nodeKey.Public(),
		IPv4:       &netip.Addr{},
		IPv6:       &netip.Addr{},
	}

	return node
}
