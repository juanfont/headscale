package servertest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// TestNodeAttrs verifies that nodeAttrs in a Headscale policy are
// compiled, cached, and distributed to Tailscale clients via MapResponse.
// It uses the in-process servertest harness (no Docker).
// Scenarios progress from simple to complex.
func TestNodeAttrs(t *testing.T) {
	t.Parallel()

	// Scenario 1: Single node gets a single capability.
	// Validates the most basic nodeAttrs path.
	t.Run("single_node_single_cap", func(t *testing.T) {
		t.Parallel()

		server := NewServer(t)
		defer server.Close()

		user := server.CreateUser(t, "single-user")
		client := NewClient(t, server, "single-node", WithUser(user))

		// Wait for initial map (no peers, just self).
		client.WaitForCondition(t, "initial netmap", 5*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm != nil && nm.SelfNode.Valid()
			})

		policy := []byte(`{
			"nodeAttrs": [
				{"target": ["single-user@"], "attr": ["funnel"]}
			],
			"acls": [
				{"action": "accept", "src": ["*"], "dst": ["*:*"]}
			]
		}`)

		changed, err := server.State().SetPolicy(policy)
		require.NoError(t, err)
		require.True(t, changed)

		if changed {
			changes, err := server.State().ReloadPolicy()
			require.NoError(t, err)
			server.App.Change(changes...)
		}

		client.WaitForCondition(t, "self gets funnel cap", 5*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm.SelfNode.Valid() &&
					nm.SelfNode.CapMap().Contains(tailcfg.NodeCapability("funnel"))
			})

		nm := client.Netmap()
		require.NotNil(t, nm)
		require.True(t, nm.SelfNode.CapMap().Contains(tailcfg.NodeCapability("funnel")),
			"self node should have funnel capability")
	})

	// Scenario 2: One node gets multiple capabilities.
	// Validates that CapMap can hold more than one entry.
	t.Run("multiple_caps_per_node", func(t *testing.T) {
		t.Parallel()

		server := NewServer(t)
		defer server.Close()

		user := server.CreateUser(t, "multi-cap-user")
		client := NewClient(t, server, "multi-cap-node", WithUser(user))

		client.WaitForCondition(t, "initial netmap", 5*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm != nil && nm.SelfNode.Valid()
			})

		policy := []byte(`{
			"nodeAttrs": [
				{
					"target": ["multi-cap-user@"],
					"attr": ["funnel", "custom:abac-allow", "custom:route-admin"]
				}
			],
			"acls": [
				{"action": "accept", "src": ["*"], "dst": ["*:*"]}
			]
		}`)

		changed, err := server.State().SetPolicy(policy)
		require.NoError(t, err)
		require.True(t, changed)

		if changed {
			changes, err := server.State().ReloadPolicy()
			require.NoError(t, err)
			server.App.Change(changes...)
		}

		client.WaitForCondition(t, "self gets all caps", 5*time.Second,
			func(nm *netmap.NetworkMap) bool {
				if !nm.SelfNode.Valid() {
					return false
				}
				cm := nm.SelfNode.CapMap()
				return cm.Contains(tailcfg.NodeCapability("funnel")) &&
					cm.Contains(tailcfg.NodeCapability("custom:abac-allow")) &&
					cm.Contains(tailcfg.NodeCapability("custom:route-admin"))
			})

		nm := client.Netmap()
		require.NotNil(t, nm)
		cm := nm.SelfNode.CapMap()
		require.True(t, cm.Contains(tailcfg.NodeCapability("funnel")))
		require.True(t, cm.Contains(tailcfg.NodeCapability("custom:abac-allow")))
		require.True(t, cm.Contains(tailcfg.NodeCapability("custom:route-admin")))
	})

	// Scenario 3: Multi-user isolation — only targeted user gets caps.
	// Validates that target matching is precise and non-targeted users
	// do not receive capabilities.
	t.Run("multi_user_isolation", func(t *testing.T) {
		t.Parallel()

		server := NewServer(t)
		defer server.Close()

		alice := server.CreateUser(t, "alice")
		bob := server.CreateUser(t, "bob")

		aliceClient := NewClient(t, server, "alice-node", WithUser(alice))
		bobClient := NewClient(t, server, "bob-node", WithUser(bob))

		aliceClient.WaitForPeers(t, 1, 5*time.Second)
		bobClient.WaitForPeers(t, 1, 5*time.Second)

		policy := []byte(`{
			"nodeAttrs": [
				{"target": ["alice@"], "attr": ["funnel"]}
			],
			"acls": [
				{"action": "accept", "src": ["*"], "dst": ["*:*"]}
			]
		}`)

		changed, err := server.State().SetPolicy(policy)
		require.NoError(t, err)
		require.True(t, changed)

		if changed {
			changes, err := server.State().ReloadPolicy()
			require.NoError(t, err)
			server.App.Change(changes...)
		}

		aliceClient.WaitForCondition(t, "alice gets funnel", 5*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm.SelfNode.Valid() &&
					nm.SelfNode.CapMap().Contains(tailcfg.NodeCapability("funnel"))
			})
		bobClient.WaitForCondition(t, "bob netmap stable", 5*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm.SelfNode.Valid() &&
					!nm.SelfNode.CapMap().Contains(tailcfg.NodeCapability("funnel"))
			})

		aliceNM := aliceClient.Netmap()
		require.NotNil(t, aliceNM)
		require.True(t, aliceNM.SelfNode.CapMap().Contains(tailcfg.NodeCapability("funnel")),
			"alice should have funnel")

		bobNM := bobClient.Netmap()
		require.NotNil(t, bobNM)
		require.False(t, bobNM.SelfNode.CapMap().Contains(tailcfg.NodeCapability("funnel")),
			"bob should NOT have funnel")
	})

	// Scenario 4: Peer CapMap visibility.
	// Validates that peers see each other's CapMap entries in their
	// netmap, not just their own.
	t.Run("peer_capmap_visibility", func(t *testing.T) {
		t.Parallel()

		server := NewServer(t)
		defer server.Close()

		alice := server.CreateUser(t, "alice")
		bob := server.CreateUser(t, "bob")

		aliceClient := NewClient(t, server, "alice-node", WithUser(alice))
		bobClient := NewClient(t, server, "bob-node", WithUser(bob))

		aliceClient.WaitForPeers(t, 1, 5*time.Second)
		bobClient.WaitForPeers(t, 1, 5*time.Second)

		policy := []byte(`{
			"nodeAttrs": [
				{"target": ["alice@"], "attr": ["funnel"]}
			],
			"acls": [
				{"action": "accept", "src": ["*"], "dst": ["*:*"]}
			]
		}`)

		changed, err := server.State().SetPolicy(policy)
		require.NoError(t, err)
		require.True(t, changed)

		if changed {
			changes, err := server.State().ReloadPolicy()
			require.NoError(t, err)
			server.App.Change(changes...)
		}

		// Alice sees herself with funnel.
		aliceClient.WaitForCondition(t, "alice self has funnel", 5*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm.SelfNode.Valid() &&
					nm.SelfNode.CapMap().Contains(tailcfg.NodeCapability("funnel"))
			})

		// Bob sees alice with funnel in peer list.
		bobClient.WaitForCondition(t, "bob sees alice with funnel", 5*time.Second,
			func(nm *netmap.NetworkMap) bool {
				if peer, ok := bobClient.PeerByName("alice-node"); ok {
					return peer.CapMap().Contains(tailcfg.NodeCapability("funnel"))
				}
				return false
			})

		// Alice sees bob WITHOUT funnel.
		alicePeerBob, ok := aliceClient.PeerByName("bob-node")
		require.True(t, ok, "alice should see bob")
		require.False(t, alicePeerBob.CapMap().Contains(tailcfg.NodeCapability("funnel")),
			"alice should see bob without funnel")

		// Bob sees himself WITHOUT funnel.
		bobNM := bobClient.Netmap()
		require.NotNil(t, bobNM)
		require.False(t, bobNM.SelfNode.CapMap().Contains(tailcfg.NodeCapability("funnel")),
			"bob self should not have funnel")
	})

	// Scenario 5: Dynamic policy change — capabilities are added, then removed.
	// Validates that CapMap is updated incrementally when policy changes.
	t.Run("dynamic_policy_change", func(t *testing.T) {
		t.Parallel()

		server := NewServer(t)
		defer server.Close()

		user := server.CreateUser(t, "dynamic-user")
		client := NewClient(t, server, "dynamic-node", WithUser(user))

		client.WaitForCondition(t, "initial netmap", 5*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm != nil && nm.SelfNode.Valid()
			})

		// Phase 1: grant capability.
		policyWithCap := []byte(`{
			"nodeAttrs": [
				{"target": ["dynamic-user@"], "attr": ["funnel"]}
			],
			"acls": [
				{"action": "accept", "src": ["*"], "dst": ["*:*"]}
			]
		}`)

		changed, err := server.State().SetPolicy(policyWithCap)
		require.NoError(t, err)
		require.True(t, changed)

		if changed {
			changes, err := server.State().ReloadPolicy()
			require.NoError(t, err)
			server.App.Change(changes...)
		}

		client.WaitForCondition(t, "self gets funnel", 5*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm.SelfNode.Valid() &&
					nm.SelfNode.CapMap().Contains(tailcfg.NodeCapability("funnel"))
			})

		// Phase 2: remove nodeAttrs entirely.
		policyWithoutCap := []byte(`{
			"acls": [
				{"action": "accept", "src": ["*"], "dst": ["*:*"]}
			]
		}`)

		changed, err = server.State().SetPolicy(policyWithoutCap)
		require.NoError(t, err)
		require.True(t, changed)

		if changed {
			changes, err := server.State().ReloadPolicy()
			require.NoError(t, err)
			server.App.Change(changes...)
		}

		client.WaitForCondition(t, "self loses funnel", 5*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm.SelfNode.Valid() &&
					!nm.SelfNode.CapMap().Contains(tailcfg.NodeCapability("funnel"))
			})

		nm := client.Netmap()
		require.NotNil(t, nm)
		require.False(t, nm.SelfNode.CapMap().Contains(tailcfg.NodeCapability("funnel")),
			"capability should be removed after policy change")
	})

	// Scenario 6: Tag-based target.
	// Validates that nodeAttrs can target tags instead of users.
	t.Run("tag_target", func(t *testing.T) {
		t.Parallel()

		server := NewServer(t)
		defer server.Close()

		user := server.CreateUser(t, "tag-owner")

		// Set policy with tag owners before creating tagged nodes.
		policy := []byte(`{
			"tagOwners": {
				"tag:abac-node": ["tag-owner@"]
			},
			"nodeAttrs": [
				{"target": ["tag:abac-node"], "attr": ["custom:abac-allow"]}
			],
			"acls": [
				{"action": "accept", "src": ["*"], "dst": ["*:*"]}
			]
		}`)

		changed, err := server.State().SetPolicy(policy)
		require.NoError(t, err)
		require.True(t, changed)

		if changed {
			changes, err := server.State().ReloadPolicy()
			require.NoError(t, err)
			server.App.Change(changes...)
		}

		taggedClient := NewClient(t, server, "tagged-node",
			WithUser(user), WithTags("tag:abac-node"))
		plainClient := NewClient(t, server, "plain-node", WithUser(user))

		taggedClient.WaitForPeers(t, 1, 5*time.Second)
		plainClient.WaitForPeers(t, 1, 5*time.Second)

		taggedClient.WaitForCondition(t, "tagged self has cap", 5*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm.SelfNode.Valid() &&
					nm.SelfNode.CapMap().Contains(tailcfg.NodeCapability("custom:abac-allow"))
			})

		plainClient.WaitForCondition(t, "plain self stable", 5*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm.SelfNode.Valid() &&
					!nm.SelfNode.CapMap().Contains(tailcfg.NodeCapability("custom:abac-allow"))
			})

		taggedNM := taggedClient.Netmap()
		require.NotNil(t, taggedNM)
		require.True(t, taggedNM.SelfNode.CapMap().Contains(tailcfg.NodeCapability("custom:abac-allow")),
			"tagged node should have custom:abac-allow")

		plainNM := plainClient.Netmap()
		require.NotNil(t, plainNM)
		require.False(t, plainNM.SelfNode.CapMap().Contains(tailcfg.NodeCapability("custom:abac-allow")),
			"plain node should NOT have custom:abac-allow")

		// Verify peer visibility: plain sees tagged with cap.
		taggedPeer, ok := plainClient.PeerByName("tagged-node")
		require.True(t, ok, "plain should see tagged as peer")
		require.True(t, taggedPeer.CapMap().Contains(tailcfg.NodeCapability("custom:abac-allow")),
			"plain should see tagged node with custom:abac-allow")
	})

	// Scenario 7: Full end-to-end with multiple users, multiple caps,
	// and peer visibility in both directions.
	// This is the integration-style smoke test.
	t.Run("full_end_to_end", func(t *testing.T) {
		t.Parallel()

		server := NewServer(t)
		defer server.Close()

		alice := server.CreateUser(t, "alice")
		bob := server.CreateUser(t, "bob")

		aliceClient := NewClient(t, server, "alice-node", WithUser(alice))
		bobClient := NewClient(t, server, "bob-node", WithUser(bob))

		aliceClient.WaitForPeers(t, 1, 5*time.Second)
		bobClient.WaitForPeers(t, 1, 5*time.Second)

		policy := []byte(`{
			"nodeAttrs": [
				{
					"target": ["alice@"],
					"attr": ["funnel", "custom:abac-allow"]
				}
			],
			"acls": [
				{"action": "accept", "src": ["*"], "dst": ["*:*"]}
			]
		}`)

		changed, err := server.State().SetPolicy(policy)
		require.NoError(t, err)
		require.True(t, changed)

		if changed {
			changes, err := server.State().ReloadPolicy()
			require.NoError(t, err)
			server.App.Change(changes...)
		}

		aliceClient.WaitForCondition(t, "alice gets funnel cap", 5*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm.SelfNode.Valid() &&
					nm.SelfNode.CapMap().Contains(tailcfg.NodeCapability("funnel"))
			})
		bobClient.WaitForCondition(t, "bob sees alice with funnel", 5*time.Second,
			func(nm *netmap.NetworkMap) bool {
				if peer, ok := bobClient.PeerByName("alice-node"); ok {
					return peer.CapMap().Contains(tailcfg.NodeCapability("funnel"))
				}
				return false
			})

		aliceNM := aliceClient.Netmap()
		require.NotNil(t, aliceNM)
		aliceCapMap := aliceNM.SelfNode.CapMap()
		require.True(t, aliceCapMap.Contains(tailcfg.NodeCapability("funnel")))
		require.True(t, aliceCapMap.Contains(tailcfg.NodeCapability("custom:abac-allow")))

		bobPeer, ok := aliceClient.PeerByName("bob-node")
		require.True(t, ok)
		require.False(t, bobPeer.CapMap().Contains(tailcfg.NodeCapability("custom:abac-allow")),
			"bob should not have custom:abac-allow in alice's view")

		bobNM := bobClient.Netmap()
		require.NotNil(t, bobNM)
		require.False(t, bobNM.SelfNode.CapMap().Contains(tailcfg.NodeCapability("funnel")),
			"bob self should not have funnel")

		alicePeer, ok := bobClient.PeerByName("alice-node")
		require.True(t, ok)
		require.True(t, alicePeer.CapMap().Contains(tailcfg.NodeCapability("funnel")),
			"bob should see alice with funnel cap")
	})
}
