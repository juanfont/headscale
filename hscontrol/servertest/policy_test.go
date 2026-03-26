package servertest_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/netmap"
)

// TestPolicyChanges verifies that ACL policy changes propagate
// correctly to all connected nodes, affecting peer visibility
// and packet filters.
func TestPolicyChanges(t *testing.T) {
	t.Parallel()

	t.Run("default_allow_all", func(t *testing.T) {
		t.Parallel()
		// With no explicit policy (database mode), the default
		// is to allow all traffic. All nodes should see each other.
		h := servertest.NewHarness(t, 3)
		servertest.AssertMeshComplete(t, h.Clients())
	})

	t.Run("explicit_allow_all_policy", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		// Record update counts before policy change.
		countBefore := h.Client(0).UpdateCount()

		// Set an allow-all policy explicitly.
		h.ChangePolicy(t, []byte(`{
			"acls": [
				{"action": "accept", "src": ["*"], "dst": ["*:*"]}
			]
		}`))

		// Both clients should receive an update after the policy change.
		h.Client(0).WaitForCondition(t, "update after policy",
			10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return h.Client(0).UpdateCount() > countBefore
			})
	})

	t.Run("policy_with_allow_all_has_packet_filter", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "pf-user")

		// Set a valid allow-all policy.
		changed, err := srv.State().SetPolicy([]byte(`{
			"acls": [
				{"action": "accept", "src": ["*"], "dst": ["*:*"]}
			]
		}`))
		require.NoError(t, err)

		if changed {
			changes, err := srv.State().ReloadPolicy()
			require.NoError(t, err)
			srv.App.Change(changes...)
		}

		c := servertest.NewClient(t, srv, "pf-node", servertest.WithUser(user))
		c.WaitForUpdate(t, 15*time.Second)

		nm := c.Netmap()
		require.NotNil(t, nm)

		// The netmap should have packet filter rules from the
		// allow-all policy.
		assert.NotNil(t, nm.PacketFilter,
			"PacketFilter should be populated with allow-all rules")
	})

	t.Run("policy_change_triggers_update_on_all_nodes", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 3)

		counts := make([]int, len(h.Clients()))
		for i, c := range h.Clients() {
			counts[i] = c.UpdateCount()
		}

		// Change policy.
		h.ChangePolicy(t, []byte(`{
			"acls": [
				{"action": "accept", "src": ["*"], "dst": ["*:*"]}
			]
		}`))

		// All clients should receive at least one more update.
		for i, c := range h.Clients() {
			c.WaitForCondition(t, "update after policy change",
				10*time.Second,
				func(nm *netmap.NetworkMap) bool {
					return c.UpdateCount() > counts[i]
				})
		}
	})

	t.Run("multiple_policy_changes", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		// Apply policy twice and verify updates arrive both times.
		for round := range 2 {
			countBefore := h.Client(0).UpdateCount()

			h.ChangePolicy(t, []byte(`{
				"acls": [
					{"action": "accept", "src": ["*"], "dst": ["*:*"]}
				]
			}`))

			h.Client(0).WaitForCondition(t, "update after policy change",
				10*time.Second,
				func(nm *netmap.NetworkMap) bool {
					return h.Client(0).UpdateCount() > countBefore
				})

			t.Logf("round %d: update received", round)
		}
	})

	t.Run("policy_with_multiple_users", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user1 := srv.CreateUser(t, "multi-user1")
		user2 := srv.CreateUser(t, "multi-user2")
		user3 := srv.CreateUser(t, "multi-user3")

		c1 := servertest.NewClient(t, srv, "multi-node1", servertest.WithUser(user1))
		c2 := servertest.NewClient(t, srv, "multi-node2", servertest.WithUser(user2))
		c3 := servertest.NewClient(t, srv, "multi-node3", servertest.WithUser(user3))

		// With default allow-all, all should see each other.
		c1.WaitForPeers(t, 2, 15*time.Second)
		c2.WaitForPeers(t, 2, 15*time.Second)
		c3.WaitForPeers(t, 2, 15*time.Second)

		servertest.AssertMeshComplete(t,
			[]*servertest.TestClient{c1, c2, c3})
	})
}

// TestIPv6OnlyPrefixACL verifies that an ACL using only IPv6 prefixes
// correctly generates filter rules for IPv6 traffic. Address-based aliases
// (Prefix, Host) resolve to exactly the literal prefix and do NOT expand
// to include the matching node's other IP addresses.
//
// PacketFilter rules are INBOUND: they tell the destination node what
// traffic to accept. So the IPv6 destination rule appears in test2's
// PacketFilter (the destination), not test1's (the source).
func TestIPv6OnlyPrefixACL(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "ipv6-user")

	// Set a policy that only uses IPv6 prefixes.
	changed, err := srv.State().SetPolicy([]byte(`{
		"hosts": {
			"test1": "fd7a:115c:a1e0::1/128",
			"test2": "fd7a:115c:a1e0::2/128"
		},
		"acls": [{
			"action": "accept",
			"src": ["test1"],
			"dst": ["test2:*"]
		}]
	}`))
	require.NoError(t, err)

	if changed {
		changes, err := srv.State().ReloadPolicy()
		require.NoError(t, err)
		srv.App.Change(changes...)
	}

	c1 := servertest.NewClient(t, srv, "test1",
		servertest.WithUser(user))
	c2 := servertest.NewClient(t, srv, "test2",
		servertest.WithUser(user))

	c1.WaitForPeers(t, 1, 10*time.Second)
	c2.WaitForPeers(t, 1, 10*time.Second)

	// PacketFilter is an INBOUND filter: test2 (the destination) should
	// have the rule allowing traffic FROM test1's IPv6.
	nm2 := c2.Netmap()
	require.NotNil(t, nm2)
	require.NotNil(t, nm2.PacketFilter,
		"c2 PacketFilter should not be nil with IPv6-only policy")

	// Verify that IPv6 destination is present in the filter rules on test2.
	var foundIPv6Dst bool

	expectedDst := netip.MustParseAddr("fd7a:115c:a1e0::2")

	for _, m := range nm2.PacketFilter {
		for _, dst := range m.Dsts {
			if dst.Net.Addr() == expectedDst {
				foundIPv6Dst = true
			}
		}
	}

	assert.True(t, foundIPv6Dst,
		"test2 PacketFilter should contain IPv6 destination fd7a:115c:a1e0::2 from IPv6-only host definition")

	// With the current resolve behavior, the filter should NOT contain
	// the corresponding IPv4 address as a destination, because
	// address-based aliases resolve to exactly the literal prefix.
	var foundIPv4Dst bool

	ipv4Dst := netip.MustParseAddr("100.64.0.2")

	for _, m := range nm2.PacketFilter {
		for _, dst := range m.Dsts {
			if dst.Net.Addr() == ipv4Dst {
				foundIPv4Dst = true
			}
		}
	}

	assert.False(t, foundIPv4Dst,
		"test2 PacketFilter should NOT contain IPv4 destination 100.64.0.2 when policy only specifies IPv6 hosts")
}
