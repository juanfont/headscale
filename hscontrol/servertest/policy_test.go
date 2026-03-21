package servertest_test

import (
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
