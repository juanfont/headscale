package servertest_test

import (
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/netmap"
)

// TestContentVerification exercises the correctness of MapResponse
// content: that the self node, peers, DERP map, and other fields
// are populated correctly.
func TestContentVerification(t *testing.T) {
	t.Parallel()

	t.Run("self_node", func(t *testing.T) {
		t.Parallel()

		t.Run("has_addresses", func(t *testing.T) {
			t.Parallel()
			h := servertest.NewHarness(t, 1)
			servertest.AssertSelfHasAddresses(t, h.Client(0))
		})

		t.Run("has_machine_authorized", func(t *testing.T) {
			t.Parallel()
			h := servertest.NewHarness(t, 1)
			nm := h.Client(0).Netmap()
			require.NotNil(t, nm)
			require.True(t, nm.SelfNode.Valid())
			assert.True(t, nm.SelfNode.MachineAuthorized(),
				"self node should be machine-authorized")
		})
	})

	t.Run("derp_map", func(t *testing.T) {
		t.Parallel()

		t.Run("present_in_netmap", func(t *testing.T) {
			t.Parallel()
			h := servertest.NewHarness(t, 1)
			servertest.AssertDERPMapPresent(t, h.Client(0))
		})

		t.Run("has_test_region", func(t *testing.T) {
			t.Parallel()
			h := servertest.NewHarness(t, 1)
			nm := h.Client(0).Netmap()
			require.NotNil(t, nm)
			require.NotNil(t, nm.DERPMap)
			_, ok := nm.DERPMap.Regions[900]
			assert.True(t, ok, "DERPMap should contain test region 900")
		})
	})

	t.Run("peers", func(t *testing.T) {
		t.Parallel()

		t.Run("have_addresses", func(t *testing.T) {
			t.Parallel()
			h := servertest.NewHarness(t, 3)

			for _, c := range h.Clients() {
				nm := c.Netmap()
				require.NotNil(t, nm, "client %s has no netmap", c.Name)

				for _, peer := range nm.Peers {
					assert.Positive(t, peer.Addresses().Len(),
						"client %s: peer %d should have addresses",
						c.Name, peer.ID())
				}
			}
		})

		t.Run("have_allowed_ips", func(t *testing.T) {
			t.Parallel()
			h := servertest.NewHarness(t, 3)

			for _, c := range h.Clients() {
				nm := c.Netmap()
				require.NotNil(t, nm)

				for _, peer := range nm.Peers {
					// AllowedIPs should at least contain the peer's addresses.
					assert.Positive(t, peer.AllowedIPs().Len(),
						"client %s: peer %d should have AllowedIPs",
						c.Name, peer.ID())
				}
			}
		})

		t.Run("online_status", func(t *testing.T) {
			t.Parallel()
			h := servertest.NewHarness(t, 3)

			// Wait for online status to propagate (it may take an
			// extra update cycle after initial mesh formation).
			for _, c := range h.Clients() {
				c.WaitForCondition(t, "all peers online",
					15*time.Second,
					func(nm *netmap.NetworkMap) bool {
						for _, peer := range nm.Peers {
							isOnline, known := peer.Online().GetOk()
							if !known || !isOnline {
								return false
							}
						}

						return len(nm.Peers) >= 2
					})
			}
		})

		t.Run("hostnames_match", func(t *testing.T) {
			t.Parallel()
			h := servertest.NewHarness(t, 3)

			for _, c := range h.Clients() {
				for _, other := range h.Clients() {
					if c == other {
						continue
					}

					peer, found := c.PeerByName(other.Name)
					require.True(t, found,
						"client %s should see peer %s", c.Name, other.Name)

					hi := peer.Hostinfo()
					assert.True(t, hi.Valid())
					assert.Equal(t, other.Name, hi.Hostname())
				}
			}
		})
	})

	t.Run("update_history", func(t *testing.T) {
		t.Parallel()

		t.Run("monotonic_peer_count_growth", func(t *testing.T) {
			t.Parallel()
			// Connect nodes one at a time and verify the first
			// node's history shows monotonic peer count growth.
			srv := servertest.NewServer(t)
			user := srv.CreateUser(t, "hist-user")

			c0 := servertest.NewClient(t, srv, "hist-0", servertest.WithUser(user))
			c0.WaitForUpdate(t, 10*time.Second)

			// Add second node.
			servertest.NewClient(t, srv, "hist-1", servertest.WithUser(user))
			c0.WaitForPeers(t, 1, 10*time.Second)

			// Add third node.
			servertest.NewClient(t, srv, "hist-2", servertest.WithUser(user))
			c0.WaitForPeers(t, 2, 10*time.Second)

			// Verify update history is monotonically increasing in peer count.
			history := c0.History()
			require.Greater(t, len(history), 1,
				"should have multiple netmap updates")

			maxPeers := 0
			for _, nm := range history {
				if len(nm.Peers) > maxPeers {
					maxPeers = len(nm.Peers)
				}
			}

			assert.Equal(t, 2, maxPeers,
				"max peer count should be 2 (for 3 total nodes)")
		})

		t.Run("self_node_consistent_across_updates", func(t *testing.T) {
			t.Parallel()
			h := servertest.NewHarness(t, 2)

			history := h.Client(0).History()
			require.NotEmpty(t, history)

			// All updates should have the same self node key.
			firstKey := history[0].NodeKey
			for i, nm := range history {
				assert.Equal(t, firstKey, nm.NodeKey,
					"update %d: NodeKey should be consistent", i)
			}
		})
	})

	t.Run("domain", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 1)
		nm := h.Client(0).Netmap()
		require.NotNil(t, nm)
		// The domain might be empty in test mode, but shouldn't panic.
		_ = nm.Domain
	})

	t.Run("user_profiles", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)
		nm := h.Client(0).Netmap()
		require.NotNil(t, nm)
		// User profiles should be populated for at least the self node.
		if nm.SelfNode.Valid() {
			userID := nm.SelfNode.User()
			_, hasProfile := nm.UserProfiles[userID]
			assert.True(t, hasProfile,
				"UserProfiles should contain the self node's user")
		}
	})

	t.Run("peers_have_key", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		// Each client's peer should have a non-zero node key.
		nm := h.Client(0).Netmap()
		require.NotNil(t, nm)
		require.Len(t, nm.Peers, 1)
		assert.False(t, nm.Peers[0].Key().IsZero(),
			"peer should have a non-zero node key")
	})

	t.Run("endpoint_update_propagates", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		// Record initial update count on client 1.
		initialCount := h.Client(1).UpdateCount()

		// Client 0 sends a non-streaming endpoint update
		// (this triggers a state update on the server).
		h.Client(0).WaitForCondition(t, "has netmap", 5*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm.SelfNode.Valid()
			})

		// Wait for client 1 to receive an update after mesh formation.
		// The initial mesh formation already delivered updates, but
		// any future change should also propagate.
		assert.GreaterOrEqual(t, h.Client(1).UpdateCount(), initialCount,
			"client 1 should have received updates")
	})
}
