package servertest_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
	"tailscale.com/types/netmap"
)

// TestConnectionLifecycle exercises the core node lifecycle:
// connecting, seeing peers, joining mid-session, departing, and
// reconnecting.
func TestConnectionLifecycle(t *testing.T) {
	t.Parallel()

	t.Run("single_node", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 1)
		nm := h.Client(0).Netmap()
		assert.NotNil(t, nm, "single node should receive a netmap")
		assert.Empty(t, nm.Peers, "single node should have no peers")
	})

	t.Run("new_node_joins_mesh", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 3)

		// Add a 4th client mid-test.
		h.AddClient(t)
		h.WaitForMeshComplete(t, 10*time.Second)
		servertest.AssertMeshComplete(t, h.Clients())
		servertest.AssertSymmetricVisibility(t, h.Clients())
	})

	t.Run("node_departs_peer_goes_offline", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 3)

		departingName := h.Client(2).Name

		// First verify the departing node is online (may need a moment
		// for Online status to propagate after mesh formation).
		h.Client(0).WaitForCondition(t, "peer initially online", 15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == departingName {
						isOnline, known := p.Online().GetOk()

						return known && isOnline
					}
				}

				return false
			})

		h.Client(2).Disconnect(t)

		// After the 10-second grace period, the remaining clients
		// should see the departed node as offline. The peer stays
		// in the peer list (non-ephemeral nodes are not removed).
		h.Client(0).WaitForCondition(t, "peer goes offline", 30*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == departingName {
						isOnline, known := p.Online().GetOk()

						return known && !isOnline
					}
				}

				return false
			})
	})

	t.Run("reconnect_restores_mesh", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		// Disconnect and reconnect.
		h.Client(0).Disconnect(t)
		h.Client(0).Reconnect(t)

		// Mesh should recover.
		h.WaitForMeshComplete(t, 15*time.Second)
		servertest.AssertMeshComplete(t, h.Clients())
	})

	t.Run("session_replacement", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		// Reconnect without explicitly waiting for the old session to
		// fully drain. This tests that Headscale correctly replaces
		// the old map session for the same node.
		h.Client(0).Reconnect(t)
		h.WaitForMeshComplete(t, 15*time.Second)
		servertest.AssertMeshComplete(t, h.Clients())
	})

	t.Run("multiple_nodes_join_sequentially", func(t *testing.T) {
		t.Parallel()

		sizes := []int{2, 5, 10}
		for _, n := range sizes {
			t.Run(fmt.Sprintf("%d_nodes", n), func(t *testing.T) {
				t.Parallel()
				h := servertest.NewHarness(t, n)
				servertest.AssertMeshComplete(t, h.Clients())
				servertest.AssertSymmetricVisibility(t, h.Clients())
			})
		}
	})
}
