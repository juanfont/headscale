package servertest_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
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

	t.Run("node_departs_peers_update", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 3)

		departingName := h.Client(2).Name
		h.Client(2).Disconnect(t)

		// The remaining clients should eventually stop seeing the
		// departed node (after the grace period).
		assert.Eventually(t, func() bool {
			_, found := h.Client(0).PeerByName(departingName)
			return !found
		}, 30*time.Second, 500*time.Millisecond,
			"client 0 should stop seeing departed node")
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
