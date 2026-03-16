package servertest_test

import (
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
)

// TestConsistency verifies that all nodes converge to the same
// view of the network and that no updates are lost during various
// operations.
func TestConsistency(t *testing.T) {
	t.Parallel()

	t.Run("all_nodes_converge", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 5)
		servertest.AssertMeshComplete(t, h.Clients())
		servertest.AssertConsistentState(t, h.Clients())
		servertest.AssertSymmetricVisibility(t, h.Clients())
	})

	t.Run("self_node_has_correct_hostname", func(t *testing.T) {
		t.Parallel()

		h := servertest.NewHarness(t, 3)
		for _, c := range h.Clients() {
			assert.Equal(t, c.Name, c.SelfName(),
				"client %s self name should match", c.Name)
		}
	})

	t.Run("update_count_positive", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 3)
		// After mesh formation, each client should have received
		// at least one update.
		for _, c := range h.Clients() {
			assert.Positive(t, c.UpdateCount(),
				"client %s should have received at least one update", c.Name)
		}
	})

	t.Run("new_node_visible_to_all", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 3)

		newClient := h.AddClient(t)
		h.WaitForMeshComplete(t, 10*time.Second)

		// Verify every original client sees the new node.
		for _, c := range h.Clients() {
			if c == newClient {
				continue
			}

			_, found := c.PeerByName(newClient.Name)
			assert.True(t, found,
				"client %s should see new client %s", c.Name, newClient.Name)
		}

		// And the new node sees all others.
		for _, c := range h.Clients() {
			if c == newClient {
				continue
			}

			_, found := newClient.PeerByName(c.Name)
			assert.True(t, found,
				"new client %s should see %s", newClient.Name, c.Name)
		}
	})

	t.Run("interleaved_join_and_leave", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 5)

		// Disconnect 2 nodes.
		h.Client(0).Disconnect(t)
		h.Client(1).Disconnect(t)

		// Add 3 new nodes while 2 are disconnected.
		c5 := h.AddClient(t)
		c6 := h.AddClient(t)
		c7 := h.AddClient(t)

		// Wait for new nodes to see at least all other connected
		// clients (they may also see the disconnected nodes during
		// the grace period, so we check >= not ==).
		connected := h.ConnectedClients()
		minPeers := len(connected) - 1

		for _, c := range connected {
			c.WaitForPeers(t, minPeers, 30*time.Second)
		}

		// Verify the new nodes can see each other.
		for _, a := range []*servertest.TestClient{c5, c6, c7} {
			for _, b := range []*servertest.TestClient{c5, c6, c7} {
				if a == b {
					continue
				}

				_, found := a.PeerByName(b.Name)
				assert.True(t, found,
					"new client %s should see %s", a.Name, b.Name)
			}
		}

		// Verify all connected clients see each other (consistent state).
		servertest.AssertConsistentState(t, connected)
	})
}
