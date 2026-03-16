package servertest_test

import (
	"sync"
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

	t.Run("concurrent_join_and_leave", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 5)

		var wg sync.WaitGroup

		// 3 nodes joining concurrently.
		for range 3 {
			wg.Go(func() {
				h.AddClient(t)
			})
		}

		// 2 nodes leaving concurrently.
		for i := range 2 {
			wg.Add(1)

			c := h.Client(i)

			go func() {
				defer wg.Done()

				c.Disconnect(t)
			}()
		}

		wg.Wait()

		// After all churn, connected clients should converge.
		servertest.EventuallyAssertMeshComplete(t, h.ConnectedClients(), 30*time.Second)
		servertest.AssertConsistentState(t, h.ConnectedClients())
	})
}
