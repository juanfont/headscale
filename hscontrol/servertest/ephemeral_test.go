package servertest_test

import (
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/netmap"
)

// TestEphemeralNodes tests the lifecycle of ephemeral nodes,
// which should be automatically cleaned up when they disconnect.
//
// TODO(kradalby): These tests wait for real-time grace periods and
// GC intervals (up to 60s). testing/synctest would allow instant
// fake-clock advancement, but three blockers prevent adoption
// as of Go 1.26:
//
//  1. zcache janitor goroutine: No Close() method; stopped only via
//     runtime.SetFinalizer which runs outside synctest bubbles.
//     - https://github.com/patrickmn/go-cache/issues/185
//     - https://github.com/golang/go/issues/75113 (Go1.27: finalizers inside bubble)
//
//  2. database/sql internal goroutines: Uses sync.RWMutex which is not
//     durably blocking in synctest, causing hangs.
//     - https://github.com/golang/go/issues/77687 (mutex as durably blocking)
//
//  3. net/http server goroutines: I/O-blocked goroutines are not durably
//     blocking, preventing bubble termination.
//     - https://github.com/golang/go/issues/76608 (httptest synctest support)
func TestEphemeralNodes(t *testing.T) {
	t.Parallel()

	t.Run("ephemeral_connects_and_sees_peers", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t,
			servertest.WithEphemeralTimeout(5*time.Second))
		user := srv.CreateUser(t, "eph-user")

		regular := servertest.NewClient(t, srv, "eph-regular",
			servertest.WithUser(user))
		ephemeral := servertest.NewClient(t, srv, "eph-ephemeral",
			servertest.WithUser(user), servertest.WithEphemeral())

		// Both should see each other.
		regular.WaitForPeers(t, 1, 10*time.Second)
		ephemeral.WaitForPeers(t, 1, 10*time.Second)

		_, found := regular.PeerByName("eph-ephemeral")
		assert.True(t, found, "regular should see ephemeral peer")

		_, found = ephemeral.PeerByName("eph-regular")
		assert.True(t, found, "ephemeral should see regular peer")
	})

	t.Run("ephemeral_cleanup_after_disconnect", func(t *testing.T) {
		t.Parallel()

		// Use a short ephemeral timeout so the test doesn't take long.
		srv := servertest.NewServer(t,
			servertest.WithEphemeralTimeout(3*time.Second))
		user := srv.CreateUser(t, "eph-cleanup-user")

		regular := servertest.NewClient(t, srv, "eph-cleanup-regular",
			servertest.WithUser(user))
		ephemeral := servertest.NewClient(t, srv, "eph-cleanup-ephemeral",
			servertest.WithUser(user), servertest.WithEphemeral())

		regular.WaitForPeers(t, 1, 10*time.Second)

		// Verify ephemeral peer is present before disconnect.
		_, found := regular.PeerByName("eph-cleanup-ephemeral")
		require.True(t, found, "ephemeral peer should be visible before disconnect")

		// Ensure the ephemeral node's long-poll session is fully
		// established on the server before disconnecting. Without
		// this, the Disconnect may cancel a PollNetMap that hasn't
		// yet reached serveLongPoll, so no grace period or ephemeral
		// GC would ever be scheduled.
		ephemeral.WaitForPeers(t, 1, 10*time.Second)

		// Disconnect the ephemeral node.
		ephemeral.Disconnect(t)

		// After the grace period (10s) + ephemeral timeout (3s),
		// the ephemeral node should be deleted from the server and
		// disappear from the regular node's peer list entirely.
		// Unlike non-ephemeral nodes which go offline but stay in
		// the peer list, ephemeral nodes should be garbage collected.
		regular.WaitForCondition(t, "ephemeral peer removed from peer list",
			60*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == "eph-cleanup-ephemeral" {
						return false // still present
					}
				}

				return true // gone
			})
	})

	t.Run("ephemeral_and_regular_mixed", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t,
			servertest.WithEphemeralTimeout(5*time.Second))
		user := srv.CreateUser(t, "mix-user")

		r1 := servertest.NewClient(t, srv, "mix-regular-1",
			servertest.WithUser(user))
		r2 := servertest.NewClient(t, srv, "mix-regular-2",
			servertest.WithUser(user))
		e1 := servertest.NewClient(t, srv, "mix-eph-1",
			servertest.WithUser(user), servertest.WithEphemeral())

		// All three should see each other.
		r1.WaitForPeers(t, 2, 15*time.Second)
		r2.WaitForPeers(t, 2, 15*time.Second)
		e1.WaitForPeers(t, 2, 15*time.Second)

		servertest.AssertMeshComplete(t,
			[]*servertest.TestClient{r1, r2, e1})
	})

	t.Run("ephemeral_reconnect_prevents_cleanup", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t,
			servertest.WithEphemeralTimeout(5*time.Second))
		user := srv.CreateUser(t, "eph-recon-user")

		regular := servertest.NewClient(t, srv, "eph-recon-regular",
			servertest.WithUser(user))
		ephemeral := servertest.NewClient(t, srv, "eph-recon-ephemeral",
			servertest.WithUser(user), servertest.WithEphemeral())

		regular.WaitForPeers(t, 1, 10*time.Second)

		// Ensure the ephemeral node's long-poll is established.
		ephemeral.WaitForPeers(t, 1, 10*time.Second)

		// Disconnect and quickly reconnect.
		ephemeral.Disconnect(t)
		ephemeral.Reconnect(t)

		// After reconnecting, the ephemeral node should still be visible.
		regular.WaitForPeers(t, 1, 15*time.Second)

		_, found := regular.PeerByName("eph-recon-ephemeral")
		assert.True(t, found,
			"ephemeral node should still be visible after quick reconnect")
	})
}
