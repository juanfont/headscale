package servertest_test

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/netmap"
)

// TestPollRace targets logical race conditions specifically in the
// poll.go session lifecycle and the batcher's handling of concurrent
// sessions for the same node.

func TestPollRace(t *testing.T) {
	t.Parallel()

	// The core race: when a node disconnects, poll.go starts a
	// grace period goroutine (10s ticker loop). If the node
	// reconnects during this period, the new session calls
	// Connect() to mark the node online. But the old grace period
	// goroutine is still running and may call Disconnect() AFTER
	// the new Connect(), setting IsOnline=false incorrectly.
	//
	// This test verifies the exact symptom: after reconnect within
	// the grace period, the server-side node state should be online.
	t.Run("server_state_online_after_reconnect_within_grace", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "gracerace-user")

		c1 := servertest.NewClient(t, srv, "gracerace-node1",
			servertest.WithUser(user))
		servertest.NewClient(t, srv, "gracerace-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		nodeID := findNodeID(t, srv, "gracerace-node1")

		// Disconnect and immediately reconnect.
		c1.Disconnect(t)
		c1.Reconnect(t)
		c1.WaitForPeers(t, 1, 15*time.Second)

		// Check server-side state immediately.
		nv, ok := srv.State().GetNodeByID(nodeID)
		require.True(t, ok)

		isOnline, known := nv.IsOnline().GetOk()
		assert.True(t, known,
			"server should know online status after reconnect")
		assert.True(t, isOnline,
			"server should show node as online after reconnect within grace period")
	})

	// Same test but wait a few seconds after reconnect. The old
	// grace period goroutine may still be running.
	t.Run("server_state_online_2s_after_reconnect", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "gracewait-user")

		c1 := servertest.NewClient(t, srv, "gracewait-node1",
			servertest.WithUser(user))
		servertest.NewClient(t, srv, "gracewait-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		nodeID := findNodeID(t, srv, "gracewait-node1")

		c1.Disconnect(t)
		c1.Reconnect(t)
		c1.WaitForPeers(t, 1, 15*time.Second)

		// Wait 2 seconds for the old grace period to potentially fire.
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()

		<-timer.C

		nv, ok := srv.State().GetNodeByID(nodeID)
		require.True(t, ok)

		isOnline, known := nv.IsOnline().GetOk()
		assert.True(t, known,
			"server should know online status 2s after reconnect")
		assert.True(t, isOnline,
			"server should STILL show node as online 2s after reconnect (grace period goroutine should not overwrite)")
	})

	// Wait the full grace period (10s) after reconnect. The old
	// grace period goroutine should have checked IsConnected
	// and found the node connected, so should NOT have called
	// Disconnect().
	t.Run("server_state_online_12s_after_reconnect", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "gracelong-user")

		c1 := servertest.NewClient(t, srv, "gracelong-node1",
			servertest.WithUser(user))
		servertest.NewClient(t, srv, "gracelong-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		nodeID := findNodeID(t, srv, "gracelong-node1")

		c1.Disconnect(t)
		c1.Reconnect(t)
		c1.WaitForPeers(t, 1, 15*time.Second)

		// Wait past the full grace period.
		timer := time.NewTimer(12 * time.Second)
		defer timer.Stop()

		<-timer.C

		nv, ok := srv.State().GetNodeByID(nodeID)
		require.True(t, ok)

		isOnline, known := nv.IsOnline().GetOk()
		assert.True(t, known,
			"server should know online status after grace period expires")
		assert.True(t, isOnline,
			"server should show node as online after grace period -- the reconnect should have prevented the Disconnect() call")
	})

	// Peer's view: after rapid reconnect, the peer should see
	// the reconnected node as online, not offline.
	t.Run("peer_sees_online_after_rapid_reconnect", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "peeronl-user")

		c1 := servertest.NewClient(t, srv, "peeronl-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "peeronl-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		// Wait for online status to propagate first.
		c2.WaitForCondition(t, "peer initially online",
			15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == "peeronl-node1" {
						isOnline, known := p.Online().GetOk()

						return known && isOnline
					}
				}

				return false
			})

		// Rapid reconnect.
		c1.Disconnect(t)
		c1.Reconnect(t)
		c1.WaitForPeers(t, 1, 15*time.Second)

		// Wait 3 seconds for any stale updates to propagate.
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()

		<-timer.C

		// At this point, c2 should see c1 as ONLINE.
		// If the grace period race is present, c2 might
		// temporarily see offline and then online again.
		nm := c2.Netmap()
		require.NotNil(t, nm)

		for _, p := range nm.Peers {
			hi := p.Hostinfo()
			if hi.Valid() && hi.Hostname() == "peeronl-node1" {
				isOnline, known := p.Online().GetOk()
				assert.True(t, known,
					"peer online status should be known")
				assert.True(t, isOnline,
					"peer should be online 3s after rapid reconnect")
			}
		}
	})

	// The batcher's IsConnected check: when the grace period
	// goroutine calls IsConnected(), it should return true if
	// a new session has been added for the same node.
	t.Run("batcher_knows_reconnected_during_grace", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "batchknow-user")

		c1 := servertest.NewClient(t, srv, "batchknow-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "batchknow-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)
		c2.WaitForPeers(t, 1, 10*time.Second)

		// Disconnect and reconnect.
		c1.Disconnect(t)
		c1.Reconnect(t)
		c1.WaitForPeers(t, 1, 15*time.Second)

		// The mesh should be complete with both nodes seeing
		// each other as online.
		c2.WaitForCondition(t, "c1 online after reconnect",
			15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == "batchknow-node1" {
						isOnline, known := p.Online().GetOk()

						return known && isOnline
					}
				}

				return false
			})
	})

	// Test that the update history shows a clean transition:
	// the peer should never appear in the history with
	// online=false if the reconnect was fast enough.
	t.Run("update_history_no_false_offline", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "histroff-user")

		c1 := servertest.NewClient(t, srv, "histroff-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "histroff-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)
		c2.WaitForPeers(t, 1, 10*time.Second)

		// Record c2's update count before reconnect.
		countBefore := c2.UpdateCount()

		// Rapid reconnect.
		c1.Disconnect(t)
		c1.Reconnect(t)
		c1.WaitForPeers(t, 1, 15*time.Second)

		// Wait a moment for all updates to arrive.
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()

		<-timer.C

		// Check c2's update history for any false offline.
		history := c2.History()
		sawOffline := false

		for i := countBefore; i < len(history); i++ {
			nm := history[i]
			for _, p := range nm.Peers {
				hi := p.Hostinfo()
				if hi.Valid() && hi.Hostname() == "histroff-node1" {
					isOnline, known := p.Online().GetOk()
					if known && !isOnline {
						sawOffline = true

						t.Logf("update %d: saw peer offline (should not happen during rapid reconnect)", i)
					}
				}
			}
		}

		assert.False(t, sawOffline,
			"peer should never appear offline in update history during rapid reconnect")
	})

	// Multiple rapid reconnects should not cause the peer count
	// to be wrong. After N reconnects, the reconnecting node should
	// still see the right number of peers and vice versa.
	t.Run("peer_count_stable_after_many_reconnects", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "peercount-user")

		const n = 4

		clients := make([]*servertest.TestClient, n)
		for i := range n {
			clients[i] = servertest.NewClient(t, srv,
				fmt.Sprintf("peercount-%d", i),
				servertest.WithUser(user))
		}

		for _, c := range clients {
			c.WaitForPeers(t, n-1, 20*time.Second)
		}

		// Reconnect client 0 five times.
		for range 5 {
			clients[0].Disconnect(t)
			clients[0].Reconnect(t)
		}

		// All clients should still see n-1 peers.
		for _, c := range clients {
			c.WaitForPeers(t, n-1, 15*time.Second)
		}

		servertest.AssertMeshComplete(t, clients)
	})

	// Route approval during reconnect: approve a route while a
	// node is reconnecting. Both the reconnecting node and peers
	// should eventually see the correct state.
	t.Run("route_approval_during_reconnect", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "rtrecon-user")

		c1 := servertest.NewClient(t, srv, "rtrecon-node1",
			servertest.WithUser(user))
		servertest.NewClient(t, srv, "rtrecon-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		nodeID1 := findNodeID(t, srv, "rtrecon-node1")

		// Disconnect c1.
		c1.Disconnect(t)

		// While c1 is disconnected, approve a route for it.
		route := netip.MustParsePrefix("10.55.0.0/24")
		_, routeChange, err := srv.State().SetApprovedRoutes(
			nodeID1, []netip.Prefix{route})
		require.NoError(t, err)
		srv.App.Change(routeChange)

		// Reconnect c1.
		c1.Reconnect(t)
		c1.WaitForPeers(t, 1, 15*time.Second)

		// c1 should receive a self-update with the new route.
		c1.WaitForCondition(t, "self-update after route+reconnect",
			10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm != nil && nm.SelfNode.Valid()
			})

		// Verify server state is correct.
		nv, ok := srv.State().GetNodeByID(nodeID1)
		require.True(t, ok)

		routes := nv.ApprovedRoutes().AsSlice()
		assert.Contains(t, routes, route,
			"approved route should persist through reconnect")
	})
}
