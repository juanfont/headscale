package servertest_test

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// TestRace contains tests designed to trigger race conditions in
// the control plane. Run with -race to detect data races.
// These tests stress concurrent access patterns in poll.go,
// the batcher, the NodeStore, and the mapper.

// TestRacePollSessionReplacement tests the race between an old
// poll session's deferred cleanup and a new session starting.
func TestRacePollSessionReplacement(t *testing.T) {
	t.Parallel()

	// Rapidly replace the poll session by doing immediate
	// disconnect+reconnect. This races the old session's
	// deferred cleanup (RemoveNode, Disconnect, grace period
	// goroutine) with the new session's setup (AddNode, Connect,
	// initial map send).
	t.Run("immediate_session_replace_10x", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "sessrepl-user")

		c1 := servertest.NewClient(t, srv, "sessrepl-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "sessrepl-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		for range 10 {
			c1.Disconnect(t)
			// Reconnect immediately -- no sleep. This creates the
			// tightest possible race between old session cleanup
			// and new session setup.
			c1.Reconnect(t)
		}

		c1.WaitForPeers(t, 1, 15*time.Second)
		c2.WaitForPeers(t, 1, 15*time.Second)

		// Both clients should still have a consistent view.
		servertest.AssertMeshComplete(t,
			[]*servertest.TestClient{c1, c2})
	})

	// Two nodes rapidly reconnecting simultaneously.
	t.Run("two_nodes_reconnect_simultaneously", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "simrecon-user")

		c1 := servertest.NewClient(t, srv, "simrecon-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "simrecon-node2",
			servertest.WithUser(user))
		c3 := servertest.NewClient(t, srv, "simrecon-node3",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 2, 15*time.Second)

		for range 5 {
			// Both disconnect at the same time.
			c1.Disconnect(t)
			c2.Disconnect(t)

			// Both reconnect at the same time.
			c1.Reconnect(t)
			c2.Reconnect(t)
		}

		// Mesh should recover.
		c1.WaitForPeers(t, 2, 15*time.Second)
		c2.WaitForPeers(t, 2, 15*time.Second)
		c3.WaitForPeers(t, 2, 15*time.Second)

		servertest.AssertConsistentState(t,
			[]*servertest.TestClient{c1, c2, c3})
	})
}

// TestRaceConcurrentServerMutations tests concurrent mutations
// on the server side while nodes are connected and polling.
func TestRaceConcurrentServerMutations(t *testing.T) {
	t.Parallel()

	// Rename, route approval, and policy change all happening
	// concurrently while nodes are connected.
	t.Run("concurrent_rename_route_policy", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "conmut-user")

		c1 := servertest.NewClient(t, srv, "conmut-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "conmut-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		nodeID1 := findNodeID(t, srv, "conmut-node1")

		var wg sync.WaitGroup

		// Concurrent renames.

		wg.Go(func() {
			for i := range 5 {
				name := fmt.Sprintf("conmut-renamed-%d", i)
				srv.State().RenameNode(nodeID1, name) //nolint:errcheck
			}
		})

		// Concurrent route changes.

		wg.Go(func() {
			for i := range 5 {
				route := netip.MustParsePrefix(
					fmt.Sprintf("10.%d.0.0/24", i))
				_, c, _ := srv.State().SetApprovedRoutes(
					nodeID1, []netip.Prefix{route})
				srv.App.Change(c)
			}
		})

		// Concurrent policy changes.

		wg.Go(func() {
			for range 5 {
				changed, err := srv.State().SetPolicy([]byte(`{
					"acls": [
						{"action": "accept", "src": ["*"], "dst": ["*:*"]}
					]
				}`))
				if err == nil && changed {
					changes, err := srv.State().ReloadPolicy()
					if err == nil {
						srv.App.Change(changes...)
					}
				}
			}
		})

		wg.Wait()

		// Server should not have panicked, and clients should still
		// be getting updates.
		c2.WaitForCondition(t, "still receiving updates",
			10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm != nil && len(nm.Peers) > 0
			})
	})

	// Delete a node while simultaneously changing policy.
	t.Run("delete_during_policy_change", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "delpol-user")

		c1 := servertest.NewClient(t, srv, "delpol-node1",
			servertest.WithUser(user))
		servertest.NewClient(t, srv, "delpol-node2",
			servertest.WithUser(user))
		c3 := servertest.NewClient(t, srv, "delpol-node3",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 2, 15*time.Second)

		nodeID2 := findNodeID(t, srv, "delpol-node2")
		nv2, ok := srv.State().GetNodeByID(nodeID2)
		require.True(t, ok)

		var wg sync.WaitGroup

		// Delete node2 and change policy simultaneously.

		wg.Go(func() {
			delChange, err := srv.State().DeleteNode(nv2)
			if err == nil {
				srv.App.Change(delChange)
			}
		})

		wg.Go(func() {
			changed, err := srv.State().SetPolicy([]byte(`{
				"acls": [
					{"action": "accept", "src": ["*"], "dst": ["*:*"]}
				]
			}`))
			if err == nil && changed {
				changes, err := srv.State().ReloadPolicy()
				if err == nil {
					srv.App.Change(changes...)
				}
			}
		})

		wg.Wait()

		// c1 and c3 should converge -- both should see each other
		// but not node2.
		c1.WaitForCondition(t, "node2 gone from c1", 10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == "delpol-node2" {
						return false
					}
				}

				return true
			})

		c3.WaitForCondition(t, "node2 gone from c3", 10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == "delpol-node2" {
						return false
					}
				}

				return true
			})
	})

	// Many clients sending hostinfo updates simultaneously.
	t.Run("concurrent_hostinfo_updates", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "chiupd-user")

		const n = 6

		clients := make([]*servertest.TestClient, n)
		for i := range n {
			clients[i] = servertest.NewClient(t, srv,
				fmt.Sprintf("chiupd-%d", i),
				servertest.WithUser(user))
		}

		for _, c := range clients {
			c.WaitForPeers(t, n-1, 20*time.Second)
		}

		// All clients update their hostinfo simultaneously.
		var wg sync.WaitGroup
		for i, c := range clients {
			wg.Go(func() {
				c.Direct().SetHostinfo(&tailcfg.Hostinfo{
					BackendLogID: fmt.Sprintf("servertest-chiupd-%d", i),
					Hostname:     fmt.Sprintf("chiupd-%d", i),
					OS:           fmt.Sprintf("ConcurrentOS-%d", i),
				})

				ctx, cancel := context.WithTimeout(
					context.Background(), 5*time.Second)
				defer cancel()

				_ = c.Direct().SendUpdate(ctx)
			})
		}

		wg.Wait()

		// Each client should eventually see all others' updated OS.
		for _, observer := range clients {
			observer.WaitForCondition(t, "all OS updates visible",
				15*time.Second,
				func(nm *netmap.NetworkMap) bool {
					seenOS := 0

					for _, p := range nm.Peers {
						hi := p.Hostinfo()
						if hi.Valid() && hi.OS() != "" &&
							len(hi.OS()) > 12 { // "ConcurrentOS-" prefix
							seenOS++
						}
					}
					// Should see n-1 peers with updated OS.
					return seenOS >= n-1
				})
		}
	})
}

// TestRaceConnectDuringGracePeriod tests connecting a new node
// while another node is in its grace period.
func TestRaceConnectDuringGracePeriod(t *testing.T) {
	t.Parallel()

	// A node disconnects, and during the 10-second grace period
	// a new node joins. The new node should see the disconnecting
	// node as a peer (it hasn't been removed yet).
	t.Run("new_node_during_grace_period", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "grace-user")

		c1 := servertest.NewClient(t, srv, "grace-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "grace-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		// Disconnect c1 -- starts grace period.
		c1.Disconnect(t)

		// Immediately add a new node while c1 is in grace period.
		c3 := servertest.NewClient(t, srv, "grace-node3",
			servertest.WithUser(user))

		// c3 should see c2 for sure. Whether it sees c1 depends on
		// whether c1's grace period has expired. Either way it should
		// not panic or hang.
		c3.WaitForPeers(t, 1, 15*time.Second)

		// c2 should see c3.
		c2.WaitForCondition(t, "c2 sees c3", 10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				_, found := c2.PeerByName("grace-node3")

				return found
			})
	})

	// Multiple nodes disconnect and new ones connect simultaneously,
	// creating a mixed grace-period race.
	t.Run("multi_disconnect_multi_connect_race", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "mixgrace-user")

		const n = 4

		originals := make([]*servertest.TestClient, n)
		for i := range n {
			originals[i] = servertest.NewClient(t, srv,
				fmt.Sprintf("mixgrace-orig-%d", i),
				servertest.WithUser(user))
		}

		for _, c := range originals {
			c.WaitForPeers(t, n-1, 20*time.Second)
		}

		// Disconnect half.
		for i := range n / 2 {
			originals[i].Disconnect(t)
		}

		// Add new nodes during grace period.
		replacements := make([]*servertest.TestClient, n/2)
		for i := range n / 2 {
			replacements[i] = servertest.NewClient(t, srv,
				fmt.Sprintf("mixgrace-new-%d", i),
				servertest.WithUser(user))
		}

		// The surviving originals + new nodes should form a mesh.
		surviving := originals[n/2:]
		allActive := append(surviving, replacements...)

		for _, c := range allActive {
			c.WaitForPeers(t, len(allActive)-1, 30*time.Second)
		}

		servertest.AssertConsistentState(t, allActive)
	})
}

// TestRaceBatcherContention tests race conditions in the batcher
// when many changes arrive simultaneously.
func TestRaceBatcherContention(t *testing.T) {
	t.Parallel()

	// Many nodes connecting at the same time generates many
	// concurrent Change() calls. The batcher must handle this
	// without dropping updates or panicking.
	t.Run("many_simultaneous_connects", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "batchcon-user")

		const n = 8

		clients := make([]*servertest.TestClient, n)

		// Create all clients as fast as possible.
		for i := range n {
			clients[i] = servertest.NewClient(t, srv,
				fmt.Sprintf("batchcon-%d", i),
				servertest.WithUser(user))
		}

		// All should converge.
		for _, c := range clients {
			c.WaitForPeers(t, n-1, 30*time.Second)
		}

		servertest.AssertMeshComplete(t, clients)
	})

	// Rapid connect + disconnect + connect of different nodes
	// generates interleaved AddNode/RemoveNode/AddNode in the
	// batcher.
	t.Run("interleaved_add_remove_add", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "intleave-user")

		observer := servertest.NewClient(t, srv, "intleave-obs",
			servertest.WithUser(user))
		observer.WaitForUpdate(t, 10*time.Second)

		// Rapidly create, disconnect, create nodes.
		for i := range 5 {
			c := servertest.NewClient(t, srv,
				fmt.Sprintf("intleave-temp-%d", i),
				servertest.WithUser(user))
			c.WaitForUpdate(t, 10*time.Second)
			c.Disconnect(t)
		}

		// Add a final persistent node.
		final := servertest.NewClient(t, srv, "intleave-final",
			servertest.WithUser(user))

		// Observer should see at least the final node.
		observer.WaitForCondition(t, "sees final node",
			15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				_, found := observer.PeerByName("intleave-final")

				return found
			})

		// Final should see observer.
		final.WaitForCondition(t, "sees observer",
			15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				_, found := final.PeerByName("intleave-obs")

				return found
			})
	})

	// Route changes and node connect happening at the same time.
	t.Run("route_change_during_connect", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "rtcon-user")

		c1 := servertest.NewClient(t, srv, "rtcon-node1",
			servertest.WithUser(user))
		c1.WaitForUpdate(t, 10*time.Second)

		nodeID1 := findNodeID(t, srv, "rtcon-node1")

		// Approve routes while c2 is connecting.
		var wg sync.WaitGroup

		wg.Go(func() {
			route := netip.MustParsePrefix("10.88.0.0/24")
			_, c, _ := srv.State().SetApprovedRoutes(
				nodeID1, []netip.Prefix{route})
			srv.App.Change(c)
		})

		wg.Add(1)

		var c2 *servertest.TestClient

		go func() {
			defer wg.Done()

			c2 = servertest.NewClient(t, srv, "rtcon-node2",
				servertest.WithUser(user))
		}()

		wg.Wait()

		// Both should converge.
		c1.WaitForPeers(t, 1, 10*time.Second)
		c2.WaitForPeers(t, 1, 10*time.Second)
	})
}

// TestRaceMapResponseDuringDisconnect tests what happens when a
// map response is being written while the session is being torn down.
func TestRaceMapResponseDuringDisconnect(t *testing.T) {
	t.Parallel()

	// Generate a lot of updates for a node, then disconnect it
	// while updates are still being delivered. The disconnect
	// should be clean -- no panics, no hangs.
	t.Run("disconnect_during_update_storm", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "updstorm-user")

		victim := servertest.NewClient(t, srv, "updstorm-victim",
			servertest.WithUser(user))
		victim.WaitForUpdate(t, 10*time.Second)

		// Create several nodes to generate connection updates.
		for i := range 5 {
			servertest.NewClient(t, srv,
				fmt.Sprintf("updstorm-gen-%d", i),
				servertest.WithUser(user))
		}

		// While updates are flying, disconnect the victim.
		victim.Disconnect(t)

		// No panic, no hang = success. The other nodes should
		// still be working.
		remaining := servertest.NewClient(t, srv, "updstorm-check",
			servertest.WithUser(user))
		remaining.WaitForPeers(t, 5, 15*time.Second)
	})

	// Send a hostinfo update and disconnect almost simultaneously.
	t.Run("hostinfo_update_then_immediate_disconnect", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "hidc-user")

		c1 := servertest.NewClient(t, srv, "hidc-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "hidc-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		// Fire a hostinfo update.
		c1.Direct().SetHostinfo(&tailcfg.Hostinfo{
			BackendLogID: "servertest-hidc-node1",
			Hostname:     "hidc-node1",
			OS:           "DisconnectOS",
		})

		ctx, cancel := context.WithTimeout(
			context.Background(), 5*time.Second)
		defer cancel()

		_ = c1.Direct().SendUpdate(ctx)

		// Immediately disconnect.
		c1.Disconnect(t)

		// c2 might or might not see the OS update, but it should
		// not panic or hang. Verify c2 is still functional.
		c2.WaitForCondition(t, "c2 still functional", 10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm != nil
			})
	})
}

// TestRaceNodeStoreContention tests concurrent access to the NodeStore.
func TestRaceNodeStoreContention(t *testing.T) {
	t.Parallel()

	// Many GetNodeByID calls while nodes are connecting and
	// disconnecting. This tests the NodeStore's read/write locking.
	t.Run("concurrent_reads_during_mutations", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "nsrace-user")

		const n = 4

		clients := make([]*servertest.TestClient, n)
		for i := range n {
			clients[i] = servertest.NewClient(t, srv,
				fmt.Sprintf("nsrace-%d", i),
				servertest.WithUser(user))
		}

		for _, c := range clients {
			c.WaitForPeers(t, n-1, 15*time.Second)
		}

		nodeIDs := make([]types.NodeID, n)
		for i := range n {
			nodeIDs[i] = findNodeID(t, srv,
				fmt.Sprintf("nsrace-%d", i))
		}

		// Concurrently: read nodes, disconnect/reconnect, read again.
		var wg sync.WaitGroup

		// Readers.
		for range 4 {
			wg.Go(func() {
				for range 100 {
					for _, id := range nodeIDs {
						nv, ok := srv.State().GetNodeByID(id)
						if ok {
							_ = nv.Hostname()
							_ = nv.IsOnline()
							_ = nv.ApprovedRoutes()
						}
					}
				}
			})
		}

		// Mutators: disconnect and reconnect nodes.
		for i := range 2 {
			wg.Go(func() {
				clients[i].Disconnect(t)
				clients[i].Reconnect(t)
			})
		}

		wg.Wait()

		// Everything should still be working.
		for i := 2; i < n; i++ {
			_, ok := srv.State().GetNodeByID(nodeIDs[i])
			assert.True(t, ok,
				"node %d should still be in NodeStore", i)
		}
	})

	// ListNodes while nodes are being added and removed.
	t.Run("list_nodes_during_churn", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "listrace-user")

		var wg sync.WaitGroup

		// Continuously list nodes.
		stop := make(chan struct{})

		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					nodes := srv.State().ListNodes()
					// Access each node to exercise read paths.
					for i := range nodes.Len() {
						n := nodes.At(i)
						_ = n.Hostname()
						_ = n.IPs()
					}
				}
			}
		})

		// Add and remove nodes.
		for i := range 5 {
			c := servertest.NewClient(t, srv,
				fmt.Sprintf("listrace-%d", i),
				servertest.WithUser(user))
			c.WaitForUpdate(t, 10*time.Second)

			if i%2 == 0 {
				c.Disconnect(t)
			}
		}

		close(stop)
		wg.Wait()
	})
}
