package servertest_test

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// TestStress hammers the control plane with concurrent operations,
// rapid mutations, and edge cases to surface race conditions and
// consistency bugs.

// TestStressConnectDisconnect exercises rapid connect/disconnect
// patterns that stress the grace period, batcher, and NodeStore.
func TestStressConnectDisconnect(t *testing.T) {
	t.Parallel()

	// A node that disconnects and reconnects faster than the
	// grace period should never cause a second node to see
	// the first node as offline.
	t.Run("rapid_reconnect_peer_never_sees_offline", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		// Wait for both to be online.
		h.Client(0).WaitForCondition(t, "peer online", 15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					isOnline, known := p.Online().GetOk()
					if known && isOnline {
						return true
					}
				}

				return false
			})

		// Do 10 rapid reconnects and check that client 0 never
		// sees client 1 as offline during the process.
		sawOffline := false

		var offlineMu sync.Mutex

		// Monitor client 0's view of client 1 in the background.
		stopMonitor := make(chan struct{})
		monitorDone := make(chan struct{})

		go func() {
			defer close(monitorDone)

			for {
				select {
				case <-stopMonitor:
					return
				default:
				}

				nm := h.Client(0).Netmap()
				if nm == nil {
					continue
				}

				for _, p := range nm.Peers {
					isOnline, known := p.Online().GetOk()
					if known && !isOnline {
						offlineMu.Lock()
						sawOffline = true
						offlineMu.Unlock()
					}
				}
			}
		}()

		for range 10 {
			h.Client(1).Disconnect(t)
			h.Client(1).Reconnect(t)
		}

		// Give the monitor a moment to catch up, then stop it.
		h.Client(0).WaitForPeers(t, 1, 10*time.Second)
		close(stopMonitor)
		<-monitorDone

		offlineMu.Lock()
		defer offlineMu.Unlock()

		assert.False(t, sawOffline,
			"peer should never appear offline during rapid reconnect cycles")
	})

	// Delete a node while it has an active poll session. The poll
	// session should terminate cleanly and other peers should see
	// the node disappear.
	t.Run("delete_node_during_active_poll", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "delpoll-user")

		c1 := servertest.NewClient(t, srv, "delpoll-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "delpoll-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)
		c2.WaitForPeers(t, 1, 10*time.Second)

		// Delete c1 while it's actively polling.
		nodeID := findNodeID(t, srv, "delpoll-node1")
		nv, ok := srv.State().GetNodeByID(nodeID)
		require.True(t, ok)

		deleteChange, err := srv.State().DeleteNode(nv)
		require.NoError(t, err)
		srv.App.Change(deleteChange)

		// c2 should see c1 disappear.
		c2.WaitForCondition(t, "deleted node gone", 10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == "delpoll-node1" {
						return false
					}
				}

				return true
			})

		assert.Empty(t, c2.Peers(),
			"c2 should have no peers after c1 is deleted")
	})

	// Connect many nodes, then disconnect half simultaneously.
	// The remaining half should converge to see only each other.
	t.Run("disconnect_half_remaining_converge", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "halfdisc-user")

		const total = 6

		clients := make([]*servertest.TestClient, total)
		for i := range total {
			clients[i] = servertest.NewClient(t, srv,
				fmt.Sprintf("halfdisc-%d", i),
				servertest.WithUser(user))
		}

		// Wait for full mesh.
		for _, c := range clients {
			c.WaitForPeers(t, total-1, 30*time.Second)
		}

		// Disconnect the first half.
		for i := range total / 2 {
			clients[i].Disconnect(t)
		}

		// The remaining half should eventually converge.
		remaining := clients[total/2:]

		for _, c := range remaining {
			c.WaitForCondition(t, "remaining converge",
				30*time.Second,
				func(nm *netmap.NetworkMap) bool {
					// Should see at least the other remaining peers.
					onlinePeers := 0

					for _, p := range nm.Peers {
						isOnline, known := p.Online().GetOk()
						if known && isOnline {
							onlinePeers++
						}
					}
					// Remaining peers minus self = total/2 - 1
					return onlinePeers >= len(remaining)-1
				})
		}
	})
}

// TestStressStateMutations tests rapid server-side state changes.
func TestStressStateMutations(t *testing.T) {
	t.Parallel()

	// Rapidly approve and remove routes. The final state should
	// be consistent.
	t.Run("rapid_route_changes_final_state_correct", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "rapidrt-user")

		c1 := servertest.NewClient(t, srv, "rapidrt-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "rapidrt-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		nodeID := findNodeID(t, srv, "rapidrt-node1")

		// Rapidly change routes 10 times.
		for i := range 10 {
			route := netip.MustParsePrefix(
				fmt.Sprintf("10.%d.0.0/24", i))

			_, routeChange, err := srv.State().SetApprovedRoutes(
				nodeID, []netip.Prefix{route})
			require.NoError(t, err)
			srv.App.Change(routeChange)
		}

		// Final route should be 10.9.0.0/24.
		// Verify server state is correct.
		nv, ok := srv.State().GetNodeByID(nodeID)
		require.True(t, ok)

		finalRoutes := nv.ApprovedRoutes().AsSlice()
		expected := netip.MustParsePrefix("10.9.0.0/24")
		assert.Contains(t, finalRoutes, expected,
			"final approved routes should contain the last route set")
		assert.Len(t, finalRoutes, 1,
			"should have exactly 1 approved route (the last one set)")

		// c2 should eventually see the update.
		c2.WaitForCondition(t, "final route update received",
			10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return c2.UpdateCount() > 2
			})
	})

	// Rename a node multiple times rapidly. The final name should
	// be correct in the server state and visible to peers.
	t.Run("rapid_rename_final_state_correct", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "rapidname-user")

		c1 := servertest.NewClient(t, srv, "rapidname-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "rapidname-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		nodeID := findNodeID(t, srv, "rapidname-node1")

		// Rename 5 times rapidly.
		var finalName string
		for i := range 5 {
			finalName = fmt.Sprintf("renamed-%d", i)

			_, renameChange, err := srv.State().RenameNode(nodeID, finalName)
			require.NoError(t, err)
			srv.App.Change(renameChange)
		}

		// Server state should have the final name.
		nv, ok := srv.State().GetNodeByID(nodeID)
		require.True(t, ok)
		assert.Equal(t, finalName, nv.AsStruct().GivenName,
			"server should have the final renamed value")

		// c2 should see the final name.
		c2.WaitForCondition(t, "final name visible", 10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					if p.Name() == finalName {
						return true
					}
				}

				return false
			})
	})

	// Multiple policy changes in rapid succession. The final
	// policy should be applied correctly.
	t.Run("rapid_policy_changes", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "rapidpol-user")

		c1 := servertest.NewClient(t, srv, "rapidpol-node1",
			servertest.WithUser(user))
		c1.WaitForUpdate(t, 10*time.Second)

		countBefore := c1.UpdateCount()

		// Change policy 5 times rapidly.
		for range 5 {
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
		}

		// Client should have received at least some updates.
		c1.WaitForCondition(t, "updates after policy changes",
			10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return c1.UpdateCount() > countBefore
			})
	})
}

// TestStressDataIntegrity verifies data correctness under various conditions.
func TestStressDataIntegrity(t *testing.T) {
	t.Parallel()

	// Every node's self-addresses should match what peers see
	// as that node's Addresses.
	t.Run("self_addresses_match_peer_view", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "addrmatch-user")

		const n = 5

		clients := make([]*servertest.TestClient, n)
		for i := range n {
			clients[i] = servertest.NewClient(t, srv,
				fmt.Sprintf("addrmatch-%d", i),
				servertest.WithUser(user))
		}

		for _, c := range clients {
			c.WaitForPeers(t, n-1, 20*time.Second)
		}

		// Build a map of hostname -> self-addresses.
		selfAddrs := make(map[string][]netip.Prefix)

		for _, c := range clients {
			nm := c.Netmap()
			require.NotNil(t, nm)
			require.True(t, nm.SelfNode.Valid())

			addrs := make([]netip.Prefix, 0, nm.SelfNode.Addresses().Len())
			for i := range nm.SelfNode.Addresses().Len() {
				addrs = append(addrs, nm.SelfNode.Addresses().At(i))
			}

			selfAddrs[c.Name] = addrs
		}

		// Now verify each client's peers have the same addresses
		// as those peers' self-view.
		for _, c := range clients {
			nm := c.Netmap()
			require.NotNil(t, nm)

			for _, peer := range nm.Peers {
				hi := peer.Hostinfo()
				if !hi.Valid() {
					continue
				}

				peerName := hi.Hostname()

				expected, ok := selfAddrs[peerName]
				if !ok {
					continue
				}

				peerAddrs := make([]netip.Prefix, 0, peer.Addresses().Len())
				for i := range peer.Addresses().Len() {
					peerAddrs = append(peerAddrs, peer.Addresses().At(i))
				}

				assert.Equal(t, expected, peerAddrs,
					"client %s: peer %s addresses should match that peer's self-view",
					c.Name, peerName)
			}
		}
	})

	// After mesh formation, no peer should have Expired=true.
	t.Run("no_peers_expired_after_mesh_formation", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 3)

		for _, c := range h.Clients() {
			nm := c.Netmap()
			require.NotNil(t, nm)

			assert.False(t, nm.SelfNode.Expired(),
				"client %s: self should not be expired", c.Name)

			for _, peer := range nm.Peers {
				assert.False(t, peer.Expired(),
					"client %s: peer %d should not be expired",
					c.Name, peer.ID())
			}
		}
	})

	// Self node should always be machine-authorized.
	t.Run("self_always_machine_authorized", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		for _, c := range h.Clients() {
			nm := c.Netmap()
			require.NotNil(t, nm)
			assert.True(t, nm.SelfNode.MachineAuthorized(),
				"client %s: self should be machine-authorized", c.Name)
		}

		// After reconnect, should still be authorized.
		h.Client(0).Disconnect(t)
		h.Client(0).Reconnect(t)
		h.Client(0).WaitForPeers(t, 1, 10*time.Second)

		nm := h.Client(0).Netmap()
		require.NotNil(t, nm)
		assert.True(t, nm.SelfNode.MachineAuthorized(),
			"after reconnect: self should be machine-authorized")
	})

	// Node IDs in the server state should match what clients see.
	t.Run("node_ids_consistent_between_server_and_client", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "idcheck-user")

		c1 := servertest.NewClient(t, srv, "idcheck-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "idcheck-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)
		c2.WaitForPeers(t, 1, 10*time.Second)

		// Get server-side node IDs.
		serverID1 := findNodeID(t, srv, "idcheck-node1")
		serverID2 := findNodeID(t, srv, "idcheck-node2")

		// Get client-side node IDs.
		nm1 := c1.Netmap()
		nm2 := c2.Netmap()

		require.NotNil(t, nm1)
		require.NotNil(t, nm2)

		clientID1 := nm1.SelfNode.ID()
		clientID2 := nm2.SelfNode.ID()

		//nolint:gosec // G115: test-only, IDs won't overflow
		assert.Equal(t, int64(serverID1), int64(clientID1),
			"node 1: server ID should match client self ID")
		//nolint:gosec // G115: test-only, IDs won't overflow
		assert.Equal(t, int64(serverID2), int64(clientID2),
			"node 2: server ID should match client self ID")

		// c1's view of c2's ID should also match.
		require.Len(t, nm1.Peers, 1)
		//nolint:gosec // G115: test-only, IDs won't overflow
		assert.Equal(t, int64(serverID2), int64(nm1.Peers[0].ID()),
			"c1's view of c2's ID should match server")
	})

	// After hostinfo update, ALL peers should see the updated
	// hostinfo, not just some.
	t.Run("hostinfo_update_reaches_all_peers", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "hiall-user")

		const n = 5

		clients := make([]*servertest.TestClient, n)
		for i := range n {
			clients[i] = servertest.NewClient(t, srv,
				fmt.Sprintf("hiall-%d", i),
				servertest.WithUser(user))
		}

		for _, c := range clients {
			c.WaitForPeers(t, n-1, 20*time.Second)
		}

		// Client 0 updates its OS.
		clients[0].Direct().SetHostinfo(&tailcfg.Hostinfo{
			BackendLogID: "servertest-hiall-0",
			Hostname:     "hiall-0",
			OS:           "StressTestOS",
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = clients[0].Direct().SendUpdate(ctx)

		// ALL other clients should see the updated OS.
		for i := 1; i < n; i++ {
			clients[i].WaitForCondition(t,
				fmt.Sprintf("client %d sees OS update", i),
				15*time.Second,
				func(nm *netmap.NetworkMap) bool {
					for _, p := range nm.Peers {
						hi := p.Hostinfo()
						if hi.Valid() && hi.Hostname() == "hiall-0" {
							return hi.OS() == "StressTestOS"
						}
					}

					return false
				})
		}
	})

	// MachineKey should be consistent: the server should track
	// the same machine key the client registered with.
	t.Run("machine_key_consistent", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "mkey-user")

		c1 := servertest.NewClient(t, srv, "mkey-node1",
			servertest.WithUser(user))
		c1.WaitForUpdate(t, 10*time.Second)

		nm := c1.Netmap()
		require.NotNil(t, nm)

		// The client's MachineKey in the netmap should be non-zero.
		assert.False(t, nm.MachineKey.IsZero(),
			"client's MachineKey should be non-zero")

		// Server should have the same key.
		nodeID := findNodeID(t, srv, "mkey-node1")
		nv, ok := srv.State().GetNodeByID(nodeID)
		require.True(t, ok)

		assert.Equal(t, nm.MachineKey.String(), nv.MachineKey().String(),
			"client and server should agree on MachineKey")
	})

	// NodeKey should be consistent between client and server.
	t.Run("node_key_consistent", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "nkey-user")

		c1 := servertest.NewClient(t, srv, "nkey-node1",
			servertest.WithUser(user))
		c1.WaitForUpdate(t, 10*time.Second)

		nm := c1.Netmap()
		require.NotNil(t, nm)

		assert.False(t, nm.NodeKey.IsZero(),
			"client's NodeKey should be non-zero")

		nodeID := findNodeID(t, srv, "nkey-node1")
		nv, ok := srv.State().GetNodeByID(nodeID)
		require.True(t, ok)

		assert.Equal(t, nm.NodeKey.String(), nv.NodeKey().String(),
			"client and server should agree on NodeKey")
	})
}

// TestStressChurn tests behavior under sustained connect/disconnect churn.
func TestStressChurn(t *testing.T) {
	t.Parallel()

	// Connect 10 nodes, then replace them all one by one.
	// Each replacement connects a new node and disconnects the old.
	// The remaining nodes should always see a consistent mesh.
	t.Run("rolling_replacement", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "rolling-user")

		const n = 5

		clients := make([]*servertest.TestClient, n)
		for i := range n {
			clients[i] = servertest.NewClient(t, srv,
				fmt.Sprintf("rolling-%d", i),
				servertest.WithUser(user))
		}

		for _, c := range clients {
			c.WaitForPeers(t, n-1, 20*time.Second)
		}

		// Replace each node one at a time.
		for i := range n {
			clients[i].Disconnect(t)
			clients[i] = servertest.NewClient(t, srv,
				fmt.Sprintf("rolling-new-%d", i),
				servertest.WithUser(user))
		}

		// Wait for the new set to converge.
		for _, c := range clients {
			c.WaitForPeers(t, n-1, 30*time.Second)
		}

		servertest.AssertSymmetricVisibility(t, clients)
	})

	// Add nodes one at a time and verify the mesh grows correctly
	// at each step.
	t.Run("incremental_mesh_growth", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "incr-user")

		clients := make([]*servertest.TestClient, 0, 8)

		for i := range 8 {
			c := servertest.NewClient(t, srv,
				fmt.Sprintf("incr-%d", i),
				servertest.WithUser(user))
			clients = append(clients, c)

			// After each addition, verify all existing clients see
			// the correct number of peers.
			expectedPeers := i // i-th node means i peers for existing nodes
			for _, existing := range clients {
				existing.WaitForPeers(t, expectedPeers, 15*time.Second)
			}
		}

		// Final check.
		servertest.AssertMeshComplete(t, clients)
	})

	// Connect/disconnect the same node many times. The server
	// should handle this without leaking state.
	t.Run("repeated_connect_disconnect_same_node", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "repeat-user")

		observer := servertest.NewClient(t, srv, "repeat-observer",
			servertest.WithUser(user))
		flapper := servertest.NewClient(t, srv, "repeat-flapper",
			servertest.WithUser(user))

		observer.WaitForPeers(t, 1, 10*time.Second)

		for i := range 10 {
			flapper.Disconnect(t)
			flapper.Reconnect(t)
			flapper.WaitForPeers(t, 1, 10*time.Second)

			if i%3 == 0 {
				t.Logf("cycle %d: flapper sees %d peers, observer sees %d peers",
					i, len(flapper.Peers()), len(observer.Peers()))
			}
		}

		// After all cycles, mesh should be healthy.
		observer.WaitForPeers(t, 1, 10*time.Second)

		_, found := observer.PeerByName("repeat-flapper")
		assert.True(t, found,
			"observer should still see flapper after 10 reconnect cycles")
	})

	// All nodes disconnect and reconnect simultaneously.
	t.Run("mass_reconnect", func(t *testing.T) {
		t.Parallel()

		sizes := []int{4, 6}
		for _, n := range sizes {
			t.Run(fmt.Sprintf("%d_nodes", n), func(t *testing.T) {
				t.Parallel()

				srv := servertest.NewServer(t)
				user := srv.CreateUser(t, "massrecon-user")

				clients := make([]*servertest.TestClient, n)
				for i := range n {
					clients[i] = servertest.NewClient(t, srv,
						fmt.Sprintf("massrecon-%d", i),
						servertest.WithUser(user))
				}

				for _, c := range clients {
					c.WaitForPeers(t, n-1, 20*time.Second)
				}

				// All disconnect.
				for _, c := range clients {
					c.Disconnect(t)
				}

				// All reconnect.
				for _, c := range clients {
					c.Reconnect(t)
				}

				// Should re-form mesh.
				for _, c := range clients {
					c.WaitForPeers(t, n-1, 30*time.Second)
				}

				servertest.AssertMeshComplete(t, clients)
				servertest.AssertConsistentState(t, clients)
			})
		}
	})
}
