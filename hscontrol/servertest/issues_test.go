package servertest_test

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// These tests are intentionally strict about expected behavior.
// Failures surface real issues in the control plane.

// TestIssuesMapContent tests issues with MapResponse content correctness.
func TestIssuesMapContent(t *testing.T) {
	t.Parallel()

	// After mesh formation, all peers should have a known Online status.
	// The Online field is set when Connect() sends a NodeOnline PeerChange
	// patch. The initial MapResponse (from auth handler) may have Online=nil
	// because Connect() hasn't run yet, so we wait for the status to propagate.
	t.Run("initial_map_should_include_peer_online_status", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 3)

		for _, c := range h.Clients() {
			c.WaitForCondition(t, "all peers have known Online status",
				10*time.Second,
				func(nm *netmap.NetworkMap) bool {
					if len(nm.Peers) < 2 {
						return false
					}

					for _, peer := range nm.Peers {
						if _, known := peer.Online().GetOk(); !known {
							return false
						}
					}

					return true
				})
		}
	})

	// DiscoPublicKey set by the client should be visible to peers.
	t.Run("disco_key_should_propagate_to_peers", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		// The DiscoKey is sent in the first MapRequest (not the RegisterRequest),
		// so it may take an extra map update to propagate to peers. Wait for
		// the condition rather than checking the initial netmap.
		h.Client(0).WaitForCondition(t, "peer has non-zero DiscoKey",
			10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				if len(nm.Peers) < 1 {
					return false
				}

				return !nm.Peers[0].DiscoKey().IsZero()
			})
	})

	// All peers should reference a valid DERP region.
	t.Run("peers_have_valid_derp_region", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 3)

		for _, c := range h.Clients() {
			nm := c.Netmap()
			require.NotNil(t, nm)
			require.NotNil(t, nm.DERPMap)

			for _, peer := range nm.Peers {
				derpRegion := peer.HomeDERP()

				if derpRegion != 0 {
					_, regionExists := nm.DERPMap.Regions[derpRegion]
					assert.True(t, regionExists,
						"client %s: peer %d has HomeDERP=%d which is not in DERPMap",
						c.Name, peer.ID(), derpRegion)
				}
			}
		}
	})

	// Each peer should have a valid user profile in the netmap.
	t.Run("all_peers_have_user_profiles", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user1 := srv.CreateUser(t, "profile-user1")
		user2 := srv.CreateUser(t, "profile-user2")

		c1 := servertest.NewClient(t, srv, "profile-node1",
			servertest.WithUser(user1))
		c2 := servertest.NewClient(t, srv, "profile-node2",
			servertest.WithUser(user2))

		c1.WaitForPeers(t, 1, 10*time.Second)
		c2.WaitForPeers(t, 1, 10*time.Second)

		nm := c1.Netmap()
		require.NotNil(t, nm)

		selfUserID := nm.SelfNode.User()
		selfProfile, hasSelf := nm.UserProfiles[selfUserID]
		assert.True(t, hasSelf, "should have self user profile")

		if hasSelf {
			assert.NotEmpty(t, selfProfile.DisplayName(),
				"self user profile should have a display name")
		}

		require.Len(t, nm.Peers, 1)
		peerUserID := nm.Peers[0].User()

		peerProfile, hasPeer := nm.UserProfiles[peerUserID]
		assert.True(t, hasPeer,
			"should have peer's user profile (user %d)", peerUserID)

		if hasPeer {
			assert.NotEmpty(t, peerProfile.DisplayName(),
				"peer user profile should have a display name")
		}
	})
}

// TestIssuesRoutes tests issues with route propagation.
func TestIssuesRoutes(t *testing.T) {
	t.Parallel()

	// Approving a route via API without the node announcing it must NOT
	// make the route visible in AllowedIPs. Tailscale uses a strict
	// advertise-then-approve model: routes are only distributed when the
	// node advertises them (Hostinfo.RoutableIPs) AND they are approved.
	// An approval without advertisement is a dormant pre-approval that
	// activates once the node starts advertising.
	t.Run("approved_route_without_announcement_not_distributed", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "noannounce-user")

		c1 := servertest.NewClient(t, srv, "noannounce-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "noannounce-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		nodeID := findNodeID(t, srv, "noannounce-node1")
		route := netip.MustParsePrefix("10.0.0.0/24")

		// The API should accept the approval without error — the route
		// is stored but dormant because the node is not advertising it.
		_, routeChange, err := srv.State().SetApprovedRoutes(
			nodeID, []netip.Prefix{route})
		require.NoError(t, err)
		srv.App.Change(routeChange)

		// Wait for any updates triggered by the route change to propagate,
		// then verify the route does NOT appear in AllowedIPs.
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()

		<-timer.C

		nm := c2.Netmap()
		require.NotNil(t, nm)

		for _, p := range nm.Peers {
			hi := p.Hostinfo()
			if hi.Valid() && hi.Hostname() == "noannounce-node1" {
				for i := range p.AllowedIPs().Len() {
					assert.NotEqual(t, route, p.AllowedIPs().At(i),
						"approved-but-not-announced route should not appear in AllowedIPs")
				}
			}
		}
	})

	// When the server approves routes for a node, that node
	// should receive a self-update reflecting the change.
	t.Run("self_update_after_route_approval", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "selfup-user")

		c1 := servertest.NewClient(t, srv, "selfup-node1",
			servertest.WithUser(user))
		servertest.NewClient(t, srv, "selfup-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		nodeID := findNodeID(t, srv, "selfup-node1")
		route := netip.MustParsePrefix("10.77.0.0/24")

		countBefore := c1.UpdateCount()

		_, routeChange, err := srv.State().SetApprovedRoutes(
			nodeID, []netip.Prefix{route})
		require.NoError(t, err)
		srv.App.Change(routeChange)

		c1.WaitForCondition(t, "self-update after route approval",
			10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return c1.UpdateCount() > countBefore
			})
	})

	// Hostinfo route advertisement should be stored on server.
	t.Run("hostinfo_route_advertisement_stored_on_server", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "histore-user")

		c1 := servertest.NewClient(t, srv, "histore-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "histore-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		route := netip.MustParsePrefix("10.99.0.0/24")

		c1.Direct().SetHostinfo(&tailcfg.Hostinfo{
			BackendLogID: "servertest-histore-node1",
			Hostname:     "histore-node1",
			RoutableIPs:  []netip.Prefix{route},
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = c1.Direct().SendUpdate(ctx)

		c2.WaitForCondition(t, "route in peer hostinfo", 10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == "histore-node1" {
						return hi.RoutableIPs().Len() > 0
					}
				}

				return false
			})

		nodeID := findNodeID(t, srv, "histore-node1")
		nv, ok := srv.State().GetNodeByID(nodeID)
		require.True(t, ok, "node should exist in server state")

		announced := nv.AnnouncedRoutes()
		assert.Contains(t, announced, route,
			"server should store the advertised route as announced")
	})
}

// TestIssuesIPAllocation tests IP address allocation correctness.
func TestIssuesIPAllocation(t *testing.T) {
	t.Parallel()

	// Every node should get unique IPs.
	t.Run("ip_addresses_are_unique_across_nodes", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "ipuniq-user")

		const n = 10

		clients := make([]*servertest.TestClient, n)
		for i := range n {
			clients[i] = servertest.NewClient(t, srv,
				fmt.Sprintf("ipuniq-%d", i),
				servertest.WithUser(user))
		}

		for _, c := range clients {
			c.WaitForUpdate(t, 15*time.Second)
		}

		seen := make(map[netip.Prefix]string)

		for _, c := range clients {
			nm := c.Netmap()
			require.NotNil(t, nm)
			require.True(t, nm.SelfNode.Valid())

			for i := range nm.SelfNode.Addresses().Len() {
				addr := nm.SelfNode.Addresses().At(i)
				if other, exists := seen[addr]; exists {
					t.Errorf("IP collision: %v assigned to both %s and %s",
						addr, other, c.Name)
				}

				seen[addr] = c.Name
			}
		}
	})

	// After reconnect, IP addresses should be stable.
	t.Run("reconnect_preserves_ip_addresses", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		nm := h.Client(0).Netmap()
		require.NotNil(t, nm)
		require.True(t, nm.SelfNode.Valid())

		addrsBefore := make([]netip.Prefix, 0, nm.SelfNode.Addresses().Len())
		for i := range nm.SelfNode.Addresses().Len() {
			addrsBefore = append(addrsBefore, nm.SelfNode.Addresses().At(i))
		}

		require.NotEmpty(t, addrsBefore)

		h.Client(0).Disconnect(t)
		h.Client(0).Reconnect(t)
		h.Client(0).WaitForPeers(t, 1, 15*time.Second)

		nmAfter := h.Client(0).Netmap()
		require.NotNil(t, nmAfter)
		require.True(t, nmAfter.SelfNode.Valid())

		addrsAfter := make([]netip.Prefix, 0, nmAfter.SelfNode.Addresses().Len())
		for i := range nmAfter.SelfNode.Addresses().Len() {
			addrsAfter = append(addrsAfter, nmAfter.SelfNode.Addresses().At(i))
		}

		assert.Equal(t, addrsBefore, addrsAfter,
			"IP addresses should be stable across reconnect")
	})

	// New peers should have addresses immediately.
	t.Run("new_peer_has_addresses_immediately", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "newaddr-user")

		c1 := servertest.NewClient(t, srv, "newaddr-node1",
			servertest.WithUser(user))
		c1.WaitForUpdate(t, 10*time.Second)

		servertest.NewClient(t, srv, "newaddr-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		nm := c1.Netmap()
		require.NotNil(t, nm)
		require.Len(t, nm.Peers, 1)

		assert.Positive(t, nm.Peers[0].Addresses().Len(),
			"new peer should have addresses in the first update that includes it")
	})
}

// TestIssuesServerMutations tests that server-side mutations propagate correctly.
func TestIssuesServerMutations(t *testing.T) {
	t.Parallel()

	// Renaming a node via API should propagate to peers.
	t.Run("node_rename_propagates_to_peers", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "rename-user")

		c1 := servertest.NewClient(t, srv, "rename-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "rename-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		nodeID := findNodeID(t, srv, "rename-node1")

		_, renameChange, err := srv.State().RenameNode(nodeID, "renamed-node1")
		require.NoError(t, err)
		srv.App.Change(renameChange)

		c2.WaitForCondition(t, "renamed peer visible", 10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					if p.Name() == "renamed-node1" {
						return true
					}
				}

				return false
			})
	})

	// Deleting a node via API should remove it from all peers.
	t.Run("node_delete_removes_from_all_peers", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "del-user")

		c1 := servertest.NewClient(t, srv, "del-node1",
			servertest.WithUser(user))
		servertest.NewClient(t, srv, "del-node2",
			servertest.WithUser(user))
		c3 := servertest.NewClient(t, srv, "del-node3",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 2, 15*time.Second)

		nodeID2 := findNodeID(t, srv, "del-node2")
		node2View, ok := srv.State().GetNodeByID(nodeID2)
		require.True(t, ok)

		deleteChange, err := srv.State().DeleteNode(node2View)
		require.NoError(t, err)
		srv.App.Change(deleteChange)

		c1.WaitForCondition(t, "deleted peer gone", 10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == "del-node2" {
						return false
					}
				}

				return true
			})

		c3.WaitForCondition(t, "deleted peer gone from c3", 10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == "del-node2" {
						return false
					}
				}

				return true
			})

		assert.Len(t, c1.Peers(), 1)
		assert.Len(t, c3.Peers(), 1)
	})

	// Hostinfo changes should propagate to peers.
	t.Run("hostinfo_changes_propagate_to_peers", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "hichange-user")

		c1 := servertest.NewClient(t, srv, "hichange-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "hichange-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		c1.Direct().SetHostinfo(&tailcfg.Hostinfo{
			BackendLogID: "servertest-hichange-node1",
			Hostname:     "hichange-node1",
			OS:           "TestOS",
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = c1.Direct().SendUpdate(ctx)

		c2.WaitForCondition(t, "OS change visible", 10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == "hichange-node1" {
						return hi.OS() == "TestOS"
					}
				}

				return false
			})
	})
}

// TestIssuesNodeStoreConsistency tests NodeStore + DB consistency.
func TestIssuesNodeStoreConsistency(t *testing.T) {
	t.Parallel()

	// NodeStore and DB should agree after mutations.
	t.Run("nodestore_db_consistency_after_operations", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "consist-user")

		c1 := servertest.NewClient(t, srv, "consist-node1",
			servertest.WithUser(user))
		servertest.NewClient(t, srv, "consist-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		nodeID1 := findNodeID(t, srv, "consist-node1")

		route := netip.MustParsePrefix("10.50.0.0/24")
		_, routeChange, err := srv.State().SetApprovedRoutes(
			nodeID1, []netip.Prefix{route})
		require.NoError(t, err)
		srv.App.Change(routeChange)

		nsView, ok := srv.State().GetNodeByID(nodeID1)
		require.True(t, ok, "node should be in NodeStore")

		dbNode, err := srv.State().DB().GetNodeByID(nodeID1)
		require.NoError(t, err, "node should be in database")

		nsRoutes := nsView.ApprovedRoutes().AsSlice()
		dbRoutes := dbNode.ApprovedRoutes

		assert.Equal(t, nsRoutes, dbRoutes,
			"NodeStore and DB should agree on approved routes")
	})

	// After rapid reconnect, NodeStore should reflect correct state.
	t.Run("nodestore_correct_after_rapid_reconnect", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "nsrecon-user")

		c1 := servertest.NewClient(t, srv, "nsrecon-node1",
			servertest.WithUser(user))
		servertest.NewClient(t, srv, "nsrecon-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		nodeID1 := findNodeID(t, srv, "nsrecon-node1")

		for range 5 {
			c1.Disconnect(t)
			c1.Reconnect(t)
		}

		c1.WaitForPeers(t, 1, 15*time.Second)

		nv, ok := srv.State().GetNodeByID(nodeID1)
		require.True(t, ok)

		isOnline, known := nv.IsOnline().GetOk()
		assert.True(t, known, "NodeStore should know online status after reconnect")
		assert.True(t, isOnline, "NodeStore should show node as online after reconnect")
	})
}

// TestIssuesGracePeriod tests the disconnect grace period behavior.
func TestIssuesGracePeriod(t *testing.T) {
	t.Parallel()

	// Offline status should arrive promptly after grace period.
	t.Run("offline_status_arrives_within_grace_period_plus_margin", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		peerName := h.Client(1).Name

		h.Client(0).WaitForCondition(t, "peer online", 15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == peerName {
						isOnline, known := p.Online().GetOk()

						return known && isOnline
					}
				}

				return false
			})

		disconnectTime := time.Now()

		h.Client(1).Disconnect(t)

		h.Client(0).WaitForCondition(t, "peer offline", 20*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == peerName {
						isOnline, known := p.Online().GetOk()

						return known && !isOnline
					}
				}

				return false
			})

		elapsed := time.Since(disconnectTime)
		t.Logf("offline status arrived after %v", elapsed)

		assert.Greater(t, elapsed, 8*time.Second,
			"offline status arrived too quickly -- grace period may not be working")
		assert.Less(t, elapsed, 20*time.Second,
			"offline status took too long -- propagation delay issue")
	})

	// Ephemeral nodes should be fully deleted.
	t.Run("ephemeral_node_deleted_not_just_offline", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t,
			servertest.WithEphemeralTimeout(3*time.Second))
		user := srv.CreateUser(t, "eph-del-user")

		regular := servertest.NewClient(t, srv, "eph-del-regular",
			servertest.WithUser(user))
		ephemeral := servertest.NewClient(t, srv, "eph-del-ephemeral",
			servertest.WithUser(user), servertest.WithEphemeral())

		regular.WaitForPeers(t, 1, 10*time.Second)

		_, found := regular.PeerByName("eph-del-ephemeral")
		require.True(t, found)

		// Ensure the ephemeral node's long-poll session is fully
		// established on the server before disconnecting. Without
		// this, the Disconnect may cancel a PollNetMap that hasn't
		// yet reached serveLongPoll, so no grace period or ephemeral
		// GC would ever be scheduled.
		ephemeral.WaitForPeers(t, 1, 10*time.Second)

		ephemeral.Disconnect(t)

		// Grace period (10s) + ephemeral GC timeout (3s) + propagation.
		// Use a generous timeout for CI environments under load.
		regular.WaitForCondition(t, "ephemeral peer removed", 60*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == "eph-del-ephemeral" {
						return false
					}
				}

				return true
			})

		nodes := srv.State().ListNodes()
		for i := range nodes.Len() {
			n := nodes.At(i)
			assert.NotEqual(t, "eph-del-ephemeral", n.Hostname(),
				"ephemeral node should be deleted from server state")
		}
	})
}

// TestIssuesScale tests behavior under scale and rapid changes.
func TestIssuesScale(t *testing.T) {
	t.Parallel()

	t.Run("simultaneous_connect_all_see_all", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "simul-user")

		const n = 10

		clients := make([]*servertest.TestClient, n)
		for i := range n {
			clients[i] = servertest.NewClient(t, srv,
				fmt.Sprintf("simul-node-%d", i),
				servertest.WithUser(user))
		}

		for _, c := range clients {
			c.WaitForPeers(t, n-1, 30*time.Second)
		}

		servertest.AssertMeshComplete(t, clients)
		servertest.AssertSymmetricVisibility(t, clients)
	})

	// Many rapid additions should all be delivered.
	t.Run("rapid_sequential_additions", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "rapid-user")

		c1 := servertest.NewClient(t, srv, "rapid-node1",
			servertest.WithUser(user))
		c1.WaitForUpdate(t, 10*time.Second)

		for i := range 5 {
			servertest.NewClient(t, srv,
				fmt.Sprintf("rapid-node-%d", i+2),
				servertest.WithUser(user))
		}

		c1.WaitForPeers(t, 5, 30*time.Second)
		assert.Len(t, c1.Peers(), 5)
	})

	// Reconnect should give a complete map.
	t.Run("reconnect_gets_complete_map", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 3)

		h.Client(0).Disconnect(t)
		h.Client(0).Reconnect(t)
		h.Client(0).WaitForPeers(t, 2, 15*time.Second)

		nm := h.Client(0).Netmap()
		require.NotNil(t, nm)
		assert.Len(t, nm.Peers, 2)
		assert.True(t, nm.SelfNode.Valid())
		assert.Positive(t, nm.SelfNode.Addresses().Len())
	})
}

// TestIssuesIdentity tests node identity and naming behavior.
func TestIssuesIdentity(t *testing.T) {
	t.Parallel()

	// Cross-user visibility with default policy.
	t.Run("cross_user_visibility_default_policy", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user1 := srv.CreateUser(t, "xuser1")
		user2 := srv.CreateUser(t, "xuser2")

		c1 := servertest.NewClient(t, srv, "xuser-node1",
			servertest.WithUser(user1))
		c2 := servertest.NewClient(t, srv, "xuser-node2",
			servertest.WithUser(user2))

		c1.WaitForPeers(t, 1, 10*time.Second)
		c2.WaitForPeers(t, 1, 10*time.Second)

		_, found := c1.PeerByName("xuser-node2")
		assert.True(t, found, "user1's node should see user2's node")

		_, found = c2.PeerByName("xuser-node1")
		assert.True(t, found, "user2's node should see user1's node")
	})

	// Multiple nodes same user should be distinct.
	t.Run("multiple_nodes_same_user_distinct", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "sameuser")

		c1 := servertest.NewClient(t, srv, "sameuser-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "sameuser-node2",
			servertest.WithUser(user))
		c3 := servertest.NewClient(t, srv, "sameuser-node3",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 2, 15*time.Second)
		c2.WaitForPeers(t, 2, 15*time.Second)
		c3.WaitForPeers(t, 2, 15*time.Second)

		nm1 := c1.Netmap()
		nm2 := c2.Netmap()
		nm3 := c3.Netmap()

		require.NotNil(t, nm1)
		require.NotNil(t, nm2)
		require.NotNil(t, nm3)

		ids := map[tailcfg.NodeID]string{
			nm1.SelfNode.ID(): c1.Name,
			nm2.SelfNode.ID(): c2.Name,
			nm3.SelfNode.ID(): c3.Name,
		}
		assert.Len(t, ids, 3,
			"three nodes with same user should have distinct node IDs")
	})

	// Same hostname should get unique GivenNames.
	t.Run("same_hostname_gets_unique_given_names", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "samename-user")

		c1 := servertest.NewClient(t, srv, "samename",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "samename",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)
		c2.WaitForPeers(t, 1, 10*time.Second)

		nm1 := c1.Netmap()
		nm2 := c2.Netmap()

		require.NotNil(t, nm1)
		require.NotNil(t, nm2)
		require.True(t, nm1.SelfNode.Valid())
		require.True(t, nm2.SelfNode.Valid())

		name1 := nm1.SelfNode.Name()
		name2 := nm2.SelfNode.Name()

		assert.NotEqual(t, name1, name2,
			"nodes with same hostname should get distinct Name (GivenName): %q vs %q",
			name1, name2)
	})

	// Policy change during connect should still converge.
	t.Run("policy_change_during_connect", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "polcon-user")

		c1 := servertest.NewClient(t, srv, "polcon-node1",
			servertest.WithUser(user))
		c1.WaitForUpdate(t, 10*time.Second)

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

		c2 := servertest.NewClient(t, srv, "polcon-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 15*time.Second)
		c2.WaitForPeers(t, 1, 15*time.Second)

		for _, c := range []*servertest.TestClient{c1, c2} {
			nm := c.Netmap()
			require.NotNil(t, nm)
			assert.NotNil(t, nm.PacketFilter,
				"client %s should have packet filter after policy change", c.Name)
		}
	})
}

func findNodeID(tb testing.TB, srv *servertest.TestServer, hostname string) types.NodeID {
	tb.Helper()

	nodes := srv.State().ListNodes()
	for i := range nodes.Len() {
		n := nodes.At(i)
		if n.Hostname() == hostname {
			return n.ID()
		}
	}

	tb.Fatalf("node %q not found in server state", hostname)

	return 0
}
