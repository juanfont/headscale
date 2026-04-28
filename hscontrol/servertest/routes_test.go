package servertest_test

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// TestRoutes verifies that route advertisements and approvals
// propagate correctly through the control plane to all peers.
func TestRoutes(t *testing.T) {
	t.Parallel()

	t.Run("node_addresses_in_allowed_ips", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		// Each peer's AllowedIPs should contain the peer's addresses.
		for _, c := range h.Clients() {
			nm := c.Netmap()
			require.NotNil(t, nm)

			for _, peer := range nm.Peers {
				addrs := make(map[netip.Prefix]bool)
				for i := range peer.Addresses().Len() {
					addrs[peer.Addresses().At(i)] = true
				}

				for i := range peer.AllowedIPs().Len() {
					aip := peer.AllowedIPs().At(i)
					if addrs[aip] {
						delete(addrs, aip)
					}
				}

				assert.Empty(t, addrs,
					"client %s: peer %d AllowedIPs should contain all of Addresses",
					c.Name, peer.ID())
			}
		}
	})

	t.Run("advertised_routes_in_hostinfo", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "advroute-user")

		routePrefix := netip.MustParsePrefix("192.168.1.0/24")

		c1 := servertest.NewClient(t, srv, "advroute-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "advroute-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)

		// Update hostinfo with advertised routes.
		c1.Direct().SetHostinfo(&tailcfg.Hostinfo{
			BackendLogID: "servertest-advroute-node1",
			Hostname:     "advroute-node1",
			RoutableIPs:  []netip.Prefix{routePrefix},
		})

		// Send a non-streaming update to push the new hostinfo.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = c1.Direct().SendUpdate(ctx)

		// The observer should eventually see the advertised routes
		// in the peer's hostinfo.
		c2.WaitForCondition(t, "advertised route in hostinfo",
			15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == "advroute-node1" {
						for i := range hi.RoutableIPs().Len() {
							if hi.RoutableIPs().At(i) == routePrefix {
								return true
							}
						}
					}
				}

				return false
			})
	})

	t.Run("route_advertise_and_approve", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "fullrt-user")

		route := netip.MustParsePrefix("10.0.0.0/24")

		c1 := servertest.NewClient(t, srv, "fullrt-advertiser",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "fullrt-observer",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)
		c2.WaitForPeers(t, 1, 10*time.Second)

		// Step 1: Advertise the route by updating hostinfo.
		c1.Direct().SetHostinfo(&tailcfg.Hostinfo{
			BackendLogID: "servertest-fullrt-advertiser",
			Hostname:     "fullrt-advertiser",
			RoutableIPs:  []netip.Prefix{route},
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = c1.Direct().SendUpdate(ctx)

		// Wait for the server to process the hostinfo update
		// by waiting for observer to see the advertised route.
		c2.WaitForCondition(t, "hostinfo update propagated",
			10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == "fullrt-advertiser" {
						return hi.RoutableIPs().Len() > 0
					}
				}

				return false
			})

		// Step 2: Approve the route on the server.
		nodeID := findNodeID(t, srv, "fullrt-advertiser")

		_, routeChange, err := srv.State().SetApprovedRoutes(
			nodeID, []netip.Prefix{route})
		require.NoError(t, err)
		srv.App.Change(routeChange)

		// Step 3: Observer should see the route in AllowedIPs.
		c2.WaitForCondition(t, "approved route in AllowedIPs",
			15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == "fullrt-advertiser" {
						for i := range p.AllowedIPs().Len() {
							if p.AllowedIPs().At(i) == route {
								return true
							}
						}
					}
				}

				return false
			})
	})

	t.Run("allowed_ips_superset_of_addresses", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 3)

		for _, c := range h.Clients() {
			nm := c.Netmap()
			require.NotNil(t, nm)

			for _, peer := range nm.Peers {
				allowedSet := make(map[netip.Prefix]bool)
				for i := range peer.AllowedIPs().Len() {
					allowedSet[peer.AllowedIPs().At(i)] = true
				}

				for i := range peer.Addresses().Len() {
					addr := peer.Addresses().At(i)
					assert.True(t, allowedSet[addr],
						"client %s: peer %d Address %v should be in AllowedIPs",
						c.Name, peer.ID(), addr)
				}
			}
		}
	})

	t.Run("addresses_are_in_cgnat_range", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		cgnat := netip.MustParsePrefix("100.64.0.0/10")
		ula := netip.MustParsePrefix("fd7a:115c:a1e0::/48")

		for _, c := range h.Clients() {
			nm := c.Netmap()
			require.NotNil(t, nm)
			require.True(t, nm.SelfNode.Valid())

			for i := range nm.SelfNode.Addresses().Len() {
				addr := nm.SelfNode.Addresses().At(i)
				inCGNAT := cgnat.Contains(addr.Addr())
				inULA := ula.Contains(addr.Addr())
				assert.True(t, inCGNAT || inULA,
					"client %s: address %v should be in CGNAT or ULA range",
					c.Name, addr)
			}
		}
	})

	// Reproduces https://github.com/juanfont/headscale/issues/3203:
	// HA tracking loses the secondary subnet router after all routers serving
	// the route have been offline simultaneously and one of them returns.
	//
	// Two assertions split the failure surface:
	//   R1 — server-side primary route state restores after reconnect.
	//   R2 — observer's netmap shows the reconnected router online with
	//        the route in its primary set.
	// If R1 fails the bug is in state.Connect / primaryRoutes; if R1 passes
	// and R2 fails the bug is in change broadcast / mapBatcher.
	//
	// Caveat: servertest's Reconnect re-registers via TryLogin in addition
	// to starting a new poll session. Production reconnects after a brief
	// network outage may bypass re-registration. If this test passes on
	// main, fall back to the integration variant noted in the plan
	// (TestHASubnetRouterFailover with all routers offline simultaneously).
	t.Run("ha_secondary_recovers_after_all_offline", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "ha3203-user")

		route := netip.MustParsePrefix("10.0.0.0/24")

		r1 := servertest.NewClient(t, srv, "ha3203-router1",
			servertest.WithUser(user))
		r2 := servertest.NewClient(t, srv, "ha3203-router2",
			servertest.WithUser(user))
		obs := servertest.NewClient(t, srv, "ha3203-observer",
			servertest.WithUser(user))

		obs.WaitForPeers(t, 2, 10*time.Second)

		// Both routers advertise the same route via their hostinfo.
		advertise := func(c *servertest.TestClient, name string) {
			t.Helper()
			c.Direct().SetHostinfo(&tailcfg.Hostinfo{
				BackendLogID: "servertest-" + name,
				Hostname:     name,
				RoutableIPs:  []netip.Prefix{route},
			})

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_ = c.Direct().SendUpdate(ctx)
		}
		advertise(r1, "ha3203-router1")
		advertise(r2, "ha3203-router2")

		// Approve the route on both routers explicitly. Auto-approvers
		// would also work but introduce a policy dependency the harness
		// does not currently set up here.
		approve := func(name string) {
			t.Helper()
			id := findNodeID(t, srv, name)

			_, ch, err := srv.State().SetApprovedRoutes(id, []netip.Prefix{route})
			require.NoError(t, err)
			srv.App.Change(ch)
		}
		approve("ha3203-router1")
		approve("ha3203-router2")

		// Sanity: r1 starts as primary (lower NodeID by registration order).
		r1ID := findNodeID(t, srv, "ha3203-router1")
		r2ID := findNodeID(t, srv, "ha3203-router2")

		hasRoute := func(id types.NodeID) bool {
			return slices.Contains(srv.State().GetNodePrimaryRoutes(id), route)
		}

		assert.Eventually(t, func() bool { return hasRoute(r1ID) },
			10*time.Second, 100*time.Millisecond,
			"r1 should be primary initially")

		// 1. Take r1 offline. After the 10s grace period, r2 should take over.
		r1.Disconnect(t)
		assert.Eventually(t, func() bool { return hasRoute(r2ID) && !hasRoute(r1ID) },
			20*time.Second, 200*time.Millisecond,
			"r2 should take over as primary after r1 offline")

		// 2. Take r2 offline. With both routers gone, no primary should remain.
		r2.Disconnect(t)
		assert.Eventually(t, func() bool { return !hasRoute(r1ID) && !hasRoute(r2ID) },
			20*time.Second, 200*time.Millisecond,
			"no primary should be assigned while both routers are offline")

		// 3. Reconnect r2 (cable plugged back in).
		r2.Reconnect(t)

		// Hostinfo is part of the controlclient.Direct state; the Reconnect
		// helper re-registers via TryLogin which carries the same Hostinfo
		// that was set above. Push it again to be sure the announced route
		// is registered in the new session.
		advertise(r2, "ha3203-router2")

		// R1: server-side state must restore r2 as primary.
		assert.Eventually(t, func() bool { return hasRoute(r2ID) },
			15*time.Second, 200*time.Millisecond,
			"R1: r2 should be re-registered as primary after reconnect — issue #3203")

		// R2: observer must see r2 online with the route in its primary set.
		obs.WaitForCondition(t, "R2: observer sees r2 online with primary route",
			15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if !hi.Valid() || hi.Hostname() != "ha3203-router2" {
						continue
					}

					online, known := p.Online().GetOk()
					if !known || !online {
						return false
					}

					for i := range p.PrimaryRoutes().Len() {
						if p.PrimaryRoutes().At(i) == route {
							return true
						}
					}
				}

				return false
			})
	})
}

// findNodeID is defined in issues_test.go.
