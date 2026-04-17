package servertest_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
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
}

// findNodeID is defined in issues_test.go.
