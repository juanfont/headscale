package servertest_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// advertiseAndApproveRoute sets RoutableIPs on a client and approves
// the route on the server. Returns the node ID.
func advertiseAndApproveRoute(
	t *testing.T,
	srv *servertest.TestServer,
	c *servertest.TestClient,
	route netip.Prefix,
) types.NodeID {
	t.Helper()

	c.Direct().SetHostinfo(&tailcfg.Hostinfo{
		BackendLogID: "servertest-" + c.Name,
		Hostname:     c.Name,
		RoutableIPs:  []netip.Prefix{route},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = c.Direct().SendUpdate(ctx)

	nodeID := findNodeID(t, srv, c.Name)

	_, rc, err := srv.State().SetApprovedRoutes(nodeID, []netip.Prefix{route})
	require.NoError(t, err)
	srv.App.Change(rc)

	return nodeID
}

// TestHAHealthProbe_HealthyNodes verifies that the prober correctly
// pings HA nodes and they all respond healthy.
func TestHAHealthProbe_HealthyNodes(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "ha-healthy")

	route := netip.MustParsePrefix("10.50.0.0/24")

	c1 := servertest.NewClient(t, srv, "ha-router1", servertest.WithUser(user))
	c2 := servertest.NewClient(t, srv, "ha-router2", servertest.WithUser(user))

	c1.WaitForPeers(t, 1, 10*time.Second)
	c2.WaitForPeers(t, 1, 10*time.Second)

	nodeID1 := advertiseAndApproveRoute(t, srv, c1, route)
	advertiseAndApproveRoute(t, srv, c2, route)

	prober := state.NewHAHealthProber(
		srv.State(),
		types.HARouteConfig{
			ProbeInterval: 30 * time.Second,
			ProbeTimeout:  5 * time.Second,
		},
		srv.URL,
		srv.App.MapBatcher().IsConnected,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	prober.ProbeOnce(ctx, srv.App.Change)

	// Both nodes should be healthy, primary unchanged (node 1).
	assert.True(t, srv.State().IsNodeHealthy(nodeID1))

	primaries := srv.State().GetNodePrimaryRoutes(nodeID1)
	assert.Contains(t, primaries, route)
}

// TestHAHealthProbe_UnhealthyFailover verifies that marking a primary
// node unhealthy via the PrimaryRoutes API triggers failover to the
// standby.
func TestHAHealthProbe_UnhealthyFailover(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "ha-failover")

	route := netip.MustParsePrefix("10.60.0.0/24")

	c1 := servertest.NewClient(t, srv, "ha-fail-r1", servertest.WithUser(user))
	c2 := servertest.NewClient(t, srv, "ha-fail-r2", servertest.WithUser(user))

	c1.WaitForPeers(t, 1, 10*time.Second)
	c2.WaitForPeers(t, 1, 10*time.Second)

	nodeID1 := advertiseAndApproveRoute(t, srv, c1, route)
	nodeID2 := advertiseAndApproveRoute(t, srv, c2, route)

	// Node 1 should be primary (lower ID).
	primaries := srv.State().GetNodePrimaryRoutes(nodeID1)
	require.Contains(t, primaries, route, "node 1 should be primary initially")

	// Mark node 1 unhealthy — should failover to node 2.
	changed := srv.State().SetNodeUnhealthy(nodeID1, true)
	assert.True(t, changed, "marking primary unhealthy should change primaries")

	primaries2 := srv.State().GetNodePrimaryRoutes(nodeID2)
	assert.Contains(t, primaries2, route, "node 2 should be primary after failover")

	primaries1 := srv.State().GetNodePrimaryRoutes(nodeID1)
	assert.NotContains(t, primaries1, route, "node 1 should not be primary")
}

// TestHAHealthProbe_RecoveryNoFlap verifies that marking an unhealthy
// node healthy again does NOT cause it to reclaim primary (stability).
func TestHAHealthProbe_RecoveryNoFlap(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "ha-noflap")

	route := netip.MustParsePrefix("10.70.0.0/24")

	c1 := servertest.NewClient(t, srv, "ha-nf-r1", servertest.WithUser(user))
	c2 := servertest.NewClient(t, srv, "ha-nf-r2", servertest.WithUser(user))

	c1.WaitForPeers(t, 1, 10*time.Second)
	c2.WaitForPeers(t, 1, 10*time.Second)

	nodeID1 := advertiseAndApproveRoute(t, srv, c1, route)
	nodeID2 := advertiseAndApproveRoute(t, srv, c2, route)

	// Failover: node 1 → node 2.
	srv.State().SetNodeUnhealthy(nodeID1, true)
	primaries := srv.State().GetNodePrimaryRoutes(nodeID2)
	require.Contains(t, primaries, route, "node 2 should be primary")

	// Recovery: node 1 healthy again. Node 2 should STAY primary.
	changed := srv.State().SetNodeUnhealthy(nodeID1, false)
	assert.False(t, changed, "recovery should not change primaries (no flap)")

	primaries = srv.State().GetNodePrimaryRoutes(nodeID2)
	assert.Contains(t, primaries, route, "node 2 should remain primary after recovery")
}

// TestHAHealthProbe_ConnectClearsUnhealthy verifies that reconnecting
// a node clears its unhealthy state.
func TestHAHealthProbe_ConnectClearsUnhealthy(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "ha-reconnect")

	route := netip.MustParsePrefix("10.80.0.0/24")

	c1 := servertest.NewClient(t, srv, "ha-rc-r1", servertest.WithUser(user))
	c2 := servertest.NewClient(t, srv, "ha-rc-r2", servertest.WithUser(user))

	c1.WaitForPeers(t, 1, 10*time.Second)
	c2.WaitForPeers(t, 1, 10*time.Second)

	nodeID1 := advertiseAndApproveRoute(t, srv, c1, route)
	advertiseAndApproveRoute(t, srv, c2, route)

	// Mark unhealthy.
	srv.State().SetNodeUnhealthy(nodeID1, true)
	assert.False(t, srv.State().IsNodeHealthy(nodeID1))

	// Reconnect clears unhealthy via State.Connect → ClearUnhealthy.
	c1.Disconnect(t)
	c1.Reconnect(t)

	c1.WaitForPeers(t, 1, 10*time.Second)

	assert.True(t, srv.State().IsNodeHealthy(nodeID1),
		"reconnect should clear unhealthy state")
}

// TestHAHealthProbe_NoHARoutes verifies that the prober is a no-op
// when no HA configuration exists.
func TestHAHealthProbe_NoHARoutes(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "ha-noha")

	c1 := servertest.NewClient(t, srv, "noha-r1", servertest.WithUser(user))
	c2 := servertest.NewClient(t, srv, "noha-r2", servertest.WithUser(user))

	c1.WaitForPeers(t, 1, 10*time.Second)
	c2.WaitForPeers(t, 1, 10*time.Second)

	// Different routes — not HA.
	advertiseAndApproveRoute(t, srv, c1, netip.MustParsePrefix("10.90.0.0/24"))
	advertiseAndApproveRoute(t, srv, c2, netip.MustParsePrefix("10.91.0.0/24"))

	prober := state.NewHAHealthProber(
		srv.State(),
		types.HARouteConfig{
			ProbeInterval: 30 * time.Second,
			ProbeTimeout:  5 * time.Second,
		},
		srv.URL,
		srv.App.MapBatcher().IsConnected,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var dispatched bool

	prober.ProbeOnce(ctx, func(_ ...change.Change) {
		dispatched = true
	})
	assert.False(t, dispatched, "no HA routes should produce no changes")
}
