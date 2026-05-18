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

// advertiseAndApproveRoute sets [tailcfg.Hostinfo.RoutableIPs] on a client and approves
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
// node unhealthy via the [state.State.SetNodeUnhealthy] API triggers failover to the
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
	changed := srv.State().SetNodeHealth(nodeID1, false)
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
	srv.State().SetNodeHealth(nodeID1, false)
	primaries := srv.State().GetNodePrimaryRoutes(nodeID2)
	require.Contains(t, primaries, route, "node 2 should be primary")

	// Recovery: node 1 healthy again. Node 2 should STAY primary.
	changed := srv.State().SetNodeHealth(nodeID1, true)
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
	srv.State().SetNodeHealth(nodeID1, false)
	assert.False(t, srv.State().IsNodeHealthy(nodeID1))

	// Reconnect clears unhealthy via [state.State.Connect] → [state.State.ClearUnhealthy].
	c1.Disconnect(t)
	c1.Reconnect(t)

	c1.WaitForPeers(t, 1, 10*time.Second)

	assert.True(t, srv.State().IsNodeHealthy(nodeID1),
		"reconnect should clear unhealthy state")
}

// TestHAHealthProbe_SetApprovedRoutesEmptyClearsUnhealthy verifies
// that clearing a node's approved routes also clears any stale
// Unhealthy bit, mirroring the legacy routes.SetRoutes(empty)
// auto-clear. Without this, a probe timeout that lands just before
// [state.State.SetApprovedRoutes] would surface as a stale unhealthy node forever.
func TestHAHealthProbe_SetApprovedRoutesEmptyClearsUnhealthy(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "ha-clear-approve")

	route := netip.MustParsePrefix("10.100.0.0/24")

	c1 := servertest.NewClient(t, srv, "ha-ca-r1", servertest.WithUser(user))
	c2 := servertest.NewClient(t, srv, "ha-ca-r2", servertest.WithUser(user))

	c1.WaitForPeers(t, 1, 10*time.Second)
	c2.WaitForPeers(t, 1, 10*time.Second)

	nodeID1 := advertiseAndApproveRoute(t, srv, c1, route)
	advertiseAndApproveRoute(t, srv, c2, route)

	srv.State().SetNodeHealth(nodeID1, false)
	require.False(t, srv.State().IsNodeHealthy(nodeID1))

	_, _, err := srv.State().SetApprovedRoutes(nodeID1, nil)
	require.NoError(t, err)

	assert.True(t, srv.State().IsNodeHealthy(nodeID1),
		"clearing approved routes should drop stale Unhealthy bit")
}

// TestHAHealthProbe_DisconnectClearsUnhealthy verifies that
// Disconnect resets a stale Unhealthy bit. An offline node is not an
// HA candidate; carrying the bit forward leaks into DebugRoutes.
//
// The poll handler waits a 10s grace period before calling
// [state.State.Disconnect], so the assertion is wrapped in Eventually with a
// generous timeout.
func TestHAHealthProbe_DisconnectClearsUnhealthy(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "ha-clear-disc")

	route := netip.MustParsePrefix("10.101.0.0/24")

	c1 := servertest.NewClient(t, srv, "ha-cd-r1", servertest.WithUser(user))
	c2 := servertest.NewClient(t, srv, "ha-cd-r2", servertest.WithUser(user))

	c1.WaitForPeers(t, 1, 10*time.Second)
	c2.WaitForPeers(t, 1, 10*time.Second)

	nodeID1 := advertiseAndApproveRoute(t, srv, c1, route)
	advertiseAndApproveRoute(t, srv, c2, route)

	srv.State().SetNodeHealth(nodeID1, false)
	require.False(t, srv.State().IsNodeHealthy(nodeID1))

	c1.Disconnect(t)

	assert.Eventually(t, func() bool {
		return srv.State().IsNodeHealthy(nodeID1)
	}, 15*time.Second, 200*time.Millisecond,
		"disconnect should drop stale Unhealthy bit")
}

// TestHAHealthProbe_SetUnhealthyNoRoutesIsNoOp verifies the
// defensive guard for the still-online-but-no-routes case: a probe
// that fires after [state.State.SetApprovedRoutes](empty) should not be allowed
// to install a stale Unhealthy bit either.
func TestHAHealthProbe_SetUnhealthyNoRoutesIsNoOp(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "ha-guard-noroutes")

	route := netip.MustParsePrefix("10.103.0.0/24")

	c1 := servertest.NewClient(t, srv, "ha-gn-r1", servertest.WithUser(user))
	c2 := servertest.NewClient(t, srv, "ha-gn-r2", servertest.WithUser(user))

	c1.WaitForPeers(t, 1, 10*time.Second)
	c2.WaitForPeers(t, 1, 10*time.Second)

	nodeID1 := advertiseAndApproveRoute(t, srv, c1, route)
	advertiseAndApproveRoute(t, srv, c2, route)

	_, _, err := srv.State().SetApprovedRoutes(nodeID1, nil)
	require.NoError(t, err)

	srv.State().SetNodeHealth(nodeID1, false)

	assert.True(t, srv.State().IsNodeHealthy(nodeID1),
		"SetNodeHealth(false) on node with no approved routes should be a no-op")
}

// TestHAHealthProbe_ReconnectDuringProbeKeepsHealthy reproduces the
// race that surfaced as a TestHASubnetRouterFailover flake: a probe
// dispatched against the previous poll session sees the timeout fire
// while the client is briefly disconnected. With the session guard in
// [HAHealthProber.ProbeOnce], the timeout path observes the reconnect
// and bails out instead of installing a spurious Unhealthy bit.
//
// Without the guard, the primary fails over to the standby and the
// anti-flap election preserves that choice even after the original
// primary is fully back online.
func TestHAHealthProbe_ReconnectDuringProbeKeepsHealthy(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "ha-probe-reconnect")

	route := netip.MustParsePrefix("10.102.0.0/24")

	c1 := servertest.NewClient(t, srv, "ha-pr-r1", servertest.WithUser(user))
	c2 := servertest.NewClient(t, srv, "ha-pr-r2", servertest.WithUser(user))

	c1.WaitForPeers(t, 1, 10*time.Second)
	c2.WaitForPeers(t, 1, 10*time.Second)

	nodeID1 := advertiseAndApproveRoute(t, srv, c1, route)
	advertiseAndApproveRoute(t, srv, c2, route)

	// Node 1 is primary (lowest ID, healthy).
	require.Contains(t,
		srv.State().GetNodePrimaryRoutes(nodeID1), route,
		"node 1 should be primary initially")

	prober := state.NewHAHealthProber(
		srv.State(),
		types.HARouteConfig{
			ProbeInterval: 30 * time.Second,
			ProbeTimeout:  2 * time.Second,
		},
		srv.URL,
		srv.App.MapBatcher().IsConnected,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// TestClient does not implement ping responses, so every probe
	// times out. We exploit that to observe the timeout path under a
	// reconnect race: kick a probe in a goroutine, bounce the
	// primary's poll session, and confirm the prober drops the stale
	// timeout instead of marking the node unhealthy.
	done := make(chan struct{})

	go func() {
		defer close(done)

		prober.ProbeOnce(ctx, srv.App.Change)
	}()

	c1.Disconnect(t)
	c1.Reconnect(t)
	c1.WaitForPeers(t, 1, 10*time.Second)

	<-done

	assert.True(t, srv.State().IsNodeHealthy(nodeID1),
		"reconnect during probe must not flip node unhealthy")
	assert.Contains(t,
		srv.State().GetNodePrimaryRoutes(nodeID1), route,
		"node 1 should remain primary after stale-probe timeout")
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
