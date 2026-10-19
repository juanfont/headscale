package servertest_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
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

var errHealthRecoveryPolicyBuild = errors.New("injected health recovery policy failure")

type healthRecoveryPolicyManager struct {
	policy.PolicyManager

	fail *atomic.Bool
}

func (pm healthRecoveryPolicyManager) SetNodesAndBuildPeerMap(nodes views.Slice[types.NodeView]) (policy.ReadView, map[types.NodeID][]types.NodeID, error) {
	if pm.fail.Load() {
		return policy.ReadView{}, nil, errHealthRecoveryPolicyBuild
	}

	return pm.PolicyManager.SetNodesAndBuildPeerMap(nodes)
}

// TestHAHealthProbe_PolicyRecoveryWithoutPrimaryChange exercises the real
// prober, batched health write, Headscale.Change and connected client path.
func TestHAHealthProbe_PolicyRecoveryWithoutPrimaryChange(t *testing.T) {
	srv := servertest.NewServer(t,
		servertest.WithMagicDNS("headscale.test"),
		servertest.WithDNSResolvers("https://dns.nextdns.io/test"),
	)
	user := srv.CreateUser(t, "ha-policy-recovery")

	const pol = `{"grants":[{"src":["*"],"dst":["*"],"ip":["*"]}],"ssh":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self"],"users":["root"]}]}`

	_, err := srv.State().SetPolicy([]byte(pol))
	require.NoError(t, err)

	var fail atomic.Bool

	srv.State().WrapPolicyManagerForTest(func(pm policy.PolicyManager) policy.PolicyManager {
		return healthRecoveryPolicyManager{PolicyManager: pm, fail: &fail}
	})

	r1 := servertest.NewClient(t, srv, "ha-recovery-r1", servertest.WithUser(user))
	r2 := servertest.NewClient(t, srv, "ha-recovery-r2", servertest.WithUser(user))

	viewer := servertest.NewClient(t, srv, "ha-recovery-viewer", servertest.WithUser(user))
	for _, client := range []*servertest.TestClient{r1, r2, viewer} {
		client.WaitForPeers(t, 2, 10*time.Second)
	}

	route := netip.MustParsePrefix("10.104.0.0/24")
	router1 := advertiseAndApproveRoute(t, srv, r1, route)
	router2 := advertiseAndApproveRoute(t, srv, r2, route)
	viewerID := findNodeID(t, srv, viewer.Name)
	require.Contains(t, srv.State().GetNodePrimaryRoutes(router1), route)
	require.Empty(t, srv.State().GetNodePrimaryRoutes(router2))

	prober := state.NewHAHealthProber(srv.State(), types.HARouteConfig{
		ProbeInterval: 30 * time.Second,
		ProbeTimeout:  time.Second,
	}, srv.URL, srv.App.MapBatcher().IsConnected)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Establish stable sessions before the failed snapshot withholds pings.
	prober.ProbeOnce(ctx, srv.App.Change)
	require.True(t, srv.State().IsNodeHealthy(router1))
	require.True(t, srv.State().IsNodeHealthy(router2))

	fail.Store(true)

	current, ok := srv.State().GetNodeByID(viewerID)
	require.True(t, ok)

	withheld := current.AsStruct()
	withheld.GivenName = "withheld-self"
	withheld.Hostname = "withheld-host"
	withheld.Hostinfo.Hostname = "withheld-host"
	withheld.IPv4 = new(netip.MustParseAddr("100.64.0.99"))
	srv.State().PutNodeInStoreForTest(*withheld)
	_, err = srv.State().MapView(viewerID)
	require.ErrorIs(t, err, errHealthRecoveryPolicyBuild)
	// MagicDNS names on the wire are absolute FQDNs, including the final dot.
	const wantSelfName = "withheld-self.headscale.test."

	require.NotEqual(t, wantSelfName, viewer.Netmap().SelfNode.Name())
	fail.Store(false)

	var healthDispatches int

	dispatch := func(cs ...change.Change) {
		for _, c := range cs {
			if c.IsBroadcastPolicyChange() {
				healthDispatches++
			}
		}

		srv.App.Change(cs...)
	}
	// Invalid maps withhold both pings. Both stable sessions time out, and
	// the all-unhealthy election retains the previous primary unchanged.
	prober.ProbeOnce(ctx, dispatch)
	require.Equal(t, 1, healthDispatches, "policy recovery must dispatch even when primaries do not change")
	require.False(t, srv.State().IsNodeHealthy(router1))
	require.False(t, srv.State().IsNodeHealthy(router2))
	require.Contains(t, srv.State().GetNodePrimaryRoutes(router1), route)
	require.Empty(t, srv.State().GetNodePrimaryRoutes(router2))
	recovered, err := srv.State().MapView(viewerID)
	require.NoError(t, err)
	t.Logf("recovered snapshot: self=%q hostname=%q addresses=%v health_dispatches=%d",
		recovered.Viewer().GivenName(), recovered.Viewer().Hostname(), recovered.Viewer().Prefixes(), healthDispatches)

	defer func() {
		nm := viewer.Netmap()
		t.Logf("recovery client: want_self=%q self=%q addresses=%v resolver=%q peers=%d packet_rules=%d",
			wantSelfName, nm.SelfNode.Name(), nm.SelfNode.Addresses().AsSlice(), firstResolver(nm), len(nm.Peers), nm.PacketFilterRules.Len())
	}()

	viewer.WaitForCondition(t, "health-only recovery sends withheld self state", 10*time.Second, func(nm *netmap.NetworkMap) bool {
		return nm.SelfNode.Name() == wantSelfName &&
			slices.Contains(nm.SelfNode.Addresses().AsSlice(), netip.MustParsePrefix("100.64.0.99/32")) &&
			len(nm.DNS.Resolvers) > 0 && strings.Contains(nm.DNS.Resolvers[0].Addr, "device_name=withheld-host") &&
			strings.Contains(nm.DNS.Resolvers[0].Addr, "device_ip=100.64.0.99")
	})
	nm := viewer.Netmap()
	require.Len(t, nm.Peers, 2)
	require.Positive(t, nm.PacketFilterRules.Len())
	require.NotNil(t, nm.SSHPolicy)
	require.NotEmpty(t, nm.SSHPolicy.Rules)

	changed, err := srv.State().SetPolicy([]byte(pol))
	require.NoError(t, err)
	require.False(t, changed, "recovery does not require a policy-hash change")
	// The real Headscale dispatch consumed the one recovery bit. Repeating
	// unchanged health must not request another catch-up dispatch.
	require.False(t, srv.State().BatchSetNodeHealth(map[types.NodeID]bool{router1: false, router2: false}))
}
