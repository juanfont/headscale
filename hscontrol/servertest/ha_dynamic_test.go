package servertest_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/netmap"
)

// Dynamic HA failover scenarios, observed from a viewer client's
// perspective. Unlike the static TestViaGrantHACompat golden tests,
// these exercise runtime transitions: a primary going unhealthy,
// revoking its approved route, or losing its tag, and verify that
// the viewer's netmap converges to the new primary. These are the
// end-to-end signals that static captures cannot cover.

// hasPeerPrimaryRoute reports whether the viewer's current netmap
// lists route as a PrimaryRoute on the peer with the given hostname.
func hasPeerPrimaryRoute(nm *netmap.NetworkMap, peerHost string, route netip.Prefix) bool {
	if nm == nil {
		return false
	}

	for _, p := range nm.Peers {
		hi := p.Hostinfo()
		if !hi.Valid() || hi.Hostname() != peerHost {
			continue
		}

		for i := range p.PrimaryRoutes().Len() {
			if p.PrimaryRoutes().At(i) == route {
				return true
			}
		}
	}

	return false
}

// TestHAFailover_ViewerSeesPrimaryFlip verifies that when an HA
// primary is marked unhealthy, the viewer's netmap flips the route's
// primary assignment from the old primary to the standby.
func TestHAFailover_ViewerSeesPrimaryFlip(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "ha-dyn-flip")

	route := netip.MustParsePrefix("10.100.0.0/24")

	r1 := servertest.NewClient(t, srv, "dyn-flip-r1", servertest.WithUser(user))
	r2 := servertest.NewClient(t, srv, "dyn-flip-r2", servertest.WithUser(user))
	viewer := servertest.NewClient(t, srv, "dyn-flip-view", servertest.WithUser(user))

	r1.WaitForPeers(t, 2, 10*time.Second)
	r2.WaitForPeers(t, 2, 10*time.Second)
	viewer.WaitForPeers(t, 2, 10*time.Second)

	id1 := advertiseAndApproveRoute(t, srv, r1, route)
	id2 := advertiseAndApproveRoute(t, srv, r2, route)

	require.Contains(t, srv.State().GetNodePrimaryRoutes(id1), route,
		"node 1 should be primary initially")

	viewer.WaitForCondition(t, "viewer sees route via r1", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return hasPeerPrimaryRoute(nm, "dyn-flip-r1", route)
		})

	changed := srv.State().SetNodeUnhealthy(id1, true)
	require.True(t, changed, "marking primary unhealthy should change primaries")

	srv.App.Change(change.PolicyChange())

	assert.Contains(t, srv.State().GetNodePrimaryRoutes(id2), route,
		"node 2 should be primary after failover")
	assert.NotContains(t, srv.State().GetNodePrimaryRoutes(id1), route,
		"node 1 should no longer be primary")

	viewer.WaitForCondition(t, "viewer sees route via r2", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return hasPeerPrimaryRoute(nm, "dyn-flip-r2", route) &&
				!hasPeerPrimaryRoute(nm, "dyn-flip-r1", route)
		})
}

// TestHAFailover_ViewerSeesRouteRevoke verifies that when the primary
// revokes its approved route, the viewer's netmap re-elects the
// standby and the old primary no longer advertises the route.
func TestHAFailover_ViewerSeesRouteRevoke(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "ha-dyn-revoke")

	route := netip.MustParsePrefix("10.101.0.0/24")

	r1 := servertest.NewClient(t, srv, "dyn-rev-r1", servertest.WithUser(user))
	r2 := servertest.NewClient(t, srv, "dyn-rev-r2", servertest.WithUser(user))
	viewer := servertest.NewClient(t, srv, "dyn-rev-view", servertest.WithUser(user))

	r1.WaitForPeers(t, 2, 10*time.Second)
	r2.WaitForPeers(t, 2, 10*time.Second)
	viewer.WaitForPeers(t, 2, 10*time.Second)

	id1 := advertiseAndApproveRoute(t, srv, r1, route)
	id2 := advertiseAndApproveRoute(t, srv, r2, route)

	viewer.WaitForCondition(t, "viewer sees route via r1", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return hasPeerPrimaryRoute(nm, "dyn-rev-r1", route)
		})

	_, rc, err := srv.State().SetApprovedRoutes(id1, nil)
	require.NoError(t, err, "revoking approved routes should succeed")

	srv.App.Change(rc)

	assert.NotContains(t, srv.State().GetNodePrimaryRoutes(id1), route,
		"node 1 should no longer be primary after revoke")
	assert.Contains(t, srv.State().GetNodePrimaryRoutes(id2), route,
		"node 2 should be primary after revoke")

	viewer.WaitForCondition(t, "viewer sees route via r2 after revoke", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return hasPeerPrimaryRoute(nm, "dyn-rev-r2", route) &&
				!hasPeerPrimaryRoute(nm, "dyn-rev-r1", route)
		})
}
