package integration

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	cmpdiff "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/routes"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xmaps "golang.org/x/exp/maps"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/views"
	"tailscale.com/util/must"
	"tailscale.com/util/slicesx"
	"tailscale.com/wgengine/filter"
)

var allPorts = filter.PortRange{First: 0, Last: 0xffff}

// This test is both testing the routes command and the propagation of
// routes.
func TestEnablingRoutes(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 3,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{tsic.WithAcceptRoutes()},
		hsic.WithTestName("clienableroute"))
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	expectedRoutes := map[string]string{
		"1": "10.0.0.0/24",
		"2": "10.0.1.0/24",
		"3": "10.0.2.0/24",
	}

	// advertise routes using the up command
	for _, client := range allClients {
		status := client.MustStatus()
		command := []string{
			"tailscale",
			"set",
			"--advertise-routes=" + expectedRoutes[string(status.Self.ID)],
		}
		_, _, err = client.Execute(command)
		require.NoErrorf(t, err, "failed to advertise route: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	var nodes []*v1.Node
	// Wait for route advertisements to propagate to NodeStore
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		nodes, err = headscale.ListNodes()
		assert.NoError(ct, err)

		for _, node := range nodes {
			assert.Len(ct, node.GetAvailableRoutes(), 1)
			assert.Empty(ct, node.GetApprovedRoutes())
			assert.Empty(ct, node.GetSubnetRoutes())
		}
	}, 10*time.Second, 100*time.Millisecond, "route advertisements should propagate to all nodes")

	// Verify that no routes has been sent to the client,
	// they are not yet enabled.
	for _, client := range allClients {
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			status, err := client.Status()
			assert.NoError(c, err)

			for _, peerKey := range status.Peers() {
				peerStatus := status.Peer[peerKey]

				assert.Nil(c, peerStatus.PrimaryRoutes)
			}
		}, 5*time.Second, 200*time.Millisecond, "Verifying no routes are active before approval")
	}

	for _, node := range nodes {
		_, err := headscale.ApproveRoutes(
			node.GetId(),
			util.MustStringsToPrefixes(node.GetAvailableRoutes()),
		)
		require.NoError(t, err)
	}

	// Wait for route approvals to propagate to NodeStore
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		nodes, err = headscale.ListNodes()
		assert.NoError(ct, err)

		for _, node := range nodes {
			assert.Len(ct, node.GetAvailableRoutes(), 1)
			assert.Len(ct, node.GetApprovedRoutes(), 1)
			assert.Len(ct, node.GetSubnetRoutes(), 1)
		}
	}, 10*time.Second, 100*time.Millisecond, "route approvals should propagate to all nodes")

	// Wait for route state changes to propagate to clients
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		// Verify that the clients can see the new routes
		for _, client := range allClients {
			status, err := client.Status()
			assert.NoError(c, err)

			for _, peerKey := range status.Peers() {
				peerStatus := status.Peer[peerKey]

				assert.NotNil(c, peerStatus.PrimaryRoutes)
				assert.NotNil(c, peerStatus.AllowedIPs)
				if peerStatus.AllowedIPs != nil {
					assert.Len(c, peerStatus.AllowedIPs.AsSlice(), 3)
				}
				requirePeerSubnetRoutesWithCollect(c, peerStatus, []netip.Prefix{netip.MustParsePrefix(expectedRoutes[string(peerStatus.ID)])})
			}
		}
	}, 10*time.Second, 500*time.Millisecond, "clients should see new routes")

	_, err = headscale.ApproveRoutes(
		1,
		[]netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
	)
	require.NoError(t, err)

	_, err = headscale.ApproveRoutes(
		2,
		[]netip.Prefix{},
	)
	require.NoError(t, err)

	// Wait for route state changes to propagate to nodes
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var err error
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)

		for _, node := range nodes {
			if node.GetId() == 1 {
				assert.Len(c, node.GetAvailableRoutes(), 1) // 10.0.0.0/24
				assert.Len(c, node.GetApprovedRoutes(), 1)  // 10.0.1.0/24
				assert.Empty(c, node.GetSubnetRoutes())
			} else if node.GetId() == 2 {
				assert.Len(c, node.GetAvailableRoutes(), 1) // 10.0.1.0/24
				assert.Empty(c, node.GetApprovedRoutes())
				assert.Empty(c, node.GetSubnetRoutes())
			} else {
				assert.Len(c, node.GetAvailableRoutes(), 1) // 10.0.2.0/24
				assert.Len(c, node.GetApprovedRoutes(), 1)  // 10.0.2.0/24
				assert.Len(c, node.GetSubnetRoutes(), 1)    // 10.0.2.0/24
			}
		}
	}, 10*time.Second, 500*time.Millisecond, "route state changes should propagate to nodes")

	// Verify that the clients can see the new routes
	for _, client := range allClients {
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			status, err := client.Status()
			assert.NoError(c, err)

			for _, peerKey := range status.Peers() {
				peerStatus := status.Peer[peerKey]

				switch peerStatus.ID {
				case "1":
					requirePeerSubnetRoutesWithCollect(c, peerStatus, nil)
				case "2":
					requirePeerSubnetRoutesWithCollect(c, peerStatus, nil)
				default:
					requirePeerSubnetRoutesWithCollect(c, peerStatus, []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")})
				}
			}
		}, 5*time.Second, 200*time.Millisecond, "Verifying final route state visible to clients")
	}
}

func TestHASubnetRouterFailover(t *testing.T) {
	IntegrationSkip(t)

	propagationTime := 60 * time.Second

	// Helper function to validate primary routes table state
	validatePrimaryRoutes := func(t *testing.T, headscale ControlServer, expectedRoutes *routes.DebugRoutes, message string) {
		t.Helper()
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			primaryRoutesState, err := headscale.PrimaryRoutes()
			assert.NoError(c, err)

			if diff := cmpdiff.Diff(expectedRoutes, primaryRoutesState, util.PrefixComparer); diff != "" {
				t.Log(message)
				t.Errorf("validatePrimaryRoutes mismatch (-want +got):\n%s", diff)
			}
		}, propagationTime, 200*time.Millisecond, "Validating primary routes table")
	}

	spec := ScenarioSpec{
		NodesPerUser: 3,
		Users:        []string{"user1", "user2"},
		Networks: map[string][]string{
			"usernet1": {"user1"},
			"usernet2": {"user2"},
		},
		ExtraService: map[string][]extraServiceFunc{
			"usernet1": {Webservice},
		},
		// We build the head image with curl and traceroute, so only use
		// that for this test.
		Versions: []string{"head"},
	}

	scenario, err := NewScenario(spec)
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	// defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{tsic.WithAcceptRoutes()},
		hsic.WithTestName("clienableroute"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	prefp, err := scenario.SubnetOfNetwork("usernet1")
	require.NoError(t, err)
	pref := *prefp
	t.Logf("usernet1 prefix: %s", pref.String())

	usernet1, err := scenario.Network("usernet1")
	require.NoError(t, err)

	services, err := scenario.Services("usernet1")
	require.NoError(t, err)
	require.Len(t, services, 1)

	web := services[0]
	webip := netip.MustParseAddr(web.GetIPInNetwork(usernet1))
	weburl := fmt.Sprintf("http://%s/etc/hostname", webip)
	t.Logf("webservice: %s, %s", webip.String(), weburl)

	// Sort nodes by ID
	sort.SliceStable(allClients, func(i, j int) bool {
		statusI := allClients[i].MustStatus()
		statusJ := allClients[j].MustStatus()

		return statusI.Self.ID < statusJ.Self.ID
	})

	// This is ok because the scenario makes users in order, so the three first
	// nodes, which are subnet routes, will be created first, and the last user
	// will be created with the second.
	subRouter1 := allClients[0]
	subRouter2 := allClients[1]
	subRouter3 := allClients[2]

	client := allClients[3]

	t.Logf("%s (%s) picked as client", client.Hostname(), client.MustID())
	t.Logf("=== Initial Route Advertisement - Setting up HA configuration with 3 routers ===")
	t.Logf("[%s] Starting test section", time.Now().Format(TimestampFormat))
	t.Logf("  - Router 1 (%s): Advertising route %s - will become PRIMARY when approved", subRouter1.Hostname(), pref.String())
	t.Logf("  - Router 2 (%s): Advertising route %s - will be STANDBY when approved", subRouter2.Hostname(), pref.String())
	t.Logf("  - Router 3 (%s): Advertising route %s - will be STANDBY when approved", subRouter3.Hostname(), pref.String())
	t.Logf("  Expected: All 3 routers advertise the same route for redundancy, but only one will be primary at a time")
	for _, client := range allClients[:3] {
		command := []string{
			"tailscale",
			"set",
			"--advertise-routes=" + pref.String(),
		}
		_, _, err = client.Execute(command)
		require.NoErrorf(t, err, "failed to advertise route: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	// Wait for route configuration changes after advertising routes
	var nodes []*v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 6)
		require.GreaterOrEqual(t, len(nodes), 3, "need at least 3 nodes to avoid panic")
		requireNodeRouteCountWithCollect(c, nodes[0], 1, 0, 0)
		requireNodeRouteCountWithCollect(c, nodes[1], 1, 0, 0)
		requireNodeRouteCountWithCollect(c, nodes[2], 1, 0, 0)
	}, propagationTime, 200*time.Millisecond, "Waiting for route advertisements: All 3 routers should have advertised routes (available=1) but none approved yet (approved=0, subnet=0)")

	// Verify that no routes has been sent to the client,
	// they are not yet enabled.
	for _, client := range allClients {
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			status, err := client.Status()
			assert.NoError(c, err)

			for _, peerKey := range status.Peers() {
				peerStatus := status.Peer[peerKey]

				assert.Nil(c, peerStatus.PrimaryRoutes)
				requirePeerSubnetRoutesWithCollect(c, peerStatus, nil)
			}
		}, propagationTime, 200*time.Millisecond, "Verifying no routes are active before approval")
	}

	// Declare variables that will be used across multiple EventuallyWithT blocks
	var (
		srs1, srs2, srs3 *ipnstate.Status
		clientStatus     *ipnstate.Status
		srs1PeerStatus   *ipnstate.PeerStatus
		srs2PeerStatus   *ipnstate.PeerStatus
		srs3PeerStatus   *ipnstate.PeerStatus
	)

	// Helper function to check test failure and print route map if needed
	checkFailureAndPrintRoutes := func(t *testing.T, client TailscaleClient) {
		if t.Failed() {
			t.Logf("[%s] Test failed at this checkpoint", time.Now().Format(TimestampFormat))
			status, err := client.Status()
			if err == nil {
				printCurrentRouteMap(t, xmaps.Values(status.Peer)...)
			}
			t.FailNow()
		}
	}

	// Validate primary routes table state - no routes approved yet
	validatePrimaryRoutes(t, headscale, &routes.DebugRoutes{
		AvailableRoutes: map[types.NodeID][]netip.Prefix{},
		PrimaryRoutes:   map[string]types.NodeID{}, // No primary routes yet
	}, "Primary routes table should be empty (no approved routes yet)")

	checkFailureAndPrintRoutes(t, client)

	// Enable route on node 1
	t.Logf("=== Approving route on router 1 (%s) - Single router mode (no HA yet) ===", subRouter1.Hostname())
	t.Logf("[%s] Starting test section", time.Now().Format(TimestampFormat))
	t.Logf("  Expected: Router 1 becomes PRIMARY with route %s active", pref.String())
	t.Logf("  Expected: Routers 2 & 3 remain with advertised but unapproved routes")
	t.Logf("  Expected: Client can access webservice through router 1 only")
	_, err = headscale.ApproveRoutes(
		MustFindNode(subRouter1.Hostname(), nodes).GetId(),
		[]netip.Prefix{pref},
	)
	require.NoError(t, err)

	// Wait for route approval on first subnet router
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 6)
		require.GreaterOrEqual(t, len(nodes), 3, "need at least 3 nodes to avoid panic")
		requireNodeRouteCountWithCollect(c, nodes[0], 1, 1, 1)
		requireNodeRouteCountWithCollect(c, nodes[1], 1, 0, 0)
		requireNodeRouteCountWithCollect(c, nodes[2], 1, 0, 0)
	}, propagationTime, 200*time.Millisecond, "Router 1 approval verification: Should be PRIMARY (available=1, approved=1, subnet=1), others still unapproved (available=1, approved=0, subnet=0)")

	// Verify that the client has routes from the primary machine and can access
	// the webservice.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		srs1 = subRouter1.MustStatus()
		srs2 = subRouter2.MustStatus()
		srs3 = subRouter3.MustStatus()
		clientStatus = client.MustStatus()

		srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
		srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]
		srs3PeerStatus = clientStatus.Peer[srs3.Self.PublicKey]

		assert.NotNil(c, srs1PeerStatus, "Router 1 peer should exist")
		assert.NotNil(c, srs2PeerStatus, "Router 2 peer should exist")
		assert.NotNil(c, srs3PeerStatus, "Router 3 peer should exist")

		if srs1PeerStatus == nil || srs2PeerStatus == nil || srs3PeerStatus == nil {
			return
		}

		assert.True(c, srs1PeerStatus.Online, "Router 1 should be online and serving as PRIMARY")
		assert.True(c, srs2PeerStatus.Online, "Router 2 should be online but NOT serving routes (unapproved)")
		assert.True(c, srs3PeerStatus.Online, "Router 3 should be online but NOT serving routes (unapproved)")

		assert.Nil(c, srs2PeerStatus.PrimaryRoutes)
		assert.Nil(c, srs3PeerStatus.PrimaryRoutes)
		assert.NotNil(c, srs1PeerStatus.PrimaryRoutes)

		requirePeerSubnetRoutesWithCollect(c, srs1PeerStatus, []netip.Prefix{pref})
		requirePeerSubnetRoutesWithCollect(c, srs2PeerStatus, nil)
		requirePeerSubnetRoutesWithCollect(c, srs3PeerStatus, nil)

		if srs1PeerStatus.PrimaryRoutes != nil {
			t.Logf("got list: %v, want in: %v", srs1PeerStatus.PrimaryRoutes.AsSlice(), pref)
			assert.Contains(c,
				srs1PeerStatus.PrimaryRoutes.AsSlice(),
				pref,
			)
		}
	}, propagationTime, 200*time.Millisecond, "Verifying Router 1 is PRIMARY with routes after approval")

	t.Logf("=== Validating connectivity through PRIMARY router 1 (%s) to webservice at %s ===", must.Get(subRouter1.IPv4()).String(), webip.String())
	t.Logf("[%s] Starting test section", time.Now().Format(TimestampFormat))
	t.Logf("  Expected: Traffic flows through router 1 as it's the only approved route")
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, err := client.Curl(weburl)
		assert.NoError(c, err)
		assert.Len(c, result, 13)
	}, propagationTime, 200*time.Millisecond, "Verifying client can reach webservice through router 1")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		tr, err := client.Traceroute(webip)
		assert.NoError(c, err)
		ip, err := subRouter1.IPv4()
		if !assert.NoError(c, err, "failed to get IPv4 for subRouter1") {
			return
		}
		assertTracerouteViaIPWithCollect(c, tr, ip)
	}, propagationTime, 200*time.Millisecond, "Verifying traceroute goes through router 1")

	// Validate primary routes table state - router 1 is primary
	validatePrimaryRoutes(t, headscale, &routes.DebugRoutes{
		AvailableRoutes: map[types.NodeID][]netip.Prefix{
			types.NodeID(MustFindNode(subRouter1.Hostname(), nodes).GetId()): {pref},
			// Note: Router 2 and 3 are available but not approved
		},
		PrimaryRoutes: map[string]types.NodeID{
			pref.String(): types.NodeID(MustFindNode(subRouter1.Hostname(), nodes).GetId()),
		},
	}, "Router 1 should be primary for route "+pref.String())

	checkFailureAndPrintRoutes(t, client)

	// Enable route on node 2, now we will have a HA subnet router
	t.Logf("=== Enabling High Availability by approving route on router 2 (%s) ===", subRouter2.Hostname())
	t.Logf("[%s] Starting test section", time.Now().Format(TimestampFormat))
	t.Logf("  Current state: Router 1 is PRIMARY and actively serving traffic")
	t.Logf("  Expected: Router 2 becomes STANDBY (approved but not primary)")
	t.Logf("  Expected: Router 1 remains PRIMARY (no flapping - stability preferred)")
	t.Logf("  Expected: HA is now active - if router 1 fails, router 2 can take over")
	_, err = headscale.ApproveRoutes(
		MustFindNode(subRouter2.Hostname(), nodes).GetId(),
		[]netip.Prefix{pref},
	)
	require.NoError(t, err)

	// Wait for route approval on second subnet router
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 6)
		if len(nodes) >= 3 {
			requireNodeRouteCountWithCollect(c, nodes[0], 1, 1, 1)
			requireNodeRouteCountWithCollect(c, nodes[1], 1, 1, 0)
			requireNodeRouteCountWithCollect(c, nodes[2], 1, 0, 0)
		}
	}, 3*time.Second, 200*time.Millisecond, "HA setup verification: Router 2 approved as STANDBY (available=1, approved=1, subnet=0), Router 1 stays PRIMARY (subnet=1)")

	// Verify that the client has routes from the primary machine
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		srs1 = subRouter1.MustStatus()
		srs2 = subRouter2.MustStatus()
		srs3 = subRouter3.MustStatus()
		clientStatus = client.MustStatus()

		srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
		srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]
		srs3PeerStatus = clientStatus.Peer[srs3.Self.PublicKey]

		assert.NotNil(c, srs1PeerStatus, "Router 1 peer should exist")
		assert.NotNil(c, srs2PeerStatus, "Router 2 peer should exist")
		assert.NotNil(c, srs3PeerStatus, "Router 3 peer should exist")

		if srs1PeerStatus == nil || srs2PeerStatus == nil || srs3PeerStatus == nil {
			return
		}

		assert.True(c, srs1PeerStatus.Online, "Router 1 should be online and remain PRIMARY")
		assert.True(c, srs2PeerStatus.Online, "Router 2 should be online and now approved as STANDBY")
		assert.True(c, srs3PeerStatus.Online, "Router 3 should be online but still unapproved")

		assert.Nil(c, srs2PeerStatus.PrimaryRoutes)
		assert.Nil(c, srs3PeerStatus.PrimaryRoutes)
		assert.NotNil(c, srs1PeerStatus.PrimaryRoutes)

		requirePeerSubnetRoutesWithCollect(c, srs1PeerStatus, []netip.Prefix{pref})
		requirePeerSubnetRoutesWithCollect(c, srs2PeerStatus, nil)
		requirePeerSubnetRoutesWithCollect(c, srs3PeerStatus, nil)

		if srs1PeerStatus.PrimaryRoutes != nil {
			t.Logf("got list: %v, want in: %v", srs1PeerStatus.PrimaryRoutes.AsSlice(), pref)
			assert.Contains(c,
				srs1PeerStatus.PrimaryRoutes.AsSlice(),
				pref,
			)
		}
	}, propagationTime, 200*time.Millisecond, "Verifying Router 1 remains PRIMARY after Router 2 approval")

	// Validate primary routes table state - router 1 still primary, router 2 approved but standby
	validatePrimaryRoutes(t, headscale, &routes.DebugRoutes{
		AvailableRoutes: map[types.NodeID][]netip.Prefix{
			types.NodeID(MustFindNode(subRouter1.Hostname(), nodes).GetId()): {pref},
			types.NodeID(MustFindNode(subRouter2.Hostname(), nodes).GetId()): {pref},
			// Note: Router 3 is available but not approved
		},
		PrimaryRoutes: map[string]types.NodeID{
			pref.String(): types.NodeID(MustFindNode(subRouter1.Hostname(), nodes).GetId()),
		},
	}, "Router 1 should remain primary after router 2 approval")

	checkFailureAndPrintRoutes(t, client)

	t.Logf("=== Validating HA configuration - Router 1 PRIMARY, Router 2 STANDBY ===")
	t.Logf("[%s] Starting test section", time.Now().Format(TimestampFormat))
	t.Logf("  Current routing: Traffic through router 1 (%s) to %s", must.Get(subRouter1.IPv4()), webip.String())
	t.Logf("  Expected: Router 1 continues to handle all traffic (no change from before)")
	t.Logf("  Expected: Router 2 is ready to take over if router 1 fails")
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, err := client.Curl(weburl)
		assert.NoError(c, err)
		assert.Len(c, result, 13)
	}, propagationTime, 200*time.Millisecond, "Verifying client can reach webservice through router 1 in HA mode")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		tr, err := client.Traceroute(webip)
		assert.NoError(c, err)
		ip, err := subRouter1.IPv4()
		if !assert.NoError(c, err, "failed to get IPv4 for subRouter1") {
			return
		}
		assertTracerouteViaIPWithCollect(c, tr, ip)
	}, propagationTime, 200*time.Millisecond, "Verifying traceroute still goes through router 1 in HA mode")

	// Validate primary routes table state - router 1 primary, router 2 approved (standby)
	validatePrimaryRoutes(t, headscale, &routes.DebugRoutes{
		AvailableRoutes: map[types.NodeID][]netip.Prefix{
			types.NodeID(MustFindNode(subRouter1.Hostname(), nodes).GetId()): {pref},
			types.NodeID(MustFindNode(subRouter2.Hostname(), nodes).GetId()): {pref},
			// Note: Router 3 is available but not approved
		},
		PrimaryRoutes: map[string]types.NodeID{
			pref.String(): types.NodeID(MustFindNode(subRouter1.Hostname(), nodes).GetId()),
		},
	}, "Router 1 primary with router 2 as standby")

	checkFailureAndPrintRoutes(t, client)

	// Enable route on node 3, now we will have a second standby and all will
	// be enabled.
	t.Logf("=== Adding second STANDBY router by approving route on router 3 (%s) ===", subRouter3.Hostname())
	t.Logf("[%s] Starting test section", time.Now().Format(TimestampFormat))
	t.Logf("  Current state: Router 1 PRIMARY, Router 2 STANDBY")
	t.Logf("  Expected: Router 3 becomes second STANDBY (approved but not primary)")
	t.Logf("  Expected: Router 1 remains PRIMARY, Router 2 remains first STANDBY")
	t.Logf("  Expected: Full HA configuration with 1 PRIMARY + 2 STANDBY routers")
	_, err = headscale.ApproveRoutes(
		MustFindNode(subRouter3.Hostname(), nodes).GetId(),
		[]netip.Prefix{pref},
	)
	require.NoError(t, err)

	// Wait for route approval on third subnet router
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 6)
		require.GreaterOrEqual(t, len(nodes), 3, "need at least 3 nodes to avoid panic")
		requireNodeRouteCountWithCollect(c, nodes[0], 1, 1, 1)
		requireNodeRouteCountWithCollect(c, nodes[1], 1, 1, 0)
		requireNodeRouteCountWithCollect(c, nodes[2], 1, 1, 0)
	}, 3*time.Second, 200*time.Millisecond, "Full HA verification: Router 3 approved as second STANDBY (available=1, approved=1, subnet=0), Router 1 PRIMARY, Router 2 first STANDBY")

	// Verify that the client has routes from the primary machine
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		srs1 = subRouter1.MustStatus()
		srs2 = subRouter2.MustStatus()
		srs3 = subRouter3.MustStatus()
		clientStatus = client.MustStatus()

		srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
		srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]
		srs3PeerStatus = clientStatus.Peer[srs3.Self.PublicKey]

		assert.NotNil(c, srs1PeerStatus, "Router 1 peer should exist")
		assert.NotNil(c, srs2PeerStatus, "Router 2 peer should exist")
		assert.NotNil(c, srs3PeerStatus, "Router 3 peer should exist")

		if srs1PeerStatus == nil || srs2PeerStatus == nil || srs3PeerStatus == nil {
			return
		}

		assert.True(c, srs1PeerStatus.Online, "Router 1 should be online and remain PRIMARY")
		assert.True(c, srs2PeerStatus.Online, "Router 2 should be online as first STANDBY")
		assert.True(c, srs3PeerStatus.Online, "Router 3 should be online as second STANDBY")

		assert.Nil(c, srs2PeerStatus.PrimaryRoutes)
		assert.Nil(c, srs3PeerStatus.PrimaryRoutes)
		assert.NotNil(c, srs1PeerStatus.PrimaryRoutes)

		requirePeerSubnetRoutesWithCollect(c, srs1PeerStatus, []netip.Prefix{pref})
		requirePeerSubnetRoutesWithCollect(c, srs2PeerStatus, nil)
		requirePeerSubnetRoutesWithCollect(c, srs3PeerStatus, nil)

		if srs1PeerStatus.PrimaryRoutes != nil {
			t.Logf("got list: %v, want in: %v", srs1PeerStatus.PrimaryRoutes.AsSlice(), pref)
			assert.Contains(c,
				srs1PeerStatus.PrimaryRoutes.AsSlice(),
				pref,
			)
		}
	}, propagationTime, 200*time.Millisecond, "Verifying full HA with 3 routers: Router 1 PRIMARY, Routers 2 & 3 STANDBY")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, err := client.Curl(weburl)
		assert.NoError(c, err)
		assert.Len(c, result, 13)
	}, propagationTime, 200*time.Millisecond, "Verifying client can reach webservice through router 1 with full HA")

	// Wait for traceroute to work correctly through the expected router
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		tr, err := client.Traceroute(webip)
		assert.NoError(c, err)

		// Get the expected router IP - use a more robust approach to handle temporary disconnections
		ips, err := subRouter1.IPs()
		assert.NoError(c, err)
		assert.NotEmpty(c, ips, "subRouter1 should have IP addresses")

		var expectedIP netip.Addr
		for _, ip := range ips {
			if ip.Is4() {
				expectedIP = ip
				break
			}
		}
		assert.True(c, expectedIP.IsValid(), "subRouter1 should have a valid IPv4 address")

		assertTracerouteViaIPWithCollect(c, tr, expectedIP)
	}, propagationTime, 200*time.Millisecond, "Verifying traffic still flows through PRIMARY router 1 with full HA setup active")

	// Validate primary routes table state - all 3 routers approved, router 1 still primary
	validatePrimaryRoutes(t, headscale, &routes.DebugRoutes{
		AvailableRoutes: map[types.NodeID][]netip.Prefix{
			types.NodeID(MustFindNode(subRouter1.Hostname(), nodes).GetId()): {pref},
			types.NodeID(MustFindNode(subRouter2.Hostname(), nodes).GetId()): {pref},
			types.NodeID(MustFindNode(subRouter3.Hostname(), nodes).GetId()): {pref},
		},
		PrimaryRoutes: map[string]types.NodeID{
			pref.String(): types.NodeID(MustFindNode(subRouter1.Hostname(), nodes).GetId()),
		},
	}, "Router 1 primary with all 3 routers approved")

	checkFailureAndPrintRoutes(t, client)

	// Take down the current primary
	t.Logf("=== FAILOVER TEST: Taking down PRIMARY router 1 (%s) ===", subRouter1.Hostname())
	t.Logf("[%s] Starting test section", time.Now().Format(TimestampFormat))
	t.Logf("  Current state: Router 1 PRIMARY (serving traffic), Router 2 & 3 STANDBY")
	t.Logf("  Action: Shutting down router 1 to simulate failure")
	t.Logf("  Expected: Router 2 (%s) should automatically become new PRIMARY", subRouter2.Hostname())
	t.Logf("  Expected: Router 3 remains STANDBY")
	t.Logf("  Expected: Traffic seamlessly fails over to router 2")
	err = subRouter1.Down()
	require.NoError(t, err)

	// Wait for router status changes after r1 goes down
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		srs2 = subRouter2.MustStatus()
		clientStatus = client.MustStatus()

		srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
		srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]
		srs3PeerStatus = clientStatus.Peer[srs3.Self.PublicKey]

		assert.NotNil(c, srs1PeerStatus, "Router 1 peer should exist")
		assert.NotNil(c, srs2PeerStatus, "Router 2 peer should exist")
		assert.NotNil(c, srs3PeerStatus, "Router 3 peer should exist")

		if srs1PeerStatus == nil || srs2PeerStatus == nil || srs3PeerStatus == nil {
			return
		}

		assert.False(c, srs1PeerStatus.Online, "r1 should be offline")
		assert.True(c, srs2PeerStatus.Online, "r2 should be online")
		assert.True(c, srs3PeerStatus.Online, "r3 should be online")

		assert.Nil(c, srs1PeerStatus.PrimaryRoutes)
		assert.NotNil(c, srs2PeerStatus.PrimaryRoutes)
		assert.Nil(c, srs3PeerStatus.PrimaryRoutes)

		requirePeerSubnetRoutesWithCollect(c, srs1PeerStatus, nil)
		requirePeerSubnetRoutesWithCollect(c, srs2PeerStatus, []netip.Prefix{pref})
		requirePeerSubnetRoutesWithCollect(c, srs3PeerStatus, nil)

		if srs2PeerStatus.PrimaryRoutes != nil {
			assert.Contains(c,
				srs2PeerStatus.PrimaryRoutes.AsSlice(),
				pref,
			)
		}
	}, propagationTime, 200*time.Millisecond, "Failover verification: Router 1 offline, Router 2 should be new PRIMARY with routes, Router 3 still STANDBY")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, err := client.Curl(weburl)
		assert.NoError(c, err)
		assert.Len(c, result, 13)
	}, propagationTime, 200*time.Millisecond, "Verifying client can reach webservice through router 2 after failover")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		tr, err := client.Traceroute(webip)
		assert.NoError(c, err)
		ip, err := subRouter2.IPv4()
		if !assert.NoError(c, err, "failed to get IPv4 for subRouter2") {
			return
		}
		assertTracerouteViaIPWithCollect(c, tr, ip)
	}, propagationTime, 200*time.Millisecond, "Verifying traceroute goes through router 2 after failover")

	// Validate primary routes table state - router 2 is now primary after router 1 failure
	validatePrimaryRoutes(t, headscale, &routes.DebugRoutes{
		AvailableRoutes: map[types.NodeID][]netip.Prefix{
			// Router 1 is disconnected, so not in AvailableRoutes
			types.NodeID(MustFindNode(subRouter2.Hostname(), nodes).GetId()): {pref},
			types.NodeID(MustFindNode(subRouter3.Hostname(), nodes).GetId()): {pref},
		},
		PrimaryRoutes: map[string]types.NodeID{
			pref.String(): types.NodeID(MustFindNode(subRouter2.Hostname(), nodes).GetId()),
		},
	}, "Router 2 should be primary after router 1 failure")

	checkFailureAndPrintRoutes(t, client)

	// Take down subnet router 2, leaving none available
	t.Logf("=== FAILOVER TEST: Taking down NEW PRIMARY router 2 (%s) ===", subRouter2.Hostname())
	t.Logf("[%s] Starting test section", time.Now().Format(TimestampFormat))
	t.Logf("  Current state: Router 1 OFFLINE, Router 2 PRIMARY (serving traffic), Router 3 STANDBY")
	t.Logf("  Action: Shutting down router 2 to simulate cascading failure")
	t.Logf("  Expected: Router 3 (%s) should become new PRIMARY (last remaining router)", subRouter3.Hostname())
	t.Logf("  Expected: With only 1 router left, HA is effectively disabled")
	t.Logf("  Expected: Traffic continues through router 3")
	err = subRouter2.Down()
	require.NoError(t, err)

	// Wait for router status changes after r2 goes down
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		clientStatus, err = client.Status()
		assert.NoError(c, err)

		srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
		srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]
		srs3PeerStatus = clientStatus.Peer[srs3.Self.PublicKey]

		assert.NotNil(c, srs1PeerStatus, "Router 1 peer should exist")
		assert.NotNil(c, srs2PeerStatus, "Router 2 peer should exist")
		assert.NotNil(c, srs3PeerStatus, "Router 3 peer should exist")

		if srs1PeerStatus == nil || srs2PeerStatus == nil || srs3PeerStatus == nil {
			return
		}

		assert.False(c, srs1PeerStatus.Online, "Router 1 should still be offline")
		assert.False(c, srs2PeerStatus.Online, "Router 2 should now be offline after failure")
		assert.True(c, srs3PeerStatus.Online, "Router 3 should be online and taking over as PRIMARY")

		assert.Nil(c, srs1PeerStatus.PrimaryRoutes)
		assert.Nil(c, srs2PeerStatus.PrimaryRoutes)
		assert.NotNil(c, srs3PeerStatus.PrimaryRoutes)

		requirePeerSubnetRoutesWithCollect(c, srs1PeerStatus, nil)
		requirePeerSubnetRoutesWithCollect(c, srs2PeerStatus, nil)
		requirePeerSubnetRoutesWithCollect(c, srs3PeerStatus, []netip.Prefix{pref})
	}, propagationTime, 200*time.Millisecond, "Second failover verification: Router 1 & 2 offline, Router 3 should be new PRIMARY (last router standing) with routes")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, err := client.Curl(weburl)
		assert.NoError(c, err)
		assert.Len(c, result, 13)
	}, propagationTime, 200*time.Millisecond, "Verifying client can reach webservice through router 3 after second failover")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		tr, err := client.Traceroute(webip)
		assert.NoError(c, err)
		ip, err := subRouter3.IPv4()
		if !assert.NoError(c, err, "failed to get IPv4 for subRouter3") {
			return
		}
		assertTracerouteViaIPWithCollect(c, tr, ip)
	}, propagationTime, 200*time.Millisecond, "Verifying traceroute goes through router 3 after second failover")

	// Validate primary routes table state - router 3 is now primary after router 2 failure
	validatePrimaryRoutes(t, headscale, &routes.DebugRoutes{
		AvailableRoutes: map[types.NodeID][]netip.Prefix{
			// Routers 1 and 2 are disconnected, so not in AvailableRoutes
			types.NodeID(MustFindNode(subRouter3.Hostname(), nodes).GetId()): {pref},
		},
		PrimaryRoutes: map[string]types.NodeID{
			pref.String(): types.NodeID(MustFindNode(subRouter3.Hostname(), nodes).GetId()),
		},
	}, "Router 3 should be primary after router 2 failure")

	checkFailureAndPrintRoutes(t, client)

	// Bring up subnet router 1, making the route available from there.
	t.Logf("=== RECOVERY TEST: Bringing router 1 (%s) back online ===", subRouter1.Hostname())
	t.Logf("[%s] Starting test section", time.Now().Format(TimestampFormat))
	t.Logf("  Current state: Router 1 OFFLINE, Router 2 OFFLINE, Router 3 PRIMARY (only router)")
	t.Logf("  Action: Starting router 1 to restore HA capability")
	t.Logf("  Expected: Router 3 remains PRIMARY (stability - no unnecessary failover)")
	t.Logf("  Expected: Router 1 becomes STANDBY (ready for HA)")
	t.Logf("  Expected: HA is restored with 2 routers available")
	err = subRouter1.Up()
	require.NoError(t, err)

	// Wait for router status changes after r1 comes back up
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		clientStatus, err = client.Status()
		assert.NoError(c, err)

		srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
		srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]
		srs3PeerStatus = clientStatus.Peer[srs3.Self.PublicKey]

		assert.NotNil(c, srs1PeerStatus, "Router 1 peer should exist")
		assert.NotNil(c, srs2PeerStatus, "Router 2 peer should exist")
		assert.NotNil(c, srs3PeerStatus, "Router 3 peer should exist")

		if srs1PeerStatus == nil || srs2PeerStatus == nil || srs3PeerStatus == nil {
			return
		}

		assert.True(c, srs1PeerStatus.Online, "Router 1 should be back online as STANDBY")
		assert.False(c, srs2PeerStatus.Online, "Router 2 should still be offline")
		assert.True(c, srs3PeerStatus.Online, "Router 3 should remain online as PRIMARY")

		assert.Nil(c, srs1PeerStatus.PrimaryRoutes)
		assert.Nil(c, srs2PeerStatus.PrimaryRoutes)
		assert.NotNil(c, srs3PeerStatus.PrimaryRoutes)

		requirePeerSubnetRoutesWithCollect(c, srs1PeerStatus, nil)
		requirePeerSubnetRoutesWithCollect(c, srs2PeerStatus, nil)
		requirePeerSubnetRoutesWithCollect(c, srs3PeerStatus, []netip.Prefix{pref})

		if srs3PeerStatus.PrimaryRoutes != nil {
			assert.Contains(c,
				srs3PeerStatus.PrimaryRoutes.AsSlice(),
				pref,
			)
		}
	}, propagationTime, 200*time.Millisecond, "Recovery verification: Router 1 back online as STANDBY, Router 3 remains PRIMARY (no flapping) with routes")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, err := client.Curl(weburl)
		assert.NoError(c, err)
		assert.Len(c, result, 13)
	}, propagationTime, 200*time.Millisecond, "Verifying client can still reach webservice through router 3 after router 1 recovery")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		tr, err := client.Traceroute(webip)
		assert.NoError(c, err)
		ip, err := subRouter3.IPv4()
		if !assert.NoError(c, err, "failed to get IPv4 for subRouter3") {
			return
		}
		assertTracerouteViaIPWithCollect(c, tr, ip)
	}, propagationTime, 200*time.Millisecond, "Verifying traceroute still goes through router 3 after router 1 recovery")

	// Validate primary routes table state - router 3 remains primary after router 1 comes back
	validatePrimaryRoutes(t, headscale, &routes.DebugRoutes{
		AvailableRoutes: map[types.NodeID][]netip.Prefix{
			types.NodeID(MustFindNode(subRouter1.Hostname(), nodes).GetId()): {pref},
			// Router 2 is still disconnected
			types.NodeID(MustFindNode(subRouter3.Hostname(), nodes).GetId()): {pref},
		},
		PrimaryRoutes: map[string]types.NodeID{
			pref.String(): types.NodeID(MustFindNode(subRouter3.Hostname(), nodes).GetId()),
		},
	}, "Router 3 should remain primary after router 1 recovery")

	checkFailureAndPrintRoutes(t, client)

	// Bring up subnet router 2, should result in no change.
	t.Logf("=== FULL RECOVERY TEST: Bringing router 2 (%s) back online ===", subRouter2.Hostname())
	t.Logf("[%s] Starting test section", time.Now().Format(TimestampFormat))
	t.Logf("  Current state: Router 1 STANDBY, Router 2 OFFLINE, Router 3 PRIMARY")
	t.Logf("  Action: Starting router 2 to restore full HA (3 routers)")
	t.Logf("  Expected: Router 3 (%s) remains PRIMARY (stability - avoid unnecessary failovers)", subRouter3.Hostname())
	t.Logf("  Expected: Router 1 (%s) remains first STANDBY", subRouter1.Hostname())
	t.Logf("  Expected: Router 2 (%s) becomes second STANDBY", subRouter2.Hostname())
	t.Logf("  Expected: Full HA restored with all 3 routers online")
	err = subRouter2.Up()
	require.NoError(t, err)

	// Wait for nodestore batch processing to complete and online status to be updated
	// NodeStore batching timeout is 500ms, so we wait up to 10 seconds for all routers to be online
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		clientStatus, err = client.Status()
		assert.NoError(c, err)

		srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
		srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]
		srs3PeerStatus = clientStatus.Peer[srs3.Self.PublicKey]

		assert.NotNil(c, srs1PeerStatus, "Router 1 peer should exist")
		assert.NotNil(c, srs2PeerStatus, "Router 2 peer should exist")
		assert.NotNil(c, srs3PeerStatus, "Router 3 peer should exist")

		if srs1PeerStatus == nil || srs2PeerStatus == nil || srs3PeerStatus == nil {
			return
		}

		assert.True(c, srs1PeerStatus.Online, "Router 1 should be online as STANDBY")
		assert.True(c, srs2PeerStatus.Online, "Router 2 should be back online as STANDBY")
		assert.True(c, srs3PeerStatus.Online, "Router 3 should remain online as PRIMARY")

		assert.Nil(c, srs1PeerStatus.PrimaryRoutes)
		assert.Nil(c, srs2PeerStatus.PrimaryRoutes)
		assert.NotNil(c, srs3PeerStatus.PrimaryRoutes)

		requirePeerSubnetRoutesWithCollect(c, srs1PeerStatus, nil)
		requirePeerSubnetRoutesWithCollect(c, srs2PeerStatus, nil)
		requirePeerSubnetRoutesWithCollect(c, srs3PeerStatus, []netip.Prefix{pref})

		if srs3PeerStatus.PrimaryRoutes != nil {
			assert.Contains(c,
				srs3PeerStatus.PrimaryRoutes.AsSlice(),
				pref,
			)
		}
	}, 10*time.Second, 500*time.Millisecond, "Full recovery verification: All 3 routers online, Router 3 remains PRIMARY (no flapping) with routes")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, err := client.Curl(weburl)
		assert.NoError(c, err)
		assert.Len(c, result, 13)
	}, propagationTime, 200*time.Millisecond, "Verifying client can reach webservice through router 3 after full recovery")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		tr, err := client.Traceroute(webip)
		assert.NoError(c, err)
		ip, err := subRouter3.IPv4()
		if !assert.NoError(c, err, "failed to get IPv4 for subRouter3") {
			return
		}
		assertTracerouteViaIPWithCollect(c, tr, ip)
	}, propagationTime, 200*time.Millisecond, "Verifying traceroute goes through router 3 after full recovery")

	// Validate primary routes table state - router 3 remains primary after all routers back online
	validatePrimaryRoutes(t, headscale, &routes.DebugRoutes{
		AvailableRoutes: map[types.NodeID][]netip.Prefix{
			types.NodeID(MustFindNode(subRouter1.Hostname(), nodes).GetId()): {pref},
			types.NodeID(MustFindNode(subRouter2.Hostname(), nodes).GetId()): {pref},
			types.NodeID(MustFindNode(subRouter3.Hostname(), nodes).GetId()): {pref},
		},
		PrimaryRoutes: map[string]types.NodeID{
			pref.String(): types.NodeID(MustFindNode(subRouter3.Hostname(), nodes).GetId()),
		},
	}, "Router 3 should remain primary after full recovery")

	checkFailureAndPrintRoutes(t, client)

	t.Logf("=== ROUTE DISABLE TEST: Removing approved route from PRIMARY router 3 (%s) ===", subRouter3.Hostname())
	t.Logf("[%s] Starting test section", time.Now().Format(TimestampFormat))
	t.Logf("  Current state: Router 1 STANDBY, Router 2 STANDBY, Router 3 PRIMARY")
	t.Logf("  Action: Disabling route approval on router 3 (route still advertised but not approved)")
	t.Logf("  Expected: Router 1 (%s) should become new PRIMARY (lowest ID with approved route)", subRouter1.Hostname())
	t.Logf("  Expected: Router 2 (%s) remains STANDBY", subRouter2.Hostname())
	t.Logf("  Expected: Router 3 (%s) goes to advertised-only state (no longer serving)", subRouter3.Hostname())
	_, err = headscale.ApproveRoutes(MustFindNode(subRouter3.Hostname(), nodes).GetId(), []netip.Prefix{})

	// Wait for nodestore batch processing and route state changes to complete
	// NodeStore batching timeout is 500ms, so we wait up to 10 seconds for route failover
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 6)

		// After disabling route on r3, r1 should become primary with 1 subnet route
		requireNodeRouteCountWithCollect(c, MustFindNode(subRouter1.Hostname(), nodes), 1, 1, 1)
		requireNodeRouteCountWithCollect(c, MustFindNode(subRouter2.Hostname(), nodes), 1, 1, 0)
		requireNodeRouteCountWithCollect(c, MustFindNode(subRouter3.Hostname(), nodes), 1, 0, 0)
	}, 10*time.Second, 500*time.Millisecond, "Route disable verification: Router 3 route disabled, Router 1 should be new PRIMARY, Router 2 STANDBY")

	// Verify that the route is announced from subnet router 1
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		clientStatus, err = client.Status()
		assert.NoError(c, err)

		srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
		srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]
		srs3PeerStatus = clientStatus.Peer[srs3.Self.PublicKey]

		assert.NotNil(c, srs1PeerStatus, "Router 1 peer should exist")
		assert.NotNil(c, srs2PeerStatus, "Router 2 peer should exist")
		assert.NotNil(c, srs3PeerStatus, "Router 3 peer should exist")

		if srs1PeerStatus == nil || srs2PeerStatus == nil || srs3PeerStatus == nil {
			return
		}

		assert.NotNil(c, srs1PeerStatus.PrimaryRoutes)
		assert.Nil(c, srs2PeerStatus.PrimaryRoutes)
		assert.Nil(c, srs3PeerStatus.PrimaryRoutes)

		requirePeerSubnetRoutesWithCollect(c, srs1PeerStatus, []netip.Prefix{pref})
		requirePeerSubnetRoutesWithCollect(c, srs2PeerStatus, nil)
		requirePeerSubnetRoutesWithCollect(c, srs3PeerStatus, nil)

		if srs1PeerStatus.PrimaryRoutes != nil {
			assert.Contains(c,
				srs1PeerStatus.PrimaryRoutes.AsSlice(),
				pref,
			)
		}
	}, propagationTime, 200*time.Millisecond, "Verifying Router 1 becomes PRIMARY after Router 3 route disabled")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, err := client.Curl(weburl)
		assert.NoError(c, err)
		assert.Len(c, result, 13)
	}, propagationTime, 200*time.Millisecond, "Verifying client can reach webservice through router 1 after route disable")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		tr, err := client.Traceroute(webip)
		assert.NoError(c, err)
		ip, err := subRouter1.IPv4()
		if !assert.NoError(c, err, "failed to get IPv4 for subRouter1") {
			return
		}
		assertTracerouteViaIPWithCollect(c, tr, ip)
	}, propagationTime, 200*time.Millisecond, "Verifying traceroute goes through router 1 after route disable")

	// Validate primary routes table state - router 1 is primary after router 3 route disabled
	validatePrimaryRoutes(t, headscale, &routes.DebugRoutes{
		AvailableRoutes: map[types.NodeID][]netip.Prefix{
			types.NodeID(MustFindNode(subRouter1.Hostname(), nodes).GetId()): {pref},
			types.NodeID(MustFindNode(subRouter2.Hostname(), nodes).GetId()): {pref},
			// Router 3's route is no longer approved, so not in AvailableRoutes
		},
		PrimaryRoutes: map[string]types.NodeID{
			pref.String(): types.NodeID(MustFindNode(subRouter1.Hostname(), nodes).GetId()),
		},
	}, "Router 1 should be primary after router 3 route disabled")

	checkFailureAndPrintRoutes(t, client)

	// Disable the route of subnet router 1, making it failover to 2
	t.Logf("=== ROUTE DISABLE TEST: Removing approved route from NEW PRIMARY router 1 (%s) ===", subRouter1.Hostname())
	t.Logf("[%s] Starting test section", time.Now().Format(TimestampFormat))
	t.Logf("  Current state: Router 1 PRIMARY, Router 2 STANDBY, Router 3 advertised-only")
	t.Logf("  Action: Disabling route approval on router 1")
	t.Logf("  Expected: Router 2 (%s) should become new PRIMARY (only remaining approved route)", subRouter2.Hostname())
	t.Logf("  Expected: Router 1 (%s) goes to advertised-only state", subRouter1.Hostname())
	t.Logf("  Expected: Router 3 (%s) remains advertised-only", subRouter3.Hostname())
	_, err = headscale.ApproveRoutes(MustFindNode(subRouter1.Hostname(), nodes).GetId(), []netip.Prefix{})

	// Wait for nodestore batch processing and route state changes to complete
	// NodeStore batching timeout is 500ms, so we wait up to 10 seconds for route failover
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 6)

		// After disabling route on r1, r2 should become primary with 1 subnet route
		requireNodeRouteCountWithCollect(c, MustFindNode(subRouter1.Hostname(), nodes), 1, 0, 0)
		requireNodeRouteCountWithCollect(c, MustFindNode(subRouter2.Hostname(), nodes), 1, 1, 1)
		requireNodeRouteCountWithCollect(c, MustFindNode(subRouter3.Hostname(), nodes), 1, 0, 0)
	}, 10*time.Second, 500*time.Millisecond, "Second route disable verification: Router 1 route disabled, Router 2 should be new PRIMARY")

	// Verify that the route is announced from subnet router 1
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		clientStatus, err = client.Status()
		assert.NoError(c, err)

		srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
		srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]
		srs3PeerStatus = clientStatus.Peer[srs3.Self.PublicKey]

		assert.NotNil(c, srs1PeerStatus, "Router 1 peer should exist")
		assert.NotNil(c, srs2PeerStatus, "Router 2 peer should exist")
		assert.NotNil(c, srs3PeerStatus, "Router 3 peer should exist")

		if srs1PeerStatus == nil || srs2PeerStatus == nil || srs3PeerStatus == nil {
			return
		}

		assert.Nil(c, srs1PeerStatus.PrimaryRoutes)
		assert.NotNil(c, srs2PeerStatus.PrimaryRoutes)
		assert.Nil(c, srs3PeerStatus.PrimaryRoutes)

		requirePeerSubnetRoutesWithCollect(c, srs1PeerStatus, nil)
		requirePeerSubnetRoutesWithCollect(c, srs2PeerStatus, []netip.Prefix{pref})
		requirePeerSubnetRoutesWithCollect(c, srs3PeerStatus, nil)

		if srs2PeerStatus.PrimaryRoutes != nil {
			assert.Contains(c,
				srs2PeerStatus.PrimaryRoutes.AsSlice(),
				pref,
			)
		}
	}, propagationTime, 200*time.Millisecond, "Verifying Router 2 becomes PRIMARY after Router 1 route disabled")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, err := client.Curl(weburl)
		assert.NoError(c, err)
		assert.Len(c, result, 13)
	}, propagationTime, 200*time.Millisecond, "Verifying client can reach webservice through router 2 after second route disable")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		tr, err := client.Traceroute(webip)
		assert.NoError(c, err)
		ip, err := subRouter2.IPv4()
		if !assert.NoError(c, err, "failed to get IPv4 for subRouter2") {
			return
		}
		assertTracerouteViaIPWithCollect(c, tr, ip)
	}, propagationTime, 200*time.Millisecond, "Verifying traceroute goes through router 2 after second route disable")

	// Validate primary routes table state - router 2 is primary after router 1 route disabled
	validatePrimaryRoutes(t, headscale, &routes.DebugRoutes{
		AvailableRoutes: map[types.NodeID][]netip.Prefix{
			// Router 1's route is no longer approved, so not in AvailableRoutes
			types.NodeID(MustFindNode(subRouter2.Hostname(), nodes).GetId()): {pref},
			// Router 3's route is still not approved
		},
		PrimaryRoutes: map[string]types.NodeID{
			pref.String(): types.NodeID(MustFindNode(subRouter2.Hostname(), nodes).GetId()),
		},
	}, "Router 2 should be primary after router 1 route disabled")

	checkFailureAndPrintRoutes(t, client)

	// enable the route of subnet router 1, no change expected
	t.Logf("=== ROUTE RE-ENABLE TEST: Re-approving route on router 1 (%s) ===", subRouter1.Hostname())
	t.Logf("[%s] Starting test section", time.Now().Format(TimestampFormat))
	t.Logf("  Current state: Router 1 advertised-only, Router 2 PRIMARY, Router 3 advertised-only")
	t.Logf("  Action: Re-enabling route approval on router 1")
	t.Logf("  Expected: Router 2 (%s) remains PRIMARY (stability - no unnecessary flapping)", subRouter2.Hostname())
	t.Logf("  Expected: Router 1 (%s) becomes STANDBY (approved but not primary)", subRouter1.Hostname())
	t.Logf("  Expected: HA fully restored with Router 2 PRIMARY and Router 1 STANDBY")
	r1Node := MustFindNode(subRouter1.Hostname(), nodes)
	_, err = headscale.ApproveRoutes(
		r1Node.GetId(),
		util.MustStringsToPrefixes(r1Node.GetAvailableRoutes()),
	)

	// Wait for route state changes after re-enabling r1
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 6)

		requireNodeRouteCountWithCollect(c, MustFindNode(subRouter1.Hostname(), nodes), 1, 1, 0)
		requireNodeRouteCountWithCollect(c, MustFindNode(subRouter2.Hostname(), nodes), 1, 1, 1)
		requireNodeRouteCountWithCollect(c, MustFindNode(subRouter3.Hostname(), nodes), 1, 0, 0)
	}, propagationTime, 200*time.Millisecond, "Re-enable verification: Router 1 approved as STANDBY, Router 2 remains PRIMARY (no flapping), full HA restored")

	// Verify that the route is announced from subnet router 1
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		clientStatus, err = client.Status()
		assert.NoError(c, err)

		srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
		srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]
		srs3PeerStatus = clientStatus.Peer[srs3.Self.PublicKey]

		assert.NotNil(c, srs1PeerStatus, "Router 1 peer should exist")
		assert.NotNil(c, srs2PeerStatus, "Router 2 peer should exist")
		assert.NotNil(c, srs3PeerStatus, "Router 3 peer should exist")

		if srs1PeerStatus == nil || srs2PeerStatus == nil || srs3PeerStatus == nil {
			return
		}

		assert.Nil(c, srs1PeerStatus.PrimaryRoutes)
		assert.NotNil(c, srs2PeerStatus.PrimaryRoutes)
		assert.Nil(c, srs3PeerStatus.PrimaryRoutes)

		if srs2PeerStatus.PrimaryRoutes != nil {
			assert.Contains(c,
				srs2PeerStatus.PrimaryRoutes.AsSlice(),
				pref,
			)
		}
	}, propagationTime, 200*time.Millisecond, "Verifying Router 2 remains PRIMARY after Router 1 route re-enabled")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, err := client.Curl(weburl)
		assert.NoError(c, err)
		assert.Len(c, result, 13)
	}, propagationTime, 200*time.Millisecond, "Verifying client can reach webservice through router 2 after route re-enable")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		tr, err := client.Traceroute(webip)
		assert.NoError(c, err)
		ip, err := subRouter2.IPv4()
		if !assert.NoError(c, err, "failed to get IPv4 for subRouter2") {
			return
		}
		assertTracerouteViaIPWithCollect(c, tr, ip)
	}, propagationTime, 200*time.Millisecond, "Verifying traceroute still goes through router 2 after route re-enable")

	// Validate primary routes table state after router 1 re-approval
	validatePrimaryRoutes(t, headscale, &routes.DebugRoutes{
		AvailableRoutes: map[types.NodeID][]netip.Prefix{
			types.NodeID(MustFindNode(subRouter1.Hostname(), nodes).GetId()): {pref},
			types.NodeID(MustFindNode(subRouter2.Hostname(), nodes).GetId()): {pref},
			// Router 3 route is still not approved
		},
		PrimaryRoutes: map[string]types.NodeID{
			pref.String(): types.NodeID(MustFindNode(subRouter2.Hostname(), nodes).GetId()),
		},
	}, "Router 2 should remain primary after router 1 re-approval")

	checkFailureAndPrintRoutes(t, client)

	// Enable route on node 3, we now have all routes re-enabled
	t.Logf("=== ROUTE RE-ENABLE TEST: Re-approving route on router 3 (%s) - Full HA Restoration ===", subRouter3.Hostname())
	t.Logf("[%s] Starting test section", time.Now().Format(TimestampFormat))
	t.Logf("  Current state: Router 1 STANDBY, Router 2 PRIMARY, Router 3 advertised-only")
	t.Logf("  Action: Re-enabling route approval on router 3")
	t.Logf("  Expected: Router 2 (%s) remains PRIMARY (stability preferred)", subRouter2.Hostname())
	t.Logf("  Expected: Routers 1 & 3 are both STANDBY")
	t.Logf("  Expected: Full HA restored with all 3 routers available")
	r3Node := MustFindNode(subRouter3.Hostname(), nodes)
	_, err = headscale.ApproveRoutes(
		r3Node.GetId(),
		util.MustStringsToPrefixes(r3Node.GetAvailableRoutes()),
	)

	// Wait for route state changes after re-enabling r3
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 6)
		require.GreaterOrEqual(t, len(nodes), 3, "need at least 3 nodes to avoid panic")
		// After router 3 re-approval: Router 2 remains PRIMARY, Routers 1&3 are STANDBY
		// SubnetRoutes should only show routes for PRIMARY node (actively serving)
		requireNodeRouteCountWithCollect(c, nodes[0], 1, 1, 0) // Router 1: STANDBY (available, approved, but not serving)
		requireNodeRouteCountWithCollect(c, nodes[1], 1, 1, 1) // Router 2: PRIMARY (available, approved, and serving)
		requireNodeRouteCountWithCollect(c, nodes[2], 1, 1, 0) // Router 3: STANDBY (available, approved, but not serving)
	}, propagationTime, 200*time.Millisecond, "Waiting for route state after router 3 re-approval")

	// Validate primary routes table state after router 3 re-approval
	validatePrimaryRoutes(t, headscale, &routes.DebugRoutes{
		AvailableRoutes: map[types.NodeID][]netip.Prefix{
			types.NodeID(MustFindNode(subRouter1.Hostname(), nodes).GetId()): {pref},
			types.NodeID(MustFindNode(subRouter2.Hostname(), nodes).GetId()): {pref},
			types.NodeID(MustFindNode(subRouter3.Hostname(), nodes).GetId()): {pref},
		},
		PrimaryRoutes: map[string]types.NodeID{
			pref.String(): types.NodeID(MustFindNode(subRouter2.Hostname(), nodes).GetId()),
		},
	}, "Router 2 should remain primary after router 3 re-approval")

	checkFailureAndPrintRoutes(t, client)
}

// TestSubnetRouteACL verifies that Subnet routes are distributed
// as expected when ACLs are activated.
// It implements the issue from
// https://github.com/juanfont/headscale/issues/1604
func TestSubnetRouteACL(t *testing.T) {
	IntegrationSkip(t)

	user := "user4"

	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{user},
	}

	scenario, err := NewScenario(spec)
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{
		tsic.WithAcceptRoutes(),
	}, hsic.WithTestName("clienableroute"), hsic.WithACLPolicy(
		&policyv2.Policy{
			Groups: policyv2.Groups{
				policyv2.Group("group:admins"): []policyv2.Username{policyv2.Username(user + "@")},
			},
			ACLs: []policyv2.ACL{
				{
					Action:  "accept",
					Sources: []policyv2.Alias{groupp("group:admins")},
					Destinations: []policyv2.AliasWithPorts{
						aliasWithPorts(groupp("group:admins"), tailcfg.PortRangeAny),
					},
				},
				{
					Action:  "accept",
					Sources: []policyv2.Alias{groupp("group:admins")},
					Destinations: []policyv2.AliasWithPorts{
						aliasWithPorts(prefixp("10.33.0.0/16"), tailcfg.PortRangeAny),
					},
				},
			},
		},
	))
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	expectedRoutes := map[string]string{
		"1": "10.33.0.0/16",
	}

	// Sort nodes by ID
	sort.SliceStable(allClients, func(i, j int) bool {
		statusI := allClients[i].MustStatus()
		statusJ := allClients[j].MustStatus()
		return statusI.Self.ID < statusJ.Self.ID
	})

	subRouter1 := allClients[0]

	client := allClients[1]

	for _, client := range allClients {
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			status, err := client.Status()
			assert.NoError(c, err)

			if route, ok := expectedRoutes[string(status.Self.ID)]; ok {
				command := []string{
					"tailscale",
					"set",
					"--advertise-routes=" + route,
				}
				_, _, err = client.Execute(command)
				assert.NoErrorf(c, err, "failed to advertise route: %s", err)
			}
		}, 5*time.Second, 200*time.Millisecond, "Configuring route advertisements")
	}

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	// Wait for route advertisements to propagate to the server
	var nodes []*v1.Node
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		var err error
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 2)

		// Find the node that should have the route by checking node IDs
		var routeNode *v1.Node
		var otherNode *v1.Node
		for _, node := range nodes {
			nodeIDStr := strconv.FormatUint(node.GetId(), 10)
			if _, shouldHaveRoute := expectedRoutes[nodeIDStr]; shouldHaveRoute {
				routeNode = node
			} else {
				otherNode = node
			}
		}

		assert.NotNil(c, routeNode, "could not find node that should have route")
		assert.NotNil(c, otherNode, "could not find node that should not have route")

		// After NodeStore fix: routes are properly tracked in route manager
		// This test uses a policy with NO auto-approvers, so routes should be:
		// announced=1, approved=0, subnet=0 (routes announced but not approved)
		requireNodeRouteCountWithCollect(c, routeNode, 1, 0, 0)
		requireNodeRouteCountWithCollect(c, otherNode, 0, 0, 0)
	}, 10*time.Second, 100*time.Millisecond, "route advertisements should propagate to server")

	// Verify that no routes has been sent to the client,
	// they are not yet enabled.
	for _, client := range allClients {
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			status, err := client.Status()
			assert.NoError(c, err)

			for _, peerKey := range status.Peers() {
				peerStatus := status.Peer[peerKey]

				assert.Nil(c, peerStatus.PrimaryRoutes)
				requirePeerSubnetRoutesWithCollect(c, peerStatus, nil)
			}
		}, 5*time.Second, 200*time.Millisecond, "Verifying no routes are active before approval")
	}

	_, err = headscale.ApproveRoutes(
		1,
		[]netip.Prefix{netip.MustParsePrefix(expectedRoutes["1"])},
	)
	require.NoError(t, err)

	// Wait for route state changes to propagate to nodes
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 2)

		requireNodeRouteCountWithCollect(c, nodes[0], 1, 1, 1)
		requireNodeRouteCountWithCollect(c, nodes[1], 0, 0, 0)
	}, 10*time.Second, 500*time.Millisecond, "route state changes should propagate to nodes")

	// Verify that the client has routes from the primary machine
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		srs1, err := subRouter1.Status()
		assert.NoError(c, err)

		clientStatus, err := client.Status()
		assert.NoError(c, err)

		srs1PeerStatus := clientStatus.Peer[srs1.Self.PublicKey]

		assert.NotNil(c, srs1PeerStatus, "Router 1 peer should exist")
		if srs1PeerStatus == nil {
			return
		}

		requirePeerSubnetRoutesWithCollect(c, srs1PeerStatus, []netip.Prefix{netip.MustParsePrefix(expectedRoutes["1"])})
	}, 5*time.Second, 200*time.Millisecond, "Verifying client can see subnet routes from router")

	// Wait for packet filter updates to propagate to client netmap
	wantClientFilter := []filter.Match{
		{
			IPProto: views.SliceOf([]ipproto.Proto{
				ipproto.TCP, ipproto.UDP,
			}),
			Srcs: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("100.64.0.2/32"),
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
				netip.MustParsePrefix("fd7a:115c:a1e0::2/128"),
			},
			Dsts: []filter.NetPortRange{
				{
					Net:   netip.MustParsePrefix("100.64.0.2/32"),
					Ports: allPorts,
				},
				{
					Net:   netip.MustParsePrefix("fd7a:115c:a1e0::2/128"),
					Ports: allPorts,
				},
			},
			Caps: []filter.CapMatch{},
		},
	}

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		clientNm, err := client.Netmap()
		assert.NoError(c, err)

		if diff := cmpdiff.Diff(wantClientFilter, clientNm.PacketFilter, util.ViewSliceIPProtoComparer, util.PrefixComparer); diff != "" {
			assert.Fail(c, fmt.Sprintf("Client (%s) filter, unexpected result (-want +got):\n%s", client.Hostname(), diff))
		}
	}, 10*time.Second, 200*time.Millisecond, "Waiting for client packet filter to update")

	// Wait for packet filter updates to propagate to subnet router netmap
	wantSubnetFilter := []filter.Match{
		{
			IPProto: views.SliceOf([]ipproto.Proto{
				ipproto.TCP, ipproto.UDP,
			}),
			Srcs: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("100.64.0.2/32"),
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
				netip.MustParsePrefix("fd7a:115c:a1e0::2/128"),
			},
			Dsts: []filter.NetPortRange{
				{
					Net:   netip.MustParsePrefix("100.64.0.1/32"),
					Ports: allPorts,
				},
				{
					Net:   netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
					Ports: allPorts,
				},
			},
			Caps: []filter.CapMatch{},
		},
		{
			IPProto: views.SliceOf([]ipproto.Proto{
				ipproto.TCP, ipproto.UDP,
			}),
			Srcs: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("100.64.0.2/32"),
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
				netip.MustParsePrefix("fd7a:115c:a1e0::2/128"),
			},
			Dsts: []filter.NetPortRange{
				{
					Net:   netip.MustParsePrefix("10.33.0.0/16"),
					Ports: allPorts,
				},
			},
			Caps: []filter.CapMatch{},
		},
	}

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		subnetNm, err := subRouter1.Netmap()
		assert.NoError(c, err)

		if diff := cmpdiff.Diff(wantSubnetFilter, subnetNm.PacketFilter, util.ViewSliceIPProtoComparer, util.PrefixComparer); diff != "" {
			assert.Fail(c, fmt.Sprintf("Subnet (%s) filter, unexpected result (-want +got):\n%s", subRouter1.Hostname(), diff))
		}
	}, 10*time.Second, 200*time.Millisecond, "Waiting for subnet router packet filter to update")
}

// TestEnablingExitRoutes tests enabling exit routes for clients.
// Its more or less the same as TestEnablingRoutes, but with the --advertise-exit-node flag
// set during login instead of set.
func TestEnablingExitRoutes(t *testing.T) {
	IntegrationSkip(t)

	user := "user2"

	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{user},
	}

	scenario, err := NewScenario(spec)
	require.NoErrorf(t, err, "failed to create scenario")
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{
		tsic.WithExtraLoginArgs([]string{"--advertise-exit-node"}),
	}, hsic.WithTestName("clienableroute"))
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	var nodes []*v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var err error
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 2)

		requireNodeRouteCountWithCollect(c, nodes[0], 2, 0, 0)
		requireNodeRouteCountWithCollect(c, nodes[1], 2, 0, 0)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for route advertisements to propagate")

	// Verify that no routes has been sent to the client,
	// they are not yet enabled.
	for _, client := range allClients {
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			status, err := client.Status()
			assert.NoError(c, err)

			for _, peerKey := range status.Peers() {
				peerStatus := status.Peer[peerKey]

				assert.Nil(c, peerStatus.PrimaryRoutes)
			}
		}, 5*time.Second, 200*time.Millisecond, "Verifying no exit routes are active before approval")
	}

	// Enable all routes, but do v4 on one and v6 on other to ensure they
	// are both added since they are exit routes.
	_, err = headscale.ApproveRoutes(
		nodes[0].GetId(),
		[]netip.Prefix{tsaddr.AllIPv4()},
	)
	require.NoError(t, err)
	_, err = headscale.ApproveRoutes(
		nodes[1].GetId(),
		[]netip.Prefix{tsaddr.AllIPv6()},
	)
	require.NoError(t, err)

	// Wait for route state changes to propagate
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 2)

		requireNodeRouteCountWithCollect(c, nodes[0], 2, 2, 2)
		requireNodeRouteCountWithCollect(c, nodes[1], 2, 2, 2)
	}, 10*time.Second, 500*time.Millisecond, "route state changes should propagate to both nodes")

	// Wait for route state changes to propagate to clients
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		// Verify that the clients can see the new routes
		for _, client := range allClients {
			status, err := client.Status()
			assert.NoError(c, err)

			for _, peerKey := range status.Peers() {
				peerStatus := status.Peer[peerKey]

				assert.NotNil(c, peerStatus.AllowedIPs)
				if peerStatus.AllowedIPs != nil {
					assert.Len(c, peerStatus.AllowedIPs.AsSlice(), 4)
					assert.Contains(c, peerStatus.AllowedIPs.AsSlice(), tsaddr.AllIPv4())
					assert.Contains(c, peerStatus.AllowedIPs.AsSlice(), tsaddr.AllIPv6())
				}
			}
		}
	}, 10*time.Second, 500*time.Millisecond, "clients should see new routes")
}

// TestSubnetRouterMultiNetwork is an evolution of the subnet router test.
// This test will set up multiple docker networks and use two isolated tailscale
// clients and a service available in one of the networks to validate that a
// subnet router is working as expected.
func TestSubnetRouterMultiNetwork(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1", "user2"},
		Networks: map[string][]string{
			"usernet1": {"user1"},
			"usernet2": {"user2"},
		},
		ExtraService: map[string][]extraServiceFunc{
			"usernet1": {Webservice},
		},
	}

	scenario, err := NewScenario(spec)
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{tsic.WithAcceptRoutes()},
		hsic.WithTestName("clienableroute"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)
	assert.NotNil(t, headscale)

	pref, err := scenario.SubnetOfNetwork("usernet1")
	require.NoError(t, err)

	var user1c, user2c TailscaleClient

	for _, c := range allClients {
		s := c.MustStatus()
		if s.User[s.Self.UserID].LoginName == "user1@test.no" {
			user1c = c
		}
		if s.User[s.Self.UserID].LoginName == "user2@test.no" {
			user2c = c
		}
	}
	require.NotNil(t, user1c)
	require.NotNil(t, user2c)

	// Advertise the route for the dockersubnet of user1
	command := []string{
		"tailscale",
		"set",
		"--advertise-routes=" + pref.String(),
	}
	_, _, err = user1c.Execute(command)
	require.NoErrorf(t, err, "failed to advertise route: %s", err)

	var nodes []*v1.Node
	// Wait for route advertisements to propagate to NodeStore
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		nodes, err = headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, nodes, 2)
		requireNodeRouteCountWithCollect(ct, nodes[0], 1, 0, 0)
	}, 10*time.Second, 100*time.Millisecond, "route advertisements should propagate")

	// Verify that no routes has been sent to the client,
	// they are not yet enabled.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := user1c.Status()
		assert.NoError(c, err)

		for _, peerKey := range status.Peers() {
			peerStatus := status.Peer[peerKey]

			assert.Nil(c, peerStatus.PrimaryRoutes)
			requirePeerSubnetRoutesWithCollect(c, peerStatus, nil)
		}
	}, 5*time.Second, 200*time.Millisecond, "Verifying no routes are active before approval")

	// Enable route
	_, err = headscale.ApproveRoutes(
		nodes[0].GetId(),
		[]netip.Prefix{*pref},
	)
	require.NoError(t, err)

	// Wait for route state changes to propagate to nodes
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var err error
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 2)
		requireNodeRouteCountWithCollect(c, nodes[0], 1, 1, 1)
	}, 10*time.Second, 500*time.Millisecond, "route state changes should propagate to nodes")

	// Verify that the routes have been sent to the client
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := user2c.Status()
		assert.NoError(c, err)

		for _, peerKey := range status.Peers() {
			peerStatus := status.Peer[peerKey]

			if peerStatus.PrimaryRoutes != nil {
				assert.Contains(c, peerStatus.PrimaryRoutes.AsSlice(), *pref)
			}
			requirePeerSubnetRoutesWithCollect(c, peerStatus, []netip.Prefix{*pref})
		}
	}, 10*time.Second, 500*time.Millisecond, "routes should be visible to client")

	usernet1, err := scenario.Network("usernet1")
	require.NoError(t, err)

	services, err := scenario.Services("usernet1")
	require.NoError(t, err)
	require.Len(t, services, 1)

	web := services[0]
	webip := netip.MustParseAddr(web.GetIPInNetwork(usernet1))

	url := fmt.Sprintf("http://%s/etc/hostname", webip)
	t.Logf("url from %s to %s", user2c.Hostname(), url)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, err := user2c.Curl(url)
		assert.NoError(c, err)
		assert.Len(c, result, 13)
	}, 5*time.Second, 200*time.Millisecond, "Verifying client can reach webservice through subnet route")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		tr, err := user2c.Traceroute(webip)
		assert.NoError(c, err)
		ip, err := user1c.IPv4()
		if !assert.NoError(c, err, "failed to get IPv4 for user1c") {
			return
		}
		assertTracerouteViaIPWithCollect(c, tr, ip)
	}, 5*time.Second, 200*time.Millisecond, "Verifying traceroute goes through subnet router")
}

func TestSubnetRouterMultiNetworkExitNode(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1", "user2"},
		Networks: map[string][]string{
			"usernet1": {"user1"},
			"usernet2": {"user2"},
		},
		ExtraService: map[string][]extraServiceFunc{
			"usernet1": {Webservice},
		},
	}

	scenario, err := NewScenario(spec)
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{},
		hsic.WithTestName("clienableroute"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)
	assert.NotNil(t, headscale)

	var user1c, user2c TailscaleClient

	for _, c := range allClients {
		s := c.MustStatus()
		if s.User[s.Self.UserID].LoginName == "user1@test.no" {
			user1c = c
		}
		if s.User[s.Self.UserID].LoginName == "user2@test.no" {
			user2c = c
		}
	}
	require.NotNil(t, user1c)
	require.NotNil(t, user2c)

	// Advertise the exit nodes for the dockersubnet of user1
	command := []string{
		"tailscale",
		"set",
		"--advertise-exit-node",
	}
	_, _, err = user1c.Execute(command)
	require.NoErrorf(t, err, "failed to advertise route: %s", err)

	var nodes []*v1.Node
	// Wait for route advertisements to propagate to NodeStore
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		nodes, err = headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, nodes, 2)
		requireNodeRouteCountWithCollect(ct, nodes[0], 2, 0, 0)
	}, 10*time.Second, 100*time.Millisecond, "route advertisements should propagate")

	// Verify that no routes has been sent to the client,
	// they are not yet enabled.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := user1c.Status()
		assert.NoError(c, err)

		for _, peerKey := range status.Peers() {
			peerStatus := status.Peer[peerKey]

			assert.Nil(c, peerStatus.PrimaryRoutes)
			requirePeerSubnetRoutesWithCollect(c, peerStatus, nil)
		}
	}, 5*time.Second, 200*time.Millisecond, "Verifying no routes sent to client before approval")

	// Enable route
	_, err = headscale.ApproveRoutes(nodes[0].GetId(), []netip.Prefix{tsaddr.AllIPv4()})
	require.NoError(t, err)

	// Wait for route state changes to propagate to nodes
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, 2)
		requireNodeRouteCountWithCollect(c, nodes[0], 2, 2, 2)
	}, 10*time.Second, 500*time.Millisecond, "route state changes should propagate to nodes")

	// Verify that the routes have been sent to the client
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := user2c.Status()
		assert.NoError(c, err)

		for _, peerKey := range status.Peers() {
			peerStatus := status.Peer[peerKey]

			requirePeerSubnetRoutesWithCollect(c, peerStatus, []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6()})
		}
	}, 10*time.Second, 500*time.Millisecond, "routes should be visible to client")

	// Tell user2c to use user1c as an exit node.
	command = []string{
		"tailscale",
		"set",
		"--exit-node",
		user1c.Hostname(),
	}
	_, _, err = user2c.Execute(command)
	require.NoErrorf(t, err, "failed to advertise route: %s", err)

	usernet1, err := scenario.Network("usernet1")
	require.NoError(t, err)

	services, err := scenario.Services("usernet1")
	require.NoError(t, err)
	require.Len(t, services, 1)

	web := services[0]
	webip := netip.MustParseAddr(web.GetIPInNetwork(usernet1))

	// We can't mess to much with ip forwarding in containers so
	// we settle for a simple ping here.
	// Direct is false since we use internal DERP which means we
	// can't discover a direct path between docker networks.
	err = user2c.Ping(webip.String(),
		tsic.WithPingUntilDirect(false),
		tsic.WithPingCount(1),
		tsic.WithPingTimeout(7*time.Second),
	)
	require.NoError(t, err)
}

func MustFindNode(hostname string, nodes []*v1.Node) *v1.Node {
	for _, node := range nodes {
		if node.GetName() == hostname {
			return node
		}
	}
	panic("node not found")
}

// TestAutoApproveMultiNetwork tests auto approving of routes
// by setting up two networks where network1 has three subnet
// routers:
// - routerUsernet1: advertising the docker network
// - routerSubRoute: advertising a subroute, a /24 inside a auto approved /16
// - routeExitNode: advertising an exit node
//
// Each router is tested step by step through the following scenarios
//   - Policy is set to auto approve the nodes route
//   - Node advertises route and it is verified that it is auto approved and sent to nodes
//   - Policy is changed to _not_ auto approve the route
//   - Verify that peers can still see the node
//   - Disable route, making it unavailable
//   - Verify that peers can no longer use node
//   - Policy is changed back to auto approve route, check that routes already existing is approved.
//   - Verify that routes can now be seen by peers.
func TestAutoApproveMultiNetwork(t *testing.T) {
	IntegrationSkip(t)
	bigRoute := netip.MustParsePrefix("10.42.0.0/16")
	subRoute := netip.MustParsePrefix("10.42.7.0/24")
	notApprovedRoute := netip.MustParsePrefix("192.168.0.0/24")

	tests := []struct {
		name     string
		pol      *policyv2.Policy
		approver string
		spec     ScenarioSpec
		withURL  bool
	}{
		{
			name: "authkey-tag",
			pol: &policyv2.Policy{
				ACLs: []policyv2.ACL{
					{
						Action:  "accept",
						Sources: []policyv2.Alias{wildcard()},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
						},
					},
				},
				TagOwners: policyv2.TagOwners{
					policyv2.Tag("tag:approve"): policyv2.Owners{usernameOwner("user1@")},
				},
				AutoApprovers: policyv2.AutoApproverPolicy{
					Routes: map[netip.Prefix]policyv2.AutoApprovers{
						bigRoute: {tagApprover("tag:approve")},
					},
					ExitNode: policyv2.AutoApprovers{tagApprover("tag:approve")},
				},
			},
			approver: "tag:approve",
			spec: ScenarioSpec{
				NodesPerUser: 3,
				Users:        []string{"user1", "user2"},
				Networks: map[string][]string{
					"usernet1": {"user1"},
					"usernet2": {"user2"},
				},
				ExtraService: map[string][]extraServiceFunc{
					"usernet1": {Webservice},
				},
				// We build the head image with curl and traceroute, so only use
				// that for this test.
				Versions: []string{"head"},
			},
		},
		{
			name: "authkey-user",
			pol: &policyv2.Policy{
				ACLs: []policyv2.ACL{
					{
						Action:  "accept",
						Sources: []policyv2.Alias{wildcard()},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
						},
					},
				},
				AutoApprovers: policyv2.AutoApproverPolicy{
					Routes: map[netip.Prefix]policyv2.AutoApprovers{
						bigRoute: {usernameApprover("user1@")},
					},
					ExitNode: policyv2.AutoApprovers{usernameApprover("user1@")},
				},
			},
			approver: "user1@",
			spec: ScenarioSpec{
				NodesPerUser: 3,
				Users:        []string{"user1", "user2"},
				Networks: map[string][]string{
					"usernet1": {"user1"},
					"usernet2": {"user2"},
				},
				ExtraService: map[string][]extraServiceFunc{
					"usernet1": {Webservice},
				},
				// We build the head image with curl and traceroute, so only use
				// that for this test.
				Versions: []string{"head"},
			},
		},
		{
			name: "authkey-group",
			pol: &policyv2.Policy{
				ACLs: []policyv2.ACL{
					{
						Action:  "accept",
						Sources: []policyv2.Alias{wildcard()},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
						},
					},
				},
				Groups: policyv2.Groups{
					policyv2.Group("group:approve"): []policyv2.Username{policyv2.Username("user1@")},
				},
				AutoApprovers: policyv2.AutoApproverPolicy{
					Routes: map[netip.Prefix]policyv2.AutoApprovers{
						bigRoute: {groupApprover("group:approve")},
					},
					ExitNode: policyv2.AutoApprovers{groupApprover("group:approve")},
				},
			},
			approver: "group:approve",
			spec: ScenarioSpec{
				NodesPerUser: 3,
				Users:        []string{"user1", "user2"},
				Networks: map[string][]string{
					"usernet1": {"user1"},
					"usernet2": {"user2"},
				},
				ExtraService: map[string][]extraServiceFunc{
					"usernet1": {Webservice},
				},
				// We build the head image with curl and traceroute, so only use
				// that for this test.
				Versions: []string{"head"},
			},
		},
		{
			name: "webauth-user",
			pol: &policyv2.Policy{
				ACLs: []policyv2.ACL{
					{
						Action:  "accept",
						Sources: []policyv2.Alias{wildcard()},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
						},
					},
				},
				AutoApprovers: policyv2.AutoApproverPolicy{
					Routes: map[netip.Prefix]policyv2.AutoApprovers{
						bigRoute: {usernameApprover("user1@")},
					},
					ExitNode: policyv2.AutoApprovers{usernameApprover("user1@")},
				},
			},
			approver: "user1@",
			spec: ScenarioSpec{
				NodesPerUser: 3,
				Users:        []string{"user1", "user2"},
				Networks: map[string][]string{
					"usernet1": {"user1"},
					"usernet2": {"user2"},
				},
				ExtraService: map[string][]extraServiceFunc{
					"usernet1": {Webservice},
				},
				// We build the head image with curl and traceroute, so only use
				// that for this test.
				Versions: []string{"head"},
			},
			withURL: true,
		},
		{
			name: "webauth-tag",
			pol: &policyv2.Policy{
				ACLs: []policyv2.ACL{
					{
						Action:  "accept",
						Sources: []policyv2.Alias{wildcard()},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
						},
					},
				},
				TagOwners: policyv2.TagOwners{
					policyv2.Tag("tag:approve"): policyv2.Owners{usernameOwner("user1@")},
				},
				AutoApprovers: policyv2.AutoApproverPolicy{
					Routes: map[netip.Prefix]policyv2.AutoApprovers{
						bigRoute: {tagApprover("tag:approve")},
					},
					ExitNode: policyv2.AutoApprovers{tagApprover("tag:approve")},
				},
			},
			approver: "tag:approve",
			spec: ScenarioSpec{
				NodesPerUser: 3,
				Users:        []string{"user1", "user2"},
				Networks: map[string][]string{
					"usernet1": {"user1"},
					"usernet2": {"user2"},
				},
				ExtraService: map[string][]extraServiceFunc{
					"usernet1": {Webservice},
				},
				// We build the head image with curl and traceroute, so only use
				// that for this test.
				Versions: []string{"head"},
			},
			withURL: true,
		},
		{
			name: "webauth-group",
			pol: &policyv2.Policy{
				ACLs: []policyv2.ACL{
					{
						Action:  "accept",
						Sources: []policyv2.Alias{wildcard()},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
						},
					},
				},
				Groups: policyv2.Groups{
					policyv2.Group("group:approve"): []policyv2.Username{policyv2.Username("user1@")},
				},
				AutoApprovers: policyv2.AutoApproverPolicy{
					Routes: map[netip.Prefix]policyv2.AutoApprovers{
						bigRoute: {groupApprover("group:approve")},
					},
					ExitNode: policyv2.AutoApprovers{groupApprover("group:approve")},
				},
			},
			approver: "group:approve",
			spec: ScenarioSpec{
				NodesPerUser: 3,
				Users:        []string{"user1", "user2"},
				Networks: map[string][]string{
					"usernet1": {"user1"},
					"usernet2": {"user2"},
				},
				ExtraService: map[string][]extraServiceFunc{
					"usernet1": {Webservice},
				},
				// We build the head image with curl and traceroute, so only use
				// that for this test.
				Versions: []string{"head"},
			},
			withURL: true,
		},
	}

	// Check if we should run the full matrix of tests
	// By default, we only run a minimal subset to avoid overwhelming Docker/disk
	// Set HEADSCALE_INTEGRATION_FULL_MATRIX=1 to run all combinations
	fullMatrix := envknob.Bool("HEADSCALE_INTEGRATION_FULL_MATRIX")

	// Minimal test set: 3 tests covering all key dimensions
	// - Both auth methods (authkey, webauth)
	// - All 3 approver types (tag, user, group)
	// - Both policy modes (database, file)
	// - Both advertiseDuringUp values (true, false)
	minimalTestSet := map[string]bool{
		"authkey-tag-advertiseduringup-false-pol-database":  true, // authkey + database + tag + false
		"webauth-user-advertiseduringup-true-pol-file":      true, // webauth + file + user + true
		"authkey-group-advertiseduringup-false-pol-file":    true, // authkey + file + group + false
	}

	for _, tt := range tests {
		for _, polMode := range []types.PolicyMode{types.PolicyModeDB, types.PolicyModeFile} {
			for _, advertiseDuringUp := range []bool{false, true} {
				name := fmt.Sprintf("%s-advertiseduringup-%t-pol-%s", tt.name, advertiseDuringUp, polMode)
				t.Run(name, func(t *testing.T) {
					// Skip tests not in minimal set unless full matrix is enabled
					if !fullMatrix && !minimalTestSet[name] {
						t.Skip("Skipping to reduce test matrix size. Set HEADSCALE_INTEGRATION_FULL_MATRIX=1 to run all tests.")
					}
					scenario, err := NewScenario(tt.spec)
					require.NoErrorf(t, err, "failed to create scenario: %s", err)
					defer scenario.ShutdownAssertNoPanics(t)

					var nodes []*v1.Node
					opts := []hsic.Option{
						hsic.WithTestName("autoapprovemulti"),
						hsic.WithEmbeddedDERPServerOnly(),
						hsic.WithTLS(),
						hsic.WithACLPolicy(tt.pol),
						hsic.WithPolicyMode(polMode),
					}

					tsOpts := []tsic.Option{
						tsic.WithAcceptRoutes(),
					}

					if tt.approver == "tag:approve" {
						tsOpts = append(tsOpts,
							tsic.WithTags([]string{"tag:approve"}),
						)
					}

					route, err := scenario.SubnetOfNetwork("usernet1")
					require.NoError(t, err)

					err = scenario.createHeadscaleEnv(tt.withURL, tsOpts,
						opts...,
					)
					requireNoErrHeadscaleEnv(t, err)

					allClients, err := scenario.ListTailscaleClients()
					requireNoErrListClients(t, err)

					err = scenario.WaitForTailscaleSync()
					requireNoErrSync(t, err)

					services, err := scenario.Services("usernet1")
					require.NoError(t, err)
					require.Len(t, services, 1)

					usernet1, err := scenario.Network("usernet1")
					require.NoError(t, err)

					headscale, err := scenario.Headscale()
					requireNoErrGetHeadscale(t, err)
					assert.NotNil(t, headscale)

					// Add the Docker network route to the auto-approvers
					// Keep existing auto-approvers (like bigRoute) in place
					var approvers policyv2.AutoApprovers
					switch {
					case strings.HasPrefix(tt.approver, "tag:"):
						approvers = append(approvers, tagApprover(tt.approver))
					case strings.HasPrefix(tt.approver, "group:"):
						approvers = append(approvers, groupApprover(tt.approver))
					default:
						approvers = append(approvers, usernameApprover(tt.approver))
					}
					if tt.pol.AutoApprovers.Routes == nil {
						tt.pol.AutoApprovers.Routes = make(map[netip.Prefix]policyv2.AutoApprovers)
					}
					prefix := *route
					tt.pol.AutoApprovers.Routes[prefix] = approvers
					err = headscale.SetPolicy(tt.pol)
					require.NoError(t, err)

					if advertiseDuringUp {
						tsOpts = append(tsOpts,
							tsic.WithExtraLoginArgs([]string{"--advertise-routes=" + route.String()}),
						)
					}

					tsOpts = append(tsOpts, tsic.WithNetwork(usernet1))

					// This whole dance is to add a node _after_ all the other nodes
					// with an additional tsOpt which advertises the route as part
					// of the `tailscale up` command. If we do this as part of the
					// scenario creation, it will be added to all nodes and turn
					// into a HA node, which isn't something we are testing here.
					routerUsernet1, err := scenario.CreateTailscaleNode("head", tsOpts...)
					require.NoError(t, err)
					defer routerUsernet1.Shutdown()

					if tt.withURL {
						u, err := routerUsernet1.LoginWithURL(headscale.GetEndpoint())
						require.NoError(t, err)

						body, err := doLoginURL(routerUsernet1.Hostname(), u)
						require.NoError(t, err)

						scenario.runHeadscaleRegister("user1", body)
					} else {
						userMap, err := headscale.MapUsers()
						require.NoError(t, err)

						pak, err := scenario.CreatePreAuthKey(userMap["user1"].GetId(), false, false)
						require.NoError(t, err)

						err = routerUsernet1.Login(headscale.GetEndpoint(), pak.GetKey())
						require.NoError(t, err)
					}
					// extra creation end.

					routerUsernet1ID := routerUsernet1.MustID()

					web := services[0]
					webip := netip.MustParseAddr(web.GetIPInNetwork(usernet1))
					weburl := fmt.Sprintf("http://%s/etc/hostname", webip)
					t.Logf("webservice: %s, %s", webip.String(), weburl)

					// Sort nodes by ID
					sort.SliceStable(allClients, func(i, j int) bool {
						statusI := allClients[i].MustStatus()
						statusJ := allClients[j].MustStatus()

						return statusI.Self.ID < statusJ.Self.ID
					})

					// This is ok because the scenario makes users in order, so the three first
					// nodes, which are subnet routes, will be created first, and the last user
					// will be created with the second.
					routerSubRoute := allClients[1]
					routerExitNode := allClients[2]

					client := allClients[3]

					if !advertiseDuringUp {
						// Advertise the route for the dockersubnet of user1
						command := []string{
							"tailscale",
							"set",
							"--advertise-routes=" + route.String(),
						}
						_, _, err = routerUsernet1.Execute(command)
						require.NoErrorf(t, err, "failed to advertise route: %s", err)
					}

					// Wait for route state changes to propagate
					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						// These route should auto approve, so the node is expected to have a route
						// for all counts.
						nodes, err := headscale.ListNodes()
						assert.NoError(c, err)

						routerNode := MustFindNode(routerUsernet1.Hostname(), nodes)
						t.Logf("Initial auto-approval check - Router node %s: announced=%v, approved=%v, subnet=%v",
							routerNode.GetName(),
							routerNode.GetAvailableRoutes(),
							routerNode.GetApprovedRoutes(),
							routerNode.GetSubnetRoutes())

						requireNodeRouteCountWithCollect(c, routerNode, 1, 1, 1)
					}, 10*time.Second, 500*time.Millisecond, "Initial route auto-approval: Route should be approved via policy")

					// Verify that the routes have been sent to the client.
					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						status, err := client.Status()
						assert.NoError(c, err)

						// Debug output to understand peer visibility
						t.Logf("Client %s sees %d peers", client.Hostname(), len(status.Peers()))

						routerPeerFound := false
						for _, peerKey := range status.Peers() {
							peerStatus := status.Peer[peerKey]

							if peerStatus.ID == routerUsernet1ID.StableID() {
								routerPeerFound = true
								t.Logf("Client sees router peer %s (ID=%s): AllowedIPs=%v, PrimaryRoutes=%v",
									peerStatus.HostName,
									peerStatus.ID,
									peerStatus.AllowedIPs,
									peerStatus.PrimaryRoutes)

								assert.NotNil(c, peerStatus.PrimaryRoutes)
								if peerStatus.PrimaryRoutes != nil {
									assert.Contains(c, peerStatus.PrimaryRoutes.AsSlice(), *route)
								}
								requirePeerSubnetRoutesWithCollect(c, peerStatus, []netip.Prefix{*route})
							} else {
								requirePeerSubnetRoutesWithCollect(c, peerStatus, nil)
							}
						}

						assert.True(c, routerPeerFound, "Client should see the router peer")
					}, 5*time.Second, 200*time.Millisecond, "Verifying routes sent to client after auto-approval")

					url := fmt.Sprintf("http://%s/etc/hostname", webip)
					t.Logf("url from %s to %s", client.Hostname(), url)

					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						result, err := client.Curl(url)
						assert.NoError(c, err)
						assert.Len(c, result, 13)
					}, 20*time.Second, 200*time.Millisecond, "Verifying client can reach webservice through auto-approved route")

					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						tr, err := client.Traceroute(webip)
						assert.NoError(c, err)
						ip, err := routerUsernet1.IPv4()
						if !assert.NoError(c, err, "failed to get IPv4 for routerUsernet1") {
							return
						}
						assertTracerouteViaIPWithCollect(c, tr, ip)
					}, 20*time.Second, 200*time.Millisecond, "Verifying traceroute goes through auto-approved router")

					// Remove the auto approval from the policy, any routes already enabled should be allowed.
					prefix = *route
					delete(tt.pol.AutoApprovers.Routes, prefix)
					err = headscale.SetPolicy(tt.pol)
					require.NoError(t, err)
					t.Logf("Policy updated: removed auto-approver for route %s", prefix)

					// Wait for route state changes to propagate
					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						// Routes already approved should remain approved even after policy change
						nodes, err = headscale.ListNodes()
						assert.NoError(c, err)

						routerNode := MustFindNode(routerUsernet1.Hostname(), nodes)
						t.Logf("After policy removal - Router node %s: announced=%v, approved=%v, subnet=%v",
							routerNode.GetName(),
							routerNode.GetAvailableRoutes(),
							routerNode.GetApprovedRoutes(),
							routerNode.GetSubnetRoutes())

						requireNodeRouteCountWithCollect(c, routerNode, 1, 1, 1)
					}, 10*time.Second, 500*time.Millisecond, "Routes should remain approved after auto-approver removal")

					// Verify that the routes have been sent to the client.
					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						status, err := client.Status()
						assert.NoError(c, err)

						for _, peerKey := range status.Peers() {
							peerStatus := status.Peer[peerKey]

							if peerStatus.ID == routerUsernet1ID.StableID() {
								assert.NotNil(c, peerStatus.PrimaryRoutes)
								if peerStatus.PrimaryRoutes != nil {
									assert.Contains(c, peerStatus.PrimaryRoutes.AsSlice(), *route)
								}
								requirePeerSubnetRoutesWithCollect(c, peerStatus, []netip.Prefix{*route})
							} else {
								requirePeerSubnetRoutesWithCollect(c, peerStatus, nil)
							}
						}
					}, 5*time.Second, 200*time.Millisecond, "Verifying routes remain after policy change")

					url = fmt.Sprintf("http://%s/etc/hostname", webip)
					t.Logf("url from %s to %s", client.Hostname(), url)

					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						result, err := client.Curl(url)
						assert.NoError(c, err)
						assert.Len(c, result, 13)
					}, 20*time.Second, 200*time.Millisecond, "Verifying client can still reach webservice after policy change")

					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						tr, err := client.Traceroute(webip)
						assert.NoError(c, err)
						ip, err := routerUsernet1.IPv4()
						if !assert.NoError(c, err, "failed to get IPv4 for routerUsernet1") {
							return
						}
						assertTracerouteViaIPWithCollect(c, tr, ip)
					}, 20*time.Second, 200*time.Millisecond, "Verifying traceroute still goes through router after policy change")

					// Disable the route, making it unavailable since it is no longer auto-approved
					_, err = headscale.ApproveRoutes(
						MustFindNode(routerUsernet1.Hostname(), nodes).GetId(),
						[]netip.Prefix{},
					)
					require.NoError(t, err)

					// Wait for route state changes to propagate
					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						// These route should auto approve, so the node is expected to have a route
						// for all counts.
						nodes, err = headscale.ListNodes()
						assert.NoError(c, err)
						requireNodeRouteCountWithCollect(c, MustFindNode(routerUsernet1.Hostname(), nodes), 1, 0, 0)
					}, 10*time.Second, 500*time.Millisecond, "route state changes should propagate")

					// Verify that the routes have been sent to the client.
					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						status, err := client.Status()
						assert.NoError(c, err)

						for _, peerKey := range status.Peers() {
							peerStatus := status.Peer[peerKey]
							requirePeerSubnetRoutesWithCollect(c, peerStatus, nil)
						}
					}, 5*time.Second, 200*time.Millisecond, "Verifying routes disabled after route removal")

					// Add the route back to the auto approver in the policy, the route should
					// now become available again.
					var newApprovers policyv2.AutoApprovers
					switch {
					case strings.HasPrefix(tt.approver, "tag:"):
						newApprovers = append(newApprovers, tagApprover(tt.approver))
					case strings.HasPrefix(tt.approver, "group:"):
						newApprovers = append(newApprovers, groupApprover(tt.approver))
					default:
						newApprovers = append(newApprovers, usernameApprover(tt.approver))
					}
					if tt.pol.AutoApprovers.Routes == nil {
						tt.pol.AutoApprovers.Routes = make(map[netip.Prefix]policyv2.AutoApprovers)
					}
					prefix = *route
					tt.pol.AutoApprovers.Routes[prefix] = newApprovers
					err = headscale.SetPolicy(tt.pol)
					require.NoError(t, err)

					// Wait for route state changes to propagate
					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						// These route should auto approve, so the node is expected to have a route
						// for all counts.
						nodes, err = headscale.ListNodes()
						assert.NoError(c, err)
						requireNodeRouteCountWithCollect(c, MustFindNode(routerUsernet1.Hostname(), nodes), 1, 1, 1)
					}, 10*time.Second, 500*time.Millisecond, "route state changes should propagate")

					// Verify that the routes have been sent to the client.
					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						status, err := client.Status()
						assert.NoError(c, err)

						for _, peerKey := range status.Peers() {
							peerStatus := status.Peer[peerKey]

							if peerStatus.ID == routerUsernet1ID.StableID() {
								assert.NotNil(c, peerStatus.PrimaryRoutes)
								if peerStatus.PrimaryRoutes != nil {
									assert.Contains(c, peerStatus.PrimaryRoutes.AsSlice(), *route)
								}
								requirePeerSubnetRoutesWithCollect(c, peerStatus, []netip.Prefix{*route})
							} else {
								requirePeerSubnetRoutesWithCollect(c, peerStatus, nil)
							}
						}
					}, 5*time.Second, 200*time.Millisecond, "Verifying routes re-enabled after policy re-approval")

					url = fmt.Sprintf("http://%s/etc/hostname", webip)
					t.Logf("url from %s to %s", client.Hostname(), url)

					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						result, err := client.Curl(url)
						assert.NoError(c, err)
						assert.Len(c, result, 13)
					}, 20*time.Second, 200*time.Millisecond, "Verifying client can reach webservice after route re-approval")

					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						tr, err := client.Traceroute(webip)
						assert.NoError(c, err)
						ip, err := routerUsernet1.IPv4()
						if !assert.NoError(c, err, "failed to get IPv4 for routerUsernet1") {
							return
						}
						assertTracerouteViaIPWithCollect(c, tr, ip)
					}, 20*time.Second, 200*time.Millisecond, "Verifying traceroute goes through router after re-approval")

					// Advertise and validate a subnet of an auto approved route, /24 inside the
					// auto approved /16.
					command := []string{
						"tailscale",
						"set",
						"--advertise-routes=" + subRoute.String(),
					}
					_, _, err = routerSubRoute.Execute(command)
					require.NoErrorf(t, err, "failed to advertise route: %s", err)

					// Wait for route state changes to propagate
					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						// These route should auto approve, so the node is expected to have a route
						// for all counts.
						nodes, err = headscale.ListNodes()
						assert.NoError(c, err)
						requireNodeRouteCountWithCollect(c, MustFindNode(routerUsernet1.Hostname(), nodes), 1, 1, 1)
						requireNodeRouteCountWithCollect(c, nodes[1], 1, 1, 1)
					}, 10*time.Second, 500*time.Millisecond, "route state changes should propagate")

					// Verify that the routes have been sent to the client.
					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						status, err := client.Status()
						assert.NoError(c, err)

						for _, peerKey := range status.Peers() {
							peerStatus := status.Peer[peerKey]

							if peerStatus.ID == routerUsernet1ID.StableID() {
								if peerStatus.PrimaryRoutes != nil {
									assert.Contains(c, peerStatus.PrimaryRoutes.AsSlice(), *route)
								}
								requirePeerSubnetRoutesWithCollect(c, peerStatus, []netip.Prefix{*route})
							} else if peerStatus.ID == "2" {
								if peerStatus.PrimaryRoutes != nil {
									assert.Contains(c, peerStatus.PrimaryRoutes.AsSlice(), subRoute)
								}
								requirePeerSubnetRoutesWithCollect(c, peerStatus, []netip.Prefix{subRoute})
							} else {
								requirePeerSubnetRoutesWithCollect(c, peerStatus, nil)
							}
						}
					}, 5*time.Second, 200*time.Millisecond, "Verifying sub-route propagated to client")

					// Advertise a not approved route will not end up anywhere
					command = []string{
						"tailscale",
						"set",
						"--advertise-routes=" + notApprovedRoute.String(),
					}
					_, _, err = routerSubRoute.Execute(command)
					require.NoErrorf(t, err, "failed to advertise route: %s", err)

					// Wait for route state changes to propagate
					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						// These route should auto approve, so the node is expected to have a route
						// for all counts.
						nodes, err = headscale.ListNodes()
						assert.NoError(c, err)
						requireNodeRouteCountWithCollect(c, MustFindNode(routerUsernet1.Hostname(), nodes), 1, 1, 1)
						requireNodeRouteCountWithCollect(c, nodes[1], 1, 1, 0)
						requireNodeRouteCountWithCollect(c, nodes[2], 0, 0, 0)
					}, 10*time.Second, 500*time.Millisecond, "route state changes should propagate")

					// Verify that the routes have been sent to the client.
					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						status, err := client.Status()
						assert.NoError(c, err)

						for _, peerKey := range status.Peers() {
							peerStatus := status.Peer[peerKey]

							if peerStatus.ID == routerUsernet1ID.StableID() {
								assert.NotNil(c, peerStatus.PrimaryRoutes)
								if peerStatus.PrimaryRoutes != nil {
									assert.Contains(c, peerStatus.PrimaryRoutes.AsSlice(), *route)
								}
								requirePeerSubnetRoutesWithCollect(c, peerStatus, []netip.Prefix{*route})
							} else {
								requirePeerSubnetRoutesWithCollect(c, peerStatus, nil)
							}
						}
					}, 5*time.Second, 200*time.Millisecond, "Verifying unapproved route not propagated")

					// Exit routes are also automatically approved
					command = []string{
						"tailscale",
						"set",
						"--advertise-exit-node",
					}
					_, _, err = routerExitNode.Execute(command)
					require.NoErrorf(t, err, "failed to advertise route: %s", err)

					// Wait for route state changes to propagate
					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						nodes, err = headscale.ListNodes()
						assert.NoError(c, err)
						requireNodeRouteCountWithCollect(c, MustFindNode(routerUsernet1.Hostname(), nodes), 1, 1, 1)
						requireNodeRouteCountWithCollect(c, nodes[1], 1, 1, 0)
						requireNodeRouteCountWithCollect(c, nodes[2], 2, 2, 2)
					}, 10*time.Second, 500*time.Millisecond, "route state changes should propagate")

					// Verify that the routes have been sent to the client.
					assert.EventuallyWithT(t, func(c *assert.CollectT) {
						status, err := client.Status()
						assert.NoError(c, err)

						for _, peerKey := range status.Peers() {
							peerStatus := status.Peer[peerKey]

							if peerStatus.ID == routerUsernet1ID.StableID() {
								if peerStatus.PrimaryRoutes != nil {
									assert.Contains(c, peerStatus.PrimaryRoutes.AsSlice(), *route)
								}
								requirePeerSubnetRoutesWithCollect(c, peerStatus, []netip.Prefix{*route})
							} else if peerStatus.ID == "3" {
								requirePeerSubnetRoutesWithCollect(c, peerStatus, []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6()})
							} else {
								requirePeerSubnetRoutesWithCollect(c, peerStatus, nil)
							}
						}
					}, 5*time.Second, 200*time.Millisecond, "Verifying exit node routes propagated to client")
				})
			}
		}
	}
}

func assertTracerouteViaIP(t *testing.T, tr util.Traceroute, ip netip.Addr) {
	t.Helper()

	require.NotNil(t, tr)
	require.True(t, tr.Success)
	require.NoError(t, tr.Err)
	require.NotEmpty(t, tr.Route)
	require.Equal(t, tr.Route[0].IP, ip)
}

// assertTracerouteViaIPWithCollect is a version of assertTracerouteViaIP that works with assert.CollectT.
func assertTracerouteViaIPWithCollect(c *assert.CollectT, tr util.Traceroute, ip netip.Addr) {
	assert.NotNil(c, tr)
	assert.True(c, tr.Success)
	assert.NoError(c, tr.Err)
	assert.NotEmpty(c, tr.Route)
	// Since we're inside EventuallyWithT, we can't use require.Greater with t
	// but assert.NotEmpty above ensures len(tr.Route) > 0
	if len(tr.Route) > 0 {
		assert.Equal(c, tr.Route[0].IP.String(), ip.String())
	}
}

// requirePeerSubnetRoutes asserts that the peer has the expected subnet routes.
func requirePeerSubnetRoutes(t *testing.T, status *ipnstate.PeerStatus, expected []netip.Prefix) {
	t.Helper()
	if status.AllowedIPs.Len() <= 2 && len(expected) != 0 {
		t.Fatalf("peer %s (%s) has no subnet routes, expected %v", status.HostName, status.ID, expected)
		return
	}

	if len(expected) == 0 {
		expected = []netip.Prefix{}
	}

	got := slicesx.Filter(nil, status.AllowedIPs.AsSlice(), func(p netip.Prefix) bool {
		if tsaddr.IsExitRoute(p) {
			return true
		}
		return !slices.ContainsFunc(status.TailscaleIPs, p.Contains)
	})

	if diff := cmpdiff.Diff(expected, got, util.PrefixComparer, cmpopts.EquateEmpty()); diff != "" {
		t.Fatalf("peer %s (%s) subnet routes, unexpected result (-want +got):\n%s", status.HostName, status.ID, diff)
	}
}

func SortPeerStatus(a, b *ipnstate.PeerStatus) int {
	return cmp.Compare(a.ID, b.ID)
}

func printCurrentRouteMap(t *testing.T, routers ...*ipnstate.PeerStatus) {
	t.Logf("== Current routing map ==")
	slices.SortFunc(routers, SortPeerStatus)
	for _, router := range routers {
		got := filterNonRoutes(router)
		t.Logf("  Router %s (%s) is serving:", router.HostName, router.ID)
		t.Logf("    AllowedIPs: %v", got)
		if router.PrimaryRoutes != nil {
			t.Logf("    PrimaryRoutes: %v", router.PrimaryRoutes.AsSlice())
		}
	}
}

// filterNonRoutes returns the list of routes that a [ipnstate.PeerStatus] is serving.
func filterNonRoutes(status *ipnstate.PeerStatus) []netip.Prefix {
	return slicesx.Filter(nil, status.AllowedIPs.AsSlice(), func(p netip.Prefix) bool {
		if tsaddr.IsExitRoute(p) {
			return true
		}
		return !slices.ContainsFunc(status.TailscaleIPs, p.Contains)
	})
}

func requirePeerSubnetRoutesWithCollect(c *assert.CollectT, status *ipnstate.PeerStatus, expected []netip.Prefix) {
	if status.AllowedIPs.Len() <= 2 && len(expected) != 0 {
		assert.Fail(c, fmt.Sprintf("peer %s (%s) has no subnet routes, expected %v", status.HostName, status.ID, expected))
		return
	}

	if len(expected) == 0 {
		expected = []netip.Prefix{}
	}

	got := filterNonRoutes(status)

	if diff := cmpdiff.Diff(expected, got, util.PrefixComparer, cmpopts.EquateEmpty()); diff != "" {
		assert.Fail(c, fmt.Sprintf("peer %s (%s) subnet routes, unexpected result (-want +got):\n%s", status.HostName, status.ID, diff))
	}
}

func requireNodeRouteCount(t *testing.T, node *v1.Node, announced, approved, subnet int) {
	t.Helper()
	require.Lenf(t, node.GetAvailableRoutes(), announced, "expected %q announced routes(%v) to have %d route, had %d", node.GetName(), node.GetAvailableRoutes(), announced, len(node.GetAvailableRoutes()))
	require.Lenf(t, node.GetApprovedRoutes(), approved, "expected %q approved routes(%v) to have %d route, had %d", node.GetName(), node.GetApprovedRoutes(), approved, len(node.GetApprovedRoutes()))
	require.Lenf(t, node.GetSubnetRoutes(), subnet, "expected %q subnet routes(%v) to have %d route, had %d", node.GetName(), node.GetSubnetRoutes(), subnet, len(node.GetSubnetRoutes()))
}

func requireNodeRouteCountWithCollect(c *assert.CollectT, node *v1.Node, announced, approved, subnet int) {
	assert.Lenf(c, node.GetAvailableRoutes(), announced, "expected %q announced routes(%v) to have %d route, had %d", node.GetName(), node.GetAvailableRoutes(), announced, len(node.GetAvailableRoutes()))
	assert.Lenf(c, node.GetApprovedRoutes(), approved, "expected %q approved routes(%v) to have %d route, had %d", node.GetName(), node.GetApprovedRoutes(), approved, len(node.GetApprovedRoutes()))
	assert.Lenf(c, node.GetSubnetRoutes(), subnet, "expected %q subnet routes(%v) to have %d route, had %d", node.GetName(), node.GetSubnetRoutes(), subnet, len(node.GetSubnetRoutes()))
}

// TestSubnetRouteACLFiltering tests that a node can only access subnet routes
// that are explicitly allowed in the ACL.
func TestSubnetRouteACLFiltering(t *testing.T) {
	IntegrationSkip(t)

	// Use router and node users for better clarity
	routerUser := "router"
	nodeUser := "node"

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{routerUser, nodeUser},
		Networks: map[string][]string{
			"usernet1": {routerUser, nodeUser},
		},
		ExtraService: map[string][]extraServiceFunc{
			"usernet1": {Webservice},
		},
		// We build the head image with curl and traceroute, so only use
		// that for this test.
		Versions: []string{"head"},
	}

	scenario, err := NewScenario(spec)
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	// Set up the ACL policy that allows the node to access only one of the subnet routes (10.10.10.0/24)
	aclPolicyStr := `{
		"hosts": {
			"router": "100.64.0.1/32",
			"node": "100.64.0.2/32"
		},
		"acls": [
			{
				"action": "accept",
				"src": [
					"*"
				],
				"dst": [
					"router:8000"
				]
			},
			{
				"action": "accept",
				"src": [
					"node"
				],
				"dst": [
					"*:*"
				]
			}
		]
	}`

	route, err := scenario.SubnetOfNetwork("usernet1")
	require.NoError(t, err)

	services, err := scenario.Services("usernet1")
	require.NoError(t, err)
	require.Len(t, services, 1)

	usernet1, err := scenario.Network("usernet1")
	require.NoError(t, err)

	web := services[0]
	webip := netip.MustParseAddr(web.GetIPInNetwork(usernet1))
	weburl := fmt.Sprintf("http://%s/etc/hostname", webip)
	t.Logf("webservice: %s, %s", webip.String(), weburl)

	aclPolicy := &policyv2.Policy{}
	err = json.Unmarshal([]byte(aclPolicyStr), aclPolicy)
	require.NoError(t, err)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{
		tsic.WithAcceptRoutes(),
	}, hsic.WithTestName("routeaclfilter"),
		hsic.WithACLPolicy(aclPolicy),
		hsic.WithPolicyMode(types.PolicyModeDB),
	)
	requireNoErrHeadscaleEnv(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	// Get the router and node clients by user
	routerClients, err := scenario.ListTailscaleClients(routerUser)
	require.NoError(t, err)
	require.Len(t, routerClients, 1)
	routerClient := routerClients[0]

	nodeClients, err := scenario.ListTailscaleClients(nodeUser)
	require.NoError(t, err)
	require.Len(t, nodeClients, 1)
	nodeClient := nodeClients[0]

	routerIP, err := routerClient.IPv4()
	require.NoError(t, err, "failed to get router IPv4")
	nodeIP, err := nodeClient.IPv4()
	require.NoError(t, err, "failed to get node IPv4")

	aclPolicy.Hosts = policyv2.Hosts{
		policyv2.Host(routerUser): policyv2.Prefix(must.Get(routerIP.Prefix(32))),
		policyv2.Host(nodeUser):   policyv2.Prefix(must.Get(nodeIP.Prefix(32))),
	}
	aclPolicy.ACLs[1].Destinations = []policyv2.AliasWithPorts{
		aliasWithPorts(prefixp(route.String()), tailcfg.PortRangeAny),
	}
	require.NoError(t, headscale.SetPolicy(aclPolicy))

	// Set up the subnet routes for the router
	routes := []netip.Prefix{
		*route,                                 // This should be accessible by the client
		netip.MustParsePrefix("10.10.11.0/24"), // These should NOT be accessible
		netip.MustParsePrefix("10.10.12.0/24"),
	}

	routeArg := "--advertise-routes=" + routes[0].String() + "," + routes[1].String() + "," + routes[2].String()
	command := []string{
		"tailscale",
		"set",
		routeArg,
	}

	_, _, err = routerClient.Execute(command)
	require.NoErrorf(t, err, "failed to advertise routes: %s", err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	var routerNode, nodeNode *v1.Node
	// Wait for route advertisements to propagate to NodeStore
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		// List nodes and verify the router has 3 available routes
		nodes, err := headscale.NodesByUser()
		assert.NoError(ct, err)
		assert.Len(ct, nodes, 2)

		// Find the router node
		routerNode = nodes[routerUser][0]
		nodeNode = nodes[nodeUser][0]

		assert.NotNil(ct, routerNode, "Router node not found")
		assert.NotNil(ct, nodeNode, "Client node not found")

		// Check that the router has 3 routes available but not approved yet
		requireNodeRouteCountWithCollect(ct, routerNode, 3, 0, 0)
		requireNodeRouteCountWithCollect(ct, nodeNode, 0, 0, 0)
	}, 10*time.Second, 100*time.Millisecond, "route advertisements should propagate to router node")

	// Approve all routes for the router
	_, err = headscale.ApproveRoutes(
		routerNode.GetId(),
		util.MustStringsToPrefixes(routerNode.GetAvailableRoutes()),
	)
	require.NoError(t, err)

	// Wait for route state changes to propagate
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		// List nodes and verify the router has 3 available routes
		var err error
		nodes, err := headscale.NodesByUser()
		assert.NoError(c, err)
		assert.Len(c, nodes, 2)

		// Find the router node
		routerNode = nodes[routerUser][0]

		// Check that the router has 3 routes now approved and available
		requireNodeRouteCountWithCollect(c, routerNode, 3, 3, 3)
	}, 10*time.Second, 500*time.Millisecond, "route state changes should propagate")

	// Now check the client node status
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodeStatus, err := nodeClient.Status()
		assert.NoError(c, err)

		routerStatus, err := routerClient.Status()
		assert.NoError(c, err)

		// Check that the node can see the subnet routes from the router
		routerPeerStatus := nodeStatus.Peer[routerStatus.Self.PublicKey]

		// The node should only have 1 subnet route
		requirePeerSubnetRoutesWithCollect(c, routerPeerStatus, []netip.Prefix{*route})
	}, 5*time.Second, 200*time.Millisecond, "Verifying node sees filtered subnet routes")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, err := nodeClient.Curl(weburl)
		assert.NoError(c, err)
		assert.Len(c, result, 13)
	}, 20*time.Second, 200*time.Millisecond, "Verifying node can reach webservice through allowed route")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		tr, err := nodeClient.Traceroute(webip)
		assert.NoError(c, err)
		ip, err := routerClient.IPv4()
		if !assert.NoError(c, err, "failed to get IPv4 for routerClient") {
			return
		}
		assertTracerouteViaIPWithCollect(c, tr, ip)
	}, 20*time.Second, 200*time.Millisecond, "Verifying traceroute goes through router")
}
