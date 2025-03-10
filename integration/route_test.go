package integration

import (
	"net/netip"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	policyv1 "github.com/juanfont/headscale/hscontrol/policy/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/views"
	"tailscale.com/wgengine/filter"
)

var allPorts = filter.PortRange{First: 0, Last: 0xffff}

// This test is both testing the routes command and the propagation of
// routes.
func TestEnablingRoutes(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	user := "user6"

	scenario, err := NewScenario(dockertestMaxWait())
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		user: 3,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clienableroute"))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	assertNoErrGetHeadscale(t, err)

	expectedRoutes := map[string]string{
		"1": "10.0.0.0/24",
		"2": "10.0.1.0/24",
		"3": "10.0.2.0/24",
	}

	// advertise routes using the up command
	for _, client := range allClients {
		status, err := client.Status()
		require.NoError(t, err)

		command := []string{
			"tailscale",
			"set",
			"--advertise-routes=" + expectedRoutes[string(status.Self.ID)],
		}
		_, _, err = client.Execute(command)
		require.NoErrorf(t, err, "failed to advertise route: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	nodes, err := headscale.ListNodes()
	require.NoError(t, err)

	for _, node := range nodes {
		assert.Len(t, node.GetAvailableRoutes(), 1)
		assert.Empty(t, node.GetApprovedRoutes())
		assert.Empty(t, node.GetSubnetRoutes())
	}

	// Verify that no routes has been sent to the client,
	// they are not yet enabled.
	for _, client := range allClients {
		status, err := client.Status()
		require.NoError(t, err)

		for _, peerKey := range status.Peers() {
			peerStatus := status.Peer[peerKey]

			assert.Nil(t, peerStatus.PrimaryRoutes)
		}
	}

	for _, node := range nodes {
		_, err := headscale.ApproveRoutes(
			node.GetId(),
			util.MustStringsToPrefixes(node.GetAvailableRoutes()),
		)
		require.NoError(t, err)
	}

	nodes, err = headscale.ListNodes()
	require.NoError(t, err)

	for _, node := range nodes {
		assert.Len(t, node.GetAvailableRoutes(), 1)
		assert.Len(t, node.GetApprovedRoutes(), 1)
		assert.Len(t, node.GetSubnetRoutes(), 1)
	}

	time.Sleep(5 * time.Second)

	// Verify that the clients can see the new routes
	for _, client := range allClients {
		status, err := client.Status()
		require.NoError(t, err)

		for _, peerKey := range status.Peers() {
			peerStatus := status.Peer[peerKey]

			assert.Nil(t, peerStatus.PrimaryRoutes)

			assert.Len(t, peerStatus.AllowedIPs.AsSlice(), 3)

			if peerStatus.AllowedIPs.Len() > 2 {
				peerRoute := peerStatus.AllowedIPs.At(2)

				// id starts at 1, we created routes with 0 index
				assert.Equalf(
					t,
					expectedRoutes[string(peerStatus.ID)],
					peerRoute.String(),
					"expected route %s to be present on peer %s (%s) in %s (%s) status",
					expectedRoutes[string(peerStatus.ID)],
					peerStatus.HostName,
					peerStatus.ID,
					client.Hostname(),
					client.ID(),
				)
			}
		}
	}

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

	time.Sleep(5 * time.Second)

	nodes, err = headscale.ListNodes()
	require.NoError(t, err)

	for _, node := range nodes {
		if node.GetId() == 1 {
			assert.Len(t, node.GetAvailableRoutes(), 1) // 10.0.0.0/24
			assert.Len(t, node.GetApprovedRoutes(), 1)  // 10.0.1.0/24
			assert.Empty(t, node.GetSubnetRoutes())
		} else if node.GetId() == 2 {
			assert.Len(t, node.GetAvailableRoutes(), 1) // 10.0.1.0/24
			assert.Empty(t, node.GetApprovedRoutes())
			assert.Empty(t, node.GetSubnetRoutes())
		} else {
			assert.Len(t, node.GetAvailableRoutes(), 1) // 10.0.2.0/24
			assert.Len(t, node.GetApprovedRoutes(), 1)  // 10.0.2.0/24
			assert.Len(t, node.GetSubnetRoutes(), 1)    // 10.0.2.0/24
		}
	}

	// Verify that the clients can see the new routes
	for _, client := range allClients {
		status, err := client.Status()
		require.NoError(t, err)

		for _, peerKey := range status.Peers() {
			peerStatus := status.Peer[peerKey]

			assert.Nil(t, peerStatus.PrimaryRoutes)
			if peerStatus.ID == "1" {
				assertPeerSubnetRoutes(t, peerStatus, nil)
			} else if peerStatus.ID == "2" {
				assertPeerSubnetRoutes(t, peerStatus, nil)
			} else {
				assertPeerSubnetRoutes(t, peerStatus, []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")})
			}
		}
	}
}

func TestHASubnetRouterFailover(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	user := "user9"

	scenario, err := NewScenario(dockertestMaxWait())
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		user: 4,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{},
		hsic.WithTestName("clienableroute"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	assertNoErrGetHeadscale(t, err)

	expectedRoutes := map[string]string{
		"1": "10.0.0.0/24",
		"2": "10.0.0.0/24",
		"3": "10.0.0.0/24",
	}

	// Sort nodes by ID
	sort.SliceStable(allClients, func(i, j int) bool {
		statusI := allClients[i].MustStatus()
		statusJ := allClients[j].MustStatus()

		return statusI.Self.ID < statusJ.Self.ID
	})

	subRouter1 := allClients[0]
	subRouter2 := allClients[1]
	subRouter3 := allClients[2]

	client := allClients[3]

	t.Logf("Advertise route from r1 (%s), r2 (%s), r3 (%s), making it HA, n1 is primary", subRouter1.Hostname(), subRouter2.Hostname(), subRouter3.Hostname())
	// advertise HA route on node 1, 2, 3
	// ID 1 will be primary
	// ID 2 will be standby
	// ID 3 will be standby
	for _, client := range allClients[:3] {
		status, err := client.Status()
		require.NoError(t, err)

		if route, ok := expectedRoutes[string(status.Self.ID)]; ok {
			command := []string{
				"tailscale",
				"set",
				"--advertise-routes=" + route,
			}
			_, _, err = client.Execute(command)
			require.NoErrorf(t, err, "failed to advertise route: %s", err)
		} else {
			t.Fatalf("failed to find route for Node %s (id: %s)", status.Self.HostName, status.Self.ID)
		}
	}

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	nodes, err := headscale.ListNodes()
	require.NoError(t, err)
	assert.Len(t, nodes, 4)

	assertNodeRouteCount(t, nodes[0], 1, 0, 0)
	assertNodeRouteCount(t, nodes[1], 1, 0, 0)
	assertNodeRouteCount(t, nodes[2], 1, 0, 0)

	// Verify that no routes has been sent to the client,
	// they are not yet enabled.
	for _, client := range allClients {
		status, err := client.Status()
		require.NoError(t, err)

		for _, peerKey := range status.Peers() {
			peerStatus := status.Peer[peerKey]

			assert.Nil(t, peerStatus.PrimaryRoutes)
			assertPeerSubnetRoutes(t, peerStatus, nil)
		}
	}

	// Enable all routes
	for _, node := range nodes {
		_, err := headscale.ApproveRoutes(
			node.GetId(),
			util.MustStringsToPrefixes(node.GetAvailableRoutes()),
		)
		require.NoError(t, err)
	}

	nodes, err = headscale.ListNodes()
	require.NoError(t, err)
	assert.Len(t, nodes, 4)

	assertNodeRouteCount(t, nodes[0], 1, 1, 1)
	assertNodeRouteCount(t, nodes[1], 1, 1, 1)
	assertNodeRouteCount(t, nodes[2], 1, 1, 1)

	// Verify that the client has routes from the primary machine
	srs1 := subRouter1.MustStatus()
	srs2 := subRouter2.MustStatus()
	srs3 := subRouter3.MustStatus()
	clientStatus := client.MustStatus()

	srs1PeerStatus := clientStatus.Peer[srs1.Self.PublicKey]
	srs2PeerStatus := clientStatus.Peer[srs2.Self.PublicKey]
	srs3PeerStatus := clientStatus.Peer[srs3.Self.PublicKey]

	assert.True(t, srs1PeerStatus.Online, "r1 up, r2 up")
	assert.True(t, srs2PeerStatus.Online, "r1 up, r2 up")
	assert.True(t, srs3PeerStatus.Online, "r1 up, r2 up")

	assert.Nil(t, srs2PeerStatus.PrimaryRoutes)
	assert.Nil(t, srs3PeerStatus.PrimaryRoutes)
	require.NotNil(t, srs1PeerStatus.PrimaryRoutes)

	assert.Contains(t,
		srs1PeerStatus.PrimaryRoutes.AsSlice(),
		netip.MustParsePrefix(expectedRoutes[string(srs1.Self.ID)]),
	)

	// Take down the current primary
	t.Logf("taking down subnet router r1 (%s)", subRouter1.Hostname())
	t.Logf("expecting r2 (%s) to take over as primary", subRouter2.Hostname())
	err = subRouter1.Down()
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	srs2 = subRouter2.MustStatus()
	clientStatus = client.MustStatus()

	srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
	srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]
	srs3PeerStatus = clientStatus.Peer[srs3.Self.PublicKey]

	assert.False(t, srs1PeerStatus.Online, "r1 down, r2 down")
	assert.True(t, srs2PeerStatus.Online, "r1 down, r2 up")
	assert.True(t, srs3PeerStatus.Online, "r1 down, r2 up")

	assert.Nil(t, srs1PeerStatus.PrimaryRoutes)
	require.NotNil(t, srs2PeerStatus.PrimaryRoutes)
	assert.Nil(t, srs3PeerStatus.PrimaryRoutes)

	assert.Contains(
		t,
		srs2PeerStatus.PrimaryRoutes.AsSlice(),
		netip.MustParsePrefix(expectedRoutes[string(srs2.Self.ID)]),
	)

	// Take down subnet router 2, leaving none available
	t.Logf("taking down subnet router r2 (%s)", subRouter2.Hostname())
	t.Logf("expecting no primary, r3 available, but no HA so no primary")
	err = subRouter2.Down()
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	// TODO(kradalby): Check client status
	// Both are expected to be down

	// Verify that the route is not presented from either router
	clientStatus, err = client.Status()
	require.NoError(t, err)

	srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
	srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]
	srs3PeerStatus = clientStatus.Peer[srs3.Self.PublicKey]

	assert.False(t, srs1PeerStatus.Online, "r1 down, r2 down")
	assert.False(t, srs2PeerStatus.Online, "r1 down, r2 down")
	assert.True(t, srs3PeerStatus.Online, "r1 down, r2 down")

	assert.Nil(t, srs1PeerStatus.PrimaryRoutes)
	assert.Nil(t, srs2PeerStatus.PrimaryRoutes)
	assert.Nil(t, srs3PeerStatus.PrimaryRoutes)

	// Bring up subnet router 1, making the route available from there.
	t.Logf("bringing up subnet router r1 (%s)", subRouter1.Hostname())
	t.Logf("expecting r1 (%s) to take over as primary, r1 and r3 available", subRouter1.Hostname())
	err = subRouter1.Up()
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	// Verify that the route is announced from subnet router 1
	clientStatus, err = client.Status()
	require.NoError(t, err)

	srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
	srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]
	srs3PeerStatus = clientStatus.Peer[srs3.Self.PublicKey]

	assert.True(t, srs1PeerStatus.Online, "r1 is back up, r2 down")
	assert.False(t, srs2PeerStatus.Online, "r1 is back up, r2 down")
	assert.True(t, srs3PeerStatus.Online, "r1 is back up, r3 available")

	assert.NotNil(t, srs1PeerStatus.PrimaryRoutes)
	assert.Nil(t, srs2PeerStatus.PrimaryRoutes)
	assert.Nil(t, srs3PeerStatus.PrimaryRoutes)

	assert.Contains(
		t,
		srs1PeerStatus.PrimaryRoutes.AsSlice(),
		netip.MustParsePrefix(expectedRoutes[string(srs1.Self.ID)]),
	)

	// Bring up subnet router 2, should result in no change.
	t.Logf("bringing up subnet router r2 (%s)", subRouter2.Hostname())
	t.Logf("all online, expecting r1 (%s) to still be primary (no flapping)", subRouter1.Hostname())
	err = subRouter2.Up()
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	// Verify that the route is announced from subnet router 1
	clientStatus, err = client.Status()
	require.NoError(t, err)

	srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
	srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]
	srs3PeerStatus = clientStatus.Peer[srs3.Self.PublicKey]

	assert.True(t, srs1PeerStatus.Online, "r1 up, r2 up")
	assert.True(t, srs2PeerStatus.Online, "r1 up, r2 up")
	assert.True(t, srs3PeerStatus.Online, "r1 up, r2 up")

	require.NotNil(t, srs1PeerStatus.PrimaryRoutes)
	assert.Nil(t, srs2PeerStatus.PrimaryRoutes)
	assert.Nil(t, srs3PeerStatus.PrimaryRoutes)

	assert.Contains(
		t,
		srs1PeerStatus.PrimaryRoutes.AsSlice(),
		netip.MustParsePrefix(expectedRoutes[string(srs1.Self.ID)]),
	)

	// Disable the route of subnet router 1, making it failover to 2
	t.Logf("disabling route in subnet router r1 (%s)", subRouter1.Hostname())
	t.Logf("expecting route to failover to r2 (%s), which is still available with r3", subRouter2.Hostname())
	_, err = headscale.ApproveRoutes(nodes[0].GetId(), []netip.Prefix{})

	time.Sleep(5 * time.Second)

	nodes, err = headscale.ListNodes()
	require.NoError(t, err)
	assert.Len(t, nodes, 4)

	assertNodeRouteCount(t, nodes[0], 1, 0, 0)
	assertNodeRouteCount(t, nodes[1], 1, 1, 1)
	assertNodeRouteCount(t, nodes[2], 1, 1, 1)

	// Verify that the route is announced from subnet router 1
	clientStatus, err = client.Status()
	require.NoError(t, err)

	srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
	srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]
	srs3PeerStatus = clientStatus.Peer[srs3.Self.PublicKey]

	assert.Nil(t, srs1PeerStatus.PrimaryRoutes)
	assert.NotNil(t, srs2PeerStatus.PrimaryRoutes)
	assert.Nil(t, srs3PeerStatus.PrimaryRoutes)

	assert.Contains(
		t,
		srs2PeerStatus.PrimaryRoutes.AsSlice(),
		netip.MustParsePrefix(expectedRoutes[string(srs2.Self.ID)]),
	)

	// enable the route of subnet router 1, no change expected
	t.Logf("enabling route in subnet router 1 (%s)", subRouter1.Hostname())
	t.Logf("both online, expecting r2 (%s) to still be primary (no flapping)", subRouter2.Hostname())
	_, err = headscale.ApproveRoutes(
		nodes[0].GetId(),
		util.MustStringsToPrefixes(nodes[0].GetAvailableRoutes()),
	)

	time.Sleep(5 * time.Second)

	nodes, err = headscale.ListNodes()
	require.NoError(t, err)
	assert.Len(t, nodes, 4)

	assertNodeRouteCount(t, nodes[0], 1, 1, 1)
	assertNodeRouteCount(t, nodes[1], 1, 1, 1)
	assertNodeRouteCount(t, nodes[2], 1, 1, 1)

	// Verify that the route is announced from subnet router 1
	clientStatus, err = client.Status()
	require.NoError(t, err)

	srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
	srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]
	srs3PeerStatus = clientStatus.Peer[srs3.Self.PublicKey]

	assert.Nil(t, srs1PeerStatus.PrimaryRoutes)
	require.NotNil(t, srs2PeerStatus.PrimaryRoutes)
	assert.Nil(t, srs3PeerStatus.PrimaryRoutes)

	assert.Contains(
		t,
		srs2PeerStatus.PrimaryRoutes.AsSlice(),
		netip.MustParsePrefix(expectedRoutes[string(srs2.Self.ID)]),
	)
}

func TestEnableDisableAutoApprovedRoute(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	expectedRoutes := "172.0.0.0/24"

	user := "user2"

	scenario, err := NewScenario(dockertestMaxWait())
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		user: 1,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{tsic.WithTags([]string{"tag:approve"})}, hsic.WithTestName("clienableroute"), hsic.WithACLPolicy(
		&policyv1.ACLPolicy{
			ACLs: []policyv1.ACL{
				{
					Action:       "accept",
					Sources:      []string{"*"},
					Destinations: []string{"*:*"},
				},
			},
			TagOwners: map[string][]string{
				"tag:approve": {user},
			},
			AutoApprovers: policyv1.AutoApprovers{
				Routes: map[string][]string{
					expectedRoutes: {"tag:approve"},
				},
			},
		},
	))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	assertNoErrGetHeadscale(t, err)

	subRouter1 := allClients[0]

	// Initially advertise route
	command := []string{
		"tailscale",
		"set",
		"--advertise-routes=" + expectedRoutes,
	}
	_, _, err = subRouter1.Execute(command)
	require.NoErrorf(t, err, "failed to advertise route: %s", err)

	time.Sleep(10 * time.Second)

	nodes, err := headscale.ListNodes()
	require.NoError(t, err)
	assert.Len(t, nodes, 1)
	assertNodeRouteCount(t, nodes[0], 1, 1, 1)

	// Stop advertising route
	command = []string{
		"tailscale",
		"set",
		"--advertise-routes=",
	}
	_, _, err = subRouter1.Execute(command)
	require.NoErrorf(t, err, "failed to remove advertised route: %s", err)

	time.Sleep(10 * time.Second)

	nodes, err = headscale.ListNodes()
	require.NoError(t, err)
	assert.Len(t, nodes, 1)
	assertNodeRouteCount(t, nodes[0], 0, 1, 0)

	// Advertise route again
	command = []string{
		"tailscale",
		"set",
		"--advertise-routes=" + expectedRoutes,
	}
	_, _, err = subRouter1.Execute(command)
	require.NoErrorf(t, err, "failed to advertise route: %s", err)

	time.Sleep(10 * time.Second)

	nodes, err = headscale.ListNodes()
	require.NoError(t, err)
	assert.Len(t, nodes, 1)
	assertNodeRouteCount(t, nodes[0], 1, 1, 1)
}

func TestAutoApprovedSubRoute2068(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	expectedRoutes := "10.42.7.0/24"

	user := "user1"

	scenario, err := NewScenario(dockertestMaxWait())
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		user: 1,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{tsic.WithTags([]string{"tag:approve"})},
		hsic.WithTestName("clienableroute"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
		hsic.WithACLPolicy(
			&policyv1.ACLPolicy{
				ACLs: []policyv1.ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:*"},
					},
				},
				TagOwners: map[string][]string{
					"tag:approve": {user},
				},
				AutoApprovers: policyv1.AutoApprovers{
					Routes: map[string][]string{
						"10.42.0.0/16": {"tag:approve"},
					},
				},
			},
		))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	assertNoErrGetHeadscale(t, err)

	subRouter1 := allClients[0]

	// Initially advertise route
	command := []string{
		"tailscale",
		"set",
		"--advertise-routes=" + expectedRoutes,
	}
	_, _, err = subRouter1.Execute(command)
	require.NoErrorf(t, err, "failed to advertise route: %s", err)

	time.Sleep(10 * time.Second)

	nodes, err := headscale.ListNodes()
	require.NoError(t, err)
	assert.Len(t, nodes, 1)
	assertNodeRouteCount(t, nodes[0], 1, 1, 1)
}

// TestSubnetRouteACL verifies that Subnet routes are distributed
// as expected when ACLs are activated.
// It implements the issue from
// https://github.com/juanfont/headscale/issues/1604
func TestSubnetRouteACL(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	user := "user4"

	scenario, err := NewScenario(dockertestMaxWait())
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		user: 2,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clienableroute"), hsic.WithACLPolicy(
		&policyv1.ACLPolicy{
			Groups: policyv1.Groups{
				"group:admins": {user},
			},
			ACLs: []policyv1.ACL{
				{
					Action:       "accept",
					Sources:      []string{"group:admins"},
					Destinations: []string{"group:admins:*"},
				},
				{
					Action:       "accept",
					Sources:      []string{"group:admins"},
					Destinations: []string{"10.33.0.0/16:*"},
				},
				// {
				// 	Action:       "accept",
				// 	Sources:      []string{"group:admins"},
				// 	Destinations: []string{"0.0.0.0/0:*"},
				// },
			},
		},
	))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	assertNoErrGetHeadscale(t, err)

	expectedRoutes := map[string]string{
		"1": "10.33.0.0/16",
	}

	// Sort nodes by ID
	sort.SliceStable(allClients, func(i, j int) bool {
		statusI, err := allClients[i].Status()
		if err != nil {
			return false
		}

		statusJ, err := allClients[j].Status()
		if err != nil {
			return false
		}

		return statusI.Self.ID < statusJ.Self.ID
	})

	subRouter1 := allClients[0]

	client := allClients[1]

	for _, client := range allClients {
		status, err := client.Status()
		require.NoError(t, err)

		if route, ok := expectedRoutes[string(status.Self.ID)]; ok {
			command := []string{
				"tailscale",
				"set",
				"--advertise-routes=" + route,
			}
			_, _, err = client.Execute(command)
			require.NoErrorf(t, err, "failed to advertise route: %s", err)
		}
	}

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	nodes, err := headscale.ListNodes()
	require.NoError(t, err)
	require.Len(t, nodes, 2)

	assertNodeRouteCount(t, nodes[0], 1, 0, 0)
	assertNodeRouteCount(t, nodes[1], 0, 0, 0)

	// Verify that no routes has been sent to the client,
	// they are not yet enabled.
	for _, client := range allClients {
		status, err := client.Status()
		require.NoError(t, err)

		for _, peerKey := range status.Peers() {
			peerStatus := status.Peer[peerKey]

			assert.Nil(t, peerStatus.PrimaryRoutes)
			assertPeerSubnetRoutes(t, peerStatus, nil)
		}
	}

	_, err = headscale.ApproveRoutes(
		1,
		[]netip.Prefix{netip.MustParsePrefix(expectedRoutes["1"])},
	)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	nodes, err = headscale.ListNodes()
	require.NoError(t, err)
	require.Len(t, nodes, 2)

	assertNodeRouteCount(t, nodes[0], 1, 1, 1)
	assertNodeRouteCount(t, nodes[1], 0, 0, 0)

	// Verify that the client has routes from the primary machine
	srs1, _ := subRouter1.Status()

	clientStatus, err := client.Status()
	require.NoError(t, err)

	srs1PeerStatus := clientStatus.Peer[srs1.Self.PublicKey]

	assertPeerSubnetRoutes(t, srs1PeerStatus, []netip.Prefix{netip.MustParsePrefix(expectedRoutes["1"])})

	clientNm, err := client.Netmap()
	require.NoError(t, err)

	wantClientFilter := []filter.Match{
		{
			IPProto: views.SliceOf([]ipproto.Proto{
				ipproto.TCP, ipproto.UDP, ipproto.ICMPv4, ipproto.ICMPv6,
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

	if diff := cmp.Diff(wantClientFilter, clientNm.PacketFilter, util.ViewSliceIPProtoComparer, util.PrefixComparer); diff != "" {
		t.Errorf("Client (%s) filter, unexpected result (-want +got):\n%s", client.Hostname(), diff)
	}

	subnetNm, err := subRouter1.Netmap()
	require.NoError(t, err)

	wantSubnetFilter := []filter.Match{
		{
			IPProto: views.SliceOf([]ipproto.Proto{
				ipproto.TCP, ipproto.UDP, ipproto.ICMPv4, ipproto.ICMPv6,
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
				ipproto.TCP, ipproto.UDP, ipproto.ICMPv4, ipproto.ICMPv6,
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

	if diff := cmp.Diff(wantSubnetFilter, subnetNm.PacketFilter, util.ViewSliceIPProtoComparer, util.PrefixComparer); diff != "" {
		t.Errorf("Subnet (%s) filter, unexpected result (-want +got):\n%s", subRouter1.Hostname(), diff)
	}
}

// TestEnablingExitRoutes tests enabling exit routes for clients.
// Its more or less the same as TestEnablingRoutes, but with the --advertise-exit-node flag
// set during login instead of set.
func TestEnablingExitRoutes(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	user := "user2"

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErrf(t, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		user: 2,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{
		tsic.WithExtraLoginArgs([]string{"--advertise-exit-node"}),
	}, hsic.WithTestName("clienableroute"))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	assertNoErrGetHeadscale(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	nodes, err := headscale.ListNodes()
	require.NoError(t, err)
	require.Len(t, nodes, 2)

	assertNodeRouteCount(t, nodes[0], 2, 0, 0)
	assertNodeRouteCount(t, nodes[1], 2, 0, 0)

	// Verify that no routes has been sent to the client,
	// they are not yet enabled.
	for _, client := range allClients {
		status, err := client.Status()
		assertNoErr(t, err)

		for _, peerKey := range status.Peers() {
			peerStatus := status.Peer[peerKey]

			assert.Nil(t, peerStatus.PrimaryRoutes)
		}
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

	nodes, err = headscale.ListNodes()
	require.NoError(t, err)
	require.Len(t, nodes, 2)

	assertNodeRouteCount(t, nodes[0], 2, 2, 2)
	assertNodeRouteCount(t, nodes[1], 2, 2, 2)

	time.Sleep(5 * time.Second)

	// Verify that the clients can see the new routes
	for _, client := range allClients {
		status, err := client.Status()
		assertNoErr(t, err)

		for _, peerKey := range status.Peers() {
			peerStatus := status.Peer[peerKey]

			require.NotNil(t, peerStatus.AllowedIPs)
			assert.Len(t, peerStatus.AllowedIPs.AsSlice(), 4)
			assert.Contains(t, peerStatus.AllowedIPs.AsSlice(), tsaddr.AllIPv4())
			assert.Contains(t, peerStatus.AllowedIPs.AsSlice(), tsaddr.AllIPv6())
		}
	}
}

// assertPeerSubnetRoutes asserts that the peer has the expected subnet routes.
func assertPeerSubnetRoutes(t *testing.T, status *ipnstate.PeerStatus, expected []netip.Prefix) {
	t.Helper()
	if status.AllowedIPs.Len() <= 2 && len(expected) != 0 {
		t.Errorf("peer %s (%s) has no subnet routes, expected %v", status.HostName, status.ID, expected)
		return
	}

	if len(expected) == 0 {
		expected = []netip.Prefix{}
	}

	got := status.AllowedIPs.AsSlice()[2:]

	if diff := cmp.Diff(expected, got, util.PrefixComparer); diff != "" {
		t.Errorf("peer %s (%s) subnet routes, unexpected result (-want +got):\n%s", status.HostName, status.ID, diff)
	}
}

func assertNodeRouteCount(t *testing.T, node *v1.Node, announced, approved, subnet int) {
	t.Helper()
	assert.Len(t, node.GetAvailableRoutes(), announced)
	assert.Len(t, node.GetApprovedRoutes(), approved)
	assert.Len(t, node.GetSubnetRoutes(), subnet)
}
