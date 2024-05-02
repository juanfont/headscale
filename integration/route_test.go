package integration

import (
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"tailscale.com/types/ipproto"
	"tailscale.com/wgengine/filter"
)

// This test is both testing the routes command and the propagation of
// routes.
func TestEnablingRoutes(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	user := "enable-routing"

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErrf(t, "failed to create scenario: %s", err)
	defer scenario.Shutdown()

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
		assertNoErr(t, err)

		command := []string{
			"tailscale",
			"set",
			"--advertise-routes=" + expectedRoutes[string(status.Self.ID)],
		}
		_, _, err = client.Execute(command)
		assertNoErrf(t, "failed to advertise route: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	var routes []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&routes,
	)

	assertNoErr(t, err)
	assert.Len(t, routes, 3)

	for _, route := range routes {
		assert.Equal(t, true, route.GetAdvertised())
		assert.Equal(t, false, route.GetEnabled())
		assert.Equal(t, false, route.GetIsPrimary())
	}

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

	// Enable all routes
	for _, route := range routes {
		_, err = headscale.Execute(
			[]string{
				"headscale",
				"routes",
				"enable",
				"--route",
				strconv.Itoa(int(route.GetId())),
			})
		assertNoErr(t, err)
	}

	var enablingRoutes []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&enablingRoutes,
	)
	assertNoErr(t, err)
	assert.Len(t, enablingRoutes, 3)

	for _, route := range enablingRoutes {
		assert.Equal(t, true, route.GetAdvertised())
		assert.Equal(t, true, route.GetEnabled())
		assert.Equal(t, true, route.GetIsPrimary())
	}

	time.Sleep(5 * time.Second)

	// Verify that the clients can see the new routes
	for _, client := range allClients {
		status, err := client.Status()
		assertNoErr(t, err)

		for _, peerKey := range status.Peers() {
			peerStatus := status.Peer[peerKey]

			assert.NotNil(t, peerStatus.PrimaryRoutes)
			if peerStatus.PrimaryRoutes == nil {
				continue
			}

			pRoutes := peerStatus.PrimaryRoutes.AsSlice()

			assert.Len(t, pRoutes, 1)

			if len(pRoutes) > 0 {
				peerRoute := peerStatus.PrimaryRoutes.AsSlice()[0]

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

	routeToBeDisabled := enablingRoutes[0]
	log.Printf("preparing to disable %v", routeToBeDisabled)

	_, err = headscale.Execute(
		[]string{
			"headscale",
			"routes",
			"disable",
			"--route",
			strconv.Itoa(int(routeToBeDisabled.GetId())),
		})
	assertNoErr(t, err)

	time.Sleep(5 * time.Second)

	var disablingRoutes []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&disablingRoutes,
	)
	assertNoErr(t, err)

	for _, route := range disablingRoutes {
		assert.Equal(t, true, route.GetAdvertised())

		if route.GetId() == routeToBeDisabled.GetId() {
			assert.Equal(t, false, route.GetEnabled())

			// since this is the only route of this cidr,
			// it will not failover, and remain Primary
			// until something can replace it.
			assert.Equal(t, true, route.GetIsPrimary())
		} else {
			assert.Equal(t, true, route.GetEnabled())
			assert.Equal(t, true, route.GetIsPrimary())
		}
	}

	// Verify that the clients can see the new routes
	for _, client := range allClients {
		status, err := client.Status()
		assertNoErr(t, err)

		for _, peerKey := range status.Peers() {
			peerStatus := status.Peer[peerKey]

			if string(peerStatus.ID) == fmt.Sprintf("%d", routeToBeDisabled.GetNode().GetId()) {
				assert.Nilf(
					t,
					peerStatus.PrimaryRoutes,
					"expected node %s to have no routes, got primary route (%v)",
					peerStatus.HostName,
					peerStatus.PrimaryRoutes,
				)
			}
		}
	}
}

func TestHASubnetRouterFailover(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	user := "enable-routing"

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErrf(t, "failed to create scenario: %s", err)
	defer scenario.Shutdown()

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
		"2": "10.0.0.0/24",
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
	subRouter2 := allClients[1]

	client := allClients[2]

	t.Logf("Advertise route from r1 (%s) and r2 (%s), making it HA, n1 is primary", subRouter1.Hostname(), subRouter2.Hostname())
	// advertise HA route on node 1 and 2
	// ID 1 will be primary
	// ID 2 will be secondary
	for _, client := range allClients[:2] {
		status, err := client.Status()
		assertNoErr(t, err)

		if route, ok := expectedRoutes[string(status.Self.ID)]; ok {
			command := []string{
				"tailscale",
				"set",
				"--advertise-routes=" + route,
			}
			_, _, err = client.Execute(command)
			assertNoErrf(t, "failed to advertise route: %s", err)
		} else {
			t.Fatalf("failed to find route for Node %s (id: %s)", status.Self.HostName, status.Self.ID)
		}
	}

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	var routes []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&routes,
	)

	assertNoErr(t, err)
	assert.Len(t, routes, 2)

	t.Logf("initial routes %#v", routes)

	for _, route := range routes {
		assert.Equal(t, true, route.GetAdvertised())
		assert.Equal(t, false, route.GetEnabled())
		assert.Equal(t, false, route.GetIsPrimary())
	}

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

	// Enable all routes
	for _, route := range routes {
		_, err = headscale.Execute(
			[]string{
				"headscale",
				"routes",
				"enable",
				"--route",
				strconv.Itoa(int(route.GetId())),
			})
		assertNoErr(t, err)

		time.Sleep(time.Second)
	}

	var enablingRoutes []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&enablingRoutes,
	)
	assertNoErr(t, err)
	assert.Len(t, enablingRoutes, 2)

	// Node 1 is primary
	assert.Equal(t, true, enablingRoutes[0].GetAdvertised())
	assert.Equal(t, true, enablingRoutes[0].GetEnabled())
	assert.Equal(t, true, enablingRoutes[0].GetIsPrimary(), "both subnet routers are up, expected r1 to be primary")

	// Node 2 is not primary
	assert.Equal(t, true, enablingRoutes[1].GetAdvertised())
	assert.Equal(t, true, enablingRoutes[1].GetEnabled())
	assert.Equal(t, false, enablingRoutes[1].GetIsPrimary(), "both subnet routers are up, expected r2 to be non-primary")

	// Verify that the client has routes from the primary machine
	srs1, err := subRouter1.Status()
	srs2, err := subRouter2.Status()

	clientStatus, err := client.Status()
	assertNoErr(t, err)

	srs1PeerStatus := clientStatus.Peer[srs1.Self.PublicKey]
	srs2PeerStatus := clientStatus.Peer[srs2.Self.PublicKey]

	assert.True(t, srs1PeerStatus.Online, "r1 up, r2 up")
	assert.True(t, srs2PeerStatus.Online, "r1 up, r2 up")

	assertNotNil(t, srs1PeerStatus.PrimaryRoutes)
	assert.Nil(t, srs2PeerStatus.PrimaryRoutes)

	assert.Contains(
		t,
		srs1PeerStatus.PrimaryRoutes.AsSlice(),
		netip.MustParsePrefix(expectedRoutes[string(srs1.Self.ID)]),
	)

	// Take down the current primary
	t.Logf("taking down subnet router r1 (%s)", subRouter1.Hostname())
	t.Logf("expecting r2 (%s) to take over as primary", subRouter2.Hostname())
	err = subRouter1.Down()
	assertNoErr(t, err)

	time.Sleep(5 * time.Second)

	var routesAfterMove []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&routesAfterMove,
	)
	assertNoErr(t, err)
	assert.Len(t, routesAfterMove, 2)

	// Node 1 is not primary
	assert.Equal(t, true, routesAfterMove[0].GetAdvertised())
	assert.Equal(t, true, routesAfterMove[0].GetEnabled())
	assert.Equal(t, false, routesAfterMove[0].GetIsPrimary(), "r1 is down, expected r2 to be primary")

	// Node 2 is primary
	assert.Equal(t, true, routesAfterMove[1].GetAdvertised())
	assert.Equal(t, true, routesAfterMove[1].GetEnabled())
	assert.Equal(t, true, routesAfterMove[1].GetIsPrimary(), "r1 is down, expected r2 to be primary")

	srs2, err = subRouter2.Status()

	clientStatus, err = client.Status()
	assertNoErr(t, err)

	srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
	srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]

	assert.False(t, srs1PeerStatus.Online, "r1 down, r2 down")
	assert.True(t, srs2PeerStatus.Online, "r1 down, r2 up")

	assert.Nil(t, srs1PeerStatus.PrimaryRoutes)
	assertNotNil(t, srs2PeerStatus.PrimaryRoutes)

	if srs2PeerStatus.PrimaryRoutes != nil {
		assert.Contains(
			t,
			srs2PeerStatus.PrimaryRoutes.AsSlice(),
			netip.MustParsePrefix(expectedRoutes[string(srs2.Self.ID)]),
		)
	}

	// Take down subnet router 2, leaving none available
	t.Logf("taking down subnet router r2 (%s)", subRouter2.Hostname())
	t.Logf("expecting r2 (%s) to remain primary, no other available", subRouter2.Hostname())
	err = subRouter2.Down()
	assertNoErr(t, err)

	time.Sleep(5 * time.Second)

	var routesAfterBothDown []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&routesAfterBothDown,
	)
	assertNoErr(t, err)
	assert.Len(t, routesAfterBothDown, 2)

	// Node 1 is not primary
	assert.Equal(t, true, routesAfterBothDown[0].GetAdvertised())
	assert.Equal(t, true, routesAfterBothDown[0].GetEnabled())
	assert.Equal(t, false, routesAfterBothDown[0].GetIsPrimary(), "r1 and r2 is down, expected r2 to _still_ be primary")

	// Node 2 is primary
	// if the node goes down, but no other suitable route is
	// available, keep the last known good route.
	assert.Equal(t, true, routesAfterBothDown[1].GetAdvertised())
	assert.Equal(t, true, routesAfterBothDown[1].GetEnabled())
	assert.Equal(t, true, routesAfterBothDown[1].GetIsPrimary(), "r1 and r2 is down, expected r2 to _still_ be primary")

	// TODO(kradalby): Check client status
	// Both are expected to be down

	// Verify that the route is not presented from either router
	clientStatus, err = client.Status()
	assertNoErr(t, err)

	srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
	srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]

	assert.False(t, srs1PeerStatus.Online, "r1 down, r2 down")
	assert.False(t, srs2PeerStatus.Online, "r1 down, r2 down")

	assert.Nil(t, srs1PeerStatus.PrimaryRoutes)
	assertNotNil(t, srs2PeerStatus.PrimaryRoutes)

	if srs2PeerStatus.PrimaryRoutes != nil {
		assert.Contains(
			t,
			srs2PeerStatus.PrimaryRoutes.AsSlice(),
			netip.MustParsePrefix(expectedRoutes[string(srs2.Self.ID)]),
		)
	}

	// Bring up subnet router 1, making the route available from there.
	t.Logf("bringing up subnet router r1 (%s)", subRouter1.Hostname())
	t.Logf("expecting r1 (%s) to take over as primary (only one online)", subRouter1.Hostname())
	err = subRouter1.Up()
	assertNoErr(t, err)

	time.Sleep(5 * time.Second)

	var routesAfter1Up []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&routesAfter1Up,
	)
	assertNoErr(t, err)
	assert.Len(t, routesAfter1Up, 2)

	// Node 1 is primary
	assert.Equal(t, true, routesAfter1Up[0].GetAdvertised())
	assert.Equal(t, true, routesAfter1Up[0].GetEnabled())
	assert.Equal(t, true, routesAfter1Up[0].GetIsPrimary(), "r1 is back up, expected r1 to become be primary")

	// Node 2 is not primary
	assert.Equal(t, true, routesAfter1Up[1].GetAdvertised())
	assert.Equal(t, true, routesAfter1Up[1].GetEnabled())
	assert.Equal(t, false, routesAfter1Up[1].GetIsPrimary(), "r1 is back up, expected r1 to become be primary")

	// Verify that the route is announced from subnet router 1
	clientStatus, err = client.Status()
	assertNoErr(t, err)

	srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
	srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]

	assert.True(t, srs1PeerStatus.Online, "r1 is back up, r2 down")
	assert.False(t, srs2PeerStatus.Online, "r1 is back up, r2 down")

	assert.NotNil(t, srs1PeerStatus.PrimaryRoutes)
	assert.Nil(t, srs2PeerStatus.PrimaryRoutes)

	if srs1PeerStatus.PrimaryRoutes != nil {
		assert.Contains(
			t,
			srs1PeerStatus.PrimaryRoutes.AsSlice(),
			netip.MustParsePrefix(expectedRoutes[string(srs1.Self.ID)]),
		)
	}

	// Bring up subnet router 2, should result in no change.
	t.Logf("bringing up subnet router r2 (%s)", subRouter2.Hostname())
	t.Logf("both online, expecting r1 (%s) to still be primary (no flapping)", subRouter1.Hostname())
	err = subRouter2.Up()
	assertNoErr(t, err)

	time.Sleep(5 * time.Second)

	var routesAfter2Up []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&routesAfter2Up,
	)
	assertNoErr(t, err)
	assert.Len(t, routesAfter2Up, 2)

	// Node 1 is not primary
	assert.Equal(t, true, routesAfter2Up[0].GetAdvertised())
	assert.Equal(t, true, routesAfter2Up[0].GetEnabled())
	assert.Equal(t, true, routesAfter2Up[0].GetIsPrimary(), "r1 and r2 is back up, expected r1 to _still_ be primary")

	// Node 2 is primary
	assert.Equal(t, true, routesAfter2Up[1].GetAdvertised())
	assert.Equal(t, true, routesAfter2Up[1].GetEnabled())
	assert.Equal(t, false, routesAfter2Up[1].GetIsPrimary(), "r1 and r2 is back up, expected r1 to _still_ be primary")

	// Verify that the route is announced from subnet router 1
	clientStatus, err = client.Status()
	assertNoErr(t, err)

	srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
	srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]

	assert.True(t, srs1PeerStatus.Online, "r1 up, r2 up")
	assert.True(t, srs2PeerStatus.Online, "r1 up, r2 up")

	assert.NotNil(t, srs1PeerStatus.PrimaryRoutes)
	assert.Nil(t, srs2PeerStatus.PrimaryRoutes)

	if srs1PeerStatus.PrimaryRoutes != nil {
		assert.Contains(
			t,
			srs1PeerStatus.PrimaryRoutes.AsSlice(),
			netip.MustParsePrefix(expectedRoutes[string(srs1.Self.ID)]),
		)
	}

	// Disable the route of subnet router 1, making it failover to 2
	t.Logf("disabling route in subnet router r1 (%s)", subRouter1.Hostname())
	t.Logf("expecting route to failover to r2 (%s), which is still available", subRouter2.Hostname())
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"routes",
			"disable",
			"--route",
			fmt.Sprintf("%d", routesAfter2Up[0].GetId()),
		})
	assertNoErr(t, err)

	time.Sleep(5 * time.Second)

	var routesAfterDisabling1 []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&routesAfterDisabling1,
	)
	assertNoErr(t, err)
	assert.Len(t, routesAfterDisabling1, 2)

	t.Logf("routes after disabling r1 %#v", routesAfterDisabling1)

	// Node 1 is not primary
	assert.Equal(t, true, routesAfterDisabling1[0].GetAdvertised())
	assert.Equal(t, false, routesAfterDisabling1[0].GetEnabled())
	assert.Equal(t, false, routesAfterDisabling1[0].GetIsPrimary())

	// Node 2 is primary
	assert.Equal(t, true, routesAfterDisabling1[1].GetAdvertised())
	assert.Equal(t, true, routesAfterDisabling1[1].GetEnabled())
	assert.Equal(t, true, routesAfterDisabling1[1].GetIsPrimary())

	// Verify that the route is announced from subnet router 1
	clientStatus, err = client.Status()
	assertNoErr(t, err)

	srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
	srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]

	assert.Nil(t, srs1PeerStatus.PrimaryRoutes)
	assert.NotNil(t, srs2PeerStatus.PrimaryRoutes)

	if srs2PeerStatus.PrimaryRoutes != nil {
		assert.Contains(
			t,
			srs2PeerStatus.PrimaryRoutes.AsSlice(),
			netip.MustParsePrefix(expectedRoutes[string(srs2.Self.ID)]),
		)
	}

	// enable the route of subnet router 1, no change expected
	t.Logf("enabling route in subnet router 1 (%s)", subRouter1.Hostname())
	t.Logf("both online, expecting r2 (%s) to still be primary (no flapping)", subRouter2.Hostname())
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"routes",
			"enable",
			"--route",
			fmt.Sprintf("%d", routesAfter2Up[0].GetId()),
		})
	assertNoErr(t, err)

	time.Sleep(5 * time.Second)

	var routesAfterEnabling1 []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&routesAfterEnabling1,
	)
	assertNoErr(t, err)
	assert.Len(t, routesAfterEnabling1, 2)

	// Node 1 is not primary
	assert.Equal(t, true, routesAfterEnabling1[0].GetAdvertised())
	assert.Equal(t, true, routesAfterEnabling1[0].GetEnabled())
	assert.Equal(t, false, routesAfterEnabling1[0].GetIsPrimary())

	// Node 2 is primary
	assert.Equal(t, true, routesAfterEnabling1[1].GetAdvertised())
	assert.Equal(t, true, routesAfterEnabling1[1].GetEnabled())
	assert.Equal(t, true, routesAfterEnabling1[1].GetIsPrimary())

	// Verify that the route is announced from subnet router 1
	clientStatus, err = client.Status()
	assertNoErr(t, err)

	srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
	srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]

	assert.Nil(t, srs1PeerStatus.PrimaryRoutes)
	assert.NotNil(t, srs2PeerStatus.PrimaryRoutes)

	if srs2PeerStatus.PrimaryRoutes != nil {
		assert.Contains(
			t,
			srs2PeerStatus.PrimaryRoutes.AsSlice(),
			netip.MustParsePrefix(expectedRoutes[string(srs2.Self.ID)]),
		)
	}

	// delete the route of subnet router 2, failover to one expected
	t.Logf("deleting route in subnet router r2 (%s)", subRouter2.Hostname())
	t.Logf("expecting route to failover to r1 (%s)", subRouter1.Hostname())
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"routes",
			"delete",
			"--route",
			fmt.Sprintf("%d", routesAfterEnabling1[1].GetId()),
		})
	assertNoErr(t, err)

	time.Sleep(5 * time.Second)

	var routesAfterDeleting2 []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&routesAfterDeleting2,
	)
	assertNoErr(t, err)
	assert.Len(t, routesAfterDeleting2, 1)

	t.Logf("routes after deleting r2 %#v", routesAfterDeleting2)

	// Node 1 is primary
	assert.Equal(t, true, routesAfterDeleting2[0].GetAdvertised())
	assert.Equal(t, true, routesAfterDeleting2[0].GetEnabled())
	assert.Equal(t, true, routesAfterDeleting2[0].GetIsPrimary())

	// Verify that the route is announced from subnet router 1
	clientStatus, err = client.Status()
	assertNoErr(t, err)

	srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
	srs2PeerStatus = clientStatus.Peer[srs2.Self.PublicKey]

	assertNotNil(t, srs1PeerStatus.PrimaryRoutes)
	assert.Nil(t, srs2PeerStatus.PrimaryRoutes)

	if srs1PeerStatus.PrimaryRoutes != nil {
		assert.Contains(
			t,
			srs1PeerStatus.PrimaryRoutes.AsSlice(),
			netip.MustParsePrefix(expectedRoutes[string(srs1.Self.ID)]),
		)
	}
}

func TestEnableDisableAutoApprovedRoute(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	expectedRoutes := "172.0.0.0/24"

	user := "enable-disable-routing"

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErrf(t, "failed to create scenario: %s", err)
	defer scenario.Shutdown()

	spec := map[string]int{
		user: 1,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{tsic.WithTags([]string{"tag:approve"})}, hsic.WithTestName("clienableroute"), hsic.WithACLPolicy(
		&policy.ACLPolicy{
			ACLs: []policy.ACL{
				{
					Action:       "accept",
					Sources:      []string{"*"},
					Destinations: []string{"*:*"},
				},
			},
			TagOwners: map[string][]string{
				"tag:approve": {user},
			},
			AutoApprovers: policy.AutoApprovers{
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
	assertNoErrf(t, "failed to advertise route: %s", err)

	time.Sleep(10 * time.Second)

	var routes []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&routes,
	)
	assertNoErr(t, err)
	assert.Len(t, routes, 1)

	// All routes should be auto approved and enabled
	assert.Equal(t, true, routes[0].GetAdvertised())
	assert.Equal(t, true, routes[0].GetEnabled())
	assert.Equal(t, true, routes[0].GetIsPrimary())

	// Stop advertising route
	command = []string{
		"tailscale",
		"set",
		"--advertise-routes=",
	}
	_, _, err = subRouter1.Execute(command)
	assertNoErrf(t, "failed to remove advertised route: %s", err)

	time.Sleep(10 * time.Second)

	var notAdvertisedRoutes []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&notAdvertisedRoutes,
	)
	assertNoErr(t, err)
	assert.Len(t, notAdvertisedRoutes, 1)

	// Route is no longer advertised
	assert.Equal(t, false, notAdvertisedRoutes[0].GetAdvertised())
	assert.Equal(t, false, notAdvertisedRoutes[0].GetEnabled())
	assert.Equal(t, true, notAdvertisedRoutes[0].GetIsPrimary())

	// Advertise route again
	command = []string{
		"tailscale",
		"set",
		"--advertise-routes=" + expectedRoutes,
	}
	_, _, err = subRouter1.Execute(command)
	assertNoErrf(t, "failed to advertise route: %s", err)

	time.Sleep(10 * time.Second)

	var reAdvertisedRoutes []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&reAdvertisedRoutes,
	)
	assertNoErr(t, err)
	assert.Len(t, reAdvertisedRoutes, 1)

	// All routes should be auto approved and enabled
	assert.Equal(t, true, reAdvertisedRoutes[0].GetAdvertised())
	assert.Equal(t, true, reAdvertisedRoutes[0].GetEnabled())
	assert.Equal(t, true, reAdvertisedRoutes[0].GetIsPrimary())
}

// TestSubnetRouteACL verifies that Subnet routes are distributed
// as expected when ACLs are activated.
// It implements the issue from
// https://github.com/juanfont/headscale/issues/1604
func TestSubnetRouteACL(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	user := "subnet-route-acl"

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErrf(t, "failed to create scenario: %s", err)
	defer scenario.Shutdown()

	spec := map[string]int{
		user: 2,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clienableroute"), hsic.WithACLPolicy(
		&policy.ACLPolicy{
			Groups: policy.Groups{
				"group:admins": {user},
			},
			ACLs: []policy.ACL{
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

	// advertise HA route on node 1 and 2
	// ID 1 will be primary
	// ID 2 will be secondary
	for _, client := range allClients {
		status, err := client.Status()
		assertNoErr(t, err)

		if route, ok := expectedRoutes[string(status.Self.ID)]; ok {
			command := []string{
				"tailscale",
				"set",
				"--advertise-routes=" + route,
			}
			_, _, err = client.Execute(command)
			assertNoErrf(t, "failed to advertise route: %s", err)
		}
	}

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	var routes []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&routes,
	)

	assertNoErr(t, err)
	assert.Len(t, routes, 1)

	for _, route := range routes {
		assert.Equal(t, true, route.GetAdvertised())
		assert.Equal(t, false, route.GetEnabled())
		assert.Equal(t, false, route.GetIsPrimary())
	}

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

	// Enable all routes
	for _, route := range routes {
		_, err = headscale.Execute(
			[]string{
				"headscale",
				"routes",
				"enable",
				"--route",
				strconv.Itoa(int(route.GetId())),
			})
		assertNoErr(t, err)
	}

	time.Sleep(5 * time.Second)

	var enablingRoutes []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&enablingRoutes,
	)
	assertNoErr(t, err)
	assert.Len(t, enablingRoutes, 1)

	// Node 1 has active route
	assert.Equal(t, true, enablingRoutes[0].GetAdvertised())
	assert.Equal(t, true, enablingRoutes[0].GetEnabled())
	assert.Equal(t, true, enablingRoutes[0].GetIsPrimary())

	// Verify that the client has routes from the primary machine
	srs1, _ := subRouter1.Status()

	clientStatus, err := client.Status()
	assertNoErr(t, err)

	srs1PeerStatus := clientStatus.Peer[srs1.Self.PublicKey]

	assertNotNil(t, srs1PeerStatus.PrimaryRoutes)

	t.Logf("subnet1 has following routes: %v", srs1PeerStatus.PrimaryRoutes.AsSlice())
	assert.Len(t, srs1PeerStatus.PrimaryRoutes.AsSlice(), 1)
	assert.Contains(
		t,
		srs1PeerStatus.PrimaryRoutes.AsSlice(),
		netip.MustParsePrefix(expectedRoutes[string(srs1.Self.ID)]),
	)

	clientNm, err := client.Netmap()
	assertNoErr(t, err)

	wantClientFilter := []filter.Match{
		{
			IPProto: []ipproto.Proto{
				ipproto.TCP, ipproto.UDP, ipproto.ICMPv4, ipproto.ICMPv6,
			},
			Srcs: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("100.64.0.2/32"),
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
				netip.MustParsePrefix("fd7a:115c:a1e0::2/128"),
			},
			Dsts: []filter.NetPortRange{
				{
					Net:   netip.MustParsePrefix("100.64.0.2/32"),
					Ports: filter.PortRange{0, 0xffff},
				},
				{
					Net:   netip.MustParsePrefix("fd7a:115c:a1e0::2/128"),
					Ports: filter.PortRange{0, 0xffff},
				},
			},
			Caps: []filter.CapMatch{},
		},
	}

	if diff := cmp.Diff(wantClientFilter, clientNm.PacketFilter, util.PrefixComparer); diff != "" {
		t.Errorf("Client (%s) filter, unexpected result (-want +got):\n%s", client.Hostname(), diff)
	}

	subnetNm, err := subRouter1.Netmap()
	assertNoErr(t, err)

	wantSubnetFilter := []filter.Match{
		{
			IPProto: []ipproto.Proto{
				ipproto.TCP, ipproto.UDP, ipproto.ICMPv4, ipproto.ICMPv6,
			},
			Srcs: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("100.64.0.2/32"),
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
				netip.MustParsePrefix("fd7a:115c:a1e0::2/128"),
			},
			Dsts: []filter.NetPortRange{
				{
					Net:   netip.MustParsePrefix("100.64.0.1/32"),
					Ports: filter.PortRange{0, 0xffff},
				},
				{
					Net:   netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
					Ports: filter.PortRange{0, 0xffff},
				},
			},
			Caps: []filter.CapMatch{},
		},
		{
			IPProto: []ipproto.Proto{
				ipproto.TCP, ipproto.UDP, ipproto.ICMPv4, ipproto.ICMPv6,
			},
			Srcs: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("100.64.0.2/32"),
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
				netip.MustParsePrefix("fd7a:115c:a1e0::2/128"),
			},
			Dsts: []filter.NetPortRange{
				{
					Net:   netip.MustParsePrefix("10.33.0.0/16"),
					Ports: filter.PortRange{0, 0xffff},
				},
			},
			Caps: []filter.CapMatch{},
		},
	}

	if diff := cmp.Diff(wantSubnetFilter, subnetNm.PacketFilter, util.PrefixComparer); diff != "" {
		t.Errorf("Subnet (%s) filter, unexpected result (-want +got):\n%s", subRouter1.Hostname(), diff)
	}
}
