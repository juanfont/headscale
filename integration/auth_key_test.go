package integration

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthKeyLogoutAndReloginSameUser(t *testing.T) {
	IntegrationSkip(t)

	for _, https := range []bool{true, false} {
		t.Run(fmt.Sprintf("with-https-%t", https), func(t *testing.T) {
			spec := ScenarioSpec{
				NodesPerUser: len(MustTestVersions),
				Users:        []string{"user1", "user2"},
			}

			scenario, err := NewScenario(spec)
			assertNoErr(t, err)
			defer scenario.ShutdownAssertNoPanics(t)

			opts := []hsic.Option{
				hsic.WithTestName("pingallbyip"),
				hsic.WithEmbeddedDERPServerOnly(),
				hsic.WithDERPAsIP(),
			}
			if https {
				opts = append(opts, []hsic.Option{
					hsic.WithTLS(),
				}...)
			}

			err = scenario.CreateHeadscaleEnv([]tsic.Option{}, opts...)
			assertNoErrHeadscaleEnv(t, err)

			allClients, err := scenario.ListTailscaleClients()
			assertNoErrListClients(t, err)

			allIps, err := scenario.ListTailscaleClientsIPs()
			assertNoErrListClientIPs(t, err)

			err = scenario.WaitForTailscaleSync()
			assertNoErrSync(t, err)

			headscale, err := scenario.Headscale()
			assertNoErrGetHeadscale(t, err)

			expectedNodes := make([]types.NodeID, 0, len(allClients))
			for _, client := range allClients {
				status := client.MustStatus()
				nodeID, err := strconv.ParseUint(string(status.Self.ID), 10, 64)
				assertNoErr(t, err)
				expectedNodes = append(expectedNodes, types.NodeID(nodeID))
			}
			requireAllClientsOnline(t, headscale, expectedNodes, true, "all clients should be connected", 30*time.Second)

			// Validate that all nodes have NetInfo and DERP servers before logout
			requireAllClientsNetInfoAndDERP(t, headscale, expectedNodes, "all clients should have NetInfo and DERP before logout", 1*time.Minute)

			// assertClientsState(t, allClients)

			clientIPs := make(map[TailscaleClient][]netip.Addr)
			for _, client := range allClients {
				ips, err := client.IPs()
				if err != nil {
					t.Fatalf("failed to get IPs for client %s: %s", client.Hostname(), err)
				}
				clientIPs[client] = ips
			}

			listNodes, err := headscale.ListNodes()
			assert.Len(t, allClients, len(listNodes))
			nodeCountBeforeLogout := len(listNodes)
			t.Logf("node count before logout: %d", nodeCountBeforeLogout)

			for _, node := range listNodes {
				assertLastSeenSet(t, node)
			}

			for _, client := range allClients {
				err := client.Logout()
				if err != nil {
					t.Fatalf("failed to logout client %s: %s", client.Hostname(), err)
				}
			}

			err = scenario.WaitForTailscaleLogout()
			assertNoErrLogout(t, err)

			// After taking down all nodes, verify all systems show nodes offline
			requireAllClientsOnline(t, headscale, expectedNodes, false, "all nodes should have logged out", 120*time.Second)

			t.Logf("all clients logged out")

			assert.EventuallyWithT(t, func(ct *assert.CollectT) {
				var err error
				listNodes, err = headscale.ListNodes()
				assert.NoError(ct, err)
				assert.Len(ct, listNodes, nodeCountBeforeLogout, "Node count should match before logout count")
			}, 20*time.Second, 1*time.Second)

			for _, node := range listNodes {
				assertLastSeenSet(t, node)
			}

			// if the server is not running with HTTPS, we have to wait a bit before
			// reconnection as the newest Tailscale client has a measure that will only
			// reconnect over HTTPS if they saw a noise connection previously.
			// https://github.com/tailscale/tailscale/commit/1eaad7d3deb0815e8932e913ca1a862afa34db38
			// https://github.com/juanfont/headscale/issues/2164
			if !https {
				time.Sleep(5 * time.Minute)
			}

			userMap, err := headscale.MapUsers()
			assertNoErr(t, err)

			for _, userName := range spec.Users {
				key, err := scenario.CreatePreAuthKey(userMap[userName].GetId(), true, false)
				if err != nil {
					t.Fatalf("failed to create pre-auth key for user %s: %s", userName, err)
				}

				err = scenario.RunTailscaleUp(userName, headscale.GetEndpoint(), key.GetKey())
				if err != nil {
					t.Fatalf("failed to run tailscale up for user %s: %s", userName, err)
				}
			}

			assert.EventuallyWithT(t, func(ct *assert.CollectT) {
				var err error
				listNodes, err = headscale.ListNodes()
				assert.NoError(ct, err)
				assert.Len(ct, listNodes, nodeCountBeforeLogout, "Node count should match after HTTPS reconnection")
			}, 30*time.Second, 2*time.Second)

			for _, node := range listNodes {
				assertLastSeenSet(t, node)
			}

			requireAllClientsOnline(t, headscale, expectedNodes, true, "all clients should be connected to batcher", 120*time.Second)

			// Validate that all nodes have NetInfo and DERP servers after reconnection
			requireAllClientsNetInfoAndDERP(t, headscale, expectedNodes, "all clients should have NetInfo and DERP after reconnection", 1*time.Minute)

			err = scenario.WaitForTailscaleSync()
			assertNoErrSync(t, err)

			allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
				return x.String()
			})

			success := pingAllHelper(t, allClients, allAddrs)
			t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

			for _, client := range allClients {
				ips, err := client.IPs()
				if err != nil {
					t.Fatalf("failed to get IPs for client %s: %s", client.Hostname(), err)
				}

				// lets check if the IPs are the same
				if len(ips) != len(clientIPs[client]) {
					t.Fatalf("IPs changed for client %s", client.Hostname())
				}

				for _, ip := range ips {
					if !slices.Contains(clientIPs[client], ip) {
						t.Fatalf(
							"IPs changed for client %s. Used to be %v now %v",
							client.Hostname(),
							clientIPs[client],
							ips,
						)
					}
				}
			}

			listNodes, err = headscale.ListNodes()
			require.Len(t, listNodes, nodeCountBeforeLogout)
			for _, node := range listNodes {
				assertLastSeenSet(t, node)
			}
		})
	}
}

// requireAllClientsNetInfoAndDERP validates that all nodes have NetInfo in the database
// and a valid DERP server based on the NetInfo. This function follows the pattern of
// requireAllClientsOnline by using hsic.DebugNodeStore to get the database state.
func requireAllClientsNetInfoAndDERP(t *testing.T, headscale ControlServer, expectedNodes []types.NodeID, message string, timeout time.Duration) {
	t.Helper()

	startTime := time.Now()
	t.Logf("requireAllClientsNetInfoAndDERP: Starting validation at %s - %s", startTime.Format(TimestampFormat), message)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		// Get nodestore state
		nodeStore, err := headscale.DebugNodeStore()
		assert.NoError(c, err, "Failed to get nodestore debug info")
		if err != nil {
			return
		}

		// Validate node counts first
		expectedCount := len(expectedNodes)
		assert.Equal(c, expectedCount, len(nodeStore), "NodeStore total nodes mismatch")

		// Check each expected node
		for _, nodeID := range expectedNodes {
			node, exists := nodeStore[nodeID]
			assert.True(c, exists, "Node %d not found in nodestore", nodeID)
			if !exists {
				continue
			}

			// Validate that the node has Hostinfo
			assert.NotNil(c, node.Hostinfo, "Node %d (%s) should have Hostinfo", nodeID, node.Hostname)
			if node.Hostinfo == nil {
				continue
			}

			// Validate that the node has NetInfo
			assert.NotNil(c, node.Hostinfo.NetInfo, "Node %d (%s) should have NetInfo in Hostinfo", nodeID, node.Hostname)
			if node.Hostinfo.NetInfo == nil {
				continue
			}

			// Validate that the node has a valid DERP server (PreferredDERP should be > 0)
			preferredDERP := node.Hostinfo.NetInfo.PreferredDERP
			assert.Greater(c, preferredDERP, 0, "Node %d (%s) should have a valid DERP server (PreferredDERP > 0), got %d", nodeID, node.Hostname, preferredDERP)

			t.Logf("Node %d (%s) has valid NetInfo with DERP server %d", nodeID, node.Hostname, preferredDERP)
		}
	}, timeout, 2*time.Second, message)

	endTime := time.Now()
	duration := endTime.Sub(startTime)
	t.Logf("requireAllClientsNetInfoAndDERP: Completed validation at %s - Duration: %v - %s", endTime.Format(TimestampFormat), duration, message)
}

func assertLastSeenSet(t *testing.T, node *v1.Node) {
	assert.NotNil(t, node)
	assert.NotNil(t, node.GetLastSeen())
}

// This test will first log in two sets of nodes to two sets of users, then
// it will log out all users from user2 and log them in as user1.
// This should leave us with all nodes connected to user1, while user2
// still has nodes, but they are not connected.
func TestAuthKeyLogoutAndReloginNewUser(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: len(MustTestVersions),
		Users:        []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{},
		hsic.WithTestName("keyrelognewuser"),
		hsic.WithTLS(),
		hsic.WithDERPAsIP(),
	)
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// assertClientsState(t, allClients)

	headscale, err := scenario.Headscale()
	assertNoErrGetHeadscale(t, err)

	listNodes, err := headscale.ListNodes()
	assert.Len(t, allClients, len(listNodes))
	nodeCountBeforeLogout := len(listNodes)
	t.Logf("node count before logout: %d", nodeCountBeforeLogout)

	for _, client := range allClients {
		err := client.Logout()
		if err != nil {
			t.Fatalf("failed to logout client %s: %s", client.Hostname(), err)
		}
	}

	err = scenario.WaitForTailscaleLogout()
	assertNoErrLogout(t, err)

	t.Logf("all clients logged out")

	userMap, err := headscale.MapUsers()
	assertNoErr(t, err)

	// Create a new authkey for user1, to be used for all clients
	key, err := scenario.CreatePreAuthKey(userMap["user1"].GetId(), true, false)
	if err != nil {
		t.Fatalf("failed to create pre-auth key for user1: %s", err)
	}

	// Log in all clients as user1, iterating over the spec only returns the
	// clients, not the usernames.
	for _, userName := range spec.Users {
		err = scenario.RunTailscaleUp(userName, headscale.GetEndpoint(), key.GetKey())
		if err != nil {
			t.Fatalf("failed to run tailscale up for user %s: %s", userName, err)
		}
	}

	var user1Nodes []*v1.Node
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		user1Nodes, err = headscale.ListNodes("user1")
		assert.NoError(ct, err)
		assert.Len(ct, user1Nodes, len(allClients), "User1 should have all clients after re-login")
	}, 20*time.Second, 1*time.Second)

	// Validate that all the old nodes are still present with user2
	var user2Nodes []*v1.Node
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		user2Nodes, err = headscale.ListNodes("user2")
		assert.NoError(ct, err)
		assert.Len(ct, user2Nodes, len(allClients)/2, "User2 should have half the clients")
	}, 20*time.Second, 1*time.Second)

	for _, client := range allClients {
		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			status, err := client.Status()
			assert.NoError(ct, err, "Failed to get status for client %s", client.Hostname())
			assert.Equal(ct, "user1@test.no", status.User[status.Self.UserID].LoginName, "Client %s should be logged in as user1", client.Hostname())
		}, 30*time.Second, 2*time.Second)
	}
}

func TestAuthKeyLogoutAndReloginSameUserExpiredKey(t *testing.T) {
	IntegrationSkip(t)

	for _, https := range []bool{true, false} {
		t.Run(fmt.Sprintf("with-https-%t", https), func(t *testing.T) {
			spec := ScenarioSpec{
				NodesPerUser: len(MustTestVersions),
				Users:        []string{"user1", "user2"},
			}

			scenario, err := NewScenario(spec)
			assertNoErr(t, err)
			defer scenario.ShutdownAssertNoPanics(t)

			opts := []hsic.Option{
				hsic.WithTestName("pingallbyip"),
				hsic.WithDERPAsIP(),
			}
			if https {
				opts = append(opts, []hsic.Option{
					hsic.WithTLS(),
				}...)
			}

			err = scenario.CreateHeadscaleEnv([]tsic.Option{}, opts...)
			assertNoErrHeadscaleEnv(t, err)

			allClients, err := scenario.ListTailscaleClients()
			assertNoErrListClients(t, err)

			err = scenario.WaitForTailscaleSync()
			assertNoErrSync(t, err)

			// assertClientsState(t, allClients)

			clientIPs := make(map[TailscaleClient][]netip.Addr)
			for _, client := range allClients {
				ips, err := client.IPs()
				if err != nil {
					t.Fatalf("failed to get IPs for client %s: %s", client.Hostname(), err)
				}
				clientIPs[client] = ips
			}

			headscale, err := scenario.Headscale()
			assertNoErrGetHeadscale(t, err)

			listNodes, err := headscale.ListNodes()
			assert.Len(t, allClients, len(listNodes))
			nodeCountBeforeLogout := len(listNodes)
			t.Logf("node count before logout: %d", nodeCountBeforeLogout)

			for _, client := range allClients {
				err := client.Logout()
				if err != nil {
					t.Fatalf("failed to logout client %s: %s", client.Hostname(), err)
				}
			}

			err = scenario.WaitForTailscaleLogout()
			assertNoErrLogout(t, err)

			t.Logf("all clients logged out")

			// if the server is not running with HTTPS, we have to wait a bit before
			// reconnection as the newest Tailscale client has a measure that will only
			// reconnect over HTTPS if they saw a noise connection previously.
			// https://github.com/tailscale/tailscale/commit/1eaad7d3deb0815e8932e913ca1a862afa34db38
			// https://github.com/juanfont/headscale/issues/2164
			if !https {
				time.Sleep(5 * time.Minute)
			}

			userMap, err := headscale.MapUsers()
			assertNoErr(t, err)

			for _, userName := range spec.Users {
				key, err := scenario.CreatePreAuthKey(userMap[userName].GetId(), true, false)
				if err != nil {
					t.Fatalf("failed to create pre-auth key for user %s: %s", userName, err)
				}

				// Expire the key so it can't be used
				_, err = headscale.Execute(
					[]string{
						"headscale",
						"preauthkeys",
						"--user",
						strconv.FormatUint(userMap[userName].GetId(), 10),
						"expire",
						key.GetKey(),
					})
				assertNoErr(t, err)

				err = scenario.RunTailscaleUp(userName, headscale.GetEndpoint(), key.GetKey())
				assert.ErrorContains(t, err, "authkey expired")
			}
		})
	}
}
