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
			require.NoError(t, err)
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
			requireNoErrHeadscaleEnv(t, err)

			allClients, err := scenario.ListTailscaleClients()
			requireNoErrListClients(t, err)

			allIps, err := scenario.ListTailscaleClientsIPs()
			requireNoErrListClientIPs(t, err)

			err = scenario.WaitForTailscaleSync()
			requireNoErrSync(t, err)

			headscale, err := scenario.Headscale()
			requireNoErrGetHeadscale(t, err)

			expectedNodes := collectExpectedNodeIDs(t, allClients)
			requireAllClientsOnline(t, headscale, expectedNodes, true, "all clients should be connected", 120*time.Second)

			// Validate that all nodes have NetInfo and DERP servers before logout
			requireAllClientsNetInfoAndDERP(t, headscale, expectedNodes, "all clients should have NetInfo and DERP before logout", 3*time.Minute)

			// assertClientsState(t, allClients)

			clientIPs := make(map[TailscaleClient][]netip.Addr)
			for _, client := range allClients {
				ips, err := client.IPs()
				if err != nil {
					t.Fatalf("failed to get IPs for client %s: %s", client.Hostname(), err)
				}
				clientIPs[client] = ips
			}

			var listNodes []*v1.Node
			var nodeCountBeforeLogout int
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				var err error
				listNodes, err = headscale.ListNodes()
				assert.NoError(c, err)
				assert.Len(c, listNodes, len(allClients))

				for _, node := range listNodes {
					assertLastSeenSetWithCollect(c, node)
				}
			}, 10*time.Second, 200*time.Millisecond, "Waiting for expected node list before logout")

			nodeCountBeforeLogout = len(listNodes)
			t.Logf("node count before logout: %d", nodeCountBeforeLogout)

			for _, client := range allClients {
				err := client.Logout()
				if err != nil {
					t.Fatalf("failed to logout client %s: %s", client.Hostname(), err)
				}
			}

			err = scenario.WaitForTailscaleLogout()
			requireNoErrLogout(t, err)

			// After taking down all nodes, verify all systems show nodes offline
			requireAllClientsOnline(t, headscale, expectedNodes, false, "all nodes should have logged out", 120*time.Second)

			t.Logf("all clients logged out")

			t.Logf("Validating node persistence after logout at %s", time.Now().Format(TimestampFormat))
			assert.EventuallyWithT(t, func(ct *assert.CollectT) {
				var err error
				listNodes, err = headscale.ListNodes()
				assert.NoError(ct, err, "Failed to list nodes after logout")
				assert.Len(ct, listNodes, nodeCountBeforeLogout, "Node count should match before logout count - expected %d nodes, got %d", nodeCountBeforeLogout, len(listNodes))
			}, 30*time.Second, 2*time.Second, "validating node persistence after logout (nodes should remain in database)")

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
			require.NoError(t, err)

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

			t.Logf("Validating node persistence after relogin at %s", time.Now().Format(TimestampFormat))
			assert.EventuallyWithT(t, func(ct *assert.CollectT) {
				var err error
				listNodes, err = headscale.ListNodes()
				assert.NoError(ct, err, "Failed to list nodes after relogin")
				assert.Len(ct, listNodes, nodeCountBeforeLogout, "Node count should remain unchanged after relogin - expected %d nodes, got %d", nodeCountBeforeLogout, len(listNodes))
			}, 60*time.Second, 2*time.Second, "validating node count stability after same-user auth key relogin")

			for _, node := range listNodes {
				assertLastSeenSet(t, node)
			}

			requireAllClientsOnline(t, headscale, expectedNodes, true, "all clients should be connected to batcher", 120*time.Second)

			// Wait for Tailscale sync before validating NetInfo to ensure proper state propagation
			err = scenario.WaitForTailscaleSync()
			requireNoErrSync(t, err)

			// Validate that all nodes have NetInfo and DERP servers after reconnection
			requireAllClientsNetInfoAndDERP(t, headscale, expectedNodes, "all clients should have NetInfo and DERP after reconnection", 3*time.Minute)

			err = scenario.WaitForTailscaleSync()
			requireNoErrSync(t, err)

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

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				var err error
				listNodes, err = headscale.ListNodes()
				assert.NoError(c, err)
				assert.Len(c, listNodes, nodeCountBeforeLogout)

				for _, node := range listNodes {
					assertLastSeenSetWithCollect(c, node)
				}
			}, 10*time.Second, 200*time.Millisecond, "Waiting for node list after relogin")
		})
	}
}

// This test will first log in two sets of nodes to two sets of users, then
// it will log out all nodes and log them in as user1 using a pre-auth key.
// This should create new nodes for user1 while preserving the original nodes for user2.
// Pre-auth key re-authentication with a different user creates new nodes, not transfers.
func TestAuthKeyLogoutAndReloginNewUser(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: len(MustTestVersions),
		Users:        []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{},
		hsic.WithTestName("keyrelognewuser"),
		hsic.WithTLS(),
		hsic.WithDERPAsIP(),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	// assertClientsState(t, allClients)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	// Collect expected node IDs for validation
	expectedNodes := collectExpectedNodeIDs(t, allClients)

	// Validate initial connection state
	requireAllClientsOnline(t, headscale, expectedNodes, true, "all clients should be connected after initial login", 120*time.Second)
	requireAllClientsNetInfoAndDERP(t, headscale, expectedNodes, "all clients should have NetInfo and DERP after initial login", 3*time.Minute)

	var listNodes []*v1.Node
	var nodeCountBeforeLogout int
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var err error
		listNodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, listNodes, len(allClients))
	}, 10*time.Second, 200*time.Millisecond, "Waiting for expected node list before logout")

	nodeCountBeforeLogout = len(listNodes)
	t.Logf("node count before logout: %d", nodeCountBeforeLogout)

	for _, client := range allClients {
		err := client.Logout()
		if err != nil {
			t.Fatalf("failed to logout client %s: %s", client.Hostname(), err)
		}
	}

	err = scenario.WaitForTailscaleLogout()
	requireNoErrLogout(t, err)

	// Validate that all nodes are offline after logout
	requireAllClientsOnline(t, headscale, expectedNodes, false, "all nodes should be offline after logout", 120*time.Second)

	t.Logf("all clients logged out")

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

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
	t.Logf("Validating user1 node count after relogin at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		user1Nodes, err = headscale.ListNodes("user1")
		assert.NoError(ct, err, "Failed to list nodes for user1 after relogin")
		assert.Len(ct, user1Nodes, len(allClients), "User1 should have all %d clients after relogin, got %d nodes", len(allClients), len(user1Nodes))
	}, 60*time.Second, 2*time.Second, "validating user1 has all client nodes after auth key relogin")

	// Collect expected node IDs for user1 after relogin
	expectedUser1Nodes := make([]types.NodeID, 0, len(user1Nodes))
	for _, node := range user1Nodes {
		expectedUser1Nodes = append(expectedUser1Nodes, types.NodeID(node.GetId()))
	}

	// Validate connection state after relogin as user1
	requireAllClientsOnline(t, headscale, expectedUser1Nodes, true, "all user1 nodes should be connected after relogin", 120*time.Second)
	requireAllClientsNetInfoAndDERP(t, headscale, expectedUser1Nodes, "all user1 nodes should have NetInfo and DERP after relogin", 3*time.Minute)

	// Validate that user2 still has their original nodes after user1's re-authentication
	// When nodes re-authenticate with a different user's pre-auth key, NEW nodes are created
	// for the new user. The original nodes remain with the original user.
	var user2Nodes []*v1.Node
	t.Logf("Validating user2 node persistence after user1 relogin at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		user2Nodes, err = headscale.ListNodes("user2")
		assert.NoError(ct, err, "Failed to list nodes for user2 after user1 relogin")
		assert.Len(ct, user2Nodes, len(allClients)/2, "User2 should still have %d clients after user1 relogin, got %d nodes", len(allClients)/2, len(user2Nodes))
	}, 30*time.Second, 2*time.Second, "validating user2 nodes persist after user1 relogin (should not be affected)")

	t.Logf("Validating client login states after user switch at %s", time.Now().Format(TimestampFormat))
	for _, client := range allClients {
		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			status, err := client.Status()
			assert.NoError(ct, err, "Failed to get status for client %s", client.Hostname())
			assert.Equal(ct, "user1@test.no", status.User[status.Self.UserID].LoginName, "Client %s should be logged in as user1 after user switch, got %s", client.Hostname(), status.User[status.Self.UserID].LoginName)
		}, 30*time.Second, 2*time.Second, fmt.Sprintf("validating %s is logged in as user1 after auth key user switch", client.Hostname()))
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
			require.NoError(t, err)
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
			requireNoErrHeadscaleEnv(t, err)

			allClients, err := scenario.ListTailscaleClients()
			requireNoErrListClients(t, err)

			err = scenario.WaitForTailscaleSync()
			requireNoErrSync(t, err)

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
			requireNoErrGetHeadscale(t, err)

			// Collect expected node IDs for validation
			expectedNodes := collectExpectedNodeIDs(t, allClients)

			// Validate initial connection state
			requireAllClientsOnline(t, headscale, expectedNodes, true, "all clients should be connected after initial login", 120*time.Second)
			requireAllClientsNetInfoAndDERP(t, headscale, expectedNodes, "all clients should have NetInfo and DERP after initial login", 3*time.Minute)

			var listNodes []*v1.Node
			var nodeCountBeforeLogout int
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				var err error
				listNodes, err = headscale.ListNodes()
				assert.NoError(c, err)
				assert.Len(c, listNodes, len(allClients))
			}, 10*time.Second, 200*time.Millisecond, "Waiting for expected node list before logout")

			nodeCountBeforeLogout = len(listNodes)
			t.Logf("node count before logout: %d", nodeCountBeforeLogout)

			for _, client := range allClients {
				err := client.Logout()
				if err != nil {
					t.Fatalf("failed to logout client %s: %s", client.Hostname(), err)
				}
			}

			err = scenario.WaitForTailscaleLogout()
			requireNoErrLogout(t, err)

			// Validate that all nodes are offline after logout
			requireAllClientsOnline(t, headscale, expectedNodes, false, "all nodes should be offline after logout", 120*time.Second)

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
			require.NoError(t, err)

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
				require.NoError(t, err)
				require.NoError(t, err)

				err = scenario.RunTailscaleUp(userName, headscale.GetEndpoint(), key.GetKey())
				assert.ErrorContains(t, err, "authkey expired")
			}
		})
	}
}

// TestAuthKeyDeleteKey tests Issue #2830: node with deleted auth key should still reconnect.
// Scenario from user report: "create node, delete the auth key, restart to validate it can connect"
// Steps:
// 1. Create node with auth key
// 2. DELETE the auth key from database (completely remove it)
// 3. Restart node - should successfully reconnect using MachineKey identity
func TestAuthKeyDeleteKey(t *testing.T) {
	IntegrationSkip(t)

	// Create scenario with NO nodes - we'll create the node manually so we can capture the auth key
	scenario, err := NewScenario(ScenarioSpec{
		NodesPerUser: 0, // No nodes created automatically
		Users:        []string{"user1"},
	})
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("delkey"), hsic.WithTLS(), hsic.WithDERPAsIP())
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	// Get the user
	userMap, err := headscale.MapUsers()
	require.NoError(t, err)
	userID := userMap["user1"].GetId()

	// Create a pre-auth key - we keep the full key string before it gets redacted
	authKey, err := scenario.CreatePreAuthKey(userID, false, false)
	require.NoError(t, err)
	authKeyString := authKey.GetKey()
	authKeyID := authKey.GetId()
	t.Logf("Created pre-auth key ID %d: %s", authKeyID, authKeyString)

	// Create a tailscale client and log it in with the auth key
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
	)
	require.NoError(t, err)

	err = client.Login(headscale.GetEndpoint(), authKeyString)
	require.NoError(t, err)

	// Wait for the node to be registered
	var user1Nodes []*v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var err error
		user1Nodes, err = headscale.ListNodes("user1")
		assert.NoError(c, err)
		assert.Len(c, user1Nodes, 1)
	}, 30*time.Second, 500*time.Millisecond, "waiting for node to be registered")

	nodeID := user1Nodes[0].GetId()
	nodeName := user1Nodes[0].GetName()
	t.Logf("Node %d (%s) created successfully with auth_key_id=%d", nodeID, nodeName, authKeyID)

	// Verify node is online
	requireAllClientsOnline(t, headscale, []types.NodeID{types.NodeID(nodeID)}, true, "node should be online initially", 120*time.Second)

	// Verify the node has the auth key ID set
	nodeAuthKeyBefore, err := headscale.Execute([]string{
		"sqlite3", "/tmp/integration_test_db.sqlite3",
		fmt.Sprintf("SELECT auth_key_id FROM nodes WHERE id = %d;", nodeID),
	})
	require.NoError(t, err)
	t.Logf("Node auth_key_id before delete: %s", nodeAuthKeyBefore)

	// DELETE the pre-auth key from the database
	// This simulates the scenario where an admin deletes the auth key record
	t.Logf("Deleting pre-auth key ID %d from database", authKeyID)

	// First, clear the foreign key reference from the node
	_, err = headscale.Execute([]string{
		"sqlite3", "/tmp/integration_test_db.sqlite3",
		fmt.Sprintf("UPDATE nodes SET auth_key_id = NULL WHERE id = %d;", nodeID),
	})
	require.NoError(t, err)

	// Then delete the pre-auth key itself
	_, err = headscale.Execute([]string{
		"sqlite3", "/tmp/integration_test_db.sqlite3",
		fmt.Sprintf("DELETE FROM pre_auth_keys WHERE id = %d;", authKeyID),
	})
	require.NoError(t, err)
	t.Logf("Deleted auth key from database")

	// Verify the node no longer has an auth key reference
	nodeAuthKeyAfter, err := headscale.Execute([]string{
		"sqlite3", "/tmp/integration_test_db.sqlite3",
		fmt.Sprintf("SELECT auth_key_id FROM nodes WHERE id = %d;", nodeID),
	})
	require.NoError(t, err)
	t.Logf("Node auth_key_id after delete: '%s' (should be empty)", nodeAuthKeyAfter)

	// Verify pre-auth key is gone
	keyCount, err := headscale.Execute([]string{
		"sqlite3", "/tmp/integration_test_db.sqlite3",
		fmt.Sprintf("SELECT COUNT(*) FROM pre_auth_keys WHERE id = %d;", authKeyID),
	})
	require.NoError(t, err)
	require.Equal(t, "0\n", keyCount, "Pre-auth key should be deleted")

	// Simulate node restart (down + up)
	t.Logf("Restarting node after deleting its auth key")
	err = client.Down()
	require.NoError(t, err)

	time.Sleep(3 * time.Second)

	err = client.Up()
	require.NoError(t, err)

	// Verify node comes back online
	// This will FAIL without the fix because auth key validation will reject deleted key
	// With the fix, MachineKey identity allows reconnection even with deleted key
	requireAllClientsOnline(t, headscale, []types.NodeID{types.NodeID(nodeID)}, true, "node should reconnect after restart despite deleted key", 120*time.Second)

	t.Logf("✓ Node successfully reconnected after its auth key was deleted")
}
