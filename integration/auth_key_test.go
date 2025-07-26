package integration

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthKeyLogoutAndReloginSameUser tests the scenario where a set of nodes
// are logged out and then logged back in as the same user. This test ensures
// that the nodes can successfully re-authenticate and that their IP addresses
// remain the same after re-login.
//
// The test sets up a scenario with two users, each with a set of nodes. It
// then logs out all nodes, and then logs them back in using a new pre-
// authenticated key for the same user. The test verifies that the node count
// remains the same and that the nodes can still ping each other after re-
// login.
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

			opts := []hsic.Option{hsic.WithTestName("pingallbyip")}
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

			t.Logf("all clients logged out")

			assert.EventuallyWithT(t, func(ct *assert.CollectT) {
				var err error
				listNodes, err = headscale.ListNodes()
				assert.NoError(ct, err)
				assert.Equal(ct, nodeCountBeforeLogout, len(listNodes), "Node count should match before logout count")
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
				assert.Equal(ct, nodeCountBeforeLogout, len(listNodes), "Node count should match after HTTPS reconnection")
			}, 30*time.Second, 2*time.Second)

			for _, node := range listNodes {
				assertLastSeenSet(t, node)
			}

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
			require.Equal(t, nodeCountBeforeLogout, len(listNodes))
			for _, node := range listNodes {
				assertLastSeenSet(t, node)
			}
		})
	}
}

func assertLastSeenSet(t *testing.T, node *v1.Node) {
	assert.NotNil(t, node)
	assert.NotNil(t, node.GetLastSeen())
}

// TestAuthKeyLogoutAndReloginNewUser tests the scenario where a set of nodes
// are logged out from one user and then logged back in as a different user.
// This test ensures that the nodes are correctly associated with the new user
// and that the old user's nodes are no longer connected.
//
// The test sets up a scenario with two users, each with a set of nodes. It
// then logs out all nodes and logs them all back in as user1. The test
// verifies that all nodes are now associated with user1, and that user2 has
// no connected nodes.
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

// TestAuthKeyLogoutAndReloginSameUserExpiredKey tests that a node cannot log
// back in with an expired pre-authenticated key.
//
// The test sets up a scenario with two users and their nodes. It then logs
// out all nodes, creates a new pre-authenticated key for each user, and then
// expires the key. The test then attempts to log the nodes back in with the
// expired key and verifies that the authentication fails with the expected
// error message.
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

			opts := []hsic.Option{hsic.WithTestName("pingallbyip")}
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
						key.Key,
					})
				assertNoErr(t, err)

				err = scenario.RunTailscaleUp(userName, headscale.GetEndpoint(), key.GetKey())
				assert.ErrorContains(t, err, "authkey expired")
			}
		})
	}
}
