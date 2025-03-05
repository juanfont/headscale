package integration

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthKeyLogoutAndReloginSameUser(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	for _, https := range []bool{true, false} {
		t.Run(fmt.Sprintf("with-https-%t", https), func(t *testing.T) {
			scenario, err := NewScenario(dockertestMaxWait())
			assertNoErr(t, err)
			defer scenario.ShutdownAssertNoPanics(t)

			spec := ScenarioSpec{
				NodesPerUser: len(MustTestVersions),
				Users:        []string{"user1", "user2"},
			}

			opts := []hsic.Option{hsic.WithTestName("pingallbyip")}
			if https {
				opts = append(opts, []hsic.Option{
					hsic.WithTLS(),
				}...)
			}

			err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, opts...)
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
			assert.Equal(t, len(listNodes), len(allClients))
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

			for _, userName := range spec.Users {
				key, err := scenario.CreatePreAuthKey(userName, true, false)
				if err != nil {
					t.Fatalf("failed to create pre-auth key for user %s: %s", userName, err)
				}

				err = scenario.RunTailscaleUp(userName, headscale.GetEndpoint(), key.GetKey())
				if err != nil {
					t.Fatalf("failed to run tailscale up for user %s: %s", userName, err)
				}
			}

			listNodes, err = headscale.ListNodes()
			require.Equal(t, nodeCountBeforeLogout, len(listNodes))

			allIps, err := scenario.ListTailscaleClientsIPs()
			assertNoErrListClientIPs(t, err)

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
					found := false
					for _, oldIP := range clientIPs[client] {
						if ip == oldIP {
							found = true

							break
						}
					}

					if !found {
						t.Fatalf(
							"IPs changed for client %s. Used to be %v now %v",
							client.Hostname(),
							clientIPs[client],
							ips,
						)
					}
				}
			}
		})
	}
}

// This test will first log in two sets of nodes to two sets of users, then
// it will log out all users from user2 and log them in as user1.
// This should leave us with all nodes connected to user1, while user2
// still has nodes, but they are not connected.
func TestAuthKeyLogoutAndReloginNewUser(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := ScenarioSpec{
		NodesPerUser: len(MustTestVersions),
		Users:        []string{"user1", "user2"},
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{},
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
	assert.Equal(t, len(listNodes), len(allClients))
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

	// Create a new authkey for user1, to be used for all clients
	key, err := scenario.CreatePreAuthKey("user1", true, false)
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

	user1Nodes, err := headscale.ListNodes("user1")
	assertNoErr(t, err)
	assert.Len(t, user1Nodes, len(allClients))

	// Validate that all the old nodes are still present with user2
	user2Nodes, err := headscale.ListNodes("user2")
	assertNoErr(t, err)
	assert.Len(t, user2Nodes, len(allClients)/2)

	for _, client := range allClients {
		status, err := client.Status()
		if err != nil {
			t.Fatalf("failed to get status for client %s: %s", client.Hostname(), err)
		}

		assert.Equal(t, "user1@test.no", status.User[status.Self.UserID].LoginName)
	}
}

func TestAuthKeyLogoutAndReloginSameUserExpiredKey(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	for _, https := range []bool{true, false} {
		t.Run(fmt.Sprintf("with-https-%t", https), func(t *testing.T) {
			scenario, err := NewScenario(dockertestMaxWait())
			assertNoErr(t, err)
			defer scenario.ShutdownAssertNoPanics(t)

			spec := ScenarioSpec{
				NodesPerUser: len(MustTestVersions),
				Users:        []string{"user1", "user2"},
			}

			opts := []hsic.Option{hsic.WithTestName("pingallbyip")}
			if https {
				opts = append(opts, []hsic.Option{
					hsic.WithTLS(),
				}...)
			}

			err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, opts...)
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
			assert.Equal(t, len(listNodes), len(allClients))
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

			for _, userName := range spec.Users {
				key, err := scenario.CreatePreAuthKey(userName, true, false)
				if err != nil {
					t.Fatalf("failed to create pre-auth key for user %s: %s", userName, err)
				}

				// Expire the key so it can't be used
				_, err = headscale.Execute(
					[]string{
						"headscale",
						"preauthkeys",
						"--user",
						userName,
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
