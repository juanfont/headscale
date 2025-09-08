package integration

import (
	"maps"
	"net/netip"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
)

func TestOIDCAuthenticationPingAll(t *testing.T) {
	IntegrationSkip(t)

	// Logins to MockOIDC is served by a queue with a strict order,
	// if we use more than one node per user, the order of the logins
	// will not be deterministic and the test will fail.
	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1", "user2"},
		OIDCUsers: []mockoidc.MockUser{
			oidcMockUser("user1", true),
			oidcMockUser("user2", false),
		},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	oidcMap := map[string]string{
		"HEADSCALE_OIDC_ISSUER":             scenario.mockOIDC.Issuer(),
		"HEADSCALE_OIDC_CLIENT_ID":          scenario.mockOIDC.ClientID(),
		"CREDENTIALS_DIRECTORY_TEST":        "/tmp",
		"HEADSCALE_OIDC_CLIENT_SECRET_PATH": "${CREDENTIALS_DIRECTORY_TEST}/hs_client_oidc_secret",
	}

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		nil,
		hsic.WithTestName("oidcauthping"),
		hsic.WithConfigEnv(oidcMap),
		hsic.WithTLS(),
		hsic.WithFileInContainer("/tmp/hs_client_oidc_secret", []byte(scenario.mockOIDC.ClientSecret())),
	)
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// assertClientsState(t, allClients)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	listUsers, err := headscale.ListUsers()
	assertNoErr(t, err)

	want := []*v1.User{
		{
			Id:    1,
			Name:  "user1",
			Email: "user1@test.no",
		},
		{
			Id:         2,
			Name:       "user1",
			Email:      "user1@headscale.net",
			Provider:   "oidc",
			ProviderId: scenario.mockOIDC.Issuer() + "/user1",
		},
		{
			Id:    3,
			Name:  "user2",
			Email: "user2@test.no",
		},
		{
			Id:         4,
			Name:       "user2",
			Email:      "", // Unverified
			Provider:   "oidc",
			ProviderId: scenario.mockOIDC.Issuer() + "/user2",
		},
	}

	sort.Slice(listUsers, func(i, j int) bool {
		return listUsers[i].GetId() < listUsers[j].GetId()
	})

	if diff := cmp.Diff(want, listUsers, cmpopts.IgnoreUnexported(v1.User{}), cmpopts.IgnoreFields(v1.User{}, "CreatedAt")); diff != "" {
		t.Fatalf("unexpected users: %s", diff)
	}
}

// TestOIDCExpireNodesBasedOnTokenExpiry validates that nodes correctly transition to NeedsLogin
// state when their OIDC tokens expire. This test uses a short token TTL to validate the
// expiration behavior without waiting for production-length timeouts.
//
// The test verifies:
// - Nodes can successfully authenticate via OIDC and establish connectivity
// - When OIDC tokens expire, nodes transition to NeedsLogin state
// - The expiration is based on individual token issue times, not a global timer
//
// Known timing considerations:
// - Nodes may expire at different times due to sequential login processing
// - The test must account for login time spread between first and last node.
func TestOIDCExpireNodesBasedOnTokenExpiry(t *testing.T) {
	IntegrationSkip(t)

	shortAccessTTL := 5 * time.Minute

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1", "user2"},
		OIDCUsers: []mockoidc.MockUser{
			oidcMockUser("user1", true),
			oidcMockUser("user2", false),
		},
		OIDCAccessTTL: shortAccessTTL,
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	oidcMap := map[string]string{
		"HEADSCALE_OIDC_ISSUER":                scenario.mockOIDC.Issuer(),
		"HEADSCALE_OIDC_CLIENT_ID":             scenario.mockOIDC.ClientID(),
		"HEADSCALE_OIDC_CLIENT_SECRET":         scenario.mockOIDC.ClientSecret(),
		"HEADSCALE_OIDC_USE_EXPIRY_FROM_TOKEN": "1",
	}

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		nil,
		hsic.WithTestName("oidcexpirenodes"),
		hsic.WithConfigEnv(oidcMap),
	)
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	// Record when sync completes to better estimate token expiry timing
	syncCompleteTime := time.Now()
	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)
	loginDuration := time.Since(syncCompleteTime)
	t.Logf("Login and sync completed in %v", loginDuration)

	// assertClientsState(t, allClients)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d (before expiry)", success, len(allClients)*len(allIps))

	// Wait for OIDC token expiry and verify all nodes transition to NeedsLogin.
	// We add extra time to account for:
	// - Sequential login processing causing different token issue times
	// - Network and processing delays
	// - Safety margin for test reliability
	loginTimeSpread := 1 * time.Minute // Account for sequential login delays
	safetyBuffer := 30 * time.Second   // Additional safety margin
	totalWaitTime := shortAccessTTL + loginTimeSpread + safetyBuffer

	t.Logf("Waiting %v for OIDC tokens to expire (TTL: %v, spread: %v, buffer: %v)",
		totalWaitTime, shortAccessTTL, loginTimeSpread, safetyBuffer)

	// EventuallyWithT retries the test function until it passes or times out.
	// IMPORTANT: Use 'ct' (CollectT) for all assertions inside the function, not 't'.
	// Using 't' would cause immediate test failure without retries, defeating the purpose
	// of EventuallyWithT which is designed to handle timing-dependent conditions.
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Check each client's status individually to provide better diagnostics
		expiredCount := 0
		for _, client := range allClients {
			status, err := client.Status()
			if assert.NoError(ct, err, "failed to get status for client %s", client.Hostname()) {
				if status.BackendState == "NeedsLogin" {
					expiredCount++
				}
			}
		}

		// Log progress for debugging
		if expiredCount < len(allClients) {
			t.Logf("Token expiry progress: %d/%d clients in NeedsLogin state", expiredCount, len(allClients))
		}

		// All clients must be in NeedsLogin state
		assert.Equal(ct, len(allClients), expiredCount,
			"expected all %d clients to be in NeedsLogin state, but only %d are",
			len(allClients), expiredCount)

		// Only check detailed logout state if all clients are expired
		if expiredCount == len(allClients) {
			assertTailscaleNodesLogout(ct, allClients)
		}
	}, totalWaitTime, 5*time.Second)
}

func TestOIDC024UserCreation(t *testing.T) {
	IntegrationSkip(t)

	tests := []struct {
		name          string
		config        map[string]string
		emailVerified bool
		cliUsers      []string
		oidcUsers     []string
		want          func(iss string) []*v1.User
	}{
		{
			name:          "no-migration-verified-email",
			emailVerified: true,
			cliUsers:      []string{"user1", "user2"},
			oidcUsers:     []string{"user1", "user2"},
			want: func(iss string) []*v1.User {
				return []*v1.User{
					{
						Id:    1,
						Name:  "user1",
						Email: "user1@test.no",
					},
					{
						Id:         2,
						Name:       "user1",
						Email:      "user1@headscale.net",
						Provider:   "oidc",
						ProviderId: iss + "/user1",
					},
					{
						Id:    3,
						Name:  "user2",
						Email: "user2@test.no",
					},
					{
						Id:         4,
						Name:       "user2",
						Email:      "user2@headscale.net",
						Provider:   "oidc",
						ProviderId: iss + "/user2",
					},
				}
			},
		},
		{
			name:          "no-migration-not-verified-email",
			emailVerified: false,
			cliUsers:      []string{"user1", "user2"},
			oidcUsers:     []string{"user1", "user2"},
			want: func(iss string) []*v1.User {
				return []*v1.User{
					{
						Id:    1,
						Name:  "user1",
						Email: "user1@test.no",
					},
					{
						Id:         2,
						Name:       "user1",
						Provider:   "oidc",
						ProviderId: iss + "/user1",
					},
					{
						Id:    3,
						Name:  "user2",
						Email: "user2@test.no",
					},
					{
						Id:         4,
						Name:       "user2",
						Provider:   "oidc",
						ProviderId: iss + "/user2",
					},
				}
			},
		},
		{
			name:          "migration-no-strip-domains-not-verified-email",
			emailVerified: false,
			cliUsers:      []string{"user1.headscale.net", "user2.headscale.net"},
			oidcUsers:     []string{"user1", "user2"},
			want: func(iss string) []*v1.User {
				return []*v1.User{
					{
						Id:    1,
						Name:  "user1.headscale.net",
						Email: "user1.headscale.net@test.no",
					},
					{
						Id:         2,
						Name:       "user1",
						Provider:   "oidc",
						ProviderId: iss + "/user1",
					},
					{
						Id:    3,
						Name:  "user2.headscale.net",
						Email: "user2.headscale.net@test.no",
					},
					{
						Id:         4,
						Name:       "user2",
						Provider:   "oidc",
						ProviderId: iss + "/user2",
					},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := ScenarioSpec{
				NodesPerUser: 1,
			}
			spec.Users = append(spec.Users, tt.cliUsers...)

			for _, user := range tt.oidcUsers {
				spec.OIDCUsers = append(spec.OIDCUsers, oidcMockUser(user, tt.emailVerified))
			}

			scenario, err := NewScenario(spec)
			assertNoErr(t, err)
			defer scenario.ShutdownAssertNoPanics(t)

			oidcMap := map[string]string{
				"HEADSCALE_OIDC_ISSUER":             scenario.mockOIDC.Issuer(),
				"HEADSCALE_OIDC_CLIENT_ID":          scenario.mockOIDC.ClientID(),
				"CREDENTIALS_DIRECTORY_TEST":        "/tmp",
				"HEADSCALE_OIDC_CLIENT_SECRET_PATH": "${CREDENTIALS_DIRECTORY_TEST}/hs_client_oidc_secret",
			}
			maps.Copy(oidcMap, tt.config)

			err = scenario.CreateHeadscaleEnvWithLoginURL(
				nil,
				hsic.WithTestName("oidcmigration"),
				hsic.WithConfigEnv(oidcMap),
				hsic.WithTLS(),
				hsic.WithFileInContainer("/tmp/hs_client_oidc_secret", []byte(scenario.mockOIDC.ClientSecret())),
			)
			assertNoErrHeadscaleEnv(t, err)

			// Ensure that the nodes have logged in, this is what
			// triggers user creation via OIDC.
			err = scenario.WaitForTailscaleSync()
			assertNoErrSync(t, err)

			headscale, err := scenario.Headscale()
			assertNoErr(t, err)

			want := tt.want(scenario.mockOIDC.Issuer())

			listUsers, err := headscale.ListUsers()
			assertNoErr(t, err)

			sort.Slice(listUsers, func(i, j int) bool {
				return listUsers[i].GetId() < listUsers[j].GetId()
			})

			if diff := cmp.Diff(want, listUsers, cmpopts.IgnoreUnexported(v1.User{}), cmpopts.IgnoreFields(v1.User{}, "CreatedAt")); diff != "" {
				t.Errorf("unexpected users: %s", diff)
			}
		})
	}
}

func TestOIDCAuthenticationWithPKCE(t *testing.T) {
	IntegrationSkip(t)

	// Single user with one node for testing PKCE flow
	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1"},
		OIDCUsers: []mockoidc.MockUser{
			oidcMockUser("user1", true),
		},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	oidcMap := map[string]string{
		"HEADSCALE_OIDC_ISSUER":             scenario.mockOIDC.Issuer(),
		"HEADSCALE_OIDC_CLIENT_ID":          scenario.mockOIDC.ClientID(),
		"HEADSCALE_OIDC_CLIENT_SECRET_PATH": "${CREDENTIALS_DIRECTORY_TEST}/hs_client_oidc_secret",
		"CREDENTIALS_DIRECTORY_TEST":        "/tmp",
		"HEADSCALE_OIDC_PKCE_ENABLED":       "1", // Enable PKCE
	}

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		nil,
		hsic.WithTestName("oidcauthpkce"),
		hsic.WithConfigEnv(oidcMap),
		hsic.WithTLS(),
		hsic.WithFileInContainer("/tmp/hs_client_oidc_secret", []byte(scenario.mockOIDC.ClientSecret())),
	)
	assertNoErrHeadscaleEnv(t, err)

	// Get all clients and verify they can connect
	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))
}

func TestOIDCReloginSameNodeNewUser(t *testing.T) {
	IntegrationSkip(t)

	// Create no nodes and no users
	scenario, err := NewScenario(ScenarioSpec{
		// First login creates the first OIDC user
		// Second login logs in the same node, which creates a new node
		// Third login logs in the same node back into the original user
		OIDCUsers: []mockoidc.MockUser{
			oidcMockUser("user1", true),
			oidcMockUser("user2", true),
			oidcMockUser("user1", true),
		},
	})
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	oidcMap := map[string]string{
		"HEADSCALE_OIDC_ISSUER":             scenario.mockOIDC.Issuer(),
		"HEADSCALE_OIDC_CLIENT_ID":          scenario.mockOIDC.ClientID(),
		"CREDENTIALS_DIRECTORY_TEST":        "/tmp",
		"HEADSCALE_OIDC_CLIENT_SECRET_PATH": "${CREDENTIALS_DIRECTORY_TEST}/hs_client_oidc_secret",
	}

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		nil,
		hsic.WithTestName("oidcauthrelog"),
		hsic.WithConfigEnv(oidcMap),
		hsic.WithTLS(),
		hsic.WithFileInContainer("/tmp/hs_client_oidc_secret", []byte(scenario.mockOIDC.ClientSecret())),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithDERPAsIP(),
	)
	assertNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	ts, err := scenario.CreateTailscaleNode("unstable", tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]))
	assertNoErr(t, err)

	u, err := ts.LoginWithURL(headscale.GetEndpoint())
	assertNoErr(t, err)

	_, err = doLoginURL(ts.Hostname(), u)
	assertNoErr(t, err)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		listUsers, err := headscale.ListUsers()
		assertNoErr(t, err)
		assert.Len(t, listUsers, 1)
		wantUsers := []*v1.User{
			{
				Id:         1,
				Name:       "user1",
				Email:      "user1@headscale.net",
				Provider:   "oidc",
				ProviderId: scenario.mockOIDC.Issuer() + "/user1",
			},
		}

		sort.Slice(listUsers, func(i, j int) bool {
			return listUsers[i].GetId() < listUsers[j].GetId()
		})

		if diff := cmp.Diff(wantUsers, listUsers, cmpopts.IgnoreUnexported(v1.User{}), cmpopts.IgnoreFields(v1.User{}, "CreatedAt")); diff != "" {
			t.Fatalf("unexpected users: %s", diff)
		}
	}, 30*time.Second, 1*time.Second, "validating users after first login")

	listNodes, err := headscale.ListNodes()
	assertNoErr(t, err)
	assert.Len(t, listNodes, 1)

	// Log out user1 and log in user2, this should create a new node
	// for user2, the node should have the same machine key and
	// a new node key.
	err = ts.Logout()
	assertNoErr(t, err)

	// TODO(kradalby): Not sure why we need to logout twice, but it fails and
	// logs in immediately after the first logout and I cannot reproduce it
	// manually.
	err = ts.Logout()
	assertNoErr(t, err)

	// Wait for logout to complete and then do second logout
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Check that the first logout completed
		status, err := ts.Status()
		assert.NoError(ct, err)
		assert.Equal(ct, "NeedsLogin", status.BackendState)
	}, 30*time.Second, 1*time.Second)

	u, err = ts.LoginWithURL(headscale.GetEndpoint())
	assertNoErr(t, err)

	_, err = doLoginURL(ts.Hostname(), u)
	assertNoErr(t, err)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		listUsers, err := headscale.ListUsers()
		assertNoErr(t, err)
		assert.Len(t, listUsers, 2)
		wantUsers := []*v1.User{
			{
				Id:         1,
				Name:       "user1",
				Email:      "user1@headscale.net",
				Provider:   "oidc",
				ProviderId: scenario.mockOIDC.Issuer() + "/user1",
			},
			{
				Id:         2,
				Name:       "user2",
				Email:      "user2@headscale.net",
				Provider:   "oidc",
				ProviderId: scenario.mockOIDC.Issuer() + "/user2",
			},
		}

		sort.Slice(listUsers, func(i, j int) bool {
			return listUsers[i].GetId() < listUsers[j].GetId()
		})

		if diff := cmp.Diff(wantUsers, listUsers, cmpopts.IgnoreUnexported(v1.User{}), cmpopts.IgnoreFields(v1.User{}, "CreatedAt")); diff != "" {
			ct.Errorf("unexpected users: %s", diff)
		}
	}, 30*time.Second, 1*time.Second, "validating users after new user login")

	var listNodesAfterNewUserLogin []*v1.Node
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		listNodesAfterNewUserLogin, err = headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, listNodesAfterNewUserLogin, 2)

		// Machine key is the same as the "machine" has not changed,
		// but Node key is not as it is a new node
		assert.Equal(ct, listNodes[0].GetMachineKey(), listNodesAfterNewUserLogin[0].GetMachineKey())
		assert.Equal(ct, listNodesAfterNewUserLogin[0].GetMachineKey(), listNodesAfterNewUserLogin[1].GetMachineKey())
		assert.NotEqual(ct, listNodesAfterNewUserLogin[0].GetNodeKey(), listNodesAfterNewUserLogin[1].GetNodeKey())
	}, 30*time.Second, 1*time.Second, "listing nodes after new user login")

	// Log out user2, and log into user1, no new node should be created,
	// the node should now "become" node1 again
	err = ts.Logout()
	assertNoErr(t, err)

	t.Logf("Logged out take one")
	t.Log("timestamp: " + time.Now().Format(TimestampFormat) + "\n")

	// TODO(kradalby): Not sure why we need to logout twice, but it fails and
	// logs in immediately after the first logout and I cannot reproduce it
	// manually.
	err = ts.Logout()
	assertNoErr(t, err)

	t.Logf("Logged out take two")
	t.Log("timestamp: " + time.Now().Format(TimestampFormat) + "\n")

	// Wait for logout to complete and then do second logout
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Check that the first logout completed
		status, err := ts.Status()
		assert.NoError(ct, err)
		assert.Equal(ct, "NeedsLogin", status.BackendState)
	}, 30*time.Second, 1*time.Second)

	// We do not actually "change" the user here, it is done by logging in again
	// as the OIDC mock server is kind of like a stack, and the next user is
	// prepared and ready to go.
	u, err = ts.LoginWithURL(headscale.GetEndpoint())
	assertNoErr(t, err)

	_, err = doLoginURL(ts.Hostname(), u)
	assertNoErr(t, err)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		status, err := ts.Status()
		assert.NoError(ct, err)
		assert.Equal(ct, "Running", status.BackendState)
	}, 30*time.Second, 1*time.Second)

	t.Logf("Logged back in")
	t.Log("timestamp: " + time.Now().Format(TimestampFormat) + "\n")

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		listUsers, err := headscale.ListUsers()
		assert.NoError(ct, err)
		assert.Len(ct, listUsers, 2)
		wantUsers := []*v1.User{
			{
				Id:         1,
				Name:       "user1",
				Email:      "user1@headscale.net",
				Provider:   "oidc",
				ProviderId: scenario.mockOIDC.Issuer() + "/user1",
			},
			{
				Id:         2,
				Name:       "user2",
				Email:      "user2@headscale.net",
				Provider:   "oidc",
				ProviderId: scenario.mockOIDC.Issuer() + "/user2",
			},
		}

		sort.Slice(listUsers, func(i, j int) bool {
			return listUsers[i].GetId() < listUsers[j].GetId()
		})

		if diff := cmp.Diff(wantUsers, listUsers, cmpopts.IgnoreUnexported(v1.User{}), cmpopts.IgnoreFields(v1.User{}, "CreatedAt")); diff != "" {
			ct.Errorf("unexpected users: %s", diff)
		}
	}, 30*time.Second, 1*time.Second, "log out user2, and log into user1, no new node should be created")

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		listNodesAfterLoggingBackIn, err := headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, listNodesAfterLoggingBackIn, 2)

		// Validate that the machine we had when we logged in the first time, has the same
		// machine key, but a different ID than the newly logged in version of the same
		// machine.
		assert.Equal(ct, listNodes[0].GetMachineKey(), listNodesAfterNewUserLogin[0].GetMachineKey())
		assert.Equal(ct, listNodes[0].GetNodeKey(), listNodesAfterNewUserLogin[0].GetNodeKey())
		assert.Equal(ct, listNodes[0].GetId(), listNodesAfterNewUserLogin[0].GetId())
		assert.Equal(ct, listNodes[0].GetMachineKey(), listNodesAfterNewUserLogin[1].GetMachineKey())
		assert.NotEqual(ct, listNodes[0].GetId(), listNodesAfterNewUserLogin[1].GetId())
		assert.NotEqual(ct, listNodes[0].GetUser().GetId(), listNodesAfterNewUserLogin[1].GetUser().GetId())

		// Even tho we are logging in again with the same user, the previous key has been expired
		// and a new one has been generated. The node entry in the database should be the same
		// as the user + machinekey still matches.
		assert.Equal(ct, listNodes[0].GetMachineKey(), listNodesAfterLoggingBackIn[0].GetMachineKey())
		assert.NotEqual(ct, listNodes[0].GetNodeKey(), listNodesAfterLoggingBackIn[0].GetNodeKey())
		assert.Equal(ct, listNodes[0].GetId(), listNodesAfterLoggingBackIn[0].GetId())

		// The "logged back in" machine should have the same machinekey but a different nodekey
		// than the version logged in with a different user.
		assert.Equal(ct, listNodesAfterLoggingBackIn[0].GetMachineKey(), listNodesAfterLoggingBackIn[1].GetMachineKey())
		assert.NotEqual(ct, listNodesAfterLoggingBackIn[0].GetNodeKey(), listNodesAfterLoggingBackIn[1].GetNodeKey())
	}, 30*time.Second, 1*time.Second, "log out user2, and log into user1, no new node should be created")
}

// assertTailscaleNodesLogout verifies that all provided Tailscale clients
// are in the logged-out state (NeedsLogin).
func assertTailscaleNodesLogout(t assert.TestingT, clients []TailscaleClient) {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}

	for _, client := range clients {
		status, err := client.Status()
		assert.NoError(t, err, "failed to get status for client %s", client.Hostname())
		assert.Equal(t, "NeedsLogin", status.BackendState,
			"client %s should be logged out", client.Hostname())
	}
}

func oidcMockUser(username string, emailVerified bool) mockoidc.MockUser {
	return mockoidc.MockUser{
		Subject:           username,
		PreferredUsername: username,
		Email:             username + "@headscale.net",
		EmailVerified:     emailVerified,
	}
}
