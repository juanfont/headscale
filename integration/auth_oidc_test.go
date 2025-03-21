package integration

import (
	"fmt"
	"net/netip"
	"sort"
	"testing"
	"time"

	"maps"

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
	t.Parallel()

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

// This test is really flaky.
func TestOIDCExpireNodesBasedOnTokenExpiry(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

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

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// assertClientsState(t, allClients)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d (before expiry)", success, len(allClients)*len(allIps))

	// This is not great, but this sadly is a time dependent test, so the
	// safe thing to do is wait out the whole TTL time before checking if
	// the clients have logged out. The Wait function can't do it itself
	// as it has an upper bound of 1 min.
	time.Sleep(shortAccessTTL)

	assertTailscaleNodesLogout(t, allClients)
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
			for _, user := range tt.cliUsers {
				spec.Users = append(spec.Users, user)
			}

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
	t.Parallel()

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
	t.Parallel()

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
	)
	assertNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	listUsers, err := headscale.ListUsers()
	assertNoErr(t, err)
	assert.Len(t, listUsers, 0)

	ts, err := scenario.CreateTailscaleNode("unstable", tsic.WithNetwork(scenario.networks[TestDefaultNetwork]))
	assertNoErr(t, err)

	u, err := ts.LoginWithURL(headscale.GetEndpoint())
	assertNoErr(t, err)

	_, err = doLoginURL(ts.Hostname(), u)
	assertNoErr(t, err)

	listUsers, err = headscale.ListUsers()
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

	listNodes, err := headscale.ListNodes()
	assertNoErr(t, err)
	assert.Len(t, listNodes, 1)

	// Log out user1 and log in user2, this should create a new node
	// for user2, the node should have the same machine key and
	// a new node key.
	err = ts.Logout()
	assertNoErr(t, err)

	time.Sleep(5 * time.Second)

	// TODO(kradalby): Not sure why we need to logout twice, but it fails and
	// logs in immediately after the first logout and I cannot reproduce it
	// manually.
	err = ts.Logout()
	assertNoErr(t, err)

	u, err = ts.LoginWithURL(headscale.GetEndpoint())
	assertNoErr(t, err)

	_, err = doLoginURL(ts.Hostname(), u)
	assertNoErr(t, err)

	listUsers, err = headscale.ListUsers()
	assertNoErr(t, err)
	assert.Len(t, listUsers, 2)
	wantUsers = []*v1.User{
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
		t.Fatalf("unexpected users: %s", diff)
	}

	listNodesAfterNewUserLogin, err := headscale.ListNodes()
	assertNoErr(t, err)
	assert.Len(t, listNodesAfterNewUserLogin, 2)

	// Machine key is the same as the "machine" has not changed,
	// but Node key is not as it is a new node
	assert.Equal(t, listNodes[0].MachineKey, listNodesAfterNewUserLogin[0].MachineKey)
	assert.Equal(t, listNodesAfterNewUserLogin[0].MachineKey, listNodesAfterNewUserLogin[1].MachineKey)
	assert.NotEqual(t, listNodesAfterNewUserLogin[0].NodeKey, listNodesAfterNewUserLogin[1].NodeKey)

	// Log out user2, and log into user1, no new node should be created,
	// the node should now "become" node1 again
	err = ts.Logout()
	assertNoErr(t, err)

	time.Sleep(5 * time.Second)

	// TODO(kradalby): Not sure why we need to logout twice, but it fails and
	// logs in immediately after the first logout and I cannot reproduce it
	// manually.
	err = ts.Logout()
	assertNoErr(t, err)

	u, err = ts.LoginWithURL(headscale.GetEndpoint())
	assertNoErr(t, err)

	_, err = doLoginURL(ts.Hostname(), u)
	assertNoErr(t, err)

	listUsers, err = headscale.ListUsers()
	assertNoErr(t, err)
	assert.Len(t, listUsers, 2)
	wantUsers = []*v1.User{
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
		t.Fatalf("unexpected users: %s", diff)
	}

	listNodesAfterLoggingBackIn, err := headscale.ListNodes()
	assertNoErr(t, err)
	assert.Len(t, listNodesAfterLoggingBackIn, 2)

	// Validate that the machine we had when we logged in the first time, has the same
	// machine key, but a different ID than the newly logged in version of the same
	// machine.
	assert.Equal(t, listNodes[0].MachineKey, listNodesAfterNewUserLogin[0].MachineKey)
	assert.Equal(t, listNodes[0].NodeKey, listNodesAfterNewUserLogin[0].NodeKey)
	assert.Equal(t, listNodes[0].Id, listNodesAfterNewUserLogin[0].Id)
	assert.Equal(t, listNodes[0].MachineKey, listNodesAfterNewUserLogin[1].MachineKey)
	assert.NotEqual(t, listNodes[0].Id, listNodesAfterNewUserLogin[1].Id)
	assert.NotEqual(t, listNodes[0].User.Id, listNodesAfterNewUserLogin[1].User.Id)

	// Even tho we are logging in again with the same user, the previous key has been expired
	// and a new one has been generated. The node entry in the database should be the same
	// as the user + machinekey still matches.
	assert.Equal(t, listNodes[0].MachineKey, listNodesAfterLoggingBackIn[0].MachineKey)
	assert.NotEqual(t, listNodes[0].NodeKey, listNodesAfterLoggingBackIn[0].NodeKey)
	assert.Equal(t, listNodes[0].Id, listNodesAfterLoggingBackIn[0].Id)

	// The "logged back in" machine should have the same machinekey but a different nodekey
	// than the version logged in with a different user.
	assert.Equal(t, listNodesAfterLoggingBackIn[0].MachineKey, listNodesAfterLoggingBackIn[1].MachineKey)
	assert.NotEqual(t, listNodesAfterLoggingBackIn[0].NodeKey, listNodesAfterLoggingBackIn[1].NodeKey)
}

func assertTailscaleNodesLogout(t *testing.T, clients []TailscaleClient) {
	t.Helper()

	for _, client := range clients {
		status, err := client.Status()
		assertNoErr(t, err)

		assert.Equal(t, "NeedsLogin", status.BackendState)
	}
}

func oidcMockUser(username string, emailVerified bool) mockoidc.MockUser {
	return mockoidc.MockUser{
		Subject:           username,
		PreferredUsername: username,
		Email:             fmt.Sprintf("%s@headscale.net", username),
		EmailVerified:     emailVerified,
	}
}
