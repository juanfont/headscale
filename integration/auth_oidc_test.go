package integration

import (
	"maps"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)

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
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	requireNoErrListClientIPs(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	// assertClientsState(t, allClients)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	listUsers, err := headscale.ListUsers()
	require.NoError(t, err)

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
	require.NoError(t, err)
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
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	requireNoErrListClientIPs(t, err)

	// Record when sync completes to better estimate token expiry timing
	syncCompleteTime := time.Now()
	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)
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
			require.NoError(t, err)
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
			requireNoErrHeadscaleEnv(t, err)

			// Ensure that the nodes have logged in, this is what
			// triggers user creation via OIDC.
			err = scenario.WaitForTailscaleSync()
			requireNoErrSync(t, err)

			headscale, err := scenario.Headscale()
			require.NoError(t, err)

			want := tt.want(scenario.mockOIDC.Issuer())

			listUsers, err := headscale.ListUsers()
			require.NoError(t, err)

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
	require.NoError(t, err)
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
	requireNoErrHeadscaleEnv(t, err)

	// Get all clients and verify they can connect
	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	requireNoErrListClientIPs(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))
}

// TestOIDCReloginSameNodeNewUser tests the scenario where:
// 1. A Tailscale client logs in with user1 (creates node1 for user1)
// 2. The same client logs out and logs in with user2 (creates node2 for user2)
// 3. The same client logs out and logs in with user1 again (reuses node1, node2 remains)
// This validates that OIDC relogin properly handles node reuse and cleanup.
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
	require.NoError(t, err)
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
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	ts, err := scenario.CreateTailscaleNode("unstable", tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]))
	require.NoError(t, err)

	u, err := ts.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	_, err = doLoginURL(ts.Hostname(), u)
	require.NoError(t, err)

	t.Logf("Validating initial user creation at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		listUsers, err := headscale.ListUsers()
		assert.NoError(ct, err, "Failed to list users during initial validation")
		assert.Len(ct, listUsers, 1, "Expected exactly 1 user after first login, got %d", len(listUsers))
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
			ct.Errorf("User validation failed after first login - unexpected users: %s", diff)
		}
	}, 30*time.Second, 1*time.Second, "validating user1 creation after initial OIDC login")

	t.Logf("Validating initial node creation at %s", time.Now().Format(TimestampFormat))
	var listNodes []*v1.Node
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		listNodes, err = headscale.ListNodes()
		assert.NoError(ct, err, "Failed to list nodes during initial validation")
		assert.Len(ct, listNodes, 1, "Expected exactly 1 node after first login, got %d", len(listNodes))
	}, 30*time.Second, 1*time.Second, "validating initial node creation for user1 after OIDC login")

	// Collect expected node IDs for validation after user1 initial login
	expectedNodes := make([]types.NodeID, 0, 1)
	var nodeID uint64
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		status := ts.MustStatus()
		assert.NotEmpty(ct, status.Self.ID, "Node ID should be populated in status")
		var err error
		nodeID, err = strconv.ParseUint(string(status.Self.ID), 10, 64)
		assert.NoError(ct, err, "Failed to parse node ID from status")
	}, 30*time.Second, 1*time.Second, "waiting for node ID to be populated in status after initial login")
	expectedNodes = append(expectedNodes, types.NodeID(nodeID))

	// Validate initial connection state for user1
	validateInitialConnection(t, headscale, expectedNodes)

	// Log out user1 and log in user2, this should create a new node
	// for user2, the node should have the same machine key and
	// a new node key.
	err = ts.Logout()
	require.NoError(t, err)

	// TODO(kradalby): Not sure why we need to logout twice, but it fails and
	// logs in immediately after the first logout and I cannot reproduce it
	// manually.
	err = ts.Logout()
	require.NoError(t, err)

	// Wait for logout to complete and then do second logout
	t.Logf("Waiting for user1 logout completion at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Check that the first logout completed
		status, err := ts.Status()
		assert.NoError(ct, err, "Failed to get client status during logout validation")
		assert.Equal(ct, "NeedsLogin", status.BackendState, "Expected NeedsLogin state after logout, got %s", status.BackendState)
	}, 30*time.Second, 1*time.Second, "waiting for user1 logout to complete before user2 login")

	u, err = ts.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	_, err = doLoginURL(ts.Hostname(), u)
	require.NoError(t, err)

	t.Logf("Validating user2 creation at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		listUsers, err := headscale.ListUsers()
		assert.NoError(ct, err, "Failed to list users after user2 login")
		assert.Len(ct, listUsers, 2, "Expected exactly 2 users after user2 login, got %d users", len(listUsers))
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
			ct.Errorf("User validation failed after user2 login - expected both user1 and user2: %s", diff)
		}
	}, 30*time.Second, 1*time.Second, "validating both user1 and user2 exist after second OIDC login")

	var listNodesAfterNewUserLogin []*v1.Node
	// First, wait for the new node to be created
	t.Logf("Waiting for user2 node creation at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		listNodesAfterNewUserLogin, err = headscale.ListNodes()
		assert.NoError(ct, err, "Failed to list nodes after user2 login")
		// We might temporarily have more than 2 nodes during cleanup, so check for at least 2
		assert.GreaterOrEqual(ct, len(listNodesAfterNewUserLogin), 2, "Should have at least 2 nodes after user2 login, got %d (may include temporary nodes during cleanup)", len(listNodesAfterNewUserLogin))
	}, 30*time.Second, 1*time.Second, "waiting for user2 node creation (allowing temporary extra nodes during cleanup)")

	// Then wait for cleanup to stabilize at exactly 2 nodes
	t.Logf("Waiting for node cleanup stabilization at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		listNodesAfterNewUserLogin, err = headscale.ListNodes()
		assert.NoError(ct, err, "Failed to list nodes during cleanup validation")
		assert.Len(ct, listNodesAfterNewUserLogin, 2, "Should have exactly 2 nodes after cleanup (1 for user1, 1 for user2), got %d nodes", len(listNodesAfterNewUserLogin))

		// Validate that both nodes have the same machine key but different node keys
		if len(listNodesAfterNewUserLogin) >= 2 {
			// Machine key is the same as the "machine" has not changed,
			// but Node key is not as it is a new node
			assert.Equal(ct, listNodes[0].GetMachineKey(), listNodesAfterNewUserLogin[0].GetMachineKey(), "Machine key should be preserved from original node")
			assert.Equal(ct, listNodesAfterNewUserLogin[0].GetMachineKey(), listNodesAfterNewUserLogin[1].GetMachineKey(), "Both nodes should share the same machine key")
			assert.NotEqual(ct, listNodesAfterNewUserLogin[0].GetNodeKey(), listNodesAfterNewUserLogin[1].GetNodeKey(), "Node keys should be different between user1 and user2 nodes")
		}
	}, 90*time.Second, 2*time.Second, "waiting for node count stabilization at exactly 2 nodes after user2 login")

	// Security validation: Only user2's node should be active after user switch
	var activeUser2NodeID types.NodeID
	for _, node := range listNodesAfterNewUserLogin {
		if node.GetUser().GetId() == 2 { // user2
			activeUser2NodeID = types.NodeID(node.GetId())
			t.Logf("Active user2 node: %d (User: %s)", node.GetId(), node.GetUser().GetName())
			break
		}
	}

	// Validate only user2's node is online (security requirement)
	t.Logf("Validating only user2 node is online at %s", time.Now().Format(TimestampFormat))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		nodeStore, err := headscale.DebugNodeStore()
		assert.NoError(c, err, "Failed to get nodestore debug info")

		// Check user2 node is online
		if node, exists := nodeStore[activeUser2NodeID]; exists {
			assert.NotNil(c, node.IsOnline, "User2 node should have online status")
			if node.IsOnline != nil {
				assert.True(c, *node.IsOnline, "User2 node should be online after login")
			}
		} else {
			assert.Fail(c, "User2 node not found in nodestore")
		}
	}, 60*time.Second, 2*time.Second, "validating only user2 node is online after user switch")

	// Before logging out user2, validate we have exactly 2 nodes and both are stable
	t.Logf("Pre-logout validation: checking node stability at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		currentNodes, err := headscale.ListNodes()
		assert.NoError(ct, err, "Failed to list nodes before user2 logout")
		assert.Len(ct, currentNodes, 2, "Should have exactly 2 stable nodes before user2 logout, got %d", len(currentNodes))

		// Validate node stability - ensure no phantom nodes
		for i, node := range currentNodes {
			assert.NotNil(ct, node.GetUser(), "Node %d should have a valid user before logout", i)
			assert.NotEmpty(ct, node.GetMachineKey(), "Node %d should have a valid machine key before logout", i)
			t.Logf("Pre-logout node %d: User=%s, MachineKey=%s", i, node.GetUser().GetName(), node.GetMachineKey()[:16]+"...")
		}
	}, 60*time.Second, 2*time.Second, "validating stable node count and integrity before user2 logout")

	// Log out user2, and log into user1, no new node should be created,
	// the node should now "become" node1 again
	err = ts.Logout()
	require.NoError(t, err)

	t.Logf("Logged out take one")
	t.Log("timestamp: " + time.Now().Format(TimestampFormat) + "\n")

	// TODO(kradalby): Not sure why we need to logout twice, but it fails and
	// logs in immediately after the first logout and I cannot reproduce it
	// manually.
	err = ts.Logout()
	require.NoError(t, err)

	t.Logf("Logged out take two")
	t.Log("timestamp: " + time.Now().Format(TimestampFormat) + "\n")

	// Wait for logout to complete and then do second logout
	t.Logf("Waiting for user2 logout completion at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Check that the first logout completed
		status, err := ts.Status()
		assert.NoError(ct, err, "Failed to get client status during user2 logout validation")
		assert.Equal(ct, "NeedsLogin", status.BackendState, "Expected NeedsLogin state after user2 logout, got %s", status.BackendState)
	}, 30*time.Second, 1*time.Second, "waiting for user2 logout to complete before user1 relogin")

	// Before logging back in, ensure we still have exactly 2 nodes
	// Note: We skip validateLogoutComplete here since it expects all nodes to be offline,
	// but in OIDC scenario we maintain both nodes in DB with only active user online

	// Additional validation that nodes are properly maintained during logout
	t.Logf("Post-logout validation: checking node persistence at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		currentNodes, err := headscale.ListNodes()
		assert.NoError(ct, err, "Failed to list nodes after user2 logout")
		assert.Len(ct, currentNodes, 2, "Should still have exactly 2 nodes after user2 logout (nodes should persist), got %d", len(currentNodes))

		// Ensure both nodes are still valid (not cleaned up incorrectly)
		for i, node := range currentNodes {
			assert.NotNil(ct, node.GetUser(), "Node %d should still have a valid user after user2 logout", i)
			assert.NotEmpty(ct, node.GetMachineKey(), "Node %d should still have a valid machine key after user2 logout", i)
			t.Logf("Post-logout node %d: User=%s, MachineKey=%s", i, node.GetUser().GetName(), node.GetMachineKey()[:16]+"...")
		}
	}, 60*time.Second, 2*time.Second, "validating node persistence and integrity after user2 logout")

	// We do not actually "change" the user here, it is done by logging in again
	// as the OIDC mock server is kind of like a stack, and the next user is
	// prepared and ready to go.
	u, err = ts.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	_, err = doLoginURL(ts.Hostname(), u)
	require.NoError(t, err)

	t.Logf("Waiting for user1 relogin completion at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		status, err := ts.Status()
		assert.NoError(ct, err, "Failed to get client status during user1 relogin validation")
		assert.Equal(ct, "Running", status.BackendState, "Expected Running state after user1 relogin, got %s", status.BackendState)
	}, 30*time.Second, 1*time.Second, "waiting for user1 relogin to complete (final login)")

	t.Logf("Logged back in")
	t.Log("timestamp: " + time.Now().Format(TimestampFormat) + "\n")

	t.Logf("Final validation: checking user persistence at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		listUsers, err := headscale.ListUsers()
		assert.NoError(ct, err, "Failed to list users during final validation")
		assert.Len(ct, listUsers, 2, "Should still have exactly 2 users after user1 relogin, got %d", len(listUsers))
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
			ct.Errorf("Final user validation failed - both users should persist after relogin cycle: %s", diff)
		}
	}, 30*time.Second, 1*time.Second, "validating user persistence after complete relogin cycle (user1->user2->user1)")

	var listNodesAfterLoggingBackIn []*v1.Node
	// Wait for login to complete and nodes to stabilize
	t.Logf("Final node validation: checking node stability after user1 relogin at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		listNodesAfterLoggingBackIn, err = headscale.ListNodes()
		assert.NoError(ct, err, "Failed to list nodes during final validation")

		// Allow for temporary instability during login process
		if len(listNodesAfterLoggingBackIn) < 2 {
			ct.Errorf("Not enough nodes yet during final validation, got %d, want at least 2", len(listNodesAfterLoggingBackIn))
			return
		}

		// Final check should have exactly 2 nodes
		assert.Len(ct, listNodesAfterLoggingBackIn, 2, "Should have exactly 2 nodes after complete relogin cycle, got %d", len(listNodesAfterLoggingBackIn))

		// Validate that the machine we had when we logged in the first time, has the same
		// machine key, but a different ID than the newly logged in version of the same
		// machine.
		assert.Equal(ct, listNodes[0].GetMachineKey(), listNodesAfterNewUserLogin[0].GetMachineKey(), "Original user1 machine key should match user1 node after user switch")
		assert.Equal(ct, listNodes[0].GetNodeKey(), listNodesAfterNewUserLogin[0].GetNodeKey(), "Original user1 node key should match user1 node after user switch")
		assert.Equal(ct, listNodes[0].GetId(), listNodesAfterNewUserLogin[0].GetId(), "Original user1 node ID should match user1 node after user switch")
		assert.Equal(ct, listNodes[0].GetMachineKey(), listNodesAfterNewUserLogin[1].GetMachineKey(), "User1 and user2 nodes should share the same machine key")
		assert.NotEqual(ct, listNodes[0].GetId(), listNodesAfterNewUserLogin[1].GetId(), "User1 and user2 nodes should have different node IDs")
		assert.NotEqual(ct, listNodes[0].GetUser().GetId(), listNodesAfterNewUserLogin[1].GetUser().GetId(), "User1 and user2 nodes should belong to different users")

		// Even tho we are logging in again with the same user, the previous key has been expired
		// and a new one has been generated. The node entry in the database should be the same
		// as the user + machinekey still matches.
		assert.Equal(ct, listNodes[0].GetMachineKey(), listNodesAfterLoggingBackIn[0].GetMachineKey(), "Machine key should remain consistent after user1 relogin")
		assert.NotEqual(ct, listNodes[0].GetNodeKey(), listNodesAfterLoggingBackIn[0].GetNodeKey(), "Node key should be regenerated after user1 relogin")
		assert.Equal(ct, listNodes[0].GetId(), listNodesAfterLoggingBackIn[0].GetId(), "Node ID should be preserved for user1 after relogin")

		// The "logged back in" machine should have the same machinekey but a different nodekey
		// than the version logged in with a different user.
		assert.Equal(ct, listNodesAfterLoggingBackIn[0].GetMachineKey(), listNodesAfterLoggingBackIn[1].GetMachineKey(), "Both final nodes should share the same machine key")
		assert.NotEqual(ct, listNodesAfterLoggingBackIn[0].GetNodeKey(), listNodesAfterLoggingBackIn[1].GetNodeKey(), "Final nodes should have different node keys for different users")

		t.Logf("Final validation complete - node counts and key relationships verified at %s", time.Now().Format(TimestampFormat))
	}, 60*time.Second, 2*time.Second, "validating final node state after complete user1->user2->user1 relogin cycle with detailed key validation")

	// Security validation: Only user1's node should be active after relogin
	var activeUser1NodeID types.NodeID
	for _, node := range listNodesAfterLoggingBackIn {
		if node.GetUser().GetId() == 1 { // user1
			activeUser1NodeID = types.NodeID(node.GetId())
			t.Logf("Active user1 node after relogin: %d (User: %s)", node.GetId(), node.GetUser().GetName())
			break
		}
	}

	// Validate only user1's node is online (security requirement)
	t.Logf("Validating only user1 node is online after relogin at %s", time.Now().Format(TimestampFormat))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		nodeStore, err := headscale.DebugNodeStore()
		assert.NoError(c, err, "Failed to get nodestore debug info")

		// Check user1 node is online
		if node, exists := nodeStore[activeUser1NodeID]; exists {
			assert.NotNil(c, node.IsOnline, "User1 node should have online status after relogin")
			if node.IsOnline != nil {
				assert.True(c, *node.IsOnline, "User1 node should be online after relogin")
			}
		} else {
			assert.Fail(c, "User1 node not found in nodestore after relogin")
		}
	}, 60*time.Second, 2*time.Second, "validating only user1 node is online after final relogin")
}

// TestOIDCFollowUpUrl validates the follow-up login flow
// Prerequisites:
// - short TTL for the registration cache via HEADSCALE_TUNING_REGISTER_CACHE_EXPIRATION
// Scenario:
// - client starts a login process and gets initial AuthURL
// - time.sleep(HEADSCALE_TUNING_REGISTER_CACHE_EXPIRATION + 30 secs) waits for the cache to expire
// - client checks its status to verify that AuthUrl has changed (by followup URL)
// - client uses the new AuthURL to log in. It should complete successfully.
func TestOIDCFollowUpUrl(t *testing.T) {
	IntegrationSkip(t)

	// Create no nodes and no users
	scenario, err := NewScenario(
		ScenarioSpec{
			OIDCUsers: []mockoidc.MockUser{
				oidcMockUser("user1", true),
			},
		},
	)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	oidcMap := map[string]string{
		"HEADSCALE_OIDC_ISSUER":             scenario.mockOIDC.Issuer(),
		"HEADSCALE_OIDC_CLIENT_ID":          scenario.mockOIDC.ClientID(),
		"CREDENTIALS_DIRECTORY_TEST":        "/tmp",
		"HEADSCALE_OIDC_CLIENT_SECRET_PATH": "${CREDENTIALS_DIRECTORY_TEST}/hs_client_oidc_secret",
		// smaller cache expiration time to quickly expire AuthURL
		"HEADSCALE_TUNING_REGISTER_CACHE_CLEANUP":    "10s",
		"HEADSCALE_TUNING_REGISTER_CACHE_EXPIRATION": "1m30s",
	}

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		nil,
		hsic.WithTestName("oidcauthrelog"),
		hsic.WithConfigEnv(oidcMap),
		hsic.WithTLS(),
		hsic.WithFileInContainer("/tmp/hs_client_oidc_secret", []byte(scenario.mockOIDC.ClientSecret())),
		hsic.WithEmbeddedDERPServerOnly(),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	listUsers, err := headscale.ListUsers()
	require.NoError(t, err)
	assert.Empty(t, listUsers)

	ts, err := scenario.CreateTailscaleNode(
		"unstable",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
	)
	require.NoError(t, err)

	u, err := ts.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	// wait for the registration cache to expire
	// a little bit more than HEADSCALE_TUNING_REGISTER_CACHE_EXPIRATION
	time.Sleep(2 * time.Minute)

	var newUrl *url.URL
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		st, err := ts.Status()
		assert.NoError(c, err)
		assert.Equal(c, "NeedsLogin", st.BackendState)

		// get new AuthURL from daemon
		newUrl, err = url.Parse(st.AuthURL)
		assert.NoError(c, err)

		assert.NotEqual(c, u.String(), st.AuthURL, "AuthURL should change")
	}, 10*time.Second, 200*time.Millisecond, "Waiting for registration cache to expire and status to reflect NeedsLogin")

	_, err = doLoginURL(ts.Hostname(), newUrl)
	require.NoError(t, err)

	listUsers, err = headscale.ListUsers()
	require.NoError(t, err)
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

	sort.Slice(
		listUsers, func(i, j int) bool {
			return listUsers[i].GetId() < listUsers[j].GetId()
		},
	)

	if diff := cmp.Diff(
		wantUsers,
		listUsers,
		cmpopts.IgnoreUnexported(v1.User{}),
		cmpopts.IgnoreFields(v1.User{}, "CreatedAt"),
	); diff != "" {
		t.Fatalf("unexpected users: %s", diff)
	}

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		listNodes, err := headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, listNodes, 1)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for expected node list after OIDC login")
}

// TestOIDCMultipleOpenedLoginUrls tests the scenario:
// - client (mostly Windows) opens multiple browser tabs with different login URLs
// - client performs auth on the first opened browser tab
//
// This test makes sure that cookies are still valid for the first browser tab.
func TestOIDCMultipleOpenedLoginUrls(t *testing.T) {
	IntegrationSkip(t)

	scenario, err := NewScenario(
		ScenarioSpec{
			OIDCUsers: []mockoidc.MockUser{
				oidcMockUser("user1", true),
			},
		},
	)

	require.NoError(t, err)
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
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	listUsers, err := headscale.ListUsers()
	require.NoError(t, err)
	assert.Empty(t, listUsers)

	ts, err := scenario.CreateTailscaleNode(
		"unstable",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
	)
	require.NoError(t, err)

	u1, err := ts.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	u2, err := ts.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	// make sure login URLs are different
	require.NotEqual(t, u1.String(), u2.String())

	loginClient, err := newLoginHTTPClient(ts.Hostname())
	require.NoError(t, err)

	// open the first login URL "in browser"
	_, redirect1, err := doLoginURLWithClient(ts.Hostname(), u1, loginClient, false)
	require.NoError(t, err)
	// open the second login URL "in browser"
	_, redirect2, err := doLoginURLWithClient(ts.Hostname(), u2, loginClient, false)
	require.NoError(t, err)

	// two valid redirects with different state/nonce params
	require.NotEqual(t, redirect1.String(), redirect2.String())

	// complete auth with the first opened "browser tab"
	_, redirect1, err = doLoginURLWithClient(ts.Hostname(), redirect1, loginClient, true)
	require.NoError(t, err)

	listUsers, err = headscale.ListUsers()
	require.NoError(t, err)
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

	sort.Slice(
		listUsers, func(i, j int) bool {
			return listUsers[i].GetId() < listUsers[j].GetId()
		},
	)

	if diff := cmp.Diff(
		wantUsers,
		listUsers,
		cmpopts.IgnoreUnexported(v1.User{}),
		cmpopts.IgnoreFields(v1.User{}, "CreatedAt"),
	); diff != "" {
		t.Fatalf("unexpected users: %s", diff)
	}

	assert.EventuallyWithT(
		t, func(c *assert.CollectT) {
			listNodes, err := headscale.ListNodes()
			assert.NoError(c, err)
			assert.Len(c, listNodes, 1)
		}, 10*time.Second, 200*time.Millisecond, "Waiting for expected node list after OIDC login",
	)
}

// TestOIDCReloginSameNodeSameUser tests the scenario where a single Tailscale client
// authenticates using OIDC (OpenID Connect), logs out, and then logs back in as the same user.
//
// OIDC is an authentication layer built on top of OAuth 2.0 that allows users to authenticate
// using external identity providers (like Google, Microsoft, etc.) rather than managing
// credentials directly in headscale.
//
// This test validates the "same user relogin" behavior in headscale's OIDC authentication flow:
// - A single client authenticates via OIDC as user1
// - The client logs out, ending the session
// - The same client logs back in via OIDC as the same user (user1)
// - The test verifies that the user account persists correctly
// - The test verifies that the machine key is preserved (since it's the same physical device)
// - The test verifies that the node ID is preserved (since it's the same user on the same device)
// - The test verifies that the node key is regenerated (since it's a new session)
// - The test verifies that the client comes back online properly
//
// This scenario is important for normal user workflows where someone might need to restart
// their Tailscale client, reboot their computer, or temporarily disconnect and reconnect.
// It ensures that headscale properly handles session management while preserving device
// identity and user associations.
//
// The test uses a single node scenario (unlike multi-node tests) to focus specifically on
// the authentication and session management aspects rather than network topology changes.
// The "same node" in the name refers to the same physical device/client, while "same user"
// refers to authenticating with the same OIDC identity.
func TestOIDCReloginSameNodeSameUser(t *testing.T) {
	IntegrationSkip(t)

	// Create scenario with same user for both login attempts
	scenario, err := NewScenario(ScenarioSpec{
		OIDCUsers: []mockoidc.MockUser{
			oidcMockUser("user1", true), // Initial login
			oidcMockUser("user1", true), // Relogin with same user
		},
	})
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	oidcMap := map[string]string{
		"HEADSCALE_OIDC_ISSUER":             scenario.mockOIDC.Issuer(),
		"HEADSCALE_OIDC_CLIENT_ID":          scenario.mockOIDC.ClientID(),
		"CREDENTIALS_DIRECTORY_TEST":        "/tmp",
		"HEADSCALE_OIDC_CLIENT_SECRET_PATH": "${CREDENTIALS_DIRECTORY_TEST}/hs_client_oidc_secret",
	}

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		nil,
		hsic.WithTestName("oidcsameuser"),
		hsic.WithConfigEnv(oidcMap),
		hsic.WithTLS(),
		hsic.WithFileInContainer("/tmp/hs_client_oidc_secret", []byte(scenario.mockOIDC.ClientSecret())),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithDERPAsIP(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	ts, err := scenario.CreateTailscaleNode("unstable", tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]))
	require.NoError(t, err)

	// Initial login as user1
	u, err := ts.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	_, err = doLoginURL(ts.Hostname(), u)
	require.NoError(t, err)

	t.Logf("Validating initial user1 creation at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		listUsers, err := headscale.ListUsers()
		assert.NoError(ct, err, "Failed to list users during initial validation")
		assert.Len(ct, listUsers, 1, "Expected exactly 1 user after first login, got %d", len(listUsers))
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
			ct.Errorf("User validation failed after first login - unexpected users: %s", diff)
		}
	}, 30*time.Second, 1*time.Second, "validating user1 creation after initial OIDC login")

	t.Logf("Validating initial node creation at %s", time.Now().Format(TimestampFormat))
	var initialNodes []*v1.Node
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		initialNodes, err = headscale.ListNodes()
		assert.NoError(ct, err, "Failed to list nodes during initial validation")
		assert.Len(ct, initialNodes, 1, "Expected exactly 1 node after first login, got %d", len(initialNodes))
	}, 30*time.Second, 1*time.Second, "validating initial node creation for user1 after OIDC login")

	// Collect expected node IDs for validation after user1 initial login
	expectedNodes := make([]types.NodeID, 0, 1)
	var nodeID uint64
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		status := ts.MustStatus()
		assert.NotEmpty(ct, status.Self.ID, "Node ID should be populated in status")
		var err error
		nodeID, err = strconv.ParseUint(string(status.Self.ID), 10, 64)
		assert.NoError(ct, err, "Failed to parse node ID from status")
	}, 30*time.Second, 1*time.Second, "waiting for node ID to be populated in status after initial login")
	expectedNodes = append(expectedNodes, types.NodeID(nodeID))

	// Validate initial connection state for user1
	validateInitialConnection(t, headscale, expectedNodes)

	// Store initial node keys for comparison
	initialMachineKey := initialNodes[0].GetMachineKey()
	initialNodeKey := initialNodes[0].GetNodeKey()
	initialNodeID := initialNodes[0].GetId()

	// Logout user1
	err = ts.Logout()
	require.NoError(t, err)

	// TODO(kradalby): Not sure why we need to logout twice, but it fails and
	// logs in immediately after the first logout and I cannot reproduce it
	// manually.
	err = ts.Logout()
	require.NoError(t, err)

	// Wait for logout to complete
	t.Logf("Waiting for user1 logout completion at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Check that the logout completed
		status, err := ts.Status()
		assert.NoError(ct, err, "Failed to get client status during logout validation")
		assert.Equal(ct, "NeedsLogin", status.BackendState, "Expected NeedsLogin state after logout, got %s", status.BackendState)
	}, 30*time.Second, 1*time.Second, "waiting for user1 logout to complete before same-user relogin")

	// Validate node persistence during logout (node should remain in DB)
	t.Logf("Validating node persistence during logout at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		listNodes, err := headscale.ListNodes()
		assert.NoError(ct, err, "Failed to list nodes during logout validation")
		assert.Len(ct, listNodes, 1, "Should still have exactly 1 node during logout (node should persist in DB), got %d", len(listNodes))
	}, 30*time.Second, 1*time.Second, "validating node persistence in database during same-user logout")

	// Login again as the same user (user1)
	u, err = ts.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	_, err = doLoginURL(ts.Hostname(), u)
	require.NoError(t, err)

	t.Logf("Waiting for user1 relogin completion at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		status, err := ts.Status()
		assert.NoError(ct, err, "Failed to get client status during relogin validation")
		assert.Equal(ct, "Running", status.BackendState, "Expected Running state after user1 relogin, got %s", status.BackendState)
	}, 30*time.Second, 1*time.Second, "waiting for user1 relogin to complete (same user)")

	t.Logf("Final validation: checking user persistence after same-user relogin at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		listUsers, err := headscale.ListUsers()
		assert.NoError(ct, err, "Failed to list users during final validation")
		assert.Len(ct, listUsers, 1, "Should still have exactly 1 user after same-user relogin, got %d", len(listUsers))
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
			ct.Errorf("Final user validation failed - user1 should persist after same-user relogin: %s", diff)
		}
	}, 30*time.Second, 1*time.Second, "validating user1 persistence after same-user OIDC relogin cycle")

	var finalNodes []*v1.Node
	t.Logf("Final node validation: checking node stability after same-user relogin at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		finalNodes, err = headscale.ListNodes()
		assert.NoError(ct, err, "Failed to list nodes during final validation")
		assert.Len(ct, finalNodes, 1, "Should have exactly 1 node after same-user relogin, got %d", len(finalNodes))

		// Validate node key behavior for same user relogin
		finalNode := finalNodes[0]

		// Machine key should be preserved (same physical machine)
		assert.Equal(ct, initialMachineKey, finalNode.GetMachineKey(), "Machine key should be preserved for same user same node relogin")

		// Node ID should be preserved (same user, same machine)
		assert.Equal(ct, initialNodeID, finalNode.GetId(), "Node ID should be preserved for same user same node relogin")

		// Node key should be regenerated (new session after logout)
		assert.NotEqual(ct, initialNodeKey, finalNode.GetNodeKey(), "Node key should be regenerated after logout/relogin even for same user")

		t.Logf("Final validation complete - same user relogin key relationships verified at %s", time.Now().Format(TimestampFormat))
	}, 60*time.Second, 2*time.Second, "validating final node state after same-user OIDC relogin cycle with key preservation validation")

	// Security validation: user1's node should be active after relogin
	activeUser1NodeID := types.NodeID(finalNodes[0].GetId())
	t.Logf("Validating user1 node is online after same-user relogin at %s", time.Now().Format(TimestampFormat))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		nodeStore, err := headscale.DebugNodeStore()
		assert.NoError(c, err, "Failed to get nodestore debug info")

		// Check user1 node is online
		if node, exists := nodeStore[activeUser1NodeID]; exists {
			assert.NotNil(c, node.IsOnline, "User1 node should have online status after same-user relogin")
			if node.IsOnline != nil {
				assert.True(c, *node.IsOnline, "User1 node should be online after same-user relogin")
			}
		} else {
			assert.Fail(c, "User1 node not found in nodestore after same-user relogin")
		}
	}, 60*time.Second, 2*time.Second, "validating user1 node is online after same-user OIDC relogin")
}

// TestOIDCExpiryAfterRestart validates that node expiry is preserved
// when a tailscaled client restarts and reconnects to headscale.
//
// This test reproduces the bug reported in https://github.com/juanfont/headscale/issues/2862
// where OIDC expiry was reset to 0001-01-01 00:00:00 after tailscaled restart.
//
// Test flow:
// 1. Node logs in with OIDC (gets 72h expiry)
// 2. Verify expiry is set correctly in headscale
// 3. Restart tailscaled container (simulates daemon restart)
// 4. Wait for reconnection
// 5. Verify expiry is still set correctly (not zero).
func TestOIDCExpiryAfterRestart(t *testing.T) {
	IntegrationSkip(t)

	scenario, err := NewScenario(ScenarioSpec{
		OIDCUsers: []mockoidc.MockUser{
			oidcMockUser("user1", true),
		},
	})

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	oidcMap := map[string]string{
		"HEADSCALE_OIDC_ISSUER":             scenario.mockOIDC.Issuer(),
		"HEADSCALE_OIDC_CLIENT_ID":          scenario.mockOIDC.ClientID(),
		"CREDENTIALS_DIRECTORY_TEST":        "/tmp",
		"HEADSCALE_OIDC_CLIENT_SECRET_PATH": "${CREDENTIALS_DIRECTORY_TEST}/hs_client_oidc_secret",
		"HEADSCALE_OIDC_EXPIRY":             "72h",
	}

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		nil,
		hsic.WithTestName("oidcexpiry"),
		hsic.WithConfigEnv(oidcMap),
		hsic.WithTLS(),
		hsic.WithFileInContainer("/tmp/hs_client_oidc_secret", []byte(scenario.mockOIDC.ClientSecret())),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithDERPAsIP(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	// Create and login tailscale client
	ts, err := scenario.CreateTailscaleNode("unstable", tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]))
	require.NoError(t, err)

	u, err := ts.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	_, err = doLoginURL(ts.Hostname(), u)
	require.NoError(t, err)

	t.Logf("Validating initial login and expiry at %s", time.Now().Format(TimestampFormat))

	// Verify initial expiry is set
	var initialExpiry time.Time
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		nodes, err := headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, nodes, 1)

		node := nodes[0]
		assert.NotNil(ct, node.GetExpiry(), "Expiry should be set after OIDC login")

		if node.GetExpiry() != nil {
			expiryTime := node.GetExpiry().AsTime()
			assert.False(ct, expiryTime.IsZero(), "Expiry should not be zero time")

			initialExpiry = expiryTime
			t.Logf("Initial expiry set to: %v (expires in %v)", expiryTime, time.Until(expiryTime))
		}
	}, 30*time.Second, 1*time.Second, "validating initial expiry after OIDC login")

	// Now restart the tailscaled container
	t.Logf("Restarting tailscaled container at %s", time.Now().Format(TimestampFormat))

	err = ts.Restart()
	require.NoError(t, err, "Failed to restart tailscaled container")

	t.Logf("Tailscaled restarted, waiting for reconnection at %s", time.Now().Format(TimestampFormat))

	// Wait for the node to come back online
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		status, err := ts.Status()
		if !assert.NoError(ct, err) {
			return
		}

		if !assert.NotNil(ct, status) {
			return
		}

		assert.Equal(ct, "Running", status.BackendState)
	}, 60*time.Second, 2*time.Second, "waiting for tailscale to reconnect after restart")

	// THE CRITICAL TEST: Verify expiry is still set correctly after restart
	t.Logf("Validating expiry preservation after restart at %s", time.Now().Format(TimestampFormat))

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		nodes, err := headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, nodes, 1, "Should still have exactly 1 node after restart")

		node := nodes[0]
		assert.NotNil(ct, node.GetExpiry(), "Expiry should NOT be nil after restart")

		if node.GetExpiry() != nil {
			expiryTime := node.GetExpiry().AsTime()

			// This is the bug check - expiry should NOT be zero time
			assert.False(ct, expiryTime.IsZero(),
				"BUG: Expiry was reset to zero time after tailscaled restart! This is issue #2862")

			// Expiry should be exactly the same as before restart
			assert.Equal(ct, initialExpiry, expiryTime,
				"Expiry should be exactly the same after restart, got %v, expected %v",
				expiryTime, initialExpiry)

			t.Logf("SUCCESS: Expiry preserved after restart: %v (expires in %v)",
				expiryTime, time.Until(expiryTime))
		}
	}, 30*time.Second, 1*time.Second, "validating expiry preservation after restart")
}
