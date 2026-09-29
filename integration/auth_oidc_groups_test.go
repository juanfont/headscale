package integration

import (
	"net/netip"
	"testing"
	"time"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

const oidcGroupsDomain = "example.com"

// oidcGroupsEnv returns the headscale environment for OIDC with group sync
// set to enabled. The groups scope is requested because the mock provider,
// like several real ones, only asserts groups when asked for them.
func oidcGroupsEnv(scenario *Scenario, enabled bool) map[string]string {
	env := map[string]string{
		"HEADSCALE_OIDC_ISSUER":             scenario.mockOIDC.Issuer(),
		"HEADSCALE_OIDC_CLIENT_ID":          scenario.mockOIDC.ClientID(),
		"HEADSCALE_OIDC_SCOPE":              "openid profile email groups",
		"CREDENTIALS_DIRECTORY_TEST":        "/tmp",
		"HEADSCALE_OIDC_CLIENT_SECRET_PATH": "${CREDENTIALS_DIRECTORY_TEST}/hs_client_oidc_secret",
	}

	if enabled {
		env["HEADSCALE_OIDC_GROUPS_ENABLED"] = "true"
		env["HEADSCALE_OIDC_GROUPS_DOMAIN"] = oidcGroupsDomain
	}

	return env
}

func findUserByEmail(users []*clientv1.User, email string) *clientv1.User {
	for _, u := range users {
		if u.Email == email {
			return u
		}
	}

	return nil
}

// TestOIDCGroupsGrantAndRevokeAccess is the feature end to end against a real
// headscale and real clients: an ACL written as group:<name>@<domain> grants
// access to a member of that identity-provider group, the grant reaches an
// already-connected peer without a restart, and removing the group at the
// identity provider revokes it at the next login.
//
// The OIDC user logs in three times: without groups, as a member of
// "Engineering", and without groups again. An anchor peer, logged in first as
// its own OIDC user, stays connected
// throughout and inspects its own packet filter, where the OIDC user's IP can
// only appear through the group-gated rule.
func TestOIDCGroupsGrantAndRevokeAccess(t *testing.T) {
	IntegrationSkip(t)

	const (
		oidcUsername = "engineer"
		anchorUser   = "anchor"
	)

	oidcEmail := oidcUsername + "@headscale.net"

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{anchorUser},
		// The mock provider serves logins from this queue in order, and
		// the scenario logs the anchor's node in through it first.
		OIDCUsers: []mockoidc.MockUser{
			oidcMockUser(anchorUser, true),
			oidcMockUser(oidcUsername, true),
			oidcMockUserWithGroups(oidcUsername, true, "Engineering"),
			oidcMockUser(oidcUsername, true),
		},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		nil,
		hsic.WithTestName("oidcgroupsacl"),
		hsic.WithConfigEnv(oidcGroupsEnv(scenario, true)),
		hsic.WithFileInContainer("/tmp/hs_client_oidc_secret", []byte(scenario.mockOIDC.ClientSecret())),
		hsic.WithACLPolicy(&policyv2.Policy{
			ACLs: []policyv2.ACL{
				{
					Action:  "accept",
					Sources: []policyv2.Alias{groupp("group:engineering@" + oidcGroupsDomain)},
					Destinations: []policyv2.AliasWithPorts{
						aliasWithPorts(prefixp("100.64.0.0/10"), tailcfg.PortRangeAny),
					},
				},
			},
		}),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	anchorClients, err := scenario.ListTailscaleClients()
	require.NoError(t, err)
	require.Len(t, anchorClients, 1, "expected exactly one anchor client before the OIDC login")

	anchor := anchorClients[0]

	oidcClient, err := scenario.CreateTailscaleNode("unstable",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]))
	require.NoError(t, err)

	login := func() {
		t.Helper()

		u, err := oidcClient.LoginWithURL(headscale.GetEndpoint())
		require.NoError(t, err)

		_, err = doLoginURL(oidcClient.Hostname(), u)
		require.NoError(t, err)
	}

	relogin := func() {
		t.Helper()

		// Logging out twice mirrors TestOIDCReloginSameNodeSameUser.
		require.NoError(t, oidcClient.Logout())
		require.NoError(t, oidcClient.Logout())

		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			status, err := oidcClient.Status()
			assert.NoError(ct, err)
			assert.Equal(ct, "NeedsLogin", status.BackendState)
		}, integrationutil.ScaledTimeout(30*time.Second), 1*time.Second,
			"waiting for logout to settle before relogin")

		login()
	}

	assertGroups := func(want []string, msg string) {
		t.Helper()

		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			users, err := headscale.ListUsers()
			assert.NoError(ct, err)

			user := findUserByEmail(users, oidcEmail)
			if assert.NotNil(ct, user, "OIDC user must be registered") {
				assert.ElementsMatch(ct, want, user.Groups)
			}
		}, integrationutil.ScaledTimeout(30*time.Second), 1*time.Second, msg)
	}

	login()
	require.NoError(t, scenario.WaitForTailscaleSync())

	oidcIPv4, err := oidcClient.IPv4()
	require.NoError(t, err)

	// anchorAllows reports whether the anchor's packet filter admits ip as a
	// source. A filter that cannot be read fails the check rather than
	// counting as "not allowed", which would let the revocation checks pass
	// vacuously.
	anchorAllows := func(ct assert.TestingT, ip netip.Addr) bool {
		pf, err := anchor.PacketFilter()
		if !assert.NoError(ct, err, "reading the anchor's packet filter") {
			return false
		}

		for _, m := range pf {
			for _, src := range m.Srcs {
				if src.Contains(ip) {
					return true
				}
			}
		}

		return false
	}

	// First login: no groups, so group:engineering@example.com is empty.
	assertGroups([]string{}, "the first login asserts no groups")
	assert.Never(t, func() bool { return anchorAllows(t, oidcIPv4) },
		integrationutil.ScaledTimeout(5*time.Second), 500*time.Millisecond,
		"the OIDC user must not be allowed before joining the group")

	// Second login: a member of Engineering. The grant must reach the
	// connected anchor without a restart.
	relogin()
	assertGroups([]string{"engineering@" + oidcGroupsDomain},
		"the second login stores the qualified, lowercased group")
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.True(ct, anchorAllows(ct, oidcIPv4),
			"the anchor's packet filter must allow the new group member")
	}, integrationutil.ScaledTimeout(30*time.Second), 1*time.Second,
		"group membership must propagate to connected peers")

	// Third login: the group was removed at the identity provider.
	relogin()
	assertGroups([]string{}, "the third login revokes the group")
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.False(ct, anchorAllows(ct, oidcIPv4),
			"the anchor's packet filter must drop the former group member")
	}, integrationutil.ScaledTimeout(30*time.Second), 1*time.Second,
		"group revocation must propagate to connected peers")
}

// TestOIDCGroupsDisabledDoesNotPersist checks the default: with group sync off,
// a provider asserting groups leaves the user without memberships, so
// upgrading changes nothing for existing deployments.
func TestOIDCGroupsDisabledDoesNotPersist(t *testing.T) {
	IntegrationSkip(t)

	const username = "engineer"

	// The scenario logs the listed user's node in through the mock provider.
	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{username},
		OIDCUsers: []mockoidc.MockUser{
			oidcMockUserWithGroups(username, true, "engineering"),
		},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		nil,
		hsic.WithTestName("oidcgroupsdisabled"),
		hsic.WithConfigEnv(oidcGroupsEnv(scenario, false)),
		hsic.WithFileInContainer("/tmp/hs_client_oidc_secret", []byte(scenario.mockOIDC.ClientSecret())),
	)
	requireNoErrHeadscaleEnv(t, err)

	require.NoError(t, scenario.WaitForTailscaleSync())

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		users, err := headscale.ListUsers()
		assert.NoError(ct, err)

		user := findUserByEmail(users, username+"@headscale.net")
		if assert.NotNil(ct, user, "OIDC user must be registered") {
			assert.Empty(ct, user.Groups)
		}
	}, integrationutil.ScaledTimeout(30*time.Second), 1*time.Second,
		"no groups may be stored while group sync is disabled")
}
