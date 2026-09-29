package hscontrol

import (
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newOIDCGroupsBrowser(t *testing.T, groups types.OIDCGroupsConfig) *oidcBrowser {
	t.Helper()

	return newOIDCBrowserWith(t, "", func(cfg *types.OIDCConfig) {
		// The mock provider, like several real ones, only asserts groups
		// when the groups scope is requested.
		cfg.Scope = append(cfg.Scope, "groups")
		cfg.Groups = groups
	})
}

// loginAs completes an interactive OIDC login as user for a new pending node
// and returns the confirmation page and the URL it was served from.
func (b *oidcBrowser) loginAs(t *testing.T, user *mockoidc.MockUser) (*url.URL, string) {
	t.Helper()

	b.idp.QueueUser(user)

	_, registerURL := b.pendingNode(t)

	status, landed, body := b.get(t, registerURL)
	require.Equal(t, http.StatusOK, status, "login must succeed; body: %s", body)
	require.Contains(t, body, "Confirm node registration")

	return landed, body
}

// confirm submits the registration confirmation form on page.
func (b *oidcBrowser) confirm(t *testing.T, pageURL *url.URL, page string) {
	t.Helper()

	csrf := csrfInputRe.FindStringSubmatch(page)
	require.Len(t, csrf, 2)

	action := formActionRe.FindStringSubmatch(page)
	require.Len(t, action, 2)

	confirmURL, err := pageURL.Parse(action[1])
	require.NoError(t, err)

	//nolint:noctx // test client
	resp, err := b.client.PostForm(confirmURL.String(), url.Values{
		registerConfirmCSRFCookie: {csrf[1]},
	})
	require.NoError(t, err)

	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// userGroups returns the groups of the user logged in by [groupsUser].
func (b *oidcBrowser) userGroups(t *testing.T) []string {
	t.Helper()

	users, err := b.app.state.ListAllUsers()
	require.NoError(t, err)

	for _, u := range users {
		if u.Email == groupsUserEmail {
			return u.GroupNames()
		}
	}

	require.Failf(t, "user not found", "no user with email %q", groupsUserEmail)

	return nil
}

const groupsUserEmail = "jane@example.com"

func groupsUser(groups ...string) *mockoidc.MockUser {
	return &mockoidc.MockUser{
		Subject:           "groups-user",
		Email:             groupsUserEmail,
		EmailVerified:     true,
		PreferredUsername: "jane",
		Groups:            groups,
	}
}

// TestOIDCLoginSyncsGroups drives real logins through the callback and checks
// that each one replaces the user's memberships with what the identity
// provider asserts, and that the compiled policy follows, including when a
// group is taken away.
func TestOIDCLoginSyncsGroups(t *testing.T) {
	b := newOIDCGroupsBrowser(t, types.OIDCGroupsConfig{
		Enabled: true,
		Claim:   "groups",
		Domain:  "example.com",
	})

	_, err := b.app.state.SetPolicy([]byte(`{
		"tagOwners": {"tag:eng": ["group:eng@example.com"]},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	// Names are normalised, qualified with the domain, and names qualified
	// with another domain are dropped.
	page, body := b.loginAs(t, groupsUser("Eng", "ops@example.com", "hr@other.example"))
	assert.Equal(t, []string{"eng@example.com", "ops@example.com"}, b.userGroups(t))

	b.confirm(t, page, body)

	var node types.NodeView

	for _, n := range b.app.state.ListNodes().All() {
		if n.User().Email() == groupsUserEmail {
			node = n
		}
	}

	require.True(t, node.Valid(), "the confirmed node must be registered")
	assert.True(t, b.app.state.NodeCanHaveTag(node, "tag:eng"),
		"a member of group:eng@example.com must own the tags the group owns")

	// The next login asserts fewer groups: the dropped one is revoked.
	b.loginAs(t, groupsUser("ops"))
	assert.Equal(t, []string{"ops@example.com"}, b.userGroups(t))
	assert.False(t, b.app.state.NodeCanHaveTag(node, "tag:eng"),
		"removing the group at the identity provider must revoke it at the next login")

	// No groups claim at all clears the remaining memberships.
	b.loginAs(t, groupsUser())
	assert.Empty(t, b.userGroups(t))
}

func TestOIDCLoginIgnoresGroupsWhenDisabled(t *testing.T) {
	b := newOIDCGroupsBrowser(t, types.OIDCGroupsConfig{Claim: "groups", Domain: "example.com"})

	b.loginAs(t, groupsUser("eng"))
	assert.Empty(t, b.userGroups(t))
}

func TestGroupsFromClaims(t *testing.T) {
	provider := &AuthProviderOIDC{cfg: &types.OIDCConfig{Groups: types.OIDCGroupsConfig{
		Enabled: true,
		Claim:   "cognito:groups",
		Domain:  "example.com",
	}}}

	idClaims := map[string]any{"cognito:groups": []any{"FromIDToken"}, "groups": []any{"standard"}}
	infoClaims := map[string]any{"cognito:groups": []any{"FromUserinfo", "bad@other.example"}}

	assert.Equal(t, []string{"fromuserinfo@example.com"}, provider.groupsFromClaims(idClaims, infoClaims),
		"the userinfo response wins when it carries the claim")
	assert.Equal(t, []string{"fromidtoken@example.com"}, provider.groupsFromClaims(idClaims, map[string]any{}),
		"the ID token is used when userinfo lacks the claim")
	assert.Equal(t, []string{"fromidtoken@example.com"}, provider.groupsFromClaims(idClaims, nil),
		"the ID token is used when userinfo is unavailable")
	assert.Empty(t, provider.groupsFromClaims(map[string]any{}, nil))
}

// TestOIDCDeniedLoginRevokesGroups checks that a returning user whom
// authorization rejects, here by leaving allowed_groups, loses the
// memberships their previous login granted, which would otherwise keep
// applying to their other nodes.
func TestOIDCDeniedLoginRevokesGroups(t *testing.T) {
	b := newOIDCBrowserWith(t, "", func(cfg *types.OIDCConfig) {
		cfg.Scope = append(cfg.Scope, "groups")
		cfg.AllowedGroups = []string{"vpn"}
		cfg.Groups = types.OIDCGroupsConfig{Enabled: true, Claim: "groups", Domain: "example.com"}
	})

	b.loginAs(t, groupsUser("vpn", "eng"))
	require.Equal(t, []string{"eng@example.com", "vpn@example.com"}, b.userGroups(t))

	b.idp.QueueUser(groupsUser("eng"))

	_, registerURL := b.pendingNode(t)
	status, _, _ := b.get(t, registerURL)
	require.Equal(t, http.StatusUnauthorized, status, "a user outside allowed_groups must be rejected")

	assert.Empty(t, b.userGroups(t), "a rejected login must revoke the user's groups")
}
