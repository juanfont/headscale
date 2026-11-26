package integration

import (
	"testing"
	"time"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOAuthClientCommand exercises the `headscale api oauth-clients` CLI end to
// end: create (with scopes and tags) -> list (secret hidden) -> get -> delete,
// which revokes the client.
func TestOAuthClientCommand(t *testing.T) {
	IntegrationSkip(t)

	scenario, err := NewScenario(ScenarioSpec{Users: []string{}})
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	// A client may only carry tags the policy defines, as on Tailscale.
	err = scenario.CreateHeadscaleEnv([]tsic.Option{},
		hsic.WithTestName("cli-oauthclient"),
		hsic.WithACLPolicy(&policyv2.Policy{
			TagOwners: policyv2.TagOwners{policyv2.Tag("tag:k8s-operator"): policyv2.Owners{}},
		}),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	// Create an OAuth client with scopes and a tag. devices:core/auth_keys
	// require a tag, which is supplied.
	created := assertJSONRoundtrip[*clientv0.CreatedOAuthClient](t, headscale, []string{
		"headscale", "api", "oauth-clients", "create", "auth_keys,devices:core",
		"--tags", "tag:k8s-operator",
		"--description", "operator",
		"--output", "json",
	})
	assert.NotEmpty(t, created.Id, "client id returned")
	assert.NotEmpty(t, created.Key, "secret returned once on create")
	assert.ElementsMatch(t, []string{"auth_keys", "devices:core"}, created.Scopes)
	assert.Equal(t, []string{"tag:k8s-operator"}, created.Tags)

	// List shows the client without its secret.
	var listed []clientv0.OAuthClient

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err := executeAndUnmarshal(headscale,
			[]string{"headscale", "api", "oauth-clients", "list", "--output", "json"}, &listed)
		assert.NoError(c, err)
		assert.Len(c, listed, 1)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "waiting for oauth client list")

	// The object of a list has no field for the secret.
	assert.Equal(t, created.Id, listed[0].Id)
	assert.ElementsMatch(t, []string{"auth_keys", "devices:core"}, listed[0].Scopes)
	assert.Equal(t, "operator", listed[0].Description)

	var got clientv0.OAuthClient
	require.NoError(t, executeAndUnmarshal(headscale,
		[]string{"headscale", "api", "oauth-clients", "get", created.Id, "--output", "json"}, &got))
	assert.Equal(t, []string{"tag:k8s-operator"}, got.Tags)

	// Delete it: it is revoked, and only the list with --all shows it.
	_, err = headscale.Execute([]string{"headscale", "api", "oauth-clients", "delete", created.Id, "--force"})
	require.NoError(t, err)

	var afterDelete []clientv0.OAuthClient

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err := executeAndUnmarshal(headscale,
			[]string{"headscale", "api", "oauth-clients", "list", "--output", "json"}, &afterDelete)
		assert.NoError(c, err)
		assert.Empty(c, afterDelete)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "waiting for oauth client list after delete")

	var all []clientv0.OAuthClient
	require.NoError(t, executeAndUnmarshal(headscale,
		[]string{"headscale", "api", "oauth-clients", "list", "--all", "--output", "json"}, &all))
	require.Len(t, all, 1)
	assert.Equal(t, clientv0.OAuthClientStateRevoked, all[0].State)
}

// TestOAuthClientCommandValidation covers the CLI's input validation and
// deleting an unknown client.
func TestOAuthClientCommandValidation(t *testing.T) {
	IntegrationSkip(t)

	scenario, err := NewScenario(ScenarioSpec{Users: []string{}})
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cli-oauthclientval"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "no scope", args: []string{"api", "oauth-clients", "create"}, wantErr: "`api oauth-clients create` needs 1 argument, got 0."},
		{name: "devices:core needs tag", args: []string{"api", "oauth-clients", "create", "devices:core"}, wantErr: "scope devices:core needs at least one tag (--tags)."},
		{name: "delete no id", args: []string{"api", "oauth-clients", "delete", "--force"}, wantErr: "`api oauth-clients delete` needs 1 argument, got 0."},
		{name: "delete nonexistent id", args: []string{"api", "oauth-clients", "delete", "doesnotexist", "--force"}, wantErr: `no OAuth client matches "doesnotexist"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := headscale.Execute(append([]string{"headscale"}, tt.args...))
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
