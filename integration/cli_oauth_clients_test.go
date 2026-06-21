package integration

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cliOAuthClient is the JSON the `oauth-clients` commands emit (the v2 Key shape,
// only the fields the test asserts on).
type cliOAuthClient struct {
	ID          string   `json:"id"`
	Key         string   `json:"key"`
	KeyType     string   `json:"keyType"`
	Scopes      []string `json:"scopes"`
	Tags        []string `json:"tags"`
	Description string   `json:"description"`
}

// TestOAuthClientCommand exercises the `headscale oauth-clients` CLI end to end:
// create (with scopes and tags) -> list (secret hidden) -> delete. The CLI talks
// to the v2 keys handler over the local unix socket, so this also proves the v2
// API is reachable over the socket with local trust.
func TestOAuthClientCommand(t *testing.T) {
	IntegrationSkip(t)

	scenario, err := NewScenario(ScenarioSpec{Users: []string{}})
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cli-oauthclient"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	// Create an OAuth client with scopes and a tag. devices:core/auth_keys
	// require a tag, which is supplied.
	createOut, err := headscale.Execute([]string{
		"headscale", "oauth-clients", "create",
		"--scope", "auth_keys",
		"--scope", "devices:core",
		"--tag", "tag:k8s-operator",
		"--description", "operator",
		"--output", "json",
	})
	require.NoError(t, err)

	var created cliOAuthClient
	require.NoError(t, json.Unmarshal([]byte(createOut), &created))
	assert.Equal(t, "client", created.KeyType)
	assert.NotEmpty(t, created.ID, "client id returned")
	assert.NotEmpty(t, created.Key, "secret returned once on create")
	assert.ElementsMatch(t, []string{"auth_keys", "devices:core"}, created.Scopes)
	assert.Equal(t, []string{"tag:k8s-operator"}, created.Tags)

	// List shows the client without its secret.
	var listed []cliOAuthClient

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err := executeAndUnmarshal(headscale,
			[]string{"headscale", "oauth-clients", "list", "--output", "json"}, &listed)
		assert.NoError(c, err)
		assert.Len(c, listed, 1)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "waiting for oauth client list")

	assert.Equal(t, created.ID, listed[0].ID)
	assert.Empty(t, listed[0].Key, "secret is never exposed on list")
	assert.ElementsMatch(t, []string{"auth_keys", "devices:core"}, listed[0].Scopes)
	assert.Equal(t, "operator", listed[0].Description)

	// Delete it.
	_, err = headscale.Execute([]string{"headscale", "oauth-clients", "delete", "--id", created.ID})
	require.NoError(t, err)

	var afterDelete []cliOAuthClient

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err := executeAndUnmarshal(headscale,
			[]string{"headscale", "oauth-clients", "list", "--output", "json"}, &afterDelete)
		assert.NoError(c, err)
		assert.Empty(c, afterDelete)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "waiting for oauth client list after delete")
}

// TestOAuthClientCommandValidation covers the CLI's input validation and the
// server's 404 on deleting an unknown client.
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
		{name: "no scope", args: []string{"oauth-clients", "create"}, wantErr: "at least one --scope is required"},
		{name: "devices:core needs tag", args: []string{"oauth-clients", "create", "--scope", "devices:core"}, wantErr: "tags are required"},
		{name: "delete no id", args: []string{"oauth-clients", "delete"}, wantErr: "--id is required"},
		{name: "delete nonexistent id", args: []string{"oauth-clients", "delete", "--id", "doesnotexist"}, wantErr: "404"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := headscale.Execute(append([]string{"headscale"}, tt.args...))
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
