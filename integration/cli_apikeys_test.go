package integration

import (
	"strconv"
	"testing"
	"time"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApiKeyCommand(t *testing.T) {
	IntegrationSkip(t)

	count := 5

	spec := ScenarioSpec{
		Users: []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cli-apikey"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	keys := make([]*clientv0.CreatedAPIKey, count)

	for idx := range count {
		var key clientv0.CreatedAPIKey

		err := executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"api",
				"keys",
				"create",
				"--expiry",
				"24h",
				"--output",
				"json",
			},
			&key,
		)
		require.NoError(t, err)
		assert.NotEmpty(t, key.Key)

		keys[idx] = &key
	}

	listAPIKeys := func(all bool) []clientv0.APIKey {
		command := []string{"headscale", "api", "keys", "list", "--output", "json"}
		if all {
			command = append(command, "--all")
		}

		var listed []clientv0.APIKey

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			err := executeAndUnmarshal(headscale, command, &listed)
			assert.NoError(c, err)
		}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for API keys list")

		return listed
	}

	listedAPIKeys := listAPIKeys(false)
	require.Len(t, listedAPIKeys, 5)

	// IDs are drawn from the shared credentials table, so they are not
	// guaranteed to start at 1 (pre-auth keys created during env setup take the
	// first ids). They are still listed in strictly increasing creation order.
	var prevID uint64

	for i, key := range listedAPIKeys {
		id, err := strconv.ParseUint(key.Id, 10, 64)
		require.NoError(t, err)
		assert.Greater(t, id, prevID, "API key ids must be strictly increasing")
		prevID = id

		assert.Equal(t, keys[i].Id, key.Id)
		assert.NotEmpty(t, key.Prefix)

		expiry, err := key.Expiry.Get()
		require.NoError(t, err)
		assert.True(t, expiry.After(time.Now()))
		assert.True(t, expiry.Before(time.Now().Add(time.Hour*26)))
	}

	// Revoke three keys by prefix: they stop working at once, and the list of
	// keys that work no longer shows them.
	revokedIDs := make(map[string]bool)

	for idx := range 3 {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"api",
				"keys",
				"delete",
				listedAPIKeys[idx].Prefix,
				"--force",
			},
		)
		require.NoError(t, err)

		revokedIDs[listedAPIKeys[idx].Id] = true
	}

	assert.Len(t, listAPIKeys(false), 2)

	listedAfterRevoke := listAPIKeys(true)
	assert.Len(t, listedAfterRevoke, 5)

	for _, key := range listedAfterRevoke {
		if revokedIDs[key.Id] {
			assert.Equal(t, clientv0.APIKeyStateRevoked, key.State)
			assert.False(t, key.Revoked.IsNull())
		} else {
			assert.Equal(t, clientv0.APIKeyStateValid, key.State)
		}
	}

	// Revoke by ID.
	deletedKeyID := listedAPIKeys[3].Id
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"api",
			"keys",
			"delete",
			deletedKeyID,
			"--force",
		})
	require.NoError(t, err)

	listedAfterDeleteByID := listAPIKeys(false)
	require.Len(t, listedAfterDeleteByID, 1)
	assert.Equal(t, listedAPIKeys[4].Id, listedAfterDeleteByID[0].Id)

	// get finds a revoked key too.
	var got clientv0.APIKey

	err = executeAndUnmarshal(headscale, []string{"headscale", "api", "keys", "get", deletedKeyID, "--output", "json"}, &got)
	require.NoError(t, err)
	assert.Equal(t, clientv0.APIKeyStateRevoked, got.State)
}

// TestApiKeyCommandValidation covers the validation permutations of `api keys
// create` and `api keys delete`: an invalid --expiry, no key, and a key that
// does not exist by prefix or by ID.
func TestApiKeyCommandValidation(t *testing.T) {
	IntegrationSkip(t)

	scenario, headscale := setupCLIScenario(t, "cli-apikeyval", []string{"user1"}, 0)
	defer scenario.ShutdownAssertNoPanics(t)

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "create invalid expiry", args: []string{"api", "keys", "create", "--expiry", "not-a-duration"}, wantErr: `"not-a-duration" is not a valid --expiry`},
		{name: "delete missing key", args: []string{"api", "keys", "delete", "--force"}, wantErr: "`api keys delete` needs 1 argument, got 0."},
		{name: "delete nonexistent prefix", args: []string{"api", "keys", "delete", "nonexistent", "--force"}, wantErr: `no API key matches "nonexistent"`},
		{name: "delete nonexistent id", args: []string{"api", "keys", "delete", "99999", "--force"}, wantErr: `no API key matches "99999"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := headscale.Execute(append([]string{"headscale"}, tt.args...))
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
