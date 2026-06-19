package integration

import (
	"testing"
	"time"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
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

	keys := make([]string, count)

	for idx := range count {
		apiResult, err := headscale.Execute(
			[]string{
				"headscale",
				"apikeys",
				"create",
				"--expiration",
				"24h",
				"--output",
				"json",
			},
		)
		require.NoError(t, err)
		assert.NotEmpty(t, apiResult)

		keys[idx] = apiResult
	}

	assert.Len(t, keys, 5)

	var listedAPIKeys []clientv1.ApiKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"apikeys",
				"list",
				"--output",
				"json",
			},
			&listedAPIKeys,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for API keys list")

	assert.Len(t, listedAPIKeys, 5)

	assert.Equal(t, "1", listedAPIKeys[0].Id)
	assert.Equal(t, "2", listedAPIKeys[1].Id)
	assert.Equal(t, "3", listedAPIKeys[2].Id)
	assert.Equal(t, "4", listedAPIKeys[3].Id)
	assert.Equal(t, "5", listedAPIKeys[4].Id)

	assert.NotEmpty(t, listedAPIKeys[0].Prefix)
	assert.NotEmpty(t, listedAPIKeys[1].Prefix)
	assert.NotEmpty(t, listedAPIKeys[2].Prefix)
	assert.NotEmpty(t, listedAPIKeys[3].Prefix)
	assert.NotEmpty(t, listedAPIKeys[4].Prefix)

	assert.True(t, listedAPIKeys[0].Expiration.After(time.Now()))
	assert.True(t, listedAPIKeys[1].Expiration.After(time.Now()))
	assert.True(t, listedAPIKeys[2].Expiration.After(time.Now()))
	assert.True(t, listedAPIKeys[3].Expiration.After(time.Now()))
	assert.True(t, listedAPIKeys[4].Expiration.After(time.Now()))

	assert.True(
		t,
		listedAPIKeys[0].Expiration.Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedAPIKeys[1].Expiration.Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedAPIKeys[2].Expiration.Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedAPIKeys[3].Expiration.Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedAPIKeys[4].Expiration.Before(time.Now().Add(time.Hour*26)),
	)

	expiredPrefixes := make(map[string]bool)

	// Expire three keys
	for idx := range 3 {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"apikeys",
				"expire",
				"--prefix",
				listedAPIKeys[idx].Prefix,
			},
		)
		require.NoError(t, err)

		expiredPrefixes[listedAPIKeys[idx].Prefix] = true
	}

	var listedAfterExpireAPIKeys []clientv1.ApiKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"apikeys",
				"list",
				"--output",
				"json",
			},
			&listedAfterExpireAPIKeys,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for API keys list after expire")

	for index := range listedAfterExpireAPIKeys {
		if _, ok := expiredPrefixes[listedAfterExpireAPIKeys[index].Prefix]; ok {
			// Expired
			assert.True(
				t,
				listedAfterExpireAPIKeys[index].Expiration.Before(time.Now()),
			)
		} else {
			// Not expired
			assert.False(
				t,
				listedAfterExpireAPIKeys[index].Expiration.Before(time.Now()),
			)
		}
	}

	_, err = headscale.Execute(
		[]string{
			"headscale",
			"apikeys",
			"delete",
			"--prefix",
			listedAPIKeys[0].Prefix,
		})
	require.NoError(t, err)

	var listedAPIKeysAfterDelete []clientv1.ApiKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"apikeys",
				"list",
				"--output",
				"json",
			},
			&listedAPIKeysAfterDelete,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for API keys list after delete")

	assert.Len(t, listedAPIKeysAfterDelete, 4)

	// Test expire by ID (using key at index 0)
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"apikeys",
			"expire",
			"--id",
			listedAPIKeysAfterDelete[0].Id,
		})
	require.NoError(t, err)

	var listedAPIKeysAfterExpireByID []clientv1.ApiKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"apikeys",
				"list",
				"--output",
				"json",
			},
			&listedAPIKeysAfterExpireByID,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for API keys list after expire by ID")

	// Verify the key was expired
	for idx := range listedAPIKeysAfterExpireByID {
		if listedAPIKeysAfterExpireByID[idx].Id == listedAPIKeysAfterDelete[0].Id {
			assert.True(t, listedAPIKeysAfterExpireByID[idx].Expiration.Before(time.Now()),
				"Key expired by ID should have expiration in the past")
		}
	}

	// Test delete by ID (using key at index 1)
	deletedKeyID := listedAPIKeysAfterExpireByID[1].Id
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"apikeys",
			"delete",
			"--id",
			deletedKeyID,
		})
	require.NoError(t, err)

	var listedAPIKeysAfterDeleteByID []clientv1.ApiKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"apikeys",
				"list",
				"--output",
				"json",
			},
			&listedAPIKeysAfterDeleteByID,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for API keys list after delete by ID")

	assert.Len(t, listedAPIKeysAfterDeleteByID, 3)

	// Verify the specific key was deleted
	for idx := range listedAPIKeysAfterDeleteByID {
		assert.NotEqual(t, deletedKeyID, listedAPIKeysAfterDeleteByID[idx].Id,
			"Deleted key should not be present in the list")
	}
}

// TestApiKeyCommandValidation covers the validation permutations of
// `apikeys expire` and `apikeys delete`: the mutually-exclusive --id/--prefix
// flags (neither / both), a non-existent prefix, and an invalid --expiration on
// create. A real key is created so the "both flags" path has a valid prefix.
func TestApiKeyCommandValidation(t *testing.T) {
	IntegrationSkip(t)

	scenario, headscale := setupCLIScenario(t, "cli-apikeyval", []string{"user1"}, 0)
	defer scenario.ShutdownAssertNoPanics(t)

	// Create a real key so a valid prefix exists. `apikeys create` prints the
	// raw secret, not JSON of the key, so list to discover the prefix.
	_, err := headscale.Execute([]string{"headscale", "apikeys", "create", "--output", "json"})
	require.NoError(t, err)

	var listed []clientv1.ApiKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err := executeAndUnmarshal(headscale,
			[]string{"headscale", "apikeys", "list", "--output", "json"},
			&listed,
		)
		assert.NoError(c, err)
		assert.Len(c, listed, 1)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for API key list")

	prefix := listed[0].Prefix
	id := listed[0].Id

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "create invalid expiration", args: []string{"apikeys", "create", "--expiration", "not-a-duration"}},
		{name: "expire neither selector", args: []string{"apikeys", "expire"}, wantErr: "either --id or --prefix must be provided"},
		{name: "expire both selectors", args: []string{"apikeys", "expire", "--id", id, "--prefix", prefix}, wantErr: "only one of --id or --prefix can be provided"},
		{name: "expire nonexistent prefix", args: []string{"apikeys", "expire", "--prefix", "nonexistent"}},
		{name: "delete neither selector", args: []string{"apikeys", "delete"}, wantErr: "either --id or --prefix must be provided"},
		{name: "delete both selectors", args: []string{"apikeys", "delete", "--id", id, "--prefix", prefix}, wantErr: "only one of --id or --prefix can be provided"},
		{name: "delete nonexistent id", args: []string{"apikeys", "delete", "--id", "99999"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := headscale.Execute(append([]string{"headscale"}, tt.args...))
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.Error(t, err)
		})
	}
}
