package integration

import (
	"testing"
	"time"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreAuthKeyCommand(t *testing.T) {
	IntegrationSkip(t)

	user := "preauthkeyspace"
	count := 3

	spec := ScenarioSpec{
		Users: []string{user},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	// A key for tags needs tags that the policy names.
	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("clipak"),
		hsic.WithACLPolicy(allowAllWithTagOwners(user, "tag:test1", "tag:test2")),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	keys := make([]*clientv0.CreatedAuthKey, count)

	for index := range count {
		var preAuthKey clientv0.CreatedAuthKey

		err := executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"auth",
				"keys",
				"create",
				"tag:test1,tag:test2",
				"--reusable",
				"--expiry",
				"24h",
				"--output",
				"json",
			},
			&preAuthKey,
		)
		require.NoError(t, err)

		keys[index] = &preAuthKey
	}

	var listedPreAuthKeys []clientv0.AuthKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"auth",
				"keys",
				"list",
				"--output",
				"json",
			},
			&listedPreAuthKeys,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for preauth keys list")

	// There is one key created by [Scenario.CreateHeadscaleEnv]
	assert.Len(t, listedPreAuthKeys, 4)

	assert.Equal(
		t,
		[]string{keys[0].Id, keys[1].Id, keys[2].Id},
		[]string{
			listedPreAuthKeys[1].Id,
			listedPreAuthKeys[2].Id,
			listedPreAuthKeys[3].Id,
		},
	)

	// New keys show prefix after listing, so check the created keys instead
	assert.NotEmpty(t, keys[0].Key)
	assert.NotEmpty(t, keys[1].Key)
	assert.NotEmpty(t, keys[2].Key)

	for _, key := range listedPreAuthKeys[1:] {
		expiry, err := key.Expiry.Get()
		require.NoError(t, err)
		assert.True(t, expiry.After(time.Now()))
		assert.True(t, expiry.Before(time.Now().Add(time.Hour*26)))
	}

	for index := range listedPreAuthKeys {
		if index == 0 {
			continue
		}

		assert.Equal(
			t,
			[]string{"tag:test1", "tag:test2"},
			integrationutil.OwnerTags(listedPreAuthKeys[index].Owner),
		)
	}

	// Revoking a key ends it at once: the list shows it only with --all.
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"auth",
			"keys",
			"delete",
			keys[0].Id,
			"--force",
		},
	)
	require.NoError(t, err)

	var listedPreAuthKeysAfterExpire []clientv0.AuthKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"auth",
				"keys",
				"list",
				"--all",
				"--output",
				"json",
			},
			&listedPreAuthKeysAfterExpire,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for preauth keys list after expire")

	require.Len(t, listedPreAuthKeysAfterExpire, 4)
	assert.Equal(t, clientv0.AuthKeyStateRevoked, listedPreAuthKeysAfterExpire[1].State)
	assert.False(t, listedPreAuthKeysAfterExpire[1].Revoked.IsNull())
	assert.Equal(t, clientv0.AuthKeyStateValid, listedPreAuthKeysAfterExpire[2].State)
	assert.Equal(t, clientv0.AuthKeyStateValid, listedPreAuthKeysAfterExpire[3].State)
}

func TestPreAuthKeyCommandWithoutExpiry(t *testing.T) {
	IntegrationSkip(t)

	user := "pre-auth-key-without-exp-user"
	spec := ScenarioSpec{
		Users: []string{user},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("clipaknaexp"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	var preAuthKey clientv0.CreatedAuthKey

	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"auth",
			"keys",
			"create",
			"1",
			"--reusable",
			"--output",
			"json",
		},
		&preAuthKey,
	)
	require.NoError(t, err)

	var listedPreAuthKeys []clientv0.AuthKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"auth",
				"keys",
				"list",
				"--output",
				"json",
			},
			&listedPreAuthKeys,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for preauth keys list")

	// There is one key created by [Scenario.CreateHeadscaleEnv]
	assert.Len(t, listedPreAuthKeys, 2)

	expiry, err := listedPreAuthKeys[1].Expiry.Get()
	require.NoError(t, err)
	assert.True(t, expiry.After(time.Now()))
	assert.True(t, expiry.Before(time.Now().Add(time.Minute*70)))
}

func TestPreAuthKeyCommandReusableEphemeral(t *testing.T) {
	IntegrationSkip(t)

	user := "pre-auth-key-reus-ephm-user"
	spec := ScenarioSpec{
		Users: []string{user},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("clipakresueeph"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	var preAuthReusableKey clientv0.CreatedAuthKey

	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"auth",
			"keys",
			"create",
			"1",
			"--reusable=true",
			"--output",
			"json",
		},
		&preAuthReusableKey,
	)
	require.NoError(t, err)

	var preAuthEphemeralKey clientv0.CreatedAuthKey

	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"auth",
			"keys",
			"create",
			"1",
			"--ephemeral=true",
			"--output",
			"json",
		},
		&preAuthEphemeralKey,
	)
	require.NoError(t, err)

	assert.True(t, preAuthEphemeralKey.Ephemeral)
	assert.False(t, preAuthEphemeralKey.Reusable)

	var listedPreAuthKeys []clientv0.AuthKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"auth",
				"keys",
				"list",
				"--output",
				"json",
			},
			&listedPreAuthKeys,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for preauth keys list after reusable/ephemeral creation")

	// There is one key created by [Scenario.CreateHeadscaleEnv]
	assert.Len(t, listedPreAuthKeys, 3)
}

// TestPreAuthKeyDeleteCommand covers `auth keys delete` plus its missing
// argument validation: a deleted key is revoked, and the list of keys that
// work no longer shows it.
func TestPreAuthKeyDeleteCommand(t *testing.T) {
	IntegrationSkip(t)

	scenario, headscale := setupCLIScenario(t, "cli-pakdelete", []string{"user1"}, 0)
	defer scenario.ShutdownAssertNoPanics(t)

	// Create a key to delete.
	created := assertJSONRoundtrip[*clientv0.CreatedAuthKey](t, headscale, []string{
		"headscale",
		"auth", "keys", "create", "1",
		"--reusable",
		"--output", "json",
	})
	require.NotEmpty(t, created.Id)

	// delete with no key must be rejected.
	_, err := headscale.Execute([]string{"headscale", "auth", "keys", "delete", "--force"})
	require.ErrorContains(t, err, "`auth keys delete` needs 1 argument, got 0.")

	// delete the created key by id; with -o json it prints the revoked record.
	revoked := assertJSONRoundtrip[*clientv0.AuthKey](t, headscale, []string{
		"headscale", "auth", "keys", "delete", created.Id, "--force", "--output", "json",
	})
	assert.Equal(t, created.Id, revoked.Id)
	assert.Equal(t, clientv0.AuthKeyStateRevoked, revoked.State)

	// The deleted key must be gone from the list.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var listed []clientv0.AuthKey

		err := executeAndUnmarshal(headscale,
			[]string{"headscale", "auth", "keys", "list", "--output", "json"},
			&listed,
		)
		assert.NoError(c, err)

		for i := range listed {
			assert.NotEqual(c, created.Id, listed[i].Id, "deleted key should not be listed")
		}
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for preauth key list after delete")

	// get still finds the revoked record, by its prefix.
	var got clientv0.AuthKey

	err = executeAndUnmarshal(headscale, []string{"headscale", "auth", "keys", "get", created.Prefix, "--output", "json"}, &got)
	require.NoError(t, err)
	assert.Equal(t, clientv0.AuthKeyStateRevoked, got.State)
}

// TestPreAuthKeyCommandValidation covers the validation permutations of the
// auth key subcommands: create for a tag the policy does not name or for a
// user that does not exist, and delete with no key or of a key that does not
// exist.
func TestPreAuthKeyCommandValidation(t *testing.T) {
	IntegrationSkip(t)

	scenario, headscale := setupCLIScenario(t, "cli-pakval", []string{"user1"}, 0)
	defer scenario.ShutdownAssertNoPanics(t)

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "create tag not in policy", args: []string{"auth", "keys", "create", "tag:notinpolicy", "--output", "json"}, wantErr: "these tags are not in the policy: tag:notinpolicy."},
		{name: "create nonexistent user", args: []string{"auth", "keys", "create", "99999", "--output", "json"}, wantErr: `no user matches "99999"`},
		{name: "delete missing key", args: []string{"auth", "keys", "delete", "--force"}, wantErr: "`auth keys delete` needs 1 argument, got 0."},
		{name: "delete nonexistent key", args: []string{"auth", "keys", "delete", "99999", "--force"}, wantErr: `no auth key matches "99999"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := headscale.Execute(append([]string{"headscale"}, tt.args...))
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
