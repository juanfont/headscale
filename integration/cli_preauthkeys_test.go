package integration

import (
	"strconv"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
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

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("clipak"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	keys := make([]*v1.PreAuthKey, count)

	require.NoError(t, err)

	for index := range count {
		var preAuthKey v1.PreAuthKey

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			err := executeAndUnmarshal(
				headscale,
				[]string{
					"headscale",
					"preauthkeys",
					"--user",
					"1",
					"create",
					"--reusable",
					"--expiration",
					"24h",
					"--output",
					"json",
					"--tags",
					"tag:test1,tag:test2",
				},
				&preAuthKey,
			)
			assert.NoError(c, err)
		}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for preauth key creation")

		keys[index] = &preAuthKey
	}

	assert.Len(t, keys, 3)

	var listedPreAuthKeys []v1.PreAuthKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"preauthkeys",
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
		[]uint64{keys[0].GetId(), keys[1].GetId(), keys[2].GetId()},
		[]uint64{
			listedPreAuthKeys[1].GetId(),
			listedPreAuthKeys[2].GetId(),
			listedPreAuthKeys[3].GetId(),
		},
	)

	// New keys show prefix after listing, so check the created keys instead
	assert.NotEmpty(t, keys[0].GetKey())
	assert.NotEmpty(t, keys[1].GetKey())
	assert.NotEmpty(t, keys[2].GetKey())

	assert.True(t, listedPreAuthKeys[1].GetExpiration().AsTime().After(time.Now()))
	assert.True(t, listedPreAuthKeys[2].GetExpiration().AsTime().After(time.Now()))
	assert.True(t, listedPreAuthKeys[3].GetExpiration().AsTime().After(time.Now()))

	assert.True(
		t,
		listedPreAuthKeys[1].GetExpiration().AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedPreAuthKeys[2].GetExpiration().AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedPreAuthKeys[3].GetExpiration().AsTime().Before(time.Now().Add(time.Hour*26)),
	)

	for index := range listedPreAuthKeys {
		if index == 0 {
			continue
		}

		assert.Equal(
			t,
			[]string{"tag:test1", "tag:test2"},
			listedPreAuthKeys[index].GetAclTags(),
		)
	}

	// Test key expiry
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"preauthkeys",
			"expire",
			"--id",
			strconv.FormatUint(keys[0].GetId(), 10),
		},
	)
	require.NoError(t, err)

	var listedPreAuthKeysAfterExpire []v1.PreAuthKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"preauthkeys",
				"list",
				"--output",
				"json",
			},
			&listedPreAuthKeysAfterExpire,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for preauth keys list after expire")

	assert.True(t, listedPreAuthKeysAfterExpire[1].GetExpiration().AsTime().Before(time.Now()))
	assert.True(t, listedPreAuthKeysAfterExpire[2].GetExpiration().AsTime().After(time.Now()))
	assert.True(t, listedPreAuthKeysAfterExpire[3].GetExpiration().AsTime().After(time.Now()))
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

	var preAuthKey v1.PreAuthKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"preauthkeys",
				"--user",
				"1",
				"create",
				"--reusable",
				"--output",
				"json",
			},
			&preAuthKey,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for preauth key creation without expiry")

	var listedPreAuthKeys []v1.PreAuthKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"preauthkeys",
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

	assert.True(t, listedPreAuthKeys[1].GetExpiration().AsTime().After(time.Now()))
	assert.True(
		t,
		listedPreAuthKeys[1].GetExpiration().AsTime().Before(time.Now().Add(time.Minute*70)),
	)
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

	var preAuthReusableKey v1.PreAuthKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"preauthkeys",
				"--user",
				"1",
				"create",
				"--reusable=true",
				"--output",
				"json",
			},
			&preAuthReusableKey,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for reusable preauth key creation")

	var preAuthEphemeralKey v1.PreAuthKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"preauthkeys",
				"--user",
				"1",
				"create",
				"--ephemeral=true",
				"--output",
				"json",
			},
			&preAuthEphemeralKey,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for ephemeral preauth key creation")

	assert.True(t, preAuthEphemeralKey.GetEphemeral())
	assert.False(t, preAuthEphemeralKey.GetReusable())

	var listedPreAuthKeys []v1.PreAuthKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"preauthkeys",
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

// TestPreAuthKeyDeleteCommand covers `preauthkeys delete --id` (the only
// pre-auth-key subcommand not otherwise exercised) plus its missing-flag
// validation.
func TestPreAuthKeyDeleteCommand(t *testing.T) {
	IntegrationSkip(t)

	scenario, headscale := setupCLIScenario(t, "cli-pakdelete", []string{"user1"}, 0)
	defer scenario.ShutdownAssertNoPanics(t)

	// Create a key to delete.
	created := assertJSONRoundtrip[*v1.PreAuthKey](t, headscale, []string{
		"headscale",
		"preauthkeys",
		"--user", "1",
		"create",
		"--reusable",
		"--output", "json",
	})
	require.NotZero(t, created.GetId())

	// delete with no --id must be rejected.
	_, err := headscale.Execute([]string{"headscale", "preauthkeys", "delete"})
	require.ErrorContains(t, err, "missing --id parameter")

	// delete the created key by id.
	_, err = headscale.Execute([]string{
		"headscale", "preauthkeys", "delete",
		"--id", strconv.FormatUint(created.GetId(), 10),
	})
	require.NoError(t, err)

	// The deleted key must be gone from the list.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		var listed []v1.PreAuthKey

		err := executeAndUnmarshal(headscale,
			[]string{"headscale", "preauthkeys", "list", "--output", "json"},
			&listed,
		)
		assert.NoError(c, err)

		for i := range listed {
			assert.NotEqual(c, created.GetId(), listed[i].GetId(), "deleted key should not be listed")
		}
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for preauth key list after delete")
}

// TestPreAuthKeyCommandValidation covers the validation permutations of the
// pre-auth-key subcommands: create with a malformed tag or a non-existent user,
// the required --id on expire/delete, and deleting a non-existent key.
func TestPreAuthKeyCommandValidation(t *testing.T) {
	IntegrationSkip(t)

	scenario, headscale := setupCLIScenario(t, "cli-pakval", []string{"user1"}, 0)
	defer scenario.ShutdownAssertNoPanics(t)

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "create malformed tag", args: []string{"preauthkeys", "--user", "1", "create", "--tags", "notatag", "--output", "json"}},
		{name: "create nonexistent user", args: []string{"preauthkeys", "--user", "99999", "create", "--output", "json"}},
		{name: "expire missing id", args: []string{"preauthkeys", "expire"}, wantErr: "missing --id parameter"},
		{name: "delete missing id", args: []string{"preauthkeys", "delete"}, wantErr: "missing --id parameter"},
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
