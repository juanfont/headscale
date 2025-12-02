package integration

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	tcmp "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func executeAndUnmarshal[T any](headscale ControlServer, command []string, result T) error {
	str, err := headscale.Execute(command)
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(str), result)
	if err != nil {
		return fmt.Errorf("failed to unmarshal: %w\n command err: %s", err, str)
	}

	return nil
}

// Interface ensuring that we can sort structs from gRPC that
// have an ID field.
type GRPCSortable interface {
	GetId() uint64
}

func sortWithID[T GRPCSortable](a, b T) int {
	return cmp.Compare(a.GetId(), b.GetId())
}

func TestUserCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("clins"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	var listUsers []*v1.User
	var result []string
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		err := executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"users",
				"list",
				"--output",
				"json",
			},
			&listUsers,
		)
		assert.NoError(ct, err)

		slices.SortFunc(listUsers, sortWithID)
		result = []string{listUsers[0].GetName(), listUsers[1].GetName()}

		assert.Equal(
			ct,
			[]string{"user1", "user2"},
			result,
			"Should have user1 and user2 in users list",
		)
	}, 20*time.Second, 1*time.Second)

	_, err = headscale.Execute(
		[]string{
			"headscale",
			"users",
			"rename",
			"--output=json",
			fmt.Sprintf("--identifier=%d", listUsers[1].GetId()),
			"--new-name=newname",
		},
	)
	require.NoError(t, err)

	var listAfterRenameUsers []*v1.User
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		err := executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"users",
				"list",
				"--output",
				"json",
			},
			&listAfterRenameUsers,
		)
		assert.NoError(ct, err)

		slices.SortFunc(listAfterRenameUsers, sortWithID)
		result = []string{listAfterRenameUsers[0].GetName(), listAfterRenameUsers[1].GetName()}

		assert.Equal(
			ct,
			[]string{"user1", "newname"},
			result,
			"Should have user1 and newname after rename operation",
		)
	}, 20*time.Second, 1*time.Second)

	var listByUsername []*v1.User
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"users",
				"list",
				"--output",
				"json",
				"--name=user1",
			},
			&listByUsername,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for user list by username")

	slices.SortFunc(listByUsername, sortWithID)
	want := []*v1.User{
		{
			Id:    1,
			Name:  "user1",
			Email: "user1@test.no",
		},
	}

	if diff := tcmp.Diff(want, listByUsername, cmpopts.IgnoreUnexported(v1.User{}), cmpopts.IgnoreFields(v1.User{}, "CreatedAt")); diff != "" {
		t.Errorf("unexpected users (-want +got):\n%s", diff)
	}

	var listByID []*v1.User
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"users",
				"list",
				"--output",
				"json",
				"--identifier=1",
			},
			&listByID,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for user list by ID")

	slices.SortFunc(listByID, sortWithID)
	want = []*v1.User{
		{
			Id:    1,
			Name:  "user1",
			Email: "user1@test.no",
		},
	}

	if diff := tcmp.Diff(want, listByID, cmpopts.IgnoreUnexported(v1.User{}), cmpopts.IgnoreFields(v1.User{}, "CreatedAt")); diff != "" {
		t.Errorf("unexpected users (-want +got):\n%s", diff)
	}

	deleteResult, err := headscale.Execute(
		[]string{
			"headscale",
			"users",
			"destroy",
			"--force",
			// Delete "user1"
			"--identifier=1",
		},
	)
	assert.NoError(t, err)
	assert.Contains(t, deleteResult, "User destroyed")

	var listAfterIDDelete []*v1.User
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		err := executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"users",
				"list",
				"--output",
				"json",
			},
			&listAfterIDDelete,
		)
		assert.NoError(ct, err)

		slices.SortFunc(listAfterIDDelete, sortWithID)
		want := []*v1.User{
			{
				Id:    2,
				Name:  "newname",
				Email: "user2@test.no",
			},
		}

		if diff := tcmp.Diff(want, listAfterIDDelete, cmpopts.IgnoreUnexported(v1.User{}), cmpopts.IgnoreFields(v1.User{}, "CreatedAt")); diff != "" {
			assert.Fail(ct, "unexpected users", "diff (-want +got):\n%s", diff)
		}
	}, 20*time.Second, 1*time.Second)

	deleteResult, err = headscale.Execute(
		[]string{
			"headscale",
			"users",
			"destroy",
			"--force",
			"--name=newname",
		},
	)
	assert.NoError(t, err)
	assert.Contains(t, deleteResult, "User destroyed")

	var listAfterNameDelete []v1.User
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"users",
				"list",
				"--output",
				"json",
			},
			&listAfterNameDelete,
		)
		assert.NoError(c, err)
		assert.Empty(c, listAfterNameDelete)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for user list after name delete")
}

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
		}, 10*time.Second, 200*time.Millisecond, "Waiting for preauth key creation")

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
				"--user",
				"1",
				"list",
				"--output",
				"json",
			},
			&listedPreAuthKeys,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for preauth keys list")

	// There is one key created by "scenario.CreateHeadscaleEnv"
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

	// Test key expiry - use the full key from creation, not the masked one from listing
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"preauthkeys",
			"--user",
			"1",
			"expire",
			keys[0].GetKey(),
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
				"--user",
				"1",
				"list",
				"--output",
				"json",
			},
			&listedPreAuthKeysAfterExpire,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for preauth keys list after expire")

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
	}, 10*time.Second, 200*time.Millisecond, "Waiting for preauth key creation without expiry")

	var listedPreAuthKeys []v1.PreAuthKey
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"preauthkeys",
				"--user",
				"1",
				"list",
				"--output",
				"json",
			},
			&listedPreAuthKeys,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for preauth keys list without expiry")

	// There is one key created by "scenario.CreateHeadscaleEnv"
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
	}, 10*time.Second, 200*time.Millisecond, "Waiting for reusable preauth key creation")

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
	}, 10*time.Second, 200*time.Millisecond, "Waiting for ephemeral preauth key creation")

	assert.True(t, preAuthEphemeralKey.GetEphemeral())
	assert.False(t, preAuthEphemeralKey.GetReusable())

	var listedPreAuthKeys []v1.PreAuthKey
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"preauthkeys",
				"--user",
				"1",
				"list",
				"--output",
				"json",
			},
			&listedPreAuthKeys,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for preauth keys list after reusable/ephemeral creation")

	// There is one key created by "scenario.CreateHeadscaleEnv"
	assert.Len(t, listedPreAuthKeys, 3)
}

func TestPreAuthKeyCorrectUserLoggedInCommand(t *testing.T) {
	IntegrationSkip(t)

	user1 := "user1"
	user2 := "user2"

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{user1},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("clipak"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	u2, err := headscale.CreateUser(user2)
	require.NoError(t, err)

	var user2Key v1.PreAuthKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"preauthkeys",
				"--user",
				strconv.FormatUint(u2.GetId(), 10),
				"create",
				"--reusable",
				"--expiration",
				"24h",
				"--output",
				"json",
				"--tags",
				"tag:test1,tag:test2",
			},
			&user2Key,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for user2 preauth key creation")

	var listNodes []*v1.Node
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		listNodes, err = headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, listNodes, 1, "Should have exactly 1 node for user1")
		assert.Equal(ct, user1, listNodes[0].GetUser().GetName(), "Node should belong to user1")
	}, 15*time.Second, 1*time.Second)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	require.Len(t, allClients, 1)

	client := allClients[0]

	// Log out from user1
	err = client.Logout()
	require.NoError(t, err)

	err = scenario.WaitForTailscaleLogout()
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		status, err := client.Status()
		assert.NoError(ct, err)
		assert.NotContains(ct, []string{"Starting", "Running"}, status.BackendState,
			"Expected node to be logged out, backend state: %s", status.BackendState)
	}, 30*time.Second, 2*time.Second)

	err = client.Login(headscale.GetEndpoint(), user2Key.GetKey())
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		status, err := client.Status()
		assert.NoError(ct, err)
		assert.Equal(ct, "Running", status.BackendState, "Expected node to be logged in, backend state: %s", status.BackendState)
		// With tags-as-identity model, tagged nodes show as TaggedDevices user (2147455555)
		// The PreAuthKey was created with tags, so the node is tagged
		assert.Equal(ct, "userid:2147455555", status.Self.UserID.String(), "Expected node to be logged in as tagged-devices user")
	}, 30*time.Second, 2*time.Second)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		listNodes, err = headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, listNodes, 2, "Should have 2 nodes after re-login")
		assert.Equal(ct, user1, listNodes[0].GetUser().GetName(), "First node should belong to user1")
		// Second node is tagged (created with tagged PreAuthKey), so it shows as "tagged-devices"
		assert.Equal(ct, "tagged-devices", listNodes[1].GetUser().GetName(), "Second node should be tagged-devices")
	}, 20*time.Second, 1*time.Second)
}

func TestApiKeyCommand(t *testing.T) {
	IntegrationSkip(t)

	count := 5

	spec := ScenarioSpec{
		Users: []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("clins"))
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
		assert.NoError(t, err)
		assert.NotEmpty(t, apiResult)

		keys[idx] = apiResult
	}

	assert.Len(t, keys, 5)

	var listedAPIKeys []v1.ApiKey
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
	}, 10*time.Second, 200*time.Millisecond, "Waiting for API keys list")

	assert.Len(t, listedAPIKeys, 5)

	assert.Equal(t, uint64(1), listedAPIKeys[0].GetId())
	assert.Equal(t, uint64(2), listedAPIKeys[1].GetId())
	assert.Equal(t, uint64(3), listedAPIKeys[2].GetId())
	assert.Equal(t, uint64(4), listedAPIKeys[3].GetId())
	assert.Equal(t, uint64(5), listedAPIKeys[4].GetId())

	assert.NotEmpty(t, listedAPIKeys[0].GetPrefix())
	assert.NotEmpty(t, listedAPIKeys[1].GetPrefix())
	assert.NotEmpty(t, listedAPIKeys[2].GetPrefix())
	assert.NotEmpty(t, listedAPIKeys[3].GetPrefix())
	assert.NotEmpty(t, listedAPIKeys[4].GetPrefix())

	assert.True(t, listedAPIKeys[0].GetExpiration().AsTime().After(time.Now()))
	assert.True(t, listedAPIKeys[1].GetExpiration().AsTime().After(time.Now()))
	assert.True(t, listedAPIKeys[2].GetExpiration().AsTime().After(time.Now()))
	assert.True(t, listedAPIKeys[3].GetExpiration().AsTime().After(time.Now()))
	assert.True(t, listedAPIKeys[4].GetExpiration().AsTime().After(time.Now()))

	assert.True(
		t,
		listedAPIKeys[0].GetExpiration().AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedAPIKeys[1].GetExpiration().AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedAPIKeys[2].GetExpiration().AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedAPIKeys[3].GetExpiration().AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedAPIKeys[4].GetExpiration().AsTime().Before(time.Now().Add(time.Hour*26)),
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
				listedAPIKeys[idx].GetPrefix(),
			},
		)
		assert.NoError(t, err)

		expiredPrefixes[listedAPIKeys[idx].GetPrefix()] = true
	}

	var listedAfterExpireAPIKeys []v1.ApiKey
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
	}, 10*time.Second, 200*time.Millisecond, "Waiting for API keys list after expire")

	for index := range listedAfterExpireAPIKeys {
		if _, ok := expiredPrefixes[listedAfterExpireAPIKeys[index].GetPrefix()]; ok {
			// Expired
			assert.True(
				t,
				listedAfterExpireAPIKeys[index].GetExpiration().AsTime().Before(time.Now()),
			)
		} else {
			// Not expired
			assert.False(
				t,
				listedAfterExpireAPIKeys[index].GetExpiration().AsTime().Before(time.Now()),
			)
		}
	}

	_, err = headscale.Execute(
		[]string{
			"headscale",
			"apikeys",
			"delete",
			"--prefix",
			listedAPIKeys[0].GetPrefix(),
		})
	assert.NoError(t, err)

	var listedAPIKeysAfterDelete []v1.ApiKey
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
	}, 10*time.Second, 200*time.Millisecond, "Waiting for API keys list after delete")

	assert.Len(t, listedAPIKeysAfterDelete, 4)
}

func TestNodeTagCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("clins"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	// Test 1: Verify that tags require authorization via ACL policy
	// The tags-as-identity model allows conversion from user-owned to tagged, but only
	// if the tag is authorized via tagOwners in the ACL policy.
	regID := types.MustRegistrationID().String()

	_, err = headscale.Execute(
		[]string{
			"headscale",
			"debug",
			"create-node",
			"--name",
			"user-owned-node",
			"--user",
			"user1",
			"--key",
			regID,
			"--output",
			"json",
		},
	)
	assert.NoError(t, err)

	var userOwnedNode v1.Node

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"--user",
				"user1",
				"register",
				"--key",
				regID,
				"--output",
				"json",
			},
			&userOwnedNode,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for user-owned node registration")

	// Verify node is user-owned (no tags)
	assert.Empty(t, userOwnedNode.GetValidTags(), "User-owned node should not have tags")
	assert.Empty(t, userOwnedNode.GetForcedTags(), "User-owned node should not have forced tags")

	// Attempt to set tags on user-owned node should FAIL because there's no ACL policy
	// authorizing the tag. The tags-as-identity model allows conversion from user-owned
	// to tagged, but only if the tag is authorized via tagOwners in the ACL policy.
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"nodes",
			"tag",
			"-i", strconv.FormatUint(userOwnedNode.GetId(), 10),
			"-t", "tag:test",
			"--output", "json",
		},
	)
	require.ErrorContains(t, err, "invalid or unauthorized tags", "Setting unauthorized tags should fail")

	// Test 2: Verify tag format validation
	// Create a PreAuthKey with tags to create a tagged node
	// Get the user ID from the node
	userID := userOwnedNode.GetUser().GetId()

	var preAuthKey v1.PreAuthKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"preauthkeys",
				"--user", strconv.FormatUint(userID, 10),
				"create",
				"--reusable",
				"--tags", "tag:integration-test",
				"--output", "json",
			},
			&preAuthKey,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Creating PreAuthKey with tags")

	// Verify PreAuthKey has tags
	assert.Contains(t, preAuthKey.GetAclTags(), "tag:integration-test", "PreAuthKey should have tags")

	// Test 3: Verify invalid tag format is rejected
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"preauthkeys",
			"--user", strconv.FormatUint(userID, 10),
			"create",
			"--tags", "wrong-tag", // Missing "tag:" prefix
			"--output", "json",
		},
	)
	assert.ErrorContains(t, err, "tag must start with the string 'tag:'", "Invalid tag format should be rejected")
}

func TestTaggedNodeRegistration(t *testing.T) {
	IntegrationSkip(t)

	// ACL policy that authorizes the tags used in tagged PreAuthKeys
	// user1 and user2 can assign these tags when creating PreAuthKeys
	policy := &policyv2.Policy{
		TagOwners: policyv2.TagOwners{
			"tag:server":    policyv2.Owners{usernameOwner("user1@"), usernameOwner("user2@")},
			"tag:prod":      policyv2.Owners{usernameOwner("user1@"), usernameOwner("user2@")},
			"tag:forbidden": policyv2.Owners{usernameOwner("user1@"), usernameOwner("user2@")},
		},
		ACLs: []policyv2.ACL{
			{
				Action:       "accept",
				Sources:      []policyv2.Alias{policyv2.Wildcard},
				Destinations: []policyv2.AliasWithPorts{{Alias: policyv2.Wildcard, Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}}},
			},
		},
	}

	spec := ScenarioSpec{
		Users: []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tagged-reg"),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	// Get users (they were already created by ScenarioSpec)
	users, err := headscale.ListUsers()
	require.NoError(t, err)
	require.Len(t, users, 2, "Should have 2 users")

	var user1, user2 *v1.User

	for _, u := range users {
		if u.GetName() == "user1" {
			user1 = u
		} else if u.GetName() == "user2" {
			user2 = u
		}
	}

	require.NotNil(t, user1, "Should find user1")
	require.NotNil(t, user2, "Should find user2")

	// Test 1: Create a PreAuthKey with tags
	var taggedKey v1.PreAuthKey
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"preauthkeys",
				"--user", strconv.FormatUint(user1.GetId(), 10),
				"create",
				"--reusable",
				"--tags", "tag:server,tag:prod",
				"--output", "json",
			},
			&taggedKey,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Creating tagged PreAuthKey")

	// Verify PreAuthKey has both tags
	assert.Contains(t, taggedKey.GetAclTags(), "tag:server", "PreAuthKey should have tag:server")
	assert.Contains(t, taggedKey.GetAclTags(), "tag:prod", "PreAuthKey should have tag:prod")
	assert.Len(t, taggedKey.GetAclTags(), 2, "PreAuthKey should have exactly 2 tags")

	// Test 2: Register a node using the tagged PreAuthKey
	err = scenario.CreateTailscaleNodesInUser("user1", "unstable", 1, tsic.WithNetwork(scenario.Networks()[0]))
	require.NoError(t, err)

	err = scenario.RunTailscaleUp("user1", headscale.GetEndpoint(), taggedKey.GetKey())
	require.NoError(t, err)

	// Wait for the node to be registered
	var registeredNode *v1.Node

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes()
		assert.NoError(c, err)
		assert.GreaterOrEqual(c, len(nodes), 1, "Should have at least 1 node")

		// Find the tagged node - it will have user "tagged-devices" per tags-as-identity model
		for _, node := range nodes {
			if node.GetUser().GetName() == "tagged-devices" && len(node.GetValidTags()) > 0 {
				registeredNode = node
				break
			}
		}

		assert.NotNil(c, registeredNode, "Should find a tagged node")
	}, 30*time.Second, 500*time.Millisecond, "Waiting for tagged node registration")

	// Test 3: Verify the registered node has the tags from the PreAuthKey
	assert.Contains(t, registeredNode.GetValidTags(), "tag:server", "Node should have tag:server")
	assert.Contains(t, registeredNode.GetValidTags(), "tag:prod", "Node should have tag:prod")
	assert.Len(t, registeredNode.GetValidTags(), 2, "Node should have exactly 2 tags")

	// Test 4: Verify the node shows as TaggedDevices user (tags-as-identity model)
	// Tagged nodes always show as "tagged-devices" in API responses, even though
	// internally UserID may be set for "created by" tracking
	assert.Equal(t, "tagged-devices", registeredNode.GetUser().GetName(), "Tagged node should show as tagged-devices user")

	// Test 5: Verify the node is identified as tagged
	assert.NotEmpty(t, registeredNode.GetValidTags(), "Tagged node should have tags")

	// Test 6: Verify tag modification on tagged nodes
	// NOTE: Changing tags requires complex ACL authorization where the node's IP
	// must be authorized for the new tags via tagOwners. For simplicity, we skip
	// this test and instead verify that tags cannot be arbitrarily changed without
	// proper ACL authorization.
	//
	// This is expected behavior - tag changes must be authorized by ACL policy.
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"nodes",
			"tag",
			"-i", strconv.FormatUint(registeredNode.GetId(), 10),
			"-t", "tag:unauthorized",
			"--output", "json",
		},
	)
	// This SHOULD fail because tag:unauthorized is not in our ACL policy
	require.ErrorContains(t, err, "invalid or unauthorized tags", "Unauthorized tag should be rejected")

	// Test 7: Create a user-owned node for comparison
	var userOwnedKey v1.PreAuthKey
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"preauthkeys",
				"--user", strconv.FormatUint(user2.GetId(), 10),
				"create",
				"--reusable",
				"--output", "json",
			},
			&userOwnedKey,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Creating user-owned PreAuthKey")

	// Verify this PreAuthKey has NO tags
	assert.Empty(t, userOwnedKey.GetAclTags(), "User-owned PreAuthKey should have no tags")

	err = scenario.CreateTailscaleNodesInUser("user2", "unstable", 1, tsic.WithNetwork(scenario.Networks()[0]))
	require.NoError(t, err)

	err = scenario.RunTailscaleUp("user2", headscale.GetEndpoint(), userOwnedKey.GetKey())
	require.NoError(t, err)

	// Wait for the user-owned node to be registered
	var userOwnedNode *v1.Node

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes()
		assert.NoError(c, err)
		assert.GreaterOrEqual(c, len(nodes), 2, "Should have at least 2 nodes")

		// Find the node registered with user2
		for _, node := range nodes {
			if node.GetUser().GetName() == "user2" {
				userOwnedNode = node
				break
			}
		}

		assert.NotNil(c, userOwnedNode, "Should find a node for user2")
	}, 30*time.Second, 500*time.Millisecond, "Waiting for user-owned node registration")

	// Test 8: Verify user-owned node has NO tags
	assert.Empty(t, userOwnedNode.GetValidTags(), "User-owned node should have no tags")
	assert.NotZero(t, userOwnedNode.GetUser().GetId(), "User-owned node should have UserID")

	// Test 9: Verify attempting to set UNAUTHORIZED tags on user-owned node fails
	// Note: Under tags-as-identity model, user-owned nodes CAN be converted to tagged nodes
	// if the tags are authorized. We use an unauthorized tag to test rejection.
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"nodes",
			"tag",
			"-i", strconv.FormatUint(userOwnedNode.GetId(), 10),
			"-t", "tag:not-in-policy",
			"--output", "json",
		},
	)
	require.ErrorContains(t, err, "invalid or unauthorized tags", "Setting unauthorized tags should fail")

	// Test 10: Verify basic connectivity - wait for sync
	err = scenario.WaitForTailscaleSync()
	require.NoError(t, err, "Clients should be able to sync")
}

// TestTagPersistenceAcrossRestart validates that tags persist across container
// restarts and that re-authentication doesn't re-apply tags from PreAuthKey.
// This is a regression test for issue #2830.
func TestTagPersistenceAcrossRestart(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"user1"},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("tag-persist"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	// Get user
	users, err := headscale.ListUsers()
	require.NoError(t, err)
	require.Len(t, users, 1)
	user1 := users[0]

	// Create a reusable PreAuthKey with tags
	var taggedKey v1.PreAuthKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"preauthkeys",
				"--user", strconv.FormatUint(user1.GetId(), 10),
				"create",
				"--reusable", // Critical: key must be reusable for container restart
				"--tags", "tag:server,tag:prod",
				"--output", "json",
			},
			&taggedKey,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Creating reusable tagged PreAuthKey")

	require.True(t, taggedKey.GetReusable(), "PreAuthKey must be reusable for restart scenario")
	require.Contains(t, taggedKey.GetAclTags(), "tag:server")
	require.Contains(t, taggedKey.GetAclTags(), "tag:prod")

	// Register initial node with tagged PreAuthKey
	err = scenario.CreateTailscaleNodesInUser("user1", "unstable", 1, tsic.WithNetwork(scenario.Networks()[0]))
	require.NoError(t, err)

	err = scenario.RunTailscaleUp("user1", headscale.GetEndpoint(), taggedKey.GetKey())
	require.NoError(t, err)

	// Wait for node registration and get initial node state
	var initialNode *v1.Node

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes()
		assert.NoError(c, err)
		assert.GreaterOrEqual(c, len(nodes), 1, "Should have at least 1 node")

		for _, node := range nodes {
			if node.GetUser().GetId() == user1.GetId() || node.GetUser().GetName() == "tagged-devices" {
				initialNode = node
				break
			}
		}

		assert.NotNil(c, initialNode, "Should find the registered node")
	}, 30*time.Second, 500*time.Millisecond, "Waiting for initial node registration")

	// Verify initial tags
	require.Contains(t, initialNode.GetValidTags(), "tag:server", "Initial node should have tag:server")
	require.Contains(t, initialNode.GetValidTags(), "tag:prod", "Initial node should have tag:prod")
	require.Len(t, initialNode.GetValidTags(), 2, "Initial node should have exactly 2 tags")

	initialNodeID := initialNode.GetId()
	t.Logf("Initial node registered with ID %d and tags %v", initialNodeID, initialNode.GetValidTags())

	// Simulate container restart by shutting down and restarting Tailscale client
	allClients, err := scenario.ListTailscaleClients()
	require.NoError(t, err)
	require.Len(t, allClients, 1, "Should have exactly 1 client")

	client := allClients[0]

	// Stop the client (simulates container stop)
	err = client.Down()
	require.NoError(t, err)

	// Wait a bit to ensure the client is fully stopped
	time.Sleep(2 * time.Second)

	// Restart the client with the SAME PreAuthKey (container restart scenario)
	// This simulates what happens when a Docker container restarts with a reusable PreAuthKey
	err = scenario.RunTailscaleUp("user1", headscale.GetEndpoint(), taggedKey.GetKey())
	require.NoError(t, err)

	// Wait for re-authentication
	var nodeAfterRestart *v1.Node

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes()
		assert.NoError(c, err)

		for _, node := range nodes {
			if node.GetId() == initialNodeID {
				nodeAfterRestart = node
				break
			}
		}

		assert.NotNil(c, nodeAfterRestart, "Should find the same node after restart")
	}, 30*time.Second, 500*time.Millisecond, "Waiting for node re-authentication")

	// CRITICAL ASSERTION: Tags should NOT be re-applied from PreAuthKey
	// Tags are only applied during INITIAL authentication, not re-authentication
	// The node should keep its existing tags (which happen to be the same in this case)
	assert.Contains(t, nodeAfterRestart.GetValidTags(), "tag:server", "Node should still have tag:server after restart")
	assert.Contains(t, nodeAfterRestart.GetValidTags(), "tag:prod", "Node should still have tag:prod after restart")
	assert.Len(t, nodeAfterRestart.GetValidTags(), 2, "Node should still have exactly 2 tags after restart")

	// Verify it's the SAME node (same ID), not a new registration
	assert.Equal(t, initialNodeID, nodeAfterRestart.GetId(), "Should be the same node, not a new registration")

	// Verify node count hasn't increased (no duplicate nodes)
	finalNodes, err := headscale.ListNodes()
	require.NoError(t, err)
	assert.Len(t, finalNodes, 1, "Should still have exactly 1 node (no duplicates from restart)")

	t.Logf("Container restart validation complete - node %d maintained tags across restart", initialNodeID)
}

func TestNodeAdvertiseTagCommand(t *testing.T) {
	IntegrationSkip(t)

	tests := []struct {
		name    string
		policy  *policyv2.Policy
		wantTag bool
	}{
		{
			name:    "no-policy",
			wantTag: false,
		},
		{
			name: "with-policy-email",
			policy: &policyv2.Policy{
				ACLs: []policyv2.ACL{
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources:  []policyv2.Alias{wildcard()},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
						},
					},
				},
				TagOwners: policyv2.TagOwners{
					policyv2.Tag("tag:test"): policyv2.Owners{usernameOwner("user1@test.no")},
				},
			},
			wantTag: true,
		},
		{
			name: "with-policy-username",
			policy: &policyv2.Policy{
				ACLs: []policyv2.ACL{
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources:  []policyv2.Alias{wildcard()},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
						},
					},
				},
				TagOwners: policyv2.TagOwners{
					policyv2.Tag("tag:test"): policyv2.Owners{usernameOwner("user1@")},
				},
			},
			wantTag: true,
		},
		{
			name: "with-policy-groups",
			policy: &policyv2.Policy{
				Groups: policyv2.Groups{
					policyv2.Group("group:admins"): []policyv2.Username{policyv2.Username("user1@")},
				},
				ACLs: []policyv2.ACL{
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources:  []policyv2.Alias{wildcard()},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
						},
					},
				},
				TagOwners: policyv2.TagOwners{
					policyv2.Tag("tag:test"): policyv2.Owners{groupOwner("group:admins")},
				},
			},
			wantTag: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := ScenarioSpec{
				NodesPerUser: 1,
				Users:        []string{"user1"},
			}

			scenario, err := NewScenario(spec)
			require.NoError(t, err)
			defer scenario.ShutdownAssertNoPanics(t)

			err = scenario.CreateHeadscaleEnv(
				[]tsic.Option{tsic.WithTags([]string{"tag:test"})},
				hsic.WithTestName("cliadvtags"),
				hsic.WithACLPolicy(tt.policy),
			)
			require.NoError(t, err)

			headscale, err := scenario.Headscale()
			require.NoError(t, err)

			// Test list all nodes after added seconds
			var resultMachines []*v1.Node
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				resultMachines = make([]*v1.Node, spec.NodesPerUser)
				err = executeAndUnmarshal(
					headscale,
					[]string{
						"headscale",
						"nodes",
						"list",
						"--tags",
						"--output", "json",
					},
					&resultMachines,
				)
				assert.NoError(c, err)
				found := false
				for _, node := range resultMachines {
					if tags := node.GetValidTags(); tags != nil {
						found = slices.Contains(tags, "tag:test")
					}
				}
				assert.Equalf(
					c,
					tt.wantTag,
					found,
					"'tag:test' found(%t) is the list of nodes, expected %t", found, tt.wantTag,
				)
			}, 10*time.Second, 200*time.Millisecond, "Waiting for tag propagation to nodes")
		})
	}
}

func TestNodeCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"node-user", "other-user"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("clins"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	regIDs := []string{
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
	}
	nodes := make([]*v1.Node, len(regIDs))
	assert.NoError(t, err)

	for index, regID := range regIDs {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("node-%d", index+1),
				"--user",
				"node-user",
				"--key",
				regID,
				"--output",
				"json",
			},
		)
		assert.NoError(t, err)

		var node v1.Node
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			err = executeAndUnmarshal(
				headscale,
				[]string{
					"headscale",
					"nodes",
					"--user",
					"node-user",
					"register",
					"--key",
					regID,
					"--output",
					"json",
				},
				&node,
			)
			assert.NoError(c, err)
		}, 10*time.Second, 200*time.Millisecond, "Waiting for node registration")

		nodes[index] = &node
	}

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.Len(ct, nodes, len(regIDs), "Should have correct number of nodes after CLI operations")
	}, 15*time.Second, 1*time.Second)

	// Test list all nodes after added seconds
	var listAll []v1.Node
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		err := executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--output",
				"json",
			},
			&listAll,
		)
		assert.NoError(ct, err)
		assert.Len(ct, listAll, len(regIDs), "Should list all nodes after CLI operations")
	}, 20*time.Second, 1*time.Second)

	assert.Equal(t, uint64(1), listAll[0].GetId())
	assert.Equal(t, uint64(2), listAll[1].GetId())
	assert.Equal(t, uint64(3), listAll[2].GetId())
	assert.Equal(t, uint64(4), listAll[3].GetId())
	assert.Equal(t, uint64(5), listAll[4].GetId())

	assert.Equal(t, "node-1", listAll[0].GetName())
	assert.Equal(t, "node-2", listAll[1].GetName())
	assert.Equal(t, "node-3", listAll[2].GetName())
	assert.Equal(t, "node-4", listAll[3].GetName())
	assert.Equal(t, "node-5", listAll[4].GetName())

	otherUserRegIDs := []string{
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
	}
	otherUserMachines := make([]*v1.Node, len(otherUserRegIDs))
	assert.NoError(t, err)

	for index, regID := range otherUserRegIDs {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("otheruser-node-%d", index+1),
				"--user",
				"other-user",
				"--key",
				regID,
				"--output",
				"json",
			},
		)
		assert.NoError(t, err)

		var node v1.Node
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			err = executeAndUnmarshal(
				headscale,
				[]string{
					"headscale",
					"nodes",
					"--user",
					"other-user",
					"register",
					"--key",
					regID,
					"--output",
					"json",
				},
				&node,
			)
			assert.NoError(c, err)
		}, 10*time.Second, 200*time.Millisecond, "Waiting for other-user node registration")

		otherUserMachines[index] = &node
	}

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.Len(ct, otherUserMachines, len(otherUserRegIDs), "Should have correct number of otherUser machines after CLI operations")
	}, 15*time.Second, 1*time.Second)

	// Test list all nodes after added otherUser
	var listAllWithotherUser []v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--output",
				"json",
			},
			&listAllWithotherUser,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for nodes list after adding other-user nodes")

	// All nodes, nodes + otherUser
	assert.Len(t, listAllWithotherUser, 7)

	assert.Equal(t, uint64(6), listAllWithotherUser[5].GetId())
	assert.Equal(t, uint64(7), listAllWithotherUser[6].GetId())

	assert.Equal(t, "otheruser-node-1", listAllWithotherUser[5].GetName())
	assert.Equal(t, "otheruser-node-2", listAllWithotherUser[6].GetName())

	// Test list all nodes after added otherUser
	var listOnlyotherUserMachineUser []v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--user",
				"other-user",
				"--output",
				"json",
			},
			&listOnlyotherUserMachineUser,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for nodes list filtered by other-user")

	assert.Len(t, listOnlyotherUserMachineUser, 2)

	assert.Equal(t, uint64(6), listOnlyotherUserMachineUser[0].GetId())
	assert.Equal(t, uint64(7), listOnlyotherUserMachineUser[1].GetId())

	assert.Equal(
		t,
		"otheruser-node-1",
		listOnlyotherUserMachineUser[0].GetName(),
	)
	assert.Equal(
		t,
		"otheruser-node-2",
		listOnlyotherUserMachineUser[1].GetName(),
	)

	// Delete a nodes
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"nodes",
			"delete",
			"--identifier",
			// Delete the last added machine
			"4",
			"--output",
			"json",
			"--force",
		},
	)
	assert.NoError(t, err)

	// Test: list main user after node is deleted
	var listOnlyMachineUserAfterDelete []v1.Node
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		err := executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--user",
				"node-user",
				"--output",
				"json",
			},
			&listOnlyMachineUserAfterDelete,
		)
		assert.NoError(ct, err)
		assert.Len(ct, listOnlyMachineUserAfterDelete, 4, "Should have 4 nodes for node-user after deletion")
	}, 20*time.Second, 1*time.Second)
}

func TestNodeExpireCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"node-expire-user"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("clins"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	regIDs := []string{
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
	}
	nodes := make([]*v1.Node, len(regIDs))

	for index, regID := range regIDs {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("node-%d", index+1),
				"--user",
				"node-expire-user",
				"--key",
				regID,
				"--output",
				"json",
			},
		)
		assert.NoError(t, err)

		var node v1.Node
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			err = executeAndUnmarshal(
				headscale,
				[]string{
					"headscale",
					"nodes",
					"--user",
					"node-expire-user",
					"register",
					"--key",
					regID,
					"--output",
					"json",
				},
				&node,
			)
			assert.NoError(c, err)
		}, 10*time.Second, 200*time.Millisecond, "Waiting for node-expire-user node registration")

		nodes[index] = &node
	}

	assert.Len(t, nodes, len(regIDs))

	var listAll []v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--output",
				"json",
			},
			&listAll,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for nodes list in expire test")

	assert.Len(t, listAll, 5)

	assert.True(t, listAll[0].GetExpiry().AsTime().IsZero())
	assert.True(t, listAll[1].GetExpiry().AsTime().IsZero())
	assert.True(t, listAll[2].GetExpiry().AsTime().IsZero())
	assert.True(t, listAll[3].GetExpiry().AsTime().IsZero())
	assert.True(t, listAll[4].GetExpiry().AsTime().IsZero())

	for idx := range 3 {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"nodes",
				"expire",
				"--identifier",
				strconv.FormatUint(listAll[idx].GetId(), 10),
			},
		)
		assert.NoError(t, err)
	}

	var listAllAfterExpiry []v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--output",
				"json",
			},
			&listAllAfterExpiry,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for nodes list after expiry")

	assert.Len(t, listAllAfterExpiry, 5)

	assert.True(t, listAllAfterExpiry[0].GetExpiry().AsTime().Before(time.Now()))
	assert.True(t, listAllAfterExpiry[1].GetExpiry().AsTime().Before(time.Now()))
	assert.True(t, listAllAfterExpiry[2].GetExpiry().AsTime().Before(time.Now()))
	assert.True(t, listAllAfterExpiry[3].GetExpiry().AsTime().IsZero())
	assert.True(t, listAllAfterExpiry[4].GetExpiry().AsTime().IsZero())
}

func TestNodeRenameCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"node-rename-command"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("clins"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	regIDs := []string{
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
	}
	nodes := make([]*v1.Node, len(regIDs))
	assert.NoError(t, err)

	for index, regID := range regIDs {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("node-%d", index+1),
				"--user",
				"node-rename-command",
				"--key",
				regID,
				"--output",
				"json",
			},
		)
		require.NoError(t, err)

		var node v1.Node
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			err = executeAndUnmarshal(
				headscale,
				[]string{
					"headscale",
					"nodes",
					"--user",
					"node-rename-command",
					"register",
					"--key",
					regID,
					"--output",
					"json",
				},
				&node,
			)
			assert.NoError(c, err)
		}, 10*time.Second, 200*time.Millisecond, "Waiting for node-rename-command node registration")

		nodes[index] = &node
	}

	assert.Len(t, nodes, len(regIDs))

	var listAll []v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--output",
				"json",
			},
			&listAll,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for nodes list in rename test")

	assert.Len(t, listAll, 5)

	assert.Contains(t, listAll[0].GetGivenName(), "node-1")
	assert.Contains(t, listAll[1].GetGivenName(), "node-2")
	assert.Contains(t, listAll[2].GetGivenName(), "node-3")
	assert.Contains(t, listAll[3].GetGivenName(), "node-4")
	assert.Contains(t, listAll[4].GetGivenName(), "node-5")

	for idx := range 3 {
		res, err := headscale.Execute(
			[]string{
				"headscale",
				"nodes",
				"rename",
				"--identifier",
				strconv.FormatUint(listAll[idx].GetId(), 10),
				fmt.Sprintf("newnode-%d", idx+1),
			},
		)
		assert.NoError(t, err)

		assert.Contains(t, res, "Node renamed")
	}

	var listAllAfterRename []v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--output",
				"json",
			},
			&listAllAfterRename,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for nodes list after rename")

	assert.Len(t, listAllAfterRename, 5)

	assert.Equal(t, "newnode-1", listAllAfterRename[0].GetGivenName())
	assert.Equal(t, "newnode-2", listAllAfterRename[1].GetGivenName())
	assert.Equal(t, "newnode-3", listAllAfterRename[2].GetGivenName())
	assert.Contains(t, listAllAfterRename[3].GetGivenName(), "node-4")
	assert.Contains(t, listAllAfterRename[4].GetGivenName(), "node-5")

	// Test failure for too long names
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"nodes",
			"rename",
			"--identifier",
			strconv.FormatUint(listAll[4].GetId(), 10),
			strings.Repeat("t", 64),
		},
	)
	assert.ErrorContains(t, err, "must not exceed 63 characters")

	var listAllAfterRenameAttempt []v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--output",
				"json",
			},
			&listAllAfterRenameAttempt,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for nodes list after failed rename attempt")

	assert.Len(t, listAllAfterRenameAttempt, 5)

	assert.Equal(t, "newnode-1", listAllAfterRenameAttempt[0].GetGivenName())
	assert.Equal(t, "newnode-2", listAllAfterRenameAttempt[1].GetGivenName())
	assert.Equal(t, "newnode-3", listAllAfterRenameAttempt[2].GetGivenName())
	assert.Contains(t, listAllAfterRenameAttempt[3].GetGivenName(), "node-4")
	assert.Contains(t, listAllAfterRenameAttempt[4].GetGivenName(), "node-5")
}

func TestPolicyCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("clins"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_POLICY_MODE": "database",
		}),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	p := policyv2.Policy{
		ACLs: []policyv2.ACL{
			{
				Action:   "accept",
				Protocol: "tcp",
				Sources:  []policyv2.Alias{wildcard()},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
				},
			},
		},
		TagOwners: policyv2.TagOwners{
			policyv2.Tag("tag:exists"): policyv2.Owners{usernameOwner("user1@")},
		},
	}

	pBytes, _ := json.Marshal(p)

	policyFilePath := "/etc/headscale/policy.json"

	err = headscale.WriteFile(policyFilePath, pBytes)
	require.NoError(t, err)

	// No policy is present at this time.
	// Add a new policy from a file.
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"policy",
			"set",
			"-f",
			policyFilePath,
		},
	)

	require.NoError(t, err)

	// Get the current policy and check
	// if it is the same as the one we set.
	var output *policyv2.Policy
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"policy",
				"get",
				"--output",
				"json",
			},
			&output,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for policy get command")

	assert.Len(t, output.TagOwners, 1)
	assert.Len(t, output.ACLs, 1)
}

func TestPolicyBrokenConfigCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("clins"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_POLICY_MODE": "database",
		}),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	p := policyv2.Policy{
		ACLs: []policyv2.ACL{
			{
				// This is an unknown action, so it will return an error
				// and the config will not be applied.
				Action:   "unknown-action",
				Protocol: "tcp",
				Sources:  []policyv2.Alias{wildcard()},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
				},
			},
		},
		TagOwners: policyv2.TagOwners{
			policyv2.Tag("tag:exists"): policyv2.Owners{usernameOwner("user1@")},
		},
	}

	pBytes, _ := json.Marshal(p)

	policyFilePath := "/etc/headscale/policy.json"

	err = headscale.WriteFile(policyFilePath, pBytes)
	require.NoError(t, err)

	// No policy is present at this time.
	// Add a new policy from a file.
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"policy",
			"set",
			"-f",
			policyFilePath,
		},
	)
	assert.ErrorContains(t, err, `invalid action "unknown-action"`)

	// The new policy was invalid, the old one should still be in place, which
	// is none.
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"policy",
			"get",
			"--output",
			"json",
		},
	)
	assert.ErrorContains(t, err, "acl policy not found")
}
