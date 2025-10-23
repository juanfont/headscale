package integration

import (
	"cmp"
	"encoding/json"
	"fmt"
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
	"golang.org/x/exp/slices"
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

	assert.NotEmpty(t, listedPreAuthKeys[1].GetKey())
	assert.NotEmpty(t, listedPreAuthKeys[2].GetKey())
	assert.NotEmpty(t, listedPreAuthKeys[3].GetKey())

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
			"--user",
			"1",
			"expire",
			listedPreAuthKeys[1].GetKey(),
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
		assert.Equal(ct, "userid:2", status.Self.UserID.String(), "Expected node to be logged in as userid:2")
	}, 30*time.Second, 2*time.Second)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		listNodes, err = headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, listNodes, 2, "Should have 2 nodes after re-login")
		assert.Equal(ct, user1, listNodes[0].GetUser().GetName(), "First node should belong to user1")
		assert.Equal(ct, user2, listNodes[1].GetUser().GetName(), "Second node should belong to user2")
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

	regIDs := []string{
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
				"user1",
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
					"user1",
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

	var node v1.Node
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"tag",
				"-i", "1",
				"-t", "tag:test",
				"--output", "json",
			},
			&node,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for node tag command")

	assert.Equal(t, []string{"tag:test"}, node.GetForcedTags())

	_, err = headscale.Execute(
		[]string{
			"headscale",
			"nodes",
			"tag",
			"-i", "2",
			"-t", "wrong-tag",
			"--output", "json",
		},
	)
	assert.ErrorContains(t, err, "tag must start with the string 'tag:'")

	// Test list all nodes after added seconds
	resultMachines := make([]*v1.Node, len(regIDs))
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--output", "json",
			},
			&resultMachines,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for nodes list after tagging")
	found := false
	for _, node := range resultMachines {
		if node.GetForcedTags() != nil {
			for _, tag := range node.GetForcedTags() {
				if tag == "tag:test" {
					found = true
				}
			}
		}
	}
	assert.True(
		t,
		found,
		"should find a node with the tag 'tag:test' in the list of nodes",
	)
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

func TestNodeMoveCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"old-user", "new-user"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("clins"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	// Randomly generated node key
	regID := types.MustRegistrationID()

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	_, err = headscale.Execute(
		[]string{
			"headscale",
			"debug",
			"create-node",
			"--name",
			"nomad-node",
			"--user",
			"old-user",
			"--key",
			regID.String(),
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
				"old-user",
				"register",
				"--key",
				regID.String(),
				"--output",
				"json",
			},
			&node,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for old-user node registration")

	assert.Equal(t, uint64(1), node.GetId())
	assert.Equal(t, "nomad-node", node.GetName())
	assert.Equal(t, "old-user", node.GetUser().GetName())

	nodeID := strconv.FormatUint(node.GetId(), 10)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"move",
				"--identifier",
				strconv.FormatUint(node.GetId(), 10),
				"--user",
				strconv.FormatUint(userMap["new-user"].GetId(), 10),
				"--output",
				"json",
			},
			&node,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for node move to new-user")

	assert.Equal(t, "new-user", node.GetUser().GetName())

	var allNodes []v1.Node
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
			&allNodes,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for nodes list after move")

	assert.Len(t, allNodes, 1)

	assert.Equal(t, allNodes[0].GetId(), node.GetId())
	assert.Equal(t, allNodes[0].GetUser(), node.GetUser())
	assert.Equal(t, "new-user", allNodes[0].GetUser().GetName())

	_, err = headscale.Execute(
		[]string{
			"headscale",
			"nodes",
			"move",
			"--identifier",
			nodeID,
			"--user",
			"999",
			"--output",
			"json",
		},
	)
	assert.ErrorContains(
		t,
		err,
		"user not found",
	)
	assert.Equal(t, "new-user", node.GetUser().GetName())

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"move",
				"--identifier",
				nodeID,
				"--user",
				strconv.FormatUint(userMap["old-user"].GetId(), 10),
				"--output",
				"json",
			},
			&node,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for node move back to old-user")

	assert.Equal(t, "old-user", node.GetUser().GetName())

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"move",
				"--identifier",
				nodeID,
				"--user",
				strconv.FormatUint(userMap["old-user"].GetId(), 10),
				"--output",
				"json",
			},
			&node,
		)
		assert.NoError(c, err)
	}, 10*time.Second, 200*time.Millisecond, "Waiting for node move to same user")

	assert.Equal(t, "old-user", node.GetUser().GetName())
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
