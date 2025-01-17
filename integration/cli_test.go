package integration

import (
	"cmp"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	tcmp "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"
)

func executeAndUnmarshal[T any](headscale ControlServer, command []string, result T) error {
	str, err := headscale.Execute(command)
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(str), result)
	if err != nil {
		return fmt.Errorf("failed to unmarshal: %s\n command err: %s", err, str)
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
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		"user1": 0,
		"user2": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	var listUsers []*v1.User
	err = executeAndUnmarshal(headscale,
		[]string{
			"headscale",
			"users",
			"list",
			"--output",
			"json",
		},
		&listUsers,
	)
	assertNoErr(t, err)

	slices.SortFunc(listUsers, sortWithID)
	result := []string{listUsers[0].GetName(), listUsers[1].GetName()}

	assert.Equal(
		t,
		[]string{"user1", "user2"},
		result,
	)

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
	assertNoErr(t, err)

	var listAfterRenameUsers []*v1.User
	err = executeAndUnmarshal(headscale,
		[]string{
			"headscale",
			"users",
			"list",
			"--output",
			"json",
		},
		&listAfterRenameUsers,
	)
	assertNoErr(t, err)

	slices.SortFunc(listUsers, sortWithID)
	result = []string{listAfterRenameUsers[0].GetName(), listAfterRenameUsers[1].GetName()}

	assert.Equal(
		t,
		[]string{"user1", "newname"},
		result,
	)

	var listByUsername []*v1.User
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
	assertNoErr(t, err)

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
	assertNoErr(t, err)

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
	assert.Nil(t, err)
	assert.Contains(t, deleteResult, "User destroyed")

	var listAfterIDDelete []*v1.User
	err = executeAndUnmarshal(headscale,
		[]string{
			"headscale",
			"users",
			"list",
			"--output",
			"json",
		},
		&listAfterIDDelete,
	)
	assertNoErr(t, err)

	slices.SortFunc(listAfterIDDelete, sortWithID)
	want = []*v1.User{
		{
			Id:    2,
			Name:  "newname",
			Email: "user2@test.no",
		},
	}

	if diff := tcmp.Diff(want, listAfterIDDelete, cmpopts.IgnoreUnexported(v1.User{}), cmpopts.IgnoreFields(v1.User{}, "CreatedAt")); diff != "" {
		t.Errorf("unexpected users (-want +got):\n%s", diff)
	}

	deleteResult, err = headscale.Execute(
		[]string{
			"headscale",
			"users",
			"destroy",
			"--force",
			"--name=newname",
		},
	)
	assert.Nil(t, err)
	assert.Contains(t, deleteResult, "User destroyed")

	var listAfterNameDelete []v1.User
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
	assertNoErr(t, err)

	require.Len(t, listAfterNameDelete, 0)
}

func TestPreAuthKeyCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	user := "preauthkeyspace"
	count := 3

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		user: 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clipak"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	keys := make([]*v1.PreAuthKey, count)
	assertNoErr(t, err)

	for index := 0; index < count; index++ {
		var preAuthKey v1.PreAuthKey
		err := executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"preauthkeys",
				"--user",
				user,
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
		assertNoErr(t, err)

		keys[index] = &preAuthKey
	}

	assert.Len(t, keys, 3)

	var listedPreAuthKeys []v1.PreAuthKey
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--user",
			user,
			"list",
			"--output",
			"json",
		},
		&listedPreAuthKeys,
	)
	assertNoErr(t, err)

	// There is one key created by "scenario.CreateHeadscaleEnv"
	assert.Len(t, listedPreAuthKeys, 4)

	assert.Equal(
		t,
		[]string{keys[0].GetId(), keys[1].GetId(), keys[2].GetId()},
		[]string{
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

		assert.Equal(t, listedPreAuthKeys[index].GetAclTags(), []string{"tag:test1", "tag:test2"})
	}

	// Test key expiry
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"preauthkeys",
			"--user",
			user,
			"expire",
			listedPreAuthKeys[1].GetKey(),
		},
	)
	assertNoErr(t, err)

	var listedPreAuthKeysAfterExpire []v1.PreAuthKey
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--user",
			user,
			"list",
			"--output",
			"json",
		},
		&listedPreAuthKeysAfterExpire,
	)
	assertNoErr(t, err)

	assert.True(t, listedPreAuthKeysAfterExpire[1].GetExpiration().AsTime().Before(time.Now()))
	assert.True(t, listedPreAuthKeysAfterExpire[2].GetExpiration().AsTime().After(time.Now()))
	assert.True(t, listedPreAuthKeysAfterExpire[3].GetExpiration().AsTime().After(time.Now()))
}

func TestPreAuthKeyCommandWithoutExpiry(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	user := "pre-auth-key-without-exp-user"

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		user: 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clipaknaexp"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	var preAuthKey v1.PreAuthKey
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--user",
			user,
			"create",
			"--reusable",
			"--output",
			"json",
		},
		&preAuthKey,
	)
	assertNoErr(t, err)

	var listedPreAuthKeys []v1.PreAuthKey
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--user",
			user,
			"list",
			"--output",
			"json",
		},
		&listedPreAuthKeys,
	)
	assertNoErr(t, err)

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
	t.Parallel()

	user := "pre-auth-key-reus-ephm-user"

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		user: 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clipakresueeph"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	var preAuthReusableKey v1.PreAuthKey
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--user",
			user,
			"create",
			"--reusable=true",
			"--output",
			"json",
		},
		&preAuthReusableKey,
	)
	assertNoErr(t, err)

	var preAuthEphemeralKey v1.PreAuthKey
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--user",
			user,
			"create",
			"--ephemeral=true",
			"--output",
			"json",
		},
		&preAuthEphemeralKey,
	)
	assertNoErr(t, err)

	assert.True(t, preAuthEphemeralKey.GetEphemeral())
	assert.False(t, preAuthEphemeralKey.GetReusable())

	var listedPreAuthKeys []v1.PreAuthKey
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--user",
			user,
			"list",
			"--output",
			"json",
		},
		&listedPreAuthKeys,
	)
	assertNoErr(t, err)

	// There is one key created by "scenario.CreateHeadscaleEnv"
	assert.Len(t, listedPreAuthKeys, 3)
}

func TestPreAuthKeyCorrectUserLoggedInCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	user1 := "user1"
	user2 := "user2"

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		user1: 1,
		user2: 0,
	}

	err = scenario.CreateHeadscaleEnv(
		spec,
		[]tsic.Option{},
		hsic.WithTestName("clipak"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	var user2Key v1.PreAuthKey

	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--user",
			user2,
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
	assertNoErr(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	assert.Len(t, allClients, 1)

	client := allClients[0]

	// Log out from user1
	err = client.Logout()
	assertNoErr(t, err)

	err = scenario.WaitForTailscaleLogout()
	assertNoErr(t, err)

	status, err := client.Status()
	assertNoErr(t, err)
	if status.BackendState == "Starting" || status.BackendState == "Running" {
		t.Fatalf("expected node to be logged out, backend state: %s", status.BackendState)
	}

	err = client.Login(headscale.GetEndpoint(), user2Key.GetKey())
	assertNoErr(t, err)

	status, err = client.Status()
	assertNoErr(t, err)
	if status.BackendState != "Running" {
		t.Fatalf("expected node to be logged in, backend state: %s", status.BackendState)
	}

	if status.Self.UserID.String() != "userid:2" {
		t.Fatalf("expected node to be logged in as userid:2, got: %s", status.Self.UserID.String())
	}

	var listNodes []v1.Node
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--output",
			"json",
		},
		&listNodes,
	)
	assert.Nil(t, err)
	assert.Len(t, listNodes, 1)

	assert.Equal(t, "user2", listNodes[0].GetUser().GetName())
}

func TestApiKeyCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	count := 5

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		"user1": 0,
		"user2": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	keys := make([]string, count)

	for idx := 0; idx < count; idx++ {
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
		assert.Nil(t, err)
		assert.NotEmpty(t, apiResult)

		keys[idx] = apiResult
	}

	assert.Len(t, keys, 5)

	var listedAPIKeys []v1.ApiKey
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
	assert.Nil(t, err)

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
	for idx := 0; idx < 3; idx++ {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"apikeys",
				"expire",
				"--prefix",
				listedAPIKeys[idx].GetPrefix(),
			},
		)
		assert.Nil(t, err)

		expiredPrefixes[listedAPIKeys[idx].GetPrefix()] = true
	}

	var listedAfterExpireAPIKeys []v1.ApiKey
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
	assert.Nil(t, err)

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
	assert.Nil(t, err)

	var listedAPIKeysAfterDelete []v1.ApiKey
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
	assert.Nil(t, err)

	assert.Len(t, listedAPIKeysAfterDelete, 4)
}

func TestNodeTagCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		"user1": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	regIDs := []string{
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
	}
	nodes := make([]*v1.Node, len(regIDs))
	assert.Nil(t, err)

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
		assert.Nil(t, err)

		var node v1.Node
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
		assert.Nil(t, err)

		nodes[index] = &node
	}
	assert.Len(t, nodes, len(regIDs))

	var node v1.Node
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
	assert.Nil(t, err)

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
	assert.Nil(t, err)
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
	assert.Equal(
		t,
		true,
		found,
		"should find a node with the tag 'tag:test' in the list of nodes",
	)
}

func TestNodeAdvertiseTagCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	tests := []struct {
		name    string
		policy  *policy.ACLPolicy
		wantTag bool
	}{
		{
			name:    "no-policy",
			wantTag: false,
		},
		{
			name: "with-policy-email",
			policy: &policy.ACLPolicy{
				ACLs: []policy.ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:*"},
					},
				},
				TagOwners: map[string][]string{
					"tag:test": {"user1@test.no"},
				},
			},
			wantTag: true,
		},
		{
			name: "with-policy-username",
			policy: &policy.ACLPolicy{
				ACLs: []policy.ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:*"},
					},
				},
				TagOwners: map[string][]string{
					"tag:test": {"user1"},
				},
			},
			wantTag: true,
		},
		{
			name: "with-policy-groups",
			policy: &policy.ACLPolicy{
				Groups: policy.Groups{
					"group:admins": []string{"user1"},
				},
				ACLs: []policy.ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:*"},
					},
				},
				TagOwners: map[string][]string{
					"tag:test": {"group:admins"},
				},
			},
			wantTag: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scenario, err := NewScenario(dockertestMaxWait())
			assertNoErr(t, err)
			defer scenario.ShutdownAssertNoPanics(t)

			spec := map[string]int{
				"user1": 1,
			}

			err = scenario.CreateHeadscaleEnv(spec,
				[]tsic.Option{tsic.WithTags([]string{"tag:test"})},
				hsic.WithTestName("cliadvtags"),
				hsic.WithACLPolicy(tt.policy),
			)
			assertNoErr(t, err)

			headscale, err := scenario.Headscale()
			assertNoErr(t, err)

			// Test list all nodes after added seconds
			resultMachines := make([]*v1.Node, spec["user1"])
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
			assert.Nil(t, err)
			found := false
			for _, node := range resultMachines {
				if tags := node.GetValidTags(); tags != nil {
					found = slices.Contains(tags, "tag:test")
				}
			}
			assert.Equalf(
				t,
				tt.wantTag,
				found,
				"'tag:test' found(%t) is the list of nodes, expected %t", found, tt.wantTag,
			)
		})
	}
}

func TestNodeCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		"node-user":  0,
		"other-user": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	regIDs := []string{
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
	}
	nodes := make([]*v1.Node, len(regIDs))
	assert.Nil(t, err)

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
		assert.Nil(t, err)

		var node v1.Node
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
		assert.Nil(t, err)

		nodes[index] = &node
	}

	assert.Len(t, nodes, len(regIDs))

	// Test list all nodes after added seconds
	var listAll []v1.Node
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
	assert.Nil(t, err)

	assert.Len(t, listAll, 5)

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
	assert.Nil(t, err)

	for index, regID := range otherUserRegIDs {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("otherUser-node-%d", index+1),
				"--user",
				"other-user",
				"--key",
				regID,
				"--output",
				"json",
			},
		)
		assert.Nil(t, err)

		var node v1.Node
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
		assert.Nil(t, err)

		otherUserMachines[index] = &node
	}

	assert.Len(t, otherUserMachines, len(otherUserRegIDs))

	// Test list all nodes after added otherUser
	var listAllWithotherUser []v1.Node
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
	assert.Nil(t, err)

	// All nodes, nodes + otherUser
	assert.Len(t, listAllWithotherUser, 7)

	assert.Equal(t, uint64(6), listAllWithotherUser[5].GetId())
	assert.Equal(t, uint64(7), listAllWithotherUser[6].GetId())

	assert.Equal(t, "otherUser-node-1", listAllWithotherUser[5].GetName())
	assert.Equal(t, "otherUser-node-2", listAllWithotherUser[6].GetName())

	// Test list all nodes after added otherUser
	var listOnlyotherUserMachineUser []v1.Node
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
	assert.Nil(t, err)

	assert.Len(t, listOnlyotherUserMachineUser, 2)

	assert.Equal(t, uint64(6), listOnlyotherUserMachineUser[0].GetId())
	assert.Equal(t, uint64(7), listOnlyotherUserMachineUser[1].GetId())

	assert.Equal(
		t,
		"otherUser-node-1",
		listOnlyotherUserMachineUser[0].GetName(),
	)
	assert.Equal(
		t,
		"otherUser-node-2",
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
	assert.Nil(t, err)

	// Test: list main user after node is deleted
	var listOnlyMachineUserAfterDelete []v1.Node
	err = executeAndUnmarshal(
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
	assert.Nil(t, err)

	assert.Len(t, listOnlyMachineUserAfterDelete, 4)
}

func TestNodeExpireCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		"node-expire-user": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

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
		assert.Nil(t, err)

		var node v1.Node
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
		assert.Nil(t, err)

		nodes[index] = &node
	}

	assert.Len(t, nodes, len(regIDs))

	var listAll []v1.Node
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
	assert.Nil(t, err)

	assert.Len(t, listAll, 5)

	assert.True(t, listAll[0].GetExpiry().AsTime().IsZero())
	assert.True(t, listAll[1].GetExpiry().AsTime().IsZero())
	assert.True(t, listAll[2].GetExpiry().AsTime().IsZero())
	assert.True(t, listAll[3].GetExpiry().AsTime().IsZero())
	assert.True(t, listAll[4].GetExpiry().AsTime().IsZero())

	for idx := 0; idx < 3; idx++ {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"nodes",
				"expire",
				"--identifier",
				fmt.Sprintf("%d", listAll[idx].GetId()),
			},
		)
		assert.Nil(t, err)
	}

	var listAllAfterExpiry []v1.Node
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
	assert.Nil(t, err)

	assert.Len(t, listAllAfterExpiry, 5)

	assert.True(t, listAllAfterExpiry[0].GetExpiry().AsTime().Before(time.Now()))
	assert.True(t, listAllAfterExpiry[1].GetExpiry().AsTime().Before(time.Now()))
	assert.True(t, listAllAfterExpiry[2].GetExpiry().AsTime().Before(time.Now()))
	assert.True(t, listAllAfterExpiry[3].GetExpiry().AsTime().IsZero())
	assert.True(t, listAllAfterExpiry[4].GetExpiry().AsTime().IsZero())
}

func TestNodeRenameCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		"node-rename-command": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	regIDs := []string{
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
		types.MustRegistrationID().String(),
	}
	nodes := make([]*v1.Node, len(regIDs))
	assert.Nil(t, err)

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
		assertNoErr(t, err)

		var node v1.Node
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
		assertNoErr(t, err)

		nodes[index] = &node
	}

	assert.Len(t, nodes, len(regIDs))

	var listAll []v1.Node
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
	assert.Nil(t, err)

	assert.Len(t, listAll, 5)

	assert.Contains(t, listAll[0].GetGivenName(), "node-1")
	assert.Contains(t, listAll[1].GetGivenName(), "node-2")
	assert.Contains(t, listAll[2].GetGivenName(), "node-3")
	assert.Contains(t, listAll[3].GetGivenName(), "node-4")
	assert.Contains(t, listAll[4].GetGivenName(), "node-5")

	for idx := 0; idx < 3; idx++ {
		res, err := headscale.Execute(
			[]string{
				"headscale",
				"nodes",
				"rename",
				"--identifier",
				fmt.Sprintf("%d", listAll[idx].GetId()),
				fmt.Sprintf("newnode-%d", idx+1),
			},
		)
		assert.Nil(t, err)

		assert.Contains(t, res, "Node renamed")
	}

	var listAllAfterRename []v1.Node
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
	assert.Nil(t, err)

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
			fmt.Sprintf("%d", listAll[4].GetId()),
			strings.Repeat("t", 64),
		},
	)
	assert.ErrorContains(t, err, "not be over 63 chars")

	var listAllAfterRenameAttempt []v1.Node
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
	assert.Nil(t, err)

	assert.Len(t, listAllAfterRenameAttempt, 5)

	assert.Equal(t, "newnode-1", listAllAfterRenameAttempt[0].GetGivenName())
	assert.Equal(t, "newnode-2", listAllAfterRenameAttempt[1].GetGivenName())
	assert.Equal(t, "newnode-3", listAllAfterRenameAttempt[2].GetGivenName())
	assert.Contains(t, listAllAfterRenameAttempt[3].GetGivenName(), "node-4")
	assert.Contains(t, listAllAfterRenameAttempt[4].GetGivenName(), "node-5")
}

func TestNodeMoveCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		"old-user": 0,
		"new-user": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	// Randomly generated node key
	regID := types.MustRegistrationID()

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
	assert.Nil(t, err)

	var node v1.Node
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
	assert.Nil(t, err)

	assert.Equal(t, uint64(1), node.GetId())
	assert.Equal(t, "nomad-node", node.GetName())
	assert.Equal(t, node.GetUser().GetName(), "old-user")

	nodeID := fmt.Sprintf("%d", node.GetId())

	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"nodes",
			"move",
			"--identifier",
			nodeID,
			"--user",
			"new-user",
			"--output",
			"json",
		},
		&node,
	)
	assert.Nil(t, err)

	assert.Equal(t, node.GetUser().GetName(), "new-user")

	var allNodes []v1.Node
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
	assert.Nil(t, err)

	assert.Len(t, allNodes, 1)

	assert.Equal(t, allNodes[0].GetId(), node.GetId())
	assert.Equal(t, allNodes[0].GetUser(), node.GetUser())
	assert.Equal(t, allNodes[0].GetUser().GetName(), "new-user")

	_, err = headscale.Execute(
		[]string{
			"headscale",
			"nodes",
			"move",
			"--identifier",
			nodeID,
			"--user",
			"non-existing-user",
			"--output",
			"json",
		},
	)
	assert.ErrorContains(
		t,
		err,
		"user not found",
	)
	assert.Equal(t, node.GetUser().GetName(), "new-user")

	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"nodes",
			"move",
			"--identifier",
			nodeID,
			"--user",
			"old-user",
			"--output",
			"json",
		},
		&node,
	)
	assert.Nil(t, err)

	assert.Equal(t, node.GetUser().GetName(), "old-user")

	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"nodes",
			"move",
			"--identifier",
			nodeID,
			"--user",
			"old-user",
			"--output",
			"json",
		},
		&node,
	)
	assert.Nil(t, err)

	assert.Equal(t, node.GetUser().GetName(), "old-user")
}

func TestPolicyCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		"policy-user": 0,
	}

	err = scenario.CreateHeadscaleEnv(
		spec,
		[]tsic.Option{},
		hsic.WithTestName("clins"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_POLICY_MODE": "database",
		}),
	)
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	p := policy.ACLPolicy{
		ACLs: []policy.ACL{
			{
				Action:       "accept",
				Sources:      []string{"*"},
				Destinations: []string{"*:*"},
			},
		},
		TagOwners: map[string][]string{
			"tag:exists": {"policy-user"},
		},
	}

	pBytes, _ := json.Marshal(p)

	policyFilePath := "/etc/headscale/policy.json"

	err = headscale.WriteFile(policyFilePath, pBytes)
	assertNoErr(t, err)

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

	assertNoErr(t, err)

	// Get the current policy and check
	// if it is the same as the one we set.
	var output *policy.ACLPolicy
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
	assertNoErr(t, err)

	assert.Len(t, output.TagOwners, 1)
	assert.Len(t, output.ACLs, 1)
	assert.Equal(t, output.TagOwners["tag:exists"], []string{"policy-user"})
}

func TestPolicyBrokenConfigCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	spec := map[string]int{
		"policy-user": 1,
	}

	err = scenario.CreateHeadscaleEnv(
		spec,
		[]tsic.Option{},
		hsic.WithTestName("clins"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_POLICY_MODE": "database",
		}),
	)
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	p := policy.ACLPolicy{
		ACLs: []policy.ACL{
			{
				// This is an unknown action, so it will return an error
				// and the config will not be applied.
				Action:       "acccept",
				Sources:      []string{"*"},
				Destinations: []string{"*:*"},
			},
		},
		TagOwners: map[string][]string{
			"tag:exists": {"policy-user"},
		},
	}

	pBytes, _ := json.Marshal(p)

	policyFilePath := "/etc/headscale/policy.json"

	err = headscale.WriteFile(policyFilePath, pBytes)
	assertNoErr(t, err)

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
	assert.ErrorContains(t, err, "compiling filter rules: invalid action")

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
