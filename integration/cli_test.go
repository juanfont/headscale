package integration

import (
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
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

func TestUserCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.Shutdown()

	spec := map[string]int{
		"user1": 0,
		"user2": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	var listUsers []v1.User
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

	result := []string{listUsers[0].GetName(), listUsers[1].GetName()}
	sort.Strings(result)

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
			"--output",
			"json",
			"user2",
			"newname",
		},
	)
	assertNoErr(t, err)

	var listAfterRenameUsers []v1.User
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

	result = []string{listAfterRenameUsers[0].GetName(), listAfterRenameUsers[1].GetName()}
	sort.Strings(result)

	assert.Equal(
		t,
		[]string{"newname", "user1"},
		result,
	)
}

func TestPreAuthKeyCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	user := "preauthkeyspace"
	count := 3

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.Shutdown()

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
	defer scenario.Shutdown()

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
	defer scenario.Shutdown()

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
	defer scenario.Shutdown()

	spec := map[string]int{
		user1: 1,
		user2: 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clipak"))
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

	assert.Equal(t, "user2", listNodes[0].User.Name)
}

func TestApiKeyCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	count := 5

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.Shutdown()

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
	defer scenario.Shutdown()

	spec := map[string]int{
		"user1": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	machineKeys := []string{
		"mkey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		"mkey:6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
	}
	nodes := make([]*v1.Node, len(machineKeys))
	assert.Nil(t, err)

	for index, machineKey := range machineKeys {
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
				machineKey,
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
				machineKey,
				"--output",
				"json",
			},
			&node,
		)
		assert.Nil(t, err)

		nodes[index] = &node
	}
	assert.Len(t, nodes, len(machineKeys))

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

	// try to set a wrong tag and retrieve the error
	type errOutput struct {
		Error string `json:"error"`
	}
	var errorOutput errOutput
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"nodes",
			"tag",
			"-i", "2",
			"-t", "wrong-tag",
			"--output", "json",
		},
		&errorOutput,
	)
	assert.Nil(t, err)
	assert.Contains(t, errorOutput.Error, "tag must start with the string 'tag:'")

	// Test list all nodes after added seconds
	resultMachines := make([]*v1.Node, len(machineKeys))
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

func TestNodeAdvertiseTagNoACLCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.Shutdown()

	spec := map[string]int{
		"user1": 1,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{tsic.WithTags([]string{"tag:test"})}, hsic.WithTestName("cliadvtags"))
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
		if node.GetInvalidTags() != nil {
			for _, tag := range node.GetInvalidTags() {
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
		"should not find a node with the tag 'tag:test' in the list of nodes",
	)
}

func TestNodeAdvertiseTagWithACLCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.Shutdown()

	spec := map[string]int{
		"user1": 1,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{tsic.WithTags([]string{"tag:exists"})}, hsic.WithTestName("cliadvtags"), hsic.WithACLPolicy(
		&policy.ACLPolicy{
			ACLs: []policy.ACL{
				{
					Action:       "accept",
					Sources:      []string{"*"},
					Destinations: []string{"*:*"},
				},
			},
			TagOwners: map[string][]string{
				"tag:exists": {"user1"},
			},
		},
	))
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
		if node.GetValidTags() != nil {
			for _, tag := range node.GetValidTags() {
				if tag == "tag:exists" {
					found = true
				}
			}
		}
	}
	assert.Equal(
		t,
		true,
		found,
		"should not find a node with the tag 'tag:exists' in the list of nodes",
	)
}

func TestNodeCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.Shutdown()

	spec := map[string]int{
		"node-user":  0,
		"other-user": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	// Pregenerated machine keys
	machineKeys := []string{
		"mkey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		"mkey:6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
		"mkey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		"mkey:8bc13285cee598acf76b1824a6f4490f7f2e3751b201e28aeb3b07fe81d5b4a1",
		"mkey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
	}
	nodes := make([]*v1.Node, len(machineKeys))
	assert.Nil(t, err)

	for index, machineKey := range machineKeys {
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
				machineKey,
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
				machineKey,
				"--output",
				"json",
			},
			&node,
		)
		assert.Nil(t, err)

		nodes[index] = &node
	}

	assert.Len(t, nodes, len(machineKeys))

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

	otherUserMachineKeys := []string{
		"mkey:b5b444774186d4217adcec407563a1223929465ee2c68a4da13af0d0185b4f8e",
		"mkey:dc721977ac7415aafa87f7d4574cbe07c6b171834a6d37375782bdc1fb6b3584",
	}
	otherUserMachines := make([]*v1.Node, len(otherUserMachineKeys))
	assert.Nil(t, err)

	for index, machineKey := range otherUserMachineKeys {
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
				machineKey,
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
				machineKey,
				"--output",
				"json",
			},
			&node,
		)
		assert.Nil(t, err)

		otherUserMachines[index] = &node
	}

	assert.Len(t, otherUserMachines, len(otherUserMachineKeys))

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
	defer scenario.Shutdown()

	spec := map[string]int{
		"node-expire-user": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	// Pregenerated machine keys
	machineKeys := []string{
		"mkey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		"mkey:6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
		"mkey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		"mkey:8bc13285cee598acf76b1824a6f4490f7f2e3751b201e28aeb3b07fe81d5b4a1",
		"mkey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
	}
	nodes := make([]*v1.Node, len(machineKeys))

	for index, machineKey := range machineKeys {
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
				machineKey,
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
				machineKey,
				"--output",
				"json",
			},
			&node,
		)
		assert.Nil(t, err)

		nodes[index] = &node
	}

	assert.Len(t, nodes, len(machineKeys))

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
	defer scenario.Shutdown()

	spec := map[string]int{
		"node-rename-command": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	// Pregenerated machine keys
	machineKeys := []string{
		"mkey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
		"mkey:8bc13285cee598acf76b1824a6f4490f7f2e3751b201e28aeb3b07fe81d5b4a1",
		"mkey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		"mkey:6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
		"mkey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
	}
	nodes := make([]*v1.Node, len(machineKeys))
	assert.Nil(t, err)

	for index, machineKey := range machineKeys {
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
				machineKey,
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
				machineKey,
				"--output",
				"json",
			},
			&node,
		)
		assertNoErr(t, err)

		nodes[index] = &node
	}

	assert.Len(t, nodes, len(machineKeys))

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
	result, err := headscale.Execute(
		[]string{
			"headscale",
			"nodes",
			"rename",
			"--identifier",
			fmt.Sprintf("%d", listAll[4].GetId()),
			"testmaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaachine12345678901234567890",
		},
	)
	assert.Nil(t, err)
	assert.Contains(t, result, "not be over 63 chars")

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
	defer scenario.Shutdown()

	spec := map[string]int{
		"old-user": 0,
		"new-user": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	// Randomly generated node key
	machineKey := "mkey:688411b767663479632d44140f08a9fde87383adc7cdeb518f62ce28a17ef0aa"

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
			machineKey,
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
			machineKey,
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

	moveToNonExistingNSResult, err := headscale.Execute(
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
	assert.Nil(t, err)

	assert.Contains(
		t,
		moveToNonExistingNSResult,
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
