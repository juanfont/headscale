package integration

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
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
		return err
	}

	return nil
}

func TestUserCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		"user1": 0,
		"user2": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assert.NoError(t, err)

	headscale, err := scenario.Headscale()
	assert.NoError(t, err)

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
	assert.NoError(t, err)

	result := []string{listUsers[0].Name, listUsers[1].Name}
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
	assert.NoError(t, err)

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
	assert.NoError(t, err)

	result = []string{listAfterRenameUsers[0].Name, listAfterRenameUsers[1].Name}
	sort.Strings(result)

	assert.Equal(
		t,
		[]string{"newname", "user1"},
		result,
	)

	err = scenario.Shutdown()
	assert.NoError(t, err)
}

func TestPreAuthKeyCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	user := "preauthkeyspace"
	count := 3

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		user: 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clipak"))
	assert.NoError(t, err)

	headscale, err := scenario.Headscale()
	assert.NoError(t, err)

	keys := make([]*v1.PreAuthKey, count)
	assert.NoError(t, err)

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
		assert.NoError(t, err)

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
	assert.NoError(t, err)

	// There is one key created by "scenario.CreateHeadscaleEnv"
	assert.Len(t, listedPreAuthKeys, 4)

	assert.Equal(
		t,
		[]string{keys[0].Id, keys[1].Id, keys[2].Id},
		[]string{listedPreAuthKeys[1].Id, listedPreAuthKeys[2].Id, listedPreAuthKeys[3].Id},
	)

	assert.NotEmpty(t, listedPreAuthKeys[1].Key)
	assert.NotEmpty(t, listedPreAuthKeys[2].Key)
	assert.NotEmpty(t, listedPreAuthKeys[3].Key)

	assert.True(t, listedPreAuthKeys[1].Expiration.AsTime().After(time.Now()))
	assert.True(t, listedPreAuthKeys[2].Expiration.AsTime().After(time.Now()))
	assert.True(t, listedPreAuthKeys[3].Expiration.AsTime().After(time.Now()))

	assert.True(
		t,
		listedPreAuthKeys[1].Expiration.AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedPreAuthKeys[2].Expiration.AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedPreAuthKeys[3].Expiration.AsTime().Before(time.Now().Add(time.Hour*26)),
	)

	for index := range listedPreAuthKeys {
		if index == 0 {
			continue
		}

		assert.Equal(t, listedPreAuthKeys[index].AclTags, []string{"tag:test1", "tag:test2"})
	}

	// Test key expiry
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"preauthkeys",
			"--user",
			user,
			"expire",
			listedPreAuthKeys[1].Key,
		},
	)
	assert.NoError(t, err)

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
	assert.NoError(t, err)

	assert.True(t, listedPreAuthKeysAfterExpire[1].Expiration.AsTime().Before(time.Now()))
	assert.True(t, listedPreAuthKeysAfterExpire[2].Expiration.AsTime().After(time.Now()))
	assert.True(t, listedPreAuthKeysAfterExpire[3].Expiration.AsTime().After(time.Now()))

	err = scenario.Shutdown()
	assert.NoError(t, err)
}

func TestPreAuthKeyCommandWithoutExpiry(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	user := "pre-auth-key-without-exp-user"

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		user: 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clipaknaexp"))
	assert.NoError(t, err)

	headscale, err := scenario.Headscale()
	assert.NoError(t, err)

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
	assert.NoError(t, err)

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
	assert.NoError(t, err)

	// There is one key created by "scenario.CreateHeadscaleEnv"
	assert.Len(t, listedPreAuthKeys, 2)

	assert.True(t, listedPreAuthKeys[1].Expiration.AsTime().After(time.Now()))
	assert.True(
		t,
		listedPreAuthKeys[1].Expiration.AsTime().Before(time.Now().Add(time.Minute*70)),
	)

	err = scenario.Shutdown()
	assert.NoError(t, err)
}

func TestPreAuthKeyCommandReusableEphemeral(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	user := "pre-auth-key-reus-ephm-user"

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		user: 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clipakresueeph"))
	assert.NoError(t, err)

	headscale, err := scenario.Headscale()
	assert.NoError(t, err)

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
	assert.NoError(t, err)

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
	assert.NoError(t, err)

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
	assert.NoError(t, err)

	// There is one key created by "scenario.CreateHeadscaleEnv"
	assert.Len(t, listedPreAuthKeys, 3)

	err = scenario.Shutdown()
	assert.NoError(t, err)
}

func TestEnablingRoutes(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	user := "enable-routing"

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		user: 3,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clienableroute"))
	assert.NoError(t, err)

	allClients, err := scenario.ListTailscaleClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	headscale, err := scenario.Headscale()
	assert.NoError(t, err)

	// advertise routes using the up command
	for i, client := range allClients {
		routeStr := fmt.Sprintf("10.0.%d.0/24", i)
		hostname, _ := client.FQDN()
		_, _, err = client.Execute([]string{
			"tailscale",
			"up",
			fmt.Sprintf("--advertise-routes=%s", routeStr),
			"-login-server", headscale.GetEndpoint(),
			"--hostname", hostname,
		})
		assert.NoError(t, err)
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	var routes []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&routes,
	)

	assert.NoError(t, err)
	assert.Len(t, routes, 3)

	for _, route := range routes {
		assert.Equal(t, route.Advertised, true)
		assert.Equal(t, route.Enabled, false)
		assert.Equal(t, route.IsPrimary, false)
	}

	for _, route := range routes {
		_, err = headscale.Execute(
			[]string{
				"headscale",
				"routes",
				"enable",
				"--route",
				strconv.Itoa(int(route.Id)),
			})
		assert.NoError(t, err)
	}

	var enablingRoutes []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&enablingRoutes,
	)
	assert.NoError(t, err)

	for _, route := range enablingRoutes {
		assert.Equal(t, route.Advertised, true)
		assert.Equal(t, route.Enabled, true)
		assert.Equal(t, route.IsPrimary, true)
	}

	routeIDToBeDisabled := enablingRoutes[0].Id

	_, err = headscale.Execute(
		[]string{
			"headscale",
			"routes",
			"disable",
			"--route",
			strconv.Itoa(int(routeIDToBeDisabled)),
		})
	assert.NoError(t, err)

	var disablingRoutes []*v1.Route
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"routes",
			"list",
			"--output",
			"json",
		},
		&disablingRoutes,
	)
	assert.NoError(t, err)

	for _, route := range disablingRoutes {
		assert.Equal(t, true, route.Advertised)

		if route.Id == routeIDToBeDisabled {
			assert.Equal(t, route.Enabled, false)
			assert.Equal(t, route.IsPrimary, false)
		} else {
			assert.Equal(t, route.Enabled, true)
			assert.Equal(t, route.IsPrimary, true)
		}
	}
}

func TestApiKeyCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	count := 5

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		"user1": 0,
		"user2": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assert.NoError(t, err)

	headscale, err := scenario.Headscale()
	assert.NoError(t, err)

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

	assert.Equal(t, uint64(1), listedAPIKeys[0].Id)
	assert.Equal(t, uint64(2), listedAPIKeys[1].Id)
	assert.Equal(t, uint64(3), listedAPIKeys[2].Id)
	assert.Equal(t, uint64(4), listedAPIKeys[3].Id)
	assert.Equal(t, uint64(5), listedAPIKeys[4].Id)

	assert.NotEmpty(t, listedAPIKeys[0].Prefix)
	assert.NotEmpty(t, listedAPIKeys[1].Prefix)
	assert.NotEmpty(t, listedAPIKeys[2].Prefix)
	assert.NotEmpty(t, listedAPIKeys[3].Prefix)
	assert.NotEmpty(t, listedAPIKeys[4].Prefix)

	assert.True(t, listedAPIKeys[0].Expiration.AsTime().After(time.Now()))
	assert.True(t, listedAPIKeys[1].Expiration.AsTime().After(time.Now()))
	assert.True(t, listedAPIKeys[2].Expiration.AsTime().After(time.Now()))
	assert.True(t, listedAPIKeys[3].Expiration.AsTime().After(time.Now()))
	assert.True(t, listedAPIKeys[4].Expiration.AsTime().After(time.Now()))

	assert.True(
		t,
		listedAPIKeys[0].Expiration.AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedAPIKeys[1].Expiration.AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedAPIKeys[2].Expiration.AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedAPIKeys[3].Expiration.AsTime().Before(time.Now().Add(time.Hour*26)),
	)
	assert.True(
		t,
		listedAPIKeys[4].Expiration.AsTime().Before(time.Now().Add(time.Hour*26)),
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
				listedAPIKeys[idx].Prefix,
			},
		)
		assert.Nil(t, err)

		expiredPrefixes[listedAPIKeys[idx].Prefix] = true
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
		if _, ok := expiredPrefixes[listedAfterExpireAPIKeys[index].Prefix]; ok {
			// Expired
			assert.True(
				t,
				listedAfterExpireAPIKeys[index].Expiration.AsTime().Before(time.Now()),
			)
		} else {
			// Not expired
			assert.False(
				t,
				listedAfterExpireAPIKeys[index].Expiration.AsTime().Before(time.Now()),
			)
		}
	}

	err = scenario.Shutdown()
	assert.NoError(t, err)
}

func TestNodeTagCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		"user1": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assert.NoError(t, err)

	headscale, err := scenario.Headscale()
	assert.NoError(t, err)

	machineKeys := []string{
		"nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		"nodekey:6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
	}
	machines := make([]*v1.Machine, len(machineKeys))
	assert.Nil(t, err)

	for index, machineKey := range machineKeys {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("machine-%d", index+1),
				"--user",
				"user1",
				"--key",
				machineKey,
				"--output",
				"json",
			},
		)
		assert.Nil(t, err)

		var machine v1.Machine
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
			&machine,
		)
		assert.Nil(t, err)

		machines[index] = &machine
	}
	assert.Len(t, machines, len(machineKeys))

	var machine v1.Machine
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
		&machine,
	)
	assert.Nil(t, err)

	assert.Equal(t, []string{"tag:test"}, machine.ForcedTags)

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
	resultMachines := make([]*v1.Machine, len(machineKeys))
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
	for _, machine := range resultMachines {
		if machine.ForcedTags != nil {
			for _, tag := range machine.ForcedTags {
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
		"should find a machine with the tag 'tag:test' in the list of machines",
	)

	err = scenario.Shutdown()
	assert.NoError(t, err)
}

func TestNodeCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		"machine-user": 0,
		"other-user":   0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assert.NoError(t, err)

	headscale, err := scenario.Headscale()
	assert.NoError(t, err)

	// Randomly generated machine keys
	machineKeys := []string{
		"nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		"nodekey:6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
		"nodekey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		"nodekey:8bc13285cee598acf76b1824a6f4490f7f2e3751b201e28aeb3b07fe81d5b4a1",
		"nodekey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
	}
	machines := make([]*v1.Machine, len(machineKeys))
	assert.Nil(t, err)

	for index, machineKey := range machineKeys {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("machine-%d", index+1),
				"--user",
				"machine-user",
				"--key",
				machineKey,
				"--output",
				"json",
			},
		)
		assert.Nil(t, err)

		var machine v1.Machine
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"--user",
				"machine-user",
				"register",
				"--key",
				machineKey,
				"--output",
				"json",
			},
			&machine,
		)
		assert.Nil(t, err)

		machines[index] = &machine
	}

	assert.Len(t, machines, len(machineKeys))

	// Test list all nodes after added seconds
	var listAll []v1.Machine
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

	assert.Equal(t, uint64(1), listAll[0].Id)
	assert.Equal(t, uint64(2), listAll[1].Id)
	assert.Equal(t, uint64(3), listAll[2].Id)
	assert.Equal(t, uint64(4), listAll[3].Id)
	assert.Equal(t, uint64(5), listAll[4].Id)

	assert.Equal(t, "machine-1", listAll[0].Name)
	assert.Equal(t, "machine-2", listAll[1].Name)
	assert.Equal(t, "machine-3", listAll[2].Name)
	assert.Equal(t, "machine-4", listAll[3].Name)
	assert.Equal(t, "machine-5", listAll[4].Name)

	otherUserMachineKeys := []string{
		"nodekey:b5b444774186d4217adcec407563a1223929465ee2c68a4da13af0d0185b4f8e",
		"nodekey:dc721977ac7415aafa87f7d4574cbe07c6b171834a6d37375782bdc1fb6b3584",
	}
	otherUserMachines := make([]*v1.Machine, len(otherUserMachineKeys))
	assert.Nil(t, err)

	for index, machineKey := range otherUserMachineKeys {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("otherUser-machine-%d", index+1),
				"--user",
				"other-user",
				"--key",
				machineKey,
				"--output",
				"json",
			},
		)
		assert.Nil(t, err)

		var machine v1.Machine
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
			&machine,
		)
		assert.Nil(t, err)

		otherUserMachines[index] = &machine
	}

	assert.Len(t, otherUserMachines, len(otherUserMachineKeys))

	// Test list all nodes after added otherUser
	var listAllWithotherUser []v1.Machine
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

	// All nodes, machines + otherUser
	assert.Len(t, listAllWithotherUser, 7)

	assert.Equal(t, uint64(6), listAllWithotherUser[5].Id)
	assert.Equal(t, uint64(7), listAllWithotherUser[6].Id)

	assert.Equal(t, "otherUser-machine-1", listAllWithotherUser[5].Name)
	assert.Equal(t, "otherUser-machine-2", listAllWithotherUser[6].Name)

	// Test list all nodes after added otherUser
	var listOnlyotherUserMachineUser []v1.Machine
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

	assert.Equal(t, uint64(6), listOnlyotherUserMachineUser[0].Id)
	assert.Equal(t, uint64(7), listOnlyotherUserMachineUser[1].Id)

	assert.Equal(
		t,
		"otherUser-machine-1",
		listOnlyotherUserMachineUser[0].Name,
	)
	assert.Equal(
		t,
		"otherUser-machine-2",
		listOnlyotherUserMachineUser[1].Name,
	)

	// Delete a machines
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

	// Test: list main user after machine is deleted
	var listOnlyMachineUserAfterDelete []v1.Machine
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--user",
			"machine-user",
			"--output",
			"json",
		},
		&listOnlyMachineUserAfterDelete,
	)
	assert.Nil(t, err)

	assert.Len(t, listOnlyMachineUserAfterDelete, 4)

	err = scenario.Shutdown()
	assert.NoError(t, err)
}

func TestNodeExpireCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		"machine-expire-user": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assert.NoError(t, err)

	headscale, err := scenario.Headscale()
	assert.NoError(t, err)

	// Randomly generated machine keys
	machineKeys := []string{
		"nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		"nodekey:6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
		"nodekey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		"nodekey:8bc13285cee598acf76b1824a6f4490f7f2e3751b201e28aeb3b07fe81d5b4a1",
		"nodekey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
	}
	machines := make([]*v1.Machine, len(machineKeys))

	for index, machineKey := range machineKeys {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("machine-%d", index+1),
				"--user",
				"machine-expire-user",
				"--key",
				machineKey,
				"--output",
				"json",
			},
		)
		assert.Nil(t, err)

		var machine v1.Machine
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"--user",
				"machine-expire-user",
				"register",
				"--key",
				machineKey,
				"--output",
				"json",
			},
			&machine,
		)
		assert.Nil(t, err)

		machines[index] = &machine
	}

	assert.Len(t, machines, len(machineKeys))

	var listAll []v1.Machine
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

	assert.True(t, listAll[0].Expiry.AsTime().IsZero())
	assert.True(t, listAll[1].Expiry.AsTime().IsZero())
	assert.True(t, listAll[2].Expiry.AsTime().IsZero())
	assert.True(t, listAll[3].Expiry.AsTime().IsZero())
	assert.True(t, listAll[4].Expiry.AsTime().IsZero())

	for idx := 0; idx < 3; idx++ {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"nodes",
				"expire",
				"--identifier",
				fmt.Sprintf("%d", listAll[idx].Id),
			},
		)
		assert.Nil(t, err)
	}

	var listAllAfterExpiry []v1.Machine
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

	assert.True(t, listAllAfterExpiry[0].Expiry.AsTime().Before(time.Now()))
	assert.True(t, listAllAfterExpiry[1].Expiry.AsTime().Before(time.Now()))
	assert.True(t, listAllAfterExpiry[2].Expiry.AsTime().Before(time.Now()))
	assert.True(t, listAllAfterExpiry[3].Expiry.AsTime().IsZero())
	assert.True(t, listAllAfterExpiry[4].Expiry.AsTime().IsZero())

	err = scenario.Shutdown()
	assert.NoError(t, err)
}

func TestNodeRenameCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		"machine-rename-command": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assert.NoError(t, err)

	headscale, err := scenario.Headscale()
	assert.NoError(t, err)

	// Randomly generated machine keys
	machineKeys := []string{
		"nodekey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
		"nodekey:8bc13285cee598acf76b1824a6f4490f7f2e3751b201e28aeb3b07fe81d5b4a1",
		"nodekey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		"nodekey:6abd00bb5fdda622db51387088c68e97e71ce58e7056aa54f592b6a8219d524c",
		"nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
	}
	machines := make([]*v1.Machine, len(machineKeys))
	assert.Nil(t, err)

	for index, machineKey := range machineKeys {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("machine-%d", index+1),
				"--user",
				"machine-rename-command",
				"--key",
				machineKey,
				"--output",
				"json",
			},
		)
		assert.Nil(t, err)

		var machine v1.Machine
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"--user",
				"machine-rename-command",
				"register",
				"--key",
				machineKey,
				"--output",
				"json",
			},
			&machine,
		)
		assert.Nil(t, err)

		machines[index] = &machine
	}

	assert.Len(t, machines, len(machineKeys))

	var listAll []v1.Machine
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

	assert.Contains(t, listAll[0].GetGivenName(), "machine-1")
	assert.Contains(t, listAll[1].GetGivenName(), "machine-2")
	assert.Contains(t, listAll[2].GetGivenName(), "machine-3")
	assert.Contains(t, listAll[3].GetGivenName(), "machine-4")
	assert.Contains(t, listAll[4].GetGivenName(), "machine-5")

	for idx := 0; idx < 3; idx++ {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"nodes",
				"rename",
				"--identifier",
				fmt.Sprintf("%d", listAll[idx].Id),
				fmt.Sprintf("newmachine-%d", idx+1),
			},
		)
		assert.Nil(t, err)
	}

	var listAllAfterRename []v1.Machine
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

	assert.Equal(t, "newmachine-1", listAllAfterRename[0].GetGivenName())
	assert.Equal(t, "newmachine-2", listAllAfterRename[1].GetGivenName())
	assert.Equal(t, "newmachine-3", listAllAfterRename[2].GetGivenName())
	assert.Contains(t, listAllAfterRename[3].GetGivenName(), "machine-4")
	assert.Contains(t, listAllAfterRename[4].GetGivenName(), "machine-5")

	// Test failure for too long names
	result, err := headscale.Execute(
		[]string{
			"headscale",
			"nodes",
			"rename",
			"--identifier",
			fmt.Sprintf("%d", listAll[4].Id),
			"testmaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaachine12345678901234567890",
		},
	)
	assert.Nil(t, err)
	assert.Contains(t, result, "not be over 63 chars")

	var listAllAfterRenameAttempt []v1.Machine
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

	assert.Equal(t, "newmachine-1", listAllAfterRenameAttempt[0].GetGivenName())
	assert.Equal(t, "newmachine-2", listAllAfterRenameAttempt[1].GetGivenName())
	assert.Equal(t, "newmachine-3", listAllAfterRenameAttempt[2].GetGivenName())
	assert.Contains(t, listAllAfterRenameAttempt[3].GetGivenName(), "machine-4")
	assert.Contains(t, listAllAfterRenameAttempt[4].GetGivenName(), "machine-5")

	err = scenario.Shutdown()
	assert.NoError(t, err)
}

func TestNodeMoveCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		"old-user": 0,
		"new-user": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, []tsic.Option{}, hsic.WithTestName("clins"))
	assert.NoError(t, err)

	headscale, err := scenario.Headscale()
	assert.NoError(t, err)

	// Randomly generated machine key
	machineKey := "nodekey:688411b767663479632d44140f08a9fde87383adc7cdeb518f62ce28a17ef0aa"

	_, err = headscale.Execute(
		[]string{
			"headscale",
			"debug",
			"create-node",
			"--name",
			"nomad-machine",
			"--user",
			"old-user",
			"--key",
			machineKey,
			"--output",
			"json",
		},
	)
	assert.Nil(t, err)

	var machine v1.Machine
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
		&machine,
	)
	assert.Nil(t, err)

	assert.Equal(t, uint64(1), machine.Id)
	assert.Equal(t, "nomad-machine", machine.Name)
	assert.Equal(t, machine.User.Name, "old-user")

	machineID := fmt.Sprintf("%d", machine.Id)

	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"nodes",
			"move",
			"--identifier",
			machineID,
			"--user",
			"new-user",
			"--output",
			"json",
		},
		&machine,
	)
	assert.Nil(t, err)

	assert.Equal(t, machine.User.Name, "new-user")

	var allNodes []v1.Machine
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

	assert.Equal(t, allNodes[0].Id, machine.Id)
	assert.Equal(t, allNodes[0].User, machine.User)
	assert.Equal(t, allNodes[0].User.Name, "new-user")

	moveToNonExistingNSResult, err := headscale.Execute(
		[]string{
			"headscale",
			"nodes",
			"move",
			"--identifier",
			machineID,
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
	assert.Equal(t, machine.User.Name, "new-user")

	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"nodes",
			"move",
			"--identifier",
			machineID,
			"--user",
			"old-user",
			"--output",
			"json",
		},
		&machine,
	)
	assert.Nil(t, err)

	assert.Equal(t, machine.User.Name, "old-user")

	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"nodes",
			"move",
			"--identifier",
			machineID,
			"--user",
			"old-user",
			"--output",
			"json",
		},
		&machine,
	)
	assert.Nil(t, err)

	assert.Equal(t, machine.User.Name, "old-user")

	err = scenario.Shutdown()
	assert.NoError(t, err)
}
