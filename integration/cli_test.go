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
		[]string{"user1", "newname"},
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
