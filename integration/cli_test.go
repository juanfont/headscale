package integration

import (
	"encoding/json"
	"sort"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/integration/hsic"
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

func TestNamespaceCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		"namespace1": 0,
		"namespace2": 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, hsic.WithTestName("clins"))
	assert.NoError(t, err)

	headscale, err := scenario.Headscale()
	assert.NoError(t, err)

	var listNamespaces []v1.Namespace
	err = executeAndUnmarshal(headscale,
		[]string{
			"headscale",
			"namespaces",
			"list",
			"--output",
			"json",
		},
		&listNamespaces,
	)
	assert.NoError(t, err)

	result := []string{listNamespaces[0].Name, listNamespaces[1].Name}
	sort.Strings(result)

	assert.Equal(
		t,
		[]string{"namespace1", "namespace2"},
		result,
	)

	_, err = headscale.Execute(
		[]string{
			"headscale",
			"namespaces",
			"rename",
			"--output",
			"json",
			"namespace2",
			"newname",
		},
	)
	assert.NoError(t, err)

	var listAfterRenameNamespaces []v1.Namespace
	err = executeAndUnmarshal(headscale,
		[]string{
			"headscale",
			"namespaces",
			"list",
			"--output",
			"json",
		},
		&listAfterRenameNamespaces,
	)
	assert.NoError(t, err)

	result = []string{listAfterRenameNamespaces[0].Name, listAfterRenameNamespaces[1].Name}
	sort.Strings(result)

	assert.Equal(
		t,
		[]string{"namespace1", "newname"},
		result,
	)

	err = scenario.Shutdown()
	assert.NoError(t, err)
}

func TestPreAuthKeyCommand(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	namespace := "preauthkeyspace"
	count := 3

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		namespace: 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, hsic.WithTestName("clipak"))
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
				"--namespace",
				namespace,
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
			"--namespace",
			namespace,
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
			"--namespace",
			namespace,
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
			"--namespace",
			namespace,
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

	namespace := "pre-auth-key-without-exp-namespace"

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		namespace: 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, hsic.WithTestName("clipaknaexp"))
	assert.NoError(t, err)

	headscale, err := scenario.Headscale()
	assert.NoError(t, err)

	var preAuthKey v1.PreAuthKey
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--namespace",
			namespace,
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
			"--namespace",
			namespace,
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

	namespace := "pre-auth-key-reus-ephm-namespace"

	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		namespace: 0,
	}

	err = scenario.CreateHeadscaleEnv(spec, hsic.WithTestName("clipakresueeph"))
	assert.NoError(t, err)

	headscale, err := scenario.Headscale()
	assert.NoError(t, err)

	var preAuthReusableKey v1.PreAuthKey
	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"preauthkeys",
			"--namespace",
			namespace,
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
			"--namespace",
			namespace,
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
			"--namespace",
			namespace,
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
