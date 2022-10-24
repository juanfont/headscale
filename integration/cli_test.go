package integration

import (
	"encoding/json"
	"testing"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
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

	err = scenario.CreateHeadscaleEnv(spec)
	assert.NoError(t, err)

	var listNamespaces []v1.Namespace
	err = executeAndUnmarshal(scenario.Headscale(),
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

	assert.Equal(
		t,
		[]string{"namespace1", "namespace2"},
		[]string{listNamespaces[0].Name, listNamespaces[1].Name},
	)

	_, err = scenario.Headscale().Execute(
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
	err = executeAndUnmarshal(scenario.Headscale(),
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

	assert.Equal(
		t,
		[]string{"namespace1", "newname"},
		[]string{listAfterRenameNamespaces[0].Name, listAfterRenameNamespaces[1].Name},
	)

	err = scenario.Shutdown()
	assert.NoError(t, err)
}
