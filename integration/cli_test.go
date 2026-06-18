package integration

import (
	"cmp"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/require"
)

// This file holds the shared helpers used by the per-command CLI integration
// test files (cli_users_test.go, cli_nodes_test.go, cli_apikeys_test.go,
// cli_preauthkeys_test.go, cli_auth_test.go, cli_server_test.go and
// cli_policy_test.go). The tests themselves live in those files, grouped by
// the command they exercise.
//
// The whole point of the CLI test suite is to guard the transport: every
// command is invoked with `--output json` and the result is unmarshalled into
// the matching gen/go/headscale/v1 Go type, so a change to the gRPC handlers,
// proto definitions or output encoders that breaks a command is caught here.

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

// assertJSONRoundtrip executes command (which must include `--output json`),
// decodes the stdout into T, then marshals T back to JSON and re-decodes it,
// asserting the serialisation is stable. This is the transport contract guard:
// if the underlying v1 type drifts in a way that loses data, the round-trip
// breaks. The decoded value is returned so callers can assert on real fields.
func assertJSONRoundtrip[T any](t require.TestingT, headscale ControlServer, command []string) T {
	var first T

	err := executeAndUnmarshal(headscale, command, &first)
	require.NoError(t, err, "decoding CLI json output")

	firstBytes, err := json.Marshal(first)
	require.NoError(t, err, "re-marshalling decoded value")

	var second T

	require.NoError(t, json.Unmarshal(firstBytes, &second), "re-decoding marshalled value")

	secondBytes, err := json.Marshal(second)
	require.NoError(t, err, "re-marshalling round-tripped value")

	require.JSONEq(t, string(firstBytes), string(secondBytes), "json round-trip should be stable")

	return second
}

// Interface ensuring that we can sort structs from gRPC that
// have an ID field.
type GRPCSortable interface {
	GetId() uint64
}

func sortWithID[T GRPCSortable](a, b T) int {
	return cmp.Compare(a.GetId(), b.GetId())
}

// setupCLIScenario boots a scenario with the given users and nodes-per-user,
// creates the headscale environment and returns the running scenario and its
// control server. It removes the repeated NewScenario/CreateHeadscaleEnv/
// Headscale boilerplate shared by the CLI tests. Callers still defer
// scenario.ShutdownAssertNoPanics(t) themselves so the cleanup is visible at
// the call site.
func setupCLIScenario(t *testing.T, testName string, users []string, nodesPerUser int) (*Scenario, ControlServer) {
	t.Helper()

	spec := ScenarioSpec{
		Users:        users,
		NodesPerUser: nodesPerUser,
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName(testName))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	return scenario, headscale
}
