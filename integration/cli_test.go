package integration

import (
	"bytes"
	"cmp"
	"encoding/json"
	"testing"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// This file holds the shared helpers used by the per-command CLI integration
// test files (cli_users_test.go, cli_nodes_test.go, cli_apikeys_test.go,
// cli_preauthkeys_test.go, cli_auth_test.go, cli_server_test.go and
// cli_policy_test.go). The tests themselves live in those files, grouped by
// the command they exercise.
//
// The whole point of the CLI test suite is to guard the transport: every
// command is invoked with `--output json` and the result is unmarshalled into
// the matching object of the v0 API, so a change to the API handlers,
// schema definitions or output encoders that breaks a command is caught here.

func executeAndUnmarshal[T any](headscale ControlServer, command []string, result T) error {
	str, err := headscale.Execute(command)
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(str), result)
	if err != nil {
		// The output of a command that makes a credential holds its secret.
		return dockertestutil.Redactf(err, "failed to unmarshal: %v\n command err: %s", err, str)
	}

	return nil
}

// assertJSONRoundtrip executes command (which must include `--output json`),
// decodes the stdout into T, then marshals T back to JSON and re-decodes it,
// asserting the serialisation is stable. This is the transport contract guard:
// if the underlying type drifts in a way that loses data, the round-trip
// breaks. The decoded value is returned so callers can assert on real fields.
func assertJSONRoundtrip[T any](t require.TestingT, headscale ControlServer, command []string) T {
	var first T

	err := executeAndUnmarshal(headscale, command, &first)
	require.NoError(t, err, "decoding CLI json output")

	// The object may hold a credential's secret: what a failure prints is
	// masked.
	firstBytes, err := json.Marshal(first)
	require.NoError(t, dockertestutil.RedactError(err), "re-marshalling decoded value")

	var second T

	require.NoError(t, dockertestutil.RedactError(json.Unmarshal(firstBytes, &second)), "re-decoding marshalled value")

	secondBytes, err := json.Marshal(second)
	require.NoError(t, dockertestutil.RedactError(err), "re-marshalling round-tripped value")

	require.JSONEq(t, dockertestutil.Redact(string(firstBytes)), dockertestutil.Redact(string(secondBytes)), "json round-trip should be stable")
	require.True(t, bytes.Equal(firstBytes, secondBytes), "json round-trip should be stable, secrets included")

	return second
}

// sortWithID orders users by their numeric ID. The HTTP client emits IDs as
// decimal strings, so they are parsed back to integers to preserve numeric
// (not lexicographic) ordering.
func sortWithID(a, b *clientv0.User) int {
	return cmp.Compare(mustParseID(a.Id), mustParseID(b.Id))
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

// registerFakeNode joins a node that never connects, as an admin would: debug
// create-node makes a registration that waits, and auth register answers it
// for user.
func registerFakeNode(t *testing.T, headscale ControlServer, name, user string) *clientv0.Node {
	t.Helper()

	authID := types.MustAuthID().Raw()

	_, err := headscale.Execute([]string{"headscale", "debug", "create-node", "--name", name, "--key", authID})
	require.NoError(t, err)

	var node clientv0.Node

	err = executeAndUnmarshal(headscale, []string{"headscale", "auth", "register", authID, user, "--output", "json"}, &node)
	require.NoError(t, err)

	return &node
}

// allowAllWithTagOwners is a policy that lets every node reach every other
// and lets owner own tags: a key for tags needs tags the policy names.
func allowAllWithTagOwners(owner string, tags ...string) *policyv2.Policy {
	pol := &policyv2.Policy{
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
		TagOwners: policyv2.TagOwners{},
	}

	for _, tag := range tags {
		pol.TagOwners[policyv2.Tag(tag)] = policyv2.Owners{usernameOwner(owner + "@")}
	}

	return pol
}
