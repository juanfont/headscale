package integration

import (
	"encoding/json"
	"testing"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestPolicyCheckCommand exercises `headscale policy check` across the
// matrix that nblock asked about on PR #3229:
//
//   - policyMode: server runs with policy_mode=file vs policy_mode=database.
//     `check` reads from `--file`, so the server-side mode should not
//     change the outcome; running both proves that.
//   - fixture: ACL only, ACL with passing tests, ACL with failing tests.
//   - bypass: no-bypass talks to the server over gRPC; bypass opens the
//     database directly.
//
// Each row spins up its own scenario because policy_mode is fixed at boot
// via `HEADSCALE_POLICY_MODE`. The two users + two nodes give the tests
// block real `user@` aliases to resolve against.
func TestPolicyCheckCommand(t *testing.T) {
	IntegrationSkip(t)

	type fixture struct {
		name   string
		policy policyv2.Policy
	}

	const (
		user1 = "user1@"
		user2 = "user2@"
	)

	aclOnly := policyv2.Policy{
		ACLs: []policyv2.ACL{
			{
				Action:   policyv2.ActionAccept,
				Protocol: "tcp", //nolint:goconst // protocol literal, used inline once
				Sources:  []policyv2.Alias{usernamep(user1)},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(usernamep(user2), tailcfg.PortRange{First: 22, Last: 22}),
				},
			},
		},
	}

	aclPlusPassingTests := aclOnly
	aclPlusPassingTests.Tests = []policyv2.PolicyTest{
		{
			Src:    user1,
			Accept: []string{user2 + ":22"},
		},
	}

	aclPlusFailingTests := aclOnly
	aclPlusFailingTests.Tests = []policyv2.PolicyTest{
		{
			// Reverse direction is not allowed by the ACL; the test
			// asserts ALLOWED, so it must fail.
			Src:    user2,
			Accept: []string{user1 + ":22"},
		},
	}

	fixtures := []fixture{
		{name: "acl-only", policy: aclOnly},
		{name: "acl-plus-passing-tests", policy: aclPlusPassingTests},
		{name: "acl-plus-failing-tests", policy: aclPlusFailingTests},
	}

	type row struct {
		name       string
		policyMode string
		fixture    fixture
		bypass     bool
		wantErr    string
		wantStdout string
	}

	modes := []string{"file", "database"} //nolint:goconst // axis labels match HEADSCALE_POLICY_MODE values
	bypasses := []bool{false, true}
	rows := make([]row, 0, len(modes)*len(fixtures)*len(bypasses))

	for _, mode := range modes {
		for _, f := range fixtures {
			for _, bypass := range bypasses {
				suffix := "no-bypass"
				if bypass {
					suffix = "bypass"
				}

				r := row{
					name:       mode + "-" + f.name + "-" + suffix,
					policyMode: mode,
					fixture:    f,
					bypass:     bypass,
					wantStdout: "Policy is valid",
				}
				if f.name == "acl-plus-failing-tests" {
					r.wantErr = "test(s) failed"
					r.wantStdout = ""
				}

				rows = append(rows, r)
			}
		}
	}

	for _, tt := range rows {
		t.Run(tt.name, func(t *testing.T) {
			spec := ScenarioSpec{
				NodesPerUser: 1,
				Users:        []string{"user1", "user2"}, //nolint:goconst // matches usernamep("user1@")/("user2@") above
			}

			scenario, err := NewScenario(spec)
			require.NoError(t, err)

			defer scenario.ShutdownAssertNoPanics(t)

			err = scenario.CreateHeadscaleEnv(
				[]tsic.Option{},
				hsic.WithTestName("cli-policycheck"),
				hsic.WithConfigEnv(map[string]string{
					"HEADSCALE_POLICY_MODE": tt.policyMode, //nolint:goconst // env var name from hscontrol/types/config.go
				}),
			)
			require.NoError(t, err)

			headscale, err := scenario.Headscale()
			require.NoError(t, err)

			pBytes, err := json.Marshal(tt.fixture.policy)
			require.NoError(t, err)

			policyFilePath := "/etc/headscale/policy.json" //nolint:goconst // standard headscale policy path
			err = headscale.WriteFile(policyFilePath, pBytes)
			require.NoError(t, err)

			cmd := []string{"headscale", "policy", "check", "-f", policyFilePath} //nolint:goconst // CLI invocation
			if tt.bypass {
				// --force suppresses the "is the server running?"
				// confirmation prompt so the command can run
				// non-interactively under the test harness.
				cmd = append(cmd, "--bypass-grpc-and-access-database-directly", "--force")
			}

			stdout, err := headscale.Execute(cmd)

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			require.Contains(t, stdout, tt.wantStdout)
		})
	}
}
