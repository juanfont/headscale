package integration

import (
	"encoding/json"
	"testing"
	"time"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestSSHTestsRejectFailingPolicy asserts `headscale policy set` rejects
// a policy whose sshTests fail, surfaces the engine's "test(s) failed"
// sentinel, and leaves the stored policy unchanged. The tests name user1's
// node by its user, so no tagged node is needed.
func TestSSHTestsRejectFailingPolicy(t *testing.T) {
	IntegrationSkip(t)

	const (
		user1 = "user1@"
		user2 = "user2@"
	)

	// Good policy: user1@ may SSH as root to its own devices, and the
	// sshTests asserts it.
	goodPolicy := policyv2.Policy{
		SSHs: []policyv2.SSH{
			{
				Action:  policyv2.SSHActionAccept,
				Sources: policyv2.SSHSrcAliases{usernamep(user1)},
				Destinations: policyv2.SSHDstAliases{
					new(policyv2.AutoGroupSelf),
				},
				Users: []policyv2.SSHUser{policyv2.SSHUser("root")},
			},
		},
		SSHTests: []policyv2.SSHPolicyTest{
			{
				Src:    usernamep(user1),
				Dst:    policyv2.SSHTestDestinations{usernamep(user1)},
				Accept: []policyv2.SSHUser{policyv2.SSHUser("root")},
			},
		},
	}

	// Bad policy: same SSH rule, but the sshTests asserts user2@ — who
	// the rule does not admit — can SSH. Must be rejected.
	badPolicy := goodPolicy
	badPolicy.SSHTests = []policyv2.SSHPolicyTest{
		{
			Src:    usernamep(user2),
			Dst:    policyv2.SSHTestDestinations{usernamep(user1)},
			Accept: []policyv2.SSHUser{policyv2.SSHUser("root")},
		},
	}

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("cli-policyset-sshtests"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_POLICY_MODE": string(types.PolicyModeDB),
		}),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	goodBytes, err := json.Marshal(goodPolicy)
	require.NoError(t, err)

	badBytes, err := json.Marshal(badPolicy)
	require.NoError(t, err)

	const (
		goodPath = "/etc/headscale/policy-good.json"
		badPath  = "/etc/headscale/policy-bad.json"
	)

	require.NoError(t, headscale.WriteFile(goodPath, goodBytes))
	require.NoError(t, headscale.WriteFile(badPath, badBytes))

	// Establish the good policy as the live policy.
	_, err = headscale.Execute([]string{
		"headscale", "policy", "set", "-f", goodPath,
	})
	require.NoError(t, err, "setting the good policy must succeed")

	// Confirm the server returns the good policy.
	stdoutBefore, err := headscale.Execute([]string{
		"headscale", "policy", "get",
	})
	require.NoError(t, err)
	require.JSONEq(t, string(goodBytes), stdoutBefore,
		"server should report the good policy after the initial set")

	// Attempt to overwrite with a policy whose sshTests fail. The CLI
	// must surface the engine's "test(s) failed" sentinel and exit
	// non-zero.
	_, err = headscale.Execute([]string{
		"headscale", "policy", "set", "-f", badPath,
	})
	require.Error(t, err, "setting a policy with failing sshTests must fail")
	require.ErrorContains(t, err, "test(s) failed",
		"CLI error must surface the engine's test failure sentinel")

	// The rejected write must not have mutated the stored policy.
	stdoutAfter, err := headscale.Execute([]string{
		"headscale", "policy", "get",
	})
	require.NoError(t, err)
	require.JSONEq(t, string(goodBytes), stdoutAfter,
		"stored policy must be unchanged after a rejected set")
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
		hsic.WithTestName("cli-policy"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_POLICY_MODE": "database", // test sets/gets policy via CLI
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

	pBytes, _ := json.Marshal(p) //nolint:errchkjson

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
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for policy get command")

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
		hsic.WithTestName("cli-policybad"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_POLICY_MODE": "database", // test sets invalid policy via CLI
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

	pBytes, _ := json.Marshal(p) //nolint:errchkjson

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
	require.ErrorContains(t, err, `action="unknown-action" is not supported: invalid ACL action`)

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
