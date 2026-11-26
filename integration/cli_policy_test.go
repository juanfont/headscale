package integration

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
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
// a policy whose sshTests fail, names the failed test, and leaves the
// stored policy unchanged. The tests name user1's
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
		"headscale", "policy", "set", goodPath,
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
	// must name the failed test and exit non-zero.
	_, err = headscale.Execute([]string{
		"headscale", "policy", "set", badPath,
	})
	require.Error(t, err, "setting a policy with failing sshTests must fail")
	require.ErrorContains(t, err, "the policy is not valid.")
	require.ErrorContains(t, err, "SSH test user2@ -> user1@ as root: expected accept, got deny",
		"CLI error must name the failed test")

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
			policyFilePath,
		},
	)

	require.NoError(t, err)

	// Get the current policy and check
	// if it is the same as the one we set.
	var output clientv0.Policy

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

	assert.Equal(t, clientv0.PolicyModeDatabase, output.Mode)
	assert.False(t, output.Updated.IsNull(), "a stored policy has its time")

	var pol policyv2.Policy
	require.NoError(t, json.Unmarshal([]byte(output.Policy), &pol))
	assert.Len(t, pol.TagOwners, 1)
	assert.Len(t, pol.ACLs, 1)

	// reload reads the stored policy again.
	_, err = headscale.Execute([]string{"headscale", "policy", "reload"})
	require.NoError(t, err)
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
			policyFilePath,
		},
	)
	require.ErrorContains(t, err, `action="unknown-action" is not supported: invalid ACL action`)

	// The new policy was invalid, the old one should still be in place, which
	// is none: an empty policy with no time.
	var output clientv0.Policy

	err = executeAndUnmarshal(headscale, []string{"headscale", "policy", "get", "--output", "json"}, &output)
	require.NoError(t, err)
	assert.Empty(t, output.Policy)
	assert.True(t, output.Updated.IsNull())
}

// TestPolicyFileModeCommand covers the policy commands when the policy is a
// file: set is refused and names the file, a dry run still checks, get names
// the file, and reload reads it again.
func TestPolicyFileModeCommand(t *testing.T) {
	IntegrationSkip(t)

	scenario, err := NewScenario(ScenarioSpec{NodesPerUser: 1, Users: []string{"user1"}})
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	pol := allowAllWithTagOwners("user1", "tag:file")

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("cli-policyfile"),
		hsic.WithACLPolicy(pol),
		hsic.WithPolicyMode(types.PolicyModeFile),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	const path = "/etc/headscale/acl.hujson"

	_, err = headscale.Execute([]string{"headscale", "policy", "set", path})
	require.ErrorContains(t, err, "the policy is read from "+path+". Edit that file.")

	out, err := headscale.Execute([]string{"headscale", "policy", "set", path, "--dry-run"})
	require.NoError(t, err)
	assert.Contains(t, out, "Nothing was changed.")

	var got clientv0.Policy

	err = executeAndUnmarshal(headscale, []string{"headscale", "policy", "get", "--output", "json"}, &got)
	require.NoError(t, err)
	assert.Equal(t, clientv0.PolicyModeFile, got.Mode)
	assert.Equal(t, path, got.Path)

	var stored policyv2.Policy
	require.NoError(t, json.Unmarshal([]byte(got.Policy), &stored))
	assert.Contains(t, stored.TagOwners, policyv2.Tag("tag:file"))

	// reload reads the file again: a change to it is in force after.
	changed, err := json.Marshal(allowAllWithTagOwners("user1", "tag:file", "tag:reloaded"))
	require.NoError(t, err)
	require.NoError(t, headscale.WriteFile(path, changed))

	out, err = headscale.Execute([]string{"headscale", "policy", "reload"})
	require.NoError(t, err)
	assert.Contains(t, out, "Policy reloaded from "+path+".")

	out, err = headscale.Execute([]string{"headscale", "policy", "get"})
	require.NoError(t, err)
	assert.JSONEq(t, string(changed), out, "the server holds the file as it is now")

	_, err = headscale.Execute([]string{"headscale", "auth", "keys", "create", "tag:reloaded"})
	require.NoError(t, err, "a tag only the reloaded file names is in force")
}

// TestPolicyBypassCommand covers the database bypass: it refuses a running
// server, and with the server stopped it stores a policy that the server
// then starts with.
func TestPolicyBypassCommand(t *testing.T) {
	IntegrationSkip(t)

	scenario, err := NewScenario(ScenarioSpec{Users: []string{"user1"}})
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("cli-policybypass"),
		hsic.WithPolicyMode(types.PolicyModeDB),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	const (
		bypass = "--bypass-server-and-access-database-directly"
		path   = "/etc/headscale/bypass.json"
	)

	pBytes, err := json.Marshal(allowAllWithTagOwners("user1", "tag:bypass"))
	require.NoError(t, err)
	require.NoError(t, headscale.WriteFile(path, pBytes))

	_, err = headscale.Execute([]string{"headscale", "policy", "get", bypass, "--force"})
	require.ErrorContains(t, err, "a server is running")

	hs, ok := headscale.(*hsic.HeadscaleInContainer)
	require.True(t, ok)
	require.NoError(t, hs.SendInterrupt())

	// The container lives on for a while after serve exits; the bypass must
	// do its work in that time.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		_, err := hs.PID()
		assert.ErrorIs(c, err, os.ErrNotExist)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "waiting for serve to stop")

	before, err := headscale.Execute([]string{"headscale", "policy", "get", bypass, "--force"})
	require.NoError(t, err)

	out, err := headscale.Execute([]string{"headscale", "policy", "set", path, bypass, "--dry-run", "--force"})
	require.NoError(t, err)
	assert.Contains(t, out, "Nothing was changed.")

	after, err := headscale.Execute([]string{"headscale", "policy", "get", bypass, "--force"})
	require.NoError(t, err)
	require.Equal(t, before, after, "a dry run stores nothing")
	require.NotContains(t, after, "tag:bypass")

	_, err = headscale.Execute([]string{"headscale", "policy", "set", path, bypass, "--force"})
	require.NoError(t, err)

	out, err = headscale.Execute([]string{"headscale", "policy", "get", bypass, "--force"})
	require.NoError(t, err)
	require.JSONEq(t, string(pBytes), out)

	require.NoError(t, headscale.Restart())

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		out, err := headscale.Execute([]string{"headscale", "policy", "get"})
		assert.NoError(c, err)
		assert.JSONEq(c, string(pBytes), out)
	}, integrationutil.ScaledTimeout(30*time.Second), integrationutil.SlowPoll, "the server starts with the policy the bypass stored")
}
