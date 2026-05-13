package v2

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// sshTestUsers/sshTestNodes are reused across the table below to keep
// each row focussed on the policy under exercise. Three users, six
// nodes:
//
//   - alice (id 1) at headscale.net owns alice-laptop and alice-tablet
//   - bob   (id 2) at headscale.net owns bob-laptop
//   - thor  (id 3) at example.org   owns thor-laptop
//   - server (alice-created tagged node) → tag:server
//   - prod   (alice-created tagged node) → tag:prod
func sshTestUsers() types.Users {
	return types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@headscale.net"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@headscale.net"},
		{Model: gorm.Model{ID: 3}, Name: "thor", Email: "thor@example.org"},
	}
}

func sshTestNodes(users types.Users) types.Nodes {
	return types.Nodes{
		{
			ID:       1,
			Hostname: "alice-laptop",
			IPv4:     ap("100.64.0.1"),
			IPv6:     ap("fd7a:115c:a1e0::1"),
			User:     &users[0],
			UserID:   &users[0].ID,
		},
		{
			ID:       2,
			Hostname: "bob-laptop",
			IPv4:     ap("100.64.0.2"),
			IPv6:     ap("fd7a:115c:a1e0::2"),
			User:     &users[1],
			UserID:   &users[1].ID,
		},
		{
			ID:       3,
			Hostname: "server",
			IPv4:     ap("100.64.0.3"),
			IPv6:     ap("fd7a:115c:a1e0::3"),
			User:     &users[0],
			UserID:   &users[0].ID,
			Tags:     []string{"tag:server"},
		},
		{
			ID:       4,
			Hostname: "alice-tablet",
			IPv4:     ap("100.64.0.4"),
			IPv6:     ap("fd7a:115c:a1e0::4"),
			User:     &users[0],
			UserID:   &users[0].ID,
		},
		{
			ID:       5,
			Hostname: "thor-laptop",
			IPv4:     ap("100.64.0.5"),
			IPv6:     ap("fd7a:115c:a1e0::5"),
			User:     &users[2],
			UserID:   &users[2].ID,
		},
		{
			ID:       6,
			Hostname: "prod",
			IPv4:     ap("100.64.0.6"),
			IPv6:     ap("fd7a:115c:a1e0::6"),
			User:     &users[0],
			UserID:   &users[0].ID,
			Tags:     []string{"tag:prod"},
		},
	}
}

// TestRunSSHTests covers the engine's per-test outcome reporting. Each
// row constructs a PolicyManager (whose SetPolicy sandbox also exercises
// evaluateSSHTests) and asserts on the resulting RunSSHTests behaviour.
// SetPolicy gating is exercised separately in
// TestSetPolicyRejectsFailingSSHTests below.
func TestRunSSHTests(t *testing.T) {
	users := sshTestUsers()
	nodes := sshTestNodes(users)

	tests := []struct {
		name       string
		policy     string
		wantPass   bool
		wantErrSub []string
	}{
		{
			name: "accept-pass-basic",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server"],
					"users":  ["root"]
				}],
				"sshTests": [{
					"src":    "alice@headscale.net",
					"dst":    ["tag:server"],
					"accept": ["root"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "accept-pass-multi-user-in-rule",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server"],
					"users":  ["root", "ubuntu"]
				}],
				"sshTests": [{
					"src":    "alice@headscale.net",
					"dst":    ["tag:server"],
					"accept": ["root", "ubuntu"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "accept-fail-no-rule",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"sshTests": [{
					"src":    "alice@headscale.net",
					"dst":    ["tag:server"],
					"accept": ["root"]
				}]
			}`,
			wantPass:   false,
			wantErrSub: []string{"alice@headscale.net", "root", "expected ALLOWED"},
		},
		{
			name: "accept-fail-user-not-allowed-by-rule",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server"],
					"users":  ["root"]
				}],
				"sshTests": [{
					"src":    "alice@headscale.net",
					"dst":    ["tag:server"],
					"accept": ["mallory"]
				}]
			}`,
			wantPass:   false,
			wantErrSub: []string{"alice@headscale.net", "mallory", "expected ALLOWED"},
		},
		{
			name: "accept-fail-different-src",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server"],
					"users":  ["root"]
				}],
				"sshTests": [{
					"src":    "bob@headscale.net",
					"dst":    ["tag:server"],
					"accept": ["root"]
				}]
			}`,
			wantPass:   false,
			wantErrSub: []string{"bob@headscale.net", "root", "expected ALLOWED"},
		},
		{
			name: "deny-pass-no-rule",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"sshTests": [{
					"src":  "alice@headscale.net",
					"dst":  ["tag:server"],
					"deny": ["root"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "deny-pass-rule-blocks-user",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server"],
					"users":  ["autogroup:nonroot"]
				}],
				"sshTests": [{
					"src":  "alice@headscale.net",
					"dst":  ["tag:server"],
					"deny": ["root"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "deny-fail-rule-allows",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server"],
					"users":  ["root"]
				}],
				"sshTests": [{
					"src":  "alice@headscale.net",
					"dst":  ["tag:server"],
					"deny": ["root"]
				}]
			}`,
			wantPass:   false,
			wantErrSub: []string{"alice@headscale.net", "root", "expected DENIED"},
		},
		{
			name: "check-pass-rule-is-check",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [{
					"action": "check",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server"],
					"users":  ["root"]
				}],
				"sshTests": [{
					"src":   "alice@headscale.net",
					"dst":   ["tag:server"],
					"check": ["root"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "check-fail-rule-is-accept",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server"],
					"users":  ["root"]
				}],
				"sshTests": [{
					"src":   "alice@headscale.net",
					"dst":   ["tag:server"],
					"check": ["root"]
				}]
			}`,
			wantPass: false,
			wantErrSub: []string{
				"alice@headscale.net",
				"root",
				"via check",
				"via accept",
			},
		},
		{
			name: "check-pass-and-accept-pass-coexist",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [
					{
						"action": "accept",
						"src":    ["alice@headscale.net"],
						"dst":    ["tag:server"],
						"users":  ["root"]
					},
					{
						"action": "check",
						"src":    ["alice@headscale.net"],
						"dst":    ["tag:server"],
						"users":  ["ubuntu"]
					}
				],
				"sshTests": [{
					"src":    "alice@headscale.net",
					"dst":    ["tag:server"],
					"accept": ["root"],
					"check":  ["ubuntu"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "accept-passes-on-check-rule",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [{
					"action": "check",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server"],
					"users":  ["root"]
				}],
				"sshTests": [{
					"src":    "alice@headscale.net",
					"dst":    ["tag:server"],
					"accept": ["root"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "multi-dst-all-must-reach",
			policy: `{
				"tagOwners": {
					"tag:server": ["alice@headscale.net"],
					"tag:prod":   ["alice@headscale.net"]
				},
				"ssh": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server"],
					"users":  ["root"]
				}],
				"sshTests": [{
					"src":    "alice@headscale.net",
					"dst":    ["tag:server", "tag:prod"],
					"accept": ["root"]
				}]
			}`,
			wantPass: false,
			wantErrSub: []string{
				"alice@headscale.net",
				"root",
				"prod",
				"expected ALLOWED",
			},
		},
		{
			name: "multi-user-mixed-accept-deny-check-in-one-entry",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [
					{
						"action": "accept",
						"src":    ["alice@headscale.net"],
						"dst":    ["tag:server"],
						"users":  ["root"]
					},
					{
						"action": "check",
						"src":    ["alice@headscale.net"],
						"dst":    ["tag:server"],
						"users":  ["ubuntu"]
					}
				],
				"sshTests": [{
					"src":    "alice@headscale.net",
					"dst":    ["tag:server"],
					"accept": ["root"],
					"deny":   ["mallory"],
					"check":  ["ubuntu"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "nonroot-allows-alice",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server"],
					"users":  ["autogroup:nonroot"]
				}],
				"sshTests": [{
					"src":    "alice@headscale.net",
					"dst":    ["tag:server"],
					"accept": ["alice"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "nonroot-denies-root",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server"],
					"users":  ["autogroup:nonroot"]
				}],
				"sshTests": [
					{
						"src":    "alice@headscale.net",
						"dst":    ["tag:server"],
						"accept": ["root"]
					},
					{
						"src":  "alice@headscale.net",
						"dst":  ["tag:server"],
						"deny": ["root"]
					}
				]
			}`,
			wantPass:   false,
			wantErrSub: []string{"alice@headscale.net", "root", "expected ALLOWED"},
		},
		{
			name: "wildcard-user-allows-mallory",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server"],
					"users":  ["autogroup:nonroot"]
				}],
				"sshTests": [{
					"src":    "alice@headscale.net",
					"dst":    ["tag:server"],
					"accept": ["mallory"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "root-only-rule",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server"],
					"users":  ["root"]
				}],
				"sshTests": [
					{
						"src":    "alice@headscale.net",
						"dst":    ["tag:server"],
						"accept": ["root"]
					},
					{
						"src":    "alice@headscale.net",
						"dst":    ["tag:server"],
						"accept": ["alice"]
					}
				]
			}`,
			wantPass:   false,
			wantErrSub: []string{"alice@headscale.net", "alice", "expected ALLOWED"},
		},
		{
			name: "autogroup-self-same-user",
			policy: `{
				"ssh": [{
					"action": "accept",
					"src":    ["autogroup:member"],
					"dst":    ["autogroup:self"],
					"users":  ["root"]
				}],
				"sshTests": [{
					"src":    "alice@headscale.net",
					"dst":    ["autogroup:self"],
					"accept": ["root"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "autogroup-self-cross-user-fails",
			policy: `{
				"ssh": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["autogroup:self"],
					"users":  ["root"]
				}],
				"sshTests": [{
					"src":    "bob@headscale.net",
					"dst":    ["autogroup:self"],
					"accept": ["root"]
				}]
			}`,
			wantPass: false,
			// autogroup:self for bob resolves to bob-laptop; the only
			// rule allows alice as src, so reachability fails.
			wantErrSub: []string{"bob@headscale.net", "root"},
		},
		{
			name: "localpart-domain-match",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server"],
					"users":  ["localpart:*@headscale.net"]
				}],
				"sshTests": [{
					"src":    "alice@headscale.net",
					"dst":    ["tag:server"],
					"accept": ["alice"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "localpart-domain-mismatch",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [{
					"action": "accept",
					"src":    ["thor@example.org"],
					"dst":    ["tag:server"],
					"users":  ["localpart:*@headscale.net"]
				}],
				"sshTests": [{
					"src":    "thor@example.org",
					"dst":    ["tag:server"],
					"accept": ["thor"]
				}]
			}`,
			wantPass:   false,
			wantErrSub: []string{"thor@example.org", "thor", "expected ALLOWED"},
		},
		{
			name: "tag-as-src",
			policy: `{
				"tagOwners": {
					"tag:server": ["alice@headscale.net"],
					"tag:prod":   ["alice@headscale.net"]
				},
				"ssh": [{
					"action": "accept",
					"src":    ["tag:prod"],
					"dst":    ["tag:server"],
					"users":  ["root"]
				}],
				"sshTests": [{
					"src":    "tag:prod",
					"dst":    ["tag:server"],
					"accept": ["root"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "acl-allows-tcp22-no-ssh-rule",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"acls": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server:22"]
				}],
				"sshTests": [{
					"src":    "alice@headscale.net",
					"dst":    ["tag:server"],
					"accept": ["root"]
				}]
			}`,
			wantPass:   false,
			wantErrSub: []string{"alice@headscale.net", "root", "expected ALLOWED"},
		},
		{
			// ACL grants only TCP:80 to alice; no rule grants TCP:22.
			// SSH rule independently allows root@tag:server. The
			// sshTests assertion must pass on the SSH layer alone,
			// proving the engine does not require an ACL packet-
			// filter rule for the SSH port.
			name: "acl-denies-tcp22-ssh-rule-allows",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"acls": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server:80"]
				}],
				"ssh": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server"],
					"users":  ["root"]
				}],
				"sshTests": [{
					"src":    "alice@headscale.net",
					"dst":    ["tag:server"],
					"accept": ["root"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "no-sshTests-block",
			policy: `{
				"acls": [{
					"action": "accept",
					"src":    ["*"],
					"dst":    ["*:*"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "both-tests-and-sshTests-both-pass",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"acls": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server:22"]
				}],
				"ssh": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server"],
					"users":  ["root"]
				}],
				"tests": [{
					"src":    "alice@headscale.net",
					"accept": ["tag:server:22"]
				}],
				"sshTests": [{
					"src":    "alice@headscale.net",
					"dst":    ["tag:server"],
					"accept": ["root"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "empty-accept-deny-check-in-entry",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"sshTests": [{
					"src": "alice@headscale.net",
					"dst": ["tag:server"]
				}]
			}`,
			wantPass:   false,
			wantErrSub: []string{"alice@headscale.net", "no accept, deny, or check"},
		},
		{
			name: "empty-user-in-accept",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server"],
					"users":  ["root"]
				}],
				"sshTests": [{
					"src":    "alice@headscale.net",
					"dst":    ["tag:server"],
					"accept": [""]
				}]
			}`,
			wantPass:   false,
			wantErrSub: []string{"alice@headscale.net", "expected ALLOWED"},
		},
		{
			// tag:empty has an owner but no tagged nodes, so the dst
			// alias resolves to no nodes. Without the empty-dst guard
			// the per-assertion loop runs zero iterations and the
			// test silently passes — exactly the regression the
			// guard exists to catch.
			name: "dst-tag-with-no-tagged-nodes-fails",
			policy: `{
				"tagOwners": { "tag:empty": ["alice@headscale.net"] },
				"sshTests": [{
					"src":    "alice@headscale.net",
					"dst":    ["tag:empty"],
					"accept": ["root"]
				}]
			}`,
			wantPass:   false,
			wantErrSub: []string{"tag:empty", "resolved to no nodes"},
		},
		{
			// autogroup:self from a tag src has no user identity to
			// scope to, so the dst alias resolves to no nodes. Same
			// empty-dst guard, distinct trigger path.
			name: "dst-autogroup-self-from-tag-src-fails",
			policy: `{
				"tagOwners": { "tag:prod": ["alice@headscale.net"] },
				"sshTests": [{
					"src":    "tag:prod",
					"dst":    ["autogroup:self"],
					"accept": ["root"]
				}]
			}`,
			wantPass:   false,
			wantErrSub: []string{"autogroup:self", "resolved to no nodes"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewPolicyManager([]byte(tt.policy), users, nodes.ViewSlice())
			require.NoError(t, err, "policy must parse and compile")

			runErr := pm.RunSSHTests()
			if tt.wantPass {
				require.NoError(t, runErr, "sshTests should pass")

				return
			}

			require.Error(t, runErr, "sshTests should fail")
			require.ErrorIs(t, runErr, errSSHPolicyTestsFailed)

			for _, sub := range tt.wantErrSub {
				assert.Contains(t, runErr.Error(), sub,
					"rendered error should mention %q", sub)
			}
		})
	}
}

// TestRunSSHTestsBothTestsPassSSHTestsFail captures the distinction the
// caller cares about: a passing ACL `tests` block plus a failing
// `sshTests` block returns errSSHPolicyTestsFailed and NOT
// errPolicyTestsFailed. The two sentinels share a literal message but
// are distinct values.
func TestRunSSHTestsBothTestsPassSSHTestsFail(t *testing.T) {
	users := sshTestUsers()
	nodes := sshTestNodes(users)

	policy := `{
		"tagOwners": { "tag:server": ["alice@headscale.net"] },
		"acls": [{
			"action": "accept",
			"src":    ["alice@headscale.net"],
			"dst":    ["tag:server:22"]
		}],
		"tests": [{
			"src":    "alice@headscale.net",
			"accept": ["tag:server:22"]
		}],
		"sshTests": [{
			"src":    "alice@headscale.net",
			"dst":    ["tag:server"],
			"accept": ["root"]
		}]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	// ACL tests should pass.
	require.NoError(t, pm.RunTests())

	// SSH tests should fail because there's no SSH rule for root.
	sshErr := pm.RunSSHTests()
	require.Error(t, sshErr)
	require.ErrorIs(t, sshErr, errSSHPolicyTestsFailed)
	require.NotErrorIs(t, sshErr, errPolicyTestsFailed,
		"ACL test sentinel must not appear on SSH-only failure")
}

// TestSetPolicyRejectsFailingSSHTests asserts SetPolicy is the user-write
// boundary: a policy whose sshTests fail is rejected without mutating
// the live PolicyManager. SSHPolicy() output must remain the prior
// rules.
func TestSetPolicyRejectsFailingSSHTests(t *testing.T) {
	users := sshTestUsers()
	nodes := sshTestNodes(users)

	good := `{
		"tagOwners": { "tag:server": ["alice@headscale.net"] },
		"ssh": [{
			"action": "accept",
			"src":    ["alice@headscale.net"],
			"dst":    ["tag:server"],
			"users":  ["root"]
		}],
		"sshTests": [{
			"src":    "alice@headscale.net",
			"dst":    ["tag:server"],
			"accept": ["root"]
		}]
	}`

	bad := `{
		"tagOwners": { "tag:server": ["alice@headscale.net"] },
		"ssh": [{
			"action": "accept",
			"src":    ["alice@headscale.net"],
			"dst":    ["tag:server"],
			"users":  ["root"]
		}],
		"sshTests": [{
			"src":    "bob@headscale.net",
			"dst":    ["tag:server"],
			"accept": ["root"]
		}]
	}`

	pm, err := NewPolicyManager([]byte(good), users, nodes.ViewSlice())
	require.NoError(t, err)

	// Snapshot SSHPolicy output for alice-laptop before the rejected
	// write — the live PolicyManager state must still describe the
	// previous (good) rules afterwards. JSON-marshal the snapshot so
	// the comparison sees rule content, not just object identity: a
	// hypothetical mutation that preserves the slice length but
	// rewrites principals or SSHUsers would slip past a count-only
	// assertion.
	aliceView := nodes.ViewSlice().At(0)

	beforePol, err := pm.SSHPolicy("", aliceView)
	require.NoError(t, err)

	beforeJSON, err := json.Marshal(beforePol)
	require.NoError(t, err)

	changed, err := pm.SetPolicy([]byte(bad))
	require.Error(t, err, "SetPolicy must reject a policy whose sshTests fail")
	require.False(t, changed, "SetPolicy must report no change when rejected")
	require.ErrorIs(t, err, errSSHPolicyTestsFailed)
	require.Contains(t, err.Error(), "expected ALLOWED")

	afterPol, err := pm.SSHPolicy("", aliceView)
	require.NoError(t, err)

	afterJSON, err := json.Marshal(afterPol)
	require.NoError(t, err)

	require.JSONEq(t, string(beforeJSON), string(afterJSON),
		"live SSH policy must not change after a rejected SetPolicy")
}

// TestSetPolicyAggregatesACLAndSSHTestFailures exercises the multierr
// aggregation: when both layers fail, the returned error wraps both
// sentinels so operators see every failure in a single round trip.
func TestSetPolicyAggregatesACLAndSSHTestFailures(t *testing.T) {
	users := sshTestUsers()
	nodes := sshTestNodes(users)

	good := `{
		"tagOwners": { "tag:server": ["alice@headscale.net"] },
		"acls": [{
			"action": "accept",
			"src":    ["alice@headscale.net"],
			"dst":    ["tag:server:22"]
		}],
		"ssh": [{
			"action": "accept",
			"src":    ["alice@headscale.net"],
			"dst":    ["tag:server"],
			"users":  ["root"]
		}],
		"tests": [{
			"src":    "alice@headscale.net",
			"accept": ["tag:server:22"]
		}],
		"sshTests": [{
			"src":    "alice@headscale.net",
			"dst":    ["tag:server"],
			"accept": ["root"]
		}]
	}`

	// Both blocks fail: acls only allow alice but tests assert bob;
	// ssh only allows alice but sshTests assert bob.
	bad := `{
		"tagOwners": { "tag:server": ["alice@headscale.net"] },
		"acls": [{
			"action": "accept",
			"src":    ["alice@headscale.net"],
			"dst":    ["tag:server:22"]
		}],
		"ssh": [{
			"action": "accept",
			"src":    ["alice@headscale.net"],
			"dst":    ["tag:server"],
			"users":  ["root"]
		}],
		"tests": [{
			"src":    "bob@headscale.net",
			"accept": ["tag:server:22"]
		}],
		"sshTests": [{
			"src":    "bob@headscale.net",
			"dst":    ["tag:server"],
			"accept": ["root"]
		}]
	}`

	pm, err := NewPolicyManager([]byte(good), users, nodes.ViewSlice())
	require.NoError(t, err)

	_, err = pm.SetPolicy([]byte(bad))
	require.Error(t, err)
	require.ErrorIs(t, err, errPolicyTestsFailed,
		"aggregated error must wrap the ACL test sentinel")
	require.ErrorIs(t, err, errSSHPolicyTestsFailed,
		"aggregated error must wrap the SSH test sentinel")

	body := err.Error()
	assert.Contains(t, body, "tag:server:22",
		"aggregated error must include the ACL failure message")
	assert.Contains(t, body, "bob@headscale.net",
		"aggregated error must include the bob src")
	// The SSH renderer emits "src/user -> dst" form; the ACL renderer
	// emits "src -> dst". Substring "/root -> " is unique to the SSH
	// body, so finding it inside the aggregated error proves the SSH
	// failure rendering was concatenated alongside the ACL body.
	assert.Contains(t, body, "/root -> ",
		"aggregated error must include the SSH-shape src/user -> dst rendering")
}

// TestNewPolicyManagerWarnsOnSSHTestsFailure asserts the boot path does
// not error on a failing sshTests block: warn-and-continue is the right
// behaviour for stale stored policy, mirroring the ACL tests handling.
func TestNewPolicyManagerWarnsOnSSHTestsFailure(t *testing.T) {
	users := sshTestUsers()
	nodes := sshTestNodes(users)

	// sshTests reference a user that does exist but no rule allows
	// them — the test should fail at user-write but not at boot.
	stale := `{
		"tagOwners": { "tag:server": ["alice@headscale.net"] },
		"sshTests": [{
			"src":    "alice@headscale.net",
			"dst":    ["tag:server"],
			"accept": ["root"]
		}]
	}`

	pm, err := NewPolicyManager([]byte(stale), users, nodes.ViewSlice())
	require.NoError(t, err, "boot must not error on sshTests failure")
	require.NotNil(t, pm)

	// A subsequent SetPolicy of the same body must reject — that's
	// the user-write path.
	_, err = pm.SetPolicy([]byte(stale))
	require.Error(t, err)
	require.ErrorIs(t, err, errSSHPolicyTestsFailed)
}

// TestSSHPolicyTestResultsErrorsRendering checks the multi-line render
// layout. Because the body is the user-facing error, the format needs
// to identify (src, user, dst) cleanly across accept, deny, and check.
func TestSSHPolicyTestResultsErrorsRendering(t *testing.T) {
	results := SSHPolicyTestResults{
		AllPassed: false,
		Results: []SSHPolicyTestResult{
			{
				Src: "alice@headscale.net",
				AcceptFail: map[string][]string{
					"root": {"server"},
				},
			},
			{
				Src: "bob@headscale.net",
				DenyFail: map[string][]string{
					"root": {"alice-laptop"},
				},
			},
			{
				Src: "alice@headscale.net",
				CheckFail: map[string][]string{
					"ubuntu": {"server"},
				},
				AcceptOK: map[string][]string{
					"ubuntu": {"server"},
				},
			},
		},
	}

	rendered := results.Errors()
	for _, sub := range []string{
		"alice@headscale.net/root -> server: expected ALLOWED, got DENIED",
		"bob@headscale.net/root -> alice-laptop: expected DENIED, got ALLOWED",
		"alice@headscale.net/ubuntu -> server: expected ALLOWED via check, got ALLOWED via accept",
	} {
		assert.Contains(t, rendered, sub)
	}

	assert.Equal(t, 3, strings.Count(rendered, "\n")+1,
		"expected one line per failing assertion")
}
