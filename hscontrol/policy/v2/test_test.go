package v2

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
)

// policyTestUsers/policyTestNodes are reused across the test cases below to
// keep each table row focussed on the policy + tests under exercise.
func policyTestUsers() types.Users {
	return types.Users{
		{ID: 1, Name: "alice", Email: "alice@headscale.net"},
		{ID: 2, Name: "bob", Email: "bob@headscale.net"},
	}
}

func policyTestNodes(users types.Users) types.Nodes {
	nodes := types.Nodes{
		// alice's user-owned laptop
		{
			ID:       1,
			Hostname: "alice-laptop",
			IPv4:     ap("100.64.0.1"),
			IPv6:     ap("fd7a:115c:a1e0::1"),
			User:     &users[0],
			UserID:   &users[0].ID,
		},
		// bob's user-owned laptop
		{
			ID:       2,
			Hostname: "bob-laptop",
			IPv4:     ap("100.64.0.2"),
			IPv6:     ap("fd7a:115c:a1e0::2"),
			User:     &users[1],
			UserID:   &users[1].ID,
		},
		// tagged server (created via tagged preauth key from alice)
		{
			ID:       3,
			Hostname: "server",
			IPv4:     ap("100.64.0.3"),
			IPv6:     ap("fd7a:115c:a1e0::3"),
			User:     &users[0],
			UserID:   &users[0].ID,
			Tags:     []string{"tag:server"},
		},
	}

	return nodes
}

// TestRunTests covers the engine's per-test outcome reporting. Each row
// constructs a PolicyManager (which also runs SetPolicy's sandbox) and
// checks the resulting RunTests behaviour. SetPolicy gating is exercised
// separately in TestSetPolicyRejectsFailingTests.
func TestRunTests(t *testing.T) {
	users := policyTestUsers()
	nodes := policyTestNodes(users)

	tests := []struct {
		name        string
		policy      string
		wantPass    bool
		wantErrSub  []string // substrings expected in the rendered error
		wantNoErrIs error    // sentinel the error must wrap
	}{
		{
			name: "all-pass-user-to-tag",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"acls": [{
					"action": "accept",
					"src": ["alice@headscale.net"],
					"dst": ["tag:server:22"]
				}],
				"tests": [{
					"src": "alice@headscale.net",
					"accept": ["tag:server:22"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "accept-fail-blocked-by-policy",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"acls": [{
					"action": "accept",
					"src": ["alice@headscale.net"],
					"dst": ["tag:server:22"]
				}],
				"tests": [{
					"src": "bob@headscale.net",
					"accept": ["tag:server:22"]
				}]
			}`,
			wantPass:    false,
			wantErrSub:  []string{"bob@headscale.net", "tag:server:22", "expected ALLOWED"},
			wantNoErrIs: errPolicyTestsFailed,
		},
		{
			// An accept needs every node behind the dst; a deny fails
			// as soon as one is reached.
			name: "dst-alias-partly-reached",
			policy: `{
				"groups": { "group:people": ["alice@headscale.net", "bob@headscale.net"] },
				"acls": [{
					"action": "accept",
					"src": ["alice@headscale.net"],
					"dst": ["alice@headscale.net:22"]
				}],
				"tests": [{
					"src": "alice@headscale.net",
					"accept": ["group:people:22"],
					"deny": ["group:people:22"]
				}]
			}`,
			wantPass: false,
			wantErrSub: []string{
				"alice@headscale.net -> group:people:22: expected ALLOWED, got DENIED",
				"alice@headscale.net -> group:people:22: expected DENIED, got ALLOWED",
			},
			wantNoErrIs: errPolicyTestsFailed,
		},
		{
			name: "src-wildcard-not-reached",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"acls": [{
					"action": "accept",
					"src": ["alice@headscale.net"],
					"dst": ["tag:server:22"]
				}],
				"tests": [
					{ "src": "*", "deny": ["tag:server:80"] },
					{ "src": "100.64.0.0/30", "deny": ["tag:server:80"] },
					{ "src": "autogroup:tagged", "deny": ["tag:server:80"] },
					{ "src": "autogroup:member", "deny": ["tag:server:80"] }
				]
			}`,
			wantPass: false,
			wantErrSub: []string{
				`unknown user or host: "*"`,
				`unknown user or host: "100.64.0.0/30"`,
				`unknown user or host: "autogroup:tagged"`,
				`unknown user or host: "autogroup:member"`,
			},
			wantNoErrIs: errPolicyTestsFailed,
		},
		{
			name: "deny-fail-policy-allows-traffic",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"acls": [{
					"action": "accept",
					"src": ["alice@headscale.net"],
					"dst": ["tag:server:22"]
				}],
				"tests": [{
					"src": "alice@headscale.net",
					"deny": ["tag:server:22"]
				}]
			}`,
			wantPass:    false,
			wantErrSub:  []string{"alice@headscale.net", "tag:server:22", "expected DENIED"},
			wantNoErrIs: errPolicyTestsFailed,
		},
		{
			name: "unknown-src-user",
			policy: `{
				"acls": [{
					"action": "accept",
					"src": ["*"],
					"dst": ["*:*"]
				}],
				"tests": [{
					"src": "ghost@headscale.net",
					"accept": ["alice-laptop:22"]
				}]
			}`,
			wantPass:    false,
			wantErrSub:  []string{"ghost@headscale.net", "failed to resolve source"},
			wantNoErrIs: errPolicyTestsFailed,
		},
		{
			// A group tolerates unregistered members like any rule (#3513).
			name: "group-src-with-unregistered-member",
			policy: `{
				"groups": {"group:eng": ["alice@headscale.net", "ghost@headscale.net"]},
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"acls": [{
					"action": "accept",
					"src": ["group:eng"],
					"dst": ["tag:server:22"]
				}],
				"tests": [{
					"src": "group:eng",
					"accept": ["tag:server:22"]
				}]
			}`,
			wantPass: true,
		},
		// "malformed-dst-missing-port" used to live here; structural
		// shape errors are now caught at parse by validateTests, so
		// RunTests no longer sees them. The parse-side behaviour is
		// covered by TestUnmarshalPolicy/tests-* in types_test.go.
		{
			name: "wildcard-src-passes",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"acls": [{
					"action": "accept",
					"src": ["*"],
					"dst": ["tag:server:80"]
				}],
				"tests": [{
					"src": "alice@headscale.net",
					"accept": ["tag:server:80"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "proto-restrict-tcp-only",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"acls": [{
					"action": "accept",
					"proto": "tcp",
					"src": ["alice@headscale.net"],
					"dst": ["tag:server:22"]
				}],
				"tests": [
					{
						"src": "alice@headscale.net",
						"proto": "tcp",
						"accept": ["tag:server:22"]
					},
					{
						"src": "alice@headscale.net",
						"proto": "udp",
						"deny": ["tag:server:22"]
					}
				]
			}`,
			wantPass: true,
		},
		{
			name: "grants-only-policy-evaluated",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"grants": [{
					"src": ["alice@headscale.net"],
					"dst": ["tag:server"],
					"ip":  ["22"]
				}],
				"tests": [{
					"src": "alice@headscale.net",
					"accept": ["tag:server:22"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "mixed-pass-and-fail-reports-failure",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"acls": [{
					"action": "accept",
					"src": ["alice@headscale.net"],
					"dst": ["tag:server:22"]
				}],
				"tests": [
					{
						"src": "alice@headscale.net",
						"accept": ["tag:server:22"]
					},
					{
						"src": "bob@headscale.net",
						"accept": ["tag:server:22"]
					}
				]
			}`,
			wantPass:    false,
			wantErrSub:  []string{"bob@headscale.net", "expected ALLOWED"},
			wantNoErrIs: errPolicyTestsFailed,
		},
		{
			// group:all resolves to one prefix per address; no single rule
			// covers them all, but every one is covered by some rule.
			name: "src-prefixes-allowed-by-different-rules",
			policy: `{
				"groups":    { "group:all": ["alice@headscale.net", "bob@headscale.net"] },
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"acls": [
					{ "action": "accept", "src": ["alice@headscale.net"], "dst": ["tag:server:22"] },
					{ "action": "accept", "src": ["bob@headscale.net"],   "dst": ["tag:server:22"] }
				],
				"tests": [{
					"src": "group:all",
					"accept": ["tag:server:22"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "src-prefixes-allowed-on-different-ports",
			policy: `{
				"groups":    { "group:all": ["alice@headscale.net", "bob@headscale.net"] },
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"acls": [
					{ "action": "accept", "src": ["alice@headscale.net"], "dst": ["tag:server:22"] },
					{ "action": "accept", "src": ["bob@headscale.net"],   "dst": ["tag:server:80"] }
				],
				"tests": [{
					"src": "group:all",
					"accept": ["tag:server:22"]
				}]
			}`,
			wantErrSub:  []string{"group:all", "tag:server:22", "expected ALLOWED"},
			wantNoErrIs: errPolicyTestsFailed,
		},
		{
			// One rule, several addresses per port and several ports per
			// address: an address is only allowed on its own ports.
			name: "dst-address-and-port-stay-paired",
			policy: `{
				"acls": [{
					"action": "accept",
					"src": ["*"],
					"dst": ["10.0.0.1:22", "10.0.0.3:22", "10.0.0.5:22", "10.0.0.2:80", "10.0.0.3:1000-2000"]
				}],
				"tests": [{
					"src": "alice@headscale.net",
					"accept": ["10.0.0.1:22", "10.0.0.3:22", "10.0.0.5:22", "10.0.0.2:80", "10.0.0.3:1500"],
					"deny": ["10.0.0.2:22", "10.0.0.4:22", "10.0.0.6:22", "10.0.0.1:80", "10.0.0.1:1500", "10.0.0.3:80"]
				}]
			}`,
			wantPass: true,
		},
		{
			name: "no-tests-block-is-no-op",
			policy: `{
				"acls": [{
					"action": "accept",
					"src": ["*"],
					"dst": ["*:*"]
				}]
			}`,
			wantPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewPolicyManager([]byte(tt.policy), users, nodes.ViewSlice())
			require.NoError(t, err, "policy must parse and compile")

			runErr := pm.RunTests()
			if tt.wantPass {
				require.NoError(t, runErr, "tests should pass")

				return
			}

			require.Error(t, runErr, "tests should fail")
			require.ErrorIs(t, runErr, tt.wantNoErrIs, "error should wrap errPolicyTestsFailed")

			for _, sub := range tt.wantErrSub {
				assert.Contains(t, runErr.Error(), sub, "rendered error should mention %q", sub)
			}
		})
	}
}

// TestTestAddrsOverlapsPrefix checks the lookup against the one it replaces.
func TestTestAddrsOverlapsPrefix(t *testing.T) {
	var b netipx.IPSetBuilder

	for _, p := range []string{
		"10.0.0.1/32", "10.0.0.3/32", "10.0.2.0/24", "100.64.0.0/10",
		"fd7a:115c:a1e0::1/128", "fd7a:115c:a1e0:1::/64",
	} {
		b.AddPrefix(mp(p))
	}

	set, err := b.IPSet()
	require.NoError(t, err)

	addrs := testAddrs(set.Ranges())

	for _, p := range []string{
		"0.0.0.0/0", "::/0", "9.0.0.0/8", "10.0.0.0/32", "10.0.0.1/32", "10.0.0.2/32",
		"10.0.0.2/31", "10.0.0.4/30", "10.0.0.0/24", "10.0.1.0/24", "10.0.2.7/32",
		"10.0.0.0/8", "100.63.255.255/32", "100.100.100.100/32", "100.128.0.0/32",
		"255.255.255.255/32", "::/128", "fd7a:115c:a1e0::/128", "fd7a:115c:a1e0::1/128",
		"fd7a:115c:a1e0::/48", "fd7a:115c:a1e0:1::5/128", "fd7a:115c:a1e0:2::/64",
	} {
		assert.Equal(t, set.OverlapsPrefix(mp(p)), addrs.overlapsPrefix(mp(p)), p)
	}

	assert.False(t, addrs.overlapsPrefix(netip.Prefix{}))
	assert.False(t, testAddrs(nil).overlapsPrefix(mp("0.0.0.0/0")))
}

// TestRunTestsManyAssertionsAndDestinations runs the shape that made a run
// quadratic: every assertion matched only the last of the rule's
// destinations, and each comparison parsed that destination again.
func TestRunTestsManyAssertionsAndDestinations(t *testing.T) {
	users := policyTestUsers()
	nodes := policyTestNodes(users)

	const count = 2600

	dsts := make([]string, 0, count+1)
	for i := range count {
		dsts = append(dsts, fmt.Sprintf(`"10.%d.%d.1:1"`, i/250, i%250))
	}

	dsts = append(dsts, `"192.0.2.1:1"`)

	accept := slices.Repeat([]string{`"192.0.2.1:1"`}, count)
	deny := slices.Repeat([]string{`"192.0.2.1:2"`}, count)

	policy := fmt.Sprintf(`{
		"acls": [{"action": "accept", "src": ["*"], "dst": [%s]}],
		"tests": [{"src": "alice@headscale.net", "accept": [%s], "deny": [%s]}]
	}`, strings.Join(dsts, ","), strings.Join(accept, ","), strings.Join(deny, ","))

	pol, err := unmarshalPolicy([]byte(policy))
	require.NoError(t, err)

	require.NoError(t, evaluateTests(pol, users, nodes.ViewSlice()))
}

// TestSetPolicyEvaluatesTestsUnlocked asserts that a policy's tests run
// before SetPolicy takes the write lock, so map generation and node writes
// do not wait for them: a reader holding the lock does not hold up the
// evaluation, and a rejected policy never needs the write lock at all.
func TestSetPolicyEvaluatesTestsUnlocked(t *testing.T) {
	users := policyTestUsers()
	nodes := policyTestNodes(users)

	pm, err := NewPolicyManager([]byte(`{}`), users, nodes.ViewSlice())
	require.NoError(t, err)

	bad := `{
		"tagOwners": { "tag:server": ["alice@headscale.net"] },
		"acls": [{
			"action": "accept",
			"src": ["alice@headscale.net"],
			"dst": ["tag:server:22"]
		}],
		"tests": [{
			"src": "bob@headscale.net",
			"accept": ["tag:server:22"]
		}]
	}`

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	done := make(chan error, 1)

	go func() {
		_, err := pm.SetPolicy([]byte(bad))
		done <- err
	}()

	select {
	case err := <-done:
		require.ErrorIs(t, err, errPolicyTestsFailed)
	case <-time.After(10 * time.Second):
		t.Fatal("SetPolicy waited for the write lock before evaluating the tests")
	}
}

// TestSetPolicyRejectsFailingTests asserts that SetPolicy is the user-write
// boundary: a policy whose tests fail must be rejected without mutating the
// live PolicyManager. NewPolicyManager (boot path) does not run tests.
func TestSetPolicyRejectsFailingTests(t *testing.T) {
	users := policyTestUsers()
	nodes := policyTestNodes(users)

	good := `{
		"tagOwners": { "tag:server": ["alice@headscale.net"] },
		"acls": [{
			"action": "accept",
			"src": ["alice@headscale.net"],
			"dst": ["tag:server:22"]
		}],
		"tests": [{
			"src": "alice@headscale.net",
			"accept": ["tag:server:22"]
		}]
	}`

	bad := `{
		"tagOwners": { "tag:server": ["alice@headscale.net"] },
		"acls": [{
			"action": "accept",
			"src": ["alice@headscale.net"],
			"dst": ["tag:server:22"]
		}],
		"tests": [{
			"src": "bob@headscale.net",
			"accept": ["tag:server:22"]
		}]
	}`

	pm, err := NewPolicyManager([]byte(good), users, nodes.ViewSlice())
	require.NoError(t, err)

	beforeFilter, _ := pm.Filter()

	changed, err := pm.SetPolicy([]byte(bad))
	require.Error(t, err, "SetPolicy must reject a policy whose tests fail")
	require.False(t, changed, "SetPolicy must report no change when rejected")
	require.ErrorIs(t, err, errPolicyTestsFailed)
	require.Contains(t, err.Error(), "expected ALLOWED")

	afterFilter, _ := pm.Filter()
	require.Len(t, afterFilter, len(beforeFilter), "live filter must not change after a rejected SetPolicy")
}

// TestNewPolicyManagerSkipsTests asserts the boot path does not evaluate
// tests, so a stale stored policy referencing a now-deleted user does not
// stop the server from booting.
func TestNewPolicyManagerSkipsTests(t *testing.T) {
	users := policyTestUsers()
	nodes := policyTestNodes(users)

	// Tests reference "ghost@headscale.net" which doesn't exist. Boot
	// must not error.
	stale := `{
		"acls": [{
			"action": "accept",
			"src": ["*"],
			"dst": ["*:*"]
		}],
		"tests": [{
			"src": "ghost@headscale.net",
			"accept": ["alice-laptop:22"]
		}]
	}`

	pm, err := NewPolicyManager([]byte(stale), users, nodes.ViewSlice())
	require.NoError(t, err, "boot must not run tests")
	require.NotNil(t, pm)

	// And a subsequent SetPolicy of the same body must reject — that's
	// the user-write path.
	_, err = pm.SetPolicy([]byte(stale))
	require.Error(t, err)
	require.ErrorIs(t, err, errPolicyTestsFailed)
}

// TestRunTestsEmptyProtoMatchesDefaultProtocols captures the bug where a
// test entry with no `proto` field fails to match a filter rule whose
// IPProto is restricted to a default protocol (TCP, UDP, ICMP, ICMPv6).
// Tailscale's client default set is {6, 17, 1, 58} when proto is omitted,
// so a TCP-only rule must satisfy an empty-proto test.
//
// The capture
// testdata/policytest_results/policytest-allpass-acls-and-grants-mixed.hujson
// is the captured signal for this same bug (api_response_code 200, two
// passing tests including `tag:client → webserver:80` with no proto over
// a `ip: tcp:80` grant).
func TestRunTestsEmptyProtoMatchesDefaultProtocols(t *testing.T) {
	users := types.Users{
		{ID: 1, Name: "odin", Email: "odin@example.com"},
	}
	nodes := types.Nodes{
		{
			ID:       1,
			Hostname: "client",
			IPv4:     ap("100.64.0.10"),
			IPv6:     ap("fd7a:115c:a1e0::a"),
			Tags:     []string{"tag:client"},
		},
		{
			ID:       2,
			Hostname: "webserver",
			IPv4:     ap("100.64.0.16"),
			IPv6:     ap("fd7a:115c:a1e0::10"),
			Tags:     []string{"tag:server"},
		},
	}

	policy := `{
		"tagOwners": {
			"tag:client": ["odin@example.com"],
			"tag:server": ["odin@example.com"]
		},
		"hosts": {
			"webserver": "100.64.0.16"
		},
		"grants": [
			{"src": ["tag:client"], "dst": ["webserver"], "ip": ["tcp:80"]}
		],
		"tests": [
			{"src": "tag:client", "accept": ["webserver:80"]}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err, "policy must parse and compile")

	require.NoError(t, pm.RunTests(),
		"empty-proto test must match a tcp-only grant rule (TCP is in the client default set)")
}

// TestPolicyTestResultsErrorsRendering checks the multi-line render layout
// since the body becomes the user-facing error.
func TestPolicyTestResultsErrorsRendering(t *testing.T) {
	results := PolicyTestResults{
		AllPassed: false,
		Results: []PolicyTestResult{
			{
				Src:        "alice@headscale.net",
				AcceptFail: []string{"tag:server:22"},
			},
			{
				Src:      "bob@headscale.net",
				Proto:    "tcp",
				DenyFail: []string{"tag:server:443"},
			},
		},
	}

	rendered := results.Errors()
	for _, sub := range []string{
		"alice@headscale.net -> tag:server:22: expected ALLOWED, got DENIED",
		"bob@headscale.net -> tag:server:443 (tcp): expected DENIED, got ALLOWED",
	} {
		assert.Contains(t, rendered, sub)
	}

	// Lines should be newline-separated, not space-joined.
	assert.Equal(t, 2, strings.Count(rendered, "\n")+1, "expected one line per failing assertion")
}

// TestFailureBreakdownIsBounded pins that the rendered breakdown of
// failing tests and sshTests does not grow with label length times
// failures: the policy author sizes both, and the breakdown is also
// rendered at boot.
func TestFailureBreakdownIsBounded(t *testing.T) {
	users := sshTestUsers()
	nodes := sshTestNodes(users)

	const failures = 2000

	name := strings.Repeat("a", 64<<10)
	hosts := `"hosts": {"` + name + `": "100.64.0.1", "gone": "100.64.0.99"},`

	quoted := make([]string, failures)
	for i := range failures {
		quoted[i] = fmt.Sprintf(`"x%d"`, i)
	}

	names := strings.Join(quoted, ",")

	for _, tt := range []struct {
		name, block string
		sentinel    error
	}{
		{
			name: "sshTests dst without node",
			block: `"sshTests": [{"src": "` + name + `", "dst": [` +
				strings.Repeat(`"gone",`, failures) + `], "accept": ["root"]}]`,
			sentinel: errSSHPolicyTestsFailed,
		},
		{
			name: "sshTests accept",
			block: `"sshTests": [{"src": "` + name +
				`", "dst": ["100.64.0.2"], "accept": [` + names + `]}]`,
			sentinel: errSSHPolicyTestsFailed,
		},
		{
			name: "sshTests check",
			block: `"sshTests": [{"src": "` + name +
				`", "dst": ["100.64.0.2"], "check": [` + names + `]}]`,
			sentinel: errSSHPolicyTestsFailed,
		},
		{
			name: "tests accept",
			block: `"tests": [{"src": "` + name + `", "accept": [` +
				strings.Repeat(`"gone:22",`, failures) + `]}]`,
			sentinel: errPolicyTestsFailed,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewPolicyManager([]byte(`{}`), users, nodes.ViewSlice())
			require.NoError(t, err)

			_, err = pm.SetPolicy([]byte(`{"acls": [], ` + hosts + tt.block + `}`))
			require.ErrorIs(t, err, tt.sentinel)
			require.Less(t, len(err.Error()), 100<<10)
			require.True(t, strings.HasSuffix(err.Error(), fmt.Sprintf(
				"... and %d more", failures-maxTestFailureLines,
			)), "error ends with the count")
		})
	}
}

func TestStandIns(t *testing.T) {
	pol, err := ParsePolicy([]byte(`{
		"groups":    {"group:a": ["g@"]},
		"hosts":     {"h": "100.64.0.1", "net": "100.64.0.8/30"},
		"tagOwners": {"tag:t": ["o@"], "tag:u": ["group:a"]},
		"autoApprovers": {
			"routes":   {"10.0.0.0/8": ["r@"]},
			"exitNode": ["e@example.com"]
		},
		"acls": [
			{"action": "accept", "src": ["as@", "user:*@example.com"], "dst": ["ad@:22", "100.64.0.2:22", "100.64.0.0/10:80", "h:22", "net:22"]}
		],
		"grants":    [{"src": ["gs@"], "dst": ["gd@"], "ip": ["*"]}],
		"nodeAttrs": [{"target": ["na@"], "attr": ["randomize-client-port"]}],
		"ssh":       [{"action": "accept", "src": ["ss@"], "dst": ["autogroup:self"], "users": ["root"]}],
		"tests":     [{"src": "ts@", "accept": ["td@:22", "100.64.0.3:22"], "deny": ["tn@:80"]}],
		"sshTests":  [{"src": "xs@", "dst": ["tag:t"], "accept": ["root"]}]
	}`))
	require.NoError(t, err)

	users, nodes := standIns(pol)

	names := make([]string, 0, len(users))
	for i, u := range users {
		require.Equal(t, uint(i+1), u.ID)

		names = append(names, u.Name)
	}

	require.Equal(t, []string{
		"*@example.com", "ad", "as", "e@example.com", "g", "gd", "gs", "na", "o",
		"r", "ss", "td", "tn", "ts", "xs",
	}, names, "one user per user token and per user:*@ domain, sorted")
	require.Equal(t, "e@example.com", users[3].Email)
	require.Empty(t, users[1].Email)

	require.Len(t, nodes, len(users)+2, "one node per user and per tag")

	named := []netip.Prefix{
		mp("100.64.0.0/32"), mp("100.64.0.1/32"), mp("100.64.0.2/32"),
		mp("100.64.0.3/32"), mp("100.64.0.8/30"),
	}
	seen := map[netip.Addr]bool{}

	for i, n := range nodes {
		require.Equal(t, types.NodeID(i+1), n.ID)

		if i < len(users) {
			require.Empty(t, n.Tags)
			require.Equal(t, users[i].ID, *n.UserID)
			require.Equal(t, &users[i], n.User)
		} else {
			require.Equal(t, []string{[]string{"tag:t", "tag:u"}[i-len(users)]}, []string(n.Tags))
			require.Nil(t, n.UserID, "tags own a tagged node")
		}

		require.True(t, mp("100.64.0.0/10").Contains(*n.IPv4))
		require.True(t, mp("fd7a:115c:a1e0::/48").Contains(*n.IPv6))
		require.NotEqual(t, mp("fd7a:115c:a1e0::/48").Addr(), *n.IPv6)

		for _, p := range named {
			require.False(t, p.Contains(*n.IPv4), "%s is named by the policy", n.IPv4)
		}

		require.False(t, seen[*n.IPv4] || seen[*n.IPv6], "addresses are unique")
		seen[*n.IPv4], seen[*n.IPv6] = true, true
	}

	again, againNodes := standIns(pol)
	require.Equal(t, users, again)
	require.Len(t, againNodes, len(nodes))

	for i := range nodes {
		require.Equal(t, *nodes[i].IPv4, *againNodes[i].IPv4, "stable addresses")
	}

	t.Run("user:*@domain", func(t *testing.T) {
		b := []byte(`{
			"acls":  [{"action": "accept", "src": ["alice@"], "dst": ["user:*@example.com:22"]}],
			"tests": [{"src": "alice@", "accept": ["user:*@example.com:22"]}]
		}`)

		pol, err := ParsePolicy(b)
		require.NoError(t, err)

		users, _ := standIns(pol)

		var inDomain []string

		for _, u := range users {
			if strings.HasSuffix(u.Email, "@example.com") {
				inDomain = append(inDomain, u.Email)
			}
		}

		require.Len(t, inDomain, 1, "one stand-in in the domain")
		require.NoError(t, CheckPolicy(b), "the test reaches the domain's stand-in")
	})
}

func TestCheckPolicy(t *testing.T) {
	const acl = `"acls": [{"action": "accept", "src": ["alice@"], "dst": ["tag:web:22"]}],
		"tagOwners": {"tag:web": ["alice@"]}`

	for _, tt := range []struct {
		name    string
		policy  string
		wantErr error
	}{
		{"empty", ``, ErrPolicyEmpty},
		{"no tests", `{` + acl + `}`, nil},
		{"tests pass", `{` + acl + `, "tests": [{"src": "alice@", "accept": ["tag:web:22"], "deny": ["tag:web:80"]}]}`, nil},
		{"tests fail", `{` + acl + `, "tests": [{"src": "bob@", "accept": ["tag:web:22"]}]}`, errPolicyTestsFailed},
		{"sshTests pass", `{` + acl + `, "ssh": [{"action": "accept", "src": ["alice@"], "dst": ["tag:web"], "users": ["root"]}],
			"sshTests": [{"src": "alice@", "dst": ["tag:web"], "accept": ["root"]}]}`, nil},
		{"sshTests fail", `{` + acl + `, "sshTests": [{"src": "alice@", "dst": ["tag:web"], "accept": ["root"]}]}`, errSSHPolicyTestsFailed},
		{"undefined group", `{"acls": [{"action": "accept", "src": ["group:x"], "dst": ["*:*"]}]}`, ErrGroupNotDefined},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckPolicy([]byte(tt.policy))
			if tt.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}
