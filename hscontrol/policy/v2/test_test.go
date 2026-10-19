package v2

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
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
				Proto:    ProtocolNameTCP,
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

func TestPolicyTestTypedIngress(t *testing.T) {
	for _, input := range []string{
		`{"src":"alice@","accept":["tag:server:443"],"deny":["[fd7a:115c:a1e0::2]:22"],"proto":"6"}`,
		`{"src":"group:team","accept":["100.64.0.1:80-90"]}`,
		`{"src":"100.64.0.1","accept":["server:80,443"]}`,
		`{"src":"fd7a:115c:a1e0::1","accept":["server:*"]}`,
		`{"src":"user\"name@","accept":["host\"name:443"]}`,
	} {
		t.Run(input, func(t *testing.T) {
			var test PolicyTest
			require.NoError(t, json.Unmarshal([]byte(input), &test))
			_, typedSource := any(test.Src).(Alias)
			require.True(t, typedSource, "source must be decoded before evaluation")

			_, typedDestinations := any(test.Accept).([]AliasWithPorts)
			require.True(t, typedDestinations, "destinations must be decoded before evaluation")

			encoded, err := json.Marshal(test)
			require.NoError(t, err)

			var roundTrip PolicyTest
			require.NoError(t, json.Unmarshal(encoded, &roundTrip))
			assert.Equal(t, test, roundTrip)
		})
	}

	for _, input := range []string{
		`{"src":"bad:selector","accept":["server:443"]}`,
		`{"src":"alice@","accept":["server"]}`,
		`{"src":"alice@","accept":["server:65536"]}`,
		`{"src":"alice@","accept":["[bad]:443"]}`,
	} {
		var test PolicyTest
		require.Error(t, json.Unmarshal([]byte(input), &test), input)
	}
}

func TestRuleMatchesProtoDoesNotWrap(t *testing.T) {
	for _, invalid := range []int{-250, 262} {
		assert.False(t, ruleMatchesProto(tailcfg.FilterRule{IPProto: []int{invalid}}, []ipproto.Proto{ipproto.TCP}))
	}
}

func TestRunPolicyTestEmptySource(t *testing.T) {
	result := runPolicyTest(PolicyTest{}, &Policy{}, nil, nil, types.Nodes{}.ViewSlice())
	assert.False(t, result.Passed)
	require.Len(t, result.Errors, 1)
	assert.Contains(t, result.Errors[0], ErrInvalidAlias.Error())
}

func TestTypedPolicyTestDiagnosticJSON(t *testing.T) {
	users := types.Users{{ID: 1, Name: `alice"quoted`}}
	nodes := types.Nodes{{User: &users[0], IPv4: ap("100.64.0.1")}}.ViewSlice()
	pol := &Policy{Hosts: Hosts{`host"quoted`: p("100.64.0.2/32")}}

	var test PolicyTest
	require.NoError(t, json.Unmarshal([]byte(`{"src":"alice\"quoted@","proto":"6","accept":["host\"quoted:443"]}`), &test))
	result := runPolicyTest(test, pol, []tailcfg.FilterRule{{
		SrcIPs:   []string{"100.64.0.1"},
		DstPorts: []tailcfg.NetPortRange{{IP: "100.64.0.2", Ports: tailcfg.PortRange{First: 443, Last: 443}}},
		IPProto:  []int{6},
	}}, users, nodes)
	require.True(t, result.Passed, result.Errors)
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	assert.JSONEq(t, `{"src":"alice\"quoted@","proto":"tcp","passed":true,"accept_ok":["host\"quoted:443"]}`, string(encoded))
}

func TestOmittedRuleProtocolsExcludeGREAndSCTP(t *testing.T) {
	for _, protocol := range []ipproto.Proto{47, 132} {
		assert.False(t, ruleMatchesProto(tailcfg.FilterRule{}, []ipproto.Proto{protocol}))
		assert.True(t, ruleMatchesProto(tailcfg.FilterRule{IPProto: []int{int(protocol)}}, []ipproto.Proto{protocol}))
	}

	for _, protocol := range Protocol(0).IPProtocols() {
		assert.True(t, ruleMatchesProto(tailcfg.FilterRule{}, []ipproto.Proto{protocol}))
	}
}
