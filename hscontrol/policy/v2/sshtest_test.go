package v2

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSHRulesStableOrderAndOwnership(t *testing.T) {
	users := sshTestUsers()
	nodes := sshTestNodes(users)
	pol, err := unmarshalPolicy([]byte(`{
		"tagOwners": {"tag:server": ["alice@"]},
		"ssh": [
			{"action":"accept", "src":["alice@"], "dst":["tag:server"], "users":["root"], "acceptEnv":["ACCEPT"]},
			{"action":"check", "src":["alice@"], "dst":["tag:server"], "users":["root"], "acceptEnv":["DEFAULT"]},
			{"action":"check", "src":["alice@"], "dst":["tag:server"], "users":["root"], "acceptEnv":["ALWAYS"], "checkPeriod":"always"},
			{"action":"check", "src":["alice@"], "dst":["tag:server"], "users":["root"], "acceptEnv":["EXPLICIT"], "checkPeriod":"2h"}
		]
	}`))
	require.NoError(t, err)
	compiled, err := pol.compileSSHRules(users, nodes[2].View(), nodes.ViewSlice())
	require.NoError(t, err)

	pol.SSHs[1].AcceptEnv[0] = "CHANGED"
	pol.SSHs[1].Users[0] = "nobody"
	wire := compiled.toTailcfg("https://first")
	require.Len(t, wire.Rules, 4)

	for i, want := range []string{"DEFAULT", "ALWAYS", "EXPLICIT", "ACCEPT"} {
		assert.Equal(t, []string{want}, wire.Rules[i].AcceptEnv)
		assert.Zero(t, wire.Rules[i].Action.SessionDuration)
	}

	assert.True(t, wire.Rules[3].Action.Accept)

	period, ok := compiled.checkParams(nodes[0].View(), "root")
	assert.True(t, ok)
	assert.Equal(t, 12*time.Hour, period)

	wire.Rules[0].SSHUsers["root"] = ""
	wire.Rules[0].Principals[0].NodeIP = "192.0.2.1"
	wire.Rules[0].Action.Accept = true
	wire.Rules[0].Action.HoldAndDelegate = "changed"
	wire.Rules[0].AcceptEnv[0] = "changed"
	wire.Rules = nil
	reach, check, err := compiled.reachableSets("root")
	require.NoError(t, err)
	assert.True(t, reach.Contains(*nodes[0].IPv4))
	assert.True(t, check.Contains(*nodes[0].IPv4))

	again := compiled.toTailcfg("https://second")
	require.Len(t, again.Rules, 4)
	assert.Equal(t, "root", again.Rules[0].SSHUsers["root"])
	assert.Equal(t, "100.64.0.1", again.Rules[0].Principals[0].NodeIP)
	assert.Equal(t, []string{"DEFAULT"}, again.Rules[0].AcceptEnv)
	assert.False(t, again.Rules[0].Action.Accept)
	assert.Equal(
		t,
		"https://second/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID?local_user=$LOCAL_USER",
		again.Rules[0].Action.HoldAndDelegate,
	)
}

func TestSSHRulesEmptyPolicyRevokesAccess(t *testing.T) {
	for _, pol := range []*Policy{nil, {}} {
		compiled, err := pol.compileSSHRules(
			nil,
			types.NodeView{},
			types.Nodes{}.ViewSlice(),
		)
		require.NoError(t, err)

		wire := compiled.toTailcfg("")
		require.NotNil(t, wire)
		require.NotNil(t, wire.Rules)
		assert.Empty(t, wire.Rules)

		reach, check, err := compiled.reachableSets("root")
		require.NoError(t, err)
		assert.True(t, reach.IsEmpty())
		assert.True(t, check.IsEmpty())
	}
}

func TestSSHRulesWireAddressIdentity(t *testing.T) {
	for _, addr := range []string{"192.0.2.1", "::ffff:192.0.2.1", "fe80::1%eth0"} {
		t.Run(addr, func(t *testing.T) {
			compiled := sshPolicy{rules: []sshRule{{
				principals: []netip.Addr{netip.MustParseAddr(addr)},
				users:      map[string]string{"root": "root"},
				action:     SSHActionAccept,
			}}}
			wire := compiled.toTailcfg("")
			require.Len(t, wire.Rules, 1)
			require.Len(t, wire.Rules[0].Principals, 1)
			assert.Equal(t, addr, wire.Rules[0].Principals[0].NodeIP)

			for _, action := range []SSHAction{SSHActionAccept, SSHActionCheck} {
				compiled.rules[0].action = action
				reach, check, err := compiled.reachableSets("root")
				require.NoError(t, err)

				for _, source := range []string{
					"192.0.2.1", "::ffff:192.0.2.1", "fe80::1",
				} {
					ip := netip.MustParseAddr(source)
					assert.Equal(t, addr == source, reach.Contains(ip))
					assert.Equal(t, addr == source && action == SSHActionCheck,
						check.Contains(ip))
				}
			}
		})
	}
}

func TestSSHRulesReachableSets(t *testing.T) {
	t.Parallel()

	compiled := sshPolicy{rules: []sshRule{
		{
			principals: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			users:      map[string]string{"root": "root"},
			action:     SSHActionAccept,
		},
		{
			principals: []netip.Addr{
				netip.MustParseAddr("::ffff:192.0.2.1"),
				netip.MustParseAddr("2001:db8::1"),
			},
			users:  map[string]string{"root": "root"},
			action: SSHActionCheck,
		},
	}}
	reach, check, err := compiled.reachableSets("root")
	require.NoError(t, err)
	assert.Equal(t, []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("::ffff:192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	}, slices.Collect(reach.Addrs()))
	assert.Equal(t, compiled.rules[1].principals, slices.Collect(check.Addrs()))

	reach, check, err = compiled.reachableSets("nobody")
	require.NoError(t, err)
	assert.True(t, reach.IsEmpty())
	assert.True(t, check.IsEmpty())

	compiled.rules[0].principals = []netip.Addr{{}}
	_, _, err = compiled.reachableSets("root")
	require.Error(t, err)
}

func TestSSHTestsSourceSetAssertions(t *testing.T) {
	t.Parallel()

	users := sshTestUsers()
	nodes := sshTestNodes(users)
	src, err := parseAlias("192.0.2.0/30")
	require.NoError(t, err)
	source, _, err := resolveSSHTestSource(src, nil, nil, nodes.ViewSlice())
	require.NoError(t, err)

	for _, tt := range []struct {
		name            string
		accept          []string
		check           []string
		wantAccept      bool
		wantDeny        bool
		wantCheck       bool
		wantCheckReason string
	}{
		{
			name:       "all covered by accept and check",
			accept:     []string{"192.0.2.2", "192.0.2.3"},
			check:      []string{"192.0.2.0", "192.0.2.1"},
			wantAccept: true, wantCheckReason: "ALLOWED via accept",
		},
		{
			name: "all checked",
			check: []string{
				"192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3",
			},
			wantAccept: true, wantCheck: true,
		},
		{
			name:            "first unchecked address denied before accepted address",
			accept:          []string{"192.0.2.2"},
			check:           []string{"192.0.2.0"},
			wantCheckReason: "DENIED",
		},
		{
			name:            "first unchecked address accepted before denied address",
			accept:          []string{"192.0.2.0"},
			check:           []string{"192.0.2.1"},
			wantCheckReason: "ALLOWED via accept",
		},
		{
			name: "none allowed", wantDeny: true, wantCheckReason: "DENIED",
		},
		{
			name:   "last address allowed",
			accept: []string{"192.0.2.3"}, wantCheckReason: "DENIED",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var compiled sshPolicy

			for _, rule := range []struct {
				action SSHAction
				addrs  []string
			}{
				{SSHActionAccept, tt.accept},
				{SSHActionCheck, tt.check},
			} {
				var principals []netip.Addr
				for _, addr := range rule.addrs {
					principals = append(principals, netip.MustParseAddr(addr))
				}

				compiled.rules = append(compiled.rules, sshRule{
					principals: principals,
					users:      map[string]string{"root": "root"},
					action:     rule.action,
				})
			}

			dst := nodes[2].View()
			cache := map[types.NodeID]sshPolicy{dst.ID(): compiled}

			for _, assertion := range []struct {
				kind     sshAssertion
				pass     bool
				acceptOK bool
			}{
				{assertAccept, tt.wantAccept, tt.wantAccept},
				{assertDeny, tt.wantDeny, false},
				{assertCheck, tt.wantCheck, tt.wantCheckReason == "ALLOWED via accept"},
			} {
				result := SSHPolicyTestResult{Passed: true}
				evaluateAssertion(nil, users, nodes.ViewSlice(), cache,
					source, []types.NodeView{dst}, "root", assertion.kind, &result)
				assert.Equal(t, assertion.pass, result.Passed, "kind %v", assertion.kind)
				assert.Empty(t, result.Errors)

				var wantAcceptOK map[string][]string
				if assertion.acceptOK {
					wantAcceptOK = map[string][]string{"root": {dst.Hostname()}}
				}

				assert.Equal(t, wantAcceptOK, result.AcceptOK, "kind %v", assertion.kind)

				if assertion.kind == assertCheck && !tt.wantCheck {
					assert.Equal(t, tt.wantCheckReason,
						checkFailReason(result, "root", dst.Hostname()))
				}
			}
		})
	}
}

func TestCompileSSHRulesInvalidAction(t *testing.T) {
	t.Parallel()

	users := sshTestUsers()
	nodes := sshTestNodes(users)
	pol := &Policy{SSHs: []SSH{{
		Action:       SSHAction("invalid"),
		Sources:      SSHSrcAliases{new(Username("alice@"))},
		Destinations: SSHDstAliases{tp("tag:server")},
		Users:        SSHUsers{"root"},
	}}}
	_, err := pol.compileSSHRules(users, nodes[2].View(), nodes.ViewSlice())
	require.ErrorIs(t, err, ErrSSHActionInvalid)
	assert.NotContains(t, err.Error(), "%!w")
}

func TestSSHTestsWideSourceBounded(t *testing.T) {
	const helperEnv = "HEADSCALE_SSH_WIDE_SOURCE_TEST"
	if os.Getenv(helperEnv) == "" {
		// A regressed address walk must terminate with the child, not leak a goroutine.
		binary, err := os.Executable()
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, binary,
			"-test.run=^TestSSHTestsWideSourceBounded$", "-test.timeout=8s")

		cmd.Env = append(os.Environ(), helperEnv+"=1")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", output)

		return
	}

	users := sshTestUsers()
	nodes := sshTestNodes(users)

	for _, source := range []string{"::/0", "*"} {
		t.Run(source, func(t *testing.T) {
			src, err := parseAlias(source)
			require.NoError(t, err)

			result := runSSHPolicyTest(SSHPolicyTest{
				Src:    src,
				Dst:    SSHTestDestinations{tp("tag:server")},
				Accept: []SSHUser{"root"},
				Deny:   []SSHUser{"root"},
				Check:  []SSHUser{"root"},
			}, &Policy{}, users, nodes.ViewSlice(), make(map[types.NodeID]sshPolicy))
			assert.False(t, result.Passed)
			assert.Empty(t, result.Errors)
			assert.Equal(t, map[string][]string{"root": {"server"}}, result.AcceptFail)
			assert.Equal(t, map[string][]string{"root": {"server"}}, result.DenyOK)
			assert.Equal(t, map[string][]string{"root": {"server"}}, result.CheckFail)
			assert.Empty(t, result.AcceptOK)
		})
	}
}

func TestResolveSSHTestSourceAddressIteration(t *testing.T) {
	for _, test := range []struct {
		prefix string
		want   []string
	}{
		{"255.255.255.254/31", []string{"255.255.255.254", "255.255.255.255"}},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127", []string{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}},
	} {
		t.Run(test.prefix, func(t *testing.T) {
			src, err := parseAlias(test.prefix)
			require.NoError(t, err)
			addrs, _, err := resolveSSHTestSource(
				src,
				nil,
				nil,
				types.Nodes{}.ViewSlice(),
			)
			require.NoError(t, err)

			var got []string
			for addr := range addrs.Addrs() {
				got = append(got, addr.String())
				require.LessOrEqual(t, len(got), len(test.want))
			}

			assert.Equal(t, test.want, got)
		})
	}

	src, err := parseAlias("::/0")
	require.NoError(t, err)
	addrs, _, err := resolveSSHTestSource(src, nil, nil, types.Nodes{}.ViewSlice())
	require.NoError(t, err)

	calls := 0

	addrs.Addrs()(func(addr netip.Addr) bool {
		calls++

		assert.Equal(t, netip.IPv6Unspecified(), addr)

		return false
	})
	assert.Equal(t, 1, calls)

	users := sshTestUsers()
	nodes := sshTestNodes(users)
	result := runSSHPolicyTest(SSHPolicyTest{
		Src:    src,
		Dst:    SSHTestDestinations{tp("tag:server")},
		Accept: []SSHUser{"root"},
	}, &Policy{}, users, nodes.ViewSlice(), make(map[types.NodeID]sshPolicy))
	assert.False(t, result.Passed)
	assert.Equal(t, map[string][]string{"root": {"server"}}, result.AcceptFail)
}

func TestSSHRulesSelectRegisteredDevices(t *testing.T) {
	users := sshTestUsers()
	nodes := sshTestNodes(users)
	nodes[2].Tags = []string{"tag:server", "tag:prod"}
	pol := &Policy{SSHs: []SSH{{
		Action:       SSHActionAccept,
		Sources:      SSHSrcAliases{new(Prefix(netip.MustParsePrefix("0.0.0.0/0")))},
		Destinations: SSHDstAliases{tp("tag:server")},
		Users:        SSHUsers{"autogroup:nonroot", "localpart:*@headscale.net"},
	}}}
	compiled, err := pol.compileSSHRules(users, nodes[2].View(), nodes.ViewSlice())
	require.NoError(t, err)

	wire := compiled.toTailcfg("")
	require.Len(t, wire.Rules, 6)
	assert.Equal(t, map[string]string{"alice": "alice"}, wire.Rules[1].SSHUsers)
	assert.Equal(t, map[string]string{"bob": "bob"}, wire.Rules[3].SSHUsers)
	assert.Equal(
		t,
		[]netip.Addr{*nodes[0].IPv4, *nodes[3].IPv4, *nodes[0].IPv6, *nodes[3].IPv6},
		compiled.rules[0].principals,
	)
	assert.Equal(
		t,
		[]netip.Addr{
			*nodes[2].IPv4,
			*nodes[2].IPv6,
			*nodes[2].IPv4,
			*nodes[2].IPv6,
			*nodes[5].IPv4,
			*nodes[5].IPv6,
		},
		compiled.rules[5].principals,
	)
	assert.False(
		t,
		slices.Contains(compiled.rules[0].principals, *nodes[2].IPv4),
		"tagged creator is not an owner",
	)
	reach, check, err := compiled.reachableSets("alice")
	require.NoError(t, err)
	assert.True(
		t,
		reach.Contains(*nodes[0].IPv6),
		"selecting one family includes the registered device's other address",
	)
	assert.True(t, check.IsEmpty())
}

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
		{ID: 1, Name: "alice", Email: "alice@headscale.net"},
		{ID: 2, Name: "bob", Email: "bob@headscale.net"},
		{ID: 3, Name: "thor", Email: "thor@example.org"},
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
			// Rules tolerate unregistered users; a test naming one fails.
			name: "unknown-src-user",
			policy: `{
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [{
					"action": "accept",
					"src":    ["alice@headscale.net"],
					"dst":    ["tag:server"],
					"users":  ["root"]
				}],
				"sshTests": [{
					"src":    "ghost@headscale.net",
					"dst":    ["tag:server"],
					"accept": ["root"]
				}]
			}`,
			wantPass:   false,
			wantErrSub: []string{"ghost@headscale.net", "failed to resolve source"},
		},
		{
			// A group tolerates unregistered members like any rule (#3513).
			name: "group-src-with-unregistered-member",
			policy: `{
				"groups": {"group:eng": ["alice@headscale.net", "ghost@headscale.net"]},
				"tagOwners": { "tag:server": ["alice@headscale.net"] },
				"ssh": [{
					"action": "accept",
					"src":    ["group:eng"],
					"dst":    ["tag:server"],
					"users":  ["root"]
				}],
				"sshTests": [{
					"src":    "group:eng",
					"dst":    ["tag:server"],
					"accept": ["root"]
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
