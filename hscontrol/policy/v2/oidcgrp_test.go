package v2

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

// mockOIDCGroupResolver implements OIDCGroupResolver for testing.
type mockOIDCGroupResolver struct {
	groups map[string][]types.User
}

func (m *mockOIDCGroupResolver) GetUsersByOIDCGroup(groupName string) ([]types.User, error) {
	return m.groups[groupName], nil
}

// TestGroupResolveFromOIDC tests that group:<name> resolves users from
// the OIDC resolver when the group is not defined in the policy's Groups map.
func TestGroupResolveFromOIDC(t *testing.T) {
	user1 := types.User{Model: gorm.Model{ID: 1}, Name: "alice"}
	user2 := types.User{Model: gorm.Model{ID: 2}, Name: "bob"}

	resolver := &mockOIDCGroupResolver{
		groups: map[string][]types.User{
			"engineering": {user1, user2},
		},
	}

	// Policy uses group:engineering but does NOT define it in the groups section.
	// The group is resolved from OIDC only.
	policyJSON := []byte(`{
		"acls": [{
			"action": "accept",
			"src": ["group:engineering"],
			"dst": ["*:*"]
		}]
	}`)

	users := types.Users{user1, user2}

	node1 := &types.Node{
		Hostname: "node1",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   &user1.ID,
		User:     &user1,
	}
	node2 := &types.Node{
		Hostname: "node2",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   &user2.ID,
		User:     &user2,
	}

	nodes := types.Nodes{node1, node2}

	pm, err := NewPolicyManager(nil, users, nodes.ViewSlice())
	require.NoError(t, err)

	pm.SetOIDCGroupResolver(resolver)

	changed, err := pm.SetPolicy(policyJSON)
	require.NoError(t, err)
	assert.True(t, changed)

	// Verify alice's filter rules have both engineering members as sources.
	rules, err := pm.FilterForNode(node1.View())
	require.NoError(t, err)
	assert.NotEmpty(t, rules, "alice (in OIDC engineering) should have filter rules")
	assertFilterRulesContainDstIP(t, rules, netip.MustParseAddr("100.64.0.2"))

	require.NotEmpty(t, rules[0].SrcIPs)
	srcStr := strings.Join(rules[0].SrcIPs, ",")
	assert.Contains(t, srcStr, "100.64.0.1")
	assert.Contains(t, srcStr, "100.64.0.2")
}

// TestGroupResolveFromLocalPolicy tests that group:<name> resolves users
// from the policy-defined Groups map (local membership).
func TestGroupResolveFromLocalPolicy(t *testing.T) {
	user1 := types.User{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@headscale.local"}
	user2 := types.User{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@headscale.local"}

	// Policy defines the group locally.
	policyJSON := []byte(`{
		"groups": {
			"group:engineering": ["alice@headscale.local", "bob@headscale.local"]
		},
		"acls": [{
			"action": "accept",
			"src": ["group:engineering"],
			"dst": ["*:*"]
		}]
	}`)

	users := types.Users{user1, user2}

	node1 := &types.Node{
		Hostname: "node1",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   &user1.ID,
		User:     &user1,
	}
	node2 := &types.Node{
		Hostname: "node2",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   &user2.ID,
		User:     &user2,
	}

	nodes := types.Nodes{node1, node2}

	pm, err := NewPolicyManager(nil, users, nodes.ViewSlice())
	require.NoError(t, err)

	changed, err := pm.SetPolicy(policyJSON)
	require.NoError(t, err)
	assert.True(t, changed)

	// Verify alice's filter rules have both engineering members as sources.
	rules, err := pm.FilterForNode(node1.View())
	require.NoError(t, err)
	assert.NotEmpty(t, rules, "alice (in local engineering) should have filter rules")
	assertFilterRulesContainDstIP(t, rules, netip.MustParseAddr("100.64.0.2"))

	require.NotEmpty(t, rules[0].SrcIPs)
	srcStr := strings.Join(rules[0].SrcIPs, ",")
	assert.Contains(t, srcStr, "100.64.0.1")
	assert.Contains(t, srcStr, "100.64.0.2")
}

// TestGroupResolveFromBothSources tests that group:<name> resolves users from
// BOTH local and OIDC sources when the same group name exists in both.
func TestGroupResolveFromBothSources(t *testing.T) {
	// Local: bob -> engineering
	// OIDC:  alice -> engineering
	// group:engineering should include both.
	userAlice := types.User{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@headscale.local"}
	userBob := types.User{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@headscale.local"}
	userCharlie := types.User{Model: gorm.Model{ID: 3}, Name: "charlie", Email: "charlie@headscale.local"}

	resolver := &mockOIDCGroupResolver{
		groups: map[string][]types.User{
			"engineering": {userAlice},
		},
	}

	// Policy defines bob in the local engineering group.
	policyJSON := []byte(`{
		"groups": {
			"group:engineering": ["bob@headscale.local"]
		},
		"acls": [{
			"action": "accept",
			"src": ["group:engineering"],
			"dst": ["*:*"]
		}]
	}`)

	users := types.Users{userAlice, userBob, userCharlie}

	nodeAlice := &types.Node{
		Hostname: "node-alice",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   &userAlice.ID,
		User:     &userAlice,
	}
	nodeBob := &types.Node{
		Hostname: "node-bob",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   &userBob.ID,
		User:     &userBob,
	}
	nodeCharlie := &types.Node{
		Hostname: "node-charlie",
		IPv4:     createAddr("100.64.0.3"),
		UserID:   &userCharlie.ID,
		User:     &userCharlie,
	}

	nodes := types.Nodes{nodeAlice, nodeBob, nodeCharlie}

	pm, err := NewPolicyManager(nil, users, nodes.ViewSlice())
	require.NoError(t, err)

	pm.SetOIDCGroupResolver(resolver)

	changed, err := pm.SetPolicy(policyJSON)
	require.NoError(t, err)
	assert.True(t, changed)

	// alice (OIDC member) should have filter rules.
	rules, err := pm.FilterForNode(nodeAlice.View())
	require.NoError(t, err)
	assert.NotEmpty(t, rules, "alice (OIDC engineering member) should have filter rules")

	// bob (local member) should have filter rules.
	rules, err = pm.FilterForNode(nodeBob.View())
	require.NoError(t, err)
	assert.NotEmpty(t, rules, "bob (local engineering member) should have filter rules")

	// charlie (not a member) should NOT have the engineering source IPs.
	rules, err = pm.FilterForNode(nodeCharlie.View())
	require.NoError(t, err)
	// charlie should not appear in any engineering-src rule as a source.
	for _, rule := range rules {
		for _, srcIP := range rule.SrcIPs {
			assert.NotContains(t, srcIP, "100.64.0.3", "charlie should not be in engineering source IPs")
		}
	}
}

// TestGroupDeduplication tests that a user in both local and OIDC membership
// is not counted twice (no duplicate nodes/rules).
func TestGroupDeduplication(t *testing.T) {
	// bob is in engineering via BOTH local and OIDC.
	userBob := types.User{Model: gorm.Model{ID: 1}, Name: "bob", Email: "bob@headscale.local"}

	resolver := &mockOIDCGroupResolver{
		groups: map[string][]types.User{
			"engineering": {userBob},
		},
	}

	policyJSON := []byte(`{
		"groups": {
			"group:engineering": ["bob@headscale.local"]
		},
		"acls": [{
			"action": "accept",
			"src": ["group:engineering"],
			"dst": ["*:*"]
		}]
	}`)

	users := types.Users{userBob}

	nodeBob := &types.Node{
		Hostname: "node-bob",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   &userBob.ID,
		User:     &userBob,
	}

	nodes := types.Nodes{nodeBob}

	pm, err := NewPolicyManager(nil, users, nodes.ViewSlice())
	require.NoError(t, err)

	pm.SetOIDCGroupResolver(resolver)

	changed, err := pm.SetPolicy(policyJSON)
	require.NoError(t, err)
	assert.True(t, changed)

	// Verify bob appears exactly once in the source IPs.
	rules, err := pm.FilterForNode(nodeBob.View())
	require.NoError(t, err)
	require.NotEmpty(t, rules)

	srcStr := strings.Join(rules[0].SrcIPs, ",")
	// The IP 100.64.0.1 should appear exactly once.
	count := strings.Count(srcStr, "100.64.0.1")
	assert.Equal(t, 1, count, "bob's IP should appear exactly once (no duplicate)")
}

// TestGroupResolveEmptyOIDCGroup tests that group: with no OIDC members
// resolves to nothing when not defined locally.
func TestGroupResolveEmptyOIDCGroup(t *testing.T) {
	resolver := &mockOIDCGroupResolver{
		groups: map[string][]types.User{},
	}

	policyJSON := []byte(`{
		"acls": [{
			"action": "accept",
			"src": ["group:empty-group"],
			"dst": ["*:*"]
		}]
	}`)

	user := types.User{Model: gorm.Model{ID: 1}, Name: "testuser"}
	users := types.Users{user}
	node := &types.Node{
		Hostname: "node1",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   &user.ID,
		User:     &user,
	}
	nodes := types.Nodes{node}

	pm, err := NewPolicyManager(nil, users, nodes.ViewSlice())
	require.NoError(t, err)

	pm.SetOIDCGroupResolver(resolver)

	changed, err := pm.SetPolicy(policyJSON)
	require.NoError(t, err)
	assert.True(t, changed)

	// With no matching users in either source, no rules should match.
	rules, err := pm.FilterForNode(node.View())
	require.NoError(t, err)
	assert.Empty(t, rules)
}

// TestGroupResolveNoResolver tests that group: works gracefully when
// the OIDC resolver is not set (no OIDC configured).
func TestGroupResolveNoResolver(t *testing.T) {
	policyJSON := []byte(`{
		"acls": [{
			"action": "accept",
			"src": ["group:some-group"],
			"dst": ["*:*"]
		}]
	}`)

	user := types.User{Model: gorm.Model{ID: 1}, Name: "testuser"}
	users := types.Users{user}
	node := &types.Node{
		Hostname: "node1",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   &user.ID,
		User:     &user,
	}
	nodes := types.Nodes{node}

	pm, err := NewPolicyManager(nil, users, nodes.ViewSlice())
	require.NoError(t, err)

	// SetPolicy should succeed (no group: defined, no resolver).
	_, err = pm.SetPolicy(policyJSON)
	require.NoError(t, err)

	// FilterForNode should return empty rules since the group has no members.
	rules, err := pm.FilterForNode(node.View())
	require.NoError(t, err)
	assert.Empty(t, rules)
}

// TestSetOIDCGroupResolver tests that SetOIDCGroupResolver properly injects
// the resolver and triggers recompilation.
func TestSetOIDCGroupResolver(t *testing.T) {
	resolver := &mockOIDCGroupResolver{
		groups: map[string][]types.User{
			"engineering": {
				{Model: gorm.Model{ID: 1}, Name: "alice"},
			},
		},
	}

	user := types.User{Model: gorm.Model{ID: 1}, Name: "alice"}
	users := types.Users{user}
	node := &types.Node{
		Hostname: "node1",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   &user.ID,
		User:     &user,
	}
	nodes := types.Nodes{node}

	policyJSON := []byte(`{
		"acls": [{
			"action": "accept",
			"src": ["group:engineering"],
			"dst": ["*:*"]
		}]
	}`)

	pm, err := NewPolicyManager(nil, users, nodes.ViewSlice())
	require.NoError(t, err)

	// Set policy before resolver - should compile but group: won't resolve
	// from OIDC (no resolver set).
	_, err = pm.SetPolicy(policyJSON)
	require.NoError(t, err)

	// Before setting resolver, filter should be empty.
	rules, err := pm.FilterForNode(node.View())
	require.NoError(t, err)
	assert.Empty(t, rules)

	// Set the resolver.
	pm.SetOIDCGroupResolver(resolver)

	// Re-set policy to trigger recompilation with the resolver.
	_, err = pm.SetPolicy(policyJSON)
	require.NoError(t, err)

	// After setting resolver, node should be visible in filter rules.
	rules, err = pm.FilterForNode(node.View())
	require.NoError(t, err)
	assert.NotEmpty(t, rules)
}

// TestIsOIDCGroup tests the isOIDCGroup helper (internal only).
func TestIsOIDCGroup(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"oidcgrp:engineering", true},
		{"oidcgrp:", true},
		{"group:engineering", false},
		{"autogroup:member", false},
		{"tag:server", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, isOIDCGroup(tt.input))
		})
	}
}

// TestOIDCGroupNotInParseAlias verifies that oidcgrp: is NOT parsed as a
// valid alias in the public policy syntax. Only group: is valid.
func TestOIDCGroupNotInParseAlias(t *testing.T) {
	// oidcgrp: should fail to parse (it's not a valid alias).
	_, err := parseAlias("oidcgrp:engineering")
	assert.Error(t, err, "oidcgrp: should not be a valid alias in policy syntax")

	// group: should parse correctly.
	alias, err := parseAlias("group:engineering")
	require.NoError(t, err)
	_, ok := alias.(*Group)
	assert.True(t, ok, "group: should parse as *Group")
}

// TestGroupResolveOIDCOnlyVsLocalOnly tests two different groups where one
// is defined only in OIDC and the other only locally.
func TestGroupResolveOIDCOnlyVsLocalOnly(t *testing.T) {
	userAlice := types.User{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@headscale.local"}
	userBob := types.User{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@headscale.local"}

	resolver := &mockOIDCGroupResolver{
		groups: map[string][]types.User{
			"oidc-team": {userAlice},
		},
	}

	// "local-team" is defined only in the policy, "oidc-team" only via OIDC.
	policyJSON := []byte(`{
		"groups": {
			"group:local-team": ["bob@headscale.local"]
		},
		"acls": [
			{
				"action": "accept",
				"src": ["group:local-team"],
				"dst": ["*:22"]
			},
			{
				"action": "accept",
				"src": ["group:oidc-team"],
				"dst": ["*:443"]
			}
		]
	}`)

	users := types.Users{userAlice, userBob}

	nodeAlice := &types.Node{
		Hostname: "node-alice",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   &userAlice.ID,
		User:     &userAlice,
	}
	nodeBob := &types.Node{
		Hostname: "node-bob",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   &userBob.ID,
		User:     &userBob,
	}

	nodes := types.Nodes{nodeAlice, nodeBob}

	pm, err := NewPolicyManager(nil, users, nodes.ViewSlice())
	require.NoError(t, err)

	pm.SetOIDCGroupResolver(resolver)

	changed, err := pm.SetPolicy(policyJSON)
	require.NoError(t, err)
	assert.True(t, changed)

	// alice (OIDC-only member of oidc-team) can access port 443.
	rules, err := pm.FilterForNode(nodeAlice.View())
	require.NoError(t, err)
	require.NotEmpty(t, rules, "alice should have rules for oidc-team")
	// Alice's rules should include port 443 destinations.
	aliceHas443 := false
	for _, rule := range rules {
		for _, dst := range rule.DstPorts {
			if strings.Contains(dst.Ports.String(), "443") {
				aliceHas443 = true
			}
		}
	}
	assert.True(t, aliceHas443, "alice's rules should include port 443 destinations")

	// bob (local-only member of local-team) can access port 22.
	rules, err = pm.FilterForNode(nodeBob.View())
	require.NoError(t, err)
	require.NotEmpty(t, rules, "bob should have rules for local-team")
	// Bob's rules should include port 22 destinations.
	bobHas22 := false
	for _, rule := range rules {
		for _, dst := range rule.DstPorts {
			if strings.Contains(dst.Ports.String(), "22") {
				bobHas22 = true
			}
		}
	}
	assert.True(t, bobHas22, "bob's rules should include port 22 destinations")
}

// --- helpers ---

func assertFilterRulesContainDstIP(t *testing.T, rules []tailcfg.FilterRule, addr netip.Addr) {
	t.Helper()
	for _, rule := range rules {
		for _, dst := range rule.DstPorts {
			if dst.IP == "*" {
				return
			}
			prefix, err := netip.ParsePrefix(dst.IP)
			if err != nil {
				addrParsed, err2 := netip.ParseAddr(dst.IP)
				if err2 == nil && addrParsed == addr {
					return
				}
				continue
			}
			if prefix.Addr() == addr {
				return
			}
		}
	}
	t.Errorf("expected filter rules to contain destination IP %s, but they don't", addr)
}
