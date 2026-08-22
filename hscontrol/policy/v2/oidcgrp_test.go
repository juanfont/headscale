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

// TestOIDCGroupParsing tests that oidcgrp: aliases are correctly parsed.
func TestOIDCGroupParsing(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid-oidcgrp",
			input:   "oidcgrp:engineering",
			wantErr: false,
		},
		{
			name:    "valid-oidcgrp-with-dash",
			input:   "oidcgrp:my-group",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alias, err := parseAlias(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			og, ok := alias.(*OIDCGroup)
			require.True(t, ok, "expected *OIDCGroup, got %T", alias)
			assert.Equal(t, tt.input, og.String())
		})
	}
}

// TestOIDCGroupResolve tests that oidcgrp: resolves to correct node IPs
// and filter rules are properly generated.
func TestOIDCGroupResolve(t *testing.T) {
	// Create test users.
	user1 := types.User{Model: gorm.Model{ID: 1}, Name: "alice"}
	user2 := types.User{Model: gorm.Model{ID: 2}, Name: "bob"}

	// Create mock resolver with group memberships.
	resolver := &mockOIDCGroupResolver{
		groups: map[string][]types.User{
			"engineering": {user1, user2},
		},
	}

	// Simple policy: engineering can reach all on any port.
	policyJSON := []byte(`{
		"acls": [{
			"action": "accept",
			"src": ["oidcgrp:engineering"],
			"dst": ["*:*"]
		}]
	}`)

	users := types.Users{user1, user2}

	// Create nodes for each user.
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

	// Inject the resolver.
	pm.SetOIDCGroupResolver(resolver)

	// Set the policy.
	changed, err := pm.SetPolicy(policyJSON)
	require.NoError(t, err)
	assert.True(t, changed)

	// Debug: dump filter rules.
	pm.mu.RLock()
	t.Logf("global filter: %+v", pm.filter)
	t.Logf("compiledGrants: %d", len(pm.compiledGrants))
	for i, cg := range pm.compiledGrants {
		t.Logf("  grant[%d]: srcIPs=%v rules=%d", i, cg.srcIPStrings, len(cg.rules))
	}
	pm.mu.RUnlock()

	// Verify alice's filter rules have engineering IPs as sources
	// and wildcard as destination (can reach anyone).
	rules, err := pm.FilterForNode(node1.View())
	require.NoError(t, err)
	t.Logf("node1 rules: %+v", rules)
	assert.NotEmpty(t, rules, "alice (in engineering) should have filter rules")
	assertFilterRulesContainDstIP(t, rules, netip.MustParseAddr("100.64.0.2"))

	// Verify the source IPs cover both engineering members (alice + bob).
	// IPs may be merged into a range like "100.64.0.1-100.64.0.2".
	require.NotEmpty(t, rules[0].SrcIPs)
	srcStr := strings.Join(rules[0].SrcIPs, ",")
	assert.Contains(t, srcStr, "100.64.0.1")
	assert.Contains(t, srcStr, "100.64.0.2")
}

// TestOIDCGroupResolveEmptyGroup tests that oidcgrp: with no members resolves to nothing.
func TestOIDCGroupResolveEmptyGroup(t *testing.T) {
	resolver := &mockOIDCGroupResolver{
		groups: map[string][]types.User{},
	}

	policyJSON := []byte(`{
		"acls": [{
			"action": "accept",
			"src": ["oidcgrp:empty-group"],
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

	// With no matching users in the source group, no rules should match.
	rules, err := pm.FilterForNode(node.View())
	require.NoError(t, err)
	assert.Empty(t, rules)
}

// TestOIDCGroupResolveNoResolver tests that oidcgrp: works when resolver is not set.
func TestOIDCGroupResolveNoResolver(t *testing.T) {
	policyJSON := []byte(`{
		"acls": [{
			"action": "accept",
			"src": ["oidcgrp:some-group"],
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

	// SetPolicy should succeed (compilation skips unresolved oidcgrp).
	_, err = pm.SetPolicy(policyJSON)
	require.NoError(t, err)

	// FilterForNode should return empty rules since oidcgrp: couldn't resolve.
	rules, err := pm.FilterForNode(node.View())
	require.NoError(t, err)
	assert.Empty(t, rules)
}

// TestOIDCGroupIsAlias tests that OIDCGroup implements the Alias interface.
func TestOIDCGroupIsAlias(t *testing.T) {
	og := OIDCGroup("oidcgrp:test")
	var _ Alias = &og
}

// TestOIDCGroupValidate tests validation of oidcgrp: format.
func TestOIDCGroupValidate(t *testing.T) {
	tests := []struct {
		name    string
		group   OIDCGroup
		wantErr bool
	}{
		{name: "valid", group: "oidcgrp:engineering", wantErr: false},
		{name: "valid-with-numbers", group: "oidcgrp:group-123", wantErr: false},
		{name: "empty", group: "oidcgrp:", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.group.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestSetOIDCGroupResolver tests that SetOIDCGroupResolver properly injects the resolver.
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
			"src": ["oidcgrp:engineering"],
			"dst": ["*:*"]
		}]
	}`)

	pm, err := NewPolicyManager(nil, users, nodes.ViewSlice())
	require.NoError(t, err)

	// Set policy before resolver - should compile but oidcgrp: won't resolve.
	_, err = pm.SetPolicy(policyJSON)
	require.NoError(t, err)

	// Before setting resolver, filter should be empty (oidcgrp: can't resolve).
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

// TestIsOIDCGroup tests the isOIDCGroup helper.
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


