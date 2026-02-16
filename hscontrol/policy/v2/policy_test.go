package v2

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

func node(name, ipv4, ipv6 string, user types.User) *types.Node {
	return &types.Node{
		ID:       0,
		Hostname: name,
		IPv4:     ap(ipv4),
		IPv6:     ap(ipv6),
		User:     new(user),
		UserID:   new(user.ID),
	}
}

func TestPolicyManager(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "testuser", Email: "testuser@headscale.net"},
		{Model: gorm.Model{ID: 2}, Name: "otheruser", Email: "otheruser@headscale.net"},
	}

	tests := []struct {
		name         string
		pol          string
		nodes        types.Nodes
		wantFilter   []tailcfg.FilterRule
		wantMatchers []matcher.Match
	}{
		{
			name:         "empty-policy",
			pol:          "{}",
			nodes:        types.Nodes{},
			wantFilter:   tailcfg.FilterAllowAll,
			wantMatchers: matcher.MatchesFromFilterRules(tailcfg.FilterAllowAll),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewPolicyManager([]byte(tt.pol), users, tt.nodes.ViewSlice())
			require.NoError(t, err)

			filter, matchers := pm.Filter()
			if diff := cmp.Diff(tt.wantFilter, filter); diff != "" {
				t.Errorf("Filter() filter mismatch (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(
				tt.wantMatchers,
				matchers,
				cmp.AllowUnexported(matcher.Match{}),
			); diff != "" {
				t.Errorf("Filter() matchers mismatch (-want +got):\n%s", diff)
			}

			// TODO(kradalby): Test SSH Policy
		})
	}
}

func TestInvalidateAutogroupSelfCache(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1", Email: "user1@headscale.net"},
		{Model: gorm.Model{ID: 2}, Name: "user2", Email: "user2@headscale.net"},
		{Model: gorm.Model{ID: 3}, Name: "user3", Email: "user3@headscale.net"},
	}

	//nolint:goconst // test-specific inline policy for clarity
	policy := `{
		"acls": [
			{
				"action": "accept",
				"src": ["autogroup:member"],
				"dst": ["autogroup:self:*"]
			}
		]
	}`

	initialNodes := types.Nodes{
		node("user1-node1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
		node("user1-node2", "100.64.0.2", "fd7a:115c:a1e0::2", users[0]),
		node("user2-node1", "100.64.0.3", "fd7a:115c:a1e0::3", users[1]),
		node("user3-node1", "100.64.0.4", "fd7a:115c:a1e0::4", users[2]),
	}

	for i, n := range initialNodes {
		n.ID = types.NodeID(i + 1) //nolint:gosec // safe conversion in test
	}

	pm, err := NewPolicyManager([]byte(policy), users, initialNodes.ViewSlice())
	require.NoError(t, err)

	// Add to cache by calling FilterForNode for each node
	for _, n := range initialNodes {
		_, err := pm.FilterForNode(n.View())
		require.NoError(t, err)
	}

	require.Len(t, pm.filterRulesMap, len(initialNodes))

	tests := []struct {
		name            string
		newNodes        types.Nodes
		expectedCleared int
		description     string
	}{
		{
			name: "no_changes",
			newNodes: types.Nodes{
				node("user1-node1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
				node("user1-node2", "100.64.0.2", "fd7a:115c:a1e0::2", users[0]),
				node("user2-node1", "100.64.0.3", "fd7a:115c:a1e0::3", users[1]),
				node("user3-node1", "100.64.0.4", "fd7a:115c:a1e0::4", users[2]),
			},
			expectedCleared: 0,
			description:     "No changes should clear no cache entries",
		},
		{
			name: "node_added",
			newNodes: types.Nodes{
				node("user1-node1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
				node("user1-node2", "100.64.0.2", "fd7a:115c:a1e0::2", users[0]),
				node("user1-node3", "100.64.0.5", "fd7a:115c:a1e0::5", users[0]), // New node
				node("user2-node1", "100.64.0.3", "fd7a:115c:a1e0::3", users[1]),
				node("user3-node1", "100.64.0.4", "fd7a:115c:a1e0::4", users[2]),
			},
			expectedCleared: 2, // user1's existing nodes should be cleared
			description:     "Adding a node should clear cache for that user's existing nodes",
		},
		{
			name: "node_removed",
			newNodes: types.Nodes{
				node("user1-node1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
				// user1-node2 removed
				node("user2-node1", "100.64.0.3", "fd7a:115c:a1e0::3", users[1]),
				node("user3-node1", "100.64.0.4", "fd7a:115c:a1e0::4", users[2]),
			},
			expectedCleared: 2, // user1's remaining node + removed node should be cleared
			description:     "Removing a node should clear cache for that user's remaining nodes",
		},
		{
			name: "user_changed",
			newNodes: types.Nodes{
				node("user1-node1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
				node("user1-node2", "100.64.0.2", "fd7a:115c:a1e0::2", users[2]), // Changed to user3
				node("user2-node1", "100.64.0.3", "fd7a:115c:a1e0::3", users[1]),
				node("user3-node1", "100.64.0.4", "fd7a:115c:a1e0::4", users[2]),
			},
			expectedCleared: 3, // user1's node + user2's node + user3's nodes should be cleared
			description:     "Changing a node's user should clear cache for both old and new users",
		},
		{
			name: "ip_changed",
			newNodes: types.Nodes{
				node("user1-node1", "100.64.0.10", "fd7a:115c:a1e0::10", users[0]), // IP changed
				node("user1-node2", "100.64.0.2", "fd7a:115c:a1e0::2", users[0]),
				node("user2-node1", "100.64.0.3", "fd7a:115c:a1e0::3", users[1]),
				node("user3-node1", "100.64.0.4", "fd7a:115c:a1e0::4", users[2]),
			},
			expectedCleared: 2, // user1's nodes should be cleared
			description:     "Changing a node's IP should clear cache for that user's nodes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i, n := range tt.newNodes {
				found := false

				for _, origNode := range initialNodes {
					if n.Hostname == origNode.Hostname {
						n.ID = origNode.ID
						found = true

						break
					}
				}

				if !found {
					n.ID = types.NodeID(len(initialNodes) + i + 1) //nolint:gosec // safe conversion in test
				}
			}

			pm.filterRulesMap = make(map[types.NodeID][]tailcfg.FilterRule)
			for _, n := range initialNodes {
				_, err := pm.FilterForNode(n.View())
				require.NoError(t, err)
			}

			initialCacheSize := len(pm.filterRulesMap)
			require.Equal(t, len(initialNodes), initialCacheSize)

			pm.invalidateAutogroupSelfCache(initialNodes.ViewSlice(), tt.newNodes.ViewSlice())

			// Verify the expected number of cache entries were cleared
			finalCacheSize := len(pm.filterRulesMap)
			clearedEntries := initialCacheSize - finalCacheSize
			require.Equal(t, tt.expectedCleared, clearedEntries, tt.description)
		})
	}
}

// TestInvalidateGlobalPolicyCache tests the cache invalidation logic for global policies.
func TestInvalidateGlobalPolicyCache(t *testing.T) {
	mustIPPtr := func(s string) *netip.Addr {
		ip := netip.MustParseAddr(s)
		return &ip
	}

	tests := []struct {
		name               string
		oldNodes           types.Nodes
		newNodes           types.Nodes
		initialCache       map[types.NodeID][]tailcfg.FilterRule
		expectedCacheAfter map[types.NodeID]bool // true = should exist, false = should not exist
	}{
		{
			name: "node property changed - invalidates only that node",
			oldNodes: types.Nodes{
				&types.Node{ID: 1, IPv4: mustIPPtr("100.64.0.1")},
				&types.Node{ID: 2, IPv4: mustIPPtr("100.64.0.2")},
			},
			newNodes: types.Nodes{
				&types.Node{ID: 1, IPv4: mustIPPtr("100.64.0.99")}, // Changed
				&types.Node{ID: 2, IPv4: mustIPPtr("100.64.0.2")},  // Unchanged
			},
			initialCache: map[types.NodeID][]tailcfg.FilterRule{
				1: {},
				2: {},
			},
			expectedCacheAfter: map[types.NodeID]bool{
				1: false, // Invalidated
				2: true,  // Preserved
			},
		},
		{
			name: "multiple nodes changed",
			oldNodes: types.Nodes{
				&types.Node{ID: 1, IPv4: mustIPPtr("100.64.0.1")},
				&types.Node{ID: 2, IPv4: mustIPPtr("100.64.0.2")},
				&types.Node{ID: 3, IPv4: mustIPPtr("100.64.0.3")},
			},
			newNodes: types.Nodes{
				&types.Node{ID: 1, IPv4: mustIPPtr("100.64.0.99")}, // Changed
				&types.Node{ID: 2, IPv4: mustIPPtr("100.64.0.2")},  // Unchanged
				&types.Node{ID: 3, IPv4: mustIPPtr("100.64.0.88")}, // Changed
			},
			initialCache: map[types.NodeID][]tailcfg.FilterRule{
				1: {},
				2: {},
				3: {},
			},
			expectedCacheAfter: map[types.NodeID]bool{
				1: false, // Invalidated
				2: true,  // Preserved
				3: false, // Invalidated
			},
		},
		{
			name: "node deleted - removes from cache",
			oldNodes: types.Nodes{
				&types.Node{ID: 1, IPv4: mustIPPtr("100.64.0.1")},
				&types.Node{ID: 2, IPv4: mustIPPtr("100.64.0.2")},
			},
			newNodes: types.Nodes{
				&types.Node{ID: 2, IPv4: mustIPPtr("100.64.0.2")},
			},
			initialCache: map[types.NodeID][]tailcfg.FilterRule{
				1: {},
				2: {},
			},
			expectedCacheAfter: map[types.NodeID]bool{
				1: false, // Deleted
				2: true,  // Preserved
			},
		},
		{
			name: "node added - no cache invalidation needed",
			oldNodes: types.Nodes{
				&types.Node{ID: 1, IPv4: mustIPPtr("100.64.0.1")},
			},
			newNodes: types.Nodes{
				&types.Node{ID: 1, IPv4: mustIPPtr("100.64.0.1")},
				&types.Node{ID: 2, IPv4: mustIPPtr("100.64.0.2")}, // New
			},
			initialCache: map[types.NodeID][]tailcfg.FilterRule{
				1: {},
			},
			expectedCacheAfter: map[types.NodeID]bool{
				1: true,  // Preserved
				2: false, // Not in cache (new node)
			},
		},
		{
			name: "no changes - preserves all cache",
			oldNodes: types.Nodes{
				&types.Node{ID: 1, IPv4: mustIPPtr("100.64.0.1")},
				&types.Node{ID: 2, IPv4: mustIPPtr("100.64.0.2")},
			},
			newNodes: types.Nodes{
				&types.Node{ID: 1, IPv4: mustIPPtr("100.64.0.1")},
				&types.Node{ID: 2, IPv4: mustIPPtr("100.64.0.2")},
			},
			initialCache: map[types.NodeID][]tailcfg.FilterRule{
				1: {},
				2: {},
			},
			expectedCacheAfter: map[types.NodeID]bool{
				1: true,
				2: true,
			},
		},
		{
			name: "routes changed - invalidates that node only",
			oldNodes: types.Nodes{
				&types.Node{
					ID:             1,
					IPv4:           mustIPPtr("100.64.0.1"),
					Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("192.168.0.0/24")}},
					ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
				},
				&types.Node{ID: 2, IPv4: mustIPPtr("100.64.0.2")},
			},
			newNodes: types.Nodes{
				&types.Node{
					ID:             1,
					IPv4:           mustIPPtr("100.64.0.1"),
					Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("192.168.0.0/24")}},
					ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")}, // Changed
				},
				&types.Node{ID: 2, IPv4: mustIPPtr("100.64.0.2")},
			},
			initialCache: map[types.NodeID][]tailcfg.FilterRule{
				1: {},
				2: {},
			},
			expectedCacheAfter: map[types.NodeID]bool{
				1: false, // Invalidated
				2: true,  // Preserved
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := &PolicyManager{
				nodes:             tt.oldNodes.ViewSlice(),
				filterRulesMap:    tt.initialCache,
				usesAutogroupSelf: false,
			}

			pm.invalidateGlobalPolicyCache(tt.newNodes.ViewSlice())

			// Verify cache state
			for nodeID, shouldExist := range tt.expectedCacheAfter {
				_, exists := pm.filterRulesMap[nodeID]
				require.Equal(t, shouldExist, exists, "node %d cache existence mismatch", nodeID)
			}
		})
	}
}

// TestAutogroupSelfReducedVsUnreducedRules verifies that:
// 1. BuildPeerMap uses unreduced compiled rules for determining peer relationships
// 2. FilterForNode returns reduced compiled rules for packet filters.
func TestAutogroupSelfReducedVsUnreducedRules(t *testing.T) {
	user1 := types.User{Model: gorm.Model{ID: 1}, Name: "user1", Email: "user1@headscale.net"}
	user2 := types.User{Model: gorm.Model{ID: 2}, Name: "user2", Email: "user2@headscale.net"}
	users := types.Users{user1, user2}

	// Create two nodes
	node1 := node("node1", "100.64.0.1", "fd7a:115c:a1e0::1", user1)
	node1.ID = 1
	node2 := node("node2", "100.64.0.2", "fd7a:115c:a1e0::2", user2)
	node2.ID = 2
	nodes := types.Nodes{node1, node2}

	// Policy with autogroup:self - all members can reach their own devices
	policyStr := `{
		"acls": [
			{
				"action": "accept",
				"src": ["autogroup:member"],
				"dst": ["autogroup:self:*"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policyStr), users, nodes.ViewSlice())
	require.NoError(t, err)
	require.True(t, pm.usesAutogroupSelf, "policy should use autogroup:self")

	// Test FilterForNode returns reduced rules
	// For node1: should have rules where node1 is in destinations (its own IP)
	filterNode1, err := pm.FilterForNode(nodes[0].View())
	require.NoError(t, err)

	// For node2: should have rules where node2 is in destinations (its own IP)
	filterNode2, err := pm.FilterForNode(nodes[1].View())
	require.NoError(t, err)

	// FilterForNode should return reduced rules - verify they only contain the node's own IPs as destinations
	// For node1, destinations should only be node1's IPs
	node1IPs := []string{"100.64.0.1/32", "100.64.0.1", "fd7a:115c:a1e0::1/128", "fd7a:115c:a1e0::1"}

	for _, rule := range filterNode1 {
		for _, dst := range rule.DstPorts {
			require.Contains(t, node1IPs, dst.IP,
				"node1 filter should only contain node1's IPs as destinations")
		}
	}

	// For node2, destinations should only be node2's IPs
	node2IPs := []string{"100.64.0.2/32", "100.64.0.2", "fd7a:115c:a1e0::2/128", "fd7a:115c:a1e0::2"}

	for _, rule := range filterNode2 {
		for _, dst := range rule.DstPorts {
			require.Contains(t, node2IPs, dst.IP,
				"node2 filter should only contain node2's IPs as destinations")
		}
	}

	// Test BuildPeerMap uses unreduced rules
	peerMap := pm.BuildPeerMap(nodes.ViewSlice())

	// According to the policy, user1 can reach autogroup:self (which expands to node1's own IPs for node1)
	// So node1 should be able to reach itself, but since we're looking at peer relationships,
	// node1 should NOT have itself in the peer map (nodes don't peer with themselves)
	// node2 should also not have any peers since user2 has no rules allowing it to reach anyone

	// Verify peer relationships based on unreduced rules
	// With unreduced rules, BuildPeerMap can properly determine that:
	// - node1 can access autogroup:self (its own IPs)
	// - node2 cannot access node1
	require.Empty(t, peerMap[node1.ID], "node1 should have no peers (can only reach itself)")
	require.Empty(t, peerMap[node2.ID], "node2 should have no peers")
}

// When separate ACL rules exist (one with autogroup:self, one with tag:router),
// the autogroup:self rule should not prevent the tag:router rule from working.
// This ensures that autogroup:self doesn't interfere with other ACL rules.
func TestAutogroupSelfWithOtherRules(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "test-1", Email: "test-1@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "test-2", Email: "test-2@example.com"},
	}

	// test-1 has a regular device
	test1Node := &types.Node{
		ID:       1,
		Hostname: "test-1-device",
		IPv4:     ap("100.64.0.1"),
		IPv6:     ap("fd7a:115c:a1e0::1"),
		User:     new(users[0]),
		UserID:   new(users[0].ID),
		Hostinfo: &tailcfg.Hostinfo{},
	}

	// test-2 has a router device with tag:node-router
	test2RouterNode := &types.Node{
		ID:       2,
		Hostname: "test-2-router",
		IPv4:     ap("100.64.0.2"),
		IPv6:     ap("fd7a:115c:a1e0::2"),
		User:     new(users[1]),
		UserID:   new(users[1].ID),
		Tags:     []string{"tag:node-router"},
		Hostinfo: &tailcfg.Hostinfo{},
	}

	nodes := types.Nodes{test1Node, test2RouterNode}

	// This matches the exact policy from issue #2838:
	// - First rule: autogroup:member -> autogroup:self (allows users to see their own devices)
	// - Second rule: group:home -> tag:node-router (should allow group members to see router)
	policy := `{
		"groups": {
			"group:home": ["test-1@example.com", "test-2@example.com"]
		},
		"tagOwners": {
			"tag:node-router": ["group:home"]
		},
		"acls": [
			{
				"action": "accept",
				"src": ["autogroup:member"],
				"dst": ["autogroup:self:*"]
			},
			{
				"action": "accept",
				"src": ["group:home"],
				"dst": ["tag:node-router:*"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	peerMap := pm.BuildPeerMap(nodes.ViewSlice())

	// test-1 (in group:home) should see:
	// 1. Their own node (from autogroup:self rule)
	// 2. The router node (from group:home -> tag:node-router rule)
	test1Peers := peerMap[test1Node.ID]

	// Verify test-1 can see the router (group:home -> tag:node-router rule)
	require.True(t, slices.ContainsFunc(test1Peers, func(n types.NodeView) bool {
		return n.ID() == test2RouterNode.ID
	}), "test-1 should see test-2's router via group:home -> tag:node-router rule, even when autogroup:self rule exists (issue #2838)")

	// Verify that test-1 has filter rules (including autogroup:self and tag:node-router access)
	rules, err := pm.FilterForNode(test1Node.View())
	require.NoError(t, err)
	require.NotEmpty(t, rules, "test-1 should have filter rules from both ACL rules")
}

// TestAutogroupSelfPolicyUpdateTriggersMapResponse verifies that when a policy with
// autogroup:self is updated, SetPolicy returns true to trigger MapResponse updates,
// even if the global filter hash didn't change (which is always empty for autogroup:self).
// This fixes the issue where policy updates would clear caches but not trigger updates,
// leaving nodes with stale filter rules until reconnect.
func TestAutogroupSelfPolicyUpdateTriggersMapResponse(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "test-1", Email: "test-1@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "test-2", Email: "test-2@example.com"},
	}

	test1Node := &types.Node{
		ID:       1,
		Hostname: "test-1-device",
		IPv4:     ap("100.64.0.1"),
		IPv6:     ap("fd7a:115c:a1e0::1"),
		User:     new(users[0]),
		UserID:   new(users[0].ID),
		Hostinfo: &tailcfg.Hostinfo{},
	}

	test2Node := &types.Node{
		ID:       2,
		Hostname: "test-2-device",
		IPv4:     ap("100.64.0.2"),
		IPv6:     ap("fd7a:115c:a1e0::2"),
		User:     new(users[1]),
		UserID:   new(users[1].ID),
		Hostinfo: &tailcfg.Hostinfo{},
	}

	nodes := types.Nodes{test1Node, test2Node}

	// Initial policy with autogroup:self
	initialPolicy := `{
		"acls": [
			{
				"action": "accept",
				"src": ["autogroup:member"],
				"dst": ["autogroup:self:*"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(initialPolicy), users, nodes.ViewSlice())
	require.NoError(t, err)
	require.True(t, pm.usesAutogroupSelf, "policy should use autogroup:self")

	// Get initial filter rules for test-1 (should be cached)
	rules1, err := pm.FilterForNode(test1Node.View())
	require.NoError(t, err)
	require.NotEmpty(t, rules1, "test-1 should have filter rules")

	// Update policy with a different ACL that still results in empty global filter
	// (only autogroup:self rules, which compile to empty global filter)
	// We add a comment/description change by adding groups (which don't affect filter compilation)
	updatedPolicy := `{
		"groups": {
			"group:test": ["test-1@example.com"]
		},
		"acls": [
			{
				"action": "accept",
				"src": ["autogroup:member"],
				"dst": ["autogroup:self:*"]
			}
		]
	}`

	// SetPolicy should return true even though global filter hash didn't change
	policyChanged, err := pm.SetPolicy([]byte(updatedPolicy))
	require.NoError(t, err)
	require.True(t, policyChanged, "SetPolicy should return true when policy content changes, even if global filter hash unchanged (autogroup:self)")

	// Verify that caches were cleared and new rules are generated
	// The cache should be empty, so FilterForNode will recompile
	rules2, err := pm.FilterForNode(test1Node.View())
	require.NoError(t, err)
	require.NotEmpty(t, rules2, "test-1 should have filter rules after policy update")

	// Verify that the policy hash tracking works - a second identical update should return false
	policyChanged2, err := pm.SetPolicy([]byte(updatedPolicy))
	require.NoError(t, err)
	require.False(t, policyChanged2, "SetPolicy should return false when policy content hasn't changed")
}

// TestTagPropagationToPeerMap tests that when a node's tags change,
// the peer map is correctly updated. This is a regression test for
// https://github.com/juanfont/headscale/issues/2389
func TestTagPropagationToPeerMap(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1", Email: "user1@headscale.net"},
		{Model: gorm.Model{ID: 2}, Name: "user2", Email: "user2@headscale.net"},
	}

	// Policy: user2 can access tag:web nodes
	policy := `{
		"tagOwners": {
			"tag:web": ["user1@headscale.net"],
			"tag:internal": ["user1@headscale.net"]
		},
		"acls": [
			{
				"action": "accept",
				"src": ["user2@headscale.net"],
				"dst": ["user2@headscale.net:*"]
			},
			{
				"action": "accept",
				"src": ["user2@headscale.net"],
				"dst": ["tag:web:*"]
			},
			{
				"action": "accept",
				"src": ["tag:web"],
				"dst": ["user2@headscale.net:*"]
			}
		]
	}`

	// user1's node starts with tag:web and tag:internal
	user1Node := &types.Node{
		ID:       1,
		Hostname: "user1-node",
		IPv4:     ap("100.64.0.1"),
		IPv6:     ap("fd7a:115c:a1e0::1"),
		User:     new(users[0]),
		UserID:   new(users[0].ID),
		Tags:     []string{"tag:web", "tag:internal"},
	}

	// user2's node (no tags)
	user2Node := &types.Node{
		ID:       2,
		Hostname: "user2-node",
		IPv4:     ap("100.64.0.2"),
		IPv6:     ap("fd7a:115c:a1e0::2"),
		User:     new(users[1]),
		UserID:   new(users[1].ID),
	}

	initialNodes := types.Nodes{user1Node, user2Node}

	pm, err := NewPolicyManager([]byte(policy), users, initialNodes.ViewSlice())
	require.NoError(t, err)

	// Initial state: user2 should see user1 as a peer (user1 has tag:web)
	initialPeerMap := pm.BuildPeerMap(initialNodes.ViewSlice())

	// Check user2's peers - should include user1
	user2Peers := initialPeerMap[user2Node.ID]
	require.Len(t, user2Peers, 1, "user2 should have 1 peer initially (user1 with tag:web)")
	require.Equal(t, user1Node.ID, user2Peers[0].ID(), "user2's peer should be user1")

	// Check user1's peers - should include user2 (bidirectional ACL)
	user1Peers := initialPeerMap[user1Node.ID]
	require.Len(t, user1Peers, 1, "user1 should have 1 peer initially (user2)")
	require.Equal(t, user2Node.ID, user1Peers[0].ID(), "user1's peer should be user2")

	// Now change user1's tags: remove tag:web, keep only tag:internal
	user1NodeUpdated := &types.Node{
		ID:       1,
		Hostname: "user1-node",
		IPv4:     ap("100.64.0.1"),
		IPv6:     ap("fd7a:115c:a1e0::1"),
		User:     new(users[0]),
		UserID:   new(users[0].ID),
		Tags:     []string{"tag:internal"}, // tag:web removed!
	}

	updatedNodes := types.Nodes{user1NodeUpdated, user2Node}

	// SetNodes should detect the tag change
	changed, err := pm.SetNodes(updatedNodes.ViewSlice())
	require.NoError(t, err)
	require.True(t, changed, "SetNodes should return true when tags change")

	// After tag change: user2 should NOT see user1 as a peer anymore
	// (no ACL allows user2 to access tag:internal)
	updatedPeerMap := pm.BuildPeerMap(updatedNodes.ViewSlice())

	// Check user2's peers - should be empty now
	user2PeersAfter := updatedPeerMap[user2Node.ID]
	require.Empty(t, user2PeersAfter, "user2 should have no peers after tag:web is removed from user1")

	// Check user1's peers - should also be empty
	user1PeersAfter := updatedPeerMap[user1Node.ID]
	require.Empty(t, user1PeersAfter, "user1 should have no peers after tag:web is removed")

	// Also verify MatchersForNode returns non-empty matchers and ReduceNodes filters correctly
	// This simulates what buildTailPeers does in the mapper
	matchersForUser2, err := pm.MatchersForNode(user2Node.View())
	require.NoError(t, err)
	require.NotEmpty(t, matchersForUser2, "MatchersForNode should return non-empty matchers (at least self-access rule)")

	// Test ReduceNodes logic with the updated nodes and matchers
	// This is what buildTailPeers does - it takes peers from ListPeers (which might include user1)
	// and filters them using ReduceNodes with the updated matchers
	// Inline the ReduceNodes logic to avoid import cycle
	user2View := user2Node.View()
	user1UpdatedView := user1NodeUpdated.View()

	// Check if user2 can access user1 OR user1 can access user2
	canAccess := user2View.CanAccess(matchersForUser2, user1UpdatedView) ||
		user1UpdatedView.CanAccess(matchersForUser2, user2View)

	require.False(t, canAccess, "user2 should NOT be able to access user1 after tag:web is removed (ReduceNodes should filter out)")
}

// TestAutogroupSelfWithAdminOverride reproduces issue #2990:
// When autogroup:self is combined with an admin rule (group:admin -> *:*),
// tagged nodes become invisible to admins because BuildPeerMap uses asymmetric
// peer visibility in the autogroup:self path.
//
// The fix requires symmetric visibility: if admin can access tagged node,
// BOTH admin and tagged node should see each other as peers.
func TestAutogroupSelfWithAdminOverride(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "admin", Email: "admin@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "user1", Email: "user1@example.com"},
	}

	// Admin has a regular device
	adminNode := &types.Node{
		ID:       1,
		Hostname: "admin-device",
		IPv4:     ap("100.64.0.1"),
		IPv6:     ap("fd7a:115c:a1e0::1"),
		User:     new(users[0]),
		UserID:   new(users[0].ID),
		Hostinfo: &tailcfg.Hostinfo{},
	}

	// user1 has a tagged server
	user1TaggedNode := &types.Node{
		ID:       2,
		Hostname: "user1-server",
		IPv4:     ap("100.64.0.2"),
		IPv6:     ap("fd7a:115c:a1e0::2"),
		User:     new(users[1]),
		UserID:   new(users[1].ID),
		Tags:     []string{"tag:server"},
		Hostinfo: &tailcfg.Hostinfo{},
	}

	nodes := types.Nodes{adminNode, user1TaggedNode}

	// Policy from issue #2990:
	// - group:admin has full access to everything (*:*)
	// - autogroup:member -> autogroup:self (allows users to see their own devices)
	//
	// Bug: The tagged server becomes invisible to admin because:
	// 1. Admin can access tagged server (via *:* rule)
	// 2. Tagged server CANNOT access admin (no rule for that)
	// 3. With asymmetric logic, tagged server is not added to admin's peer list
	policy := `{
		"groups": {
			"group:admin": ["admin@example.com"]
		},
		"tagOwners": {
			"tag:server": ["user1@example.com"]
		},
		"acls": [
			{
				"action": "accept",
				"src": ["group:admin"],
				"dst": ["*:*"]
			},
			{
				"action": "accept",
				"src": ["autogroup:member"],
				"dst": ["autogroup:self:*"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	peerMap := pm.BuildPeerMap(nodes.ViewSlice())

	// Admin should see the tagged server as a peer (via group:admin -> *:* rule)
	adminPeers := peerMap[adminNode.ID]
	require.True(t, slices.ContainsFunc(adminPeers, func(n types.NodeView) bool {
		return n.ID() == user1TaggedNode.ID
	}), "admin should see tagged server as peer via *:* rule (issue #2990)")

	// Tagged server should also see admin as a peer (symmetric visibility)
	// Even though tagged server cannot ACCESS admin, it should still SEE admin
	// because admin CAN access it. This is required for proper network operation.
	taggedPeers := peerMap[user1TaggedNode.ID]
	require.True(t, slices.ContainsFunc(taggedPeers, func(n types.NodeView) bool {
		return n.ID() == adminNode.ID
	}), "tagged server should see admin as peer (symmetric visibility)")
}

// TestAutogroupSelfSymmetricVisibility verifies that peer visibility is symmetric:
// if node A can access node B, then both A and B should see each other as peers.
// This is the same behavior as the global filter path.
func TestAutogroupSelfSymmetricVisibility(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1", Email: "user1@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "user2", Email: "user2@example.com"},
	}

	// user1 has device A
	deviceA := &types.Node{
		ID:       1,
		Hostname: "device-a",
		IPv4:     ap("100.64.0.1"),
		IPv6:     ap("fd7a:115c:a1e0::1"),
		User:     new(users[0]),
		UserID:   new(users[0].ID),
		Hostinfo: &tailcfg.Hostinfo{},
	}

	// user2 has device B (tagged)
	deviceB := &types.Node{
		ID:       2,
		Hostname: "device-b",
		IPv4:     ap("100.64.0.2"),
		IPv6:     ap("fd7a:115c:a1e0::2"),
		User:     new(users[1]),
		UserID:   new(users[1].ID),
		Tags:     []string{"tag:web"},
		Hostinfo: &tailcfg.Hostinfo{},
	}

	nodes := types.Nodes{deviceA, deviceB}

	// One-way rule: user1 can access tag:web, but tag:web cannot access user1
	policy := `{
		"tagOwners": {
			"tag:web": ["user2@example.com"]
		},
		"acls": [
			{
				"action": "accept",
				"src": ["user1@example.com"],
				"dst": ["tag:web:*"]
			},
			{
				"action": "accept",
				"src": ["autogroup:member"],
				"dst": ["autogroup:self:*"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	peerMap := pm.BuildPeerMap(nodes.ViewSlice())

	// Device A (user1) should see device B (tag:web) as peer
	aPeers := peerMap[deviceA.ID]
	require.True(t, slices.ContainsFunc(aPeers, func(n types.NodeView) bool {
		return n.ID() == deviceB.ID
	}), "device A should see device B as peer (user1 -> tag:web rule)")

	// Device B (tag:web) should ALSO see device A as peer (symmetric visibility)
	// Even though B cannot ACCESS A, B should still SEE A as a peer
	bPeers := peerMap[deviceB.ID]
	require.True(t, slices.ContainsFunc(bPeers, func(n types.NodeView) bool {
		return n.ID() == deviceA.ID
	}), "device B should see device A as peer (symmetric visibility)")
}

// TestAutogroupSelfDoesNotBreakOtherUsersAccess reproduces the Discord scenario
// where enabling autogroup:self for superadmins should NOT break access for
// other users who don't use autogroup:self.
//
// Scenario:
// - Rule 1: [superadmin, admin, direction] -> [tag:common:*]
// - Rule 2: [superadmin, admin] -> [tag:tech:*]
// - Rule 3: [superadmin] -> [tag:privileged:*, autogroup:self:*]
//
// Expected behavior:
// - Superadmin sees: tag:common, tag:tech, tag:privileged, and own devices
// - Admin sees: tag:common, tag:tech
// - Direction sees: tag:common
// - All tagged nodes should be visible to users who can access them.
func TestAutogroupSelfDoesNotBreakOtherUsersAccess(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "superadmin", Email: "superadmin@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "admin", Email: "admin@example.com"},
		{Model: gorm.Model{ID: 3}, Name: "direction", Email: "direction@example.com"},
		{Model: gorm.Model{ID: 4}, Name: "tagowner", Email: "tagowner@example.com"},
	}

	// Create nodes:
	// - superadmin's device
	// - admin's device
	// - direction's device
	// - tagged server (tag:common)
	// - tagged server (tag:tech)
	// - tagged server (tag:privileged)

	superadminDevice := &types.Node{
		ID:       1,
		Hostname: "superadmin-laptop",
		User:     new(users[0]),
		UserID:   new(users[0].ID),
		IPv4:     ap("100.64.0.1"),
		Hostinfo: &tailcfg.Hostinfo{},
	}

	adminDevice := &types.Node{
		ID:       2,
		Hostname: "admin-laptop",
		User:     new(users[1]),
		UserID:   new(users[1].ID),
		IPv4:     ap("100.64.0.2"),
		Hostinfo: &tailcfg.Hostinfo{},
	}

	directionDevice := &types.Node{
		ID:       3,
		Hostname: "direction-laptop",
		User:     new(users[2]),
		UserID:   new(users[2].ID),
		IPv4:     ap("100.64.0.3"),
		Hostinfo: &tailcfg.Hostinfo{},
	}

	commonServer := &types.Node{
		ID:       4,
		Hostname: "common-server",
		User:     new(users[3]),
		UserID:   new(users[3].ID),
		IPv4:     ap("100.64.0.4"),
		Tags:     []string{"tag:common"},
		Hostinfo: &tailcfg.Hostinfo{},
	}

	techServer := &types.Node{
		ID:       5,
		Hostname: "tech-server",
		User:     new(users[3]),
		UserID:   new(users[3].ID),
		IPv4:     ap("100.64.0.5"),
		Tags:     []string{"tag:tech"},
		Hostinfo: &tailcfg.Hostinfo{},
	}

	privilegedServer := &types.Node{
		ID:       6,
		Hostname: "privileged-server",
		User:     new(users[3]),
		UserID:   new(users[3].ID),
		IPv4:     ap("100.64.0.6"),
		Tags:     []string{"tag:privileged"},
		Hostinfo: &tailcfg.Hostinfo{},
	}

	nodes := types.Nodes{
		superadminDevice,
		adminDevice,
		directionDevice,
		commonServer,
		techServer,
		privilegedServer,
	}

	policy := `{
		"groups": {
			"group:superadmin": ["superadmin@example.com"],
			"group:admin": ["admin@example.com"],
			"group:direction": ["direction@example.com"]
		},
		"tagOwners": {
			"tag:common": ["tagowner@example.com"],
			"tag:tech": ["tagowner@example.com"],
			"tag:privileged": ["tagowner@example.com"]
		},
		"acls": [
			{
				"action": "accept",
				"src": ["group:superadmin", "group:admin", "group:direction"],
				"dst": ["tag:common:*"]
			},
			{
				"action": "accept",
				"src": ["group:superadmin", "group:admin"],
				"dst": ["tag:tech:*"]
			},
			{
				"action": "accept",
				"src": ["group:superadmin"],
				"dst": ["tag:privileged:*", "autogroup:self:*"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	peerMap := pm.BuildPeerMap(nodes.ViewSlice())

	// Helper to check if node A sees node B
	canSee := func(a, b types.NodeID) bool {
		peers := peerMap[a]

		return slices.ContainsFunc(peers, func(n types.NodeView) bool {
			return n.ID() == b
		})
	}

	// Superadmin should see all tagged servers
	require.True(t, canSee(superadminDevice.ID, commonServer.ID),
		"superadmin should see tag:common")
	require.True(t, canSee(superadminDevice.ID, techServer.ID),
		"superadmin should see tag:tech")
	require.True(t, canSee(superadminDevice.ID, privilegedServer.ID),
		"superadmin should see tag:privileged")

	// Admin should see tag:common and tag:tech (but NOT tag:privileged)
	require.True(t, canSee(adminDevice.ID, commonServer.ID),
		"admin should see tag:common")
	require.True(t, canSee(adminDevice.ID, techServer.ID),
		"admin should see tag:tech")
	require.False(t, canSee(adminDevice.ID, privilegedServer.ID),
		"admin should NOT see tag:privileged")

	// Direction should see tag:common only
	require.True(t, canSee(directionDevice.ID, commonServer.ID),
		"direction should see tag:common")
	require.False(t, canSee(directionDevice.ID, techServer.ID),
		"direction should NOT see tag:tech")
	require.False(t, canSee(directionDevice.ID, privilegedServer.ID),
		"direction should NOT see tag:privileged")

	// Tagged servers should see their authorized users (symmetric visibility)
	require.True(t, canSee(commonServer.ID, superadminDevice.ID),
		"tag:common should see superadmin (symmetric)")
	require.True(t, canSee(commonServer.ID, adminDevice.ID),
		"tag:common should see admin (symmetric)")
	require.True(t, canSee(commonServer.ID, directionDevice.ID),
		"tag:common should see direction (symmetric)")

	require.True(t, canSee(techServer.ID, superadminDevice.ID),
		"tag:tech should see superadmin (symmetric)")
	require.True(t, canSee(techServer.ID, adminDevice.ID),
		"tag:tech should see admin (symmetric)")

	require.True(t, canSee(privilegedServer.ID, superadminDevice.ID),
		"tag:privileged should see superadmin (symmetric)")
}

// TestEmptyFilterNodesStillVisible verifies that nodes with empty filter rules
// (e.g., tagged servers that are only destinations, never sources) are still
// visible to nodes that can access them.
func TestEmptyFilterNodesStillVisible(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "admin", Email: "admin@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "tagowner", Email: "tagowner@example.com"},
	}

	adminDevice := &types.Node{
		ID:       1,
		Hostname: "admin-laptop",
		User:     new(users[0]),
		UserID:   new(users[0].ID),
		IPv4:     ap("100.64.0.1"),
		Hostinfo: &tailcfg.Hostinfo{},
	}

	// Tagged server - only a destination, never a source in any rule
	// This means its compiled filter rules will be empty
	taggedServer := &types.Node{
		ID:       2,
		Hostname: "server",
		User:     new(users[1]),
		UserID:   new(users[1].ID),
		IPv4:     ap("100.64.0.2"),
		Tags:     []string{"tag:server"},
		Hostinfo: &tailcfg.Hostinfo{},
	}

	nodes := types.Nodes{adminDevice, taggedServer}

	// Policy where tagged server is ONLY a destination
	policy := `{
		"groups": {
			"group:admin": ["admin@example.com"]
		},
		"tagOwners": {
			"tag:server": ["tagowner@example.com"]
		},
		"acls": [
			{
				"action": "accept",
				"src": ["group:admin"],
				"dst": ["tag:server:*", "autogroup:self:*"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	peerMap := pm.BuildPeerMap(nodes.ViewSlice())

	// Admin should see the tagged server
	adminPeers := peerMap[adminDevice.ID]
	require.True(t, slices.ContainsFunc(adminPeers, func(n types.NodeView) bool {
		return n.ID() == taggedServer.ID
	}), "admin should see tagged server")

	// Tagged server should see admin (symmetric visibility)
	// Even though the server has no outbound rules (empty filter)
	serverPeers := peerMap[taggedServer.ID]
	require.True(t, slices.ContainsFunc(serverPeers, func(n types.NodeView) bool {
		return n.ID() == adminDevice.ID
	}), "tagged server should see admin (symmetric visibility)")
}

// TestAutogroupSelfCombinedWithTags verifies that autogroup:self combined with
// specific tags in the same rule provides "combined access" - users get both
// tagged nodes AND their own devices.
func TestAutogroupSelfCombinedWithTags(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "admin", Email: "admin@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "tagowner", Email: "tagowner@example.com"},
	}

	// Admin has two devices
	adminLaptop := &types.Node{
		ID:       1,
		Hostname: "admin-laptop",
		User:     new(users[0]),
		UserID:   new(users[0].ID),
		IPv4:     ap("100.64.0.1"),
		Hostinfo: &tailcfg.Hostinfo{},
	}

	adminPhone := &types.Node{
		ID:       2,
		Hostname: "admin-phone",
		User:     new(users[0]),
		UserID:   new(users[0].ID),
		IPv4:     ap("100.64.0.2"),
		Hostinfo: &tailcfg.Hostinfo{},
	}

	// Tagged web server
	webServer := &types.Node{
		ID:       3,
		Hostname: "web-server",
		User:     new(users[1]),
		UserID:   new(users[1].ID),
		IPv4:     ap("100.64.0.3"),
		Tags:     []string{"tag:web"},
		Hostinfo: &tailcfg.Hostinfo{},
	}

	nodes := types.Nodes{adminLaptop, adminPhone, webServer}

	// Combined rule: admin gets both tag:web AND autogroup:self
	policy := `{
		"groups": {
			"group:admin": ["admin@example.com"]
		},
		"tagOwners": {
			"tag:web": ["tagowner@example.com"]
		},
		"acls": [
			{
				"action": "accept",
				"src": ["group:admin"],
				"dst": ["tag:web:*", "autogroup:self:*"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	peerMap := pm.BuildPeerMap(nodes.ViewSlice())

	// Helper to check visibility
	canSee := func(a, b types.NodeID) bool {
		peers := peerMap[a]

		return slices.ContainsFunc(peers, func(n types.NodeView) bool {
			return n.ID() == b
		})
	}

	// Admin laptop should see: admin phone (autogroup:self) AND web server (tag:web)
	require.True(t, canSee(adminLaptop.ID, adminPhone.ID),
		"admin laptop should see admin phone (autogroup:self)")
	require.True(t, canSee(adminLaptop.ID, webServer.ID),
		"admin laptop should see web server (tag:web)")

	// Admin phone should see: admin laptop (autogroup:self) AND web server (tag:web)
	require.True(t, canSee(adminPhone.ID, adminLaptop.ID),
		"admin phone should see admin laptop (autogroup:self)")
	require.True(t, canSee(adminPhone.ID, webServer.ID),
		"admin phone should see web server (tag:web)")

	// Web server should see both admin devices (symmetric visibility)
	require.True(t, canSee(webServer.ID, adminLaptop.ID),
		"web server should see admin laptop (symmetric)")
	require.True(t, canSee(webServer.ID, adminPhone.ID),
		"web server should see admin phone (symmetric)")
}

// TestIssue2990SameUserTaggedDevice reproduces the exact scenario from issue #2990:
// - One user (user1) who is in group:admin
// - node1: user device (not tagged), belongs to user1
// - node2: tagged with tag:admin, ALSO belongs to user1 (same user!)
// - Rule: group:admin -> *:*
// - Rule: autogroup:member -> autogroup:self:*
//
// Expected: node1 should be able to reach node2 via group:admin -> *:* rule.
func TestIssue2990SameUserTaggedDevice(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1", Email: "user1@"},
	}

	// node1: user device (not tagged), belongs to user1
	node1 := &types.Node{
		ID:       1,
		Hostname: "node1",
		User:     new(users[0]),
		UserID:   new(users[0].ID),
		IPv4:     ap("100.64.0.1"),
		IPv6:     ap("fd7a:115c:a1e0::1"),
		Hostinfo: &tailcfg.Hostinfo{},
	}

	// node2: tagged with tag:admin, ALSO belongs to user1 (same user!)
	node2 := &types.Node{
		ID:       2,
		Hostname: "node2",
		User:     new(users[0]),
		UserID:   new(users[0].ID),
		IPv4:     ap("100.64.0.2"),
		IPv6:     ap("fd7a:115c:a1e0::2"),
		Tags:     []string{"tag:admin"},
		Hostinfo: &tailcfg.Hostinfo{},
	}

	nodes := types.Nodes{node1, node2}

	// Exact policy from the issue report
	policy := `{
		"groups": {
			"group:admin": ["user1@"]
		},
		"tagOwners": {
			"tag:admin": ["group:admin"]
		},
		"acls": [
			{
				"action": "accept",
				"src": ["group:admin"],
				"dst": ["*:*"]
			},
			{
				"action": "accept",
				"src": ["autogroup:member"],
				"dst": ["autogroup:self:*"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	// Check peer visibility
	peerMap := pm.BuildPeerMap(nodes.ViewSlice())

	canSee := func(a, b types.NodeID) bool {
		peers := peerMap[a]

		return slices.ContainsFunc(peers, func(n types.NodeView) bool {
			return n.ID() == b
		})
	}

	// node1 should see node2 (via group:admin -> *:* and symmetric visibility)
	require.True(t, canSee(node1.ID, node2.ID),
		"node1 should see node2 as peer")

	// node2 should see node1 (symmetric visibility)
	require.True(t, canSee(node2.ID, node1.ID),
		"node2 should see node1 as peer (symmetric visibility)")

	// Check packet filter for node1 - should allow access to node2
	filter1, err := pm.FilterForNode(node1.View())
	require.NoError(t, err)
	t.Logf("node1 filter rules: %d", len(filter1))

	for i, rule := range filter1 {
		t.Logf("  rule %d: SrcIPs=%v DstPorts=%v", i, rule.SrcIPs, rule.DstPorts)
	}

	// node1's filter should include a rule allowing access to node2's IP
	// (via the group:admin -> *:* rule)
	require.NotEmpty(t, filter1,
		"node1's packet filter should have rules (group:admin -> *:*)")

	// Check packet filter for node2 - tagged device, should have limited access
	filter2, err := pm.FilterForNode(node2.View())
	require.NoError(t, err)
	t.Logf("node2 filter rules: %d", len(filter2))

	for i, rule := range filter2 {
		t.Logf("  rule %d: SrcIPs=%v DstPorts=%v", i, rule.SrcIPs, rule.DstPorts)
	}
}
