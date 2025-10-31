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

func node(name, ipv4, ipv6 string, user types.User, hostinfo *tailcfg.Hostinfo) *types.Node {
	return &types.Node{
		ID:       0,
		Hostname: name,
		IPv4:     ap(ipv4),
		IPv6:     ap(ipv6),
		User:     user,
		UserID:   user.ID,
		Hostinfo: hostinfo,
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
		node("user1-node1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil),
		node("user1-node2", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], nil),
		node("user2-node1", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil),
		node("user3-node1", "100.64.0.4", "fd7a:115c:a1e0::4", users[2], nil),
	}

	for i, n := range initialNodes {
		n.ID = types.NodeID(i + 1)
	}

	pm, err := NewPolicyManager([]byte(policy), users, initialNodes.ViewSlice())
	require.NoError(t, err)

	// Add to cache by calling FilterForNode for each node
	for _, n := range initialNodes {
		_, err := pm.FilterForNode(n.View())
		require.NoError(t, err)
	}

	require.Equal(t, len(initialNodes), len(pm.filterRulesMap))

	tests := []struct {
		name            string
		newNodes        types.Nodes
		expectedCleared int
		description     string
	}{
		{
			name: "no_changes",
			newNodes: types.Nodes{
				node("user1-node1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil),
				node("user1-node2", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], nil),
				node("user2-node1", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil),
				node("user3-node1", "100.64.0.4", "fd7a:115c:a1e0::4", users[2], nil),
			},
			expectedCleared: 0,
			description:     "No changes should clear no cache entries",
		},
		{
			name: "node_added",
			newNodes: types.Nodes{
				node("user1-node1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil),
				node("user1-node2", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], nil),
				node("user1-node3", "100.64.0.5", "fd7a:115c:a1e0::5", users[0], nil), // New node
				node("user2-node1", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil),
				node("user3-node1", "100.64.0.4", "fd7a:115c:a1e0::4", users[2], nil),
			},
			expectedCleared: 2, // user1's existing nodes should be cleared
			description:     "Adding a node should clear cache for that user's existing nodes",
		},
		{
			name: "node_removed",
			newNodes: types.Nodes{
				node("user1-node1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil),
				// user1-node2 removed
				node("user2-node1", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil),
				node("user3-node1", "100.64.0.4", "fd7a:115c:a1e0::4", users[2], nil),
			},
			expectedCleared: 2, // user1's remaining node + removed node should be cleared
			description:     "Removing a node should clear cache for that user's remaining nodes",
		},
		{
			name: "user_changed",
			newNodes: types.Nodes{
				node("user1-node1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil),
				node("user1-node2", "100.64.0.2", "fd7a:115c:a1e0::2", users[2], nil), // Changed to user3
				node("user2-node1", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil),
				node("user3-node1", "100.64.0.4", "fd7a:115c:a1e0::4", users[2], nil),
			},
			expectedCleared: 3, // user1's node + user2's node + user3's nodes should be cleared
			description:     "Changing a node's user should clear cache for both old and new users",
		},
		{
			name: "ip_changed",
			newNodes: types.Nodes{
				node("user1-node1", "100.64.0.10", "fd7a:115c:a1e0::10", users[0], nil), // IP changed
				node("user1-node2", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], nil),
				node("user2-node1", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil),
				node("user3-node1", "100.64.0.4", "fd7a:115c:a1e0::4", users[2], nil),
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
					n.ID = types.NodeID(len(initialNodes) + i + 1)
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
// 2. FilterForNode returns reduced compiled rules for packet filters
func TestAutogroupSelfReducedVsUnreducedRules(t *testing.T) {
	user1 := types.User{Model: gorm.Model{ID: 1}, Name: "user1", Email: "user1@headscale.net"}
	user2 := types.User{Model: gorm.Model{ID: 2}, Name: "user2", Email: "user2@headscale.net"}
	users := types.Users{user1, user2}

	// Create two nodes
	node1 := node("node1", "100.64.0.1", "fd7a:115c:a1e0::1", user1, nil)
	node1.ID = 1
	node2 := node("node2", "100.64.0.2", "fd7a:115c:a1e0::2", user2, nil)
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
		User:     users[0],
		UserID:   users[0].ID,
		Hostinfo: &tailcfg.Hostinfo{},
	}

	// test-2 has a router device with tag:node-router
	test2RouterNode := &types.Node{
		ID:         2,
		Hostname:   "test-2-router",
		IPv4:       ap("100.64.0.2"),
		IPv6:       ap("fd7a:115c:a1e0::2"),
		User:       users[1],
		UserID:     users[1].ID,
		ForcedTags: []string{"tag:node-router"},
		Hostinfo:   &tailcfg.Hostinfo{},
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
