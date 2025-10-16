package v2

import (
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
