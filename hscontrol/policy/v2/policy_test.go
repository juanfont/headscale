package v2

import (
	"encoding/json"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"pgregory.net/rapid"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/views"
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
		{ID: 1, Name: "testuser", Email: "testuser@headscale.net"},
		{ID: 2, Name: "otheruser", Email: "otheruser@headscale.net"},
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
		{
			name:         "empty-acls-denies-all",
			pol:          `{"acls": []}`,
			nodes:        types.Nodes{},
			wantFilter:   nil,
			wantMatchers: matcher.MatchesFromFilterRules(nil),
		},
		{
			name:         "empty-grants-denies-all",
			pol:          `{"grants": []}`,
			nodes:        types.Nodes{},
			wantFilter:   nil,
			wantMatchers: matcher.MatchesFromFilterRules(nil),
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
				cmpopts.EquateComparable(netipx.IPRange{}),
			); diff != "" {
				t.Errorf("Filter() matchers mismatch (-want +got):\n%s", diff)
			}

			// TODO(kradalby): Test SSH Policy
		})
	}
}

func TestInvalidateAutogroupSelfCache(t *testing.T) {
	users := types.Users{
		{ID: 1, Name: "user1", Email: "user1@headscale.net"},
		{ID: 2, Name: "user2", Email: "user2@headscale.net"},
		{ID: 3, Name: "user3", Email: "user3@headscale.net"},
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

	require.Equal(t, len(initialNodes), pm.filterRulesMap.Size())

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

			pm.filterRulesMap.Clear()

			for _, n := range initialNodes {
				_, err := pm.FilterForNode(n.View())
				require.NoError(t, err)
			}

			initialCacheSize := pm.filterRulesMap.Size()
			require.Equal(t, len(initialNodes), initialCacheSize)

			pm.invalidateAutogroupSelfCache(initialNodes.ViewSlice(), tt.newNodes.ViewSlice())

			// Verify the expected number of cache entries were cleared
			finalCacheSize := pm.filterRulesMap.Size()
			clearedEntries := initialCacheSize - finalCacheSize
			require.Equal(t, tt.expectedCleared, clearedEntries, tt.description)
		})
	}
}

// TestSetNodesAutogroupSelfUnhydratedUser reproduces the panic seen on
// /machine/map when an autogroup:self policy is active and a non-tagged
// node reaches the policy manager with its UserID set but the User
// association left unhydrated (User pointer nil). The NodeStore stores
// nodes by value with User as a *User; not every write path hydrates the
// association, so the autogroup:self cache invalidation must derive the
// owning user from UserID, not from the User view.
func TestSetNodesAutogroupSelfUnhydratedUser(t *testing.T) {
	users := types.Users{
		{ID: 1, Name: "user1", Email: "user1@headscale.net"},
		{ID: 2, Name: "user2", Email: "user2@headscale.net"},
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

	// unhydratedNode mirrors a NodeStore snapshot entry whose UserID is
	// set (so it is unambiguously user-owned, not tagged) but whose User
	// association was never loaded.
	unhydratedNode := func(name, ipv4, ipv6 string, userID uint) *types.Node {
		return &types.Node{
			Hostname: name,
			IPv4:     ap(ipv4),
			IPv6:     ap(ipv6),
			UserID:   new(userID),
			User:     nil,
		}
	}

	initialNodes := types.Nodes{
		node("user1-node1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
		node("user2-node1", "100.64.0.2", "fd7a:115c:a1e0::2", users[1]),
	}
	for i, n := range initialNodes {
		n.ID = types.NodeID(i + 1) //nolint:gosec // safe conversion in test
	}

	pm, err := NewPolicyManager([]byte(policy), users, initialNodes.ViewSlice())
	require.NoError(t, err)

	require.False(t, initialNodes[0].IsTagged(), "node must be user-owned for autogroup:self")

	// Simulate a node restarting tailscaled: the same node is pushed back
	// into the policy manager, but the snapshot version has no hydrated
	// User association. This is the exact shape that crashed beta.1.
	updatedNodes := types.Nodes{
		unhydratedNode("user1-node1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0].ID),
		node("user2-node1", "100.64.0.2", "fd7a:115c:a1e0::2", users[1]),
	}
	for i, n := range updatedNodes {
		n.ID = types.NodeID(i + 1) //nolint:gosec // safe conversion in test
	}

	require.NotPanics(t, func() {
		_, err = pm.SetNodes(updatedNodes.ViewSlice())
	}, "SetNodes must not panic when a non-tagged node has an unhydrated User")
	require.NoError(t, err)
}

// TestSSHCheckParamsUnhydratedUserNoPanic proves that SSHCheckParams does
// not panic when a non-tagged node reaches the policy manager with its
// UserID set but its User association unhydrated (User pointer nil) — the
// same NodeStore shape that crashed /machine/map in commit 171fd7a3. The
// autogroup:self SSH branch dereferences node.User().ID() guarded only by
// !IsTagged(), not by User().Valid(); SSHCheckParams is reached from the
// Noise SSH-check path (noise.go), so a tailnet client triggers the panic
// and crashes the server (DoS) whenever an SSH check rule with an
// autogroup:self destination is active.
func TestSSHCheckParamsUnhydratedUserNoPanic(t *testing.T) {
	users := types.Users{
		{ID: 1, Name: "user1", Email: "user1@headscale.net"},
	}

	policy := `{
		"ssh": [
			{
				"action": "check",
				"src":    ["user1@headscale.net"],
				"dst":    ["autogroup:self"],
				"users":  ["root"]
			}
		]
	}`

	initialNodes := types.Nodes{
		node("user1-src", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
		node("user1-dst", "100.64.0.2", "fd7a:115c:a1e0::2", users[0]),
	}
	for i, n := range initialNodes {
		n.ID = types.NodeID(i + 1) //nolint:gosec // safe conversion in test
	}

	pm, err := NewPolicyManager([]byte(policy), users, initialNodes.ViewSlice())
	require.NoError(t, err)

	// Simulate a node restarting tailscaled: the destination node is pushed
	// back into the policy manager with no hydrated User association (UserID
	// set, User pointer nil), the exact shape that crashed beta.1.
	unhydratedDst := &types.Node{
		ID:       2,
		Hostname: "user1-dst",
		IPv4:     ap("100.64.0.2"),
		IPv6:     ap("fd7a:115c:a1e0::2"),
		UserID:   new(users[0].ID),
		User:     nil,
	}
	require.False(t, unhydratedDst.IsTagged(), "dst node must be user-owned for autogroup:self")

	updatedNodes := types.Nodes{
		node("user1-src", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
		unhydratedDst,
	}
	updatedNodes[0].ID = 1
	_, err = pm.SetNodes(updatedNodes.ViewSlice())
	require.NoError(t, err)

	require.NotPanics(t, func() {
		pm.SSHCheckParams(types.NodeID(1), types.NodeID(2), "alice")
	}, "SSHCheckParams must not panic when a non-tagged node has an unhydrated User")
}

func TestSetUsers(t *testing.T) {
	const allowAll = `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`

	const sshCheck = `{
		"ssh": [
			{
				"action": "check",
				"src": ["user1@headscale.net"],
				"dst": ["autogroup:self"],
				"users": ["root"]
			}
		]
	}`

	tests := []struct {
		name   string
		policy string
		mutate func(*types.User)

		wantPolicyChanged  bool
		wantPeerMapChanged bool
	}{
		{
			name:   "identical users without ssh",
			policy: allowAll,
			mutate: func(*types.User) {},
		},
		{
			name:   "identical users with ssh",
			policy: sshCheck,
			mutate: func(*types.User) {},
		},
		{
			name:   "timestamp bump only",
			policy: sshCheck,
			mutate: func(u *types.User) { u.UpdatedAt = u.UpdatedAt.Add(time.Hour) },
		},
		{
			name:   "display name change without ssh",
			policy: allowAll,
			mutate: func(u *types.User) { u.DisplayName = "Renamed" },
		},
		{
			name:   "email change without ssh",
			policy: allowAll,
			mutate: func(u *types.User) { u.Email = "other@headscale.net" },

			wantPeerMapChanged: true,
		},
		{
			name:   "rename with ssh",
			policy: sshCheck,
			mutate: func(u *types.User) { u.Name = "renamed" },

			wantPolicyChanged:  true,
			wantPeerMapChanged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users := types.Users{{ID: 1, Name: "user1", Email: "user1@headscale.net"}}

			pm, err := NewPolicyManager([]byte(tt.policy), users, types.Nodes{}.ViewSlice())
			require.NoError(t, err)

			updated := slices.Clone(users)
			tt.mutate(&updated[0])

			policyChanged, peerMapChanged, err := pm.SetUsers(updated)
			require.NoError(t, err)
			require.Equal(t, tt.wantPolicyChanged, policyChanged, "policyChanged")
			require.Equal(t, tt.wantPeerMapChanged, peerMapChanged, "peerMapChanged")
		})
	}
}

func matcherStrings(ms []matcher.Match) []string {
	out := make([]string, 0, len(ms))
	for i := range ms {
		out = append(out, ms[i].DebugString())
	}

	return out
}

// TestSetUsersDropsStaleSelfFilters pins that a user change which moves
// autogroup:self sources, without touching the global filter, still drops
// the cached per-node filters and matchers built from the old sources and
// reports a policy change so clients receive their new filter.
func TestSetUsersDropsStaleSelfFilters(t *testing.T) {
	pol := `{
		"groups": {"group:a": ["u1@", "u3@"]},
		"acls": [{"action": "accept", "src": ["group:a"], "dst": ["autogroup:self:*"]}]}`

	// ID is set by assignment so this builds where types.User embeds
	// gorm.Model and promoted-field literals are not allowed.
	u1, u3, x3 := types.User{Name: "u1"}, types.User{Name: "u3"}, types.User{Name: "x3"}
	u1.ID, u3.ID, x3.ID = 1, 3, 3

	tests := []struct {
		name   string
		before types.Users
		after  types.Users
	}{
		{name: "user-added", before: types.Users{u1}, after: types.Users{u1, u3}},
		{name: "user-renamed", before: types.Users{u1, x3}, after: types.Users{u1, u3}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodes := types.Nodes{
				node("u1-a", "100.64.0.1", "fd7a:115c:a1e0::1", u1),
				node("u3-a", "100.64.0.3", "fd7a:115c:a1e0::3", u3),
				node("u3-b", "100.64.0.4", "fd7a:115c:a1e0::4", u3),
			}
			for i, n := range nodes {
				n.ID = types.NodeID(i + 1) //nolint:gosec // safe conversion in test
			}

			pm, err := NewPolicyManager([]byte(pol), tt.before, nodes.ViewSlice())
			require.NoError(t, err)

			for _, n := range nodes {
				_, err := pm.FilterForNode(n.View())
				require.NoError(t, err)
				_, err = pm.MatchersForNode(n.View())
				require.NoError(t, err)
			}

			policyChanged, _, err := pm.SetUsers(tt.after)
			require.NoError(t, err)
			require.True(t, policyChanged, "moved self sources must reach clients")

			fresh, err := NewPolicyManager([]byte(pol), tt.after, nodes.ViewSlice())
			require.NoError(t, err)

			for _, n := range nodes {
				got, err := pm.FilterForNode(n.View())
				require.NoError(t, err)

				want, err := fresh.FilterForNode(n.View())
				require.NoError(t, err)
				require.Empty(t, cmp.Diff(want, got), "node %d FilterForNode (-fresh +cached)", n.ID)

				gotM, err := pm.MatchersForNode(n.View())
				require.NoError(t, err)

				wantM, err := fresh.MatchersForNode(n.View())
				require.NoError(t, err)
				require.Equal(t, matcherStrings(wantM), matcherStrings(gotM), "node %d MatchersForNode", n.ID)
			}
		})
	}
}

// TestSetUsersReportsLostViaSources: a user change that leaves the only via
// grant without sources must be reported, or clients keep its rules.
func TestSetUsersReportsLostViaSources(t *testing.T) {
	pol := `{
		"tagOwners": {"tag:router": ["u1@"]},
		"grants": [{"src": ["u3@"], "dst": ["10.0.0.0/16"], "via": ["tag:router"], "ip": ["*"]}]}`

	u1, u3, x3 := types.User{Name: "u1"}, types.User{Name: "u3"}, types.User{Name: "x3"}
	u1.ID, u3.ID, x3.ID = 1, 3, 3

	router := node("router", "100.64.0.1", "fd7a:115c:a1e0::1", types.User{})
	router.User, router.UserID = nil, nil
	router.Tags = []string{"tag:router"}
	router.Hostinfo = &tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")},
	}
	router.ApprovedRoutes = router.Hostinfo.RoutableIPs

	nodes := types.Nodes{router, node("u3-a", "100.64.0.3", "fd7a:115c:a1e0::3", u3)}
	for i, n := range nodes {
		n.ID = types.NodeID(i + 1) //nolint:gosec // safe conversion in test
	}

	pm, err := NewPolicyManager([]byte(pol), types.Users{u1, u3}, nodes.ViewSlice())
	require.NoError(t, err)

	rules, err := pm.FilterForNode(router.View())
	require.NoError(t, err)
	require.NotEmpty(t, rules, "the router admits u3 before the rename")

	policyChanged, _, err := pm.SetUsers(types.Users{u1, x3})
	require.NoError(t, err)

	rules, err = pm.FilterForNode(router.View())
	require.NoError(t, err)
	require.Empty(t, rules, "nobody is named u3 any more")
	require.True(t, policyChanged, "the withdrawn rule must reach clients")
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
				nodes:              tt.oldNodes.ViewSlice(),
				filterRulesMap:     xsync.NewMap[types.NodeID, []tailcfg.FilterRule](),
				matchersForNodeMap: xsync.NewMap[types.NodeID, []matcher.Match](),
			}
			for id, rules := range tt.initialCache {
				pm.filterRulesMap.Store(id, rules)
			}

			pm.invalidateGlobalPolicyCache(tt.newNodes.ViewSlice())

			// Verify cache state
			for nodeID, shouldExist := range tt.expectedCacheAfter {
				_, exists := pm.filterRulesMap.Load(nodeID)
				require.Equal(t, shouldExist, exists, "node %d cache existence mismatch", nodeID)
			}
		})
	}
}

// TestAutogroupSelfReducedVsUnreducedRules verifies that:
// 1. BuildPeerMap uses unreduced compiled rules for determining peer relationships
// 2. FilterForNode returns reduced compiled rules for packet filters.
func TestAutogroupSelfReducedVsUnreducedRules(t *testing.T) {
	user1 := types.User{ID: 1, Name: "user1", Email: "user1@headscale.net"}
	user2 := types.User{ID: 2, Name: "user2", Email: "user2@headscale.net"}
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
	require.True(t, pm.needsPerNodeFilter, "policy should need per-node filter")

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
		{ID: 1, Name: "test-1", Email: "test-1@example.com"},
		{ID: 2, Name: "test-2", Email: "test-2@example.com"},
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
	require.True(t, slices.Contains(test1Peers, test2RouterNode.ID),
		"test-1 should see test-2's router via group:home -> tag:node-router rule, even when autogroup:self rule exists (issue #2838)")

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
		{ID: 1, Name: "test-1", Email: "test-1@example.com"},
		{ID: 2, Name: "test-2", Email: "test-2@example.com"},
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
	require.True(t, pm.needsPerNodeFilter, "policy should need per-node filter")

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

// TestSSHPolicyRemovalClearsRules pins that removing every SSH rule
// yields a non-nil, empty [tailcfg.SSHPolicy]. A nil MapResponse.SSHPolicy
// tells the client to keep its previous rules, so returning nil leaves
// revoked SSH access in force. SaaS sends {"rules":[]} for policies
// without SSH rules; see the netmap in any testdata capture whose
// policy lacks an "ssh" key.
// https://github.com/juanfont/headscale/issues/3508
func TestSSHPolicyRemovalClearsRules(t *testing.T) {
	users := types.Users{{Name: "user1", Email: "user1@headscale.net"}}
	users[0].ID = 1

	nodes := types.Nodes{
		node("server", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
		node("client", "100.64.0.2", "fd7a:115c:a1e0::2", users[0]),
	}
	nodes[0].ID = 1
	nodes[1].ID = 2

	withSSH := `{
		"acls": [],
		"ssh": [{
			"action": "accept",
			"src":    ["autogroup:member"],
			"dst":    ["autogroup:self"],
			"users":  ["root"]
		}]
	}`

	for name, without := range map[string]string{
		"ssh key removed": `{"acls": []}`,
		"ssh empty list":  `{"acls": [], "ssh": []}`,
	} {
		t.Run(name, func(t *testing.T) {
			pm, err := NewPolicyManager([]byte(withSSH), users, nodes.ViewSlice())
			require.NoError(t, err)

			before, err := pm.SSHPolicy("", nodes[0].View())
			require.NoError(t, err)
			require.NotNil(t, before)
			require.NotEmpty(t, before.Rules, "precondition: server has SSH rules")

			changed, err := pm.SetPolicy([]byte(without))
			require.NoError(t, err)
			require.True(t, changed)

			after, err := pm.SSHPolicy("", nodes[0].View())
			require.NoError(t, err)
			require.NotNil(t, after,
				"nil SSHPolicy means 'unchanged' on the wire; client keeps stale rules")
			require.NotNil(t, after.Rules, `SaaS sends "rules":[], not null`)
			require.Empty(t, after.Rules)
		})
	}
}

// TestSSHPolicySharedBetweenNodes pins that what an SSH rule expands to is
// kept once, not once per rule and destination node. There is one principal
// per source address, so separate copies grow with rules × nodes².
func TestSSHPolicySharedBetweenNodes(t *testing.T) {
	users := types.Users{{Name: "user1", Email: "user1@headscale.net"}}
	users[0].ID = 1

	nodes := types.Nodes{
		node("node1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
		node("node2", "100.64.0.2", "fd7a:115c:a1e0::2", users[0]),
		node("node3", "100.64.0.3", "fd7a:115c:a1e0::3", users[0]),
	}
	for i, n := range nodes {
		n.ID = types.NodeID(i + 1) //nolint:gosec // small test value
	}

	pm, err := NewPolicyManager([]byte(`{"ssh": [
		{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:member"], "users": ["a"]},
		{"action": "accept", "src": ["user1@headscale.net"], "dst": ["autogroup:member"], "users": ["b"]}
	]}`), users, nodes[:2].ViewSlice())
	require.NoError(t, err)

	first, err := pm.SSHPolicy("", nodes[0].View())
	require.NoError(t, err)
	second, err := pm.SSHPolicy("", nodes[1].View())
	require.NoError(t, err)

	require.Len(t, first.Rules, 2)
	require.Len(t, first.Rules[0].Principals, 4)
	require.Equal(t, first, second)

	require.Same(t, first.Rules[0], second.Rules[0], "between nodes")
	require.Same(t, first.Rules[0].Principals[0], first.Rules[1].Principals[0],
		"between rules whose sources resolve to the same addresses")

	// The shared rules are dropped together with the per-node policies.
	changed, err := pm.SetNodes(nodes.ViewSlice())
	require.NoError(t, err)
	require.True(t, changed)

	after, err := pm.SSHPolicy("", nodes[0].View())
	require.NoError(t, err)
	require.Len(t, after.Rules, 2)
	require.Len(t, after.Rules[0].Principals, 6)
}

// TestTagPropagationToPeerMap tests that when a node's tags change,
// the peer map is correctly updated. This is a regression test for
// https://github.com/juanfont/headscale/issues/2389
func TestTagPropagationToPeerMap(t *testing.T) {
	users := types.Users{
		{ID: 1, Name: "user1", Email: "user1@headscale.net"},
		{ID: 2, Name: "user2", Email: "user2@headscale.net"},
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
	require.Equal(t, user1Node.ID, user2Peers[0], "user2's peer should be user1")

	// Check user1's peers - should include user2 (bidirectional ACL)
	user1Peers := initialPeerMap[user1Node.ID]
	require.Len(t, user1Peers, 1, "user1 should have 1 peer initially (user2)")
	require.Equal(t, user2Node.ID, user1Peers[0], "user1's peer should be user2")

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

	// Test [policy.ReduceNodes] logic with the updated nodes and matchers
	// This is what [mapper.MapResponseBuilder.buildTailPeers] does - it takes peers from
	// [state.State.ListPeers] (which might include user1) and filters them using
	// [policy.ReduceNodes] with the updated matchers
	// Inline the [policy.ReduceNodes] logic to avoid import cycle
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
		{ID: 1, Name: "admin", Email: "admin@example.com"},
		{ID: 2, Name: "user1", Email: "user1@example.com"},
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
	require.True(t, slices.Contains(adminPeers, user1TaggedNode.ID),
		"admin should see tagged server as peer via *:* rule (issue #2990)")

	// Tagged server should also see admin as a peer (symmetric visibility)
	// Even though tagged server cannot ACCESS admin, it should still SEE admin
	// because admin CAN access it. This is required for proper network operation.
	taggedPeers := peerMap[user1TaggedNode.ID]
	require.True(t, slices.Contains(taggedPeers, adminNode.ID),
		"tagged server should see admin as peer (symmetric visibility)")
}

// TestAutogroupSelfSymmetricVisibility verifies that peer visibility is symmetric:
// if node A can access node B, then both A and B should see each other as peers.
// This is the same behavior as the global filter path.
func TestAutogroupSelfSymmetricVisibility(t *testing.T) {
	users := types.Users{
		{ID: 1, Name: "user1", Email: "user1@example.com"},
		{ID: 2, Name: "user2", Email: "user2@example.com"},
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
	require.True(t, slices.Contains(aPeers, deviceB.ID),
		"device A should see device B as peer (user1 -> tag:web rule)")

	// Device B (tag:web) should ALSO see device A as peer (symmetric visibility)
	// Even though B cannot ACCESS A, B should still SEE A as a peer
	bPeers := peerMap[deviceB.ID]
	require.True(t, slices.Contains(bPeers, deviceA.ID),
		"device B should see device A as peer (symmetric visibility)")
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
		{ID: 1, Name: "superadmin", Email: "superadmin@example.com"},
		{ID: 2, Name: "admin", Email: "admin@example.com"},
		{ID: 3, Name: "direction", Email: "direction@example.com"},
		{ID: 4, Name: "tagowner", Email: "tagowner@example.com"},
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
		return slices.Contains(peerMap[a], b)
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
		{ID: 1, Name: "admin", Email: "admin@example.com"},
		{ID: 2, Name: "tagowner", Email: "tagowner@example.com"},
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
	require.True(t, slices.Contains(adminPeers, taggedServer.ID),
		"admin should see tagged server")

	// Tagged server should see admin (symmetric visibility)
	// Even though the server has no outbound rules (empty filter)
	serverPeers := peerMap[taggedServer.ID]
	require.True(t, slices.Contains(serverPeers, adminDevice.ID),
		"tagged server should see admin (symmetric visibility)")
}

// TestAutogroupSelfCombinedWithTags verifies that autogroup:self combined with
// specific tags in the same rule provides "combined access" - users get both
// tagged nodes AND their own devices.
func TestAutogroupSelfCombinedWithTags(t *testing.T) {
	users := types.Users{
		{ID: 1, Name: "admin", Email: "admin@example.com"},
		{ID: 2, Name: "tagowner", Email: "tagowner@example.com"},
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
		return slices.Contains(peerMap[a], b)
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

// TestAutogroupSelfRulesReachExitNodes checks that an approved exit
// node receives every user's autogroup:self rules: its exit routes
// contain every destination, and Tailscale SaaS delivers them.
func TestAutogroupSelfRulesReachExitNodes(t *testing.T) {
	users := types.Users{
		{ID: 1, Name: "alice", Email: "alice@example.com"},
		{ID: 2, Name: "bob", Email: "bob@example.com"},
	}

	alice := &types.Node{
		ID:       1,
		Hostname: "alice",
		User:     new(users[0]),
		UserID:   new(users[0].ID),
		IPv4:     ap("100.64.0.1"),
		Hostinfo: &tailcfg.Hostinfo{},
	}

	bob := &types.Node{
		ID:       2,
		Hostname: "bob",
		User:     new(users[1]),
		UserID:   new(users[1].ID),
		IPv4:     ap("100.64.0.2"),
		Hostinfo: &tailcfg.Hostinfo{},
	}

	exit := &types.Node{
		ID:             3,
		Hostname:       "exit",
		User:           new(users[0]),
		UserID:         new(users[0].ID),
		IPv4:           ap("100.64.0.3"),
		Tags:           []string{"tag:exit"},
		Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: tsaddr.ExitRoutes()},
		ApprovedRoutes: tsaddr.ExitRoutes(),
	}

	server := &types.Node{
		ID:       4,
		Hostname: "server",
		User:     new(users[0]),
		UserID:   new(users[0].ID),
		IPv4:     ap("100.64.0.4"),
		Tags:     []string{"tag:server"},
		Hostinfo: &tailcfg.Hostinfo{},
	}

	nodes := types.Nodes{alice, bob, exit, server}

	policy := `{
		"tagOwners": {
			"tag:exit":   ["alice@example.com"],
			"tag:server": ["alice@example.com"]
		},
		"acls": [
			{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	dsts := func(n *types.Node) []string {
		rules, err := pm.FilterForNode(n.View())
		require.NoError(t, err)

		var out []string

		for _, r := range rules {
			for _, dp := range r.DstPorts {
				out = append(out, dp.IP)
			}
		}

		return out
	}

	require.ElementsMatch(t, []string{"100.64.0.1", "100.64.0.2"}, dsts(exit),
		"exit node must get every user's self rule")
	require.Empty(t, dsts(server),
		"tagged node without exit routes gets no self rules")
	require.ElementsMatch(t, []string{"100.64.0.1"}, dsts(alice),
		"user device gets only its own user's self rule")
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
		{ID: 1, Name: "user1", Email: "user1@"},
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
		return slices.Contains(peerMap[a], b)
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

func TestViaRoutesForPeer(t *testing.T) {
	t.Parallel()

	users := types.Users{
		{ID: 1, Name: "user1", Email: "user1@"},
		{ID: 2, Name: "user2", Email: "user2@"},
	}

	t.Run("self_returns_empty", func(t *testing.T) {
		t.Parallel()

		nodes := types.Nodes{
			{
				ID:       1,
				Hostname: "router",
				IPv4:     ap("100.64.0.1"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Tags:     []string{"tag:router"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{mp("10.0.0.0/24")},
				},
				ApprovedRoutes: []netip.Prefix{mp("10.0.0.0/24")},
			},
		}

		//nolint:goconst
		pol := `{
			"tagOwners": {
				"tag:router": ["user1@"]
			},
			"grants": [{
				"src": ["user1@"],
				"dst": ["10.0.0.0/24"],
				"ip": ["*"],
				"via": ["tag:router"]
			}]
		}`

		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		result := pm.ViaRoutesForPeer(nodes[0].View(), nodes[0].View())
		require.Empty(t, result.Include)
		require.Empty(t, result.Exclude)
	})

	t.Run("viewer_not_in_source", func(t *testing.T) {
		t.Parallel()

		nodes := types.Nodes{
			{
				ID:       1,
				Hostname: "viewer",
				IPv4:     ap("100.64.0.1"),
				User:     new(users[1]),
				UserID:   new(users[1].ID),
				Hostinfo: &tailcfg.Hostinfo{},
			},
			{
				ID:       2,
				Hostname: "router",
				IPv4:     ap("100.64.0.2"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Tags:     []string{"tag:router"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{mp("10.0.0.0/24")},
				},
				ApprovedRoutes: []netip.Prefix{mp("10.0.0.0/24")},
			},
		}

		//nolint:goconst
		pol := `{
			"tagOwners": {
				"tag:router": ["user1@"]
			},
			"grants": [{
				"src": ["user1@"],
				"dst": ["10.0.0.0/24"],
				"ip": ["*"],
				"via": ["tag:router"]
			}]
		}`

		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		// user2 is not in the grant source (user1@), so result should be empty.
		result := pm.ViaRoutesForPeer(nodes[0].View(), nodes[1].View())
		require.Empty(t, result.Include)
		require.Empty(t, result.Exclude)
	})

	t.Run("no_via_grant_returns_empty", func(t *testing.T) {
		t.Parallel()

		nodes := types.Nodes{
			{
				ID:       1,
				Hostname: "viewer",
				IPv4:     ap("100.64.0.1"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Hostinfo: &tailcfg.Hostinfo{},
			},
			{
				ID:       2,
				Hostname: "router",
				IPv4:     ap("100.64.0.2"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Tags:     []string{"tag:router"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{mp("10.0.0.0/24")},
				},
				ApprovedRoutes: []netip.Prefix{mp("10.0.0.0/24")},
			},
		}

		// An ACL and a grant both cover the route, neither with via.
		pol := `{
			"tagOwners": {
				"tag:router": ["user1@"]
			},
			"acls": [{
				"action": "accept",
				"src": ["autogroup:member"],
				"dst": ["10.0.0.0/24:*"]
			}],
			"grants": [{
				"src": ["user1@"],
				"dst": ["10.0.0.0/24"],
				"ip": ["*"]
			}]
		}`

		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		result := pm.ViaRoutesForPeer(nodes[0].View(), nodes[1].View())
		require.Empty(t, result.Include)
		require.Empty(t, result.Exclude)
		require.Empty(t, result.UsePrimary)
	})

	t.Run("acl_destinations_share_source_match", func(t *testing.T) {
		t.Parallel()

		nodes := types.Nodes{
			{
				ID:       1,
				Hostname: "viewer",
				IPv4:     ap("100.64.0.1"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Hostinfo: &tailcfg.Hostinfo{},
			},
			{
				ID:       2,
				Hostname: "router",
				IPv4:     ap("100.64.0.2"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Tags:     []string{"tag:router"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{mp("10.0.0.0/24")},
				},
				ApprovedRoutes: []netip.Prefix{mp("10.0.0.0/24")},
			},
		}

		// Only the last destination of each ACL covers the route, and only
		// the sources of the second ACL match the viewer.
		pol := func(secondSrc string) string {
			return `{
			"tagOwners": {
				"tag:router": ["user1@"]
			},
			"acls": [{
				"action": "accept",
				"src": ["user2@"],
				"dst": ["192.168.0.0/24:*", "10.0.0.0/24:*"]
			}, {
				"action": "accept",
				"src": ["user2@", "` + secondSrc + `"],
				"dst": ["192.168.0.0/24:*", "10.0.0.0/24:*"]
			}],
			"grants": [{
				"src": ["user1@"],
				"dst": ["10.0.0.0/24"],
				"ip": ["*"],
				"via": ["tag:router"]
			}]
		}`
		}

		pm, err := NewPolicyManager([]byte(pol("user1@")), users, nodes.ViewSlice())
		require.NoError(t, err)

		result := pm.ViaRoutesForPeer(nodes[0].View(), nodes[1].View())
		require.Equal(t, []netip.Prefix{mp("10.0.0.0/24")}, result.Include)
		require.Equal(t, []netip.Prefix{mp("10.0.0.0/24")}, result.UsePrimary)

		pm, err = NewPolicyManager([]byte(pol("user2@")), users, nodes.ViewSlice())
		require.NoError(t, err)

		result = pm.ViaRoutesForPeer(nodes[0].View(), nodes[1].View())
		require.Equal(t, []netip.Prefix{mp("10.0.0.0/24")}, result.Include)
		require.Empty(t, result.UsePrimary)
	})

	t.Run("peer_does_not_advertise_destination", func(t *testing.T) {
		t.Parallel()

		nodes := types.Nodes{
			{
				ID:       1,
				Hostname: "viewer",
				IPv4:     ap("100.64.0.1"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Hostinfo: &tailcfg.Hostinfo{},
			},
			{
				ID:       2,
				Hostname: "router",
				IPv4:     ap("100.64.0.2"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Tags:     []string{"tag:router"},
				Hostinfo: &tailcfg.Hostinfo{
					// Advertises 192.168.0.0/24, not 10.0.0.0/24.
					RoutableIPs: []netip.Prefix{mp("192.168.0.0/24")},
				},
				ApprovedRoutes: []netip.Prefix{mp("192.168.0.0/24")},
			},
		}

		pol := `{
			"tagOwners": {
				"tag:router": ["user1@"]
			},
			"grants": [{
				"src": ["user1@"],
				"dst": ["10.0.0.0/24"],
				"ip": ["*"],
				"via": ["tag:router"]
			}]
		}`

		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		result := pm.ViaRoutesForPeer(nodes[0].View(), nodes[1].View())
		require.Empty(t, result.Include)
		require.Empty(t, result.Exclude)
	})

	t.Run("peer_with_via_tag_include", func(t *testing.T) {
		t.Parallel()

		nodes := types.Nodes{
			{
				ID:       1,
				Hostname: "viewer",
				IPv4:     ap("100.64.0.1"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Hostinfo: &tailcfg.Hostinfo{},
			},
			{
				ID:       2,
				Hostname: "router",
				IPv4:     ap("100.64.0.2"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Tags:     []string{"tag:router"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{mp("10.0.0.0/24")},
				},
				ApprovedRoutes: []netip.Prefix{mp("10.0.0.0/24")},
			},
		}

		pol := `{
			"tagOwners": {
				"tag:router": ["user1@"]
			},
			"grants": [{
				"src": ["user1@"],
				"dst": ["10.0.0.0/24"],
				"ip": ["*"],
				"via": ["tag:router"]
			}]
		}`

		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		result := pm.ViaRoutesForPeer(nodes[0].View(), nodes[1].View())
		require.Equal(t, []netip.Prefix{mp("10.0.0.0/24")}, result.Include)
		require.Empty(t, result.Exclude)
	})

	t.Run("peer_without_via_tag_exclude", func(t *testing.T) {
		t.Parallel()

		nodes := types.Nodes{
			{
				ID:       1,
				Hostname: "viewer",
				IPv4:     ap("100.64.0.1"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Hostinfo: &tailcfg.Hostinfo{},
			},
			{
				ID:       2,
				Hostname: "other-router",
				IPv4:     ap("100.64.0.2"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Tags:     []string{"tag:other"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{mp("10.0.0.0/24")},
				},
				ApprovedRoutes: []netip.Prefix{mp("10.0.0.0/24")},
			},
		}

		pol := `{
			"tagOwners": {
				"tag:router": ["user1@"],
				"tag:other": ["user1@"]
			},
			"grants": [{
				"src": ["user1@"],
				"dst": ["10.0.0.0/24"],
				"ip": ["*"],
				"via": ["tag:router"]
			}]
		}`

		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		// Peer has tag:other, not tag:router, so route goes to Exclude.
		result := pm.ViaRoutesForPeer(nodes[0].View(), nodes[1].View())
		require.Empty(t, result.Include)
		require.Equal(t, []netip.Prefix{mp("10.0.0.0/24")}, result.Exclude)
	})

	t.Run("mixed_prefix_and_autogroup_internet", func(t *testing.T) {
		t.Parallel()

		nodes := types.Nodes{
			{
				ID:       1,
				Hostname: "viewer",
				IPv4:     ap("100.64.0.1"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Hostinfo: &tailcfg.Hostinfo{},
			},
			{
				ID:       2,
				Hostname: "router",
				IPv4:     ap("100.64.0.2"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Tags:     []string{"tag:router"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						mp("10.0.0.0/24"),
						mp("0.0.0.0/0"),
						mp("::/0"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					mp("10.0.0.0/24"),
					mp("0.0.0.0/0"),
					mp("::/0"),
				},
			},
		}

		pol := `{
			"tagOwners": {
				"tag:router": ["user1@"]
			},
			"grants": [{
				"src": ["user1@"],
				"dst": ["10.0.0.0/24", "autogroup:internet"],
				"ip": ["*"],
				"via": ["tag:router"]
			}]
		}`

		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		result := pm.ViaRoutesForPeer(nodes[0].View(), nodes[1].View())
		// Include contains the subnet route plus the peer's approved
		// exit routes — the peer holds tag:router and advertises exit
		// routes, so autogroup:internet steering applies alongside the
		// explicit prefix.
		require.Contains(t, result.Include, mp("10.0.0.0/24"))
		require.Contains(t, result.Include, mp("0.0.0.0/0"))
		require.Contains(t, result.Include, mp("::/0"))
		require.Len(t, result.Include, 3)
		require.Empty(t, result.Exclude)
	})

	t.Run("autogroup_internet_exit_routes", func(t *testing.T) {
		t.Parallel()

		nodes := types.Nodes{
			{
				ID:       1,
				Hostname: "viewer",
				IPv4:     ap("100.64.0.1"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Hostinfo: &tailcfg.Hostinfo{},
			},
			{
				ID:       2,
				Hostname: "exit-node",
				IPv4:     ap("100.64.0.2"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Tags:     []string{"tag:exit"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						mp("0.0.0.0/0"),
						mp("::/0"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					mp("0.0.0.0/0"),
					mp("::/0"),
				},
			},
			{
				ID:       3,
				Hostname: "non-exit",
				IPv4:     ap("100.64.0.3"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Tags:     []string{"tag:other"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						mp("0.0.0.0/0"),
						mp("::/0"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					mp("0.0.0.0/0"),
					mp("::/0"),
				},
			},
		}

		pol := `{
			"tagOwners": {
				"tag:exit": ["user1@"],
				"tag:other": ["user1@"]
			},
			"grants": [{
				"src": ["user1@"],
				"dst": ["autogroup:internet"],
				"ip": ["*"],
				"via": ["tag:exit"]
			}]
		}`

		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		// autogroup:internet via grants surface the peer's approved
		// exit routes when the peer carries the via tag, and exclude
		// them when it does not — restricting which exit nodes the
		// viewer may use, per Tailscale's grants-via spec for
		// autogroup:internet.
		resultExit := pm.ViaRoutesForPeer(nodes[0].View(), nodes[1].View())
		require.Contains(t, resultExit.Include, mp("0.0.0.0/0"))
		require.Contains(t, resultExit.Include, mp("::/0"))
		require.Empty(t, resultExit.Exclude)

		resultOther := pm.ViaRoutesForPeer(nodes[0].View(), nodes[2].View())
		require.Empty(t, resultOther.Include)
		require.Contains(t, resultOther.Exclude, mp("0.0.0.0/0"))
		require.Contains(t, resultOther.Exclude, mp("::/0"))
	})

	t.Run("via_routes_survive_reduce_routes", func(t *testing.T) {
		t.Parallel()

		// This test validates that via-included routes are not
		// filtered out by ReduceRoutes. The viewer's matchers
		// allow tag-to-tag IP connectivity but don't explicitly
		// cover the subnet prefix, so ReduceRoutes alone would
		// drop it. The fix in state.RoutesForPeer applies
		// ReduceRoutes first, then appends via-included routes.

		nodes := types.Nodes{
			{
				ID:       1,
				Hostname: "client",
				IPv4:     ap("100.64.0.1"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Tags:     []string{"tag:group-a"},
				Hostinfo: &tailcfg.Hostinfo{},
			},
			{
				ID:       2,
				Hostname: "router",
				IPv4:     ap("100.64.0.2"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Tags:     []string{"tag:router-a"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{mp("10.0.0.0/24")},
				},
				ApprovedRoutes: []netip.Prefix{mp("10.0.0.0/24")},
			},
		}

		pol := `{
			"tagOwners": {
				"tag:router-a": ["user1@"],
				"tag:group-a":  ["user1@"]
			},
			"grants": [
				{
					"src": ["tag:group-a", "tag:router-a"],
					"dst": ["tag:group-a", "tag:router-a"],
					"ip": ["*"]
				},
				{
					"src": ["tag:group-a"],
					"dst": ["10.0.0.0/24"],
					"ip": ["*"],
					"via": ["tag:router-a"]
				}
			]
		}`

		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		client := nodes[0].View()
		router := nodes[1].View()

		// ViaRoutesForPeer says router should include 10.0.0.0/24.
		viaResult := pm.ViaRoutesForPeer(client, router)
		require.Equal(t, []netip.Prefix{mp("10.0.0.0/24")}, viaResult.Include)
		require.Empty(t, viaResult.Exclude)

		// Matchers for the client cover tag-to-tag connectivity
		// but do NOT cover the 10.0.0.0/24 subnet prefix.
		matchers, err := pm.MatchersForNode(client)
		require.NoError(t, err)
		require.NotEmpty(t, matchers)

		// CanAccessRoute with the client's matchers returns false for
		// 10.0.0.0/24 because the matchers only cover tag-to-tag IPs.
		// This means ReduceRoutes would filter it out, which is why
		// state.RoutesForPeer must add via routes AFTER ReduceRoutes.
		canAccess := client.CanAccessRoute(matchers, mp("10.0.0.0/24"))
		require.False(t, canAccess,
			"client should NOT be able to access 10.0.0.0/24 via matchers alone; "+
				"state.RoutesForPeer adds via routes after ReduceRoutes to fix this")
	})

	t.Run("broader_dst_includes_narrower_advertised_route", func(t *testing.T) {
		t.Parallel()

		nodes := types.Nodes{
			{
				ID:       1,
				Hostname: "viewer",
				IPv4:     ap("100.64.0.1"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Hostinfo: &tailcfg.Hostinfo{},
			},
			{
				ID:       2,
				Hostname: "router",
				IPv4:     ap("100.64.0.2"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Tags:     []string{"tag:router"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{mp("10.33.5.0/24")},
				},
				ApprovedRoutes: []netip.Prefix{mp("10.33.5.0/24")},
			},
		}

		pol := `{
			"tagOwners": {
				"tag:router": ["user1@"]
			},
			"grants": [{
				"src": ["user1@"],
				"dst": ["10.0.0.0/8"],
				"ip": ["*"],
				"via": ["tag:router"]
			}]
		}`

		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		result := pm.ViaRoutesForPeer(nodes[0].View(), nodes[1].View())
		require.Equal(t, []netip.Prefix{mp("10.33.5.0/24")}, result.Include,
			"Include must hold the advertised route /24, not the broader grant dst /8")
		require.Empty(t, result.Exclude)
	})

	t.Run("narrower_dst_includes_advertised_route", func(t *testing.T) {
		t.Parallel()

		nodes := types.Nodes{
			{
				ID:       1,
				Hostname: "viewer",
				IPv4:     ap("100.64.0.1"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Hostinfo: &tailcfg.Hostinfo{},
			},
			{
				ID:       2,
				Hostname: "router",
				IPv4:     ap("100.64.0.2"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Tags:     []string{"tag:router"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{mp("10.33.0.0/16")},
				},
				ApprovedRoutes: []netip.Prefix{mp("10.33.0.0/16")},
			},
		}

		pol := `{
			"tagOwners": {
				"tag:router": ["user1@"]
			},
			"grants": [{
				"src": ["user1@"],
				"dst": ["10.33.5.0/24"],
				"ip": ["*"],
				"via": ["tag:router"]
			}]
		}`

		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		result := pm.ViaRoutesForPeer(nodes[0].View(), nodes[1].View())
		require.Equal(t, []netip.Prefix{mp("10.33.0.0/16")}, result.Include,
			"Include must hold the advertised route /16 that covers the narrower grant dst /24")
		require.Empty(t, result.Exclude)
	})

	t.Run("disjoint_dst_emits_nothing", func(t *testing.T) {
		t.Parallel()

		nodes := types.Nodes{
			{
				ID:       1,
				Hostname: "viewer",
				IPv4:     ap("100.64.0.1"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Hostinfo: &tailcfg.Hostinfo{},
			},
			{
				ID:       2,
				Hostname: "router",
				IPv4:     ap("100.64.0.2"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Tags:     []string{"tag:router"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{mp("10.33.0.0/16")},
				},
				ApprovedRoutes: []netip.Prefix{mp("10.33.0.0/16")},
			},
		}

		pol := `{
			"tagOwners": {
				"tag:router": ["user1@"]
			},
			"grants": [{
				"src": ["user1@"],
				"dst": ["192.168.0.0/16"],
				"ip": ["*"],
				"via": ["tag:router"]
			}]
		}`

		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		result := pm.ViaRoutesForPeer(nodes[0].View(), nodes[1].View())
		require.Empty(t, result.Include,
			"disjoint dst must produce nothing — the via gate requires advertised-route overlap")
		require.Empty(t, result.Exclude)
	})

	// juanfont/headscale#3513: a group member must get via-steered exit
	// routes even when another member of the group has not registered.
	// The group resolves to the registered members' IPs plus an error
	// for the missing one; the error must not drop the resolved IPs.
	t.Run("group_src_with_unregistered_member_autogroup_internet", func(t *testing.T) {
		t.Parallel()

		nodes := types.Nodes{
			{
				ID:       1,
				Hostname: "viewer",
				IPv4:     ap("100.64.0.1"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Hostinfo: &tailcfg.Hostinfo{},
			},
			{
				ID:       2,
				Hostname: "exit-node",
				IPv4:     ap("100.64.0.2"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Tags:     []string{"tag:exit"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						mp("0.0.0.0/0"),
						mp("::/0"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					mp("0.0.0.0/0"),
					mp("::/0"),
				},
			},
		}

		for _, members := range []string{
			`["user1@"]`,
			`["user1@", "unregistered@"]`,
		} {
			pol := `{
				"groups": {"group:develop": ` + members + `},
				"tagOwners": {"tag:exit": ["user1@"]},
				"grants": [{
					"src": ["group:develop"],
					"dst": ["autogroup:internet"],
					"ip": ["*"],
					"via": ["tag:exit"]
				}]
			}`

			pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
			require.NoError(t, err)

			// The exit node's filter already admits the viewer: the
			// compile path keeps a group's partial resolution.
			rules, err := pm.FilterForNode(nodes[1].View())
			require.NoError(t, err)
			require.NotEmpty(t, rules, "members=%s: exit node must accept viewer traffic", members)

			result := pm.ViaRoutesForPeer(nodes[0].View(), nodes[1].View())
			require.Containsf(t, result.Include, mp("0.0.0.0/0"),
				"members=%s: viewer in group must get exit routes from via-tagged exit node", members)
			require.Containsf(t, result.Include, mp("::/0"),
				"members=%s: viewer in group must get exit routes from via-tagged exit node", members)
			require.Empty(t, result.Exclude)
		}
	})

	// A route is steered once, however many dst prefixes or grants overlap
	// it and however often the peer announces it. Otherwise Include grows
	// with the policy instead of the peer's routes, and the election pass,
	// which walks Include per dst, goes quadratic under the policy lock.
	t.Run("route_steered_once_per_peer", func(t *testing.T) {
		t.Parallel()

		nodes := types.Nodes{
			{
				ID:       1,
				Hostname: "viewer",
				IPv4:     ap("100.64.0.1"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Hostinfo: &tailcfg.Hostinfo{},
			},
			{
				ID:       2,
				Hostname: "router",
				IPv4:     ap("100.64.0.2"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Tags:     []string{"tag:router"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{mp("10.0.0.0/24"), mp("10.0.0.0/24")},
				},
				ApprovedRoutes: []netip.Prefix{mp("10.0.0.0/24")},
			},
			{
				ID:       3,
				Hostname: "other",
				IPv4:     ap("100.64.0.3"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Tags:     []string{"tag:other"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{mp("10.0.0.0/24"), mp("10.0.0.0/24")},
				},
				ApprovedRoutes: []netip.Prefix{mp("10.0.0.0/24")},
			},
		}

		grant := `{
			"src": ["user1@"],
			"dst": ["10.0.0.0/24", "10.0.0.0/24", "10.0.0.0/25", "10.0.0.7/32"],
			"ip": ["*"],
			"via": ["tag:router"]
		}`

		pol := `{
			"tagOwners": {
				"tag:router": ["user1@"],
				"tag:other": ["user1@"]
			},
			"grants": [` + grant + `, ` + grant + `]
		}`

		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		result := pm.ViaRoutesForPeer(nodes[0].View(), nodes[1].View())
		require.Equal(t, []netip.Prefix{mp("10.0.0.0/24")}, result.Include)
		require.Empty(t, result.Exclude)

		result = pm.ViaRoutesForPeer(nodes[0].View(), nodes[2].View())
		require.Empty(t, result.Include)
		require.Equal(t, []netip.Prefix{mp("10.0.0.0/24")}, result.Exclude)
	})

	t.Run("via_election_skips_unavailable_routers", func(t *testing.T) {
		t.Parallel()

		route := mp("10.0.0.0/24")
		nodes := types.Nodes{
			{
				ID:       1,
				Hostname: "viewer",
				IPv4:     ap("100.64.0.1"),
				User:     new(users[0]),
				UserID:   new(users[0].ID),
				Tags:     []string{"tag:group-a"},
				Hostinfo: &tailcfg.Hostinfo{},
			},
		}

		for id := types.NodeID(2); id <= 4; id++ {
			nodes = append(nodes, &types.Node{
				ID:             id,
				Hostname:       fmt.Sprintf("router-%d", id),
				IPv4:           ap(fmt.Sprintf("100.64.0.%d", id)),
				User:           new(users[0]),
				UserID:         new(users[0].ID),
				Tags:           []string{"tag:router-a"},
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}},
				ApprovedRoutes: []netip.Prefix{route},
			})
		}

		pol := `{
			"tagOwners": {
				"tag:router-a": ["user1@"],
				"tag:group-a": ["user1@"]
			},
			"grants": [{
				"src": ["tag:group-a"],
				"dst": ["10.0.0.0/24"],
				"ip": ["*"],
				"via": ["tag:router-a"]
			}]
		}`
		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		// sessions maps each available router to when its control session
		// began.
		at := func(sec int64) time.Time { return time.Unix(sec, 0) }

		for _, tt := range []struct {
			name     string
			sessions map[types.NodeID]time.Time
			want     types.NodeID
		}{
			{name: "all available", sessions: map[types.NodeID]time.Time{2: at(1), 3: at(1), 4: at(1)}, want: 2},
			{name: "lowest ID down", sessions: map[types.NodeID]time.Time{3: at(1), 4: at(1)}, want: 3},
			{name: "only highest ID left", sessions: map[types.NodeID]time.Time{4: at(1)}, want: 4},
			{name: "whole group down", want: 2},
			{name: "oldest session wins", sessions: map[types.NodeID]time.Time{2: at(3), 3: at(1), 4: at(2)}, want: 3},
		} {
			t.Run(tt.name, func(t *testing.T) {
				pm.SetRouterSession(func(id types.NodeID) (time.Time, bool) {
					since, ok := tt.sessions[id]

					return since, ok
				})

				for _, router := range nodes[1:] {
					result := pm.ViaRoutesForPeer(nodes[0].View(), router.View())
					if router.ID == tt.want {
						require.Equal(t, []netip.Prefix{route}, result.Include)
						require.Empty(t, result.Exclude)
					} else {
						require.Empty(t, result.Include)
						require.Equal(t, []netip.Prefix{route}, result.Exclude)
					}
				}
			})
		}
	})
}

// TestBuildPeerMap_AutogroupInternetMakesExitNodeVisible reproduces
// juanfont/headscale#3212. An ACL that grants access only via
// `autogroup:internet` must keep the exit node visible to the source
// in BuildPeerMap so the Tailscale client surfaces it in
// `tailscale exit-node list`. Authoritative SaaS captures
// (routes-b17/b18, 2026-04-28) confirm SaaS includes the exit node
// in the source's Peers with 0.0.0.0/0 and ::/0 in AllowedIPs.
func TestBuildPeerMap_AutogroupInternetMakesExitNodeVisible(t *testing.T) {
	t.Parallel()

	users := types.Users{
		{ID: 1, Name: "alice", Email: "alice@headscale.net"},
	}

	aliceNode := node("alice-laptop", "100.64.0.10", "fd7a:115c:a1e0::a", users[0])
	aliceNode.ID = 1

	exitRoutes := []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6()}
	exitNode := node("alice-exit", "100.64.0.1", "fd7a:115c:a1e0::1", users[0])
	exitNode.ID = 2
	exitNode.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: exitRoutes}
	exitNode.ApprovedRoutes = exitRoutes

	nodes := types.Nodes{aliceNode, exitNode}

	policy := `{
		"acls": [
			{"action": "accept", "src": ["alice@headscale.net"], "dst": ["autogroup:internet:*"]}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	peerMap := pm.BuildPeerMap(nodes.ViewSlice())

	require.True(t,
		slices.Contains(peerMap[aliceNode.ID], exitNode.ID),
		"alice should see the exit node as a peer when an ACL grants autogroup:internet (#3212)")

	_, matchers := pm.Filter()
	require.True(t, aliceNode.View().CanAccess(matchers, exitNode.View()),
		"alice.CanAccess(exit) should be true via DestsIsTheInternet()+IsExitNode() (#3212)")
}

// Reproduction for #3160: ambiguous user@ used to silently drop rules.
func TestNewPolicyManager_DuplicateUsername(t *testing.T) {
	users := types.Users{
		{ID: 2, Name: "yala"},
		{ID: 7, Name: "yala", Email: "yala@yala.yala"},
	}

	polB := []byte(`{
  "groups":    {"group:admins": ["yala@"]},
  "tagOwners": {"tag:ssh": ["group:admins"]},
  "acls":      [{"action":"accept","src":["*"],"dst":["*:*"]}],
  "ssh": [
    {"action":"accept","src":["group:admins"],"dst":["tag:ssh"],"users":["root"]}
  ]
}`)

	_, err := NewPolicyManager(polB, users, types.Nodes{}.ViewSlice())
	require.Error(t, err, "NewPolicyManager must reject policy with ambiguous username")
	require.ErrorIs(t, err, ErrMultipleUsersFound)
	require.Contains(t, err.Error(), "yala@",
		"error must name the offending token")
}

// Missing-user tokens stay tolerant per #2863; only multi-match blocks load.
func TestNewPolicyManager_UnknownUsernameTolerant(t *testing.T) {
	users := types.Users{
		{ID: 1, Name: "alice"},
	}

	polB := []byte(`{
  "acls": [{"action":"accept","src":["ghost@"],"dst":["*:*"]}]
}`)

	_, err := NewPolicyManager(polB, users, types.Nodes{}.ViewSlice())
	require.NoError(t, err, "missing-user references must not block policy load (#2863)")
}

// TestUnregisteredUsersAreNoOp pins, at every policy site that takes users,
// that naming a user who has not registered changes nothing (#3513).
// Tailscale accepts such policies; the user gains access once they join and
// loses it when deleted. Swapping in a registered user proves each site has
// an observable effect, so an equal result is not vacuous.
func TestUnregisteredUsersAreNoOp(t *testing.T) {
	t.Parallel()

	// IDs are assigned after construction so the test also builds where
	// types.User embeds gorm.Model.
	all := types.Users{{Name: "alice"}, {Name: "bob"}, {Name: "ghost"}}
	all[0].ID, all[1].ID, all[2].ID = 1, 2, 3
	registered := all[:2:2]

	exitRoutes := []netip.Prefix{mp("0.0.0.0/0"), mp("::/0")}
	userRoutes := []netip.Prefix{mp("10.44.0.0/16"), mp("0.0.0.0/0"), mp("::/0")}

	// mkNodes adds ghost's node, advertising routes for autoApprovers to
	// act on, when users includes ghost.
	mkNodes := func(users types.Users) types.Nodes {
		withHostinfo := func(n *types.Node, tags []string, routes, approved []netip.Prefix) *types.Node {
			n.Tags = tags
			n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: routes}
			n.ApprovedRoutes = approved

			return n
		}

		nodes := types.Nodes{
			withHostinfo(node("alice", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]), nil, nil, nil),
			withHostinfo(node("alice-router", "100.64.0.2", "fd7a:115c:a1e0::2", users[0]), nil, userRoutes, nil),
			withHostinfo(node("bob", "100.64.0.3", "fd7a:115c:a1e0::3", users[1]), nil, nil, nil),
			withHostinfo(node("exit", "100.64.0.4", "fd7a:115c:a1e0::4", users[1]),
				[]string{"tag:exit"}, exitRoutes, exitRoutes),
			withHostinfo(node("router", "100.64.0.5", "fd7a:115c:a1e0::5", users[1]),
				[]string{"tag:router"}, []netip.Prefix{mp("10.33.0.0/16")}, []netip.Prefix{mp("10.33.0.0/16")}),
			withHostinfo(node("server", "100.64.0.6", "fd7a:115c:a1e0::6", users[1]),
				[]string{"tag:server"}, nil, nil),
		}
		if len(users) > 2 {
			nodes = append(nodes, withHostinfo(
				node("ghost", "100.64.0.7", "fd7a:115c:a1e0::7", users[2]), nil, userRoutes, nil))
		}

		for i, n := range nodes {
			n.ID = types.NodeID(i + 1) //nolint:gosec
		}

		return nodes
	}

	// Each body receives the member list; group cases put it in group:g,
	// list cases name the users directly.
	tests := []struct {
		name      string
		devOwners string
		body      func(members string) string
	}{
		{name: "acl src group", body: func(string) string {
			return `"acls": [{"action": "accept", "src": ["group:g"], "dst": ["tag:server:22"]}]`
		}},
		{name: "acl src list", body: func(m string) string {
			return `"acls": [{"action": "accept", "src": [` + m + `], "dst": ["tag:server:22"]}]`
		}},
		{name: "acl dst group", body: func(string) string {
			return `"acls": [{"action": "accept", "src": ["tag:server"], "dst": ["group:g:*"]}]`
		}},
		{name: "acl autogroup:self", body: func(string) string {
			return `"acls": [{"action": "accept", "src": ["group:g"], "dst": ["autogroup:self:*"]}]`
		}},
		{name: "grant ip group", body: func(string) string {
			return `"grants": [{"src": ["group:g"], "dst": ["tag:server"], "ip": ["tcp:443"]}]`
		}},
		{name: "grant via exit group", body: func(string) string {
			return `"grants": [{"src": ["group:g"], "dst": ["autogroup:internet"], "ip": ["*"], "via": ["tag:exit"]}]`
		}},
		{name: "grant via exit list", body: func(m string) string {
			return `"grants": [{"src": [` + m + `], "dst": ["autogroup:internet"], "ip": ["*"], "via": ["tag:exit"]}]`
		}},
		{name: "grant via subnet group", body: func(string) string {
			return `"grants": [{"src": ["group:g"], "dst": ["10.33.0.0/16"], "ip": ["*"], "via": ["tag:router"]}]`
		}},
		{name: "grant app dst group", body: func(string) string {
			return `"grants": [{"src": ["tag:server"], "dst": ["group:g"], "app": {"tailscale.com/cap/relay": [{}]}}]`
		}},
		{name: "ssh accept group", body: func(string) string {
			return `"ssh": [{"action": "accept", "src": ["group:g"], "dst": ["tag:server"], "users": ["root"]}]`
		}},
		{name: "ssh accept list", body: func(m string) string {
			return `"ssh": [{"action": "accept", "src": [` + m + `], "dst": ["tag:server"], "users": ["root"]}]`
		}},
		{name: "ssh autogroup:self", body: func(string) string {
			return `"ssh": [{"action": "accept", "src": ["group:g"], "dst": ["autogroup:self"], "users": ["root"]}]`
		}},
		{name: "ssh check group", body: func(string) string {
			return `"ssh": [{"action": "check", "checkPeriod": "2h", "src": ["group:g"], "dst": ["tag:server"], "users": ["root"]}]`
		}},
		{name: "tagOwners group", devOwners: `"group:g"`, body: func(string) string { return "" }},
		{name: "tagOwners list", devOwners: "LIST", body: func(string) string { return "" }},
		{name: "autoApprovers routes group", body: func(string) string {
			return `"autoApprovers": {"routes": {"10.44.0.0/16": ["group:g"]}}`
		}},
		{name: "autoApprovers exitNode group", body: func(string) string {
			return `"autoApprovers": {"exitNode": ["group:g"]}`
		}},
		{name: "nodeAttrs group", body: func(string) string {
			return `"nodeAttrs": [{"target": ["group:g"], "attr": ["randomize-client-port"]}]`
		}},
		{name: "nodeAttrs list", body: func(m string) string {
			return `"nodeAttrs": [{"target": [` + m + `], "attr": ["randomize-client-port"]}]`
		}},
	}

	type checkParams struct {
		Period time.Duration
		OK     bool
	}

	// snapshot gathers every per-node and per-pair result a policy drives.
	snapshot := func(t *testing.T, pm *PolicyManager, nodes types.Nodes) map[string]any {
		t.Helper()

		got := map[string]any{}
		got["filter"], _ = pm.Filter()
		peers := pm.BuildPeerMap(nodes.ViewSlice())

		for _, n := range nodes {
			nv := n.View()

			rules, err := pm.FilterForNode(nv)
			require.NoError(t, err)

			ssh, err := pm.SSHPolicy("", nv)
			require.NoError(t, err)

			ids := slices.Clone(peers[n.ID])
			slices.Sort(ids)

			got[n.Hostname+" filter"] = rules
			got[n.Hostname+" ssh"] = ssh
			got[n.Hostname+" caps"] = pm.NodeCapMap(n.ID)
			got[n.Hostname+" peers"] = ids
			got[n.Hostname+" tag:dev"] = pm.NodeCanHaveTag(nv, "tag:dev")

			for _, r := range n.Hostinfo.RoutableIPs {
				got[n.Hostname+" approves "+r.String()] = pm.NodeCanApproveRoute(nv, r)
			}

			for _, p := range nodes {
				if p.ID == n.ID {
					continue
				}

				period, ok := pm.SSHCheckParams(n.ID, p.ID, "alice")
				got[n.Hostname+"->"+p.Hostname+" via"] = pm.ViaRoutesForPeer(nv, p.View())
				got[n.Hostname+"->"+p.Hostname+" check"] = checkParams{period, ok}
			}
		}

		return got
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			render := func(members string) []byte {
				devOwners := tt.devOwners
				switch devOwners {
				case "":
					devOwners = `"bob@"`
				case "LIST":
					devOwners = members
				}

				return []byte(`{
					"groups": {"group:g": [` + members + `]},
					"tagOwners": {
						"tag:exit": ["bob@"], "tag:router": ["bob@"], "tag:server": ["bob@"],
						"tag:dev": [` + devOwners + `],
					},
					` + tt.body(members) + `
				}`)
			}

			load := func(members string, users types.Users, nodes types.Nodes) *PolicyManager {
				t.Helper()

				pm, err := NewPolicyManager(render(members), users, nodes.ViewSlice())
				require.NoError(t, err, "a policy naming an unregistered user must load")

				return pm
			}

			diff := func(want, got map[string]any) string {
				return cmp.Diff(want, got, cmpOptions()...)
			}

			const (
				withGhost = `"alice@", "ghost@"`
				alice     = `"alice@"`
			)

			nodes := mkNodes(registered)
			want := snapshot(t, load(alice, registered, nodes), nodes)
			pm := load(withGhost, registered, nodes)

			require.Empty(t, diff(want, snapshot(t, pm, nodes)),
				"an unregistered user must change nothing")
			require.NotEmpty(t, diff(want, snapshot(t, load(`"bob@"`, registered, nodes), nodes)),
				"the site must react to its members")

			// ghost registers, then their node joins.
			grown := mkNodes(all)

			_, _, err := pm.SetUsers(all)
			require.NoError(t, err)
			_, err = pm.SetNodes(grown.ViewSlice())
			require.NoError(t, err)

			joined := snapshot(t, pm, grown)
			require.Empty(t, diff(snapshot(t, load(withGhost, all, grown), grown), joined),
				"after joining, ghost must match a fresh load")
			require.NotEmpty(t, diff(snapshot(t, load(alice, all, grown), grown), joined),
				"after joining, ghost must gain access")

			// ghost's node leaves, then ghost is deleted.
			_, err = pm.SetNodes(nodes.ViewSlice())
			require.NoError(t, err)
			_, _, err = pm.SetUsers(registered)
			require.NoError(t, err)

			require.Empty(t, diff(want, snapshot(t, pm, nodes)),
				"after deletion, ghost must leave no trace")
		})
	}
}

// Rejected SetPolicy must keep the previous policy intact.
func TestSetPolicy_DuplicateUsername(t *testing.T) {
	users := types.Users{
		{ID: 2, Name: "yala"},
		{ID: 7, Name: "yala", Email: "yala@yala.yala"},
	}

	good := []byte(`{
  "acls": [{"action":"accept","src":["*"],"dst":["*:*"]}]
}`)

	pm, err := NewPolicyManager(good, users, types.Nodes{}.ViewSlice())
	require.NoError(t, err)

	bad := []byte(`{
  "groups": {"group:admins": ["yala@"]},
  "acls":   [{"action":"accept","src":["group:admins"],"dst":["*:*"]}]
}`)

	_, err = pm.SetPolicy(bad)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMultipleUsersFound)

	filter, _ := pm.Filter()
	require.NotNil(t, filter, "filter must remain populated after rejected SetPolicy")
}

// Empty users → syntax-only check, used by `headscale policy check`.
func TestValidateUserReferences_EmptyUsersTolerant(t *testing.T) {
	polB := []byte(`{
  "groups":    {"group:admins": ["yala@"]},
  "tagOwners": {"tag:ssh": ["group:admins"]},
  "acls":      [{"action":"accept","src":["yala@"],"dst":["*:*"]}],
  "ssh": [
    {"action":"accept","src":["yala@"],"dst":["tag:ssh"],"users":["root"]}
  ]
}`)

	_, err := NewPolicyManager(polB, nil, types.Nodes{}.ViewSlice())
	require.NoError(t, err, "nil users must skip user-reference validation")

	_, err = NewPolicyManager(polB, types.Users{}, types.Nodes{}.ViewSlice())
	require.NoError(t, err, "empty users must skip user-reference validation")
}

// One case per AST site so a dropped walk fails the matching subtest.
func TestValidateUserReferences_AllSites(t *testing.T) {
	users := types.Users{
		{ID: 1, Name: "alice"},
		{ID: 2, Name: "dup"},
		{ID: 3, Name: "dup"},
	}
	nodes := types.Nodes{node("alice", "100.64.0.1", "fd7a:115c:a1e0::1", users[0])}
	nodes[0].ID = 1

	tests := []struct {
		name string
		pol  string
	}{
		{
			name: "groups",
			pol: `{
  "groups": {"group:admins": ["dup@"]},
  "acls":   [{"action":"accept","src":["group:admins"],"dst":["*:*"]}]
}`,
		},
		{
			name: "tagOwners",
			pol: `{
  "tagOwners": {"tag:ssh": ["dup@"]},
  "acls":      [{"action":"accept","src":["*"],"dst":["*:*"]}]
}`,
		},
		{
			name: "autoApprovers.routes",
			pol: `{
  "autoApprovers": {"routes": {"10.0.0.0/8": ["dup@"]}},
  "acls":          [{"action":"accept","src":["*"],"dst":["*:*"]}]
}`,
		},
		{
			name: "autoApprovers.exitNode",
			pol: `{
  "autoApprovers": {"exitNode": ["dup@"]},
  "acls":          [{"action":"accept","src":["*"],"dst":["*:*"]}]
}`,
		},
		{
			name: "acls.src",
			pol: `{
  "acls": [{"action":"accept","src":["dup@"],"dst":["*:*"]}]
}`,
		},
		{
			name: "acls.dst",
			pol: `{
  "acls": [{"action":"accept","src":["alice@"],"dst":["dup@:*"]}]
}`,
		},
		{
			name: "grants.src",
			pol: `{
  "grants": [{"src":["dup@"],"dst":["*"],"ip":["*"]}]
}`,
		},
		{
			name: "grants.dst",
			pol: `{
  "grants": [{"src":["alice@"],"dst":["dup@"],"ip":["*"]}]
}`,
		},
		{
			name: "ssh.src",
			pol: `{
  "tagOwners": {"tag:ssh": ["alice@"]},
  "acls":      [{"action":"accept","src":["*"],"dst":["*:*"]}],
  "ssh": [{"action":"accept","src":["dup@"],"dst":["tag:ssh"],"users":["root"]}]
}`,
		},
		{
			name: "nodeAttrs.target",
			pol: `{
  "acls":      [{"action":"accept","src":["*"],"dst":["*:*"]}],
  "nodeAttrs": [{"target":["dup@"],"attr":["randomize-client-port"]}]
}`,
		},
		{
			// ErrSSHUserDestRequiresSameUser forces src==dst when dst is a user.
			name: "ssh.dst",
			pol: `{
  "acls": [{"action":"accept","src":["*"],"dst":["*:*"]}],
  "ssh": [{"action":"accept","src":["dup@"],"dst":["dup@"],"users":["root"]}]
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pol, err := unmarshalPolicy([]byte(tt.pol))
			require.NoError(t, err)

			err = validateUserReferences(pol, users)
			require.Error(t, err, "site %q must surface duplicate-user errors", tt.name)
			require.ErrorIs(t, err, ErrMultipleUsersFound)

			pm, err := NewPolicyManager([]byte(`{
  "acls": [{"action":"accept","src":["alice@"],"dst":["alice@:*"]}]
}`), users, nodes.ViewSlice())
			require.NoError(t, err)

			before, _ := pm.Filter()

			_, err = pm.SetPolicy([]byte(tt.pol))
			require.ErrorIs(t, err, ErrMultipleUsersFound)

			after, _ := pm.Filter()
			require.Equal(t, before, after, "a rejected policy must not replace the live filter")
		})
	}
}

// TestPeerRelayGrantMakesRelayVisible is a regression test for
// https://github.com/juanfont/headscale/issues/3256.
//
// A grant that uses only `app: { "tailscale.com/cap/relay": [] }` must
// make the relay node visible to the source nodes (and vice-versa).
// Before the fix, MatchFromFilterRule only considered DstPorts as
// destinations and ignored CapGrant.Dsts, so cap-grant-only rules
// produced matchers with an empty destination set and BuildPeerMap
// could not detect the cap-relay relationship.
//
// Sub-tests cover every alias shape documented for peer-relay grants
// at https://tailscale.com/docs/features/peer-relay: tag→tag,
// hostname→hostname (`hosts` block lookup), autogroup:member→hostname,
// and a direct Tailscale-IP destination. Each must establish mutual
// visibility between sources and the relay node without any companion
// IP-level grant.
func TestPeerRelayGrantMakesRelayVisible(t *testing.T) {
	users := types.Users{
		{ID: 1, Name: "alice", Email: "alice@headscale.net"},
		{ID: 2, Name: "tagowner", Email: "tagowner@headscale.net"},
	}

	// Helper for tagged nodes belonging to the tag-owner user.
	taggedNode := func(id types.NodeID, hostname, v4, v6 string, tags ...string) *types.Node {
		return &types.Node{
			ID:       id,
			Hostname: hostname,
			IPv4:     ap(v4),
			IPv6:     ap(v6),
			User:     new(users[1]),
			UserID:   new(users[1].ID),
			Tags:     tags,
		}
	}

	userNode := func(id types.NodeID, hostname, v4, v6 string) *types.Node {
		return &types.Node{
			ID:       id,
			Hostname: hostname,
			IPv4:     ap(v4),
			IPv6:     ap(v6),
			User:     new(users[0]),
			UserID:   new(users[0].ID),
		}
	}

	tests := []struct {
		name    string
		nodes   types.Nodes
		policy  string
		srcIDs  []types.NodeID // expected to see the relay
		relayID types.NodeID
	}{
		{
			// Issue #3256 example: hosts block + autogroup:member src,
			// hostname dst.
			name: "hosts+autogroup_member src, hostname dst",
			nodes: types.Nodes{
				userNode(1, "n1", "100.64.0.1", "fd7a:115c:a1e0::1"),
				userNode(2, "n2", "100.64.0.2", "fd7a:115c:a1e0::2"),
				userNode(3, "peer-relay", "100.64.0.3", "fd7a:115c:a1e0::3"),
			},
			policy: `{
				"hosts": {
					"n1":         "100.64.0.1/32",
					"n2":         "100.64.0.2/32",
					"peer-relay": "100.64.0.3/32"
				},
				"grants": [
					{"src": ["n1"], "dst": ["n2"], "ip": ["*"]},
					{
						"src": ["autogroup:member"],
						"dst": ["peer-relay"],
						"app": {"tailscale.com/cap/relay": []}
					}
				]
			}`,
			srcIDs:  []types.NodeID{1, 2},
			relayID: 3,
		},
		{
			// Tailscale docs example 1: tag → tag.
			name: "tag src, tag dst",
			nodes: types.Nodes{
				taggedNode(1, "vpc-a", "100.64.0.1", "fd7a:115c:a1e0::1", "tag:us-east-vpc"),
				taggedNode(2, "vpc-b", "100.64.0.2", "fd7a:115c:a1e0::2", "tag:us-east-vpc"),
				taggedNode(3, "relay-1", "100.64.0.3", "fd7a:115c:a1e0::3", "tag:us-east-relays"),
			},
			policy: `{
				"tagOwners": {
					"tag:us-east-vpc":    ["tagowner@headscale.net"],
					"tag:us-east-relays": ["tagowner@headscale.net"]
				},
				"grants": [
					{
						"src": ["tag:us-east-vpc"],
						"dst": ["tag:us-east-relays"],
						"app": {"tailscale.com/cap/relay": []}
					}
				]
			}`,
			srcIDs:  []types.NodeID{1, 2},
			relayID: 3,
		},
		{
			// Direct Tailscale-IP destination (no hosts alias).
			name: "tag src, raw Tailscale IP dst",
			nodes: types.Nodes{
				taggedNode(1, "client-a", "100.64.0.1", "fd7a:115c:a1e0::1", "tag:client"),
				taggedNode(2, "client-b", "100.64.0.2", "fd7a:115c:a1e0::2", "tag:client"),
				userNode(3, "peer-relay", "100.64.0.3", "fd7a:115c:a1e0::3"),
			},
			policy: `{
				"tagOwners": {
					"tag:client": ["tagowner@headscale.net"]
				},
				"grants": [
					{
						"src": ["tag:client"],
						"dst": ["100.64.0.3/32"],
						"app": {"tailscale.com/cap/relay": []}
					}
				]
			}`,
			srcIDs:  []types.NodeID{1, 2},
			relayID: 3,
		},
		{
			// User → hostname relay using `hosts` aliasing.
			name: "user src, hostname dst via hosts block",
			nodes: types.Nodes{
				userNode(1, "n1", "100.64.0.1", "fd7a:115c:a1e0::1"),
				userNode(3, "peer-relay", "100.64.0.3", "fd7a:115c:a1e0::3"),
			},
			policy: `{
				"hosts": {
					"peer-relay": "100.64.0.3/32"
				},
				"grants": [
					{
						"src": ["alice@headscale.net"],
						"dst": ["peer-relay"],
						"app": {"tailscale.com/cap/relay": []}
					}
				]
			}`,
			srcIDs:  []types.NodeID{1},
			relayID: 3,
		},
		{
			// One unregistered member must not drop the cap grant (#3513).
			name: "tag src, group dst with unregistered member",
			nodes: types.Nodes{
				taggedNode(1, "client-a", "100.64.0.1", "fd7a:115c:a1e0::1", "tag:client"),
				userNode(3, "peer-relay", "100.64.0.3", "fd7a:115c:a1e0::3"),
			},
			policy: `{
				"groups": {
					"group:relays": ["alice@headscale.net", "ghost@headscale.net"]
				},
				"tagOwners": {
					"tag:client": ["tagowner@headscale.net"]
				},
				"grants": [
					{
						"src": ["tag:client"],
						"dst": ["group:relays"],
						"app": {"tailscale.com/cap/relay": []}
					}
				]
			}`,
			srcIDs:  []types.NodeID{1},
			relayID: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewPolicyManager(
				[]byte(tt.policy), users, tt.nodes.ViewSlice(),
			)
			require.NoError(t, err)

			peerMap := pm.BuildPeerMap(tt.nodes.ViewSlice())

			for _, srcID := range tt.srcIDs {
				require.True(t, slices.Contains(peerMap[srcID], tt.relayID),
					"node %d must see relay %d via cap/relay alone",
					srcID, tt.relayID)
				require.True(t, slices.Contains(peerMap[tt.relayID], srcID),
					"relay %d must see node %d via cap/relay alone",
					tt.relayID, srcID)
			}
		})
	}
}

func TestTagOwnedByTags(t *testing.T) {
	// tag:leaf is owned by tag:mid, which is owned by tag:root: a tag-to-tag
	// delegation chain, the shape an operator token uses to mint narrower keys.
	const policy = `{
		"tagOwners": {
			"tag:root": [],
			"tag:mid":  ["tag:root"],
			"tag:leaf": ["tag:mid"],
			"tag:lone": []
		},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`

	pm, err := NewPolicyManager([]byte(policy), nil, types.Nodes{}.ViewSlice())
	require.NoError(t, err)

	tests := []struct {
		name      string
		tag       string
		ownerTags []string
		want      bool
	}{
		{
			name:      "directly held tag needs no policy",
			tag:       "tag:lone",
			ownerTags: []string{"tag:lone"},
			want:      true,
		},
		{
			name:      "one-hop owned-by",
			tag:       "tag:mid",
			ownerTags: []string{"tag:root"},
			want:      true,
		},
		{
			name:      "two hops are not reached",
			tag:       "tag:leaf",
			ownerTags: []string{"tag:root"},
			want:      false,
		},
		{
			name:      "one of several held tags owns it",
			tag:       "tag:leaf",
			ownerTags: []string{"tag:lone", "tag:mid"},
			want:      true,
		},
		{
			name:      "owning one link does not grant a sibling",
			tag:       "tag:lone",
			ownerTags: []string{"tag:root"},
			want:      false,
		},
		{
			name:      "unowned tag denied",
			tag:       "tag:leaf",
			ownerTags: []string{"tag:unrelated"},
			want:      false,
		},
		{
			name:      "empty owners deny a delegated tag",
			tag:       "tag:leaf",
			ownerTags: nil,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, pm.TagOwnedByTags(tt.tag, tt.ownerTags))
		})
	}

	t.Run("nil policy manager denies", func(t *testing.T) {
		var nilPM *PolicyManager
		require.False(t, nilPM.TagOwnedByTags("tag:leaf", []string{"tag:root"}))
	})
}

// benchPolicies are the ACL shapes BenchmarkBuildPeerMap and
// BenchmarkSetNodes measure: a global ACL, autogroup:self, and a via
// grant. hscontrol/state/node_store_test.go checks the same three
// shapes for adjacency correctness; this is its own copy since test
// packages can't share one. Route dsts here are 10.0.0.0/8, wider than
// state's fixed 10.33.0.0/24: benchNodes below spreads its ~5% of
// routed nodes across 10.0.0.0/24 .. 10.255.0.0/24, so the dst must
// cover that whole range for the route-owning ACL/grant rule to be
// exercised rather than silently matching nothing.
var benchPolicies = []struct {
	name   string
	policy string
	// routerFiltered is whether the first routed node (node 1) gets a
	// filter rule, so the route-owning rule is known to be exercised.
	routerFiltered bool
}{
	{name: "global", policy: `{
		"groups": {"group:a": ["u1@"]},
		"tagOwners": {"tag:srv": ["u1@"]},
		"acls": [
			{"action": "accept", "src": ["group:a"], "dst": ["tag:srv:*"]},
			{"action": "accept", "src": ["u2@"], "dst": ["10.0.0.0/8:*"]}
		]}`, routerFiltered: true},
	{name: "self", policy: `{
		"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}]}`},
	{name: "via", policy: `{
		"tagOwners": {"tag:router": ["u1@"]},
		"grants": [{"src": ["u2@"], "dst": ["10.0.0.0/8"], "ip": ["*"], "via": ["tag:router"]}]}`, routerFiltered: true},
}

// benchSetNodesPolicies is the subset of benchPolicies BenchmarkSetNodes
// covers: via's per-node filter cost is close enough to global's that a
// third axis wouldn't add signal.
var benchSetNodesPolicies = benchPolicies[:2]

// benchNodes builds n nodes spread across 10 users for the peer-map
// benchmarks below: ~10% tagged tag:srv, ~5% also tagged tag:router and
// carrying an approved and announced 10.x.0.0/24 route, each with a
// unique IPv4.
func benchNodes(n int) ([]types.User, types.Nodes) {
	users := make([]types.User, 10)
	for i := range users {
		users[i] = types.User{ID: uint(i + 1), Name: fmt.Sprintf("u%d", i+1)}
	}

	nodes := make(types.Nodes, 0, n)
	for i := range n {
		u := users[i%len(users)]
		ip := netip.AddrFrom4([4]byte{100, 64, byte(i / 256), byte(i % 256)}) //nolint:gosec

		nd := &types.Node{
			ID:       types.NodeID(i + 1),
			Hostname: fmt.Sprintf("n%d", i+1),
			IPv4:     &ip,
		}

		if i%10 == 0 {
			nd.Tags = []string{"tag:srv"}
		} else {
			nd.UserID, nd.User = &u.ID, &u
		}

		if i%20 == 0 {
			// The via policy's routers.
			nd.Tags = []string{"tag:router", "tag:srv"}
			subnet := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte((i / 20) % 256), 0, 0}), 24) //nolint:gosec
			nd.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{subnet}}
			nd.ApprovedRoutes = []netip.Prefix{subnet}
		}

		nodes = append(nodes, nd)
	}

	return users, nodes
}

// BenchmarkBuildPeerMap measures PolicyManager.BuildPeerMap over
// realistic node counts and policy shapes, without any NodeStore or
// reuse-path involvement: the number this baseline compares later
// NodeStore write-path changes against.
func BenchmarkBuildPeerMap(b *testing.B) {
	for _, pol := range benchPolicies {
		for _, n := range []int{100, 300, 617, 1000} {
			b.Run(fmt.Sprintf("%s/n=%d", pol.name, n), func(b *testing.B) {
				users, nodes := benchNodes(n)
				pm, err := NewPolicyManager([]byte(pol.policy), users, nodes.ViewSlice())
				require.NoError(b, err)

				rules, err := pm.FilterForNode(nodes[0].View())
				require.NoError(b, err)
				require.Equal(b, pol.routerFiltered, len(rules) > 0,
					"router filter rules: %v", rules)

				b.ReportAllocs()

				for b.Loop() {
					pm.BuildPeerMap(nodes.ViewSlice())
				}
			})
		}
	}
}

// BenchmarkViaRoutesForPeer measures the mean per-peer cost of one map
// response: a user node against every peer in turn. "via-mixed" adds
// ordinary ACLs next to the via grant.
func BenchmarkViaRoutesForPeer(b *testing.B) {
	shapes := append(slices.Clone(benchPolicies), struct {
		name           string
		policy         string
		routerFiltered bool
	}{name: "via-mixed", policy: `{
		"groups": {"group:a": ["u1@"]},
		"tagOwners": {"tag:router": ["u1@"], "tag:srv": ["u1@"]},
		"acls": [
			{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:srv:*"]},
			{"action": "accept", "src": ["group:a"], "dst": ["10.0.0.0/8:22,443"]}
		],
		"grants": [{"src": ["u2@"], "dst": ["10.0.0.0/8"], "ip": ["*"], "via": ["tag:router"]}]}`})

	for _, pol := range shapes {
		for _, n := range []int{100, 300, 617, 1000} {
			b.Run(fmt.Sprintf("%s/n=%d", pol.name, n), func(b *testing.B) {
				users, nodes := benchNodes(n)
				pm, err := NewPolicyManager([]byte(pol.policy), users, nodes.ViewSlice())
				require.NoError(b, err)

				viewer := nodes[1].View()

				b.ReportAllocs()

				i := 0
				for b.Loop() {
					pm.ViaRoutesForPeer(viewer, nodes[i%n].View())
					i++
				}
			})
		}
	}
}

// BenchmarkSetNodes measures PolicyManager.SetNodes when one node's
// route changes on every call, the same per-write cost
// BenchmarkNodeStoreWrite drives through a NodeStore.
func BenchmarkSetNodes(b *testing.B) {
	for _, pol := range benchSetNodesPolicies {
		b.Run(fmt.Sprintf("%s/n=%d", pol.name, 617), func(b *testing.B) {
			users, nodes := benchNodes(617)
			pm, err := NewPolicyManager([]byte(pol.policy), users, nodes.ViewSlice())
			require.NoError(b, err)

			b.ReportAllocs()

			i := 0
			for b.Loop() {
				i++
				subnet := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(200 + i%50), 0, 0}), 24) //nolint:gosec
				// The policy manager holds views of the previous node; mutating
				// it in place would change both sides of SetNodes' comparison.
				nd := nodes[0].Clone()
				nd.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{subnet}}
				nd.ApprovedRoutes = []netip.Prefix{subnet}
				nodes[0] = nd

				changed, err := pm.SetNodes(nodes.ViewSlice())
				if err != nil {
					b.Fatal(err)
				}

				if !changed {
					b.Fatal("SetNodes must see the route change and recompile")
				}
			}
		})
	}
}

// BenchmarkSetNodesManyTags measures the recompile a join or delete costs
// when every node carries its own tag and grants reference them, a CI fleet
// shape where resolving tags dominated the compile.
func BenchmarkSetNodesManyTags(b *testing.B) {
	for _, n := range []int{1000, 4000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			nodes := scanManyRulesNodes(n)
			pm, err := NewPolicyManager([]byte(scanManyRulesPolicy(n, 400)), nil, nodes.ViewSlice())
			require.NoError(b, err)

			sets := []views.Slice[types.NodeView]{nodes[:n-1].ViewSlice(), nodes.ViewSlice()}

			b.ReportAllocs()

			i := 0
			for b.Loop() {
				i++

				_, err := pm.SetNodes(sets[i%2])
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestNodesGenerationCountsChangingSetNodes pins that NodesGeneration
// moves exactly when SetNodes reports a change, so a caller that did not
// run the SetNodes itself can still tell its write moved the policy.
func TestNodesGenerationCountsChangingSetNodes(t *testing.T) {
	users := types.Users{{ID: 1, Name: "user1"}}

	nodes := types.Nodes{node("n1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0])}
	nodes[0].ID = 1

	pm, err := NewPolicyManager([]byte(`{
		"acls": [{"action": "accept", "src": ["user1@"], "dst": ["user1@:*"]}]
	}`), users, nodes.ViewSlice())
	require.NoError(t, err)

	gen := pm.NodesGeneration()

	changed, err := pm.SetNodes(nodes.ViewSlice())
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, gen, pm.NodesGeneration(), "unchanged nodes must not advance the generation")

	added := node("n2", "100.64.0.2", "fd7a:115c:a1e0::2", users[0])
	added.ID = 2

	changed, err = pm.SetNodes(append(nodes, added).ViewSlice())
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, gen+1, pm.NodesGeneration(), "a changing SetNodes must advance the generation once")
}

// TestSetNodesRetriesAfterFailedRecompile pins that a SetNodes whose
// recompile fails keeps the previous node list, like SetUsers. Keeping the
// new list would make an identical retry look unchanged, so the recompile
// would never be retried and the caller would never learn the policy moved.
func TestSetNodesRetriesAfterFailedRecompile(t *testing.T) {
	users := types.Users{{ID: 1, Name: "user1"}}

	nodes := make(types.Nodes, 0, 2)
	nodes = append(nodes, node("n1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]))
	nodes[0].ID = 1

	pm, err := NewPolicyManager([]byte(`{
		"tagOwners": {"tag:a": ["user1@"]},
		"acls": [{"action": "accept", "src": ["user1@"], "dst": ["user1@:*"]}]
	}`), users, nodes.ViewSlice())
	require.NoError(t, err)

	added := node("n2", "100.64.0.2", "fd7a:115c:a1e0::2", users[0])
	added.ID = 2
	grown := append(nodes, added)

	// Break tag owner resolution so the recompile fails.
	good := pm.pol.TagOwners
	missing := Tag("tag:missing")
	pm.pol.TagOwners = TagOwners{"tag:a": Owners{&missing}}

	_, err = pm.SetNodes(grown.ViewSlice())
	require.Error(t, err)

	pm.pol.TagOwners = good
	gen := pm.NodesGeneration()

	changed, err := pm.SetNodes(grown.ViewSlice())
	require.NoError(t, err)
	require.True(t, changed, "the retry must recompile, not see the failed input as current")
	require.Equal(t, gen+1, pm.NodesGeneration())
}

// TestSetNodesCachedResultsMatchFresh drives random node writes through
// one PolicyManager, reading every node between writes so its caches
// fill, and checks each read against a PolicyManager built fresh from the
// same nodes. A cache entry that a write should have dropped shows up as
// a difference.
func TestSetNodesCachedResultsMatchFresh(t *testing.T) {
	users := types.Users{{ID: 1, Name: "u1"}, {ID: 2, Name: "u2"}, {ID: 3, Name: "u3"}}

	policies := []struct {
		name   string
		policy string
	}{
		{name: "global", policy: `{
			"groups": {"group:a": ["u1@", "u2@"]},
			"tagOwners": {"tag:srv": ["u1@"], "tag:router": ["u1@"], "tag:other": ["u1@"]},
			"acls": [
				{"action": "accept", "src": ["group:a"], "dst": ["tag:srv:*"]},
				{"action": "accept", "src": ["u3@"], "dst": ["10.33.0.0/16:*", "u1@:22"]}
			],
			"ssh": [{"action": "accept", "src": ["group:a"], "dst": ["tag:srv"], "users": ["root"]}]}`},
		{name: "autogroup-self", policy: `{
			"groups": {"group:a": ["u1@"]},
			"tagOwners": {"tag:srv": ["u1@"], "tag:router": ["u1@"], "tag:other": ["u1@"]},
			"acls": [
				{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]},
				{"action": "accept", "src": ["group:a"], "dst": ["tag:srv:*"]}
			],
			"ssh": [
				{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["autogroup:nonroot"]},
				{"action": "accept", "src": ["group:a"], "dst": ["tag:srv"], "users": ["root"]}
			]}`},
		{name: "via", policy: `{
			"tagOwners": {"tag:srv": ["u1@"], "tag:router": ["u1@"], "tag:other": ["u1@"]},
			"grants": [
				{"src": ["u2@"], "dst": ["10.33.0.0/16"], "ip": ["*"], "via": ["tag:router"]},
				{"src": ["u3@", "tag:srv"], "dst": ["autogroup:internet"], "ip": ["*"], "via": ["tag:router"]},
				{"src": ["u1@"], "dst": ["tag:srv"], "ip": ["*"]}
			]}`},
		{name: "autogroup-self-and-via", policy: `{
			"groups": {"group:a": ["u1@", "u2@"]},
			"tagOwners": {"tag:srv": ["u1@"], "tag:router": ["u1@"], "tag:other": ["u1@"]},
			"grants": [
				{"src": ["group:a"], "dst": ["autogroup:self"], "ip": ["*"]},
				{"src": ["u2@", "tag:srv"], "dst": ["10.33.0.0/16"], "ip": ["*"], "via": ["tag:router"]},
				{"src": ["u3@"], "dst": ["tag:srv"], "ip": ["*"]}
			]}`},
	}

	subnets := []netip.Prefix{
		netip.MustParsePrefix("10.33.0.0/24"),
		netip.MustParsePrefix("10.33.1.0/24"),
	}
	exits := []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6()}

	for _, pc := range policies {
		t.Run(pc.name, func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				nodes := make(types.Nodes, 0, 8)
				nextIP := 1

				newNode := func(id types.NodeID, u types.User) *types.Node {
					n := node(fmt.Sprintf("n%d", id), fmt.Sprintf("100.64.0.%d", nextIP), fmt.Sprintf("fd7a:115c:a1e0::%d", nextIP), u)
					n.ID = id
					nextIP++

					return n
				}

				for i := range 6 {
					nodes = append(nodes, newNode(types.NodeID(i+1), users[i%len(users)])) //nolint:gosec // safe conversion in test
				}

				nextID := types.NodeID(len(nodes) + 1) //nolint:gosec // safe conversion in test

				pm, err := NewPolicyManager([]byte(pc.policy), users, nodes.ViewSlice())
				if err != nil {
					rt.Fatalf("new policy manager: %v", err)
				}

				check := func() {
					fresh, err := NewPolicyManager([]byte(pc.policy), users, nodes.ViewSlice())
					if err != nil {
						rt.Fatalf("fresh policy manager: %v", err)
					}

					for _, n := range nodes {
						nv := n.View()

						got, _ := pm.FilterForNode(nv)

						want, _ := fresh.FilterForNode(nv)
						if diff := cmp.Diff(want, got); diff != "" {
							rt.Fatalf("node %d FilterForNode (-fresh +cached):\n%s", n.ID, diff)
						}

						gotM, _ := pm.MatchersForNode(nv)

						wantM, _ := fresh.MatchersForNode(nv)
						if diff := cmp.Diff(matcherStrings(wantM), matcherStrings(gotM)); diff != "" {
							rt.Fatalf("node %d MatchersForNode (-fresh +cached):\n%s", n.ID, diff)
						}

						gotS, err := pm.SSHPolicy("", nv)
						if err != nil {
							rt.Fatalf("node %d SSHPolicy: %v", n.ID, err)
						}

						wantS, _ := fresh.SSHPolicy("", nv)
						if diff := cmp.Diff(wantS, gotS); diff != "" {
							rt.Fatalf("node %d SSHPolicy (-fresh +cached):\n%s", n.ID, diff)
						}
					}
				}

				check()

				steps := rapid.IntRange(1, 25).Draw(rt, "steps")
				for range steps {
					// Several writes per SetNodes, as a NodeStore batch applies them.
					writes := rapid.IntRange(1, 3).Draw(rt, "writes")
					for range writes {
						i := rapid.IntRange(0, len(nodes)-1).Draw(rt, "node")
						// Mutate a copy: pm still holds views of the old node.
						n := nodes[i].View().AsStruct()

						switch rapid.IntRange(0, 9).Draw(rt, "op") {
						case 0: // tag
							n.Tags = []string{rapid.SampledFrom([]string{"tag:srv", "tag:router", "tag:other"}).Draw(rt, "tag")}
							n.UserID, n.User = nil, nil
						case 1: // (re)assign user, untagging
							u := rapid.SampledFrom(users).Draw(rt, "user")
							n.Tags = nil
							n.UserID, n.User = new(u.ID), new(u)
						case 2: // new IPs
							ip4 := netip.MustParseAddr(fmt.Sprintf("100.64.1.%d", nextIP))
							ip6 := netip.MustParseAddr(fmt.Sprintf("fd7a:115c:a1e0::1:%d", nextIP))
							n.IPv4, n.IPv6 = &ip4, &ip6
							nextIP++
						case 3: // announce and approve a subnet
							p := rapid.SampledFrom(subnets).Draw(rt, "subnet")
							n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{p}}
							n.ApprovedRoutes = []netip.Prefix{p}
						case 4: // drop approvals
							n.ApprovedRoutes = nil
						case 5: // exit node
							n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: exits}
							n.ApprovedRoutes = exits
						case 6: // add a node
							nodes = append(nodes, newNode(nextID, rapid.SampledFrom(users).Draw(rt, "user")))
							nextID++

							n = nil
						case 7: // remove the node
							if len(nodes) > 1 {
								nodes = slices.Delete(slices.Clone(nodes), i, i+1)
							}

							n = nil
						case 8: // owner association not loaded
							if !n.IsTagged() {
								n.User = nil
							}
						case 9: // payload only
							n.Hostname += "x"
						}

						if n != nil {
							nodes = slices.Clone(nodes)
							nodes[i] = n
						}
					}

					_, err := pm.SetNodes(nodes.ViewSlice())
					if err != nil {
						rt.Fatalf("SetNodes: %v", err)
					}

					check()
				}
			})
		})
	}
}

// TestFailedSetUsersKeepsCompiledPolicy renames alice to charlie and adds
// a second bob, so the recompile resolves charlie's grant and then fails on
// the ambiguous nodeAttrs target. A failed Set* must leave every compiled result as it was:
// a partial compile would hand alice's nodes charlie's port 22, and the
// reverse rename, which SetUsers sees as no change, would not clear it.
func TestFailedSetUsersKeepsCompiledPolicy(t *testing.T) {
	users := types.Users{{ID: 1, Name: "alice"}, {ID: 2, Name: "bob"}}
	nodes := types.Nodes{
		node("a1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
		node("a2", "100.64.0.2", "fd7a:115c:a1e0::2", users[0]),
		node("b1", "100.64.0.3", "fd7a:115c:a1e0::3", users[1]),
	}

	for i, n := range nodes {
		n.ID = types.NodeID(i + 1) //nolint:gosec
	}

	pol := []byte(`{
		"acls": [
			{"action": "accept", "src": ["charlie@"], "dst": ["autogroup:self:22"]},
			{"action": "accept", "src": ["bob@"], "dst": ["bob@:*"]}
		],
		"ssh": [{"action": "accept", "src": ["charlie@"], "dst": ["autogroup:self"], "users": ["root"]}],
		"nodeAttrs": [{"target": ["bob@"], "attr": ["randomize-client-port"]}]
	}`)

	pm, err := NewPolicyManager(pol, users, nodes.ViewSlice())
	require.NoError(t, err)

	type view struct {
		filter []tailcfg.FilterRule
		ssh    *tailcfg.SSHPolicy
	}

	read := func(pm *PolicyManager, n *types.Node) view {
		t.Helper()

		f, err := pm.FilterForNode(n.View())
		require.NoError(t, err)

		ssh, err := pm.SSHPolicy("", n.View())
		require.NoError(t, err)

		return view{filter: f, ssh: ssh}
	}

	before := read(pm, nodes[0])

	renamed := slices.Clone(users)
	renamed[0].Name = "charlie"
	renamed = append(renamed, types.User{ID: 3, Name: "bob"})

	_, _, err = pm.SetUsers(renamed)
	require.Error(t, err)
	require.Equal(t, before, read(pm, nodes[0]), "a failed SetUsers must not change compiled results")

	_, _, err = pm.SetUsers(users)
	require.NoError(t, err)
	require.Equal(t, before, read(pm, nodes[0]), "reversing the rename must serve the original results")

	b2 := node("b2", "100.64.0.4", "fd7a:115c:a1e0::4", users[1])
	b2.ID = 4
	grown := append(slices.Clone(nodes), b2)

	_, err = pm.SetNodes(grown.ViewSlice())
	require.NoError(t, err)

	fresh, err := NewPolicyManager(pol, users, grown.ViewSlice())
	require.NoError(t, err)

	for _, n := range grown {
		require.Equal(t, read(fresh, n), read(pm, n),
			"node %s after a later write must match a fresh compile", n.Hostname)
	}
}

// TestFailedSetNodesKeepsCompiledPolicy fails a SetNodes that retags a
// node, then retries it once the failure is gone. The failed write must
// leave the compiled filter as it was, and the retry must compile the new
// owners.
func TestFailedSetNodesKeepsCompiledPolicy(t *testing.T) {
	users := types.Users{{ID: 1, Name: "alice"}, {ID: 2, Name: "bob"}}
	nodes := types.Nodes{
		node("a1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
		node("a2", "100.64.0.2", "fd7a:115c:a1e0::2", users[0]),
		node("b1", "100.64.0.3", "fd7a:115c:a1e0::3", users[1]),
	}

	for i, n := range nodes {
		n.ID = types.NodeID(i + 1) //nolint:gosec
	}

	pol := []byte(`{
		"tagOwners": {"tag:srv": ["alice@"]},
		"acls": [{"action": "accept", "src": ["alice@"], "dst": ["alice@:*"]}],
		"ssh": [{"action": "accept", "src": ["alice@"], "dst": ["alice@"], "users": ["root"]}]
	}`)

	pm, err := NewPolicyManager(pol, users, nodes.ViewSlice())
	require.NoError(t, err)

	read := func(pm *PolicyManager, n *types.Node) ([]tailcfg.FilterRule, *tailcfg.SSHPolicy) {
		t.Helper()

		f, err := pm.FilterForNode(n.View())
		require.NoError(t, err)

		ssh, err := pm.SSHPolicy("", n.View())
		require.NoError(t, err)

		return f, ssh
	}

	beforeFilter, beforeSSH := read(pm, nodes[0])
	beforeGlobal, _ := pm.Filter()

	retagged := slices.Clone(nodes)
	tagged := nodes[1].Clone()
	tagged.Tags = []string{"tag:srv"}
	tagged.UserID, tagged.User = nil, nil
	retagged[1] = tagged

	good := pm.pol.TagOwners
	missing := Tag("tag:missing")
	pm.pol.TagOwners = TagOwners{"tag:srv": Owners{&missing}}

	_, err = pm.SetNodes(retagged.ViewSlice())
	require.Error(t, err)

	pm.pol.TagOwners = good

	gotFilter, gotSSH := read(pm, nodes[0])
	require.Equal(t, beforeFilter, gotFilter, "a failed SetNodes must not change compiled results")
	require.Equal(t, beforeSSH, gotSSH, "a failed SetNodes must not change compiled results")

	gotGlobal, _ := pm.Filter()
	require.Equal(t, beforeGlobal, gotGlobal, "a failed SetNodes must not change compiled results")

	_, err = pm.SetNodes(retagged.ViewSlice())
	require.NoError(t, err)

	fresh, err := NewPolicyManager(pol, users, retagged.ViewSlice())
	require.NoError(t, err)

	for _, n := range retagged {
		wantFilter, wantSSH := read(fresh, n)
		gotFilter, gotSSH := read(pm, n)
		require.Equal(t, wantFilter, gotFilter, "node %s filter after the retry", n.Hostname)
		require.Equal(t, wantSSH, gotSSH, "node %s SSH after the retry", n.Hostname)
	}
}

// nodeCapMapsReference is the complete bulk accessor from d00f135bf.
func (pm *PolicyManager) nodeCapMapsReference() map[types.NodeID]tailcfg.NodeCapMap {
	if pm == nil {
		return nil
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	out := make(map[types.NodeID]tailcfg.NodeCapMap, len(pm.nodeAttrsMap))
	maps.Copy(out, pm.nodeAttrsMap)

	return out
}

func TestNodeCapMapsForPeersReference(t *testing.T) {
	var nilManager *PolicyManager
	require.Nil(t, nilManager.NodeCapMaps())
	require.Nil(t, nilManager.nodeCapMapsReference())
	require.Nil(t, nilManager.NodeCapMapsForPeers(views.SliceOf([]types.NodeView{(&types.Node{ID: 1}).View()})))

	for _, attrs := range []struct {
		name string
		caps map[types.NodeID]tailcfg.NodeCapMap
	}{
		{"nil", nil},
		{"empty", map[types.NodeID]tailcfg.NodeCapMap{}},
		{"single", map[types.NodeID]tailcfg.NodeCapMap{3: {"disable-ipv4": nil}}},
		{"partial", map[types.NodeID]tailcfg.NodeCapMap{
			1: nil,
			2: {},
			3: {"disable-ipv4": nil, "value": {`{"a":1}`}},
			5: {"randomize-client-port": {}},
		}},
	} {
		t.Run(attrs.name, func(t *testing.T) {
			pm := &PolicyManager{nodeAttrsMap: attrs.caps}
			all := pm.nodeCapMapsReference()
			require.NotNil(t, all)
			require.Equal(t, all, pm.NodeCapMaps())

			for _, selection := range []struct {
				name string
				ids  []types.NodeID
			}{
				{"nil", nil},
				{"empty", []types.NodeID{}},
				{"missing", []types.NodeID{99}},
				{"one", []types.NodeID{3}},
				{"below threshold", []types.NodeID{5, 3, 3}},
				{"threshold missing", []types.NodeID{99, 99, 99, 99}},
				{"duplicates", []types.NodeID{3, 5, 3, 99, 1, 2}},
				{"full", []types.NodeID{5, 4, 3, 2, 1}},
			} {
				t.Run(selection.name, func(t *testing.T) {
					var peers []types.NodeView
					for _, id := range selection.ids {
						peers = append(peers, (&types.Node{ID: id}).View())
					}

					if selection.ids != nil && len(peers) == 0 {
						peers = []types.NodeView{}
					}

					before := slices.Clone(peers)

					var want map[types.NodeID]tailcfg.NodeCapMap
					if len(peers) > 0 && len(all) > 0 {
						want = make(map[types.NodeID]tailcfg.NodeCapMap)

						if len(peers) >= len(all) {
							maps.Copy(want, all)
						} else {
							for _, peer := range peers {
								if caps, ok := all[peer.ID()]; ok {
									want[peer.ID()] = caps
								}
							}
						}
					}

					got := pm.NodeCapMapsForPeers(views.SliceOf(peers))
					require.Equal(t, want, got)
					require.Equal(t, before, peers)

					for _, peer := range peers {
						require.Equal(t, all[peer.ID()], got[peer.ID()], "requested lookups must match the bulk snapshot")
					}

					if got != nil {
						clear(got)
						got[99] = tailcfg.NodeCapMap{"caller-only": nil}
					}

					require.Equal(t, all, pm.NodeCapMaps(), "outer mutations must not reach the manager")
				})
			}

			wantAll := pm.nodeCapMapsReference()

			clear(all)
			require.Equal(t, wantAll, pm.NodeCapMaps(), "bulk container remains independently owned")
		})
	}
}

func TestNodeCapMapsForPeersSnapshots(t *testing.T) {
	user := types.User{ID: 1, Name: "capuser"}
	nodes := types.Nodes{
		node("one", "100.64.0.1", "fd7a:115c:a1e0::1", user),
		node("two", "100.64.0.2", "fd7a:115c:a1e0::2", user),
	}
	nodes[0].ID, nodes[1].ID = 1, 2
	pm, err := NewPolicyManager([]byte(`{"nodeAttrs":[{"target":["*"],"attr":["disable-ipv4"]}]}`), []types.User{user}, nodes.ViewSlice())
	require.NoError(t, err)

	old := pm.NodeCapMapsForPeers(nodes.ViewSlice())
	all := pm.nodeCapMapsReference()

	require.Len(t, old, 2)
	require.Equal(t, all, old)
	// Probe the documented shared-inner contract, then restore before any policy update.
	old[1]["alias-probe"] = []tailcfg.RawMessage{`{"shared":true}`}

	require.Contains(t, pm.nodeAttrsMap[1], nodecap.Cap("alias-probe"))
	require.Same(t, &old[1]["alias-probe"][0], &all[1]["alias-probe"][0])
	delete(old[1], "alias-probe")

	owned := pm.NodeCapMap(1)
	delete(owned, "disable-ipv4")
	require.Contains(t, old[1], nodecap.Cap("disable-ipv4"), "single-node accessor still clones its inner map")

	_, err = pm.SetPolicy([]byte(`{"nodeAttrs":[{"target":["100.64.0.2"],"attr":["randomize-client-port"]}]}`))
	require.NoError(t, err)

	current := pm.NodeCapMapsForPeers(nodes.ViewSlice())
	require.Equal(t, pm.nodeCapMapsReference(), current)
	require.NotContains(t, current, types.NodeID(1))
	require.Contains(t, current[2], nodecap.Cap("randomize-client-port"))

	for _, caps := range old {
		require.Equal(t, tailcfg.NodeCapMap{"disable-ipv4": nil}, caps, "old snapshot survives policy replacement")
	}

	_, err = pm.SetPolicy([]byte(`{}`))
	require.NoError(t, err)
	require.Nil(t, pm.NodeCapMapsForPeers(nodes.ViewSlice()))
	require.Contains(t, current[2], nodecap.Cap("randomize-client-port"))
	require.NotNil(t, pm.NodeCapMaps(), "bulk empty result must remain non-nil")
}

func TestNodeCapMapsForPeersGlobalRandomizeClientPort(t *testing.T) {
	users, nodes := benchNodes(2)
	pm, err := NewPolicyManager([]byte(`{"randomizeClientPort":true}`), users, nodes.ViewSlice())
	require.NoError(t, err)

	all := pm.nodeCapMapsReference()
	require.Len(t, all, 2)

	peers := nodes.ViewSlice().Slice(0, 1)
	got := pm.NodeCapMapsForPeers(peers)
	require.Equal(t, map[types.NodeID]tailcfg.NodeCapMap{
		nodes[0].ID: {"randomize-client-port": nil},
	}, got)
	require.Equal(t, all, pm.NodeCapMapsForPeers(nodes.ViewSlice()))
	require.Nil(t, pm.NodeCapMapsForPeers(views.SliceOf([]types.NodeView(nil))))
}

func TestNodeCapMapsForPeersConcurrentPolicy(t *testing.T) {
	for _, k := range []int{3, 8} {
		t.Run(fmt.Sprintf("K%d", k), func(t *testing.T) {
			users, nodes := benchNodes(8)
			policies := []string{
				`{"nodeAttrs":[{"target":["*"],"attr":["disable-ipv4"]}]}`,
				`{"nodeAttrs":[{"target":["*"],"attr":["randomize-client-port"]}]}`,
			}
			pm, err := NewPolicyManager([]byte(policies[0]), users, nodes.ViewSlice())
			require.NoError(t, err)

			peers := nodes.ViewSlice().Slice(0, k)
			generations := []tailcfg.NodeCapMap{
				{"disable-ipv4": nil},
				{"randomize-client-port": nil},
			}
			checkSnapshot := func(generation int) {
				t.Helper()

				snapshot := pm.NodeCapMapsForPeers(peers)
				if len(snapshot) != peers.Len() {
					t.Errorf("snapshot has %d entries, want %d", len(snapshot), peers.Len())
				}

				first := snapshot[nodes[0].ID]
				if !maps.EqualFunc(generations[0], first, slices.Equal) &&
					!maps.EqualFunc(generations[1], first, slices.Equal) {
					t.Errorf("snapshot has unexpected capabilities: %v", first)
				}

				for _, caps := range snapshot {
					if !maps.EqualFunc(first, caps, slices.Equal) {
						t.Error("snapshot mixed policy generations")
					}

					if generation >= 0 && !maps.EqualFunc(generations[generation], caps, slices.Equal) {
						t.Errorf("snapshot did not observe published generation %d: %v", generation, caps)
					}
				}
			}
			checkSnapshot(0)

			published := make(chan int)
			acknowledged := make(chan struct{})
			writerErrors := make(chan error, 1)

			go func() {
				defer close(published)

				var err error
				defer func() { writerErrors <- err }()

				for i := range 100 {
					generation := (i + 1) % 2

					_, err = pm.SetPolicy([]byte(policies[generation]))
					if err != nil {
						return
					}

					published <- generation

					<-acknowledged
				}
			}()

			var observed [2]int

			for active := true; active; {
				checkSnapshot(-1)

				select {
				case generation, ok := <-published:
					if !ok {
						active = false
						continue
					}

					checkSnapshot(generation)
					observed[generation]++

					acknowledged <- struct{}{}
				default:
				}
			}

			require.NoError(t, <-writerErrors)
			checkSnapshot(0)
			require.Equal(t, [2]int{50, 50}, observed)
		})
	}
}

var nodeCapMapsBenchmarkSink map[types.NodeID]tailcfg.NodeCapMap

// Each call constructs a fresh outer snapshot; there is no retained selector index.
// Direct method calls keep interface adapters out of this isolated measurement.
func BenchmarkNodeCapMapsSelection(b *testing.B) {
	previousLevel := zerolog.GlobalLevel()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	b.Cleanup(func() { zerolog.SetGlobalLevel(previousLevel) })

	for _, n := range []int{100, 1000, 10000} {
		_, nodes := benchNodes(n)
		allPeers := nodes.ViewSlice()

		for _, stride := range []int{0, 10, 1, n} {
			b.Run(fmt.Sprintf("N%d/attrStride%d", n, stride), func(b *testing.B) {
				pm := &PolicyManager{nodeAttrsMap: make(map[types.NodeID]tailcfg.NodeCapMap)}

				if stride > 0 {
					for i := 0; i < n; i += stride {
						pm.nodeAttrsMap[nodes[i].ID] = tailcfg.NodeCapMap{"disable-ipv4": {}}
					}
				}

				for _, k := range []int{0, 1, 8, n} {
					peers := allPeers.Slice(0, k)
					b.Run(fmt.Sprintf("K%d/reference", k), func(b *testing.B) {
						b.ReportAllocs()

						for b.Loop() {
							nodeCapMapsBenchmarkSink = pm.nodeCapMapsReference()
						}
					})
					b.Run(fmt.Sprintf("K%d/selected", k), func(b *testing.B) {
						b.ReportAllocs()

						for b.Loop() {
							nodeCapMapsBenchmarkSink = pm.NodeCapMapsForPeers(peers)
						}
					})
				}
			})
		}
	}
}

func BenchmarkNodeCapMapsConstruction(b *testing.B) {
	previousLevel := zerolog.GlobalLevel()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	b.Cleanup(func() { zerolog.SetGlobalLevel(previousLevel) })

	for _, n := range []int{100, 1000, 10000} {
		users, nodes := benchNodes(n)
		peers := nodes.ViewSlice().Slice(0, 1)

		for _, attrs := range []string{`[]`, `[{"target":["*"],"attr":["disable-ipv4"]}]`} {
			pol := []byte(`{"acls":[],"nodeAttrs":` + attrs + `}`)
			for _, selected := range []bool{false, true} {
				b.Run(fmt.Sprintf("N%d/attrs%t/selected%t", n, attrs != `[]`, selected), func(b *testing.B) {
					b.ReportAllocs()

					for b.Loop() {
						pm, err := NewPolicyManager(pol, users, nodes.ViewSlice())
						if err != nil {
							b.Fatal(err)
						}

						if selected {
							nodeCapMapsBenchmarkSink = pm.NodeCapMapsForPeers(peers)
						} else {
							nodeCapMapsBenchmarkSink = pm.nodeCapMapsReference()
						}
					}
				})
			}
		}
	}
}

// BenchmarkCompileWideACL compiles a CI-shaped policy: one rule per CI tag
// to its own service, and one wide rule from every CI tag to the shared
// services, which compiles to one grant per destination. new compiles from
// scratch; set-nodes recompiles after a batch of tagged joins.
func BenchmarkCompileWideACL(b *testing.B) {
	const (
		ciTags = 300
		common = 100
		ci     = 5000
		joins  = 50
	)

	r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // reproducible benchmark input

	owners := map[string][]string{}
	tag := func(kind string, i int) string {
		t := fmt.Sprintf("tag:%s%d", kind, i)
		owners[t] = []string{}

		return t
	}

	acls := make([]map[string]any, 0, ciTags+1)
	wide := make([]string, 0, ciTags)
	dsts := make([]string, 0, common)

	for i := range ciTags {
		acls = append(acls, map[string]any{"action": "accept", "src": []string{tag("ci-app", i)}, "dst": []string{tag("svc-app", i) + ":80"}})
		wide = append(wide, tag("ci-app", i))
	}

	for i := range common {
		dsts = append(dsts, tag("svc-common", i)+":80")
	}

	acls = append(acls, map[string]any{"action": "accept", "src": wide, "dst": dsts})
	pol := must(json.Marshal(map[string]any{"tagOwners": owners, "acls": acls}))

	node := func(i int, t string) *types.Node {
		v4 := netip.AddrFrom4([4]byte{100, 64 + byte(i>>16), byte(i >> 8), byte(i)})                                           //nolint:gosec
		v6 := netip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 13: byte(i >> 16), 14: byte(i >> 8), 15: byte(i)}) //nolint:gosec

		return &types.Node{ID: types.NodeID(i + 1), Hostname: fmt.Sprintf("n%d", i), IPv4: &v4, IPv6: &v6, Tags: []string{t}} //nolint:gosec
	}

	before := make(types.Nodes, 0, ciTags+common+ci)
	for i := range ciTags {
		before = append(before, node(len(before), fmt.Sprintf("tag:svc-app%d", i)))
	}

	for i := range common {
		before = append(before, node(len(before), fmt.Sprintf("tag:svc-common%d", i)))
	}

	for range ci {
		before = append(before, node(len(before), fmt.Sprintf("tag:ci-app%d", r.IntN(ciTags))))
	}

	after := slices.Clone(before)
	for range joins {
		after = append(after, node(len(after), fmt.Sprintf("tag:ci-app%d", r.IntN(ciTags))))
	}

	b.Run("new", func(b *testing.B) {
		for b.Loop() {
			_, err := NewPolicyManager(pol, nil, after.ViewSlice())
			require.NoError(b, err)
		}
	})

	b.Run("set-nodes", func(b *testing.B) {
		pm, err := NewPolicyManager(pol, nil, before.ViewSlice())
		require.NoError(b, err)

		sets := []types.Nodes{after, before}

		i := 0
		for b.Loop() {
			changed, err := pm.SetNodes(sets[i%2].ViewSlice())
			require.NoError(b, err)
			require.True(b, changed)

			i++
		}
	})
}

// TestWithResolvedGroups checks that the copy answers for a group exactly
// as resolving it member by member does, without looking at users and
// nodes again, and that the policy it was made from is left untouched.
func TestWithResolvedGroups(t *testing.T) {
	users := types.Users{
		{ID: 1, Name: "alice"},
		{ID: 2, Name: "bob"},
		{ID: 3, Name: "twin"},
		{ID: 4, Name: "twin"},
	}
	nodes := types.Nodes{
		node("alice1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
		node("bob1", "100.64.0.2", "fd7a:115c:a1e0::2", users[1]),
	}.ViewSlice()

	pol := &Policy{
		Groups: Groups{
			"group:dev":       Usernames{"alice@", "bob@", "missing@"},
			"group:ambiguous": Usernames{"alice@", "twin@"},
			"group:empty":     Usernames{},
		},
	}

	resolved := pol.withResolvedGroups(users, nodes)
	require.Nil(t, pol.resolvedGroups,
		"the parsed policy is hashed and must stay as is")
	require.Len(t, resolved.resolvedGroups, len(pol.Groups))

	for g := range pol.Groups {
		want, wantErr := g.resolve(pol, users, nodes)
		got, gotErr := g.resolve(resolved, nil, views.Slice[types.NodeView]{})

		require.Equal(t, want.Prefixes(), got.Prefixes(), g)

		if wantErr != nil {
			require.EqualError(t, gotErr, wantErr.Error(), g)
		} else {
			require.NoError(t, gotErr, g)
		}
	}

	require.ErrorIs(t,
		resolved.resolvedGroups["group:ambiguous"].err, ErrMultipleUsersFound)

	unknown := Group("group:unknown")
	got, err := unknown.resolve(resolved, users, nodes)
	require.NoError(t, err)
	require.Empty(t, got.Prefixes())

	require.Nil(t, (*Policy)(nil).withResolvedGroups(users, nodes))
}

// TestResolvedGroupsFollowUsersAndNodes checks that readers resolving
// aliases on demand through the groups resolved by updateLocked see the
// users and nodes of the latest SetUsers, SetNodes and SetPolicy.
func TestResolvedGroupsFollowUsersAndNodes(t *testing.T) {
	alice := types.User{ID: 1, Name: "alice"}
	bob := types.User{ID: 2, Name: "bob"}

	srv := node("srv", "100.64.0.10", "fd7a:115c:a1e0::10", alice)
	srv.ID = 10
	srv.Tags = []string{"tag:srv"}
	alice1 := node("alice1", "100.64.0.1", "fd7a:115c:a1e0::1", alice)
	alice1.ID = 1
	bob1 := node("bob1", "100.64.0.3", "fd7a:115c:a1e0::3", bob)
	bob1.ID = 2

	pol := func(members string) []byte {
		return []byte(`{
			"groups": {"group:dev": [` + members + `]},
			"tagOwners": {"tag:srv": ["group:dev"]},
			"acls": [{"action": "accept", "src": ["group:dev"], "dst": ["tag:srv:22"]}],
			"ssh": [{"action": "accept", "src": ["group:dev"], "dst": ["tag:srv"], "users": ["root"]}]
		}`)
	}

	pm, err := NewPolicyManager(
		pol(`"alice@", "bob@"`),
		types.Users{alice},
		types.Nodes{srv, alice1}.ViewSlice(),
	)
	require.NoError(t, err)

	sshSources := func() []string {
		t.Helper()

		sshPol, err := pm.SSHPolicy("", srv.View())
		require.NoError(t, err)

		var ips []string

		for _, rule := range sshPol.Rules {
			for _, principal := range rule.Principals {
				ips = append(ips, principal.NodeIP)
			}
		}

		slices.Sort(ips)

		return ips
	}

	filterSources := func() []string {
		t.Helper()

		filter, _ := pm.Filter()
		require.Len(t, filter, 1)

		ips := slices.Clone(filter[0].SrcIPs)
		slices.Sort(ips)

		return ips
	}

	aliceIPs := []string{"100.64.0.1", "fd7a:115c:a1e0::1"}
	bothIPs := []string{
		"100.64.0.1", "100.64.0.3", "fd7a:115c:a1e0::1", "fd7a:115c:a1e0::3",
	}

	require.Equal(t, aliceIPs, filterSources())
	require.Equal(t, aliceIPs, sshSources())

	_, _, err = pm.SetUsers(types.Users{alice, bob})
	require.NoError(t, err)

	_, err = pm.SetNodes(types.Nodes{srv, alice1, bob1}.ViewSlice())
	require.NoError(t, err)
	require.Equal(t, bothIPs, filterSources())
	require.Equal(t, bothIPs, sshSources())

	_, err = pm.SetPolicy(pol(`"alice@"`))
	require.NoError(t, err)
	require.Equal(t, aliceIPs, filterSources())
	require.Equal(t, aliceIPs, sshSources())
}

// TestResolvedPolicyKeepsTagIndex checks that the copy readers resolve
// through carries both the tag index and the resolved groups.
func TestResolvedPolicyKeepsTagIndex(t *testing.T) {
	users := types.Users{{ID: 1, Name: "alice"}}
	nodes := types.Nodes{node("a", "100.64.0.1", "fd7a:115c:a1e0::1", users[0])}

	pm, err := NewPolicyManager([]byte(`{
		"groups": {"group:a": ["alice@"]},
		"tagOwners": {"tag:x": ["alice@"]},
		"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:*"]}]
	}`), users, nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, pm.resolvedPol.nodesByTag)
	require.NotNil(t, pm.resolvedPol.resolvedGroups)
}

func TestSetNodesUnapprovedRoutesKeepGeneration(t *testing.T) {
	users := types.Users{{ID: 1, Name: "user1"}}
	route := netip.MustParsePrefix("10.77.0.0/24")

	for _, tt := range []struct {
		name   string
		policy string
	}{
		{name: "global", policy: `{"acls": [{"action": "accept",
			"src": ["user1@"], "dst": ["10.77.0.0/24:*"]}]}`},
		{name: "self", policy: `{"acls": [{"action": "accept",
			"src": ["user1@"], "dst": ["autogroup:self:*"]}]}`},
		{name: "via", policy: `{
			"tagOwners": {"tag:router": ["user1@"]},
			"grants": [{"src": ["user1@"], "dst": ["10.77.0.0/24"],
				"ip": ["*"], "via": ["tag:router"]}]
		}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			router := node("router", "100.64.0.1", "fd7a:115c:a1e0::1", users[0])
			router.ID = 1
			client := node("client", "100.64.0.2", "fd7a:115c:a1e0::2", users[0])
			client.ID = 2

			if tt.name == "via" {
				router.Tags = []string{"tag:router"}
			}

			pm, err := NewPolicyManager(
				[]byte(tt.policy),
				users,
				types.Nodes{router, client}.ViewSlice(),
			)
			require.NoError(t, err)
			require.Equal(t, tt.name != "global", pm.needsPerNodeFilter)
			gen := pm.NodesGeneration()

			announced := router.Clone()
			announced.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
			changed, err := pm.SetNodes(types.Nodes{announced, client}.ViewSlice())
			require.NoError(t, err)
			require.False(t, changed, "unapproved routes are not policy inputs")
			require.Equal(t, gen, pm.NodesGeneration())
			require.Equal(
				t,
				[]netip.Prefix{route},
				pm.nodesByID[router.ID].AnnouncedRoutes(),
			)

			approved := announced.Clone()
			approved.ApprovedRoutes = []netip.Prefix{route}
			changed, err = pm.SetNodes(types.Nodes{approved, client}.ViewSlice())
			require.NoError(t, err)
			require.True(t, changed, "approval changes served routes")
			require.Equal(t, gen+1, pm.NodesGeneration())
		})
	}
}
