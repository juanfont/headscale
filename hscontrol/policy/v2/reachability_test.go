package v2

import (
	"fmt"
	"net/netip"
	"sort"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
)

// nodeR creates a test node with the given parameters.
func nodeR(id int, name, ipv4, ipv6 string, user types.User, tags []string, hostinfo *tailcfg.Hostinfo) *types.Node {
	n := &types.Node{
		ID:       types.NodeID(id),
		Hostname: name,
		IPv4:     ptr.To(netip.MustParseAddr(ipv4)),
		IPv6:     ptr.To(netip.MustParseAddr(ipv6)),
		User:     ptr.To(user),
		UserID:   ptr.To(user.ID),
		Tags:     tags,
		Hostinfo: hostinfo,
	}
	return n
}

// peerIDs extracts sorted node IDs from a peer list.
func peerIDs(peers []types.NodeView) []types.NodeID {
	ids := make([]types.NodeID, len(peers))
	for i, p := range peers {
		ids[i] = p.ID()
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// assertPeerMapsEqual compares two peer maps by converting them to sorted ID lists.
func assertPeerMapsEqual(t *testing.T, want, got map[types.NodeID][]types.NodeView) {
	t.Helper()

	allKeys := make(map[types.NodeID]bool)
	for k := range want {
		allKeys[k] = true
	}
	for k := range got {
		allKeys[k] = true
	}

	for k := range allKeys {
		wantPeers := peerIDs(want[k])
		gotPeers := peerIDs(got[k])
		assert.Equal(t, wantPeers, gotPeers, "peer mismatch for node %d", k)
	}
}

// viewSliceToSlice converts a views.Slice to a plain slice for APIs that need it.
func viewSliceToSlice(vs views.Slice[types.NodeView]) []types.NodeView {
	out := make([]types.NodeView, vs.Len())
	for i := range vs.Len() {
		out[i] = vs.At(i)
	}
	return out
}

// assertComputeMatchesBuildPeerMap verifies that ComputeNodePeers produces
// the same results as BuildPeerMap for every node.
func assertComputeMatchesBuildPeerMap(t *testing.T, pm *PolicyManager, nodes types.Nodes) {
	t.Helper()
	peerMap := pm.BuildPeerMap(nodes.ViewSlice())
	allNodes := viewSliceToSlice(nodes.ViewSlice())
	for _, n := range nodes {
		computedPeers := pm.ComputeNodePeers(n.View(), allNodes)
		assert.Equal(t, peerIDs(peerMap[n.ID]), peerIDs(computedPeers),
			"ComputeNodePeers mismatch for %s (ID=%d)", n.Hostname, n.ID)
	}
}

// TestReachabilityEquivalence verifies that BuildPeerMap and ComputeNodePeers
// produce consistent peer maps for various policy configurations.
func TestReachabilityEquivalence(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
		{Model: gorm.Model{ID: 3}, Name: "charlie", Email: "charlie@example.com"},
	}

	tests := []struct {
		name  string
		pol   string
		nodes types.Nodes
	}{
		{
			name: "wildcard-to-wildcard",
			pol: `{
				"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "bob-desktop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "charlie-phone", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
			},
		},
		{
			name: "user-to-user",
			pol: `{
				"acls": [{"action": "accept", "src": ["alice@"], "dst": ["bob@:*"]}]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "bob-desktop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "charlie-phone", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
			},
		},
		{
			name: "tag-to-tag",
			pol: `{
				"tagOwners": {"tag:web": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["tag:web"], "dst": ["tag:web:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "web1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], []string{"tag:web"}, nil),
				nodeR(2, "web2", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], []string{"tag:web"}, nil),
				nodeR(3, "db1", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil, nil),
			},
		},
		{
			name: "group-to-tag",
			pol: `{
				"groups": {"group:devs": ["alice@", "bob@"]},
				"tagOwners": {"tag:server": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["group:devs"], "dst": ["tag:server:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "bob-laptop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "server1", "100.64.0.3", "fd7a:115c:a1e0::3", users[0], []string{"tag:server"}, nil),
				nodeR(4, "charlie-phone", "100.64.0.4", "fd7a:115c:a1e0::4", users[2], nil, nil),
			},
		},
		{
			name: "autogroup-member-to-self",
			pol: `{
				"acls": [
					{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "alice-phone", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], nil, nil),
				nodeR(3, "bob-desktop", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil, nil),
				nodeR(4, "bob-phone", "100.64.0.4", "fd7a:115c:a1e0::4", users[1], nil, nil),
			},
		},
		{
			name: "wildcard-to-host-no-router",
			pol: `{
				"hosts": {"mynet": "10.0.0.0/24"},
				"acls": [
					{"action": "accept", "src": ["*"], "dst": ["mynet:22"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "bob-desktop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
			},
		},
		{
			name: "wildcard-to-host-with-router",
			pol: `{
				"hosts": {"mynet": "10.0.0.0/24"},
				"acls": [
					{"action": "accept", "src": ["*"], "dst": ["mynet:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "router", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}),
			},
		},
		{
			name: "multiple-rules-mixed",
			pol: `{
				"groups": {"group:admins": ["alice@"]},
				"tagOwners": {"tag:web": ["alice@"], "tag:db": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["group:admins"], "dst": ["*:*"]},
					{"action": "accept", "src": ["tag:web"], "dst": ["tag:db:5432"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "admin-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "web1", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], []string{"tag:web"}, nil),
				nodeR(3, "db1", "100.64.0.3", "fd7a:115c:a1e0::3", users[0], []string{"tag:db"}, nil),
				nodeR(4, "bob-laptop", "100.64.0.4", "fd7a:115c:a1e0::4", users[1], nil, nil),
			},
		},
		{
			name: "autogroup-tagged",
			pol: `{
				"tagOwners": {"tag:server": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:tagged:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "bob-desktop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "server1", "100.64.0.3", "fd7a:115c:a1e0::3", users[0], []string{"tag:server"}, nil),
			},
		},
		{
			name: "exit-node-internet",
			pol: `{
				"tagOwners": {"tag:exit": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["alice@"], "dst": ["autogroup:internet:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "exit-node", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], []string{"tag:exit"},
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("0.0.0.0/0"),
						netip.MustParsePrefix("::/0"),
					}}),
				nodeR(3, "bob-laptop", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil, nil),
			},
		},
		{
			name: "ip-prefix-overlap-with-router",
			pol: `{
				"acls": [
					{"action": "accept", "src": ["*"], "dst": ["10.0.0.0/8:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "client", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "router-small", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.5.0.0/24")}}),
			},
		},
		{
			name: "empty-policy-allow-all",
			pol:  `{}`,
			nodes: types.Nodes{
				nodeR(1, "a", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "b", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
			},
		},
		{
			name:  "empty-nodes",
			pol:   `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`,
			nodes: types.Nodes{},
		},
		{
			name: "no-matching-rules",
			pol: `{
				"tagOwners": {"tag:web": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["tag:web"], "dst": ["tag:web:80"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "bob-desktop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up approved routes for nodes that have routeableIPs
			for _, n := range tt.nodes {
				if n.Hostinfo != nil && len(n.Hostinfo.RoutableIPs) > 0 {
					n.ApprovedRoutes = n.Hostinfo.RoutableIPs
				}
			}

			pm, err := NewPolicyManager([]byte(tt.pol), users, tt.nodes.ViewSlice())
			require.NoError(t, err)

			// Verify ComputeNodePeers matches BuildPeerMap
			assertComputeMatchesBuildPeerMap(t, pm, tt.nodes)
		})
	}
}

// TestReachabilityComputeNodePeersEquivalence verifies that ComputeNodePeers
// produces the same results as BuildPeerMap for each node.
func TestReachabilityComputeNodePeersEquivalence(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
	}

	pol := `{
		"groups": {"group:devs": ["alice@", "bob@"]},
		"tagOwners": {"tag:web": ["alice@"]},
		"acls": [
			{"action": "accept", "src": ["group:devs"], "dst": ["tag:web:*"]},
			{"action": "accept", "src": ["alice@"], "dst": ["bob@:22"]}
		]
	}`

	nodes := types.Nodes{
		nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
		nodeR(2, "bob-desktop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
		nodeR(3, "web1", "100.64.0.3", "fd7a:115c:a1e0::3", users[0], []string{"tag:web"}, nil),
	}

	pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
	require.NoError(t, err)

	peerMap := pm.BuildPeerMap(nodes.ViewSlice())
	allNodes := viewSliceToSlice(nodes.ViewSlice())

	for _, n := range nodes {
		t.Run(fmt.Sprintf("node-%s", n.Hostname), func(t *testing.T) {
			computedPeers := pm.ComputeNodePeers(n.View(), allNodes)
			assert.Equal(t, peerIDs(peerMap[n.ID]), peerIDs(computedPeers),
				"ComputeNodePeers mismatch for %s", n.Hostname)
		})
	}
}

// TestReachabilityWildcardShortCircuit verifies that the wildcard->wildcard
// short-circuit produces the correct all-peers result.
func TestReachabilityWildcardShortCircuit(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
	}

	pol := `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`

	nodes := types.Nodes{
		nodeR(1, "a", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
		nodeR(2, "b", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
		nodeR(3, "c", "100.64.0.3", "fd7a:115c:a1e0::3", users[0], nil, nil),
	}

	pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
	require.NoError(t, err)

	peerMap := pm.BuildPeerMap(nodes.ViewSlice())

	// Every node should see all other nodes
	for _, n := range nodes {
		peers := peerIDs(peerMap[n.ID])
		assert.Len(t, peers, 2, "node %s should have 2 peers", n.Hostname)
	}

	// Verify ComputeNodePeers consistency
	assertComputeMatchesBuildPeerMap(t, pm, nodes)
}

// TestReachabilitySubnetRouteOverlap tests that subnet routers are correctly
// matched against IP-range-based rules with various overlap patterns.
func TestReachabilitySubnetRouteOverlap(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
	}

	tests := []struct {
		name      string
		ruleRange string
		routeServ string
		wantPeers bool
	}{
		{"exact-match", "10.0.0.0/24", "10.0.0.0/24", true},
		{"rule-bigger", "10.0.0.0/8", "10.5.0.0/24", true},
		{"rule-smaller", "10.0.0.0/28", "10.0.0.0/24", true},
		{"disjoint", "10.0.0.0/24", "172.16.0.0/24", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pol := fmt.Sprintf(`{
				"acls": [{"action": "accept", "src": ["*"], "dst": ["%s:*"]}]
			}`, tt.ruleRange)

			nodes := types.Nodes{
				nodeR(1, "client", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "router", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix(tt.routeServ)}}),
			}
			nodes[1].ApprovedRoutes = nodes[1].Hostinfo.RoutableIPs

			pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
			require.NoError(t, err)

			peerMap := pm.BuildPeerMap(nodes.ViewSlice())

			// Verify expected behavior
			clientPeers := peerMap[types.NodeID(1)]
			if tt.wantPeers {
				assert.Len(t, clientPeers, 1, "client should see router as peer")
			} else {
				assert.Len(t, clientPeers, 0, "client should not see router as peer")
			}

			// Verify ComputeNodePeers consistency
			assertComputeMatchesBuildPeerMap(t, pm, nodes)
		})
	}
}

// TestReachabilityComprehensive is a comprehensive test suite that verifies
// BuildPeerMap and ComputeNodePeers consistency for a wide range of
// complex ACL configurations.
func TestReachabilityComprehensive(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
		{Model: gorm.Model{ID: 3}, Name: "charlie", Email: "charlie@example.com"},
		{Model: gorm.Model{ID: 4}, Name: "dave", Email: "dave@example.com"},
		{Model: gorm.Model{ID: 5}, Name: "eve", Email: "eve@example.com"},
	}

	tests := []struct {
		name  string
		pol   string
		nodes types.Nodes
		// Optional: expected peer count per node (by node ID).
		// If nil, only consistency between BuildPeerMap and ComputeNodePeers is checked.
		wantPeers map[types.NodeID]int
	}{
		// ---- Wildcard variants ----
		{
			name: "wildcard-src-specific-user-dst",
			pol: `{
				"acls": [{"action": "accept", "src": ["*"], "dst": ["alice@:*"]}]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "bob-desktop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "charlie-phone", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 2, // alice sees bob+charlie (reverse: they can reach her)
				2: 1, // bob sees alice
				3: 1, // charlie sees alice
			},
		},
		{
			name: "specific-user-src-wildcard-dst",
			pol: `{
				"acls": [{"action": "accept", "src": ["alice@"], "dst": ["*:*"]}]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "bob-desktop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "charlie-phone", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 2, // alice sees everyone
				2: 1, // bob only sees alice (reverse)
				3: 1, // charlie only sees alice (reverse)
			},
		},

		// ---- Multiple devices per user ----
		{
			name: "user-with-multiple-devices",
			pol: `{
				"acls": [{"action": "accept", "src": ["alice@"], "dst": ["bob@:*"]}]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "alice-phone", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], nil, nil),
				nodeR(3, "bob-desktop", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil, nil),
				nodeR(4, "bob-phone", "100.64.0.4", "fd7a:115c:a1e0::4", users[1], nil, nil),
				nodeR(5, "charlie", "100.64.0.5", "fd7a:115c:a1e0::5", users[2], nil, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 2, // alice-laptop sees bob-desktop + bob-phone
				2: 2, // alice-phone sees bob-desktop + bob-phone
				3: 2, // bob-desktop sees alice-laptop + alice-phone (reverse)
				4: 2, // bob-phone sees alice-laptop + alice-phone (reverse)
				5: 0, // charlie sees nobody
			},
		},

		// ---- autogroup:self variants ----
		{
			name: "wildcard-to-self",
			pol: `{
				"acls": [
					{"action": "accept", "src": ["*"], "dst": ["autogroup:self:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "alice-phone", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], nil, nil),
				nodeR(3, "bob-desktop", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 1, // alice-laptop sees alice-phone (same user)
				2: 1, // alice-phone sees alice-laptop
				3: 0, // bob only has one device, no self-peers
			},
		},
		{
			name: "user-to-self",
			pol: `{
				"acls": [
					{"action": "accept", "src": ["alice@"], "dst": ["autogroup:self:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "alice-phone", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], nil, nil),
				nodeR(3, "bob-desktop", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil, nil),
				nodeR(4, "bob-phone", "100.64.0.4", "fd7a:115c:a1e0::4", users[1], nil, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 1, // alice-laptop sees alice-phone
				2: 1, // alice-phone sees alice-laptop
				3: 0, // bob devices see nothing (rule only applies to alice)
				4: 0,
			},
		},
		{
			name: "self-plus-cross-user-access",
			pol: `{
				"acls": [
					{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]},
					{"action": "accept", "src": ["alice@"], "dst": ["bob@:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "alice-phone", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], nil, nil),
				nodeR(3, "bob-desktop", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil, nil),
				nodeR(4, "charlie", "100.64.0.4", "fd7a:115c:a1e0::4", users[2], nil, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 2, // alice-laptop: self(alice-phone) + forward(bob-desktop)
				2: 2, // alice-phone: self(alice-laptop) + forward(bob-desktop)
				3: 2, // bob-desktop: reverse from alice (alice-laptop + alice-phone)
				4: 0, // charlie: only 1 device, self gives no peers
			},
		},
		{
			name: "self-with-tagged-node-excluded",
			pol: `{
				"tagOwners": {"tag:server": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "alice-phone", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], nil, nil),
				nodeR(3, "alice-server", "100.64.0.3", "fd7a:115c:a1e0::3", users[0], []string{"tag:server"}, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 1, // alice-laptop sees alice-phone (not tagged server)
				2: 1, // alice-phone sees alice-laptop
				3: 0, // tagged server: autogroup:member doesn't include tagged nodes
			},
		},

		// ---- Group interactions ----
		{
			name: "group-to-group",
			pol: `{
				"groups": {
					"group:frontend": ["alice@", "bob@"],
					"group:backend": ["charlie@", "dave@"]
				},
				"acls": [
					{"action": "accept", "src": ["group:frontend"], "dst": ["group:backend:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "bob", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "charlie", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
				nodeR(4, "dave", "100.64.0.4", "fd7a:115c:a1e0::4", users[3], nil, nil),
				nodeR(5, "eve", "100.64.0.5", "fd7a:115c:a1e0::5", users[4], nil, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 2, // alice (frontend) sees charlie+dave (backend)
				2: 2, // bob (frontend) sees charlie+dave
				3: 2, // charlie (backend) sees alice+bob (reverse)
				4: 2, // dave (backend) sees alice+bob
				5: 0, // eve not in any group
			},
		},
		{
			name: "overlapping-groups",
			pol: `{
				"groups": {
					"group:admins": ["alice@"],
					"group:devs": ["alice@", "bob@"]
				},
				"acls": [
					{"action": "accept", "src": ["group:admins"], "dst": ["group:devs:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "bob", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "charlie", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 1, // alice (admin+dev) sees bob (dev, but not herself)
				2: 1, // bob (dev) sees alice (reverse)
				3: 0, // charlie not in any group
			},
		},
		{
			name: "group-to-self",
			pol: `{
				"groups": {"group:team": ["alice@", "bob@"]},
				"acls": [
					{"action": "accept", "src": ["group:team"], "dst": ["autogroup:self:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "alice-phone", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], nil, nil),
				nodeR(3, "bob-desktop", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil, nil),
				nodeR(4, "bob-phone", "100.64.0.4", "fd7a:115c:a1e0::4", users[1], nil, nil),
				nodeR(5, "charlie", "100.64.0.5", "fd7a:115c:a1e0::5", users[2], nil, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 1, // alice-laptop sees alice-phone (self)
				2: 1, // alice-phone sees alice-laptop
				3: 1, // bob-desktop sees bob-phone (self)
				4: 1, // bob-phone sees bob-desktop
				5: 0, // charlie not in group
			},
		},
		{
			name: "group-with-nonexistent-user",
			pol: `{
				"groups": {"group:team": ["alice@", "nobody@"]},
				"acls": [
					{"action": "accept", "src": ["group:team"], "dst": ["bob@:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "bob", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 1, // alice sees bob
				2: 1, // bob sees alice (reverse)
			},
		},

		// ---- Tag interactions ----
		{
			name: "multi-tag-node",
			pol: `{
				"tagOwners": {"tag:web": ["alice@"], "tag:public": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["tag:web"], "dst": ["tag:public:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "web-only", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], []string{"tag:web"}, nil),
				nodeR(2, "both-tags", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], []string{"tag:web", "tag:public"}, nil),
				nodeR(3, "public-only", "100.64.0.3", "fd7a:115c:a1e0::3", users[0], []string{"tag:public"}, nil),
				nodeR(4, "untagged", "100.64.0.4", "fd7a:115c:a1e0::4", users[0], nil, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 2, // web-only sees both-tags + public-only (src->dst)
				2: 2, // both-tags sees web-only (reverse) + public-only (forward)
				3: 2, // public-only sees web-only + both-tags (reverse: web->public)
				4: 0, // untagged: no rules apply
			},
		},
		{
			name: "tag-to-user",
			pol: `{
				"tagOwners": {"tag:monitor": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["tag:monitor"], "dst": ["bob@:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "monitor", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], []string{"tag:monitor"}, nil),
				nodeR(2, "bob-laptop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "alice-laptop", "100.64.0.3", "fd7a:115c:a1e0::3", users[0], nil, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 1, // monitor sees bob
				2: 1, // bob sees monitor (reverse)
				3: 0, // alice-laptop not involved
			},
		},

		// ---- autogroup:tagged + autogroup:member ----
		{
			name: "member-to-tagged-bidirectional",
			pol: `{
				"tagOwners": {"tag:server": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:tagged:*"]},
					{"action": "accept", "src": ["autogroup:tagged"], "dst": ["autogroup:member:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "bob-desktop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "server1", "100.64.0.3", "fd7a:115c:a1e0::3", users[0], []string{"tag:server"}, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 1, // alice-laptop sees server1
				2: 1, // bob sees server1
				3: 2, // server1 sees alice+bob
			},
		},

		// ---- Exit node / autogroup:internet ----
		{
			name: "internet-multiple-users",
			pol: `{
				"tagOwners": {"tag:exit": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:internet:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "bob-desktop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "exit1", "100.64.0.3", "fd7a:115c:a1e0::3", users[0], []string{"tag:exit"},
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("0.0.0.0/0"),
						netip.MustParsePrefix("::/0"),
					}}),
				nodeR(4, "non-exit-server", "100.64.0.4", "fd7a:115c:a1e0::4", users[0], []string{"tag:exit"}, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 0, // autogroup:internet does not generate peer relationships
				2: 0, // exit node routing is handled via AllowedIPs, not peer map
				3: 0,
				4: 0,
			},
		},

		// ---- IP prefix / host rules ----
		{
			name: "host-with-cgnat-ip-match",
			pol: `{
				"hosts": {"my-node": "100.64.0.2/32"},
				"acls": [
					{"action": "accept", "src": ["alice@"], "dst": ["my-node:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "target-node", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "other-node", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
			},
		},
		{
			name: "prefix-dst-non-cgnat-no-router",
			pol: `{
				"acls": [
					{"action": "accept", "src": ["alice@"], "dst": ["10.0.0.0/24:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "bob", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 0, // no router for 10.0.0.0/24 -> no peers
				2: 0,
			},
		},
		{
			name: "prefix-dst-non-cgnat-with-exact-router",
			pol: `{
				"acls": [
					{"action": "accept", "src": ["alice@"], "dst": ["10.0.0.0/24:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "router", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}),
			},
		},
		{
			name: "prefix-in-src-with-router",
			pol: `{
				"acls": [
					{"action": "accept", "src": ["10.0.0.0/24"], "dst": ["alice@:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "router", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}),
				nodeR(3, "other", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
			},
		},
		{
			name: "multiple-hosts-same-rule",
			pol: `{
				"hosts": {
					"net-a": "10.0.1.0/24",
					"net-b": "10.0.2.0/24"
				},
				"acls": [
					{"action": "accept", "src": ["*"], "dst": ["net-a:*", "net-b:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "client", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "router-a", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")}}),
				nodeR(3, "router-b", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24")}}),
				nodeR(4, "no-route", "100.64.0.4", "fd7a:115c:a1e0::4", users[3], nil, nil),
			},
		},

		// ---- Complex multi-rule scenarios ----
		{
			name: "admin-full-access-plus-restricted-users",
			pol: `{
				"groups": {"group:admins": ["alice@"]},
				"tagOwners": {"tag:server": ["alice@"], "tag:db": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["group:admins"], "dst": ["*:*"]},
					{"action": "accept", "src": ["bob@"], "dst": ["tag:server:80,443"]},
					{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "alice-phone", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], nil, nil),
				nodeR(3, "bob-desktop", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil, nil),
				nodeR(4, "server1", "100.64.0.4", "fd7a:115c:a1e0::4", users[0], []string{"tag:server"}, nil),
				nodeR(5, "db1", "100.64.0.5", "fd7a:115c:a1e0::5", users[0], []string{"tag:db"}, nil),
				nodeR(6, "charlie", "100.64.0.6", "fd7a:115c:a1e0::6", users[2], nil, nil),
			},
		},
		{
			name: "tiered-access-control",
			pol: `{
				"groups": {
					"group:tier1": ["alice@"],
					"group:tier2": ["alice@", "bob@"],
					"group:tier3": ["alice@", "bob@", "charlie@"]
				},
				"tagOwners": {"tag:critical": ["alice@"], "tag:standard": ["alice@"], "tag:public": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["group:tier1"], "dst": ["tag:critical:*"]},
					{"action": "accept", "src": ["group:tier2"], "dst": ["tag:standard:*"]},
					{"action": "accept", "src": ["group:tier3"], "dst": ["tag:public:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "bob", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "charlie", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
				nodeR(4, "critical-srv", "100.64.0.4", "fd7a:115c:a1e0::4", users[0], []string{"tag:critical"}, nil),
				nodeR(5, "standard-srv", "100.64.0.5", "fd7a:115c:a1e0::5", users[0], []string{"tag:standard"}, nil),
				nodeR(6, "public-srv", "100.64.0.6", "fd7a:115c:a1e0::6", users[0], []string{"tag:public"}, nil),
				nodeR(7, "dave", "100.64.0.7", "fd7a:115c:a1e0::7", users[3], nil, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 3, // alice (all tiers) sees critical+standard+public
				2: 2, // bob (tier2+tier3) sees standard+public
				3: 1, // charlie (tier3) sees public only
				4: 1, // critical sees alice (reverse)
				5: 2, // standard sees alice+bob (reverse)
				6: 3, // public sees alice+bob+charlie (reverse)
				7: 0, // dave in no group
			},
		},
		{
			name: "mesh-between-tags",
			pol: `{
				"tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"], "tag:c": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["tag:a"], "dst": ["tag:b:*"]},
					{"action": "accept", "src": ["tag:b"], "dst": ["tag:c:*"]},
					{"action": "accept", "src": ["tag:c"], "dst": ["tag:a:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "a1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], []string{"tag:a"}, nil),
				nodeR(2, "a2", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], []string{"tag:a"}, nil),
				nodeR(3, "b1", "100.64.0.3", "fd7a:115c:a1e0::3", users[0], []string{"tag:b"}, nil),
				nodeR(4, "c1", "100.64.0.4", "fd7a:115c:a1e0::4", users[0], []string{"tag:c"}, nil),
				nodeR(5, "untagged", "100.64.0.5", "fd7a:115c:a1e0::5", users[0], nil, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 2, // a1: forward(b1) + reverse from c(c1)
				2: 2, // a2: forward(b1) + reverse from c(c1)
				3: 3, // b1: reverse from a(a1+a2) + forward(c1)
				4: 3, // c1: reverse from b(b1) + forward(a1+a2)
				5: 0, // untagged: no rules apply
			},
		},

		// ---- Subnet route edge cases ----
		{
			name: "router-with-partial-overlap",
			pol: `{
				"acls": [
					{"action": "accept", "src": ["*"], "dst": ["10.0.0.0/24:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "client", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "router-half", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/25")}}),
			},
		},
		{
			name: "router-with-superset-route",
			pol: `{
				"acls": [
					{"action": "accept", "src": ["*"], "dst": ["10.0.0.0/28:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "client", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "router-big", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}),
			},
		},
		{
			name: "multiple-routers-same-prefix",
			pol: `{
				"acls": [
					{"action": "accept", "src": ["alice@"], "dst": ["10.0.0.0/24:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "router1", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}),
				nodeR(3, "router2", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}),
			},
		},
		{
			name: "router-multiple-routes",
			pol: `{
				"acls": [
					{"action": "accept", "src": ["*"], "dst": ["10.0.1.0/24:*", "10.0.2.0/24:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "client", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "router", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.0.1.0/24"),
						netip.MustParsePrefix("10.0.2.0/24"),
					}}),
			},
		},
		{
			name: "exit-node-plus-subnet-route",
			pol: `{
				"tagOwners": {"tag:gateway": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["bob@"], "dst": ["autogroup:internet:*"]},
					{"action": "accept", "src": ["charlie@"], "dst": ["10.0.0.0/24:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "gateway", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], []string{"tag:gateway"},
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("0.0.0.0/0"),
						netip.MustParsePrefix("::/0"),
						netip.MustParsePrefix("10.0.0.0/24"),
					}}),
				nodeR(2, "bob", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "charlie", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
			},
		},

		// ---- Edge cases ----
		{
			name: "single-node",
			pol: `{
				"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
			}`,
			nodes: types.Nodes{
				nodeR(1, "lonely", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 0, // no other nodes to peer with
			},
		},
		{
			name: "all-tagged-no-member-rules",
			pol: `{
				"tagOwners": {"tag:server": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:tagged:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "srv1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], []string{"tag:server"}, nil),
				nodeR(2, "srv2", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], []string{"tag:server"}, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 0, // all nodes are tagged, no members -> no peers
				2: 0,
			},
		},
		{
			name: "same-user-different-rules",
			pol: `{
				"tagOwners": {"tag:server": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["alice@"], "dst": ["tag:server:*"]},
					{"action": "accept", "src": ["tag:server"], "dst": ["alice@:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "alice-server", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], []string{"tag:server"}, nil),
				nodeR(3, "bob", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 1, // alice sees server (forward + reverse)
				2: 1, // server sees alice
				3: 0, // bob not involved
			},
		},

		// ---- Many overlapping rules ----
		{
			name: "many-rules-overlapping-sources",
			pol: `{
				"groups": {"group:all": ["alice@", "bob@", "charlie@"]},
				"tagOwners": {"tag:web": ["alice@"], "tag:db": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["alice@"], "dst": ["*:*"]},
					{"action": "accept", "src": ["group:all"], "dst": ["tag:web:80"]},
					{"action": "accept", "src": ["bob@"], "dst": ["tag:db:5432"]},
					{"action": "accept", "src": ["*"], "dst": ["autogroup:self:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "alice-phone", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], nil, nil),
				nodeR(3, "bob-desktop", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil, nil),
				nodeR(4, "charlie-laptop", "100.64.0.4", "fd7a:115c:a1e0::4", users[2], nil, nil),
				nodeR(5, "web-srv", "100.64.0.5", "fd7a:115c:a1e0::5", users[0], []string{"tag:web"}, nil),
				nodeR(6, "db-srv", "100.64.0.6", "fd7a:115c:a1e0::6", users[0], []string{"tag:db"}, nil),
			},
		},

		// ---- CGNAT IP range match ----
		{
			name: "cgnat-range-host-definition",
			pol: `{
				"hosts": {"specific-node": "100.64.0.2/32"},
				"acls": [
					{"action": "accept", "src": ["alice@"], "dst": ["specific-node:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "target", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "other", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 1, // alice sees target (matched by CGNAT IP)
				2: 1, // target sees alice (reverse)
				3: 0, // other not matched
			},
		},
		{
			name: "ula-range-host-definition",
			pol: `{
				"hosts": {"specific-v6": "fd7a:115c:a1e0::2/128"},
				"acls": [
					{"action": "accept", "src": ["alice@"], "dst": ["specific-v6:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "target", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "other", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
			},
			wantPeers: map[types.NodeID]int{
				1: 1, // alice sees target (matched by ULA IPv6)
				2: 1, // target sees alice (reverse)
				3: 0, // other not matched
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up approved routes for nodes with routeableIPs
			for _, n := range tt.nodes {
				if n.Hostinfo != nil && len(n.Hostinfo.RoutableIPs) > 0 {
					n.ApprovedRoutes = n.Hostinfo.RoutableIPs
				}
			}

			pm, err := NewPolicyManager([]byte(tt.pol), users, tt.nodes.ViewSlice())
			require.NoError(t, err)

			// Test BuildPeerMap
			reachMap := pm.BuildPeerMap(tt.nodes.ViewSlice())

			// Verify ComputeNodePeers matches BuildPeerMap
			assertComputeMatchesBuildPeerMap(t, pm, tt.nodes)

			// Verify expected peer counts if specified
			if tt.wantPeers != nil {
				for nodeID, wantCount := range tt.wantPeers {
					gotCount := len(reachMap[nodeID])
					assert.Equal(t, wantCount, gotCount,
						"expected %d peers for node %d, got %d", wantCount, nodeID, gotCount)
				}
			}
		})
	}
}

// TestReachabilityScaleEquivalence verifies correctness at larger scale
// with a realistic multi-department policy.
func TestReachabilityScaleEquivalence(t *testing.T) {
	const (
		numUsers    = 20
		numDepts    = 5
		nodesPerDep = 4 // total = 20 user nodes + 5 tagged servers = 25
	)

	// Create users
	users := make(types.Users, numUsers)
	for i := range users {
		users[i] = types.User{
			Model: gorm.Model{ID: uint(i + 1)},
			Name:  fmt.Sprintf("user%d", i),
			Email: fmt.Sprintf("user%d@example.com", i),
		}
	}

	// Build policy: each department has a group and tagged servers
	pol := `{
		"groups": {`
	for d := range numDepts {
		if d > 0 {
			pol += ","
		}
		pol += fmt.Sprintf(`"group:dept%d": [`, d)
		for u := d * nodesPerDep; u < (d+1)*nodesPerDep && u < numUsers; u++ {
			if u > d*nodesPerDep {
				pol += ","
			}
			pol += fmt.Sprintf(`"user%d@"`, u)
		}
		pol += `]`
	}
	pol += `},
		"tagOwners": {`
	for d := range numDepts {
		if d > 0 {
			pol += ","
		}
		pol += fmt.Sprintf(`"tag:dept%d-server": ["user%d@"]`, d, d*nodesPerDep)
	}
	pol += `},
		"acls": [`
	// Each department can access its own servers
	for d := range numDepts {
		if d > 0 {
			pol += ","
		}
		pol += fmt.Sprintf(`{"action":"accept","src":["group:dept%d"],"dst":["tag:dept%d-server:*"]}`, d, d)
	}
	// Everyone can access their own devices
	pol += `,{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:*"]}`
	// Admins (dept0) can access everything
	pol += `,{"action":"accept","src":["group:dept0"],"dst":["*:*"]}`
	pol += `]}`

	// Create nodes: one per user + one tagged server per department
	var nodes types.Nodes
	nodeID := 1
	for i := range numUsers {
		nodes = append(nodes, nodeR(
			nodeID,
			fmt.Sprintf("user%d-laptop", i),
			fmt.Sprintf("100.64.0.%d", nodeID),
			fmt.Sprintf("fd7a:115c:a1e0::%d", nodeID),
			users[i], nil, nil,
		))
		nodeID++
	}
	for d := range numDepts {
		nodes = append(nodes, nodeR(
			nodeID,
			fmt.Sprintf("dept%d-server", d),
			fmt.Sprintf("100.64.0.%d", nodeID),
			fmt.Sprintf("fd7a:115c:a1e0::%d", nodeID),
			users[d*nodesPerDep],
			[]string{fmt.Sprintf("tag:dept%d-server", d)},
			nil,
		))
		nodeID++
	}

	pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
	require.NoError(t, err)

	// Verify ComputeNodePeers matches BuildPeerMap
	assertComputeMatchesBuildPeerMap(t, pm, nodes)
}

// TestReachabilitySubnetRouteComplexOverlap tests complex subnet route
// scenarios with nested, overlapping, and multiple prefixes.
func TestReachabilitySubnetRouteComplexOverlap(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
	}

	tests := []struct {
		name      string
		pol       string
		nodes     types.Nodes
		wantPeers map[types.NodeID]int
	}{
		{
			name: "router-serves-multiple-overlapping-ranges",
			pol: `{
				"acls": [
					{"action": "accept", "src": ["alice@"], "dst": ["10.0.0.0/8:*"]},
					{"action": "accept", "src": ["alice@"], "dst": ["10.0.0.0/24:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "router", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.0.0.0/24"),
					}}),
			},
		},
		{
			name: "two-routers-nested-subnets",
			pol: `{
				"acls": [
					{"action": "accept", "src": ["*"], "dst": ["10.0.0.0/16:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "client", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "router-wide", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}),
				nodeR(3, "router-narrow", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")}}),
			},
		},
		{
			name: "ipv6-subnet-route",
			pol: `{
				"acls": [
					{"action": "accept", "src": ["*"], "dst": ["2001:db8::/32:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "client", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "v6-router", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/48")}}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, n := range tt.nodes {
				if n.Hostinfo != nil && len(n.Hostinfo.RoutableIPs) > 0 {
					n.ApprovedRoutes = n.Hostinfo.RoutableIPs
				}
			}

			pm, err := NewPolicyManager([]byte(tt.pol), users, tt.nodes.ViewSlice())
			require.NoError(t, err)

			reachMap := pm.BuildPeerMap(tt.nodes.ViewSlice())

			// Verify ComputeNodePeers consistency
			assertComputeMatchesBuildPeerMap(t, pm, tt.nodes)

			if tt.wantPeers != nil {
				for nodeID, wantCount := range tt.wantPeers {
					assert.Equal(t, wantCount, len(reachMap[nodeID]),
						"node %d peer count", nodeID)
				}
			}
		})
	}
}

// TestReachabilityComputeNodePeersAllScenarios verifies that ComputeNodePeers
// matches BuildPeerMap across all the comprehensive test scenarios.
// This specifically tests the incremental peer computation path used during
// registration (ComputeNodePeers is called per new node, not BuildPeerMap).
func TestReachabilityComputeNodePeersAllScenarios(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
		{Model: gorm.Model{ID: 3}, Name: "charlie", Email: "charlie@example.com"},
	}

	tests := []struct {
		name  string
		pol   string
		nodes types.Nodes
	}{
		{
			name: "member-self-with-tags",
			pol: `{
				"tagOwners": {"tag:server": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]},
					{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:tagged:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "alice-phone", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], nil, nil),
				nodeR(3, "server", "100.64.0.3", "fd7a:115c:a1e0::3", users[0], []string{"tag:server"}, nil),
				nodeR(4, "bob", "100.64.0.4", "fd7a:115c:a1e0::4", users[1], nil, nil),
			},
		},
		{
			name: "cross-user-group-with-host-rules",
			pol: `{
				"groups": {"group:devs": ["alice@", "bob@"]},
				"hosts": {"internal-net": "10.0.0.0/16"},
				"acls": [
					{"action": "accept", "src": ["group:devs"], "dst": ["internal-net:*"]},
					{"action": "accept", "src": ["alice@"], "dst": ["bob@:22"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "bob", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "charlie", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
				nodeR(4, "router", "100.64.0.4", "fd7a:115c:a1e0::4", users[2], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")}}),
			},
		},
		{
			name: "tagged-to-tagged-via-wildcard",
			pol: `{
				"tagOwners": {"tag:server": ["alice@"], "tag:monitor": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["autogroup:tagged"], "dst": ["autogroup:tagged:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "server1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], []string{"tag:server"}, nil),
				nodeR(2, "server2", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], []string{"tag:server"}, nil),
				nodeR(3, "monitor", "100.64.0.3", "fd7a:115c:a1e0::3", users[0], []string{"tag:monitor"}, nil),
				nodeR(4, "untagged", "100.64.0.4", "fd7a:115c:a1e0::4", users[0], nil, nil),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, n := range tt.nodes {
				if n.Hostinfo != nil && len(n.Hostinfo.RoutableIPs) > 0 {
					n.ApprovedRoutes = n.Hostinfo.RoutableIPs
				}
			}

			pm, err := NewPolicyManager([]byte(tt.pol), users, tt.nodes.ViewSlice())
			require.NoError(t, err)

			// Verify ComputeNodePeers matches BuildPeerMap for all nodes
			assertComputeMatchesBuildPeerMap(t, pm, tt.nodes)
		})
	}
}

// TestReachabilityPeerSymmetry verifies that peer visibility is always
// symmetric: if A can see B, then B can see A. This is a fundamental
// requirement because if A can send packets to B, B needs A in its peer
// list to accept/route those packets.
func TestReachabilityPeerSymmetry(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
		{Model: gorm.Model{ID: 3}, Name: "charlie", Email: "charlie@example.com"},
	}

	tests := []struct {
		name  string
		pol   string
		nodes types.Nodes
	}{
		{
			name: "asymmetric-user-rule",
			pol:  `{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["bob@:*"]}]}`,
			nodes: types.Nodes{
				nodeR(1, "alice", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "bob", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "charlie", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
			},
		},
		{
			name: "one-way-tag-rule",
			pol: `{
				"tagOwners": {"tag:server": ["alice@"]},
				"acls": [{"action": "accept", "src": ["alice@"], "dst": ["tag:server:*"]}]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "server", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], []string{"tag:server"}, nil),
			},
		},
		{
			name: "exit-node-asymmetric",
			pol: `{
				"tagOwners": {"tag:exit": ["alice@"]},
				"acls": [{"action": "accept", "src": ["bob@"], "dst": ["autogroup:internet:*"]}]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "bob", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "exit", "100.64.0.3", "fd7a:115c:a1e0::3", users[0], []string{"tag:exit"},
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("0.0.0.0/0"),
						netip.MustParsePrefix("::/0"),
					}}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, n := range tt.nodes {
				if n.Hostinfo != nil && len(n.Hostinfo.RoutableIPs) > 0 {
					n.ApprovedRoutes = n.Hostinfo.RoutableIPs
				}
			}

			pm, err := NewPolicyManager([]byte(tt.pol), users, tt.nodes.ViewSlice())
			require.NoError(t, err)

			peerMap := pm.BuildPeerMap(tt.nodes.ViewSlice())

			// Check symmetry: if A sees B, B must see A
			for nodeID, peers := range peerMap {
				for _, peer := range peers {
					peerPeers := peerMap[peer.ID()]
					found := false
					for _, pp := range peerPeers {
						if pp.ID() == nodeID {
							found = true
							break
						}
					}
					assert.True(t, found,
						"asymmetry: node %d sees %d, but %d doesn't see %d",
						nodeID, peer.ID(), peer.ID(), nodeID)
				}
			}
		})
	}
}

// TestTagChangeUpdatesReachability verifies that when a user-owned node is
// tagged (e.g., via headscale nodes tag), the peer maps correctly
// reflect the new identity. Specifically:
//   - The node should become visible to users allowed to access its new tag
//   - The node should no longer be visible via its old user identity
//   - Cross-user tag visibility should work (alice can see dave's tagged server)
func TestTagChangeUpdatesReachability(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "dave", Email: "dave@example.com"},
		{Model: gorm.Model{ID: 3}, Name: "frank", Email: "frank@example.com"},
	}

	pol := `{
		"groups": {
			"group:eng": ["alice@example.com"],
			"group:ops": ["dave@example.com"]
		},
		"tagOwners": {
			"tag:server": ["group:ops"],
			"tag:exit-node": ["group:ops"]
		},
		"acls": [
			{"action": "accept", "src": ["group:eng"], "dst": ["tag:server:*"]},
			{"action": "accept", "src": ["group:eng"], "dst": ["group:eng:*"]},
			{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:exit-node:*"]},
			{"action": "accept", "src": ["group:ops"], "dst": ["group:ops:*"]}
		]
	}`

	t.Run("tag-user-node-cross-user-visibility", func(t *testing.T) {
		// Phase 1: All nodes are user-owned members
		aliceLaptop := nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil)
		daveSrv := nodeR(2, "dave-srv", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil)
		frankLaptop := nodeR(3, "frank-laptop", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil)

		initialNodes := types.Nodes{aliceLaptop, daveSrv, frankLaptop}
		pm, err := NewPolicyManager([]byte(pol), users, initialNodes.ViewSlice())
		require.NoError(t, err)

		// Before tagging: alice sees no one (eng->eng only includes alice, eng->tag:server
		// has no tagged nodes). dave sees no one (ops->ops only includes dave).
		// frank sees no one (no rules for frank).
		peerMap := pm.BuildPeerMap(initialNodes.ViewSlice())
		assert.Empty(t, peerMap[aliceLaptop.ID], "alice should see 0 peers before any tags")
		assert.Empty(t, peerMap[daveSrv.ID], "dave-srv should see 0 peers before tagging")
		assert.Empty(t, peerMap[frankLaptop.ID], "frank should see 0 peers (no rules)")

		// Phase 2: Tag dave-srv as tag:server
		daveSrvTagged := nodeR(2, "dave-srv", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], []string{"tag:server"}, nil)
		taggedNodes := types.Nodes{aliceLaptop, daveSrvTagged, frankLaptop}

		changed, identityChanged, _, err := pm.SetNodes(taggedNodes.ViewSlice())
		require.NoError(t, err)
		require.True(t, changed, "SetNodes should detect tag change")
		require.True(t, identityChanged, "SetNodes should report identity change for tag addition")

		// After tagging: alice should see dave-srv (eng->tag:server)
		taggedPeerMap := pm.BuildPeerMap(taggedNodes.ViewSlice())

		alicePeers := peerIDs(taggedPeerMap[aliceLaptop.ID])
		assert.Equal(t, []types.NodeID{daveSrvTagged.ID}, alicePeers,
			"alice should see dave-srv after it's tagged as tag:server (eng->tag:server)")

		davePeers := peerIDs(taggedPeerMap[daveSrvTagged.ID])
		assert.Equal(t, []types.NodeID{aliceLaptop.ID}, davePeers,
			"dave-srv (tag:server) should see alice (eng->tag:server reverse)")

		assert.Empty(t, taggedPeerMap[frankLaptop.ID],
			"frank should still see 0 peers (no rules for frank->tag:server)")
	})

	t.Run("tag-exit-node-visibility", func(t *testing.T) {
		// Test: autogroup:member -> tag:exit-node should make exit node visible to ALL members
		aliceLaptop := nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil)
		daveExit := nodeR(2, "dave-exit", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil)
		frankLaptop := nodeR(3, "frank-laptop", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil)

		initialNodes := types.Nodes{aliceLaptop, daveExit, frankLaptop}
		pm, err := NewPolicyManager([]byte(pol), users, initialNodes.ViewSlice())
		require.NoError(t, err)

		// Before tagging: no exit node, no member->exit-node peers
		peerMap := pm.BuildPeerMap(initialNodes.ViewSlice())
		assert.Empty(t, peerMap[frankLaptop.ID], "frank sees 0 peers before exit node tagged")

		// Tag dave-exit as tag:exit-node
		daveExitTagged := nodeR(2, "dave-exit", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], []string{"tag:exit-node"}, nil)
		taggedNodes := types.Nodes{aliceLaptop, daveExitTagged, frankLaptop}

		changed, identityChanged, _, err := pm.SetNodes(taggedNodes.ViewSlice())
		require.NoError(t, err)
		require.True(t, changed)
		require.True(t, identityChanged)

		taggedPeerMap := pm.BuildPeerMap(taggedNodes.ViewSlice())

		// ALL members should see the exit node
		alicePeers := peerIDs(taggedPeerMap[aliceLaptop.ID])
		assert.Contains(t, alicePeers, daveExitTagged.ID,
			"alice (member) should see dave-exit (tag:exit-node)")

		frankPeers := peerIDs(taggedPeerMap[frankLaptop.ID])
		assert.Equal(t, []types.NodeID{daveExitTagged.ID}, frankPeers,
			"frank (member, no other rules) should see dave-exit (member->exit-node)")

		// Exit node should see ALL members (reverse direction)
		exitPeers := peerIDs(taggedPeerMap[daveExitTagged.ID])
		assert.Contains(t, exitPeers, aliceLaptop.ID, "exit should see alice")
		assert.Contains(t, exitPeers, frankLaptop.ID, "exit should see frank")
	})

	t.Run("untag-removes-tag-visibility", func(t *testing.T) {
		// A node tagged as tag:server should lose tag-based visibility when
		// the tag is changed.
		aliceLaptop := nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil)
		daveSrv := nodeR(2, "dave-srv", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], []string{"tag:server"}, nil)

		initialNodes := types.Nodes{aliceLaptop, daveSrv}
		pm, err := NewPolicyManager([]byte(pol), users, initialNodes.ViewSlice())
		require.NoError(t, err)

		// Initially: alice sees dave-srv (eng->tag:server)
		peerMap := pm.BuildPeerMap(initialNodes.ViewSlice())
		assert.Len(t, peerMap[aliceLaptop.ID], 1, "alice should see dave-srv initially")

		// Change dave-srv's tag from tag:server to tag:exit-node
		daveSrvRetag := nodeR(2, "dave-srv", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], []string{"tag:exit-node"}, nil)
		retaggedNodes := types.Nodes{aliceLaptop, daveSrvRetag}

		changed, identityChanged, _, err := pm.SetNodes(retaggedNodes.ViewSlice())
		require.NoError(t, err)
		require.True(t, changed)
		require.True(t, identityChanged)

		retaggedPeerMap := pm.BuildPeerMap(retaggedNodes.ViewSlice())

		// alice should now see dave-srv as exit node (member->exit-node) but NOT as server
		alicePeers := peerIDs(retaggedPeerMap[aliceLaptop.ID])
		assert.Equal(t, []types.NodeID{daveSrvRetag.ID}, alicePeers,
			"alice should see dave-srv as exit node (member->exit-node)")
	})

	t.Run("multi-user-multi-tag-complex", func(t *testing.T) {
		// Complex scenario: 6 users, various tags, verifying cross-user tag visibility
		moreUsers := types.Users{
			{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
			{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
			{Model: gorm.Model{ID: 3}, Name: "carol", Email: "carol@example.com"},
			{Model: gorm.Model{ID: 4}, Name: "dave", Email: "dave@example.com"},
			{Model: gorm.Model{ID: 5}, Name: "eve", Email: "eve@example.com"},
			{Model: gorm.Model{ID: 6}, Name: "frank", Email: "frank@example.com"},
		}

		complexPol := `{
			"groups": {
				"group:eng": ["alice@example.com", "bob@example.com", "carol@example.com"],
				"group:ops": ["carol@example.com", "dave@example.com"],
				"group:security": ["eve@example.com"],
				"group:mgmt": ["frank@example.com"]
			},
			"tagOwners": {
				"tag:server": ["group:ops"],
				"tag:database": ["group:ops"],
				"tag:monitoring": ["group:ops", "group:security"],
				"tag:exit-node": ["group:ops"]
			},
			"acls": [
				{"action": "accept", "src": ["group:eng"], "dst": ["tag:server:22,80,443"]},
				{"action": "accept", "src": ["group:eng"], "dst": ["group:eng:*"]},
				{"action": "accept", "src": ["group:ops"], "dst": ["tag:server:*", "tag:database:*", "tag:monitoring:*"]},
				{"action": "accept", "src": ["group:security"], "dst": ["tag:monitoring:443,9090"]},
				{"action": "accept", "src": ["group:mgmt"], "dst": ["group:mgmt:*"]},
				{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:exit-node:*"]},
				{"action": "accept", "src": ["tag:server"], "dst": ["tag:database:5432,3306"]},
				{"action": "accept", "src": ["tag:monitoring"], "dst": ["tag:server:9100", "tag:database:9100"]}
			]
		}`

		// All start as user-owned members
		aliceLaptop := nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", moreUsers[0], nil, nil)
		bobLaptop := nodeR(2, "bob-laptop", "100.64.0.2", "fd7a:115c:a1e0::2", moreUsers[1], nil, nil)
		carolLaptop := nodeR(3, "carol-laptop", "100.64.0.3", "fd7a:115c:a1e0::3", moreUsers[2], nil, nil)
		daveSrv := nodeR(4, "dave-srv", "100.64.0.4", "fd7a:115c:a1e0::4", moreUsers[3], nil, nil)
		daveDb := nodeR(5, "dave-db", "100.64.0.5", "fd7a:115c:a1e0::5", moreUsers[3], nil, nil)
		daveExit := nodeR(6, "dave-exit", "100.64.0.6", "fd7a:115c:a1e0::6", moreUsers[3], nil, nil)
		eveLaptop := nodeR(7, "eve-laptop", "100.64.0.7", "fd7a:115c:a1e0::7", moreUsers[4], nil, nil)
		eveMonitor := nodeR(8, "eve-monitor", "100.64.0.8", "fd7a:115c:a1e0::8", moreUsers[4], nil, nil)
		frankLaptop := nodeR(9, "frank-laptop", "100.64.0.9", "fd7a:115c:a1e0::9", moreUsers[5], nil, nil)

		initialNodes := types.Nodes{aliceLaptop, bobLaptop, carolLaptop, daveSrv, daveDb, daveExit, eveLaptop, eveMonitor, frankLaptop}
		pm, err := NewPolicyManager([]byte(complexPol), moreUsers, initialNodes.ViewSlice())
		require.NoError(t, err)

		// Now tag dave's nodes and eve's monitor
		daveSrvTagged := nodeR(4, "dave-srv", "100.64.0.4", "fd7a:115c:a1e0::4", moreUsers[3], []string{"tag:server"}, nil)
		daveDbTagged := nodeR(5, "dave-db", "100.64.0.5", "fd7a:115c:a1e0::5", moreUsers[3], []string{"tag:database"}, nil)
		daveExitTagged := nodeR(6, "dave-exit", "100.64.0.6", "fd7a:115c:a1e0::6", moreUsers[3], []string{"tag:exit-node"}, nil)
		eveMonitorTagged := nodeR(8, "eve-monitor", "100.64.0.8", "fd7a:115c:a1e0::8", moreUsers[4], []string{"tag:monitoring"}, nil)

		taggedNodes := types.Nodes{aliceLaptop, bobLaptop, carolLaptop, daveSrvTagged, daveDbTagged, daveExitTagged, eveLaptop, eveMonitorTagged, frankLaptop}

		changed, identityChanged, _, err := pm.SetNodes(taggedNodes.ViewSlice())
		require.NoError(t, err)
		require.True(t, changed)
		require.True(t, identityChanged)

		peerMap := pm.BuildPeerMap(taggedNodes.ViewSlice())

		// alice (eng) should see: bob, carol (eng->eng), dave-srv (eng->tag:server),
		// dave-exit (member->exit-node)
		alicePeers := peerIDs(peerMap[aliceLaptop.ID])
		assert.Contains(t, alicePeers, bobLaptop.ID, "alice sees bob (eng->eng)")
		assert.Contains(t, alicePeers, carolLaptop.ID, "alice sees carol (eng->eng)")
		assert.Contains(t, alicePeers, daveSrvTagged.ID, "alice sees dave-srv (eng->tag:server)")
		assert.Contains(t, alicePeers, daveExitTagged.ID, "alice sees dave-exit (member->exit-node)")
		assert.NotContains(t, alicePeers, daveDbTagged.ID, "alice does NOT see dave-db (no eng->tag:database)")
		assert.NotContains(t, alicePeers, frankLaptop.ID, "alice does NOT see frank (no eng->mgmt)")
		assert.NotContains(t, alicePeers, eveLaptop.ID, "alice does NOT see eve (no eng->security)")

		// carol (eng+ops) should see: alice, bob (eng->eng), dave-srv (both eng->server and ops->server),
		// dave-db (ops->database), eve-monitor (ops->monitoring), dave-exit (member->exit-node)
		carolPeers := peerIDs(peerMap[carolLaptop.ID])
		assert.Contains(t, carolPeers, aliceLaptop.ID, "carol sees alice (eng->eng)")
		assert.Contains(t, carolPeers, daveSrvTagged.ID, "carol sees dave-srv (eng+ops->tag:server)")
		assert.Contains(t, carolPeers, daveDbTagged.ID, "carol sees dave-db (ops->tag:database)")
		assert.Contains(t, carolPeers, eveMonitorTagged.ID, "carol sees eve-monitor (ops->tag:monitoring)")
		assert.Contains(t, carolPeers, daveExitTagged.ID, "carol sees dave-exit (member->exit-node)")
		assert.NotContains(t, carolPeers, frankLaptop.ID, "carol does NOT see frank")

		// frank (mgmt) should see: dave-exit (member->exit-node), nobody else
		frankPeers := peerIDs(peerMap[frankLaptop.ID])
		assert.Equal(t, []types.NodeID{daveExitTagged.ID}, frankPeers,
			"frank should only see dave-exit (member->exit-node)")

		// eve (security) should see: eve-monitor (security->tag:monitoring),
		// dave-exit (member->exit-node)
		evePeers := peerIDs(peerMap[eveLaptop.ID])
		assert.Contains(t, evePeers, eveMonitorTagged.ID, "eve sees eve-monitor (security->tag:monitoring)")
		assert.Contains(t, evePeers, daveExitTagged.ID, "eve sees dave-exit (member->exit-node)")
		assert.NotContains(t, evePeers, aliceLaptop.ID, "eve does NOT see alice")
		assert.NotContains(t, evePeers, frankLaptop.ID, "eve does NOT see frank")

		// dave-exit (tag:exit-node) should see ALL members (reverse of member->exit-node)
		exitPeers := peerIDs(peerMap[daveExitTagged.ID])
		assert.Contains(t, exitPeers, aliceLaptop.ID, "exit sees alice (member->exit reverse)")
		assert.Contains(t, exitPeers, bobLaptop.ID, "exit sees bob (member->exit reverse)")
		assert.Contains(t, exitPeers, carolLaptop.ID, "exit sees carol (member->exit reverse)")
		assert.Contains(t, exitPeers, eveLaptop.ID, "exit sees eve (member->exit reverse)")
		assert.Contains(t, exitPeers, frankLaptop.ID, "exit sees frank (member->exit reverse)")
		assert.NotContains(t, exitPeers, daveSrvTagged.ID, "exit does NOT see dave-srv (no exit->server)")
		assert.NotContains(t, exitPeers, daveDbTagged.ID, "exit does NOT see dave-db (no exit->db)")

		// dave-srv (tag:server) should see: databases (server->database),
		// eng members (reverse of eng->server), ops members (reverse of ops->server),
		// monitoring (reverse of monitoring->server:9100)
		srvPeers := peerIDs(peerMap[daveSrvTagged.ID])
		assert.Contains(t, srvPeers, daveDbTagged.ID, "server sees dave-db (server->database)")
		assert.Contains(t, srvPeers, aliceLaptop.ID, "server sees alice (eng->server reverse)")
		assert.Contains(t, srvPeers, bobLaptop.ID, "server sees bob (eng->server reverse)")
		assert.Contains(t, srvPeers, carolLaptop.ID, "server sees carol (eng+ops->server reverse)")
		assert.Contains(t, srvPeers, eveMonitorTagged.ID, "server sees eve-monitor (monitoring->server reverse)")
		assert.NotContains(t, srvPeers, frankLaptop.ID, "server does NOT see frank (no mgmt->server)")
		assert.NotContains(t, srvPeers, eveLaptop.ID, "server does NOT see eve-laptop (security->monitoring, not server)")
		assert.NotContains(t, srvPeers, daveExitTagged.ID, "server does NOT see exit node (no rule)")
	})

	t.Run("node-count-change-is-not-identity-change", func(t *testing.T) {
		// Adding a new node should report changed=true but identityChanged=false
		aliceLaptop := nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil)

		initialNodes := types.Nodes{aliceLaptop}
		pm, err := NewPolicyManager([]byte(pol), users, initialNodes.ViewSlice())
		require.NoError(t, err)

		// Add a new node
		daveSrv := nodeR(2, "dave-srv", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil)
		updatedNodes := types.Nodes{aliceLaptop, daveSrv}

		changed, identityChanged, _, err := pm.SetNodes(updatedNodes.ViewSlice())
		require.NoError(t, err)
		require.True(t, changed, "SetNodes should detect new node")
		require.False(t, identityChanged, "adding a node is NOT an identity change")
	})
}

// TestConnectionTestScenario mirrors the exact live connection test:
// 9 users, 15 nodes, 13 ACL rules, complex group/tag interactions.
// Validates that BuildPeerMap correctly isolates peers.
func TestConnectionTestScenario(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob@example.com"},
		{Model: gorm.Model{ID: 3}, Name: "carol@example.com"},
		{Model: gorm.Model{ID: 4}, Name: "dave@example.com"},
		{Model: gorm.Model{ID: 5}, Name: "eve@example.com"},
		{Model: gorm.Model{ID: 6}, Name: "frank@example.com"},
		{Model: gorm.Model{ID: 7}, Name: "grace@example.com"},
		{Model: gorm.Model{ID: 8}, Name: "ivan@example.com"},
		{Model: gorm.Model{ID: 9}, Name: "judy@example.com"},
	}

	pol := `{
		"groups": {
			"group:engineering": ["alice@example.com", "bob@example.com", "carol@example.com"],
			"group:ops":         ["carol@example.com", "dave@example.com", "judy@example.com"],
			"group:security":    ["eve@example.com"],
			"group:management":  ["frank@example.com"],
			"group:contractors": ["grace@example.com"],
			"group:interns":     ["ivan@example.com"]
		},
		"tagOwners": {
			"tag:server":     ["group:ops"],
			"tag:database":   ["group:ops"],
			"tag:monitoring": ["group:ops", "group:security"],
			"tag:exit-node":  ["group:ops"],
			"tag:ci":         ["group:engineering"]
		},
		"acls": [
			{"action": "accept", "src": ["judy@example.com"],  "dst": ["*:*"]},
			{"action": "accept", "src": ["group:engineering"],  "dst": ["tag:server:22,80,443"]},
			{"action": "accept", "src": ["group:engineering"],  "dst": ["tag:ci:*"]},
			{"action": "accept", "src": ["group:engineering"],  "dst": ["group:engineering:*"]},
			{"action": "accept", "src": ["group:ops"],          "dst": ["tag:server:*", "tag:database:*", "tag:monitoring:*"]},
			{"action": "accept", "src": ["group:security"],     "dst": ["tag:monitoring:443,9090"]},
			{"action": "accept", "src": ["group:management"],   "dst": ["group:management:*"]},
			{"action": "accept", "src": ["group:contractors"],  "dst": ["tag:server:443"]},
			{"action": "accept", "src": ["group:interns"],      "dst": ["tag:ci:22,80"]},
			{"action": "accept", "src": ["autogroup:member"],   "dst": ["tag:exit-node:*"]},
			{"action": "accept", "src": ["tag:server"],         "dst": ["tag:database:5432,3306"]},
			{"action": "accept", "src": ["tag:ci"],             "dst": ["tag:server:22,443"]},
			{"action": "accept", "src": ["tag:monitoring"],     "dst": ["tag:server:9100", "tag:database:9100"]}
		]
	}`

	aliceLaptop := nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil)
	bobLaptop := nodeR(2, "bob-laptop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil)
	carolLaptop := nodeR(3, "carol-laptop", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil)
	aliceServer := nodeR(4, "alice-server", "100.64.0.4", "fd7a:115c:a1e0::4", users[0], []string{"tag:server"}, nil)
	carolDb := nodeR(5, "carol-db", "100.64.0.5", "fd7a:115c:a1e0::5", users[2], []string{"tag:database"}, nil)
	eveMonitor := nodeR(6, "eve-monitor", "100.64.0.6", "fd7a:115c:a1e0::6", users[4], []string{"tag:monitoring"}, nil)
	aliceCi := nodeR(7, "alice-ci", "100.64.0.7", "fd7a:115c:a1e0::7", users[0], []string{"tag:ci"}, nil)
	daveExit := nodeR(8, "dave-exit", "100.64.0.8", "fd7a:115c:a1e0::8", users[3], []string{"tag:exit-node"}, nil)
	daveLaptop := nodeR(9, "dave-laptop", "100.64.0.9", "fd7a:115c:a1e0::9", users[3], nil, nil)
	eveLaptop := nodeR(10, "eve-laptop", "100.64.0.10", "fd7a:115c:a1e0::a", users[4], nil, nil)
	frankLaptop := nodeR(11, "frank-laptop", "100.64.0.11", "fd7a:115c:a1e0::b", users[5], nil, nil)
	graceLaptop := nodeR(12, "grace-laptop", "100.64.0.12", "fd7a:115c:a1e0::c", users[6], nil, nil)
	ivanLaptop := nodeR(13, "ivan-laptop", "100.64.0.13", "fd7a:115c:a1e0::d", users[7], nil, nil)
	judyLaptop := nodeR(14, "judy-laptop", "100.64.0.14", "fd7a:115c:a1e0::e", users[8], nil, nil)
	judyServer := nodeR(15, "judy-server", "100.64.0.15", "fd7a:115c:a1e0::f", users[8], []string{"tag:server"}, nil)

	nodes := types.Nodes{
		aliceLaptop, bobLaptop, carolLaptop, aliceServer, carolDb,
		eveMonitor, aliceCi, daveExit, daveLaptop, eveLaptop,
		frankLaptop, graceLaptop, ivanLaptop, judyLaptop, judyServer,
	}

	pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
	require.NoError(t, err)

	reachPeerMap := pm.BuildPeerMap(nodes.ViewSlice())

	// === alice-laptop peers ===
	alicePeers := peerIDs(reachPeerMap[aliceLaptop.ID])
	t.Logf("alice-laptop peers: %v", alicePeers)
	assert.Contains(t, alicePeers, bobLaptop.ID, "alice sees bob (eng<->eng)")
	assert.Contains(t, alicePeers, carolLaptop.ID, "alice sees carol-laptop (eng<->eng)")
	assert.Contains(t, alicePeers, aliceServer.ID, "alice sees alice-server (eng->server)")
	assert.Contains(t, alicePeers, judyServer.ID, "alice sees judy-server (eng->server)")
	assert.Contains(t, alicePeers, aliceCi.ID, "alice sees alice-ci (eng->ci)")
	assert.Contains(t, alicePeers, daveExit.ID, "alice sees dave-exit (member->exit-node)")
	assert.Contains(t, alicePeers, judyLaptop.ID, "alice sees judy (judy->* reverse)")
	assert.NotContains(t, alicePeers, carolDb.ID, "alice does NOT see carol-db (no eng->database)")
	assert.NotContains(t, alicePeers, eveMonitor.ID, "alice does NOT see eve-monitor (no eng->monitoring)")
	assert.NotContains(t, alicePeers, frankLaptop.ID, "alice does NOT see frank (no eng->mgmt)")
	assert.NotContains(t, alicePeers, graceLaptop.ID, "alice does NOT see grace (no eng->contractor)")
	assert.NotContains(t, alicePeers, ivanLaptop.ID, "alice does NOT see ivan (no eng->intern)")
	assert.NotContains(t, alicePeers, daveLaptop.ID, "alice does NOT see dave-laptop (ops, no eng->ops)")
	assert.NotContains(t, alicePeers, eveLaptop.ID, "alice does NOT see eve-laptop (security, no eng->security)")

	// === dave-exit peers ===
	exitPeers := peerIDs(reachPeerMap[daveExit.ID])
	t.Logf("dave-exit peers: %v", exitPeers)
	// exit node visible to ALL members (reverse of autogroup:member->tag:exit-node)
	assert.Contains(t, exitPeers, aliceLaptop.ID, "exit sees alice (member->exit reverse)")
	assert.Contains(t, exitPeers, bobLaptop.ID, "exit sees bob (member->exit reverse)")
	assert.Contains(t, exitPeers, carolLaptop.ID, "exit sees carol-laptop (member->exit reverse)")
	assert.Contains(t, exitPeers, daveLaptop.ID, "exit sees dave-laptop (member->exit reverse)")
	assert.Contains(t, exitPeers, eveLaptop.ID, "exit sees eve-laptop (member->exit reverse)")
	assert.Contains(t, exitPeers, frankLaptop.ID, "exit sees frank (member->exit reverse)")
	assert.Contains(t, exitPeers, graceLaptop.ID, "exit sees grace (member->exit reverse)")
	assert.Contains(t, exitPeers, ivanLaptop.ID, "exit sees ivan (member->exit reverse)")
	assert.Contains(t, exitPeers, judyLaptop.ID, "exit sees judy (member->exit or judy->*)")
	assert.NotContains(t, exitPeers, carolDb.ID, "exit does NOT see carol-db (no exit->database)")
	assert.NotContains(t, exitPeers, aliceServer.ID, "exit does NOT see alice-server (no exit->server)")
	assert.NotContains(t, exitPeers, eveMonitor.ID, "exit does NOT see eve-monitor (no exit->monitoring)")
	assert.NotContains(t, exitPeers, aliceCi.ID, "exit does NOT see alice-ci (no exit->ci)")
	assert.NotContains(t, exitPeers, judyServer.ID, "exit does NOT see judy-server (no exit->server)")

	// === carol-laptop peers (in both eng AND ops) ===
	carolPeers := peerIDs(reachPeerMap[carolLaptop.ID])
	t.Logf("carol-laptop peers: %v", carolPeers)
	assert.Contains(t, carolPeers, aliceLaptop.ID, "carol sees alice (eng<->eng)")
	assert.Contains(t, carolPeers, bobLaptop.ID, "carol sees bob (eng<->eng)")
	assert.Contains(t, carolPeers, carolDb.ID, "carol sees carol-db (ops->database)")
	assert.Contains(t, carolPeers, eveMonitor.ID, "carol sees eve-monitor (ops->monitoring)")
	assert.Contains(t, carolPeers, aliceServer.ID, "carol sees alice-server (eng->server or ops->server)")
	assert.Contains(t, carolPeers, judyServer.ID, "carol sees judy-server (eng->server or ops->server)")
	assert.Contains(t, carolPeers, aliceCi.ID, "carol sees alice-ci (eng->ci)")
	assert.Contains(t, carolPeers, daveExit.ID, "carol sees dave-exit (member->exit-node)")
	// Note: no ops<->ops rule in this policy, so carol doesn't see dave-laptop
	assert.NotContains(t, carolPeers, daveLaptop.ID, "carol does NOT see dave-laptop (no ops<->ops rule)")
	assert.Contains(t, carolPeers, judyLaptop.ID, "carol sees judy (judy->* reverse)")

	// === frank-laptop peers (management only) ===
	frankPeers := peerIDs(reachPeerMap[frankLaptop.ID])
	t.Logf("frank-laptop peers: %v", frankPeers)
	assert.Contains(t, frankPeers, daveExit.ID, "frank sees dave-exit (member->exit-node)")
	assert.Contains(t, frankPeers, judyLaptop.ID, "frank sees judy (judy->* reverse)")
	assert.NotContains(t, frankPeers, aliceLaptop.ID, "frank does NOT see alice (no mgmt->eng)")
	assert.NotContains(t, frankPeers, aliceServer.ID, "frank does NOT see alice-server (no mgmt->server)")
	assert.NotContains(t, frankPeers, carolDb.ID, "frank does NOT see carol-db (no mgmt->db)")

	// === grace-laptop peers (contractor) ===
	gracePeers := peerIDs(reachPeerMap[graceLaptop.ID])
	t.Logf("grace-laptop peers: %v", gracePeers)
	assert.Contains(t, gracePeers, aliceServer.ID, "grace sees alice-server (contractor->server)")
	assert.Contains(t, gracePeers, judyServer.ID, "grace sees judy-server (contractor->server)")
	assert.Contains(t, gracePeers, daveExit.ID, "grace sees dave-exit (member->exit-node)")
	assert.Contains(t, gracePeers, judyLaptop.ID, "grace sees judy (judy->* reverse)")
	assert.NotContains(t, gracePeers, carolDb.ID, "grace does NOT see carol-db (no contractor->db)")
	assert.NotContains(t, gracePeers, aliceLaptop.ID, "grace does NOT see alice (no contractor->eng)")

	// === Cross-check: ComputeNodePeers matches BuildPeerMap ===
	assertComputeMatchesBuildPeerMap(t, pm, nodes)
}

// TestPeerMapDynamicJoinLeave verifies that the peer map remains correct
// as nodes join, leave, and both happen simultaneously. This exercises
// SetNodes + BuildPeerMap through realistic lifecycle transitions.
func TestPeerMapDynamicJoinLeave(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
		{Model: gorm.Model{ID: 3}, Name: "charlie", Email: "charlie@example.com"},
		{Model: gorm.Model{ID: 4}, Name: "dave", Email: "dave@example.com"},
	}

	pol := `{
		"groups": {
			"group:eng": ["alice@", "bob@"],
			"group:ops": ["charlie@", "dave@"]
		},
		"tagOwners": {
			"tag:server": ["group:ops"],
			"tag:db": ["group:ops"]
		},
		"acls": [
			{"action": "accept", "src": ["group:eng"], "dst": ["group:eng:*"]},
			{"action": "accept", "src": ["group:eng"], "dst": ["tag:server:*"]},
			{"action": "accept", "src": ["group:ops"], "dst": ["tag:server:*", "tag:db:*"]},
			{"action": "accept", "src": ["tag:server"], "dst": ["tag:db:5432"]},
			{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}
		]
	}`

	t.Run("incremental-node-join", func(t *testing.T) {
		// Start with alice alone
		alice := nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil)
		nodes := types.Nodes{alice}

		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		peerMap := pm.BuildPeerMap(nodes.ViewSlice())
		assert.Empty(t, peerMap[alice.ID], "alice alone should have no peers")

		// Bob joins — alice and bob are both eng, should see each other
		bob := nodeR(2, "bob-laptop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil)
		nodes = types.Nodes{alice, bob}
		changed, _, _, err := pm.SetNodes(nodes.ViewSlice())
		require.NoError(t, err)
		require.True(t, changed)

		peerMap = pm.BuildPeerMap(nodes.ViewSlice())
		assert.Equal(t, []types.NodeID{bob.ID}, peerIDs(peerMap[alice.ID]),
			"alice should see bob after bob joins (eng<->eng)")
		assert.Equal(t, []types.NodeID{alice.ID}, peerIDs(peerMap[bob.ID]),
			"bob should see alice after joining (eng<->eng)")
		assertComputeMatchesBuildPeerMap(t, pm, nodes)

		// A server joins — eng members should see it
		srv := nodeR(3, "srv1", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], []string{"tag:server"}, nil)
		nodes = types.Nodes{alice, bob, srv}
		changed, _, _, err = pm.SetNodes(nodes.ViewSlice())
		require.NoError(t, err)
		require.True(t, changed)

		peerMap = pm.BuildPeerMap(nodes.ViewSlice())
		alicePeers := peerIDs(peerMap[alice.ID])
		assert.Contains(t, alicePeers, bob.ID, "alice sees bob (eng<->eng)")
		assert.Contains(t, alicePeers, srv.ID, "alice sees srv (eng->server)")
		srvPeers := peerIDs(peerMap[srv.ID])
		assert.Contains(t, srvPeers, alice.ID, "srv sees alice (eng->server reverse)")
		assert.Contains(t, srvPeers, bob.ID, "srv sees bob (eng->server reverse)")
		assertComputeMatchesBuildPeerMap(t, pm, nodes)

		// A DB joins — srv should see it, eng should NOT
		db := nodeR(4, "db1", "100.64.0.4", "fd7a:115c:a1e0::4", users[3], []string{"tag:db"}, nil)
		nodes = types.Nodes{alice, bob, srv, db}
		changed, _, _, err = pm.SetNodes(nodes.ViewSlice())
		require.NoError(t, err)
		require.True(t, changed)

		peerMap = pm.BuildPeerMap(nodes.ViewSlice())
		assert.NotContains(t, peerIDs(peerMap[alice.ID]), db.ID,
			"alice should NOT see db (no eng->db rule)")
		assert.Contains(t, peerIDs(peerMap[srv.ID]), db.ID,
			"srv should see db (server->db)")
		assert.Contains(t, peerIDs(peerMap[db.ID]), srv.ID,
			"db should see srv (server->db reverse)")
		assertComputeMatchesBuildPeerMap(t, pm, nodes)
	})

	t.Run("node-leaves", func(t *testing.T) {
		alice := nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil)
		bob := nodeR(2, "bob-laptop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil)
		srv := nodeR(3, "srv1", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], []string{"tag:server"}, nil)
		db := nodeR(4, "db1", "100.64.0.4", "fd7a:115c:a1e0::4", users[3], []string{"tag:db"}, nil)

		nodes := types.Nodes{alice, bob, srv, db}
		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		peerMap := pm.BuildPeerMap(nodes.ViewSlice())
		assert.Contains(t, peerIDs(peerMap[alice.ID]), srv.ID, "alice sees srv initially")
		assert.Contains(t, peerIDs(peerMap[srv.ID]), db.ID, "srv sees db initially")

		// Server leaves — alice should no longer see it, db loses its peer
		nodes = types.Nodes{alice, bob, db}
		changed, _, _, err := pm.SetNodes(nodes.ViewSlice())
		require.NoError(t, err)
		require.True(t, changed)

		peerMap = pm.BuildPeerMap(nodes.ViewSlice())
		assert.NotContains(t, peerIDs(peerMap[alice.ID]), srv.ID,
			"alice should NOT see srv after it left")
		assert.Equal(t, []types.NodeID{bob.ID}, peerIDs(peerMap[alice.ID]),
			"alice should only see bob after srv left")
		assert.Empty(t, peerMap[db.ID],
			"db should have no peers after srv left (no ops members)")
		assertComputeMatchesBuildPeerMap(t, pm, nodes)

		// Bob also leaves — alice is alone
		nodes = types.Nodes{alice, db}
		changed, _, _, err = pm.SetNodes(nodes.ViewSlice())
		require.NoError(t, err)
		require.True(t, changed)

		peerMap = pm.BuildPeerMap(nodes.ViewSlice())
		assert.Empty(t, peerMap[alice.ID], "alice alone should have no peers")
		assert.Empty(t, peerMap[db.ID], "db alone should have no peers")
		assertComputeMatchesBuildPeerMap(t, pm, nodes)
	})

	t.Run("simultaneous-join-and-leave", func(t *testing.T) {
		// Test with different counts to exercise the real SetNodes path.
		// Start with 4 nodes, remove bob + add db = still 4, so also test via
		// fresh PolicyManager to verify correctness of the peer map.
		alice := nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil)
		bob := nodeR(2, "bob-laptop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil)
		srv := nodeR(3, "srv1", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], []string{"tag:server"}, nil)

		nodes := types.Nodes{alice, bob, srv}
		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		peerMap := pm.BuildPeerMap(nodes.ViewSlice())
		assert.Contains(t, peerIDs(peerMap[alice.ID]), bob.ID)
		assert.Contains(t, peerIDs(peerMap[alice.ID]), srv.ID)

		// Bob leaves (3→2), then DB joins (2→3) — two separate SetNodes calls
		nodes = types.Nodes{alice, srv}
		changed, _, _, err := pm.SetNodes(nodes.ViewSlice())
		require.NoError(t, err)
		require.True(t, changed)

		db := nodeR(4, "db1", "100.64.0.4", "fd7a:115c:a1e0::4", users[3], []string{"tag:db"}, nil)
		nodes = types.Nodes{alice, srv, db}
		changed, _, _, err = pm.SetNodes(nodes.ViewSlice())
		require.NoError(t, err)
		require.True(t, changed)

		peerMap = pm.BuildPeerMap(nodes.ViewSlice())
		alicePeers := peerIDs(peerMap[alice.ID])
		assert.Contains(t, alicePeers, srv.ID, "alice still sees srv (eng->server)")
		assert.NotContains(t, alicePeers, bob.ID, "alice no longer sees bob (left)")
		assert.NotContains(t, alicePeers, db.ID, "alice does NOT see db (no eng->db)")
		assert.Contains(t, peerIDs(peerMap[srv.ID]), db.ID, "srv sees db (server->db)")
		assert.Contains(t, peerIDs(peerMap[srv.ID]), alice.ID, "srv still sees alice")
		assertComputeMatchesBuildPeerMap(t, pm, nodes)
	})

	t.Run("all-nodes-replaced", func(t *testing.T) {
		alice := nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil)
		bob := nodeR(2, "bob-laptop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil)

		nodes := types.Nodes{alice, bob}
		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		peerMap := pm.BuildPeerMap(nodes.ViewSlice())
		assert.Len(t, peerMap[alice.ID], 1, "alice sees bob initially")

		// Complete replacement: all old nodes gone, all new nodes arrive (same count: 2→2)
		// Note: same-count swap — SetNodes may not detect the change via count alone.
		charlie := nodeR(3, "charlie-laptop", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil)
		dave := nodeR(4, "dave-laptop", "100.64.0.4", "fd7a:115c:a1e0::4", users[3], nil, nil)
		nodes = types.Nodes{charlie, dave}
		_, _, _, err = pm.SetNodes(nodes.ViewSlice())
		require.NoError(t, err)

		peerMap = pm.BuildPeerMap(nodes.ViewSlice())
		// charlie and dave are ops, but no ops<->ops rule in this policy
		assert.Empty(t, peerMap[charlie.ID], "charlie sees nobody (no ops<->ops rule)")
		assert.Empty(t, peerMap[dave.ID], "dave sees nobody (no ops<->ops rule)")
		// Old nodes are completely gone
		assert.Empty(t, peerMap[alice.ID], "alice no longer in map")
		assert.Empty(t, peerMap[bob.ID], "bob no longer in map")
		assertComputeMatchesBuildPeerMap(t, pm, nodes)
	})

	t.Run("self-peers-with-join-leave", func(t *testing.T) {
		// autogroup:self should correctly track as devices come and go
		alice1 := nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil)

		nodes := types.Nodes{alice1}
		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		peerMap := pm.BuildPeerMap(nodes.ViewSlice())
		assert.Empty(t, peerMap[alice1.ID], "alice alone has no self-peers")

		// Alice's second device joins
		alice2 := nodeR(2, "alice-phone", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], nil, nil)
		nodes = types.Nodes{alice1, alice2}
		_, _, _, err = pm.SetNodes(nodes.ViewSlice())
		require.NoError(t, err)

		peerMap = pm.BuildPeerMap(nodes.ViewSlice())
		assert.Equal(t, []types.NodeID{alice2.ID}, peerIDs(peerMap[alice1.ID]),
			"alice-laptop sees alice-phone (self)")
		assert.Equal(t, []types.NodeID{alice1.ID}, peerIDs(peerMap[alice2.ID]),
			"alice-phone sees alice-laptop (self)")
		assertComputeMatchesBuildPeerMap(t, pm, nodes)

		// Alice's third device joins
		alice3 := nodeR(3, "alice-tablet", "100.64.0.3", "fd7a:115c:a1e0::3", users[0], nil, nil)
		nodes = types.Nodes{alice1, alice2, alice3}
		_, _, _, err = pm.SetNodes(nodes.ViewSlice())
		require.NoError(t, err)

		peerMap = pm.BuildPeerMap(nodes.ViewSlice())
		a1Peers := peerIDs(peerMap[alice1.ID])
		assert.Len(t, a1Peers, 2, "alice-laptop sees 2 self peers")
		assert.Contains(t, a1Peers, alice2.ID)
		assert.Contains(t, a1Peers, alice3.ID)
		assertComputeMatchesBuildPeerMap(t, pm, nodes)

		// Alice's phone leaves
		nodes = types.Nodes{alice1, alice3}
		_, _, _, err = pm.SetNodes(nodes.ViewSlice())
		require.NoError(t, err)

		peerMap = pm.BuildPeerMap(nodes.ViewSlice())
		assert.Equal(t, []types.NodeID{alice3.ID}, peerIDs(peerMap[alice1.ID]),
			"alice-laptop sees only alice-tablet after phone left")
		assert.Equal(t, []types.NodeID{alice1.ID}, peerIDs(peerMap[alice3.ID]),
			"alice-tablet sees only alice-laptop after phone left")
		assertComputeMatchesBuildPeerMap(t, pm, nodes)
	})

	t.Run("tag-change-during-churn", func(t *testing.T) {
		alice := nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil)
		bob := nodeR(2, "bob-laptop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil)
		charlieSrv := nodeR(3, "charlie-srv", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil)

		nodes := types.Nodes{alice, bob, charlieSrv}
		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		// charlie-srv is untagged member — eng members don't see ops members via self
		peerMap := pm.BuildPeerMap(nodes.ViewSlice())
		assert.NotContains(t, peerIDs(peerMap[alice.ID]), charlieSrv.ID,
			"alice should NOT see charlie-srv initially (no eng->ops)")

		// charlie-srv gets tagged AND dave joins simultaneously
		charlieSrvTagged := nodeR(3, "charlie-srv", "100.64.0.3", "fd7a:115c:a1e0::3",
			users[2], []string{"tag:server"}, nil)
		dave := nodeR(4, "dave-laptop", "100.64.0.4", "fd7a:115c:a1e0::4", users[3], nil, nil)
		nodes = types.Nodes{alice, bob, charlieSrvTagged, dave}
		changed, identityChanged, _, err := pm.SetNodes(nodes.ViewSlice())
		require.NoError(t, err)
		require.True(t, changed)
		require.True(t, identityChanged) // tag change

		peerMap = pm.BuildPeerMap(nodes.ViewSlice())
		assert.Contains(t, peerIDs(peerMap[alice.ID]), charlieSrvTagged.ID,
			"alice NOW sees charlie-srv (eng->tag:server)")
		assert.Contains(t, peerIDs(peerMap[bob.ID]), charlieSrvTagged.ID,
			"bob NOW sees charlie-srv (eng->tag:server)")
		assert.NotContains(t, peerIDs(peerMap[alice.ID]), dave.ID,
			"alice does NOT see dave (no eng->ops)")
		assertComputeMatchesBuildPeerMap(t, pm, nodes)
	})

	t.Run("rapid-churn-consistency", func(t *testing.T) {
		// Simulate rapid registration: nodes 1-10 join one at a time
		pm, err := NewPolicyManager([]byte(pol), users, types.Nodes{}.ViewSlice())
		require.NoError(t, err)

		var nodes types.Nodes
		for i := 1; i <= 10; i++ {
			userIdx := (i - 1) % len(users)
			n := nodeR(i,
				fmt.Sprintf("node-%d", i),
				fmt.Sprintf("100.64.0.%d", i),
				fmt.Sprintf("fd7a:115c:a1e0::%d", i),
				users[userIdx], nil, nil,
			)
			nodes = append(nodes, n)
			_, _, _, err := pm.SetNodes(nodes.ViewSlice())
			require.NoError(t, err)

			// Verify consistency after each join
			assertComputeMatchesBuildPeerMap(t, pm, nodes)
		}

		// Now remove nodes 2,4,6,8 (every other node)
		var remaining types.Nodes
		for _, n := range nodes {
			if n.ID%2 != 0 {
				remaining = append(remaining, n)
			}
		}
		_, _, _, err = pm.SetNodes(remaining.ViewSlice())
		require.NoError(t, err)
		assertComputeMatchesBuildPeerMap(t, pm, remaining)

		// Verify peer symmetry
		peerMap := pm.BuildPeerMap(remaining.ViewSlice())
		for nodeID, peers := range peerMap {
			for _, peer := range peers {
				peerPeers := peerMap[peer.ID()]
				found := false
				for _, pp := range peerPeers {
					if pp.ID() == nodeID {
						found = true
						break
					}
				}
				assert.True(t, found,
					"asymmetry after churn: node %d sees %d, but %d doesn't see %d",
					nodeID, peer.ID(), peer.ID(), nodeID)
			}
		}
	})
}
