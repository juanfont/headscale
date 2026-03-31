package v2

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

// TestReachabilityIPBased verifies that IP-address-based ACL rules correctly
// affect peer visibility. This covers direct IPs, CIDR ranges, hosts entries,
// and mixed IP/identity rules.
func TestReachabilityIPBased(t *testing.T) {
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
			name: "direct-ip-src-and-dst",
			pol: `{
				"acls": [{"action": "accept", "src": ["100.64.0.1/32"], "dst": ["100.64.0.2/32:*"]}]
			}`,
			nodes: types.Nodes{
				nodeR(1, "node-a", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "node-b", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "node-c", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
			},
		},
		{
			name: "cidr-range-covers-multiple-nodes",
			pol: `{
				"acls": [{"action": "accept", "src": ["100.64.0.0/24"], "dst": ["100.64.0.0/24:*"]}]
			}`,
			nodes: types.Nodes{
				nodeR(1, "node-a", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "node-b", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "node-c", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
			},
		},
		{
			name: "cidr-partial-coverage",
			pol: `{
				"acls": [{"action": "accept", "src": ["100.64.0.1/32"], "dst": ["100.64.0.2/31:*"]}]
			}`,
			// 100.64.0.2/31 covers .2 and .3 but not .4
			nodes: types.Nodes{
				nodeR(1, "src", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "in-range-a", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "in-range-b", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil, nil),
				nodeR(4, "out-of-range", "100.64.0.4", "fd7a:115c:a1e0::4", users[2], nil, nil),
			},
		},
		{
			name: "hosts-entry-single-ip",
			pol: `{
				"hosts": {"webserver": "100.64.0.2/32"},
				"acls": [{"action": "accept", "src": ["alice@"], "dst": ["webserver:443"]}]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "web", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "db", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
			},
		},
		{
			name: "hosts-entry-cidr-with-subnet-router",
			pol: `{
				"hosts": {"office-net": "10.0.0.0/24"},
				"acls": [{"action": "accept", "src": ["alice@"], "dst": ["office-net:*"]}]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "router", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}),
				nodeR(3, "bob-laptop", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil, nil),
			},
		},
		{
			name: "ipv6-direct-address",
			pol: `{
				"acls": [{"action": "accept", "src": ["fd7a:115c:a1e0::1/128"], "dst": ["fd7a:115c:a1e0::2/128:*"]}]
			}`,
			nodes: types.Nodes{
				nodeR(1, "v6-src", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "v6-dst", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "v6-other", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
			},
		},
		{
			name: "ip-src-to-tag-dst",
			pol: `{
				"tagOwners": {"tag:server": ["alice@"]},
				"acls": [{"action": "accept", "src": ["100.64.0.1/32"], "dst": ["tag:server:*"]}]
			}`,
			nodes: types.Nodes{
				nodeR(1, "client", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "server", "100.64.0.2", "fd7a:115c:a1e0::2", users[0], []string{"tag:server"}, nil),
				nodeR(3, "unrelated", "100.64.0.3", "fd7a:115c:a1e0::3", users[1], nil, nil),
			},
		},
		{
			name: "tag-src-to-ip-dst",
			pol: `{
				"tagOwners": {"tag:monitor": ["alice@"]},
				"acls": [{"action": "accept", "src": ["tag:monitor"], "dst": ["100.64.0.2/32:9090"]}]
			}`,
			nodes: types.Nodes{
				nodeR(1, "monitor", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], []string{"tag:monitor"}, nil),
				nodeR(2, "target", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "other", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
			},
		},
		{
			name: "multiple-ip-rules-different-ports",
			pol: `{
				"acls": [
					{"action": "accept", "src": ["100.64.0.1/32"], "dst": ["100.64.0.2/32:80"]},
					{"action": "accept", "src": ["100.64.0.1/32"], "dst": ["100.64.0.3/32:443"]},
					{"action": "accept", "src": ["100.64.0.2/32"], "dst": ["100.64.0.3/32:22"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "client", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "web", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "api", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
				nodeR(4, "isolated", "100.64.0.4", "fd7a:115c:a1e0::4", users[2], nil, nil),
			},
		},
		{
			name: "overlapping-cidr-and-specific-ip",
			pol: `{
				"acls": [
					{"action": "accept", "src": ["100.64.0.0/24"], "dst": ["100.64.0.3/32:*"]},
					{"action": "accept", "src": ["100.64.0.1/32"], "dst": ["100.64.0.2/32:22"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "admin", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "ssh-target", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "shared", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
			},
		},
		{
			name: "ip-rule-with-subnet-route-overlap",
			pol: `{
				"acls": [
					{"action": "accept", "src": ["100.64.0.1/32"], "dst": ["10.0.0.0/8:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "client", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "router-a", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}}),
				nodeR(3, "router-b", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil,
					&tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16")}}),
				nodeR(4, "no-route", "100.64.0.4", "fd7a:115c:a1e0::4", users[2], nil, nil),
			},
		},
		{
			name: "ip-no-match-wrong-range",
			pol: `{
				"acls": [{"action": "accept", "src": ["192.168.1.0/24"], "dst": ["192.168.2.0/24:*"]}]
			}`,
			// No nodes have IPs in 192.168.x.x, so no peers should see each other
			nodes: types.Nodes{
				nodeR(1, "a", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "b", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
			},
		},
		{
			name: "mixed-identity-and-ip-rules",
			pol: `{
				"groups": {"group:eng": ["alice@", "bob@"]},
				"tagOwners": {"tag:db": ["alice@"]},
				"acls": [
					{"action": "accept", "src": ["group:eng"], "dst": ["tag:db:5432"]},
					{"action": "accept", "src": ["100.64.0.1/32"], "dst": ["100.64.0.4/32:*"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "bob-laptop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
				nodeR(3, "database", "100.64.0.3", "fd7a:115c:a1e0::3", users[0], []string{"tag:db"}, nil),
				nodeR(4, "ip-only-target", "100.64.0.4", "fd7a:115c:a1e0::4", users[2], nil, nil),
			},
		},
		{
			name: "hosts-multiple-entries",
			pol: `{
				"hosts": {
					"web-tier":  "100.64.0.2/32",
					"api-tier":  "100.64.0.3/32",
					"db-tier":   "100.64.0.4/32"
				},
				"acls": [
					{"action": "accept", "src": ["alice@"], "dst": ["web-tier:80", "api-tier:443"]},
					{"action": "accept", "src": ["bob@"],   "dst": ["db-tier:5432"]}
				]
			}`,
			nodes: types.Nodes{
				nodeR(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
				nodeR(2, "web", "100.64.0.2", "fd7a:115c:a1e0::2", users[2], nil, nil),
				nodeR(3, "api", "100.64.0.3", "fd7a:115c:a1e0::3", users[2], nil, nil),
				nodeR(4, "db", "100.64.0.4", "fd7a:115c:a1e0::4", users[2], nil, nil),
				nodeR(5, "bob-laptop", "100.64.0.5", "fd7a:115c:a1e0::5", users[1], nil, nil),
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

			assertComputeMatchesBuildPeerMap(t, pm, tt.nodes)
		})
	}
}

// TestReachabilityIPDynamic verifies IP-based rules work correctly when
// nodes are added or removed via SetNodes.
func TestReachabilityIPDynamic(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
	}

	pol := `{
		"acls": [
			{"action": "accept", "src": ["100.64.0.0/30"], "dst": ["100.64.0.0/30:*"]},
			{"action": "accept", "src": ["100.64.0.4/32"], "dst": ["100.64.0.1/32:22"]}
		]
	}`

	// Start with 2 nodes in the /30 range (covers .0-.3)
	nodes := types.Nodes{
		nodeR(1, "node-1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0], nil, nil),
		nodeR(2, "node-2", "100.64.0.2", "fd7a:115c:a1e0::2", users[1], nil, nil),
	}

	pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
	require.NoError(t, err)
	assertComputeMatchesBuildPeerMap(t, pm, nodes)

	// Add a node inside the /30 range
	nodes = append(nodes, nodeR(3, "node-3", "100.64.0.3", "fd7a:115c:a1e0::3", users[0], nil, nil))
	_, _, _, err = pm.SetNodes(nodes.ViewSlice())
	require.NoError(t, err)
	assertComputeMatchesBuildPeerMap(t, pm, nodes)

	// Add a node OUTSIDE the /30 range but with a specific IP rule
	nodes = append(nodes, nodeR(4, "node-4", "100.64.0.4", "fd7a:115c:a1e0::4", users[1], nil, nil))
	_, _, _, err = pm.SetNodes(nodes.ViewSlice())
	require.NoError(t, err)
	assertComputeMatchesBuildPeerMap(t, pm, nodes)

	// Remove a node from the /30 range
	nodes = types.Nodes{nodes[0], nodes[2], nodes[3]} // remove node-2
	_, _, _, err = pm.SetNodes(nodes.ViewSlice())
	require.NoError(t, err)
	assertComputeMatchesBuildPeerMap(t, pm, nodes)
}
