package v2

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

func TestCompileNodeAttrs(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: "alice@headscale.net"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@headscale.net"},
	}

	nodes := types.Nodes{
		{
			ID:       1,
			Hostname: "node1",
			IPv4:     ap("100.64.0.1"),
			IPv6:     ap("fd7a:115c:a1e0::1"),
			User:     &users[0],
			UserID:   &users[0].ID,
		},
		{
			ID:       2,
			Hostname: "node2",
			IPv4:     ap("100.64.0.2"),
			IPv6:     ap("fd7a:115c:a1e0::2"),
			User:     &users[1],
			UserID:   &users[1].ID,
		},
		{
			ID:       3,
			Hostname: "node3",
			IPv4:     ap("100.64.0.3"),
			IPv6:     ap("fd7a:115c:a1e0::3"),
			User:     &users[0],
			UserID:   &users[0].ID,
			Tags:     []string{"tag:server"},
		},
	}

	tests := []struct {
		name       string
		pol        string
		wantCapMap map[uint]tailcfg.NodeCapMap
	}{
		{
			name:       "no-nodeAttrs",
			pol:        `{}`,
			wantCapMap: nil,
		},
		{
			name: "nodeAttrs-by-user",
			pol: `{
				"nodeAttrs": [
					{
						"target": ["alice@headscale.net"],
						"attr":   ["funnel", "https-routing"]
					}
				]
			}`,
			wantCapMap: map[uint]tailcfg.NodeCapMap{
				1: {
					tailcfg.NodeCapability("funnel"):        {},
					tailcfg.NodeCapability("https-routing"): {},
				},
				// node 3 is tagged (tag:server), so it is owned by TaggedDevices,
				// not alice, and does not match user-based targets.
			},
		},
		{
			name: "nodeAttrs-by-tag",
			pol: `{
				"nodeAttrs": [
					{
						"target": ["tag:server"],
						"attr":   ["funnel"]
					}
				]
			}`,
			wantCapMap: map[uint]tailcfg.NodeCapMap{
				3: {
					tailcfg.NodeCapability("funnel"): {},
				},
			},
		},
		{
			name: "nodeAttrs-by-ip",
			pol: `{
				"nodeAttrs": [
					{
						"target": ["100.64.0.1"],
						"attr":   ["custom-cap"]
					}
				]
			}`,
			wantCapMap: map[uint]tailcfg.NodeCapMap{
				1: {
					tailcfg.NodeCapability("custom-cap"): {},
				},
			},
		},
		{
			name: "nodeAttrs-wildcard",
			pol: `{
				"nodeAttrs": [
					{
						"target": ["*"],
						"attr":   ["global-cap"]
					}
				]
			}`,
			wantCapMap: map[uint]tailcfg.NodeCapMap{
				1: {tailcfg.NodeCapability("global-cap"): {}},
				2: {tailcfg.NodeCapability("global-cap"): {}},
				3: {tailcfg.NodeCapability("global-cap"): {}},
			},
		},
		{
			name: "nodeAttrs-multiple-grants-merge",
			pol: `{
				"nodeAttrs": [
					{
						"target": ["alice@headscale.net"],
						"attr":   ["cap-a"]
					},
					{
						"target": ["tag:server"],
						"attr":   ["cap-b"]
					}
				]
			}`,
			wantCapMap: map[uint]tailcfg.NodeCapMap{
				1: {
					tailcfg.NodeCapability("cap-a"): {},
				},
				// node 3 is tagged, cap-a from alice@headscale.net does not apply.
				3: {
					tailcfg.NodeCapability("cap-b"): {},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewPolicyManager([]byte(tt.pol), users, nodes.ViewSlice())
			require.NoError(t, err)

			for _, n := range nodes {
				got := pm.NodeCapMap(n.View())
				want, ok := tt.wantCapMap[uint(n.ID)]
				if !ok {
					require.Nil(t, got, "node %d should have no CapMap", n.ID)
					continue
				}
				require.NotNil(t, got, "node %d should have CapMap", n.ID)
				require.Equal(t, want, got, "node %d CapMap mismatch", n.ID)
			}
		})
	}
}

func TestNodeCapMapIPv6(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice"},
	}

	nodes := types.Nodes{
		{
			ID:       1,
			Hostname: "node1",
			IPv4:     ap("100.64.0.1"),
			IPv6:     ap("fd7a:115c:a1e0::1"),
			User:     &users[0],
			UserID:   &users[0].ID,
		},
	}

	pol := `{
		"nodeAttrs": [
			{
				"target": ["fd7a:115c:a1e0::1"],
				"attr":   ["ipv6-cap"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
	require.NoError(t, err)

	capMap := pm.NodeCapMap(nodes[0].View())
	require.NotNil(t, capMap)
	require.Contains(t, capMap, tailcfg.NodeCapability("ipv6-cap"))
}
