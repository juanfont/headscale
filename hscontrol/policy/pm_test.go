package policy

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

func TestPolicySetChange(t *testing.T) {
	users := []types.User{
		{
			Model: gorm.Model{ID: 1},
			Name:  "testuser",
		},
	}
	tests := []struct {
		name             string
		users            []types.User
		nodes            types.Nodes
		policy           []byte
		wantUsersChange  bool
		wantNodesChange  bool
		wantPolicyChange bool
		wantFilter       []tailcfg.FilterRule
	}{
		{
			name: "set-nodes",
			nodes: types.Nodes{
				{
					IPv4: iap("100.64.0.2"),
					User: users[0],
				},
			},
			wantNodesChange: false,
			wantFilter: []tailcfg.FilterRule{
				{
					DstPorts: []tailcfg.NetPortRange{{IP: "100.64.0.1/32", Ports: tailcfg.PortRangeAny}},
				},
			},
		},
		{
			name:            "set-users",
			users:           users,
			wantUsersChange: false,
			wantFilter: []tailcfg.FilterRule{
				{
					DstPorts: []tailcfg.NetPortRange{{IP: "100.64.0.1/32", Ports: tailcfg.PortRangeAny}},
				},
			},
		},
		{
			name:  "set-users-and-node",
			users: users,
			nodes: types.Nodes{
				{
					IPv4: iap("100.64.0.2"),
					User: users[0],
				},
			},
			wantUsersChange: false,
			wantNodesChange: true,
			wantFilter: []tailcfg.FilterRule{
				{
					SrcIPs:   []string{"100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{{IP: "100.64.0.1/32", Ports: tailcfg.PortRangeAny}},
				},
			},
		},
		{
			name: "set-policy",
			policy: []byte(`
{
"acls": [
		{
			"action": "accept",
			"src": [
				"100.64.0.61",
			],
			"dst": [
				"100.64.0.62:*",
			],
		},
		],
}
				`),
			wantPolicyChange: true,
			wantFilter: []tailcfg.FilterRule{
				{
					SrcIPs:   []string{"100.64.0.61/32"},
					DstPorts: []tailcfg.NetPortRange{{IP: "100.64.0.62/32", Ports: tailcfg.PortRangeAny}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pol := `
{
	"groups": {
		"group:example": [
			"testuser",
		],
	},

	"hosts": {
		"host-1": "100.64.0.1",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"action": "accept",
			"src": [
				"group:example",
			],
			"dst": [
				"host-1:*",
			],
		},
	],
}
`
			pm, err := NewPolicyManager([]byte(pol), []types.User{}, types.Nodes{})
			require.NoError(t, err)

			if tt.policy != nil {
				change, err := pm.SetPolicy(tt.policy)
				require.NoError(t, err)

				assert.Equal(t, tt.wantPolicyChange, change)
			}

			if tt.users != nil {
				change, err := pm.SetUsers(tt.users)
				require.NoError(t, err)

				assert.Equal(t, tt.wantUsersChange, change)
			}

			if tt.nodes != nil {
				change, err := pm.SetNodes(tt.nodes)
				require.NoError(t, err)

				assert.Equal(t, tt.wantNodesChange, change)
			}

			if diff := cmp.Diff(tt.wantFilter, pm.Filter()); diff != "" {
				t.Errorf("TestPolicySetChange() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}
