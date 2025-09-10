package v2

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

func TestParsing(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "testuser"},
	}
	tests := []struct {
		name    string
		format  string
		acl     string
		want    []tailcfg.FilterRule
		wantErr bool
	}{
		{
			name:   "invalid-hujson",
			format: "hujson",
			acl: `
{
		`,
			want:    []tailcfg.FilterRule{},
			wantErr: true,
		},
		// The new parser will ignore all that is irrelevant
		// 		{
		// 			name:   "valid-hujson-invalid-content",
		// 			format: "hujson",
		// 			acl: `
		// {
		//   "valid_json": true,
		//   "but_a_policy_though": false
		// }
		// 				`,
		// 			want:    []tailcfg.FilterRule{},
		// 			wantErr: true,
		// 		},
		// 		{
		// 			name:   "invalid-cidr",
		// 			format: "hujson",
		// 			acl: `
		// {"example-host-1": "100.100.100.100/42"}
		// 				`,
		// 			want:    []tailcfg.FilterRule{},
		// 			wantErr: true,
		// 		},
		{
			name:   "basic-rule",
			format: "hujson",
			acl: `
{
	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"action": "accept",
			"src": [
				"subnet-1",
				"192.168.1.0/24"
			],
			"dst": [
				"*:22,3389",
				"host-1:*",
			],
		},
	],
}
		`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.100.101.0/24", "192.168.1.0/24"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "0.0.0.0/0", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						{IP: "0.0.0.0/0", Ports: tailcfg.PortRange{First: 3389, Last: 3389}},
						{IP: "::/0", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						{IP: "::/0", Ports: tailcfg.PortRange{First: 3389, Last: 3389}},
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			wantErr: false,
		},
		{
			name:   "parse-protocol",
			format: "hujson",
			acl: `
{
	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"Action": "accept",
			"src": [
				"*",
			],
			"proto": "tcp",
			"dst": [
				"host-1:*",
			],
		},
		{
			"Action": "accept",
			"src": [
				"*",
			],
			"proto": "udp",
			"dst": [
				"host-1:53",
			],
		},
		{
			"Action": "accept",
			"src": [
				"*",
			],
			"proto": "icmp",
			"dst": [
				"host-1:*",
			],
		},
	],
}`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"0.0.0.0/0", "::/0"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
					IPProto: []int{protocolTCP},
				},
				{
					SrcIPs: []string{"0.0.0.0/0", "::/0"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRange{First: 53, Last: 53}},
					},
					IPProto: []int{protocolUDP},
				},
				{
					SrcIPs: []string{"0.0.0.0/0", "::/0"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
					IPProto: []int{protocolICMP, protocolIPv6ICMP},
				},
			},
			wantErr: false,
		},
		{
			name:   "port-wildcard",
			format: "hujson",
			acl: `
{
	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"Action": "accept",
			"src": [
				"*",
			],
			"dst": [
				"host-1:*",
			],
		},
	],
}
`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"0.0.0.0/0", "::/0"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			wantErr: false,
		},
		{
			name:   "port-range",
			format: "hujson",
			acl: `
{
	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"action": "accept",
			"src": [
				"subnet-1",
			],
			"dst": [
				"host-1:5400-5500",
			],
		},
	],
}
`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.100.101.0/24"},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "100.100.100.100/32",
							Ports: tailcfg.PortRange{First: 5400, Last: 5500},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:   "port-group",
			format: "hujson",
			acl: `
{
	"groups": {
		"group:example": [
			"testuser@",
		],
	},

	"hosts": {
		"host-1": "100.100.100.100",
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
`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"200.200.200.200/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			wantErr: false,
		},
		{
			name:   "port-user",
			format: "hujson",
			acl: `
{
	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"action": "accept",
			"src": [
				"testuser@",
			],
			"dst": [
				"host-1:*",
			],
		},
	],
}
`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"200.200.200.200/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			wantErr: false,
		},
		{
			name:   "ipv6",
			format: "hujson",
			acl: `
{
	"hosts": {
		"host-1": "100.100.100.100/32",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"action": "accept",
			"src": [
				"*",
			],
			"dst": [
				"host-1:*",
			],
		},
	],
}
`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"0.0.0.0/0", "::/0"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pol, err := unmarshalPolicy([]byte(tt.acl))
			if tt.wantErr && err == nil {
				t.Errorf("parsing() error = %v, wantErr %v", err, tt.wantErr)

				return
			} else if !tt.wantErr && err != nil {
				t.Errorf("parsing() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if err != nil {
				return
			}

			rules, err := pol.compileFilterRules(
				users,
				types.Nodes{
					&types.Node{
						IPv4: ap("100.100.100.100"),
					},
					&types.Node{
						IPv4:     ap("200.200.200.200"),
						User:     users[0],
						Hostinfo: &tailcfg.Hostinfo{},
					},
				}.ViewSlice())

			if (err != nil) != tt.wantErr {
				t.Errorf("parsing() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if diff := cmp.Diff(tt.want, rules); diff != "" {
				t.Errorf("parsing() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCompileSSHPolicy_UserMapping(t *testing.T) {
	users := types.Users{
		{Name: "user1", Model: gorm.Model{ID: 1}},
		{Name: "user2", Model: gorm.Model{ID: 2}},
	}

	// Create test nodes
	nodeUser1 := types.Node{
		Hostname: "user1-device",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   1,
		User:     users[0],
	}
	nodeUser2 := types.Node{
		Hostname: "user2-device",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   2,
		User:     users[1],
	}

	nodes := types.Nodes{&nodeUser1, &nodeUser2}

	tests := []struct {
		name         string
		targetNode   types.Node
		policy       *Policy
		wantSSHUsers map[string]string
		wantEmpty    bool
	}{
		{
			name:       "specific user mapping",
			targetNode: nodeUser1,
			policy: &Policy{
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{up("user1@")},
						Users:        []SSHUser{"ssh-it-user"},
					},
				},
			},
			wantSSHUsers: map[string]string{
				"ssh-it-user": "ssh-it-user",
			},
		},
		{
			name:       "multiple specific users",
			targetNode: nodeUser1,
			policy: &Policy{
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{up("user1@")},
						Users:        []SSHUser{"ubuntu", "admin", "deploy"},
					},
				},
			},
			wantSSHUsers: map[string]string{
				"ubuntu": "ubuntu",
				"admin":  "admin",
				"deploy": "deploy",
			},
		},
		{
			name:       "autogroup:nonroot only",
			targetNode: nodeUser1,
			policy: &Policy{
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{up("user1@")},
						Users:        []SSHUser{SSHUser(AutoGroupNonRoot)},
					},
				},
			},
			wantSSHUsers: map[string]string{
				"*":    "=",
				"root": "",
			},
		},
		{
			name:       "root only",
			targetNode: nodeUser1,
			policy: &Policy{
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{up("user1@")},
						Users:        []SSHUser{"root"},
					},
				},
			},
			wantSSHUsers: map[string]string{
				"root": "root",
			},
		},
		{
			name:       "autogroup:nonroot plus root",
			targetNode: nodeUser1,
			policy: &Policy{
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{up("user1@")},
						Users:        []SSHUser{SSHUser(AutoGroupNonRoot), "root"},
					},
				},
			},
			wantSSHUsers: map[string]string{
				"*":    "=",
				"root": "root",
			},
		},
		{
			name:       "mixed specific users and autogroups",
			targetNode: nodeUser1,
			policy: &Policy{
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{up("user1@")},
						Users:        []SSHUser{SSHUser(AutoGroupNonRoot), "root", "ubuntu", "admin"},
					},
				},
			},
			wantSSHUsers: map[string]string{
				"*":      "=",
				"root":   "root",
				"ubuntu": "ubuntu",
				"admin":  "admin",
			},
		},
		{
			name:       "no matching destination",
			targetNode: nodeUser2, // Target node2, but policy only allows user1
			policy: &Policy{
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{up("user1@")}, // Only user1, not user2
						Users:        []SSHUser{"ssh-it-user"},
					},
				},
			},
			wantEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate the policy
			err := tt.policy.validate()
			require.NoError(t, err)

			// Compile SSH policy
			sshPolicy, err := tt.policy.compileSSHPolicy(users, tt.targetNode.View(), nodes.ViewSlice())
			require.NoError(t, err)

			if tt.wantEmpty {
				if sshPolicy == nil {
					return // Expected empty result
				}
				assert.Empty(t, sshPolicy.Rules, "SSH policy should be empty when no rules match")
				return
			}

			require.NotNil(t, sshPolicy)
			require.Len(t, sshPolicy.Rules, 1, "Should have exactly one SSH rule")

			rule := sshPolicy.Rules[0]
			assert.Equal(t, tt.wantSSHUsers, rule.SSHUsers, "SSH users mapping should match expected")

			// Verify principals are set correctly (should contain user2's IP since that's the source)
			require.Len(t, rule.Principals, 1)
			assert.Equal(t, "100.64.0.2", rule.Principals[0].NodeIP)

			// Verify action is set correctly
			assert.True(t, rule.Action.Accept)
			assert.True(t, rule.Action.AllowAgentForwarding)
			assert.True(t, rule.Action.AllowLocalPortForwarding)
			assert.True(t, rule.Action.AllowRemotePortForwarding)
		})
	}
}

func TestCompileSSHPolicy_CheckAction(t *testing.T) {
	users := types.Users{
		{Name: "user1", Model: gorm.Model{ID: 1}},
		{Name: "user2", Model: gorm.Model{ID: 2}},
	}

	nodeUser1 := types.Node{
		Hostname: "user1-device",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   1,
		User:     users[0],
	}
	nodeUser2 := types.Node{
		Hostname: "user2-device",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   2,
		User:     users[1],
	}

	nodes := types.Nodes{&nodeUser1, &nodeUser2}

	policy := &Policy{
		Groups: Groups{
			Group("group:admins"): []Username{Username("user2@")},
		},
		SSHs: []SSH{
			{
				Action:       "check",
				CheckPeriod:  model.Duration(24 * time.Hour),
				Sources:      SSHSrcAliases{gp("group:admins")},
				Destinations: SSHDstAliases{up("user1@")},
				Users:        []SSHUser{"ssh-it-user"},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	sshPolicy, err := policy.compileSSHPolicy(users, nodeUser1.View(), nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, sshPolicy)
	require.Len(t, sshPolicy.Rules, 1)

	rule := sshPolicy.Rules[0]

	// Verify SSH users are correctly mapped
	expectedUsers := map[string]string{
		"ssh-it-user": "ssh-it-user",
	}
	assert.Equal(t, expectedUsers, rule.SSHUsers)

	// Verify check action with session duration
	assert.True(t, rule.Action.Accept)
	assert.Equal(t, 24*time.Hour, rule.Action.SessionDuration)
}

// TestSSHIntegrationReproduction reproduces the exact scenario from the integration test
// TestSSHOneUserToAll that was failing with empty sshUsers
func TestSSHIntegrationReproduction(t *testing.T) {
	// Create users matching the integration test
	users := types.Users{
		{Name: "user1", Model: gorm.Model{ID: 1}},
		{Name: "user2", Model: gorm.Model{ID: 2}},
	}

	// Create simple nodes for testing
	node1 := &types.Node{
		Hostname: "user1-node",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   1,
		User:     users[0],
	}

	node2 := &types.Node{
		Hostname: "user2-node",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   2,
		User:     users[1],
	}

	nodes := types.Nodes{node1, node2}

	// Create a simple policy that reproduces the issue
	policy := &Policy{
		Groups: Groups{
			Group("group:integration-test"): []Username{Username("user1@")},
		},
		SSHs: []SSH{
			{
				Action:       "accept",
				Sources:      SSHSrcAliases{gp("group:integration-test")},
				Destinations: SSHDstAliases{up("user2@")},       // Target user2
				Users:        []SSHUser{SSHUser("ssh-it-user")}, // This is the key - specific user
			},
		},
	}

	// Validate policy
	err := policy.validate()
	require.NoError(t, err)

	// Test SSH policy compilation for node2 (target)
	sshPolicy, err := policy.compileSSHPolicy(users, node2.View(), nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, sshPolicy)
	require.Len(t, sshPolicy.Rules, 1)

	rule := sshPolicy.Rules[0]

	// This was the failing assertion in integration test - sshUsers was empty
	assert.NotEmpty(t, rule.SSHUsers, "SSH users should not be empty")
	assert.Contains(t, rule.SSHUsers, "ssh-it-user", "ssh-it-user should be present in SSH users")
	assert.Equal(t, "ssh-it-user", rule.SSHUsers["ssh-it-user"], "ssh-it-user should map to itself")

	// Verify that ssh-it-user is correctly mapped
	expectedUsers := map[string]string{
		"ssh-it-user": "ssh-it-user",
	}
	assert.Equal(t, expectedUsers, rule.SSHUsers, "ssh-it-user should be mapped to itself")
}

// TestSSHJSONSerialization verifies that the SSH policy can be properly serialized
// to JSON and that the sshUsers field is not empty
func TestSSHJSONSerialization(t *testing.T) {
	users := types.Users{
		{Name: "user1", Model: gorm.Model{ID: 1}},
	}

	node := &types.Node{
		Hostname: "test-node",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   1,
		User:     users[0],
	}

	nodes := types.Nodes{node}

	policy := &Policy{
		SSHs: []SSH{
			{
				Action:       "accept",
				Sources:      SSHSrcAliases{up("user1@")},
				Destinations: SSHDstAliases{up("user1@")},
				Users:        []SSHUser{"ssh-it-user", "ubuntu", "admin"},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	sshPolicy, err := policy.compileSSHPolicy(users, node.View(), nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, sshPolicy)

	// Serialize to JSON to verify structure
	jsonData, err := json.MarshalIndent(sshPolicy, "", "  ")
	require.NoError(t, err)

	// Parse back to verify structure
	var parsed tailcfg.SSHPolicy
	err = json.Unmarshal(jsonData, &parsed)
	require.NoError(t, err)

	// Verify the parsed structure has the expected SSH users
	require.Len(t, parsed.Rules, 1)
	rule := parsed.Rules[0]

	expectedUsers := map[string]string{
		"ssh-it-user": "ssh-it-user",
		"ubuntu":      "ubuntu",
		"admin":       "admin",
	}
	assert.Equal(t, expectedUsers, rule.SSHUsers, "SSH users should survive JSON round-trip")

	// Verify JSON contains the SSH users (not empty)
	assert.Contains(t, string(jsonData), `"ssh-it-user"`)
	assert.Contains(t, string(jsonData), `"ubuntu"`)
	assert.Contains(t, string(jsonData), `"admin"`)
	assert.NotContains(t, string(jsonData), `"sshUsers": {}`, "SSH users should not be empty")
	assert.NotContains(t, string(jsonData), `"sshUsers": null`, "SSH users should not be null")
}

// Helper function to create IP addresses for testing
func createAddr(ip string) *netip.Addr {
	addr, _ := netip.ParseAddr(ip)
	return &addr
}
