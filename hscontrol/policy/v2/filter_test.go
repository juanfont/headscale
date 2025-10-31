package v2

import (
	"encoding/json"
	"net/netip"
	"strings"
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

// aliasWithPorts creates an AliasWithPorts structure from an alias and ports.
func aliasWithPorts(alias Alias, ports ...tailcfg.PortRange) AliasWithPorts {
	return AliasWithPorts{
		Alias: alias,
		Ports: ports,
	}
}

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
					IPProto: []int{protocolTCP, protocolUDP},
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
					IPProto: []int{protocolTCP, protocolUDP},
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
					IPProto: []int{protocolTCP, protocolUDP},
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
					IPProto: []int{protocolTCP, protocolUDP},
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
					IPProto: []int{protocolTCP, protocolUDP},
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
					IPProto: []int{protocolTCP, protocolUDP},
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

func TestCompileFilterRulesForNodeWithAutogroupSelf(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		{
			User: users[0],
			IPv4: ap("100.64.0.1"),
		},
		{
			User: users[0],
			IPv4: ap("100.64.0.2"),
		},
		{
			User: users[1],
			IPv4: ap("100.64.0.3"),
		},
		{
			User: users[1],
			IPv4: ap("100.64.0.4"),
		},
		// Tagged device for user1
		{
			User:       users[0],
			IPv4:       ap("100.64.0.5"),
			ForcedTags: []string{"tag:test"},
		},
		// Tagged device for user2
		{
			User:       users[1],
			IPv4:       ap("100.64.0.6"),
			ForcedTags: []string{"tag:test"},
		},
	}

	// Test: Tailscale intended usage pattern (autogroup:member + autogroup:self)
	policy2 := &Policy{
		ACLs: []ACL{
			{
				Action:  "accept",
				Sources: []Alias{agp("autogroup:member")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(agp("autogroup:self"), tailcfg.PortRangeAny),
				},
			},
		},
	}

	err := policy2.validate()
	if err != nil {
		t.Fatalf("policy validation failed: %v", err)
	}

	// Test compilation for user1's first node
	node1 := nodes[0].View()

	rules, err := policy2.compileFilterRulesForNode(users, node1, nodes.ViewSlice())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	// Check that the rule includes:
	// - Sources: only user1's untagged devices (filtered by autogroup:self semantics)
	// - Destinations: only user1's untagged devices (autogroup:self)
	rule := rules[0]

	// Sources should ONLY include user1's untagged devices (100.64.0.1, 100.64.0.2)
	expectedSourceIPs := []string{"100.64.0.1", "100.64.0.2"}

	for _, expectedIP := range expectedSourceIPs {
		found := false

		addr := netip.MustParseAddr(expectedIP)
		for _, prefix := range rule.SrcIPs {
			pref := netip.MustParsePrefix(prefix)
			if pref.Contains(addr) {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("expected source IP %s to be covered by generated prefixes %v", expectedIP, rule.SrcIPs)
		}
	}

	// Verify that other users' devices and tagged devices are not included in sources
	excludedSourceIPs := []string{"100.64.0.3", "100.64.0.4", "100.64.0.5", "100.64.0.6"}
	for _, excludedIP := range excludedSourceIPs {
		addr := netip.MustParseAddr(excludedIP)
		for _, prefix := range rule.SrcIPs {
			pref := netip.MustParsePrefix(prefix)
			if pref.Contains(addr) {
				t.Errorf("SECURITY VIOLATION: source IP %s should not be included but found in prefix %s", excludedIP, prefix)
			}
		}
	}

	expectedDestIPs := []string{"100.64.0.1", "100.64.0.2"}

	actualDestIPs := make([]string, 0, len(rule.DstPorts))
	for _, dst := range rule.DstPorts {
		actualDestIPs = append(actualDestIPs, dst.IP)
	}

	for _, expectedIP := range expectedDestIPs {
		found := false

		for _, actualIP := range actualDestIPs {
			if actualIP == expectedIP {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("expected destination IP %s to be included, got: %v", expectedIP, actualDestIPs)
		}
	}

	// Verify that other users' devices and tagged devices are not in destinations
	excludedDestIPs := []string{"100.64.0.3", "100.64.0.4", "100.64.0.5", "100.64.0.6"}
	for _, excludedIP := range excludedDestIPs {
		for _, actualIP := range actualDestIPs {
			if actualIP == excludedIP {
				t.Errorf("SECURITY: destination IP %s should not be included but found in destinations", excludedIP)
			}
		}
	}
}

func TestAutogroupSelfInSourceIsRejected(t *testing.T) {
	// Test that autogroup:self cannot be used in sources (per Tailscale spec)
	policy := &Policy{
		ACLs: []ACL{
			{
				Action:  "accept",
				Sources: []Alias{agp("autogroup:self")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(agp("autogroup:member"), tailcfg.PortRangeAny),
				},
			},
		},
	}

	err := policy.validate()
	if err == nil {
		t.Error("expected validation error when using autogroup:self in sources")
	}

	if !strings.Contains(err.Error(), "autogroup:self") {
		t.Errorf("expected error message to mention autogroup:self, got: %v", err)
	}
}

// TestAutogroupSelfWithSpecificUserSource verifies that when autogroup:self is in
// the destination and a specific user is in the source, only that user's devices
// are allowed (and only if they match the target user).
func TestAutogroupSelfWithSpecificUserSource(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		{User: users[0], IPv4: ap("100.64.0.1")},
		{User: users[0], IPv4: ap("100.64.0.2")},
		{User: users[1], IPv4: ap("100.64.0.3")},
		{User: users[1], IPv4: ap("100.64.0.4")},
	}

	policy := &Policy{
		ACLs: []ACL{
			{
				Action:  "accept",
				Sources: []Alias{up("user1@")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(agp("autogroup:self"), tailcfg.PortRangeAny),
				},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	// For user1's node: sources should be user1's devices
	node1 := nodes[0].View()
	rules, err := policy.compileFilterRulesForNode(users, node1, nodes.ViewSlice())
	require.NoError(t, err)
	require.Len(t, rules, 1)

	expectedSourceIPs := []string{"100.64.0.1", "100.64.0.2"}
	for _, expectedIP := range expectedSourceIPs {
		found := false
		addr := netip.MustParseAddr(expectedIP)

		for _, prefix := range rules[0].SrcIPs {
			pref := netip.MustParsePrefix(prefix)
			if pref.Contains(addr) {
				found = true
				break
			}
		}

		assert.True(t, found, "expected source IP %s to be present", expectedIP)
	}

	actualDestIPs := make([]string, 0, len(rules[0].DstPorts))
	for _, dst := range rules[0].DstPorts {
		actualDestIPs = append(actualDestIPs, dst.IP)
	}

	assert.ElementsMatch(t, expectedSourceIPs, actualDestIPs)

	node2 := nodes[2].View()
	rules2, err := policy.compileFilterRulesForNode(users, node2, nodes.ViewSlice())
	require.NoError(t, err)
	assert.Empty(t, rules2, "user2's node should have no rules (user1@ devices can't match user2's self)")
}

// TestAutogroupSelfWithGroupSource verifies that when a group is used as source
// and autogroup:self as destination, only group members who are the same user
// as the target are allowed.
func TestAutogroupSelfWithGroupSource(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
		{Model: gorm.Model{ID: 3}, Name: "user3"},
	}

	nodes := types.Nodes{
		{User: users[0], IPv4: ap("100.64.0.1")},
		{User: users[0], IPv4: ap("100.64.0.2")},
		{User: users[1], IPv4: ap("100.64.0.3")},
		{User: users[1], IPv4: ap("100.64.0.4")},
		{User: users[2], IPv4: ap("100.64.0.5")},
	}

	policy := &Policy{
		Groups: Groups{
			Group("group:admins"): []Username{Username("user1@"), Username("user2@")},
		},
		ACLs: []ACL{
			{
				Action:  "accept",
				Sources: []Alias{gp("group:admins")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(agp("autogroup:self"), tailcfg.PortRangeAny),
				},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	// (group:admins has user1+user2, but autogroup:self filters to same user)
	node1 := nodes[0].View()
	rules, err := policy.compileFilterRulesForNode(users, node1, nodes.ViewSlice())
	require.NoError(t, err)
	require.Len(t, rules, 1)

	expectedSrcIPs := []string{"100.64.0.1", "100.64.0.2"}
	for _, expectedIP := range expectedSrcIPs {
		found := false
		addr := netip.MustParseAddr(expectedIP)

		for _, prefix := range rules[0].SrcIPs {
			pref := netip.MustParsePrefix(prefix)
			if pref.Contains(addr) {
				found = true
				break
			}
		}

		assert.True(t, found, "expected source IP %s for user1", expectedIP)
	}

	node3 := nodes[4].View()
	rules3, err := policy.compileFilterRulesForNode(users, node3, nodes.ViewSlice())
	require.NoError(t, err)
	assert.Empty(t, rules3, "user3 should have no rules")
}

// Helper function to create IP addresses for testing
func createAddr(ip string) *netip.Addr {
	addr, _ := netip.ParseAddr(ip)
	return &addr
}

// TestSSHWithAutogroupSelfInDestination verifies that SSH policies work correctly
// with autogroup:self in destinations
func TestSSHWithAutogroupSelfInDestination(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		// User1's nodes
		{User: users[0], IPv4: ap("100.64.0.1"), Hostname: "user1-node1"},
		{User: users[0], IPv4: ap("100.64.0.2"), Hostname: "user1-node2"},
		// User2's nodes
		{User: users[1], IPv4: ap("100.64.0.3"), Hostname: "user2-node1"},
		{User: users[1], IPv4: ap("100.64.0.4"), Hostname: "user2-node2"},
		// Tagged node for user1 (should be excluded)
		{User: users[0], IPv4: ap("100.64.0.5"), Hostname: "user1-tagged", ForcedTags: []string{"tag:server"}},
	}

	policy := &Policy{
		SSHs: []SSH{
			{
				Action:       "accept",
				Sources:      SSHSrcAliases{agp("autogroup:member")},
				Destinations: SSHDstAliases{agp("autogroup:self")},
				Users:        []SSHUser{"autogroup:nonroot"},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	// Test for user1's first node
	node1 := nodes[0].View()
	sshPolicy, err := policy.compileSSHPolicy(users, node1, nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, sshPolicy)
	require.Len(t, sshPolicy.Rules, 1)

	rule := sshPolicy.Rules[0]

	// Principals should only include user1's untagged devices
	require.Len(t, rule.Principals, 2, "should have 2 principals (user1's 2 untagged nodes)")

	principalIPs := make([]string, len(rule.Principals))
	for i, p := range rule.Principals {
		principalIPs[i] = p.NodeIP
	}
	assert.ElementsMatch(t, []string{"100.64.0.1", "100.64.0.2"}, principalIPs)

	// Test for user2's first node
	node3 := nodes[2].View()
	sshPolicy2, err := policy.compileSSHPolicy(users, node3, nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, sshPolicy2)
	require.Len(t, sshPolicy2.Rules, 1)

	rule2 := sshPolicy2.Rules[0]

	// Principals should only include user2's untagged devices
	require.Len(t, rule2.Principals, 2, "should have 2 principals (user2's 2 untagged nodes)")

	principalIPs2 := make([]string, len(rule2.Principals))
	for i, p := range rule2.Principals {
		principalIPs2[i] = p.NodeIP
	}
	assert.ElementsMatch(t, []string{"100.64.0.3", "100.64.0.4"}, principalIPs2)

	// Test for tagged node (should have no SSH rules)
	node5 := nodes[4].View()
	sshPolicy3, err := policy.compileSSHPolicy(users, node5, nodes.ViewSlice())
	require.NoError(t, err)
	if sshPolicy3 != nil {
		assert.Empty(t, sshPolicy3.Rules, "tagged nodes should not get SSH rules with autogroup:self")
	}
}

// TestSSHWithAutogroupSelfAndSpecificUser verifies that when a specific user
// is in the source and autogroup:self in destination, only that user's devices
// can SSH (and only if they match the target user)
func TestSSHWithAutogroupSelfAndSpecificUser(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		{User: users[0], IPv4: ap("100.64.0.1")},
		{User: users[0], IPv4: ap("100.64.0.2")},
		{User: users[1], IPv4: ap("100.64.0.3")},
		{User: users[1], IPv4: ap("100.64.0.4")},
	}

	policy := &Policy{
		SSHs: []SSH{
			{
				Action:       "accept",
				Sources:      SSHSrcAliases{up("user1@")},
				Destinations: SSHDstAliases{agp("autogroup:self")},
				Users:        []SSHUser{"ubuntu"},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	// For user1's node: should allow SSH from user1's devices
	node1 := nodes[0].View()
	sshPolicy, err := policy.compileSSHPolicy(users, node1, nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, sshPolicy)
	require.Len(t, sshPolicy.Rules, 1)

	rule := sshPolicy.Rules[0]
	require.Len(t, rule.Principals, 2, "user1 should have 2 principals")

	principalIPs := make([]string, len(rule.Principals))
	for i, p := range rule.Principals {
		principalIPs[i] = p.NodeIP
	}
	assert.ElementsMatch(t, []string{"100.64.0.1", "100.64.0.2"}, principalIPs)

	// For user2's node: should have no rules (user1's devices can't match user2's self)
	node3 := nodes[2].View()
	sshPolicy2, err := policy.compileSSHPolicy(users, node3, nodes.ViewSlice())
	require.NoError(t, err)
	if sshPolicy2 != nil {
		assert.Empty(t, sshPolicy2.Rules, "user2 should have no SSH rules since source is user1")
	}
}

// TestSSHWithAutogroupSelfAndGroup verifies SSH with group sources and autogroup:self destinations
func TestSSHWithAutogroupSelfAndGroup(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
		{Model: gorm.Model{ID: 3}, Name: "user3"},
	}

	nodes := types.Nodes{
		{User: users[0], IPv4: ap("100.64.0.1")},
		{User: users[0], IPv4: ap("100.64.0.2")},
		{User: users[1], IPv4: ap("100.64.0.3")},
		{User: users[1], IPv4: ap("100.64.0.4")},
		{User: users[2], IPv4: ap("100.64.0.5")},
	}

	policy := &Policy{
		Groups: Groups{
			Group("group:admins"): []Username{Username("user1@"), Username("user2@")},
		},
		SSHs: []SSH{
			{
				Action:       "accept",
				Sources:      SSHSrcAliases{gp("group:admins")},
				Destinations: SSHDstAliases{agp("autogroup:self")},
				Users:        []SSHUser{"root"},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	// For user1's node: should allow SSH from user1's devices only (not user2's)
	node1 := nodes[0].View()
	sshPolicy, err := policy.compileSSHPolicy(users, node1, nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, sshPolicy)
	require.Len(t, sshPolicy.Rules, 1)

	rule := sshPolicy.Rules[0]
	require.Len(t, rule.Principals, 2, "user1 should have 2 principals (only user1's nodes)")

	principalIPs := make([]string, len(rule.Principals))
	for i, p := range rule.Principals {
		principalIPs[i] = p.NodeIP
	}
	assert.ElementsMatch(t, []string{"100.64.0.1", "100.64.0.2"}, principalIPs)

	// For user3's node: should have no rules (not in group:admins)
	node5 := nodes[4].View()
	sshPolicy2, err := policy.compileSSHPolicy(users, node5, nodes.ViewSlice())
	require.NoError(t, err)
	if sshPolicy2 != nil {
		assert.Empty(t, sshPolicy2.Rules, "user3 should have no SSH rules (not in group)")
	}
}

// TestSSHWithAutogroupSelfExcludesTaggedDevices verifies that tagged devices
// are excluded from both sources and destinations when autogroup:self is used
func TestSSHWithAutogroupSelfExcludesTaggedDevices(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
	}

	nodes := types.Nodes{
		{User: users[0], IPv4: ap("100.64.0.1"), Hostname: "untagged1"},
		{User: users[0], IPv4: ap("100.64.0.2"), Hostname: "untagged2"},
		{User: users[0], IPv4: ap("100.64.0.3"), Hostname: "tagged1", ForcedTags: []string{"tag:server"}},
		{User: users[0], IPv4: ap("100.64.0.4"), Hostname: "tagged2", ForcedTags: []string{"tag:web"}},
	}

	policy := &Policy{
		TagOwners: TagOwners{
			Tag("tag:server"): Owners{up("user1@")},
			Tag("tag:web"):    Owners{up("user1@")},
		},
		SSHs: []SSH{
			{
				Action:       "accept",
				Sources:      SSHSrcAliases{agp("autogroup:member")},
				Destinations: SSHDstAliases{agp("autogroup:self")},
				Users:        []SSHUser{"admin"},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	// For untagged node: should only get principals from other untagged nodes
	node1 := nodes[0].View()
	sshPolicy, err := policy.compileSSHPolicy(users, node1, nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, sshPolicy)
	require.Len(t, sshPolicy.Rules, 1)

	rule := sshPolicy.Rules[0]
	require.Len(t, rule.Principals, 2, "should only have 2 principals (untagged nodes)")

	principalIPs := make([]string, len(rule.Principals))
	for i, p := range rule.Principals {
		principalIPs[i] = p.NodeIP
	}
	assert.ElementsMatch(t, []string{"100.64.0.1", "100.64.0.2"}, principalIPs,
		"should only include untagged devices")

	// For tagged node: should get no SSH rules
	node3 := nodes[2].View()
	sshPolicy2, err := policy.compileSSHPolicy(users, node3, nodes.ViewSlice())
	require.NoError(t, err)
	if sshPolicy2 != nil {
		assert.Empty(t, sshPolicy2.Rules, "tagged node should get no SSH rules with autogroup:self")
	}
}

// TestSSHWithAutogroupSelfAndMixedDestinations tests that SSH rules can have both
// autogroup:self and other destinations (like tag:router) in the same rule, and that
// autogroup:self filtering only applies to autogroup:self destinations, not others.
func TestSSHWithAutogroupSelfAndMixedDestinations(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		{User: users[0], IPv4: ap("100.64.0.1"), Hostname: "user1-device"},
		{User: users[0], IPv4: ap("100.64.0.2"), Hostname: "user1-device2"},
		{User: users[1], IPv4: ap("100.64.0.3"), Hostname: "user2-device"},
		{User: users[1], IPv4: ap("100.64.0.4"), Hostname: "user2-router", ForcedTags: []string{"tag:router"}},
	}

	policy := &Policy{
		TagOwners: TagOwners{
			Tag("tag:router"): Owners{up("user2@")},
		},
		SSHs: []SSH{
			{
				Action:       "accept",
				Sources:      SSHSrcAliases{agp("autogroup:member")},
				Destinations: SSHDstAliases{agp("autogroup:self"), tp("tag:router")},
				Users:        []SSHUser{"admin"},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	// Test 1: Compile for user1's device (should only match autogroup:self destination)
	node1 := nodes[0].View()
	sshPolicy1, err := policy.compileSSHPolicy(users, node1, nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, sshPolicy1)
	require.Len(t, sshPolicy1.Rules, 1, "user1's device should have 1 SSH rule (autogroup:self)")

	// Verify autogroup:self rule has filtered sources (only same-user devices)
	selfRule := sshPolicy1.Rules[0]
	require.Len(t, selfRule.Principals, 2, "autogroup:self rule should only have user1's devices")
	selfPrincipals := make([]string, len(selfRule.Principals))
	for i, p := range selfRule.Principals {
		selfPrincipals[i] = p.NodeIP
	}
	require.ElementsMatch(t, []string{"100.64.0.1", "100.64.0.2"}, selfPrincipals,
		"autogroup:self rule should only include same-user untagged devices")

	// Test 2: Compile for router (should only match tag:router destination)
	routerNode := nodes[3].View() // user2-router
	sshPolicyRouter, err := policy.compileSSHPolicy(users, routerNode, nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, sshPolicyRouter)
	require.Len(t, sshPolicyRouter.Rules, 1, "router should have 1 SSH rule (tag:router)")

	routerRule := sshPolicyRouter.Rules[0]
	routerPrincipals := make([]string, len(routerRule.Principals))
	for i, p := range routerRule.Principals {
		routerPrincipals[i] = p.NodeIP
	}
	require.Contains(t, routerPrincipals, "100.64.0.1", "router rule should include user1's device (unfiltered sources)")
	require.Contains(t, routerPrincipals, "100.64.0.2", "router rule should include user1's other device (unfiltered sources)")
	require.Contains(t, routerPrincipals, "100.64.0.3", "router rule should include user2's device (unfiltered sources)")
}
