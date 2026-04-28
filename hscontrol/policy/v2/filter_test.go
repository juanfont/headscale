package v2

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/policy/policyutil"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
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
						{IP: "*", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						{IP: "*", Ports: tailcfg.PortRange{First: 3389, Last: 3389}},
						{IP: "100.100.100.100", Ports: tailcfg.PortRangeAny},
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
					SrcIPs: []string{"100.64.0.0-100.115.91.255", "100.115.94.0-100.127.255.255", "fd7a:115c:a1e0::/48"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100", Ports: tailcfg.PortRangeAny},
					},
					IPProto: []int{ProtocolTCP},
				},
				{
					SrcIPs: []string{"100.64.0.0-100.115.91.255", "100.115.94.0-100.127.255.255", "fd7a:115c:a1e0::/48"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100", Ports: tailcfg.PortRange{First: 53, Last: 53}},
					},
					IPProto: []int{ProtocolUDP},
				},
				{
					SrcIPs: []string{"100.64.0.0-100.115.91.255", "100.115.94.0-100.127.255.255", "fd7a:115c:a1e0::/48"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100", Ports: tailcfg.PortRangeAny},
					},
					// proto:icmp only includes ICMP (1), not ICMPv6 (58)
					IPProto: []int{ProtocolICMP},
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
					SrcIPs: []string{"100.64.0.0-100.115.91.255", "100.115.94.0-100.127.255.255", "fd7a:115c:a1e0::/48"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100", Ports: tailcfg.PortRangeAny},
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
							IP:    "100.100.100.100",
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
					SrcIPs: []string{"200.200.200.200"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100", Ports: tailcfg.PortRangeAny},
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
					SrcIPs: []string{"200.200.200.200"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100", Ports: tailcfg.PortRangeAny},
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
					SrcIPs: []string{"100.64.0.0-100.115.91.255", "100.115.94.0-100.127.255.255", "fd7a:115c:a1e0::/48"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100", Ports: tailcfg.PortRangeAny},
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
						User:     &users[0],
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

	// Create test nodes - use tagged nodes as SSH destinations
	// and untagged nodes as SSH sources (since group->username destinations
	// are not allowed per Tailscale security model, but groups can SSH to tags)
	nodeTaggedServer := types.Node{
		Hostname: "tagged-server",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   new(users[0].ID),
		User:     new(users[0]),
		Tags:     []string{"tag:server"},
	}
	nodeTaggedDB := types.Node{
		Hostname: "tagged-db",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   new(users[1].ID),
		User:     new(users[1]),
		Tags:     []string{"tag:database"},
	}
	// Add untagged node for user2 - this will be the SSH source
	// (group:admins contains user2, so user2's untagged node provides the source IPs)
	nodeUser2Untagged := types.Node{
		Hostname: "user2-device",
		IPv4:     createAddr("100.64.0.3"),
		UserID:   new(users[1].ID),
		User:     new(users[1]),
	}

	nodes := types.Nodes{&nodeTaggedServer, &nodeTaggedDB, &nodeUser2Untagged}

	acceptAction := &tailcfg.SSHAction{
		Accept:                    true,
		AllowAgentForwarding:      true,
		AllowLocalPortForwarding:  true,
		AllowRemotePortForwarding: true,
	}
	user2Principal := []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.3"}}

	tests := []struct {
		name       string
		targetNode types.Node
		policy     *Policy
		want       *tailcfg.SSHPolicy
	}{
		{
			name:       "specific user mapping",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("user1@")},
				},
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{"ssh-it-user"},
					},
				},
			},
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: user2Principal,
					SSHUsers:   map[string]string{"root": "", "ssh-it-user": "ssh-it-user"},
					Action:     acceptAction,
				},
			}},
		},
		{
			name:       "multiple specific users",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("user1@")},
				},
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{"ubuntu", "admin", "deploy"},
					},
				},
			},
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: user2Principal,
					SSHUsers:   map[string]string{"root": "", "ubuntu": "ubuntu", "admin": "admin", "deploy": "deploy"},
					Action:     acceptAction,
				},
			}},
		},
		{
			name:       "autogroup:nonroot only",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("user1@")},
				},
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{SSHUser(AutoGroupNonRoot)},
					},
				},
			},
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: user2Principal,
					SSHUsers:   map[string]string{"*": "=", "root": ""},
					Action:     acceptAction,
				},
			}},
		},
		{
			name:       "root only",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("user1@")},
				},
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{"root"},
					},
				},
			},
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: user2Principal,
					SSHUsers:   map[string]string{"root": "root"},
					Action:     acceptAction,
				},
			}},
		},
		{
			name:       "autogroup:nonroot plus root",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("user1@")},
				},
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{SSHUser(AutoGroupNonRoot), "root"},
					},
				},
			},
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: user2Principal,
					SSHUsers:   map[string]string{"*": "=", "root": "root"},
					Action:     acceptAction,
				},
			}},
		},
		{
			name:       "mixed specific users and autogroups",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("user1@")},
				},
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{SSHUser(AutoGroupNonRoot), "root", "ubuntu", "admin"},
					},
				},
			},
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: user2Principal,
					SSHUsers:   map[string]string{"*": "=", "root": "root", "ubuntu": "ubuntu", "admin": "admin"},
					Action:     acceptAction,
				},
			}},
		},
		{
			name:       "no matching destination",
			targetNode: nodeTaggedDB, // Target tag:database, but policy only allows tag:server
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"):   Owners{up("user1@")},
					Tag("tag:database"): Owners{up("user1@")},
				},
				Groups: Groups{
					Group("group:admins"): []Username{Username("user2@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{gp("group:admins")},
						Destinations: SSHDstAliases{tp("tag:server")}, // Only tag:server, not tag:database
						Users:        []SSHUser{"ssh-it-user"},
					},
				},
			},
			want: &tailcfg.SSHPolicy{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, tt.policy.validate())

			got, err := tt.policy.compileSSHPolicy("unused-server-url", users, tt.targetNode.View(), nodes.ViewSlice())
			require.NoError(t, err)

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("compileSSHPolicy() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCompileSSHPolicy_LocalpartMapping(t *testing.T) {
	users := types.Users{
		{Name: "alice", Email: "alice@example.com", Model: gorm.Model{ID: 1}},
		{Name: "bob", Email: "bob@example.com", Model: gorm.Model{ID: 2}},
		{Name: "charlie", Email: "charlie@other.com", Model: gorm.Model{ID: 3}},
		{Name: "dave", Model: gorm.Model{ID: 4}}, // CLI user, no email
	}

	nodeTaggedServer := types.Node{
		Hostname: "tagged-server",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   new(users[0].ID),
		User:     new(users[0]),
		Tags:     []string{"tag:server"},
	}
	nodeAlice := types.Node{
		Hostname: "alice-device",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   new(users[0].ID),
		User:     new(users[0]),
	}
	nodeBob := types.Node{
		Hostname: "bob-device",
		IPv4:     createAddr("100.64.0.3"),
		UserID:   new(users[1].ID),
		User:     new(users[1]),
	}
	nodeCharlie := types.Node{
		Hostname: "charlie-device",
		IPv4:     createAddr("100.64.0.4"),
		UserID:   new(users[2].ID),
		User:     new(users[2]),
	}
	nodeDave := types.Node{
		Hostname: "dave-device",
		IPv4:     createAddr("100.64.0.5"),
		UserID:   new(users[3].ID),
		User:     new(users[3]),
	}

	nodes := types.Nodes{&nodeTaggedServer, &nodeAlice, &nodeBob, &nodeCharlie, &nodeDave}

	acceptAction := &tailcfg.SSHAction{
		Accept:                    true,
		AllowAgentForwarding:      true,
		AllowLocalPortForwarding:  true,
		AllowRemotePortForwarding: true,
	}

	tests := []struct {
		name       string
		users      types.Users // nil → use default users
		nodes      types.Nodes // nil → use default nodes
		targetNode types.Node
		policy     *Policy
		want       *tailcfg.SSHPolicy
	}{
		{
			name:       "localpart only",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("alice@example.com")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{agp("autogroup:member")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{SSHUser("localpart:*@example.com")},
					},
				},
			},
			// Per-user common+localpart rules interleaved, then non-matching users.
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.2"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.2"}},
					SSHUsers:   map[string]string{"alice": "alice"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.3"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.3"}},
					SSHUsers:   map[string]string{"bob": "bob"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.4"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.5"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
			}},
		},
		{
			name:       "localpart with root",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("alice@example.com")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{agp("autogroup:member")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{SSHUser("localpart:*@example.com"), "root"},
					},
				},
			},
			// Per-user common+localpart rules interleaved, then non-matching users.
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.2"}},
					SSHUsers:   map[string]string{"root": "root"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.2"}},
					SSHUsers:   map[string]string{"alice": "alice"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.3"}},
					SSHUsers:   map[string]string{"root": "root"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.3"}},
					SSHUsers:   map[string]string{"bob": "bob"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.4"}},
					SSHUsers:   map[string]string{"root": "root"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.5"}},
					SSHUsers:   map[string]string{"root": "root"},
					Action:     acceptAction,
				},
			}},
		},
		{
			name:       "localpart no matching users in domain",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("alice@example.com")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{agp("autogroup:member")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{SSHUser("localpart:*@nonexistent.com")},
					},
				},
			},
			// No localpart matches, but per-user common rules still emitted (root deny)
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.2"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.3"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.4"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.5"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
			}},
		},
		{
			name: "localpart with special chars in email",
			users: types.Users{
				{Name: "dave+sshuser", Email: "dave+sshuser@example.com", Model: gorm.Model{ID: 10}},
			},
			nodes: func() types.Nodes {
				specialUser := types.User{Name: "dave+sshuser", Email: "dave+sshuser@example.com", Model: gorm.Model{ID: 10}}
				n := types.Node{
					Hostname: "special-device",
					IPv4:     createAddr("100.64.0.10"),
					UserID:   new(specialUser.ID),
					User:     &specialUser,
				}

				return types.Nodes{&nodeTaggedServer, &n}
			}(),
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("dave+sshuser@example.com")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{agp("autogroup:member")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{SSHUser("localpart:*@example.com")},
					},
				},
			},
			// Per-user common rule (root deny), then separate localpart rule.
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.10"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.10"}},
					SSHUsers:   map[string]string{"dave+sshuser": "dave+sshuser"},
					Action:     acceptAction,
				},
			}},
		},
		{
			name: "localpart excludes CLI users without email",
			users: types.Users{
				{Name: "dave", Model: gorm.Model{ID: 4}},
			},
			nodes: func() types.Nodes {
				cliUser := types.User{Name: "dave", Model: gorm.Model{ID: 4}}
				n := types.Node{
					Hostname: "dave-cli-device",
					IPv4:     createAddr("100.64.0.5"),
					UserID:   new(cliUser.ID),
					User:     &cliUser,
				}

				return types.Nodes{&nodeTaggedServer, &n}
			}(),
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("dave@")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{agp("autogroup:member")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users:        []SSHUser{SSHUser("localpart:*@example.com")},
					},
				},
			},
			// No localpart matches (CLI user, no email), but implicit root deny emits common rule
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.5"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
			}},
		},
		{
			name:       "localpart with multiple domains",
			targetNode: nodeTaggedServer,
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:server"): Owners{up("alice@example.com")},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      SSHSrcAliases{agp("autogroup:member")},
						Destinations: SSHDstAliases{tp("tag:server")},
						Users: []SSHUser{
							SSHUser("localpart:*@example.com"),
							SSHUser("localpart:*@other.com"),
						},
					},
				},
			},
			// Per-user common+localpart rules interleaved:
			// alice/bob match *@example.com, charlie matches *@other.com.
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.2"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.2"}},
					SSHUsers:   map[string]string{"alice": "alice"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.3"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.3"}},
					SSHUsers:   map[string]string{"bob": "bob"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.4"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.4"}},
					SSHUsers:   map[string]string{"charlie": "charlie"},
					Action:     acceptAction,
				},
				{
					Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.5"}},
					SSHUsers:   map[string]string{"root": ""},
					Action:     acceptAction,
				},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testUsers := users
			if tt.users != nil {
				testUsers = tt.users
			}

			testNodes := nodes
			if tt.nodes != nil {
				testNodes = tt.nodes
			}

			require.NoError(t, tt.policy.validate())

			got, err := tt.policy.compileSSHPolicy(
				"unused-server-url", testUsers, tt.targetNode.View(), testNodes.ViewSlice(),
			)
			require.NoError(t, err)

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("compileSSHPolicy() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCompileSSHPolicy_CheckAction(t *testing.T) {
	users := types.Users{
		{Name: "user1", Model: gorm.Model{ID: 1}},
		{Name: "user2", Model: gorm.Model{ID: 2}},
	}

	// Use tagged nodes for SSH user mapping tests
	nodeTaggedServer := types.Node{
		Hostname: "tagged-server",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   new(users[0].ID),
		User:     new(users[0]),
		Tags:     []string{"tag:server"},
	}
	nodeUser2 := types.Node{
		Hostname: "user2-device",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   new(users[1].ID),
		User:     new(users[1]),
	}

	nodes := types.Nodes{&nodeTaggedServer, &nodeUser2}

	policy := &Policy{
		TagOwners: TagOwners{
			Tag("tag:server"): Owners{up("user1@")},
		},
		Groups: Groups{
			Group("group:admins"): []Username{Username("user2@")},
		},
		SSHs: []SSH{
			{
				Action:       "check",
				CheckPeriod:  &SSHCheckPeriod{Duration: 24 * time.Hour},
				Sources:      SSHSrcAliases{gp("group:admins")},
				Destinations: SSHDstAliases{tp("tag:server")},
				Users:        []SSHUser{"ssh-it-user"},
			},
		},
	}

	require.NoError(t, policy.validate())

	sshPolicy, err := policy.compileSSHPolicy("unused-server-url", users, nodeTaggedServer.View(), nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, sshPolicy)
	require.Len(t, sshPolicy.Rules, 1)

	rule := sshPolicy.Rules[0]

	// Verify SSH users are correctly mapped
	expectedUsers := map[string]string{
		"ssh-it-user": "ssh-it-user",
		"root":        "",
	}
	assert.Equal(t, expectedUsers, rule.SSHUsers)

	// Verify check action: Accept is false, HoldAndDelegate is set
	assert.False(t, rule.Action.Accept)
	assert.False(t, rule.Action.Reject)
	assert.NotEmpty(t, rule.Action.HoldAndDelegate)
	assert.Contains(t, rule.Action.HoldAndDelegate, "/machine/ssh/action/")
	assert.Equal(t, time.Duration(0), rule.Action.SessionDuration)

	// Verify check params are NOT encoded in the URL (looked up server-side).
	assert.NotContains(t, rule.Action.HoldAndDelegate, "check_explicit")
	assert.NotContains(t, rule.Action.HoldAndDelegate, "check_period")
}

// TestCompileSSHPolicy_CheckBeforeAcceptOrdering verifies that check
// (HoldAndDelegate) rules are sorted before accept rules, even when
// the accept rule appears first in the policy definition.
func TestCompileSSHPolicy_CheckBeforeAcceptOrdering(t *testing.T) {
	users := types.Users{
		{Name: "user1", Model: gorm.Model{ID: 1}},
		{Name: "user2", Model: gorm.Model{ID: 2}},
	}

	nodeTaggedServer := types.Node{
		Hostname: "tagged-server",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   new(users[0].ID),
		User:     new(users[0]),
		Tags:     []string{"tag:server"},
	}
	nodeUser2 := types.Node{
		Hostname: "user2-device",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   new(users[1].ID),
		User:     new(users[1]),
	}

	nodes := types.Nodes{&nodeTaggedServer, &nodeUser2}

	// Accept rule appears BEFORE check rule in policy definition.
	policy := &Policy{
		TagOwners: TagOwners{
			Tag("tag:server"): Owners{up("user1@")},
		},
		Groups: Groups{
			Group("group:admins"): []Username{Username("user2@")},
		},
		SSHs: []SSH{
			{
				Action:       "accept",
				Sources:      SSHSrcAliases{gp("group:admins")},
				Destinations: SSHDstAliases{tp("tag:server")},
				Users:        []SSHUser{"root"},
			},
			{
				Action:       "check",
				CheckPeriod:  &SSHCheckPeriod{Duration: 24 * time.Hour},
				Sources:      SSHSrcAliases{gp("group:admins")},
				Destinations: SSHDstAliases{tp("tag:server")},
				Users:        []SSHUser{"ssh-it-user"},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	sshPolicy, err := policy.compileSSHPolicy(
		"unused-server-url",
		users,
		nodeTaggedServer.View(),
		nodes.ViewSlice(),
	)
	require.NoError(t, err)
	require.NotNil(t, sshPolicy)
	require.Len(t, sshPolicy.Rules, 2)

	// First rule must be the check rule (HoldAndDelegate set).
	assert.NotEmpty(t, sshPolicy.Rules[0].Action.HoldAndDelegate,
		"first rule should be check (HoldAndDelegate)")
	assert.False(t, sshPolicy.Rules[0].Action.Accept,
		"first rule should not be accept")

	// Second rule must be the accept rule.
	assert.True(t, sshPolicy.Rules[1].Action.Accept,
		"second rule should be accept")
	assert.Empty(t, sshPolicy.Rules[1].Action.HoldAndDelegate,
		"second rule should not have HoldAndDelegate")
}

// TestSSHIntegrationReproduction reproduces the exact scenario from the integration test
// TestSSHOneUserToAll that was failing with empty sshUsers.
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
		UserID:   new(users[0].ID),
		User:     new(users[0]),
	}

	node2 := &types.Node{
		Hostname: "user2-node",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   new(users[1].ID),
		User:     new(users[1]),
	}

	nodes := types.Nodes{node1, node2}

	// Create a simple policy that reproduces the issue
	// Updated to use autogroup:self instead of username destination (per Tailscale security model)
	policy := &Policy{
		Groups: Groups{
			Group("group:integration-test"): []Username{Username("user1@"), Username("user2@")},
		},
		SSHs: []SSH{
			{
				Action:       "accept",
				Sources:      SSHSrcAliases{gp("group:integration-test")},
				Destinations: SSHDstAliases{agp("autogroup:self")}, // Users can SSH to their own devices
				Users:        []SSHUser{SSHUser("ssh-it-user")},    // This is the key - specific user
			},
		},
	}

	require.NoError(t, policy.validate())

	// Test SSH policy compilation for node2 (owned by user2, who is in the group)
	got, err := policy.compileSSHPolicy("unused-server-url", users, node2.View(), nodes.ViewSlice())
	require.NoError(t, err)

	want := &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
		{
			Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.2"}},
			SSHUsers:   map[string]string{"root": "", "ssh-it-user": "ssh-it-user"},
			Action: &tailcfg.SSHAction{
				Accept:                    true,
				AllowAgentForwarding:      true,
				AllowLocalPortForwarding:  true,
				AllowRemotePortForwarding: true,
			},
		},
	}}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("compileSSHPolicy() mismatch (-want +got):\n%s", diff)
	}
}

// TestSSHJSONSerialization verifies that the SSH policy can be properly serialized
// to JSON and that the sshUsers field is not empty.
func TestSSHJSONSerialization(t *testing.T) {
	users := types.Users{
		{Name: "user1", Model: gorm.Model{ID: 1}},
	}

	uid := uint(1)
	node := &types.Node{
		Hostname: "test-node",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   &uid,
		User:     &users[0],
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

	require.NoError(t, policy.validate())

	got, err := policy.compileSSHPolicy("unused-server-url", users, node.View(), nodes.ViewSlice())
	require.NoError(t, err)

	want := &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
		{
			Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.1"}},
			SSHUsers:   map[string]string{"root": "", "ssh-it-user": "ssh-it-user", "ubuntu": "ubuntu", "admin": "admin"},
			Action: &tailcfg.SSHAction{
				Accept:                    true,
				AllowAgentForwarding:      true,
				AllowLocalPortForwarding:  true,
				AllowRemotePortForwarding: true,
			},
		},
	}}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("compileSSHPolicy() mismatch (-want +got):\n%s", diff)
	}

	// Verify JSON round-trip preserves the full structure
	jsonData, err := json.MarshalIndent(got, "", "  ")
	require.NoError(t, err)

	var parsed tailcfg.SSHPolicy
	require.NoError(t, json.Unmarshal(jsonData, &parsed))

	if diff := cmp.Diff(want, &parsed); diff != "" {
		t.Errorf("JSON round-trip mismatch (-want +got):\n%s", diff)
	}
}

func TestCompileFilterRulesForNodeWithAutogroupSelf(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		{
			User: new(users[0]),
			IPv4: ap("100.64.0.1"),
		},
		{
			User: new(users[0]),
			IPv4: ap("100.64.0.2"),
		},
		{
			User: new(users[1]),
			IPv4: ap("100.64.0.3"),
		},
		{
			User: new(users[1]),
			IPv4: ap("100.64.0.4"),
		},
		// Tagged device for user1
		{
			User: &users[0],
			IPv4: ap("100.64.0.5"),
			Tags: []string{"tag:test"},
		},
		// Tagged device for user2
		{
			User: &users[1],
			IPv4: ap("100.64.0.6"),
			Tags: []string{"tag:test"},
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

		for _, srcEntry := range rule.SrcIPs {
			ipSet, err := util.ParseIPSet(srcEntry, nil)
			if err != nil {
				t.Fatalf("failed to parse SrcIP %q: %v", srcEntry, err)
			}

			if ipSet.Contains(addr) {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("expected source IP %s to be covered by generated SrcIPs %v", expectedIP, rule.SrcIPs)
		}
	}

	// Verify that other users' devices and tagged devices are not included in sources
	excludedSourceIPs := []string{"100.64.0.3", "100.64.0.4", "100.64.0.5", "100.64.0.6"}
	for _, excludedIP := range excludedSourceIPs {
		addr := netip.MustParseAddr(excludedIP)

		for _, srcEntry := range rule.SrcIPs {
			ipSet, err := util.ParseIPSet(srcEntry, nil)
			if err != nil {
				t.Fatalf("failed to parse SrcIP %q: %v", srcEntry, err)
			}

			if ipSet.Contains(addr) {
				t.Errorf("SECURITY VIOLATION: source IP %s should not be included but found in SrcIP %s", excludedIP, srcEntry)
			}
		}
	}

	expectedDestIPs := []string{"100.64.0.1", "100.64.0.2"}

	actualDestIPs := make([]string, 0, len(rule.DstPorts))
	for _, dst := range rule.DstPorts {
		actualDestIPs = append(actualDestIPs, dst.IP)
	}

	for _, expectedIP := range expectedDestIPs {
		addr := netip.MustParseAddr(expectedIP)

		found := false

		for _, destIP := range actualDestIPs {
			ipSet, err := util.ParseIPSet(destIP, nil)
			if err != nil {
				t.Fatalf("failed to parse DstPort IP %q: %v", destIP, err)
			}

			if ipSet.Contains(addr) {
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
		addr := netip.MustParseAddr(excludedIP)

		for _, destIP := range actualDestIPs {
			ipSet, err := util.ParseIPSet(destIP, nil)
			if err != nil {
				t.Fatalf("failed to parse DstPort IP %q: %v", destIP, err)
			}

			if ipSet.Contains(addr) {
				t.Errorf("SECURITY: destination IP %s should not be included but found in dest %s", excludedIP, destIP)
			}
		}
	}
}

// TestTagUserMutualExclusivity tests that without explicit cross-identity ACL
// rules, user-owned nodes and tagged nodes are isolated from each other.
// It also verifies that tag-to-tag rules work correctly.
func TestTagUserMutualExclusivity(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		// User-owned nodes
		{
			User: new(users[0]),
			IPv4: ap("100.64.0.1"),
		},
		{
			User: new(users[1]),
			IPv4: ap("100.64.0.2"),
		},
		// Tagged nodes
		{
			User: &users[0], // "created by" tracking
			IPv4: ap("100.64.0.10"),
			Tags: []string{"tag:server"},
		},
		{
			User: &users[1], // "created by" tracking
			IPv4: ap("100.64.0.11"),
			Tags: []string{"tag:database"},
		},
	}

	pol := &Policy{
		TagOwners: TagOwners{
			Tag("tag:server"):   Owners{new(Username("user1@"))},
			Tag("tag:database"): Owners{new(Username("user2@"))},
		},
		ACLs: []ACL{
			// Only tag-to-tag rule, no user-to-tag rules.
			{
				Action:  "accept",
				Sources: []Alias{tp("tag:server")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(tp("tag:database"), tailcfg.PortRangeAny),
				},
			},
		},
	}

	err := pol.validate()
	require.NoError(t, err)

	// User1's user-owned node should have no rules reaching tagged nodes
	// since there is no explicit user→tag ACL rule. ReduceFilterRules
	// filters compiled rules to only those where the node is a destination,
	// matching the production pipeline in filterForNodeLocked.
	userNode := nodes[0].View()

	compiled, err := pol.compileFilterRulesForNode(users, userNode, nodes.ViewSlice())
	require.NoError(t, err)

	userRules := policyutil.ReduceFilterRules(userNode, compiled)

	for _, rule := range userRules {
		for _, dst := range rule.DstPorts {
			ipSet, parseErr := util.ParseIPSet(dst.IP, nil)
			require.NoError(t, parseErr)

			if ipSet.Contains(netip.MustParseAddr("100.64.0.10")) {
				t.Errorf("user-owned node should not reach tag:server without explicit grant (got dest %s)", dst.IP)
			}

			if ipSet.Contains(netip.MustParseAddr("100.64.0.11")) {
				t.Errorf("user-owned node should not reach tag:database without explicit grant (got dest %s)", dst.IP)
			}
		}
	}

	// Tag:database should receive the tag:server → tag:database rule after reduction.
	dbNode := nodes[3].View()

	compiled, err = pol.compileFilterRulesForNode(users, dbNode, nodes.ViewSlice())
	require.NoError(t, err)

	dbRules := policyutil.ReduceFilterRules(dbNode, compiled)

	foundServerSrc := false

	for _, rule := range dbRules {
		for _, srcEntry := range rule.SrcIPs {
			ipSet, parseErr := util.ParseIPSet(srcEntry, nil)
			require.NoError(t, parseErr)

			if ipSet.Contains(netip.MustParseAddr("100.64.0.10")) {
				foundServerSrc = true
				break
			}
		}
	}

	assert.True(t, foundServerSrc, "tag:database should accept traffic from tag:server")
}

// TestUserToTagCrossIdentityGrant tests that an explicit ACL rule granting
// user-owned nodes access to tagged nodes works correctly. The tags-as-identity
// model separates identity classes, but explicit ACL grants across classes
// are valid and should produce filter rules.
func TestUserToTagCrossIdentityGrant(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		{
			User: new(users[0]),
			IPv4: ap("100.64.0.1"),
		},
		{
			User: new(users[1]),
			IPv4: ap("100.64.0.2"),
		},
		{
			User: &users[0], // "created by" tracking
			IPv4: ap("100.64.0.10"),
			Tags: []string{"tag:server"},
		},
	}

	pol := &Policy{
		TagOwners: TagOwners{
			Tag("tag:server"): Owners{new(Username("user1@"))},
		},
		ACLs: []ACL{
			// Explicit cross-identity grant: user1's devices can reach tag:server.
			{
				Action:  "accept",
				Sources: []Alias{up("user1@")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(tp("tag:server"), tailcfg.PortRangeAny),
				},
			},
		},
	}

	err := pol.validate()
	require.NoError(t, err)

	// Compile and reduce rules for the tag:server node — it is the
	// destination, so after ReduceFilterRules, the filter should include
	// user1's IP as source.
	taggedNode := nodes[2].View()

	compiled, err := pol.compileFilterRulesForNode(users, taggedNode, nodes.ViewSlice())
	require.NoError(t, err)

	rules := policyutil.ReduceFilterRules(taggedNode, compiled)

	// user1's IP should appear as a source that can reach tag:server.
	foundUser1Src := false

	for _, rule := range rules {
		for _, srcEntry := range rule.SrcIPs {
			ipSet, parseErr := util.ParseIPSet(srcEntry, nil)
			require.NoError(t, parseErr)

			if ipSet.Contains(netip.MustParseAddr("100.64.0.1")) {
				foundUser1Src = true
				break
			}
		}
	}

	assert.True(t, foundUser1Src,
		"explicit user1@ -> tag:server ACL should allow user1 devices to reach tagged node")

	// user2 should NOT appear as a source.
	for _, rule := range rules {
		for _, srcEntry := range rule.SrcIPs {
			ipSet, parseErr := util.ParseIPSet(srcEntry, nil)
			require.NoError(t, parseErr)

			if ipSet.Contains(netip.MustParseAddr("100.64.0.2")) {
				t.Errorf("user2 should not reach tag:server (found in SrcIP %s)", srcEntry)
			}
		}
	}
}

// TestAutogroupTagged tests that autogroup:tagged correctly selects all devices
// with tag-based identity (IsTagged() == true or has requested tags in tagOwners).
func TestAutogroupTagged(t *testing.T) {
	t.Parallel()

	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		// User-owned nodes (not tagged)
		{
			User: new(users[0]),
			IPv4: ap("100.64.0.1"),
		},
		{
			User: new(users[1]),
			IPv4: ap("100.64.0.2"),
		},
		// Tagged nodes
		{
			User: &users[0], // "created by" tracking
			IPv4: ap("100.64.0.10"),
			Tags: []string{"tag:server"},
		},
		{
			User: &users[1], // "created by" tracking
			IPv4: ap("100.64.0.11"),
			Tags: []string{"tag:database"},
		},
		{
			User: &users[0],
			IPv4: ap("100.64.0.12"),
			Tags: []string{"tag:web", "tag:prod"},
		},
	}

	policy := &Policy{
		TagOwners: TagOwners{
			Tag("tag:server"):   Owners{new(Username("user1@"))},
			Tag("tag:database"): Owners{new(Username("user2@"))},
			Tag("tag:web"):      Owners{new(Username("user1@"))},
			Tag("tag:prod"):     Owners{new(Username("user1@"))},
		},
		ACLs: []ACL{
			// Rule: autogroup:tagged can reach user-owned nodes
			{
				Action:  "accept",
				Sources: []Alias{agp("autogroup:tagged")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(up("user1@"), tailcfg.PortRangeAny),
					aliasWithPorts(up("user2@"), tailcfg.PortRangeAny),
				},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	// Verify autogroup:tagged includes all tagged nodes
	ag := AutoGroupTagged
	taggedIPs, err := ag.Resolve(policy, users, nodes.ViewSlice())
	require.NoError(t, err)
	require.NotNil(t, taggedIPs)

	// Should contain all tagged nodes
	assert.True(t, taggedIPs.Contains(*ap("100.64.0.10")), "should include tag:server")
	assert.True(t, taggedIPs.Contains(*ap("100.64.0.11")), "should include tag:database")
	assert.True(t, taggedIPs.Contains(*ap("100.64.0.12")), "should include tag:web,tag:prod")

	// Should NOT contain user-owned nodes
	assert.False(t, taggedIPs.Contains(*ap("100.64.0.1")), "should not include user1 node")
	assert.False(t, taggedIPs.Contains(*ap("100.64.0.2")), "should not include user2 node")

	// Test ACL filtering: all tagged nodes should be able to reach user nodes
	tests := []struct {
		name        string
		sourceNode  types.NodeView
		shouldReach []string // IP strings for comparison
	}{
		{
			name:        "tag:server can reach user-owned nodes",
			sourceNode:  nodes[2].View(),
			shouldReach: []string{"100.64.0.1", "100.64.0.2"},
		},
		{
			name:        "tag:database can reach user-owned nodes",
			sourceNode:  nodes[3].View(),
			shouldReach: []string{"100.64.0.1", "100.64.0.2"},
		},
		{
			name:        "tag:web,tag:prod can reach user-owned nodes",
			sourceNode:  nodes[4].View(),
			shouldReach: []string{"100.64.0.1", "100.64.0.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rules, err := policy.compileFilterRulesForNode(users, tt.sourceNode, nodes.ViewSlice())
			require.NoError(t, err)

			// Verify all expected destinations are reachable
			for _, expectedDest := range tt.shouldReach {
				found := false

				for _, rule := range rules {
					for _, dstPort := range rule.DstPorts {
						// DstPort.IP is CIDR notation like "100.64.0.1/32"
						if strings.HasPrefix(dstPort.IP, expectedDest+"/") || dstPort.IP == expectedDest {
							found = true
							break
						}
					}

					if found {
						break
					}
				}

				assert.True(t, found, "Expected to find destination %s in rules", expectedDest)
			}
		})
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
		{User: new(users[0]), IPv4: ap("100.64.0.1")},
		{User: new(users[0]), IPv4: ap("100.64.0.2")},
		{User: new(users[1]), IPv4: ap("100.64.0.3")},
		{User: new(users[1]), IPv4: ap("100.64.0.4")},
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

		for _, srcEntry := range rules[0].SrcIPs {
			ipSet, err := util.ParseIPSet(srcEntry, nil)
			require.NoError(t, err, "failed to parse SrcIP %q", srcEntry)

			if ipSet.Contains(addr) {
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

	expectedDestIPs := []string{"100.64.0.1", "100.64.0.2"}
	assert.ElementsMatch(t, expectedDestIPs, actualDestIPs)

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
		{User: new(users[0]), IPv4: ap("100.64.0.1")},
		{User: new(users[0]), IPv4: ap("100.64.0.2")},
		{User: new(users[1]), IPv4: ap("100.64.0.3")},
		{User: new(users[1]), IPv4: ap("100.64.0.4")},
		{User: new(users[2]), IPv4: ap("100.64.0.5")},
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

		for _, srcEntry := range rules[0].SrcIPs {
			ipSet, err := util.ParseIPSet(srcEntry, nil)
			require.NoError(t, err, "failed to parse SrcIP %q", srcEntry)

			if ipSet.Contains(addr) {
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

// Helper function to create IP addresses for testing.
func createAddr(ip string) *netip.Addr {
	addr, _ := netip.ParseAddr(ip)
	return &addr
}

// TestSSHWithAutogroupSelfInDestination verifies that SSH policies work correctly
// with autogroup:self in destinations.
func TestSSHWithAutogroupSelfInDestination(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		// User1's nodes
		{User: new(users[0]), IPv4: ap("100.64.0.1"), Hostname: "user1-node1"},
		{User: new(users[0]), IPv4: ap("100.64.0.2"), Hostname: "user1-node2"},
		// User2's nodes
		{User: new(users[1]), IPv4: ap("100.64.0.3"), Hostname: "user2-node1"},
		{User: new(users[1]), IPv4: ap("100.64.0.4"), Hostname: "user2-node2"},
		// Tagged node for user1 (should be excluded)
		{User: new(users[0]), IPv4: ap("100.64.0.5"), Hostname: "user1-tagged", Tags: []string{"tag:server"}},
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
	sshPolicy, err := policy.compileSSHPolicy("unused-server-url", users, node1, nodes.ViewSlice())
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
	sshPolicy2, err := policy.compileSSHPolicy("unused-server-url", users, node3, nodes.ViewSlice())
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
	sshPolicy3, err := policy.compileSSHPolicy("unused-server-url", users, node5, nodes.ViewSlice())
	require.NoError(t, err)

	if sshPolicy3 != nil {
		assert.Empty(t, sshPolicy3.Rules, "tagged nodes should not get SSH rules with autogroup:self")
	}
}

// TestSSHWithAutogroupSelfAndSpecificUser verifies that when a specific user
// is in the source and autogroup:self in destination, only that user's devices
// can SSH (and only if they match the target user).
func TestSSHWithAutogroupSelfAndSpecificUser(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		{User: new(users[0]), IPv4: ap("100.64.0.1")},
		{User: new(users[0]), IPv4: ap("100.64.0.2")},
		{User: new(users[1]), IPv4: ap("100.64.0.3")},
		{User: new(users[1]), IPv4: ap("100.64.0.4")},
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
	sshPolicy, err := policy.compileSSHPolicy("unused-server-url", users, node1, nodes.ViewSlice())
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
	sshPolicy2, err := policy.compileSSHPolicy("unused-server-url", users, node3, nodes.ViewSlice())
	require.NoError(t, err)

	if sshPolicy2 != nil {
		assert.Empty(t, sshPolicy2.Rules, "user2 should have no SSH rules since source is user1")
	}
}

// TestSSHWithAutogroupSelfAndGroup verifies SSH with group sources and autogroup:self destinations.
func TestSSHWithAutogroupSelfAndGroup(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
		{Model: gorm.Model{ID: 3}, Name: "user3"},
	}

	nodes := types.Nodes{
		{User: new(users[0]), IPv4: ap("100.64.0.1")},
		{User: new(users[0]), IPv4: ap("100.64.0.2")},
		{User: new(users[1]), IPv4: ap("100.64.0.3")},
		{User: new(users[1]), IPv4: ap("100.64.0.4")},
		{User: new(users[2]), IPv4: ap("100.64.0.5")},
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
	sshPolicy, err := policy.compileSSHPolicy("unused-server-url", users, node1, nodes.ViewSlice())
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
	sshPolicy2, err := policy.compileSSHPolicy("unused-server-url", users, node5, nodes.ViewSlice())
	require.NoError(t, err)

	if sshPolicy2 != nil {
		assert.Empty(t, sshPolicy2.Rules, "user3 should have no SSH rules (not in group)")
	}
}

// TestSSHWithAutogroupSelfExcludesTaggedDevices verifies that tagged devices
// are excluded from both sources and destinations when autogroup:self is used.
func TestSSHWithAutogroupSelfExcludesTaggedDevices(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
	}

	nodes := types.Nodes{
		{User: new(users[0]), IPv4: ap("100.64.0.1"), Hostname: "untagged1"},
		{User: new(users[0]), IPv4: ap("100.64.0.2"), Hostname: "untagged2"},
		{User: new(users[0]), IPv4: ap("100.64.0.3"), Hostname: "tagged1", Tags: []string{"tag:server"}},
		{User: new(users[0]), IPv4: ap("100.64.0.4"), Hostname: "tagged2", Tags: []string{"tag:web"}},
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
	sshPolicy, err := policy.compileSSHPolicy("unused-server-url", users, node1, nodes.ViewSlice())
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
	sshPolicy2, err := policy.compileSSHPolicy("unused-server-url", users, node3, nodes.ViewSlice())
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
		{User: new(users[0]), IPv4: ap("100.64.0.1"), Hostname: "user1-device"},
		{User: new(users[0]), IPv4: ap("100.64.0.2"), Hostname: "user1-device2"},
		{User: new(users[1]), IPv4: ap("100.64.0.3"), Hostname: "user2-device"},
		{User: new(users[1]), IPv4: ap("100.64.0.4"), Hostname: "user2-router", Tags: []string{"tag:router"}},
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
	sshPolicy1, err := policy.compileSSHPolicy("unused-server-url", users, node1, nodes.ViewSlice())
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
	sshPolicyRouter, err := policy.compileSSHPolicy("unused-server-url", users, routerNode, nodes.ViewSlice())
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

// TestAutogroupSelfWithNonExistentUserInGroup verifies that when a group
// contains a non-existent user, partial resolution still works correctly.
// This reproduces the issue from https://github.com/juanfont/headscale/issues/2990
// where autogroup:self breaks when groups contain users that don't have
// registered nodes.
func TestAutogroupSelfWithNonExistentUserInGroup(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "superadmin"},
		{Model: gorm.Model{ID: 2}, Name: "admin"},
		{Model: gorm.Model{ID: 3}, Name: "direction"},
	}

	nodes := types.Nodes{
		// superadmin's device
		{ID: 1, User: new(users[0]), IPv4: ap("100.64.0.1"), Hostname: "superadmin-device"},
		// admin's device
		{ID: 2, User: new(users[1]), IPv4: ap("100.64.0.2"), Hostname: "admin-device"},
		// direction's device
		{ID: 3, User: new(users[2]), IPv4: ap("100.64.0.3"), Hostname: "direction-device"},
		// tagged servers
		{ID: 4, IPv4: ap("100.64.0.10"), Hostname: "common-server", Tags: []string{"tag:common"}},
		{ID: 5, IPv4: ap("100.64.0.11"), Hostname: "tech-server", Tags: []string{"tag:tech"}},
		{ID: 6, IPv4: ap("100.64.0.12"), Hostname: "privileged-server", Tags: []string{"tag:privileged"}},
	}

	policy := &Policy{
		Groups: Groups{
			// group:superadmin contains "phantom_user" who doesn't exist
			Group("group:superadmin"): []Username{Username("superadmin@"), Username("phantom_user@")},
			Group("group:admin"):      []Username{Username("admin@")},
			Group("group:direction"):  []Username{Username("direction@")},
		},
		TagOwners: TagOwners{
			Tag("tag:common"):     Owners{gp("group:superadmin")},
			Tag("tag:tech"):       Owners{gp("group:superadmin")},
			Tag("tag:privileged"): Owners{gp("group:superadmin")},
		},
		ACLs: []ACL{
			{
				// Rule 1: all groups -> tag:common
				Action:  "accept",
				Sources: []Alias{gp("group:superadmin"), gp("group:admin"), gp("group:direction")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(tp("tag:common"), tailcfg.PortRangeAny),
				},
			},
			{
				// Rule 2: superadmin + admin -> tag:tech
				Action:  "accept",
				Sources: []Alias{gp("group:superadmin"), gp("group:admin")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(tp("tag:tech"), tailcfg.PortRangeAny),
				},
			},
			{
				// Rule 3: superadmin -> tag:privileged + autogroup:self
				Action:  "accept",
				Sources: []Alias{gp("group:superadmin")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(tp("tag:privileged"), tailcfg.PortRangeAny),
					aliasWithPorts(agp("autogroup:self"), tailcfg.PortRangeAny),
				},
			},
		},
	}

	err := policy.validate()
	require.NoError(t, err)

	containsIP := func(rules []tailcfg.FilterRule, ip string) bool {
		addr := netip.MustParseAddr(ip)

		for _, rule := range rules {
			for _, dp := range rule.DstPorts {
				ipSet, err := util.ParseIPSet(dp.IP, nil)
				if err != nil {
					continue
				}

				if ipSet.Contains(addr) {
					return true
				}
			}
		}

		return false
	}

	containsSrcIP := func(rules []tailcfg.FilterRule, ip string) bool {
		addr := netip.MustParseAddr(ip)

		for _, rule := range rules {
			for _, srcIP := range rule.SrcIPs {
				ipSet, err := util.ParseIPSet(srcIP, nil)
				if err != nil {
					continue
				}

				if ipSet.Contains(addr) {
					return true
				}
			}
		}

		return false
	}

	// Test superadmin's device: should have rules with tag:common, tag:tech, tag:privileged destinations
	// and superadmin's IP should appear in sources (partial resolution of group:superadmin works)
	superadminNode := nodes[0].View()
	superadminRules, err := policy.compileFilterRulesForNode(users, superadminNode, nodes.ViewSlice())
	require.NoError(t, err)
	assert.True(t, containsIP(superadminRules, "100.64.0.10"), "rules should include tag:common server")
	assert.True(t, containsIP(superadminRules, "100.64.0.11"), "rules should include tag:tech server")
	assert.True(t, containsIP(superadminRules, "100.64.0.12"), "rules should include tag:privileged server")

	// Key assertion: superadmin's IP should appear as a source in rules
	// despite phantom_user in group:superadmin causing a partial resolution error
	assert.True(t, containsSrcIP(superadminRules, "100.64.0.1"),
		"superadmin's IP should appear in sources despite phantom_user in group:superadmin")

	// Test admin's device: admin is in group:admin which has NO phantom users.
	// The key bug was: when group:superadmin (with phantom_user) appeared as a source
	// alongside group:admin, the error from resolving group:superadmin caused its
	// partial result to be discarded via `continue`. With the fix, superadmin's IPs
	// from group:superadmin are retained alongside admin's IPs from group:admin.
	adminNode := nodes[1].View()
	adminRules, err := policy.compileFilterRulesForNode(users, adminNode, nodes.ViewSlice())
	require.NoError(t, err)

	// Rule 1 sources: [group:superadmin, group:admin, group:direction]
	// Without fix: group:superadmin discarded -> only admin + direction IPs in sources
	// With fix: superadmin IP preserved -> superadmin + admin + direction IPs in sources
	assert.True(t, containsIP(adminRules, "100.64.0.10"),
		"admin rules should include tag:common server (group:admin resolves correctly)")
	assert.True(t, containsSrcIP(adminRules, "100.64.0.1"),
		"superadmin's IP should be in sources for rules seen by admin (partial resolution preserved)")
	assert.True(t, containsSrcIP(adminRules, "100.64.0.2"),
		"admin's own IP should be in sources")

	// Test direction's device: similar to admin, verifies group:direction sources work
	directionNode := nodes[2].View()
	directionRules, err := policy.compileFilterRulesForNode(users, directionNode, nodes.ViewSlice())
	require.NoError(t, err)
	assert.True(t, containsIP(directionRules, "100.64.0.10"),
		"direction rules should include tag:common server")
	assert.True(t, containsSrcIP(directionRules, "100.64.0.3"),
		"direction's own IP should be in sources")
	// With fix: superadmin's IP preserved in rules that include group:superadmin
	assert.True(t, containsSrcIP(directionRules, "100.64.0.1"),
		"superadmin's IP should be in sources for rule 1 (partial resolution preserved)")
}

func TestMergeFilterRules(t *testing.T) {
	tests := []struct {
		name  string
		input []tailcfg.FilterRule
		want  []tailcfg.FilterRule
	}{
		{
			name:  "empty input",
			input: []tailcfg.FilterRule{},
			want:  []tailcfg.FilterRule{},
		},
		{
			name: "single rule unchanged",
			input: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
			},
		},
		{
			name: "merge two rules with same key",
			input: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP},
				},
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP},
				},
			},
		},
		{
			name: "different SrcIPs not merged",
			input: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
				{
					SrcIPs: []string{"100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
				{
					SrcIPs: []string{"100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
			},
		},
		{
			name: "different IPProto not merged",
			input: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 53, Last: 53}},
					},
					IPProto: []int{ProtocolUDP},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 53, Last: 53}},
					},
					IPProto: []int{ProtocolUDP},
				},
			},
		},
		{
			name: "DstPorts combined without deduplication",
			input: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						{IP: "100.64.0.2/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP},
				},
			},
		},
		{
			name: "merge three rules with same key",
			input: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32", "100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
				},
				{
					SrcIPs: []string{"100.64.0.1/32", "100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
				},
				{
					SrcIPs: []string{"100.64.0.1/32", "100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.4/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32", "100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						{IP: "100.64.0.4/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
					},
					IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeFilterRules(tt.input)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("mergeFilterRules() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCompileSSHPolicy_CheckPeriodVariants(t *testing.T) {
	users := types.Users{
		{Name: "user1", Model: gorm.Model{ID: 1}},
	}

	node := types.Node{
		Hostname: "device",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   new(users[0].ID),
		User:     new(users[0]),
	}

	nodes := types.Nodes{&node}

	// SaaS always sends SessionDuration=0 in the wire format
	// regardless of checkPeriod. The check period is resolved
	// server-side, not embedded in the SSHAction.
	tests := []struct {
		name        string
		checkPeriod *SSHCheckPeriod
	}{
		{
			name:        "nil period",
			checkPeriod: nil,
		},
		{
			name:        "always period",
			checkPeriod: &SSHCheckPeriod{Always: true},
		},
		{
			name:        "explicit 2h",
			checkPeriod: &SSHCheckPeriod{Duration: 2 * time.Hour},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &Policy{
				SSHs: []SSH{
					{
						Action:       SSHActionCheck,
						Sources:      SSHSrcAliases{up("user1@")},
						Destinations: SSHDstAliases{agp("autogroup:member")},
						Users:        SSHUsers{"root"},
						CheckPeriod:  tt.checkPeriod,
					},
				},
			}

			err := policy.validate()
			require.NoError(t, err)

			sshPolicy, err := policy.compileSSHPolicy(
				"http://test",
				users,
				node.View(),
				nodes.ViewSlice(),
			)
			require.NoError(t, err)
			require.NotNil(t, sshPolicy)
			require.Len(t, sshPolicy.Rules, 1)

			rule := sshPolicy.Rules[0]
			assert.Equal(t, time.Duration(0), rule.Action.SessionDuration)
			// Check params must NOT be in the URL; they are
			// resolved server-side via SSHCheckParams.
			assert.NotContains(t, rule.Action.HoldAndDelegate, "check_explicit")
			assert.NotContains(t, rule.Action.HoldAndDelegate, "check_period")
		})
	}
}

func TestIPSetToPrincipals(t *testing.T) {
	tests := []struct {
		name string
		ips  []string // IPs to add to the set
		want []*tailcfg.SSHPrincipal
	}{
		{
			name: "nil input",
			ips:  nil,
			want: nil,
		},
		{
			name: "single IPv4",
			ips:  []string{"100.64.0.1"},
			want: []*tailcfg.SSHPrincipal{{NodeIP: "100.64.0.1"}},
		},
		{
			name: "multiple IPs",
			ips:  []string{"100.64.0.1", "100.64.0.2"},
			want: []*tailcfg.SSHPrincipal{
				{NodeIP: "100.64.0.1"},
				{NodeIP: "100.64.0.2"},
			},
		},
		{
			name: "IPv6",
			ips:  []string{"fd7a:115c:a1e0::1"},
			want: []*tailcfg.SSHPrincipal{{NodeIP: "fd7a:115c:a1e0::1"}},
		},
		{
			name: "mixed IPv4 and IPv6",
			ips:  []string{"100.64.0.1", "fd7a:115c:a1e0::1"},
			want: []*tailcfg.SSHPrincipal{
				{NodeIP: "100.64.0.1"},
				{NodeIP: "fd7a:115c:a1e0::1"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ipSet *netipx.IPSet

			if tt.ips != nil {
				var builder netipx.IPSetBuilder

				for _, ip := range tt.ips {
					addr := netip.MustParseAddr(ip)
					builder.Add(addr)
				}

				var err error

				ipSet, err = builder.IPSet()
				require.NoError(t, err)
			}

			got := ipSetToPrincipals(ipSet)

			// Sort for deterministic comparison
			sortPrincipals := func(p []*tailcfg.SSHPrincipal) {
				slices.SortFunc(p, func(a, b *tailcfg.SSHPrincipal) int {
					if a.NodeIP < b.NodeIP {
						return -1
					}

					if a.NodeIP > b.NodeIP {
						return 1
					}

					return 0
				})
			}
			sortPrincipals(got)
			sortPrincipals(tt.want)

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ipSetToPrincipals() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSSHCheckParams(t *testing.T) {
	users := types.Users{
		{Name: "user1", Model: gorm.Model{ID: 1}},
		{Name: "user2", Model: gorm.Model{ID: 2}},
	}

	nodeUser1 := types.Node{
		ID:       1,
		Hostname: "user1-device",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   new(users[0].ID),
		User:     new(users[0]),
	}
	nodeUser2 := types.Node{
		ID:       2,
		Hostname: "user2-device",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   new(users[1].ID),
		User:     new(users[1]),
	}
	nodeTaggedServer := types.Node{
		ID:       3,
		Hostname: "tagged-server",
		IPv4:     createAddr("100.64.0.3"),
		UserID:   new(users[0].ID),
		User:     new(users[0]),
		Tags:     []string{"tag:server"},
	}

	nodes := types.Nodes{&nodeUser1, &nodeUser2, &nodeTaggedServer}

	tests := []struct {
		name       string
		policy     []byte
		srcID      types.NodeID
		dstID      types.NodeID
		wantPeriod time.Duration
		wantOK     bool
	}{
		{
			name: "explicit check period for tagged destination",
			policy: []byte(`{
				"tagOwners": {"tag:server": ["user1@"]},
				"ssh": [{
					"action": "check",
					"checkPeriod": "2h",
					"src": ["user2@"],
					"dst": ["tag:server"],
					"users": ["autogroup:nonroot"]
				}]
			}`),
			srcID:      types.NodeID(2),
			dstID:      types.NodeID(3),
			wantPeriod: 2 * time.Hour,
			wantOK:     true,
		},
		{
			name: "default period when checkPeriod omitted",
			policy: []byte(`{
				"tagOwners": {"tag:server": ["user1@"]},
				"ssh": [{
					"action": "check",
					"src": ["user2@"],
					"dst": ["tag:server"],
					"users": ["autogroup:nonroot"]
				}]
			}`),
			srcID:      types.NodeID(2),
			dstID:      types.NodeID(3),
			wantPeriod: SSHCheckPeriodDefault,
			wantOK:     true,
		},
		{
			name: "always check (checkPeriod always)",
			policy: []byte(`{
				"tagOwners": {"tag:server": ["user1@"]},
				"ssh": [{
					"action": "check",
					"checkPeriod": "always",
					"src": ["user2@"],
					"dst": ["tag:server"],
					"users": ["autogroup:nonroot"]
				}]
			}`),
			srcID:      types.NodeID(2),
			dstID:      types.NodeID(3),
			wantPeriod: 0,
			wantOK:     true,
		},
		{
			name: "no match when src not in rule",
			policy: []byte(`{
				"tagOwners": {"tag:server": ["user1@"]},
				"ssh": [{
					"action": "check",
					"src": ["user1@"],
					"dst": ["tag:server"],
					"users": ["autogroup:nonroot"]
				}]
			}`),
			srcID:  types.NodeID(2),
			dstID:  types.NodeID(3),
			wantOK: false,
		},
		{
			name: "no match when dst not in rule",
			policy: []byte(`{
				"tagOwners": {"tag:server": ["user1@"]},
				"ssh": [{
					"action": "check",
					"src": ["user2@"],
					"dst": ["tag:server"],
					"users": ["autogroup:nonroot"]
				}]
			}`),
			srcID:  types.NodeID(2),
			dstID:  types.NodeID(1),
			wantOK: false,
		},
		{
			name: "accept rule is not returned",
			policy: []byte(`{
				"tagOwners": {"tag:server": ["user1@"]},
				"ssh": [{
					"action": "accept",
					"src": ["user2@"],
					"dst": ["tag:server"],
					"users": ["autogroup:nonroot"]
				}]
			}`),
			srcID:  types.NodeID(2),
			dstID:  types.NodeID(3),
			wantOK: false,
		},
		{
			name: "autogroup:self matches same-user pair",
			policy: []byte(`{
				"ssh": [{
					"action": "check",
					"checkPeriod": "6h",
					"src": ["user1@"],
					"dst": ["autogroup:self"],
					"users": ["autogroup:nonroot"]
				}]
			}`),
			srcID:      types.NodeID(1),
			dstID:      types.NodeID(1),
			wantPeriod: 6 * time.Hour,
			wantOK:     true,
		},
		{
			name: "autogroup:self rejects cross-user pair",
			policy: []byte(`{
				"ssh": [{
					"action": "check",
					"src": ["user1@"],
					"dst": ["autogroup:self"],
					"users": ["autogroup:nonroot"]
				}]
			}`),
			srcID:  types.NodeID(1),
			dstID:  types.NodeID(2),
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewPolicyManager(tt.policy, users, nodes.ViewSlice())
			require.NoError(t, err)

			period, ok := pm.SSHCheckParams(tt.srcID, tt.dstID)
			assert.Equal(t, tt.wantOK, ok, "ok mismatch")

			if tt.wantOK {
				assert.Equal(t, tt.wantPeriod, period, "period mismatch")
			}
		})
	}
}

func TestResolveLocalparts(t *testing.T) {
	tests := []struct {
		name    string
		entries []SSHUser
		users   types.Users
		want    map[uint]string
	}{
		{
			name:    "no entries",
			entries: nil,
			users:   types.Users{{Name: "alice", Email: "alice@example.com", Model: gorm.Model{ID: 1}}},
			want:    nil,
		},
		{
			name:    "single match",
			entries: []SSHUser{"localpart:*@example.com"},
			users: types.Users{
				{Name: "alice", Email: "alice@example.com", Model: gorm.Model{ID: 1}},
			},
			want: map[uint]string{1: "alice"},
		},
		{
			name:    "domain mismatch",
			entries: []SSHUser{"localpart:*@other.com"},
			users: types.Users{
				{Name: "alice", Email: "alice@example.com", Model: gorm.Model{ID: 1}},
			},
			want: map[uint]string{},
		},
		{
			name:    "case insensitive domain",
			entries: []SSHUser{"localpart:*@EXAMPLE.COM"},
			users: types.Users{
				{Name: "alice", Email: "alice@example.com", Model: gorm.Model{ID: 1}},
			},
			want: map[uint]string{1: "alice"},
		},
		{
			name:    "user without email skipped",
			entries: []SSHUser{"localpart:*@example.com"},
			users: types.Users{
				{Name: "cli-user", Model: gorm.Model{ID: 1}},
			},
			want: map[uint]string{},
		},
		{
			name: "multiple domains multiple users",
			entries: []SSHUser{
				"localpart:*@example.com",
				"localpart:*@other.com",
			},
			users: types.Users{
				{Name: "alice", Email: "alice@example.com", Model: gorm.Model{ID: 1}},
				{Name: "bob", Email: "bob@other.com", Model: gorm.Model{ID: 2}},
				{Name: "charlie", Email: "charlie@nope.com", Model: gorm.Model{ID: 3}},
			},
			want: map[uint]string{1: "alice", 2: "bob"},
		},
		{
			name:    "special chars in local part",
			entries: []SSHUser{"localpart:*@example.com"},
			users: types.Users{
				{Name: "d", Email: "dave+ssh@example.com", Model: gorm.Model{ID: 1}},
			},
			want: map[uint]string{1: "dave+ssh"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveLocalparts(tt.entries, tt.users)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("resolveLocalparts() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGroupSourcesByUser(t *testing.T) {
	alice := types.User{
		Name: "alice", Email: "alice@example.com",
		Model: gorm.Model{ID: 1},
	}
	bob := types.User{
		Name: "bob", Email: "bob@example.com",
		Model: gorm.Model{ID: 2},
	}

	nodeAlice := types.Node{
		Hostname: "alice-dev",
		IPv4:     createAddr("100.64.0.1"),
		UserID:   &alice.ID,
		User:     &alice,
	}
	nodeBob := types.Node{
		Hostname: "bob-dev",
		IPv4:     createAddr("100.64.0.2"),
		UserID:   &bob.ID,
		User:     &bob,
	}
	nodeTagged := types.Node{
		Hostname: "tagged",
		IPv4:     createAddr("100.64.0.3"),
		UserID:   &alice.ID,
		User:     &alice,
		Tags:     []string{"tag:server"},
	}

	// Build an IPSet that includes all node IPs
	allIPs := func() ResolvedAddresses {
		var b netipx.IPSetBuilder
		b.AddPrefix(netip.MustParsePrefix("100.64.0.0/24"))

		s, _ := b.IPSet()
		r, _ := newResolvedAddresses(s, nil)

		return r
	}()

	tests := []struct {
		name          string
		nodes         types.Nodes
		srcIPs        ResolvedAddresses
		wantUIDs      []uint
		wantUserCount int
		wantHasTagged bool
		wantTaggedLen int
		wantAliceIP   string
		wantBobIP     string
		wantTaggedIP  string
	}{
		{
			name:          "user-owned only",
			nodes:         types.Nodes{&nodeAlice, &nodeBob},
			srcIPs:        allIPs,
			wantUIDs:      []uint{1, 2},
			wantUserCount: 2,
			wantAliceIP:   "100.64.0.1",
			wantBobIP:     "100.64.0.2",
		},
		{
			name:          "mixed user and tagged",
			nodes:         types.Nodes{&nodeAlice, &nodeTagged},
			srcIPs:        allIPs,
			wantUIDs:      []uint{1},
			wantUserCount: 1,
			wantHasTagged: true,
			wantTaggedLen: 1,
			wantAliceIP:   "100.64.0.1",
			wantTaggedIP:  "100.64.0.3",
		},
		{
			name:          "tagged only",
			nodes:         types.Nodes{&nodeTagged},
			srcIPs:        allIPs,
			wantUIDs:      nil,
			wantUserCount: 0,
			wantHasTagged: true,
			wantTaggedLen: 1,
		},
		{
			name:  "node not in srcIPs excluded",
			nodes: types.Nodes{&nodeAlice, &nodeBob},
			srcIPs: func() ResolvedAddresses {
				var b netipx.IPSetBuilder
				b.Add(netip.MustParseAddr("100.64.0.1")) // only alice

				s, _ := b.IPSet()
				r, _ := newResolvedAddresses(s, nil)

				return r
			}(),
			wantUIDs:      []uint{1},
			wantUserCount: 1,
			wantAliceIP:   "100.64.0.1",
		},
		{
			name:          "sorted by user ID",
			nodes:         types.Nodes{&nodeBob, &nodeAlice}, // reverse order
			srcIPs:        allIPs,
			wantUIDs:      []uint{1, 2}, // still sorted
			wantUserCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sortedUIDs, byUser, tagged := groupSourcesByUser(
				tt.nodes.ViewSlice(), tt.srcIPs,
			)

			assert.Equal(t, tt.wantUIDs, sortedUIDs, "sortedUIDs")
			assert.Len(t, byUser, tt.wantUserCount, "byUser count")

			if tt.wantHasTagged {
				assert.Len(t, tagged, tt.wantTaggedLen, "tagged count")
			} else {
				assert.Empty(t, tagged, "tagged should be empty")
			}

			if tt.wantAliceIP != "" {
				require.Contains(t, byUser, uint(1))
				assert.Equal(t, tt.wantAliceIP, byUser[1][0].NodeIP)
			}

			if tt.wantBobIP != "" {
				require.Contains(t, byUser, uint(2))
				assert.Equal(t, tt.wantBobIP, byUser[2][0].NodeIP)
			}

			if tt.wantTaggedIP != "" {
				require.NotEmpty(t, tagged)
				assert.Equal(t, tt.wantTaggedIP, tagged[0].NodeIP)
			}
		})
	}
}

func TestCompanionCapGrantRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		dstIPStrings []string
		srcPrefixes  []netip.Prefix
		capMap       tailcfg.PeerCapMap
		want         []tailcfg.FilterRule
	}{
		{
			name:         "drive produces drive-sharer companion with reversed IPs",
			dstIPStrings: []string{"100.64.0.1"},
			srcPrefixes:  []netip.Prefix{mp("100.64.0.2/32")},
			capMap: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityTaildrive: {tailcfg.RawMessage(`{}`)},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{mp("100.64.0.2/32")},
							CapMap: tailcfg.PeerCapMap{
								tailcfg.PeerCapabilityTaildriveSharer: nil,
							},
						},
					},
				},
			},
		},
		{
			name:         "relay produces relay-target companion with reversed IPs",
			dstIPStrings: []string{"100.64.0.10"},
			srcPrefixes:  []netip.Prefix{mp("100.64.0.20/32")},
			capMap: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityRelay: {tailcfg.RawMessage(`{}`)},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.10"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{mp("100.64.0.20/32")},
							CapMap: tailcfg.PeerCapMap{
								tailcfg.PeerCapabilityRelayTarget: nil,
							},
						},
					},
				},
			},
		},
		{
			name:         "both drive and relay sorted by original cap name",
			dstIPStrings: []string{"100.64.0.1"},
			srcPrefixes:  []netip.Prefix{mp("100.64.0.2/32")},
			capMap: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityRelay:     {tailcfg.RawMessage(`{}`)},
				tailcfg.PeerCapabilityTaildrive: {tailcfg.RawMessage(`{}`)},
			},
			want: []tailcfg.FilterRule{
				{
					// drive < relay alphabetically
					SrcIPs: []string{"100.64.0.1"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{mp("100.64.0.2/32")},
							CapMap: tailcfg.PeerCapMap{
								tailcfg.PeerCapabilityTaildriveSharer: nil,
							},
						},
					},
				},
				{
					SrcIPs: []string{"100.64.0.1"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{mp("100.64.0.2/32")},
							CapMap: tailcfg.PeerCapMap{
								tailcfg.PeerCapabilityRelayTarget: nil,
							},
						},
					},
				},
			},
		},
		{
			name:         "unknown capability produces no companion",
			dstIPStrings: []string{"100.64.0.1"},
			srcPrefixes:  []netip.Prefix{mp("100.64.0.2/32")},
			capMap: tailcfg.PeerCapMap{
				"example.com/cap/custom": {tailcfg.RawMessage(`{}`)},
			},
			want: []tailcfg.FilterRule{},
		},
		{
			name:         "companion has nil CapMap value not original",
			dstIPStrings: []string{"100.64.0.5"},
			srcPrefixes:  []netip.Prefix{mp("100.64.0.6/32")},
			capMap: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityTaildrive: {
					tailcfg.RawMessage(`{"access":"rw"}`),
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.5"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{mp("100.64.0.6/32")},
							CapMap: tailcfg.PeerCapMap{
								tailcfg.PeerCapabilityTaildriveSharer: nil,
							},
						},
					},
				},
			},
		},
		{
			name: "multiple IP ranges reversed correctly",
			dstIPStrings: []string{
				"100.64.0.10",
				"100.64.0.11",
			},
			srcPrefixes: []netip.Prefix{
				mp("100.64.0.20/32"),
				mp("100.64.0.21/32"),
			},
			capMap: tailcfg.PeerCapMap{
				tailcfg.PeerCapabilityRelay: {tailcfg.RawMessage(`{}`)},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.10", "100.64.0.11"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{
								mp("100.64.0.20/32"),
								mp("100.64.0.21/32"),
							},
							CapMap: tailcfg.PeerCapMap{
								tailcfg.PeerCapabilityRelayTarget: nil,
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := companionCapGrantRules(tt.dstIPStrings, tt.srcPrefixes, tt.capMap)
			if diff := cmp.Diff(tt.want, got, util.Comparers...); diff != "" {
				t.Errorf("companionCapGrantRules() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSourcesHaveWildcard(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		srcs Aliases
		want bool
	}{
		{
			name: "wildcard only",
			srcs: Aliases{Wildcard},
			want: true,
		},
		{
			name: "wildcard mixed with specific",
			srcs: Aliases{up("user@"), Wildcard, tp("tag:server")},
			want: true,
		},
		{
			name: "no wildcard",
			srcs: Aliases{up("user@"), tp("tag:server")},
			want: false,
		},
		{
			name: "empty",
			srcs: Aliases{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, sourcesHaveWildcard(tt.srcs))
		})
	}
}

func TestSourcesHaveDangerAll(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		srcs Aliases
		want bool
	}{
		{
			name: "danger-all only",
			srcs: Aliases{agp(string(AutoGroupDangerAll))},
			want: true,
		},
		{
			name: "danger-all mixed with others",
			srcs: Aliases{up("user@"), agp(string(AutoGroupDangerAll))},
			want: true,
		},
		{
			name: "no danger-all",
			srcs: Aliases{up("user@"), agp(string(AutoGroupMember))},
			want: false,
		},
		{
			name: "empty",
			srcs: Aliases{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, sourcesHaveDangerAll(tt.srcs))
		})
	}
}

func TestSrcIPsWithRoutes(t *testing.T) {
	t.Parallel()

	// Build a resolved address set for a single IP.
	var b netipx.IPSetBuilder
	b.AddPrefix(netip.MustParsePrefix("100.64.0.1/32"))

	resolved, err := newResolved(&b)
	require.NoError(t, err)

	// Node with approved subnet route.
	nodeWithRoutes := types.Nodes{
		&types.Node{
			IPv4: ap("100.64.0.5"),
			Hostinfo: &tailcfg.Hostinfo{
				RoutableIPs: []netip.Prefix{
					mp("10.0.0.0/24"),
				},
			},
			ApprovedRoutes: []netip.Prefix{
				mp("10.0.0.0/24"),
			},
		},
	}.ViewSlice()

	emptyNodes := types.Nodes{}.ViewSlice()

	tests := []struct {
		name         string
		resolved     ResolvedAddresses
		hasWildcard  bool
		hasDangerAll bool
		nodes        func() []string
		want         []string
	}{
		{
			name:         "danger-all returns star regardless",
			resolved:     resolved,
			hasWildcard:  false,
			hasDangerAll: true,
			want:         []string{"*"},
		},
		{
			name:         "danger-all takes precedence over wildcard",
			resolved:     resolved,
			hasWildcard:  true,
			hasDangerAll: true,
			want:         []string{"*"},
		},
		{
			name:         "wildcard appends approved subnet routes",
			resolved:     resolved,
			hasWildcard:  true,
			hasDangerAll: false,
		},
		{
			name:         "neither returns resolved addrs only",
			resolved:     resolved,
			hasWildcard:  false,
			hasDangerAll: false,
			want:         []string{"100.64.0.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			nodes := emptyNodes
			if tt.hasWildcard && !tt.hasDangerAll {
				nodes = nodeWithRoutes
			}

			got := srcIPsWithRoutes(tt.resolved, tt.hasWildcard, tt.hasDangerAll, nodes)

			if tt.hasDangerAll {
				assert.Equal(t, []string{"*"}, got)
			} else if tt.hasWildcard {
				assert.Contains(t, got, "100.64.0.1", "should contain the resolved IP")
				assert.Contains(t, got, "10.0.0.0/24", "should contain approved subnet route")
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestFilterAllowAllFix(t *testing.T) {
	t.Parallel()

	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "testuser"},
	}
	nodes := types.Nodes{
		&types.Node{
			IPv4:     ap("100.64.0.1"),
			User:     &users[0],
			Hostinfo: &tailcfg.Hostinfo{},
		},
	}.ViewSlice()

	tests := []struct {
		name            string
		pol             *Policy
		wantFilterAllow bool
	}{
		{
			name: "grants only should not return FilterAllowAll",
			pol: &Policy{
				Grants: []Grant{
					{
						Sources:      Aliases{up("testuser@")},
						Destinations: Aliases{pp("100.64.0.1/32")},
						InternetProtocols: []ProtocolPort{
							{Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}},
						},
					},
				},
			},
			wantFilterAllow: false,
		},
		{
			name:            "nil ACLs and nil grants returns FilterAllowAll",
			pol:             &Policy{},
			wantFilterAllow: true,
		},
		{
			name: "nil ACLs and empty grants denies all",
			pol: &Policy{
				Grants: []Grant{},
			},
			wantFilterAllow: false,
		},
		{
			name: "empty ACLs and nil grants denies all",
			pol: &Policy{
				ACLs: []ACL{},
			},
			wantFilterAllow: false,
		},
		{
			name: "empty ACLs and empty grants denies all",
			pol: &Policy{
				ACLs:   []ACL{},
				Grants: []Grant{},
			},
			wantFilterAllow: false,
		},
		{
			name: "both ACLs and grants should not return FilterAllowAll",
			pol: &Policy{
				ACLs: []ACL{
					{
						Action:  "accept",
						Sources: Aliases{up("testuser@")},
						Destinations: []AliasWithPorts{
							aliasWithPorts(pp("100.64.0.1/32"), tailcfg.PortRangeAny),
						},
					},
				},
				Grants: []Grant{
					{
						Sources:      Aliases{up("testuser@")},
						Destinations: Aliases{pp("100.64.0.1/32")},
						InternetProtocols: []ProtocolPort{
							{Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}},
						},
					},
				},
			},
			wantFilterAllow: false,
		},
		{
			name:            "nil policy returns FilterAllowAll",
			pol:             nil,
			wantFilterAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rules, err := tt.pol.compileFilterRules(users, nodes)
			require.NoError(t, err)

			isFilterAllowAll := cmp.Diff(tailcfg.FilterAllowAll, rules) == ""
			assert.Equal(t, tt.wantFilterAllow, isFilterAllowAll,
				"FilterAllowAll mismatch: got rules=%v", rules)
		})
	}
}

func TestCompileViaGrant(t *testing.T) {
	t.Parallel()

	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "testuser"},
	}

	allPorts := []ProtocolPort{
		{Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}},
	}

	// Node matching via tag with approved subnet routes.
	viaNode := &types.Node{
		IPv4: ap("100.64.0.1"),
		User: &users[0],
		Tags: []string{"tag:relay"},
		Hostinfo: &tailcfg.Hostinfo{
			RoutableIPs: []netip.Prefix{
				mp("10.0.0.0/24"),
			},
		},
		ApprovedRoutes: []netip.Prefix{
			mp("10.0.0.0/24"),
		},
	}

	// Node matching via tag with exit routes (0.0.0.0/0, ::/0).
	exitNode := &types.Node{
		IPv4: ap("100.64.0.2"),
		User: &users[0],
		Tags: []string{"tag:exit"},
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
	}

	// Node matching via tag but no advertised routes.
	taggedNoRoutes := &types.Node{
		IPv4:     ap("100.64.0.3"),
		User:     &users[0],
		Tags:     []string{"tag:relay"},
		Hostinfo: &tailcfg.Hostinfo{},
	}

	// Node not matching any via tag.
	nonViaNode := &types.Node{
		IPv4:     ap("100.64.0.4"),
		User:     &users[0],
		Hostinfo: &tailcfg.Hostinfo{},
	}

	// Source node with IP.
	srcNode := &types.Node{
		IPv4:     ap("100.64.0.10"),
		User:     &users[0],
		Hostinfo: &tailcfg.Hostinfo{},
	}

	tests := []struct {
		name    string
		grant   Grant
		node    *types.Node
		nodes   types.Nodes
		pol     *Policy
		want    []tailcfg.FilterRule
		wantErr error
	}{
		{
			name: "node not matching via tag returns nil",
			grant: Grant{
				Sources:           Aliases{up("testuser@")},
				Destinations:      Aliases{pp("10.0.0.0/24")},
				InternetProtocols: allPorts,
				Via:               []Tag{"tag:relay"},
			},
			node:  nonViaNode,
			nodes: types.Nodes{nonViaNode, srcNode},
			pol:   &Policy{},
			want:  nil,
		},
		{
			name: "node matching via tag no advertised routes returns nil",
			grant: Grant{
				Sources:           Aliases{up("testuser@")},
				Destinations:      Aliases{pp("10.0.0.0/24")},
				InternetProtocols: allPorts,
				Via:               []Tag{"tag:relay"},
			},
			node:  taggedNoRoutes,
			nodes: types.Nodes{taggedNoRoutes, srcNode},
			pol:   &Policy{},
			want:  nil,
		},
		{
			name: "node matching via tag with matching subnet routes returns rules",
			grant: Grant{
				Sources:           Aliases{up("testuser@")},
				Destinations:      Aliases{pp("10.0.0.0/24")},
				InternetProtocols: allPorts,
				Via:               []Tag{"tag:relay"},
			},
			node:  viaNode,
			nodes: types.Nodes{viaNode, srcNode},
			pol:   &Policy{},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.10"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "10.0.0.0/24", Ports: tailcfg.PortRangeAny},
					},
				},
			},
		},
		{
			// autogroup:internet via grants do NOT produce PacketFilter rules
			// on exit nodes. Tailscale SaaS handles exit traffic forwarding
			// through the client's exit node mechanism, not PacketFilter.
			// Verified by golden captures GRANT-V14 through GRANT-V36.
			name: "autogroup:internet with exit routes produces no rules",
			grant: Grant{
				Sources:           Aliases{up("testuser@")},
				Destinations:      Aliases{agp(string(AutoGroupInternet))},
				InternetProtocols: allPorts,
				Via:               []Tag{"tag:exit"},
			},
			node:  exitNode,
			nodes: types.Nodes{exitNode, srcNode},
			pol:   &Policy{},
			want:  nil,
		},
		{
			name: "autogroup:internet without exit routes returns nil",
			grant: Grant{
				Sources:           Aliases{up("testuser@")},
				Destinations:      Aliases{agp(string(AutoGroupInternet))},
				InternetProtocols: allPorts,
				Via:               []Tag{"tag:relay"},
			},
			node:  viaNode,
			nodes: types.Nodes{viaNode, srcNode},
			pol:   &Policy{},
			want:  nil,
		},
		{
			name: "autogroup:self in sources returns errSelfInSources",
			grant: Grant{
				Sources:           Aliases{agp(string(AutoGroupSelf))},
				Destinations:      Aliases{pp("10.0.0.0/24")},
				InternetProtocols: allPorts,
				Via:               []Tag{"tag:relay"},
			},
			node:    viaNode,
			nodes:   types.Nodes{viaNode, srcNode},
			pol:     &Policy{},
			want:    nil,
			wantErr: errSelfInSources,
		},
		{
			name: "wildcard sources include subnet routes in SrcIPs",
			grant: Grant{
				Sources:           Aliases{Wildcard},
				Destinations:      Aliases{pp("10.0.0.0/24")},
				InternetProtocols: allPorts,
				Via:               []Tag{"tag:relay"},
			},
			node:  viaNode,
			nodes: types.Nodes{viaNode, srcNode},
			pol:   &Policy{},
		},
		{
			name: "danger-all sources produce SrcIPs star",
			grant: Grant{
				Sources:           Aliases{agp(string(AutoGroupDangerAll))},
				Destinations:      Aliases{pp("10.0.0.0/24")},
				InternetProtocols: allPorts,
				Via:               []Tag{"tag:relay"},
			},
			node:  viaNode,
			nodes: types.Nodes{viaNode, srcNode},
			pol:   &Policy{},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"*"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "10.0.0.0/24", Ports: tailcfg.PortRangeAny},
					},
				},
			},
		},
		{
			name: "app-only via grant with no ip field returns nil",
			grant: Grant{
				Sources:      Aliases{up("testuser@")},
				Destinations: Aliases{pp("10.0.0.0/24")},
				App: tailcfg.PeerCapMap{
					tailcfg.PeerCapabilityRelay: {tailcfg.RawMessage(`{}`)},
				},
				Via: []Tag{"tag:relay"},
			},
			node:  viaNode,
			nodes: types.Nodes{viaNode, srcNode},
			pol:   &Policy{},
			want:  nil,
		},
		{
			name: "multiple destinations some matching some not",
			grant: Grant{
				Sources: Aliases{up("testuser@")},
				Destinations: Aliases{
					pp("10.0.0.0/24"),    // matches viaNode route
					pp("192.168.0.0/16"), // does not match viaNode route
				},
				InternetProtocols: allPorts,
				Via:               []Tag{"tag:relay"},
			},
			node:  viaNode,
			nodes: types.Nodes{viaNode, srcNode},
			pol:   &Policy{},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.10"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "10.0.0.0/24", Ports: tailcfg.PortRangeAny},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			nodeView := tt.node.View()
			nodesSlice := tt.nodes.ViewSlice()

			cg, err := tt.pol.compileOneGrant(tt.grant, users, nodesSlice)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)

			var got []tailcfg.FilterRule
			if cg != nil {
				got = compileViaForNode(cg, nodeView)
			}

			if tt.name == "wildcard sources include subnet routes in SrcIPs" {
				// Wildcard resolves to CGNAT ranges; just check the route is appended.
				require.Len(t, got, 1)
				assert.Contains(t, got[0].SrcIPs, "10.0.0.0/24",
					"wildcard SrcIPs should include approved subnet route")

				return
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("compileViaGrant() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCompileGrantWithAutogroupSelf_GrantPaths(t *testing.T) {
	t.Parallel()

	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	node1 := &types.Node{
		User:     new(users[0]),
		IPv4:     ap("100.64.0.1"),
		Hostinfo: &tailcfg.Hostinfo{},
	}
	node2 := &types.Node{
		User:     new(users[0]),
		IPv4:     ap("100.64.0.2"),
		Hostinfo: &tailcfg.Hostinfo{},
	}
	node3 := &types.Node{
		User:     new(users[1]),
		IPv4:     ap("100.64.0.3"),
		Hostinfo: &tailcfg.Hostinfo{},
	}
	taggedNode := &types.Node{
		User:     &users[0],
		IPv4:     ap("100.64.0.10"),
		Tags:     []string{"tag:server"},
		Hostinfo: &tailcfg.Hostinfo{},
	}

	allNodes := types.Nodes{node1, node2, node3, taggedNode}

	allPorts := []ProtocolPort{
		{Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}},
	}

	tests := []struct {
		name    string
		grant   Grant
		node    *types.Node
		pol     *Policy
		want    []tailcfg.FilterRule
		wantErr error
	}{
		{
			name: "empty sources produces no rules",
			grant: Grant{
				Sources:           Aliases{},
				Destinations:      Aliases{pp("100.64.0.3/32")},
				InternetProtocols: allPorts,
			},
			node: node1,
			pol:  &Policy{},
			want: nil,
		},
		{
			name: "empty destinations produces no rules",
			grant: Grant{
				Sources:           Aliases{up("user1@")},
				Destinations:      Aliases{},
				InternetProtocols: allPorts,
			},
			node: node1,
			pol:  &Policy{},
			want: nil,
		},
		{
			name: "autogroup:self in sources returns errSelfInSources",
			grant: Grant{
				Sources:           Aliases{agp(string(AutoGroupSelf))},
				Destinations:      Aliases{pp("100.64.0.3/32")},
				InternetProtocols: allPorts,
			},
			node:    node1,
			pol:     &Policy{},
			wantErr: errSelfInSources,
		},
		{
			name: "autogroup:self destination for tagged node is skipped",
			grant: Grant{
				Sources:           Aliases{up("user1@")},
				Destinations:      Aliases{agp(string(AutoGroupSelf))},
				InternetProtocols: allPorts,
			},
			node: taggedNode,
			pol:  &Policy{},
			want: nil,
		},
		{
			name: "autogroup:self destination for untagged node produces same-user devices",
			grant: Grant{
				Sources:           Aliases{up("user1@")},
				Destinations:      Aliases{agp(string(AutoGroupSelf))},
				InternetProtocols: allPorts,
			},
			node: node1,
			pol:  &Policy{},
		},
		{
			name: "combined IP and App grant produces both DstPorts and CapGrant rules",
			grant: Grant{
				Sources:      Aliases{up("user1@")},
				Destinations: Aliases{pp("100.64.0.3/32")},
				InternetProtocols: []ProtocolPort{
					{Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}},
				},
				App: tailcfg.PeerCapMap{
					"example.com/cap/custom": {tailcfg.RawMessage(`{}`)},
				},
			},
			node: node1,
			pol:  &Policy{},
		},
		{
			name: "danger-all in sources produces SrcIPs star",
			grant: Grant{
				Sources:           Aliases{agp(string(AutoGroupDangerAll))},
				Destinations:      Aliases{pp("100.64.0.3/32")},
				InternetProtocols: allPorts,
			},
			node: node1,
			pol:  &Policy{},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"*"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3", Ports: tailcfg.PortRangeAny},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			nodeView := tt.node.View()
			nodesSlice := allNodes.ViewSlice()
			userIdx := buildUserNodeIndex(nodesSlice)

			cg, err := tt.pol.compileOneGrant(
				tt.grant, users, nodesSlice,
			)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)

			var got []tailcfg.FilterRule
			if cg != nil {
				got = append(got, cg.rules...)
				got = append(got, compileAutogroupSelf(cg, nodeView, userIdx)...)
				got = mergeFilterRules(got)
			}

			switch tt.name {
			case "autogroup:self destination for untagged node produces same-user devices":
				// Should produce rules; sources and destinations should only
				// include user1's untagged devices (node1 and node2).
				// IPs are merged into ranges by IPSet (e.g. "100.64.0.1-100.64.0.2").
				require.NotEmpty(t, got, "expected rules for autogroup:self")
				rule := got[0]
				// SrcIPs from IPSet may be a merged range.
				require.Len(t, rule.SrcIPs, 1)
				assert.Equal(t, "100.64.0.1-100.64.0.2", rule.SrcIPs[0],
					"SrcIPs should contain merged range for user1 untagged devices")

				var destIPs []string
				for _, dp := range rule.DstPorts {
					destIPs = append(destIPs, dp.IP)
				}

				// DstPorts use individual IPs (not IPSet ranges).
				assert.ElementsMatch(t, []string{"100.64.0.1", "100.64.0.2"}, destIPs,
					"DstPorts should be user1 untagged devices only")

			case "combined IP and App grant produces both DstPorts and CapGrant rules":
				hasDstPorts := false
				hasCapGrant := false

				for _, rule := range got {
					if len(rule.DstPorts) > 0 {
						hasDstPorts = true
					}

					if len(rule.CapGrant) > 0 {
						hasCapGrant = true
					}
				}

				assert.True(t, hasDstPorts, "should have rules with DstPorts")
				assert.True(t, hasCapGrant, "should have rules with CapGrant")

			default:
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("compileGrantWithAutogroupSelf() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestDestinationsToNetPortRange_AutogroupInternet(t *testing.T) {
	t.Parallel()

	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "testuser"},
	}
	nodes := types.Nodes{
		&types.Node{
			IPv4:     ap("100.64.0.1"),
			User:     &users[0],
			Hostinfo: &tailcfg.Hostinfo{},
		},
	}.ViewSlice()

	pol := &Policy{}
	ports := []tailcfg.PortRange{tailcfg.PortRangeAny}

	tests := []struct {
		name     string
		dests    Aliases
		wantLen  int
		wantStar bool
	}{
		{
			name:    "autogroup:internet produces no DstPorts",
			dests:   Aliases{agp(string(AutoGroupInternet))},
			wantLen: 0,
		},
		{
			name:     "wildcard produces DstPorts with star",
			dests:    Aliases{Wildcard},
			wantLen:  1,
			wantStar: true,
		},
		{
			name:    "explicit prefix produces DstPorts",
			dests:   Aliases{pp("100.64.0.1/32")},
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := pol.destinationsToNetPortRange(users, nodes, tt.dests, ports)
			assert.Len(t, got, tt.wantLen)

			if tt.wantStar && len(got) > 0 {
				assert.Equal(t, "*", got[0].IP)
			}

			if !tt.wantStar && tt.wantLen > 0 && len(got) > 0 {
				assert.NotEqual(t, "*", got[0].IP)
			}
		})
	}
}
