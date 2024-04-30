package policy

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"go4.org/netipx"
	"gopkg.in/check.v1"
	"tailscale.com/tailcfg"
)

var iap = func(ipStr string) *netip.Addr {
	ip := netip.MustParseAddr(ipStr)
	return &ip
}

func Test(t *testing.T) {
	check.TestingT(t)
}

var _ = check.Suite(&Suite{})

type Suite struct{}

func (s *Suite) TestWrongPath(c *check.C) {
	_, err := LoadACLPolicyFromPath("asdfg")
	c.Assert(err, check.NotNil)
}

func TestParsing(t *testing.T) {
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
		{
			name:   "valid-hujson-invalid-content",
			format: "hujson",
			acl: `
{
  "valid_json": true,
  "but_a_policy_though": false
}
				`,
			want:    []tailcfg.FilterRule{},
			wantErr: true,
		},
		{
			name:   "invalid-cidr",
			format: "hujson",
			acl: `
{"example-host-1": "100.100.100.100/42"}
				`,
			want:    []tailcfg.FilterRule{},
			wantErr: true,
		},
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
			"testuser",
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
				"testuser",
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
			name:   "port-wildcard-yaml",
			format: "yaml",
			acl: `
---
hosts:
  host-1: 100.100.100.100/32
  subnet-1: 100.100.101.100/24
acls:
  - action: accept
    src:
      - "*"
    dst:
      - host-1:*
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
			name:   "ipv6-yaml",
			format: "yaml",
			acl: `
---
hosts:
  host-1: 100.100.100.100/32
  subnet-1: 100.100.101.100/24
acls:
  - action: accept
    src:
      - "*"
    dst:
      - host-1:*
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
			pol, err := LoadACLPolicyFromBytes([]byte(tt.acl), tt.format)

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

			rules, err := pol.CompileFilterRules(types.Nodes{
				&types.Node{
					IPv4: iap("100.100.100.100"),
				},
				&types.Node{
					IPv4: iap("200.200.200.200"),
					User: types.User{
						Name: "testuser",
					},
					Hostinfo: &tailcfg.Hostinfo{},
				},
			})

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

func (s *Suite) TestRuleInvalidGeneration(c *check.C) {
	acl := []byte(`
{
	// Declare static groups of users beyond those in the identity service.
	"groups": {
		"group:example": [
			"user1@example.com",
			"user2@example.com",
		],
	},
	// Declare hostname aliases to use in place of IP addresses or subnets.
	"hosts": {
		"example-host-1": "100.100.100.100",
		"example-host-2": "100.100.101.100/24",
	},
	// Define who is allowed to use which tags.
	"tagOwners": {
		// Everyone in the montreal-admins or global-admins group are
		// allowed to tag servers as montreal-webserver.
		"tag:montreal-webserver": [
			"group:montreal-admins",
			"group:global-admins",
		],
		// Only a few admins are allowed to create API servers.
		"tag:api-server": [
			"group:global-admins",
			"example-host-1",
		],
	},
	// Access control lists.
	"acls": [
		// Engineering users, plus the president, can access port 22 (ssh)
		// and port 3389 (remote desktop protocol) on all servers, and all
		// ports on git-server or ci-server.
		{
			"action": "accept",
			"src": [
				"group:engineering",
				"president@example.com"
			],
			"dst": [
				"*:22,3389",
				"git-server:*",
				"ci-server:*"
			],
		},
		// Allow engineer users to access any port on a device tagged with
		// tag:production.
		{
			"action": "accept",
			"src": [
				"group:engineers"
			],
			"dst": [
				"tag:production:*"
			],
		},
		// Allow servers in the my-subnet host and 192.168.1.0/24 to access hosts
		// on both networks.
		{
			"action": "accept",
			"src": [
				"my-subnet",
				"192.168.1.0/24"
			],
			"dst": [
				"my-subnet:*",
				"192.168.1.0/24:*"
			],
		},
		// Allow every user of your network to access anything on the network.
		// Comment out this section if you want to define specific ACL
		// restrictions above.
		{
			"action": "accept",
			"src": [
				"*"
			],
			"dst": [
				"*:*"
			],
		},
		// All users in Montreal are allowed to access the Montreal web
		// servers.
		{
			"action": "accept",
			"src": [
				"group:montreal-users"
			],
			"dst": [
				"tag:montreal-webserver:80,443"
			],
		},
		// Montreal web servers are allowed to make outgoing connections to
		// the API servers, but only on https port 443.
		// In contrast, this doesn't grant API servers the right to initiate
		// any connections.
		{
			"action": "accept",
			"src": [
				"tag:montreal-webserver"
			],
			"dst": [
				"tag:api-server:443"
			],
		},
	],
	// Declare tests to check functionality of ACL rules
	"tests": [
		{
			"src": "user1@example.com",
			"accept": [
				"example-host-1:22",
				"example-host-2:80"
			],
			"deny": [
				"exapmle-host-2:100"
			],
		},
		{
			"src": "user2@example.com",
			"accept": [
				"100.60.3.4:22"
			],
		},
	],
}
	`)
	pol, err := LoadACLPolicyFromBytes(acl, "hujson")
	c.Assert(pol.ACLs, check.HasLen, 6)
	c.Assert(err, check.IsNil)

	rules, err := pol.CompileFilterRules(types.Nodes{})
	c.Assert(err, check.NotNil)
	c.Assert(rules, check.IsNil)
}

// TODO(kradalby): Make tests values safe, independent and descriptive.
func (s *Suite) TestInvalidAction(c *check.C) {
	pol := &ACLPolicy{
		ACLs: []ACL{
			{
				Action:       "invalidAction",
				Sources:      []string{"*"},
				Destinations: []string{"*:*"},
			},
		},
	}
	_, _, err := GenerateFilterAndSSHRulesForTests(pol, &types.Node{}, types.Nodes{})
	c.Assert(errors.Is(err, ErrInvalidAction), check.Equals, true)
}

func (s *Suite) TestInvalidGroupInGroup(c *check.C) {
	// this ACL is wrong because the group in Sources sections doesn't exist
	pol := &ACLPolicy{
		Groups: Groups{
			"group:test":  []string{"foo"},
			"group:error": []string{"foo", "group:test"},
		},
		ACLs: []ACL{
			{
				Action:       "accept",
				Sources:      []string{"group:error"},
				Destinations: []string{"*:*"},
			},
		},
	}
	_, _, err := GenerateFilterAndSSHRulesForTests(pol, &types.Node{}, types.Nodes{})
	c.Assert(errors.Is(err, ErrInvalidGroup), check.Equals, true)
}

func (s *Suite) TestInvalidTagOwners(c *check.C) {
	// this ACL is wrong because no tagOwners own the requested tag for the server
	pol := &ACLPolicy{
		ACLs: []ACL{
			{
				Action:       "accept",
				Sources:      []string{"tag:foo"},
				Destinations: []string{"*:*"},
			},
		},
	}

	_, _, err := GenerateFilterAndSSHRulesForTests(pol, &types.Node{}, types.Nodes{})
	c.Assert(errors.Is(err, ErrInvalidTag), check.Equals, true)
}

func Test_expandGroup(t *testing.T) {
	type field struct {
		pol ACLPolicy
	}
	type args struct {
		group      string
		stripEmail bool
	}
	tests := []struct {
		name    string
		field   field
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "simple test",
			field: field{
				pol: ACLPolicy{
					Groups: Groups{
						"group:test": []string{"user1", "user2", "user3"},
						"group:foo":  []string{"user2", "user3"},
					},
				},
			},
			args: args{
				group: "group:test",
			},
			want:    []string{"user1", "user2", "user3"},
			wantErr: false,
		},
		{
			name: "InexistantGroup",
			field: field{
				pol: ACLPolicy{
					Groups: Groups{
						"group:test": []string{"user1", "user2", "user3"},
						"group:foo":  []string{"user2", "user3"},
					},
				},
			},
			args: args{
				group: "group:undefined",
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "Expand emails in group strip domains",
			field: field{
				pol: ACLPolicy{
					Groups: Groups{
						"group:admin": []string{
							"joe.bar@gmail.com",
							"john.doe@yahoo.fr",
						},
					},
				},
			},
			args: args{
				group:      "group:admin",
				stripEmail: true,
			},
			want:    []string{"joe.bar", "john.doe"},
			wantErr: false,
		},
		{
			name: "Expand emails in group",
			field: field{
				pol: ACLPolicy{
					Groups: Groups{
						"group:admin": []string{
							"joe.bar@gmail.com",
							"john.doe@yahoo.fr",
						},
					},
				},
			},
			args: args{
				group: "group:admin",
			},
			want:    []string{"joe.bar.gmail.com", "john.doe.yahoo.fr"},
			wantErr: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			viper.Set("oidc.strip_email_domain", test.args.stripEmail)

			got, err := test.field.pol.expandUsersFromGroup(
				test.args.group,
			)

			if (err != nil) != test.wantErr {
				t.Errorf("expandGroup() error = %v, wantErr %v", err, test.wantErr)

				return
			}

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("expandGroup() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_expandTagOwners(t *testing.T) {
	type args struct {
		aclPolicy *ACLPolicy
		tag       string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "simple tag expansion",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{"tag:test": []string{"user1"}},
				},
				tag: "tag:test",
			},
			want:    []string{"user1"},
			wantErr: false,
		},
		{
			name: "expand with tag and group",
			args: args{
				aclPolicy: &ACLPolicy{
					Groups:    Groups{"group:foo": []string{"user1", "user2"}},
					TagOwners: TagOwners{"tag:test": []string{"group:foo"}},
				},
				tag: "tag:test",
			},
			want:    []string{"user1", "user2"},
			wantErr: false,
		},
		{
			name: "expand with user and group",
			args: args{
				aclPolicy: &ACLPolicy{
					Groups:    Groups{"group:foo": []string{"user1", "user2"}},
					TagOwners: TagOwners{"tag:test": []string{"group:foo", "user3"}},
				},
				tag: "tag:test",
			},
			want:    []string{"user1", "user2", "user3"},
			wantErr: false,
		},
		{
			name: "invalid tag",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{"tag:foo": []string{"group:foo", "user1"}},
				},
				tag: "tag:test",
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "invalid group",
			args: args{
				aclPolicy: &ACLPolicy{
					Groups:    Groups{"group:bar": []string{"user1", "user2"}},
					TagOwners: TagOwners{"tag:test": []string{"group:foo", "user2"}},
				},
				tag: "tag:test",
			},
			want:    []string{},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := expandOwnersFromTag(
				test.args.aclPolicy,
				test.args.tag,
			)
			if (err != nil) != test.wantErr {
				t.Errorf("expandTagOwners() error = %v, wantErr %v", err, test.wantErr)

				return
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("expandTagOwners() = (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_expandPorts(t *testing.T) {
	type args struct {
		portsStr      string
		needsWildcard bool
	}
	tests := []struct {
		name    string
		args    args
		want    *[]tailcfg.PortRange
		wantErr bool
	}{
		{
			name: "wildcard",
			args: args{portsStr: "*", needsWildcard: true},
			want: &[]tailcfg.PortRange{
				{First: portRangeBegin, Last: portRangeEnd},
			},
			wantErr: false,
		},
		{
			name: "needs wildcard but does not require it",
			args: args{portsStr: "*", needsWildcard: false},
			want: &[]tailcfg.PortRange{
				{First: portRangeBegin, Last: portRangeEnd},
			},
			wantErr: false,
		},
		{
			name:    "needs wildcard but gets port",
			args:    args{portsStr: "80,443", needsWildcard: true},
			want:    nil,
			wantErr: true,
		},
		{
			name: "two Destinations",
			args: args{portsStr: "80,443", needsWildcard: false},
			want: &[]tailcfg.PortRange{
				{First: 80, Last: 80},
				{First: 443, Last: 443},
			},
			wantErr: false,
		},
		{
			name: "a range and a port",
			args: args{portsStr: "80-1024,443", needsWildcard: false},
			want: &[]tailcfg.PortRange{
				{First: 80, Last: 1024},
				{First: 443, Last: 443},
			},
			wantErr: false,
		},
		{
			name:    "out of bounds",
			args:    args{portsStr: "854038", needsWildcard: false},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong port",
			args:    args{portsStr: "85a38", needsWildcard: false},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong port in first",
			args:    args{portsStr: "a-80", needsWildcard: false},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong port in last",
			args:    args{portsStr: "80-85a38", needsWildcard: false},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong port format",
			args:    args{portsStr: "80-85a38-3", needsWildcard: false},
			want:    nil,
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := expandPorts(test.args.portsStr, test.args.needsWildcard)
			if (err != nil) != test.wantErr {
				t.Errorf("expandPorts() error = %v, wantErr %v", err, test.wantErr)

				return
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("expandPorts() = (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_listNodesInUser(t *testing.T) {
	type args struct {
		nodes types.Nodes
		user  string
	}
	tests := []struct {
		name string
		args args
		want types.Nodes
	}{
		{
			name: "1 node in user",
			args: args{
				nodes: types.Nodes{
					&types.Node{User: types.User{Name: "joe"}},
				},
				user: "joe",
			},
			want: types.Nodes{
				&types.Node{User: types.User{Name: "joe"}},
			},
		},
		{
			name: "3 nodes, 2 in user",
			args: args{
				nodes: types.Nodes{
					&types.Node{ID: 1, User: types.User{Name: "joe"}},
					&types.Node{ID: 2, User: types.User{Name: "marc"}},
					&types.Node{ID: 3, User: types.User{Name: "marc"}},
				},
				user: "marc",
			},
			want: types.Nodes{
				&types.Node{ID: 2, User: types.User{Name: "marc"}},
				&types.Node{ID: 3, User: types.User{Name: "marc"}},
			},
		},
		{
			name: "5 nodes, 0 in user",
			args: args{
				nodes: types.Nodes{
					&types.Node{ID: 1, User: types.User{Name: "joe"}},
					&types.Node{ID: 2, User: types.User{Name: "marc"}},
					&types.Node{ID: 3, User: types.User{Name: "marc"}},
					&types.Node{ID: 4, User: types.User{Name: "marc"}},
					&types.Node{ID: 5, User: types.User{Name: "marc"}},
				},
				user: "mickael",
			},
			want: types.Nodes{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := filterNodesByUser(test.args.nodes, test.args.user)

			if diff := cmp.Diff(test.want, got, util.Comparers...); diff != "" {
				t.Errorf("listNodesInUser() = (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_expandAlias(t *testing.T) {
	set := func(ips []string, prefixes []string) *netipx.IPSet {
		var builder netipx.IPSetBuilder

		for _, ip := range ips {
			builder.Add(netip.MustParseAddr(ip))
		}

		for _, pre := range prefixes {
			builder.AddPrefix(netip.MustParsePrefix(pre))
		}

		s, _ := builder.IPSet()

		return s
	}

	type field struct {
		pol ACLPolicy
	}
	type args struct {
		nodes     types.Nodes
		aclPolicy ACLPolicy
		alias     string
	}
	tests := []struct {
		name    string
		field   field
		args    args
		want    *netipx.IPSet
		wantErr bool
	}{
		{
			name: "wildcard",
			field: field{
				pol: ACLPolicy{},
			},
			args: args{
				alias: "*",
				nodes: types.Nodes{
					&types.Node{
						IPv4: iap("100.64.0.1"),
					},
					&types.Node{
						IPv4: iap("100.78.84.227"),
					},
				},
			},
			want: set([]string{}, []string{
				"0.0.0.0/0",
				"::/0",
			}),
			wantErr: false,
		},
		{
			name: "simple group",
			field: field{
				pol: ACLPolicy{
					Groups: Groups{"group:accountant": []string{"joe", "marc"}},
				},
			},
			args: args{
				alias: "group:accountant",
				nodes: types.Nodes{
					&types.Node{
						IPv4: iap("100.64.0.1"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						IPv4: iap("100.64.0.2"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						IPv4: iap("100.64.0.3"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						IPv4: iap("100.64.0.4"),
						User: types.User{Name: "mickael"},
					},
				},
			},
			want: set([]string{
				"100.64.0.1", "100.64.0.2", "100.64.0.3",
			}, []string{}),
			wantErr: false,
		},
		{
			name: "wrong group",
			field: field{
				pol: ACLPolicy{
					Groups: Groups{"group:accountant": []string{"joe", "marc"}},
				},
			},
			args: args{
				alias: "group:hr",
				nodes: types.Nodes{
					&types.Node{
						IPv4: iap("100.64.0.1"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						IPv4: iap("100.64.0.2"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						IPv4: iap("100.64.0.3"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						IPv4: iap("100.64.0.4"),
						User: types.User{Name: "mickael"},
					},
				},
			},
			want:    set([]string{}, []string{}),
			wantErr: true,
		},
		{
			name: "simple ipaddress",
			field: field{
				pol: ACLPolicy{},
			},
			args: args{
				alias: "10.0.0.3",
				nodes: types.Nodes{},
			},
			want: set([]string{
				"10.0.0.3",
			}, []string{}),
			wantErr: false,
		},
		{
			name: "simple host by ip passed through",
			field: field{
				pol: ACLPolicy{},
			},
			args: args{
				alias: "10.0.0.1",
				nodes: types.Nodes{},
			},
			want: set([]string{
				"10.0.0.1",
			}, []string{}),
			wantErr: false,
		},
		{
			name: "simple host by ipv4 single ipv4",
			field: field{
				pol: ACLPolicy{},
			},
			args: args{
				alias: "10.0.0.1",
				nodes: types.Nodes{
					&types.Node{
						IPv4: iap("10.0.0.1"),
						User: types.User{Name: "mickael"},
					},
				},
			},
			want: set([]string{
				"10.0.0.1",
			}, []string{}),
			wantErr: false,
		},
		{
			name: "simple host by ipv4 single dual stack",
			field: field{
				pol: ACLPolicy{},
			},
			args: args{
				alias: "10.0.0.1",
				nodes: types.Nodes{
					&types.Node{
						IPv4: iap("10.0.0.1"),
						IPv6: iap("fd7a:115c:a1e0:ab12:4843:2222:6273:2222"),
						User: types.User{Name: "mickael"},
					},
				},
			},
			want: set([]string{
				"10.0.0.1", "fd7a:115c:a1e0:ab12:4843:2222:6273:2222",
			}, []string{}),
			wantErr: false,
		},
		{
			name: "simple host by ipv6 single dual stack",
			field: field{
				pol: ACLPolicy{},
			},
			args: args{
				alias: "fd7a:115c:a1e0:ab12:4843:2222:6273:2222",
				nodes: types.Nodes{
					&types.Node{
						IPv4: iap("10.0.0.1"),
						IPv6: iap("fd7a:115c:a1e0:ab12:4843:2222:6273:2222"),
						User: types.User{Name: "mickael"},
					},
				},
			},
			want: set([]string{
				"fd7a:115c:a1e0:ab12:4843:2222:6273:2222", "10.0.0.1",
			}, []string{}),
			wantErr: false,
		},
		{
			name: "simple host by hostname alias",
			field: field{
				pol: ACLPolicy{
					Hosts: Hosts{
						"testy": netip.MustParsePrefix("10.0.0.132/32"),
					},
				},
			},
			args: args{
				alias: "testy",
				nodes: types.Nodes{},
			},
			want:    set([]string{}, []string{"10.0.0.132/32"}),
			wantErr: false,
		},
		{
			name: "private network",
			field: field{
				pol: ACLPolicy{
					Hosts: Hosts{
						"homeNetwork": netip.MustParsePrefix("192.168.1.0/24"),
					},
				},
			},
			args: args{
				alias: "homeNetwork",
				nodes: types.Nodes{},
			},
			want:    set([]string{}, []string{"192.168.1.0/24"}),
			wantErr: false,
		},
		{
			name: "simple CIDR",
			field: field{
				pol: ACLPolicy{},
			},
			args: args{
				alias:     "10.0.0.0/16",
				nodes:     types.Nodes{},
				aclPolicy: ACLPolicy{},
			},
			want:    set([]string{}, []string{"10.0.0.0/16"}),
			wantErr: false,
		},
		{
			name: "simple tag",
			field: field{
				pol: ACLPolicy{
					TagOwners: TagOwners{"tag:hr-webserver": []string{"joe"}},
				},
			},
			args: args{
				alias: "tag:hr-webserver",
				nodes: types.Nodes{
					&types.Node{
						IPv4: iap("100.64.0.1"),
						User: types.User{Name: "joe"},
						Hostinfo: &tailcfg.Hostinfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					&types.Node{
						IPv4: iap("100.64.0.2"),
						User: types.User{Name: "joe"},
						Hostinfo: &tailcfg.Hostinfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					&types.Node{
						IPv4: iap("100.64.0.3"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						IPv4: iap("100.64.0.4"),
						User: types.User{Name: "joe"},
					},
				},
			},
			want: set([]string{
				"100.64.0.1", "100.64.0.2",
			}, []string{}),
			wantErr: false,
		},
		{
			name: "No tag defined",
			field: field{
				pol: ACLPolicy{
					Groups: Groups{"group:accountant": []string{"joe", "marc"}},
					TagOwners: TagOwners{
						"tag:accountant-webserver": []string{"group:accountant"},
					},
				},
			},
			args: args{
				alias: "tag:hr-webserver",
				nodes: types.Nodes{
					&types.Node{
						IPv4: iap("100.64.0.1"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						IPv4: iap("100.64.0.2"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						IPv4: iap("100.64.0.3"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						IPv4: iap("100.64.0.4"),
						User: types.User{Name: "mickael"},
					},
				},
			},
			want:    set([]string{}, []string{}),
			wantErr: true,
		},
		{
			name: "Forced tag defined",
			field: field{
				pol: ACLPolicy{},
			},
			args: args{
				alias: "tag:hr-webserver",
				nodes: types.Nodes{
					&types.Node{
						IPv4:       iap("100.64.0.1"),
						User:       types.User{Name: "joe"},
						ForcedTags: []string{"tag:hr-webserver"},
					},
					&types.Node{
						IPv4:       iap("100.64.0.2"),
						User:       types.User{Name: "joe"},
						ForcedTags: []string{"tag:hr-webserver"},
					},
					&types.Node{
						IPv4: iap("100.64.0.3"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						IPv4: iap("100.64.0.4"),
						User: types.User{Name: "mickael"},
					},
				},
			},
			want:    set([]string{"100.64.0.1", "100.64.0.2"}, []string{}),
			wantErr: false,
		},
		{
			name: "Forced tag with legitimate tagOwner",
			field: field{
				pol: ACLPolicy{
					TagOwners: TagOwners{
						"tag:hr-webserver": []string{"joe"},
					},
				},
			},
			args: args{
				alias: "tag:hr-webserver",
				nodes: types.Nodes{
					&types.Node{
						IPv4:       iap("100.64.0.1"),
						User:       types.User{Name: "joe"},
						ForcedTags: []string{"tag:hr-webserver"},
					},
					&types.Node{
						IPv4: iap("100.64.0.2"),
						User: types.User{Name: "joe"},
						Hostinfo: &tailcfg.Hostinfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					&types.Node{
						IPv4: iap("100.64.0.3"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						IPv4: iap("100.64.0.4"),
						User: types.User{Name: "mickael"},
					},
				},
			},
			want:    set([]string{"100.64.0.1", "100.64.0.2"}, []string{}),
			wantErr: false,
		},
		{
			name: "list host in user without correctly tagged servers",
			field: field{
				pol: ACLPolicy{
					TagOwners: TagOwners{"tag:accountant-webserver": []string{"joe"}},
				},
			},
			args: args{
				alias: "joe",
				nodes: types.Nodes{
					&types.Node{
						IPv4: iap("100.64.0.1"),
						User: types.User{Name: "joe"},
						Hostinfo: &tailcfg.Hostinfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					&types.Node{
						IPv4: iap("100.64.0.2"),
						User: types.User{Name: "joe"},
						Hostinfo: &tailcfg.Hostinfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					&types.Node{
						IPv4:     iap("100.64.0.3"),
						User:     types.User{Name: "marc"},
						Hostinfo: &tailcfg.Hostinfo{},
					},
					&types.Node{
						IPv4:     iap("100.64.0.4"),
						User:     types.User{Name: "joe"},
						Hostinfo: &tailcfg.Hostinfo{},
					},
				},
			},
			want:    set([]string{"100.64.0.4"}, []string{}),
			wantErr: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.field.pol.ExpandAlias(
				test.args.nodes,
				test.args.alias,
			)
			if (err != nil) != test.wantErr {
				t.Errorf("expandAlias() error = %v, wantErr %v", err, test.wantErr)

				return
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("expandAlias() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_excludeCorrectlyTaggedNodes(t *testing.T) {
	type args struct {
		aclPolicy *ACLPolicy
		nodes     types.Nodes
		user      string
	}
	tests := []struct {
		name    string
		args    args
		want    types.Nodes
		wantErr bool
	}{
		{
			name: "exclude nodes with valid tags",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{"tag:accountant-webserver": []string{"joe"}},
				},
				nodes: types.Nodes{
					&types.Node{
						IPv4: iap("100.64.0.1"),
						User: types.User{Name: "joe"},
						Hostinfo: &tailcfg.Hostinfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					&types.Node{
						IPv4: iap("100.64.0.2"),
						User: types.User{Name: "joe"},
						Hostinfo: &tailcfg.Hostinfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					&types.Node{
						IPv4:     iap("100.64.0.4"),
						User:     types.User{Name: "joe"},
						Hostinfo: &tailcfg.Hostinfo{},
					},
				},
				user: "joe",
			},
			want: types.Nodes{
				&types.Node{
					IPv4:     iap("100.64.0.4"),
					User:     types.User{Name: "joe"},
					Hostinfo: &tailcfg.Hostinfo{},
				},
			},
		},
		{
			name: "exclude nodes with valid tags, and owner is in a group",
			args: args{
				aclPolicy: &ACLPolicy{
					Groups: Groups{
						"group:accountant": []string{"joe", "bar"},
					},
					TagOwners: TagOwners{
						"tag:accountant-webserver": []string{"group:accountant"},
					},
				},
				nodes: types.Nodes{
					&types.Node{
						IPv4: iap("100.64.0.1"),
						User: types.User{Name: "joe"},
						Hostinfo: &tailcfg.Hostinfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					&types.Node{
						IPv4: iap("100.64.0.2"),
						User: types.User{Name: "joe"},
						Hostinfo: &tailcfg.Hostinfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					&types.Node{
						IPv4:     iap("100.64.0.4"),
						User:     types.User{Name: "joe"},
						Hostinfo: &tailcfg.Hostinfo{},
					},
				},
				user: "joe",
			},
			want: types.Nodes{
				&types.Node{
					IPv4:     iap("100.64.0.4"),
					User:     types.User{Name: "joe"},
					Hostinfo: &tailcfg.Hostinfo{},
				},
			},
		},
		{
			name: "exclude nodes with valid tags and with forced tags",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{"tag:accountant-webserver": []string{"joe"}},
				},
				nodes: types.Nodes{
					&types.Node{
						IPv4: iap("100.64.0.1"),
						User: types.User{Name: "joe"},
						Hostinfo: &tailcfg.Hostinfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					&types.Node{
						IPv4:       iap("100.64.0.2"),
						User:       types.User{Name: "joe"},
						ForcedTags: []string{"tag:accountant-webserver"},
						Hostinfo:   &tailcfg.Hostinfo{},
					},
					&types.Node{
						IPv4:     iap("100.64.0.4"),
						User:     types.User{Name: "joe"},
						Hostinfo: &tailcfg.Hostinfo{},
					},
				},
				user: "joe",
			},
			want: types.Nodes{
				&types.Node{
					IPv4:     iap("100.64.0.4"),
					User:     types.User{Name: "joe"},
					Hostinfo: &tailcfg.Hostinfo{},
				},
			},
		},
		{
			name: "all nodes have invalid tags, don't exclude them",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{"tag:accountant-webserver": []string{"joe"}},
				},
				nodes: types.Nodes{
					&types.Node{
						IPv4: iap("100.64.0.1"),
						User: types.User{Name: "joe"},
						Hostinfo: &tailcfg.Hostinfo{
							OS:          "centos",
							Hostname:    "hr-web1",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					&types.Node{
						IPv4: iap("100.64.0.2"),
						User: types.User{Name: "joe"},
						Hostinfo: &tailcfg.Hostinfo{
							OS:          "centos",
							Hostname:    "hr-web2",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					&types.Node{
						IPv4:     iap("100.64.0.4"),
						User:     types.User{Name: "joe"},
						Hostinfo: &tailcfg.Hostinfo{},
					},
				},
				user: "joe",
			},
			want: types.Nodes{
				&types.Node{
					IPv4: iap("100.64.0.1"),
					User: types.User{Name: "joe"},
					Hostinfo: &tailcfg.Hostinfo{
						OS:          "centos",
						Hostname:    "hr-web1",
						RequestTags: []string{"tag:hr-webserver"},
					},
				},
				&types.Node{
					IPv4: iap("100.64.0.2"),
					User: types.User{Name: "joe"},
					Hostinfo: &tailcfg.Hostinfo{
						OS:          "centos",
						Hostname:    "hr-web2",
						RequestTags: []string{"tag:hr-webserver"},
					},
				},
				&types.Node{
					IPv4:     iap("100.64.0.4"),
					User:     types.User{Name: "joe"},
					Hostinfo: &tailcfg.Hostinfo{},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := excludeCorrectlyTaggedNodes(
				test.args.aclPolicy,
				test.args.nodes,
				test.args.user,
			)
			if diff := cmp.Diff(test.want, got, util.Comparers...); diff != "" {
				t.Errorf("excludeCorrectlyTaggedNodes() (-want +got):\n%s", diff)
			}
		})
	}
}

func TestACLPolicy_generateFilterRules(t *testing.T) {
	type field struct {
		pol ACLPolicy
	}
	type args struct {
		nodes types.Nodes
	}
	tests := []struct {
		name    string
		field   field
		args    args
		want    []tailcfg.FilterRule
		wantErr bool
	}{
		{
			name:    "no-policy",
			field:   field{},
			args:    args{},
			want:    []tailcfg.FilterRule{},
			wantErr: false,
		},
		{
			name: "allow-all",
			field: field{
				pol: ACLPolicy{
					ACLs: []ACL{
						{
							Action:       "accept",
							Sources:      []string{"*"},
							Destinations: []string{"*:*"},
						},
					},
				},
			},
			args: args{
				nodes: types.Nodes{
					&types.Node{
						IPv4: iap("100.64.0.1"),
						IPv6: iap("fd7a:115c:a1e0:ab12:4843:2222:6273:2221"),
					},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"0.0.0.0/0", "::/0"},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP: "0.0.0.0/0",
							Ports: tailcfg.PortRange{
								First: 0,
								Last:  65535,
							},
						},
						{
							IP: "::/0",
							Ports: tailcfg.PortRange{
								First: 0,
								Last:  65535,
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "host1-can-reach-host2-full",
			field: field{
				pol: ACLPolicy{
					ACLs: []ACL{
						{
							Action:       "accept",
							Sources:      []string{"100.64.0.2"},
							Destinations: []string{"100.64.0.1:*"},
						},
					},
				},
			},
			args: args{
				nodes: types.Nodes{
					&types.Node{
						IPv4: iap("100.64.0.1"),
						IPv6: iap("fd7a:115c:a1e0:ab12:4843:2222:6273:2221"),
						User: types.User{Name: "mickael"},
					},
					&types.Node{
						IPv4: iap("100.64.0.2"),
						IPv6: iap("fd7a:115c:a1e0:ab12:4843:2222:6273:2222"),
						User: types.User{Name: "mickael"},
					},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{
						"100.64.0.2/32",
						"fd7a:115c:a1e0:ab12:4843:2222:6273:2222/128",
					},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP: "100.64.0.1/32",
							Ports: tailcfg.PortRange{
								First: 0,
								Last:  65535,
							},
						},
						{
							IP: "fd7a:115c:a1e0:ab12:4843:2222:6273:2221/128",
							Ports: tailcfg.PortRange{
								First: 0,
								Last:  65535,
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.field.pol.CompileFilterRules(
				tt.args.nodes,
			)
			if (err != nil) != tt.wantErr {
				t.Errorf("ACLgenerateFilterRules() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				log.Trace().Interface("got", got).Msg("result")
				t.Errorf("ACLgenerateFilterRules() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

// tsExitNodeDest is the list of destination IP ranges that are allowed when
// you dump the filter list from a Tailscale node connected to Tailscale SaaS.
var tsExitNodeDest = []tailcfg.NetPortRange{
	{
		IP:    "0.0.0.0-9.255.255.255",
		Ports: tailcfg.PortRangeAny,
	},
	{
		IP:    "11.0.0.0-100.63.255.255",
		Ports: tailcfg.PortRangeAny,
	},
	{
		IP:    "100.128.0.0-169.253.255.255",
		Ports: tailcfg.PortRangeAny,
	},
	{
		IP:    "169.255.0.0-172.15.255.255",
		Ports: tailcfg.PortRangeAny,
	},
	{
		IP:    "172.32.0.0-192.167.255.255",
		Ports: tailcfg.PortRangeAny,
	},
	{
		IP:    "192.169.0.0-255.255.255.255",
		Ports: tailcfg.PortRangeAny,
	},
	{
		IP:    "2000::-3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		Ports: tailcfg.PortRangeAny,
	},
}

// hsExitNodeDest is the list of destination IP ranges that are allowed when
// we use headscale "autogroup:internet"
var hsExitNodeDest = []tailcfg.NetPortRange{
	{IP: "0.0.0.0/5", Ports: tailcfg.PortRangeAny},
	{IP: "8.0.0.0/7", Ports: tailcfg.PortRangeAny},
	{IP: "11.0.0.0/8", Ports: tailcfg.PortRangeAny},
	{IP: "12.0.0.0/6", Ports: tailcfg.PortRangeAny},
	{IP: "16.0.0.0/4", Ports: tailcfg.PortRangeAny},
	{IP: "32.0.0.0/3", Ports: tailcfg.PortRangeAny},
	{IP: "64.0.0.0/3", Ports: tailcfg.PortRangeAny},
	{IP: "96.0.0.0/6", Ports: tailcfg.PortRangeAny},
	{IP: "100.0.0.0/10", Ports: tailcfg.PortRangeAny},
	{IP: "100.128.0.0/9", Ports: tailcfg.PortRangeAny},
	{IP: "101.0.0.0/8", Ports: tailcfg.PortRangeAny},
	{IP: "102.0.0.0/7", Ports: tailcfg.PortRangeAny},
	{IP: "104.0.0.0/5", Ports: tailcfg.PortRangeAny},
	{IP: "112.0.0.0/4", Ports: tailcfg.PortRangeAny},
	{IP: "128.0.0.0/3", Ports: tailcfg.PortRangeAny},
	{IP: "160.0.0.0/5", Ports: tailcfg.PortRangeAny},
	{IP: "168.0.0.0/8", Ports: tailcfg.PortRangeAny},
	{IP: "169.0.0.0/9", Ports: tailcfg.PortRangeAny},
	{IP: "169.128.0.0/10", Ports: tailcfg.PortRangeAny},
	{IP: "169.192.0.0/11", Ports: tailcfg.PortRangeAny},
	{IP: "169.224.0.0/12", Ports: tailcfg.PortRangeAny},
	{IP: "169.240.0.0/13", Ports: tailcfg.PortRangeAny},
	{IP: "169.248.0.0/14", Ports: tailcfg.PortRangeAny},
	{IP: "169.252.0.0/15", Ports: tailcfg.PortRangeAny},
	{IP: "169.255.0.0/16", Ports: tailcfg.PortRangeAny},
	{IP: "170.0.0.0/7", Ports: tailcfg.PortRangeAny},
	{IP: "172.0.0.0/12", Ports: tailcfg.PortRangeAny},
	{IP: "172.32.0.0/11", Ports: tailcfg.PortRangeAny},
	{IP: "172.64.0.0/10", Ports: tailcfg.PortRangeAny},
	{IP: "172.128.0.0/9", Ports: tailcfg.PortRangeAny},
	{IP: "173.0.0.0/8", Ports: tailcfg.PortRangeAny},
	{IP: "174.0.0.0/7", Ports: tailcfg.PortRangeAny},
	{IP: "176.0.0.0/4", Ports: tailcfg.PortRangeAny},
	{IP: "192.0.0.0/9", Ports: tailcfg.PortRangeAny},
	{IP: "192.128.0.0/11", Ports: tailcfg.PortRangeAny},
	{IP: "192.160.0.0/13", Ports: tailcfg.PortRangeAny},
	{IP: "192.169.0.0/16", Ports: tailcfg.PortRangeAny},
	{IP: "192.170.0.0/15", Ports: tailcfg.PortRangeAny},
	{IP: "192.172.0.0/14", Ports: tailcfg.PortRangeAny},
	{IP: "192.176.0.0/12", Ports: tailcfg.PortRangeAny},
	{IP: "192.192.0.0/10", Ports: tailcfg.PortRangeAny},
	{IP: "193.0.0.0/8", Ports: tailcfg.PortRangeAny},
	{IP: "194.0.0.0/7", Ports: tailcfg.PortRangeAny},
	{IP: "196.0.0.0/6", Ports: tailcfg.PortRangeAny},
	{IP: "200.0.0.0/5", Ports: tailcfg.PortRangeAny},
	{IP: "208.0.0.0/4", Ports: tailcfg.PortRangeAny},
	{IP: "224.0.0.0/3", Ports: tailcfg.PortRangeAny},
	{IP: "2000::/3", Ports: tailcfg.PortRangeAny},
}

func TestTheInternet(t *testing.T) {
	internetSet := theInternet()

	internetPrefs := internetSet.Prefixes()

	for i, _ := range internetPrefs {
		if internetPrefs[i].String() != hsExitNodeDest[i].IP {
			t.Errorf("prefix from internet set %q != hsExit list %q", internetPrefs[i].String(), hsExitNodeDest[i].IP)
		}
	}

	if len(internetPrefs) != len(hsExitNodeDest) {
		t.Fatalf("expected same length of prefixes, internet: %d, hsExit: %d", len(internetPrefs), len(hsExitNodeDest))
	}
}

func TestReduceFilterRules(t *testing.T) {
	tests := []struct {
		name  string
		node  *types.Node
		peers types.Nodes
		pol   ACLPolicy
		want  []tailcfg.FilterRule
	}{
		{
			name: "host1-can-reach-host2-no-rules",
			pol: ACLPolicy{
				ACLs: []ACL{
					{
						Action:       "accept",
						Sources:      []string{"100.64.0.1"},
						Destinations: []string{"100.64.0.2:*"},
					},
				},
			},
			node: &types.Node{
				IPv4: iap("100.64.0.1"),
				IPv6: iap("fd7a:115c:a1e0:ab12:4843:2222:6273:2221"),
				User: types.User{Name: "mickael"},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: iap("100.64.0.2"),
					IPv6: iap("fd7a:115c:a1e0:ab12:4843:2222:6273:2222"),
					User: types.User{Name: "mickael"},
				},
			},
			want: []tailcfg.FilterRule{},
		},
		{
			name: "1604-subnet-routers-are-preserved",
			pol: ACLPolicy{
				Groups: Groups{
					"group:admins": {"user1"},
				},
				ACLs: []ACL{
					{
						Action:       "accept",
						Sources:      []string{"group:admins"},
						Destinations: []string{"group:admins:*"},
					},
					{
						Action:       "accept",
						Sources:      []string{"group:admins"},
						Destinations: []string{"10.33.0.0/16:*"},
					},
				},
			},
			node: &types.Node{
				IPv4: iap("100.64.0.1"),
				IPv6: iap("fd7a:115c:a1e0::1"),
				User: types.User{Name: "user1"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.33.0.0/16"),
					},
				},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: iap("100.64.0.2"),
					IPv6: iap("fd7a:115c:a1e0::2"),
					User: types.User{Name: "user1"},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{
						"100.64.0.1/32",
						"100.64.0.2/32",
						"fd7a:115c:a1e0::1/128",
						"fd7a:115c:a1e0::2/128",
					},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "100.64.0.1/32",
							Ports: tailcfg.PortRangeAny,
						},
						{
							IP:    "fd7a:115c:a1e0::1/128",
							Ports: tailcfg.PortRangeAny,
						},
					},
				},
				{
					SrcIPs: []string{
						"100.64.0.1/32",
						"100.64.0.2/32",
						"fd7a:115c:a1e0::1/128",
						"fd7a:115c:a1e0::2/128",
					},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "10.33.0.0/16",
							Ports: tailcfg.PortRangeAny,
						},
					},
				},
			},
		},
		{
			name: "1786-reducing-breaks-exit-nodes-the-client",
			pol: ACLPolicy{
				Hosts: Hosts{
					// Exit node
					"internal": netip.MustParsePrefix("100.64.0.100/32"),
				},
				Groups: Groups{
					"group:team": {"user3", "user2", "user1"},
				},
				ACLs: []ACL{
					{
						Action:  "accept",
						Sources: []string{"group:team"},
						Destinations: []string{
							"internal:*",
						},
					},
					{
						Action:  "accept",
						Sources: []string{"group:team"},
						Destinations: []string{
							"autogroup:internet:*",
						},
					},
				},
			},
			node: &types.Node{
				IPv4: iap("100.64.0.1"),
				IPv6: iap("fd7a:115c:a1e0::1"),
				User: types.User{Name: "user1"},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: iap("100.64.0.2"),
					IPv6: iap("fd7a:115c:a1e0::2"),
					User: types.User{Name: "user2"},
				},
				// "internal" exit node
				&types.Node{
					IPv4: iap("100.64.0.100"),
					IPv6: iap("fd7a:115c:a1e0::100"),
					User: types.User{Name: "user100"},
					Hostinfo: &tailcfg.Hostinfo{
						RoutableIPs: []netip.Prefix{types.ExitRouteV4, types.ExitRouteV6},
					},
				},
			},
			want: []tailcfg.FilterRule{},
		},
		{
			name: "1786-reducing-breaks-exit-nodes-the-exit",
			pol: ACLPolicy{
				Hosts: Hosts{
					// Exit node
					"internal": netip.MustParsePrefix("100.64.0.100/32"),
				},
				Groups: Groups{
					"group:team": {"user3", "user2", "user1"},
				},
				ACLs: []ACL{
					{
						Action:  "accept",
						Sources: []string{"group:team"},
						Destinations: []string{
							"internal:*",
						},
					},
					{
						Action:  "accept",
						Sources: []string{"group:team"},
						Destinations: []string{
							"autogroup:internet:*",
						},
					},
				},
			},
			node: &types.Node{
				IPv4: iap("100.64.0.100"),
				IPv6: iap("fd7a:115c:a1e0::100"),
				User: types.User{Name: "user100"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{types.ExitRouteV4, types.ExitRouteV6},
				},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: iap("100.64.0.2"),
					IPv6: iap("fd7a:115c:a1e0::2"),
					User: types.User{Name: "user2"},
				},
				&types.Node{
					IPv4: iap("100.64.0.1"),
					IPv6: iap("fd7a:115c:a1e0::1"),
					User: types.User{Name: "user1"},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32", "100.64.0.2/32", "fd7a:115c:a1e0::1/128", "fd7a:115c:a1e0::2/128"},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "100.64.0.100/32",
							Ports: tailcfg.PortRangeAny,
						},
						{
							IP:    "fd7a:115c:a1e0::100/128",
							Ports: tailcfg.PortRangeAny,
						},
					},
				},
				{
					SrcIPs:   []string{"100.64.0.1/32", "100.64.0.2/32", "fd7a:115c:a1e0::1/128", "fd7a:115c:a1e0::2/128"},
					DstPorts: hsExitNodeDest,
				},
			},
		},
		{
			name: "1786-reducing-breaks-exit-nodes-the-example-from-issue",
			pol: ACLPolicy{
				Hosts: Hosts{
					// Exit node
					"internal": netip.MustParsePrefix("100.64.0.100/32"),
				},
				Groups: Groups{
					"group:team": {"user3", "user2", "user1"},
				},
				ACLs: []ACL{
					{
						Action:  "accept",
						Sources: []string{"group:team"},
						Destinations: []string{
							"internal:*",
						},
					},
					{
						Action:  "accept",
						Sources: []string{"group:team"},
						Destinations: []string{
							"0.0.0.0/5:*",
							"8.0.0.0/7:*",
							"11.0.0.0/8:*",
							"12.0.0.0/6:*",
							"16.0.0.0/4:*",
							"32.0.0.0/3:*",
							"64.0.0.0/2:*",
							"128.0.0.0/3:*",
							"160.0.0.0/5:*",
							"168.0.0.0/6:*",
							"172.0.0.0/12:*",
							"172.32.0.0/11:*",
							"172.64.0.0/10:*",
							"172.128.0.0/9:*",
							"173.0.0.0/8:*",
							"174.0.0.0/7:*",
							"176.0.0.0/4:*",
							"192.0.0.0/9:*",
							"192.128.0.0/11:*",
							"192.160.0.0/13:*",
							"192.169.0.0/16:*",
							"192.170.0.0/15:*",
							"192.172.0.0/14:*",
							"192.176.0.0/12:*",
							"192.192.0.0/10:*",
							"193.0.0.0/8:*",
							"194.0.0.0/7:*",
							"196.0.0.0/6:*",
							"200.0.0.0/5:*",
							"208.0.0.0/4:*",
						},
					},
				},
			},
			node: &types.Node{
				IPv4: iap("100.64.0.100"),
				IPv6: iap("fd7a:115c:a1e0::100"),
				User: types.User{Name: "user100"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{types.ExitRouteV4, types.ExitRouteV6},
				},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: iap("100.64.0.2"),
					IPv6: iap("fd7a:115c:a1e0::2"),
					User: types.User{Name: "user2"},
				},
				&types.Node{
					IPv4: iap("100.64.0.1"),
					IPv6: iap("fd7a:115c:a1e0::1"),
					User: types.User{Name: "user1"},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32", "100.64.0.2/32", "fd7a:115c:a1e0::1/128", "fd7a:115c:a1e0::2/128"},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "100.64.0.100/32",
							Ports: tailcfg.PortRangeAny,
						},
						{
							IP:    "fd7a:115c:a1e0::100/128",
							Ports: tailcfg.PortRangeAny,
						},
					},
				},
				{
					SrcIPs: []string{"100.64.0.1/32", "100.64.0.2/32", "fd7a:115c:a1e0::1/128", "fd7a:115c:a1e0::2/128"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "0.0.0.0/5", Ports: tailcfg.PortRangeAny},
						{IP: "8.0.0.0/7", Ports: tailcfg.PortRangeAny},
						{IP: "11.0.0.0/8", Ports: tailcfg.PortRangeAny},
						{IP: "12.0.0.0/6", Ports: tailcfg.PortRangeAny},
						{IP: "16.0.0.0/4", Ports: tailcfg.PortRangeAny},
						{IP: "32.0.0.0/3", Ports: tailcfg.PortRangeAny},
						{IP: "64.0.0.0/2", Ports: tailcfg.PortRangeAny},
						{IP: "fd7a:115c:a1e0::1/128", Ports: tailcfg.PortRangeAny},
						{IP: "fd7a:115c:a1e0::2/128", Ports: tailcfg.PortRangeAny},
						{IP: "fd7a:115c:a1e0::100/128", Ports: tailcfg.PortRangeAny},
						{IP: "128.0.0.0/3", Ports: tailcfg.PortRangeAny},
						{IP: "160.0.0.0/5", Ports: tailcfg.PortRangeAny},
						{IP: "168.0.0.0/6", Ports: tailcfg.PortRangeAny},
						{IP: "172.0.0.0/12", Ports: tailcfg.PortRangeAny},
						{IP: "172.32.0.0/11", Ports: tailcfg.PortRangeAny},
						{IP: "172.64.0.0/10", Ports: tailcfg.PortRangeAny},
						{IP: "172.128.0.0/9", Ports: tailcfg.PortRangeAny},
						{IP: "173.0.0.0/8", Ports: tailcfg.PortRangeAny},
						{IP: "174.0.0.0/7", Ports: tailcfg.PortRangeAny},
						{IP: "176.0.0.0/4", Ports: tailcfg.PortRangeAny},
						{IP: "192.0.0.0/9", Ports: tailcfg.PortRangeAny},
						{IP: "192.128.0.0/11", Ports: tailcfg.PortRangeAny},
						{IP: "192.160.0.0/13", Ports: tailcfg.PortRangeAny},
						{IP: "192.169.0.0/16", Ports: tailcfg.PortRangeAny},
						{IP: "192.170.0.0/15", Ports: tailcfg.PortRangeAny},
						{IP: "192.172.0.0/14", Ports: tailcfg.PortRangeAny},
						{IP: "192.176.0.0/12", Ports: tailcfg.PortRangeAny},
						{IP: "192.192.0.0/10", Ports: tailcfg.PortRangeAny},
						{IP: "193.0.0.0/8", Ports: tailcfg.PortRangeAny},
						{IP: "194.0.0.0/7", Ports: tailcfg.PortRangeAny},
						{IP: "196.0.0.0/6", Ports: tailcfg.PortRangeAny},
						{IP: "200.0.0.0/5", Ports: tailcfg.PortRangeAny},
						{IP: "208.0.0.0/4", Ports: tailcfg.PortRangeAny},
					},
				},
			},
		},
		{
			name: "1786-reducing-breaks-exit-nodes-app-connector-like",
			pol: ACLPolicy{
				Hosts: Hosts{
					// Exit node
					"internal": netip.MustParsePrefix("100.64.0.100/32"),
				},
				Groups: Groups{
					"group:team": {"user3", "user2", "user1"},
				},
				ACLs: []ACL{
					{
						Action:  "accept",
						Sources: []string{"group:team"},
						Destinations: []string{
							"internal:*",
						},
					},
					{
						Action:  "accept",
						Sources: []string{"group:team"},
						Destinations: []string{
							"8.0.0.0/8:*",
							"16.0.0.0/8:*",
						},
					},
				},
			},
			node: &types.Node{
				IPv4: iap("100.64.0.100"),
				IPv6: iap("fd7a:115c:a1e0::100"),
				User: types.User{Name: "user100"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{netip.MustParsePrefix("8.0.0.0/16"), netip.MustParsePrefix("16.0.0.0/16")},
				},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: iap("100.64.0.2"),
					IPv6: iap("fd7a:115c:a1e0::2"),
					User: types.User{Name: "user2"},
				},
				&types.Node{
					IPv4: iap("100.64.0.1"),
					IPv6: iap("fd7a:115c:a1e0::1"),
					User: types.User{Name: "user1"},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32", "100.64.0.2/32", "fd7a:115c:a1e0::1/128", "fd7a:115c:a1e0::2/128"},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "100.64.0.100/32",
							Ports: tailcfg.PortRangeAny,
						},
						{
							IP:    "fd7a:115c:a1e0::100/128",
							Ports: tailcfg.PortRangeAny,
						},
					},
				},
				{
					SrcIPs: []string{"100.64.0.1/32", "100.64.0.2/32", "fd7a:115c:a1e0::1/128", "fd7a:115c:a1e0::2/128"},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "8.0.0.0/8",
							Ports: tailcfg.PortRangeAny,
						},
						{
							IP:    "16.0.0.0/8",
							Ports: tailcfg.PortRangeAny,
						},
					},
				},
			},
		},
		{
			name: "1786-reducing-breaks-exit-nodes-app-connector-like2",
			pol: ACLPolicy{
				Hosts: Hosts{
					// Exit node
					"internal": netip.MustParsePrefix("100.64.0.100/32"),
				},
				Groups: Groups{
					"group:team": {"user3", "user2", "user1"},
				},
				ACLs: []ACL{
					{
						Action:  "accept",
						Sources: []string{"group:team"},
						Destinations: []string{
							"internal:*",
						},
					},
					{
						Action:  "accept",
						Sources: []string{"group:team"},
						Destinations: []string{
							"8.0.0.0/16:*",
							"16.0.0.0/16:*",
						},
					},
				},
			},
			node: &types.Node{
				IPv4: iap("100.64.0.100"),
				IPv6: iap("fd7a:115c:a1e0::100"),
				User: types.User{Name: "user100"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{netip.MustParsePrefix("8.0.0.0/8"), netip.MustParsePrefix("16.0.0.0/8")},
				},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: iap("100.64.0.2"),
					IPv6: iap("fd7a:115c:a1e0::2"),
					User: types.User{Name: "user2"},
				},
				&types.Node{
					IPv4: iap("100.64.0.1"),
					IPv6: iap("fd7a:115c:a1e0::1"),
					User: types.User{Name: "user1"},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32", "100.64.0.2/32", "fd7a:115c:a1e0::1/128", "fd7a:115c:a1e0::2/128"},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "100.64.0.100/32",
							Ports: tailcfg.PortRangeAny,
						},
						{
							IP:    "fd7a:115c:a1e0::100/128",
							Ports: tailcfg.PortRangeAny,
						},
					},
				},
				{
					SrcIPs: []string{"100.64.0.1/32", "100.64.0.2/32", "fd7a:115c:a1e0::1/128", "fd7a:115c:a1e0::2/128"},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "8.0.0.0/16",
							Ports: tailcfg.PortRangeAny,
						},
						{
							IP:    "16.0.0.0/16",
							Ports: tailcfg.PortRangeAny,
						},
					},
				},
			},
		},
		{
			name: "1817-reduce-breaks-32-mask",
			pol: ACLPolicy{
				Hosts: Hosts{
					"vlan1": netip.MustParsePrefix("172.16.0.0/24"),
					"dns1":  netip.MustParsePrefix("172.16.0.21/32"),
				},
				Groups: Groups{
					"group:access": {"user1"},
				},
				ACLs: []ACL{
					{
						Action:  "accept",
						Sources: []string{"group:access"},
						Destinations: []string{
							"tag:access-servers:*",
							"dns1:*",
						},
					},
				},
			},
			node: &types.Node{
				IPv4: iap("100.64.0.100"),
				IPv6: iap("fd7a:115c:a1e0::100"),
				User: types.User{Name: "user100"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{netip.MustParsePrefix("172.16.0.0/24")},
				},
				ForcedTags: types.StringList{"tag:access-servers"},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: iap("100.64.0.1"),
					IPv6: iap("fd7a:115c:a1e0::1"),
					User: types.User{Name: "user1"},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32", "fd7a:115c:a1e0::1/128"},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "100.64.0.100/32",
							Ports: tailcfg.PortRangeAny,
						},
						{
							IP:    "fd7a:115c:a1e0::100/128",
							Ports: tailcfg.PortRangeAny,
						},
						{
							IP:    "172.16.0.21/32",
							Ports: tailcfg.PortRangeAny,
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := tt.pol.CompileFilterRules(
				append(tt.peers, tt.node),
			)

			got = ReduceFilterRules(tt.node, got)

			if diff := cmp.Diff(tt.want, got); diff != "" {
				log.Trace().Interface("got", got).Msg("result")
				t.Errorf("TestReduceFilterRules() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_getTags(t *testing.T) {
	type args struct {
		aclPolicy *ACLPolicy
		node      *types.Node
	}
	tests := []struct {
		name        string
		args        args
		wantInvalid []string
		wantValid   []string
	}{
		{
			name: "valid tag one nodes",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{
						"tag:valid": []string{"joe"},
					},
				},
				node: &types.Node{
					User: types.User{
						Name: "joe",
					},
					Hostinfo: &tailcfg.Hostinfo{
						RequestTags: []string{"tag:valid"},
					},
				},
			},
			wantValid:   []string{"tag:valid"},
			wantInvalid: nil,
		},
		{
			name: "invalid tag and valid tag one nodes",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{
						"tag:valid": []string{"joe"},
					},
				},
				node: &types.Node{
					User: types.User{
						Name: "joe",
					},
					Hostinfo: &tailcfg.Hostinfo{
						RequestTags: []string{"tag:valid", "tag:invalid"},
					},
				},
			},
			wantValid:   []string{"tag:valid"},
			wantInvalid: []string{"tag:invalid"},
		},
		{
			name: "multiple invalid and identical tags, should return only one invalid tag",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{
						"tag:valid": []string{"joe"},
					},
				},
				node: &types.Node{
					User: types.User{
						Name: "joe",
					},
					Hostinfo: &tailcfg.Hostinfo{
						RequestTags: []string{
							"tag:invalid",
							"tag:valid",
							"tag:invalid",
						},
					},
				},
			},
			wantValid:   []string{"tag:valid"},
			wantInvalid: []string{"tag:invalid"},
		},
		{
			name: "only invalid tags",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{
						"tag:valid": []string{"joe"},
					},
				},
				node: &types.Node{
					User: types.User{
						Name: "joe",
					},
					Hostinfo: &tailcfg.Hostinfo{
						RequestTags: []string{"tag:invalid", "very-invalid"},
					},
				},
			},
			wantValid:   nil,
			wantInvalid: []string{"tag:invalid", "very-invalid"},
		},
		{
			name: "empty ACLPolicy should return empty tags and should not panic",
			args: args{
				aclPolicy: &ACLPolicy{},
				node: &types.Node{
					User: types.User{
						Name: "joe",
					},
					Hostinfo: &tailcfg.Hostinfo{
						RequestTags: []string{"tag:invalid", "very-invalid"},
					},
				},
			},
			wantValid:   nil,
			wantInvalid: []string{"tag:invalid", "very-invalid"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotValid, gotInvalid := test.args.aclPolicy.TagsOfNode(
				test.args.node,
			)
			for _, valid := range gotValid {
				if !util.StringOrPrefixListContains(test.wantValid, valid) {
					t.Errorf(
						"valids: getTags() = %v, want %v",
						gotValid,
						test.wantValid,
					)

					break
				}
			}
			for _, invalid := range gotInvalid {
				if !util.StringOrPrefixListContains(test.wantInvalid, invalid) {
					t.Errorf(
						"invalids: getTags() = %v, want %v",
						gotInvalid,
						test.wantInvalid,
					)

					break
				}
			}
		})
	}
}

func Test_getFilteredByACLPeers(t *testing.T) {
	type args struct {
		nodes types.Nodes
		rules []tailcfg.FilterRule
		node  *types.Node
	}
	tests := []struct {
		name string
		args args
		want types.Nodes
	}{
		{
			name: "all hosts can talk to each other",
			args: args{
				nodes: types.Nodes{ // list of all nodess in the database
					&types.Node{
						ID:   1,
						IPv4: iap("100.64.0.1"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						ID:   2,
						IPv4: iap("100.64.0.2"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						ID:   3,
						IPv4: iap("100.64.0.3"),
						User: types.User{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						SrcIPs: []string{"100.64.0.1", "100.64.0.2", "100.64.0.3"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*"},
						},
					},
				},
				node: &types.Node{ // current nodes
					ID:   1,
					IPv4: iap("100.64.0.1"),
					User: types.User{Name: "joe"},
				},
			},
			want: types.Nodes{
				&types.Node{
					ID:   2,
					IPv4: iap("100.64.0.2"),
					User: types.User{Name: "marc"},
				},
				&types.Node{
					ID:   3,
					IPv4: iap("100.64.0.3"),
					User: types.User{Name: "mickael"},
				},
			},
		},
		{
			name: "One host can talk to another, but not all hosts",
			args: args{
				nodes: types.Nodes{ // list of all nodess in the database
					&types.Node{
						ID:   1,
						IPv4: iap("100.64.0.1"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						ID:   2,
						IPv4: iap("100.64.0.2"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						ID:   3,
						IPv4: iap("100.64.0.3"),
						User: types.User{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						SrcIPs: []string{"100.64.0.1", "100.64.0.2", "100.64.0.3"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.2"},
						},
					},
				},
				node: &types.Node{ // current nodes
					ID:   1,
					IPv4: iap("100.64.0.1"),
					User: types.User{Name: "joe"},
				},
			},
			want: types.Nodes{
				&types.Node{
					ID:   2,
					IPv4: iap("100.64.0.2"),
					User: types.User{Name: "marc"},
				},
			},
		},
		{
			name: "host cannot directly talk to destination, but return path is authorized",
			args: args{
				nodes: types.Nodes{ // list of all nodess in the database
					&types.Node{
						ID:   1,
						IPv4: iap("100.64.0.1"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						ID:   2,
						IPv4: iap("100.64.0.2"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						ID:   3,
						IPv4: iap("100.64.0.3"),
						User: types.User{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						SrcIPs: []string{"100.64.0.3"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.2"},
						},
					},
				},
				node: &types.Node{ // current nodes
					ID:   2,
					IPv4: iap("100.64.0.2"),
					User: types.User{Name: "marc"},
				},
			},
			want: types.Nodes{
				&types.Node{
					ID:   3,
					IPv4: iap("100.64.0.3"),
					User: types.User{Name: "mickael"},
				},
			},
		},
		{
			name: "rules allows all hosts to reach one destination",
			args: args{
				nodes: types.Nodes{ // list of all nodess in the database
					&types.Node{
						ID:   1,
						IPv4: iap("100.64.0.1"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						ID:   2,
						IPv4: iap("100.64.0.2"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						ID:   3,
						IPv4: iap("100.64.0.3"),
						User: types.User{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						SrcIPs: []string{"*"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.2"},
						},
					},
				},
				node: &types.Node{ // current nodes
					ID:   1,
					IPv4: iap("100.64.0.1"),
					User: types.User{Name: "joe"},
				},
			},
			want: types.Nodes{
				&types.Node{
					ID:   2,
					IPv4: iap("100.64.0.2"),
					User: types.User{Name: "marc"},
				},
			},
		},
		{
			name: "rules allows all hosts to reach one destination, destination can reach all hosts",
			args: args{
				nodes: types.Nodes{ // list of all nodess in the database
					&types.Node{
						ID:   1,
						IPv4: iap("100.64.0.1"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						ID:   2,
						IPv4: iap("100.64.0.2"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						ID:   3,
						IPv4: iap("100.64.0.3"),
						User: types.User{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						SrcIPs: []string{"*"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.2"},
						},
					},
				},
				node: &types.Node{ // current nodes
					ID:   2,
					IPv4: iap("100.64.0.2"),
					User: types.User{Name: "marc"},
				},
			},
			want: types.Nodes{
				&types.Node{
					ID:   1,
					IPv4: iap("100.64.0.1"),
					User: types.User{Name: "joe"},
				},
				&types.Node{
					ID:   3,
					IPv4: iap("100.64.0.3"),
					User: types.User{Name: "mickael"},
				},
			},
		},
		{
			name: "rule allows all hosts to reach all destinations",
			args: args{
				nodes: types.Nodes{ // list of all nodess in the database
					&types.Node{
						ID:   1,
						IPv4: iap("100.64.0.1"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						ID:   2,
						IPv4: iap("100.64.0.2"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						ID:   3,
						IPv4: iap("100.64.0.3"),
						User: types.User{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						SrcIPs: []string{"*"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*"},
						},
					},
				},
				node: &types.Node{ // current nodes
					ID:   2,
					IPv4: iap("100.64.0.2"),
					User: types.User{Name: "marc"},
				},
			},
			want: types.Nodes{
				&types.Node{
					ID:   1,
					IPv4: iap("100.64.0.1"),
					User: types.User{Name: "joe"},
				},
				&types.Node{
					ID:   3,
					IPv4: iap("100.64.0.3"),
					User: types.User{Name: "mickael"},
				},
			},
		},
		{
			name: "without rule all communications are forbidden",
			args: args{
				nodes: types.Nodes{ // list of all nodess in the database
					&types.Node{
						ID:   1,
						IPv4: iap("100.64.0.1"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						ID:   2,
						IPv4: iap("100.64.0.2"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						ID:   3,
						IPv4: iap("100.64.0.3"),
						User: types.User{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
				},
				node: &types.Node{ // current nodes
					ID:   2,
					IPv4: iap("100.64.0.2"),
					User: types.User{Name: "marc"},
				},
			},
			want: types.Nodes{},
		},
		{
			// Investigating 699
			// Found some nodes: [ts-head-8w6paa ts-unstable-lys2ib ts-head-upcrmb ts-unstable-rlwpvr] nodes=ts-head-8w6paa
			// ACL rules generated ACL=[{"DstPorts":[{"Bits":null,"IP":"*","Ports":{"First":0,"Last":65535}}],"SrcIPs":["fd7a:115c:a1e0::3","100.64.0.3","fd7a:115c:a1e0::4","100.64.0.4"]}]
			// ACL Cache Map={"100.64.0.3":{"*":{}},"100.64.0.4":{"*":{}},"fd7a:115c:a1e0::3":{"*":{}},"fd7a:115c:a1e0::4":{"*":{}}}
			name: "issue-699-broken-star",
			args: args{
				nodes: types.Nodes{ //
					&types.Node{
						ID:       1,
						Hostname: "ts-head-upcrmb",
						IPv4:     iap("100.64.0.3"),
						IPv6:     iap("fd7a:115c:a1e0::3"),
						User:     types.User{Name: "user1"},
					},
					&types.Node{
						ID:       2,
						Hostname: "ts-unstable-rlwpvr",
						IPv4:     iap("100.64.0.4"),
						IPv6:     iap("fd7a:115c:a1e0::4"),
						User:     types.User{Name: "user1"},
					},
					&types.Node{
						ID:       3,
						Hostname: "ts-head-8w6paa",
						IPv4:     iap("100.64.0.1"),
						IPv6:     iap("fd7a:115c:a1e0::1"),
						User:     types.User{Name: "user2"},
					},
					&types.Node{
						ID:       4,
						Hostname: "ts-unstable-lys2ib",
						IPv4:     iap("100.64.0.2"),
						IPv6:     iap("fd7a:115c:a1e0::2"),
						User:     types.User{Name: "user2"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						DstPorts: []tailcfg.NetPortRange{
							{
								IP:    "*",
								Ports: tailcfg.PortRange{First: 0, Last: 65535},
							},
						},
						SrcIPs: []string{
							"fd7a:115c:a1e0::3", "100.64.0.3",
							"fd7a:115c:a1e0::4", "100.64.0.4",
						},
					},
				},
				node: &types.Node{ // current nodes
					ID:       3,
					Hostname: "ts-head-8w6paa",
					IPv4:     iap("100.64.0.1"),
					IPv6:     iap("fd7a:115c:a1e0::1"),
					User:     types.User{Name: "user2"},
				},
			},
			want: types.Nodes{
				&types.Node{
					ID:       1,
					Hostname: "ts-head-upcrmb",
					IPv4:     iap("100.64.0.3"),
					IPv6:     iap("fd7a:115c:a1e0::3"),
					User:     types.User{Name: "user1"},
				},
				&types.Node{
					ID:       2,
					Hostname: "ts-unstable-rlwpvr",
					IPv4:     iap("100.64.0.4"),
					IPv6:     iap("fd7a:115c:a1e0::4"),
					User:     types.User{Name: "user1"},
				},
			},
		},
		{
			name: "failing-edge-case-during-p3-refactor",
			args: args{
				nodes: []*types.Node{
					{
						ID:       1,
						IPv4:     iap("100.64.0.2"),
						Hostname: "peer1",
						User:     types.User{Name: "mini"},
					},
					{
						ID:       2,
						IPv4:     iap("100.64.0.3"),
						Hostname: "peer2",
						User:     types.User{Name: "peer2"},
					},
				},
				rules: []tailcfg.FilterRule{
					{
						SrcIPs: []string{"100.64.0.1/32"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.3/32", Ports: tailcfg.PortRangeAny},
							{IP: "::/0", Ports: tailcfg.PortRangeAny},
						},
					},
				},
				node: &types.Node{
					ID:       0,
					IPv4:     iap("100.64.0.1"),
					Hostname: "mini",
					User:     types.User{Name: "mini"},
				},
			},
			want: []*types.Node{
				{
					ID:       2,
					IPv4:     iap("100.64.0.3"),
					Hostname: "peer2",
					User:     types.User{Name: "peer2"},
				},
			},
		},
		{
			name: "p4-host-in-netmap-user2-dest-bug",
			args: args{
				nodes: []*types.Node{
					{
						ID:       1,
						IPv4:     iap("100.64.0.2"),
						Hostname: "user1-2",
						User:     types.User{Name: "user1"},
					},
					{
						ID:       0,
						IPv4:     iap("100.64.0.1"),
						Hostname: "user1-1",
						User:     types.User{Name: "user1"},
					},
					{
						ID:       3,
						IPv4:     iap("100.64.0.4"),
						Hostname: "user2-2",
						User:     types.User{Name: "user2"},
					},
				},
				rules: []tailcfg.FilterRule{
					{
						SrcIPs: []string{
							"100.64.0.3/32",
							"100.64.0.4/32",
							"fd7a:115c:a1e0::3/128",
							"fd7a:115c:a1e0::4/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.3/32", Ports: tailcfg.PortRangeAny},
							{IP: "100.64.0.4/32", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::3/128", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::4/128", Ports: tailcfg.PortRangeAny},
						},
					},
					{
						SrcIPs: []string{
							"100.64.0.1/32",
							"100.64.0.2/32",
							"fd7a:115c:a1e0::1/128",
							"fd7a:115c:a1e0::2/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.3/32", Ports: tailcfg.PortRangeAny},
							{IP: "100.64.0.4/32", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::3/128", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::4/128", Ports: tailcfg.PortRangeAny},
						},
					},
				},
				node: &types.Node{
					ID:       2,
					IPv4:     iap("100.64.0.3"),
					Hostname: "user-2-1",
					User:     types.User{Name: "user2"},
				},
			},
			want: []*types.Node{
				{
					ID:       1,
					IPv4:     iap("100.64.0.2"),
					Hostname: "user1-2",
					User:     types.User{Name: "user1"},
				},
				{
					ID:       0,
					IPv4:     iap("100.64.0.1"),
					Hostname: "user1-1",
					User:     types.User{Name: "user1"},
				},
				{
					ID:       3,
					IPv4:     iap("100.64.0.4"),
					Hostname: "user2-2",
					User:     types.User{Name: "user2"},
				},
			},
		},
		{
			name: "p4-host-in-netmap-user1-dest-bug",
			args: args{
				nodes: []*types.Node{
					{
						ID:       1,
						IPv4:     iap("100.64.0.2"),
						Hostname: "user1-2",
						User:     types.User{Name: "user1"},
					},
					{
						ID:       2,
						IPv4:     iap("100.64.0.3"),
						Hostname: "user-2-1",
						User:     types.User{Name: "user2"},
					},
					{
						ID:       3,
						IPv4:     iap("100.64.0.4"),
						Hostname: "user2-2",
						User:     types.User{Name: "user2"},
					},
				},
				rules: []tailcfg.FilterRule{
					{
						SrcIPs: []string{
							"100.64.0.1/32",
							"100.64.0.2/32",
							"fd7a:115c:a1e0::1/128",
							"fd7a:115c:a1e0::2/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.1/32", Ports: tailcfg.PortRangeAny},
							{IP: "100.64.0.2/32", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::1/128", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::2/128", Ports: tailcfg.PortRangeAny},
						},
					},
					{
						SrcIPs: []string{
							"100.64.0.1/32",
							"100.64.0.2/32",
							"fd7a:115c:a1e0::1/128",
							"fd7a:115c:a1e0::2/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.3/32", Ports: tailcfg.PortRangeAny},
							{IP: "100.64.0.4/32", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::3/128", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::4/128", Ports: tailcfg.PortRangeAny},
						},
					},
				},
				node: &types.Node{
					ID:       0,
					IPv4:     iap("100.64.0.1"),
					Hostname: "user1-1",
					User:     types.User{Name: "user1"},
				},
			},
			want: []*types.Node{
				{
					ID:       1,
					IPv4:     iap("100.64.0.2"),
					Hostname: "user1-2",
					User:     types.User{Name: "user1"},
				},
				{
					ID:       2,
					IPv4:     iap("100.64.0.3"),
					Hostname: "user-2-1",
					User:     types.User{Name: "user2"},
				},
				{
					ID:       3,
					IPv4:     iap("100.64.0.4"),
					Hostname: "user2-2",
					User:     types.User{Name: "user2"},
				},
			},
		},

		{
			name: "subnet-router-with-only-route",
			args: args{
				nodes: []*types.Node{
					{
						ID:       1,
						IPv4:     iap("100.64.0.1"),
						Hostname: "user1",
						User:     types.User{Name: "user1"},
					},
					{
						ID:       2,
						IPv4:     iap("100.64.0.2"),
						Hostname: "router",
						User:     types.User{Name: "router"},
						Routes: types.Routes{
							types.Route{
								NodeID:    2,
								Prefix:    types.IPPrefix(netip.MustParsePrefix("10.33.0.0/16")),
								IsPrimary: true,
								Enabled:   true,
							},
						},
					},
				},
				rules: []tailcfg.FilterRule{
					{
						SrcIPs: []string{
							"100.64.0.1/32",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "10.33.0.0/16", Ports: tailcfg.PortRangeAny},
						},
					},
				},
				node: &types.Node{
					ID:       1,
					IPv4:     iap("100.64.0.1"),
					Hostname: "user1",
					User:     types.User{Name: "user1"},
				},
			},
			want: []*types.Node{
				{
					ID:       2,
					IPv4:     iap("100.64.0.2"),
					Hostname: "router",
					User:     types.User{Name: "router"},
					Routes: types.Routes{
						types.Route{
							NodeID:    2,
							Prefix:    types.IPPrefix(netip.MustParsePrefix("10.33.0.0/16")),
							IsPrimary: true,
							Enabled:   true,
						},
					},
				},
			},
		},
	}

	// TODO(kradalby): Remove when we have gotten rid of IPPrefix type
	prefixComparer := cmp.Comparer(func(x, y types.IPPrefix) bool {
		return x == y
	})
	comparers := append([]cmp.Option{}, util.Comparers...)
	comparers = append(comparers, prefixComparer)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterNodesByACL(
				tt.args.node,
				tt.args.nodes,
				tt.args.rules,
			)
			if diff := cmp.Diff(tt.want, got, comparers...); diff != "" {
				t.Errorf("FilterNodesByACL() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSSHRules(t *testing.T) {
	tests := []struct {
		name  string
		node  types.Node
		peers types.Nodes
		pol   ACLPolicy
		want  *tailcfg.SSHPolicy
	}{
		{
			name: "peers-can-connect",
			node: types.Node{
				Hostname: "testnodes",
				IPv4:     iap("100.64.99.42"),
				UserID:   0,
				User: types.User{
					Name: "user1",
				},
			},
			peers: types.Nodes{
				&types.Node{
					Hostname: "testnodes2",
					IPv4:     iap("100.64.0.1"),
					UserID:   0,
					User: types.User{
						Name: "user1",
					},
				},
			},
			pol: ACLPolicy{
				Groups: Groups{
					"group:test": []string{"user1"},
				},
				Hosts: Hosts{
					"client": netip.PrefixFrom(netip.MustParseAddr("100.64.99.42"), 32),
				},
				ACLs: []ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:*"},
					},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      []string{"group:test"},
						Destinations: []string{"client"},
						Users:        []string{"autogroup:nonroot"},
					},
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"client"},
						Users:        []string{"autogroup:nonroot"},
					},
					{
						Action:       "accept",
						Sources:      []string{"group:test"},
						Destinations: []string{"100.64.99.42"},
						Users:        []string{"autogroup:nonroot"},
					},
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"100.64.99.42"},
						Users:        []string{"autogroup:nonroot"},
					},
				},
			},
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{
						{
							UserLogin: "user1",
						},
					},
					SSHUsers: map[string]string{
						"autogroup:nonroot": "=",
					},
					Action: &tailcfg.SSHAction{Accept: true, AllowLocalPortForwarding: true},
				},
				{
					SSHUsers: map[string]string{
						"autogroup:nonroot": "=",
					},
					Principals: []*tailcfg.SSHPrincipal{
						{
							Any: true,
						},
					},
					Action: &tailcfg.SSHAction{Accept: true, AllowLocalPortForwarding: true},
				},
				{
					Principals: []*tailcfg.SSHPrincipal{
						{
							UserLogin: "user1",
						},
					},
					SSHUsers: map[string]string{
						"autogroup:nonroot": "=",
					},
					Action: &tailcfg.SSHAction{Accept: true, AllowLocalPortForwarding: true},
				},
				{
					SSHUsers: map[string]string{
						"autogroup:nonroot": "=",
					},
					Principals: []*tailcfg.SSHPrincipal{
						{
							Any: true,
						},
					},
					Action: &tailcfg.SSHAction{Accept: true, AllowLocalPortForwarding: true},
				},
			}},
		},
		{
			name: "peers-cannot-connect",
			node: types.Node{
				Hostname: "testnodes",
				IPv4:     iap("100.64.0.1"),
				UserID:   0,
				User: types.User{
					Name: "user1",
				},
			},
			peers: types.Nodes{
				&types.Node{
					Hostname: "testnodes2",
					IPv4:     iap("100.64.99.42"),
					UserID:   0,
					User: types.User{
						Name: "user1",
					},
				},
			},
			pol: ACLPolicy{
				Groups: Groups{
					"group:test": []string{"user1"},
				},
				Hosts: Hosts{
					"client": netip.PrefixFrom(netip.MustParseAddr("100.64.99.42"), 32),
				},
				ACLs: []ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:*"},
					},
				},
				SSHs: []SSH{
					{
						Action:       "accept",
						Sources:      []string{"group:test"},
						Destinations: []string{"100.64.99.42"},
						Users:        []string{"autogroup:nonroot"},
					},
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"100.64.99.42"},
						Users:        []string{"autogroup:nonroot"},
					},
				},
			},
			want: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.pol.CompileSSHPolicy(&tt.node, tt.peers)
			assert.NoError(t, err)

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("TestSSHRules() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseDestination(t *testing.T) {
	tests := []struct {
		dest      string
		wantAlias string
		wantPort  string
	}{
		{
			dest:      "git-server:*",
			wantAlias: "git-server",
			wantPort:  "*",
		},
		{
			dest:      "192.168.1.0/24:22",
			wantAlias: "192.168.1.0/24",
			wantPort:  "22",
		},
		{
			dest:      "192.168.1.1:22",
			wantAlias: "192.168.1.1",
			wantPort:  "22",
		},
		{
			dest:      "fd7a:115c:a1e0::2:22",
			wantAlias: "fd7a:115c:a1e0::2",
			wantPort:  "22",
		},
		{
			dest:      "fd7a:115c:a1e0::2/128:22",
			wantAlias: "fd7a:115c:a1e0::2/128",
			wantPort:  "22",
		},
		{
			dest:      "tag:montreal-webserver:80,443",
			wantAlias: "tag:montreal-webserver",
			wantPort:  "80,443",
		},
		{
			dest:      "tag:api-server:443",
			wantAlias: "tag:api-server",
			wantPort:  "443",
		},
		{
			dest:      "example-host-1:*",
			wantAlias: "example-host-1",
			wantPort:  "*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.dest, func(t *testing.T) {
			alias, port, _ := parseDestination(tt.dest)

			if alias != tt.wantAlias {
				t.Errorf("unexpected alias: want(%s) != got(%s)", tt.wantAlias, alias)
			}

			if port != tt.wantPort {
				t.Errorf("unexpected port: want(%s) != got(%s)", tt.wantPort, port)
			}
		})
	}
}

// this test should validate that we can expand a group in a TagOWner section and
// match properly the IP's of the related hosts. The owner is valid and the tag is also valid.
// the tag is matched in the Sources section.
func TestValidExpandTagOwnersInSources(t *testing.T) {
	hostInfo := tailcfg.Hostinfo{
		OS:          "centos",
		Hostname:    "testnodes",
		RequestTags: []string{"tag:test"},
	}

	node := &types.Node{
		ID:       0,
		Hostname: "testnodes",
		IPv4:     iap("100.64.0.1"),
		UserID:   0,
		User: types.User{
			Name: "user1",
		},
		RegisterMethod: util.RegisterMethodAuthKey,
		Hostinfo:       &hostInfo,
	}

	pol := &ACLPolicy{
		Groups:    Groups{"group:test": []string{"user1", "user2"}},
		TagOwners: TagOwners{"tag:test": []string{"user3", "group:test"}},
		ACLs: []ACL{
			{
				Action:       "accept",
				Sources:      []string{"tag:test"},
				Destinations: []string{"*:*"},
			},
		},
	}

	got, _, err := GenerateFilterAndSSHRulesForTests(pol, node, types.Nodes{})
	assert.NoError(t, err)

	want := []tailcfg.FilterRule{
		{
			SrcIPs: []string{"100.64.0.1/32"},
			DstPorts: []tailcfg.NetPortRange{
				{IP: "0.0.0.0/0", Ports: tailcfg.PortRange{Last: 65535}},
				{IP: "::/0", Ports: tailcfg.PortRange{Last: 65535}},
			},
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("TestValidExpandTagOwnersInSources() unexpected result (-want +got):\n%s", diff)
	}
}

// need a test with:
// tag on a host that isn't owned by a tag owners. So the user
// of the host should be valid.
func TestInvalidTagValidUser(t *testing.T) {
	hostInfo := tailcfg.Hostinfo{
		OS:          "centos",
		Hostname:    "testnodes",
		RequestTags: []string{"tag:foo"},
	}

	node := &types.Node{
		ID:       1,
		Hostname: "testnodes",
		IPv4:     iap("100.64.0.1"),
		UserID:   1,
		User: types.User{
			Name: "user1",
		},
		RegisterMethod: util.RegisterMethodAuthKey,
		Hostinfo:       &hostInfo,
	}

	pol := &ACLPolicy{
		TagOwners: TagOwners{"tag:test": []string{"user1"}},
		ACLs: []ACL{
			{
				Action:       "accept",
				Sources:      []string{"user1"},
				Destinations: []string{"*:*"},
			},
		},
	}

	got, _, err := GenerateFilterAndSSHRulesForTests(pol, node, types.Nodes{})
	assert.NoError(t, err)

	want := []tailcfg.FilterRule{
		{
			SrcIPs: []string{"100.64.0.1/32"},
			DstPorts: []tailcfg.NetPortRange{
				{IP: "0.0.0.0/0", Ports: tailcfg.PortRange{Last: 65535}},
				{IP: "::/0", Ports: tailcfg.PortRange{Last: 65535}},
			},
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("TestInvalidTagValidUser() unexpected result (-want +got):\n%s", diff)
	}
}

// this test should validate that we can expand a group in a TagOWner section and
// match properly the IP's of the related hosts. The owner is valid and the tag is also valid.
// the tag is matched in the Destinations section.
func TestValidExpandTagOwnersInDestinations(t *testing.T) {
	hostInfo := tailcfg.Hostinfo{
		OS:          "centos",
		Hostname:    "testnodes",
		RequestTags: []string{"tag:test"},
	}

	node := &types.Node{
		ID:       1,
		Hostname: "testnodes",
		IPv4:     iap("100.64.0.1"),
		UserID:   1,
		User: types.User{
			Name: "user1",
		},
		RegisterMethod: util.RegisterMethodAuthKey,
		Hostinfo:       &hostInfo,
	}

	pol := &ACLPolicy{
		Groups:    Groups{"group:test": []string{"user1", "user2"}},
		TagOwners: TagOwners{"tag:test": []string{"user3", "group:test"}},
		ACLs: []ACL{
			{
				Action:       "accept",
				Sources:      []string{"*"},
				Destinations: []string{"tag:test:*"},
			},
		},
	}

	// rules, _, err := GenerateFilterRules(pol, &node, peers, false)
	// c.Assert(err, check.IsNil)
	//
	// c.Assert(rules, check.HasLen, 1)
	// c.Assert(rules[0].DstPorts, check.HasLen, 1)
	// c.Assert(rules[0].DstPorts[0].IP, check.Equals, "100.64.0.1/32")

	got, _, err := GenerateFilterAndSSHRulesForTests(pol, node, types.Nodes{})
	assert.NoError(t, err)

	want := []tailcfg.FilterRule{
		{
			SrcIPs: []string{"0.0.0.0/0", "::/0"},
			DstPorts: []tailcfg.NetPortRange{
				{IP: "100.64.0.1/32", Ports: tailcfg.PortRange{Last: 65535}},
			},
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf(
			"TestValidExpandTagOwnersInDestinations() unexpected result (-want +got):\n%s",
			diff,
		)
	}
}

// tag on a host is owned by a tag owner, the tag is valid.
// an ACL rule is matching the tag to a user. It should not be valid since the
// host should be tied to the tag now.
func TestValidTagInvalidUser(t *testing.T) {
	hostInfo := tailcfg.Hostinfo{
		OS:          "centos",
		Hostname:    "webserver",
		RequestTags: []string{"tag:webapp"},
	}

	node := &types.Node{
		ID:       1,
		Hostname: "webserver",
		IPv4:     iap("100.64.0.1"),
		UserID:   1,
		User: types.User{
			Name: "user1",
		},
		RegisterMethod: util.RegisterMethodAuthKey,
		Hostinfo:       &hostInfo,
	}

	hostInfo2 := tailcfg.Hostinfo{
		OS:       "debian",
		Hostname: "Hostname",
	}

	nodes2 := &types.Node{
		ID:       2,
		Hostname: "user",
		IPv4:     iap("100.64.0.2"),
		UserID:   1,
		User: types.User{
			Name: "user1",
		},
		RegisterMethod: util.RegisterMethodAuthKey,
		Hostinfo:       &hostInfo2,
	}

	pol := &ACLPolicy{
		TagOwners: TagOwners{"tag:webapp": []string{"user1"}},
		ACLs: []ACL{
			{
				Action:       "accept",
				Sources:      []string{"user1"},
				Destinations: []string{"tag:webapp:80,443"},
			},
		},
	}

	got, _, err := GenerateFilterAndSSHRulesForTests(pol, node, types.Nodes{nodes2})
	assert.NoError(t, err)

	want := []tailcfg.FilterRule{
		{
			SrcIPs: []string{"100.64.0.2/32"},
			DstPorts: []tailcfg.NetPortRange{
				{IP: "100.64.0.1/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
				{IP: "100.64.0.1/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
			},
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("TestValidTagInvalidUser() unexpected result (-want +got):\n%s", diff)
	}
}
