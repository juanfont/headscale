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

var ipComparer = cmp.Comparer(func(x, y netip.Addr) bool {
	return x.Compare(y) == 0
})

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

			rules, err := pol.generateFilterRules(&types.Machine{
				IPAddresses: types.MachineAddresses{
					netip.MustParseAddr("100.100.100.100"),
				},
			}, types.Machines{
				types.Machine{
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("200.200.200.200"),
					},
					User: types.User{
						Name: "testuser",
					},
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

	rules, err := pol.generateFilterRules(&types.Machine{}, types.Machines{})
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
	_, _, err := GenerateFilterAndSSHRules(pol, &types.Machine{}, types.Machines{})
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
	_, _, err := GenerateFilterAndSSHRules(pol, &types.Machine{}, types.Machines{})
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

	_, _, err := GenerateFilterAndSSHRules(pol, &types.Machine{}, types.Machines{})
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

func Test_listMachinesInUser(t *testing.T) {
	type args struct {
		machines types.Machines
		user     string
	}
	tests := []struct {
		name string
		args args
		want types.Machines
	}{
		{
			name: "1 machine in user",
			args: args{
				machines: types.Machines{
					{User: types.User{Name: "joe"}},
				},
				user: "joe",
			},
			want: types.Machines{
				{User: types.User{Name: "joe"}},
			},
		},
		{
			name: "3 machines, 2 in user",
			args: args{
				machines: types.Machines{
					{ID: 1, User: types.User{Name: "joe"}},
					{ID: 2, User: types.User{Name: "marc"}},
					{ID: 3, User: types.User{Name: "marc"}},
				},
				user: "marc",
			},
			want: types.Machines{
				{ID: 2, User: types.User{Name: "marc"}},
				{ID: 3, User: types.User{Name: "marc"}},
			},
		},
		{
			name: "5 machines, 0 in user",
			args: args{
				machines: types.Machines{
					{ID: 1, User: types.User{Name: "joe"}},
					{ID: 2, User: types.User{Name: "marc"}},
					{ID: 3, User: types.User{Name: "marc"}},
					{ID: 4, User: types.User{Name: "marc"}},
					{ID: 5, User: types.User{Name: "marc"}},
				},
				user: "mickael",
			},
			want: types.Machines{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := filterMachinesByUser(test.args.machines, test.args.user)

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("listMachinesInUser() = (-want +got):\n%s", diff)
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
		machines  types.Machines
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
				machines: types.Machines{
					{IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.1")}},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.78.84.227"),
						},
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
				machines: types.Machines{
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: types.User{Name: "joe"},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: types.User{Name: "joe"},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: types.User{Name: "marc"},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
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
				machines: types.Machines{
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: types.User{Name: "joe"},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: types.User{Name: "joe"},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: types.User{Name: "marc"},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
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
				alias:    "10.0.0.3",
				machines: types.Machines{},
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
				alias:    "10.0.0.1",
				machines: types.Machines{},
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
				machines: types.Machines{
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("10.0.0.1"),
						},
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
				machines: types.Machines{
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("10.0.0.1"),
							netip.MustParseAddr("fd7a:115c:a1e0:ab12:4843:2222:6273:2222"),
						},
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
				machines: types.Machines{
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("10.0.0.1"),
							netip.MustParseAddr("fd7a:115c:a1e0:ab12:4843:2222:6273:2222"),
						},
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
				alias:    "testy",
				machines: types.Machines{},
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
				alias:    "homeNetwork",
				machines: types.Machines{},
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
				machines:  types.Machines{},
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
				machines: types.Machines{
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: types.User{Name: "joe"},
						HostInfo: types.HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: types.User{Name: "joe"},
						HostInfo: types.HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: types.User{Name: "marc"},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
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
				machines: types.Machines{
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: types.User{Name: "joe"},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: types.User{Name: "joe"},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: types.User{Name: "marc"},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
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
				machines: types.Machines{
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User:       types.User{Name: "joe"},
						ForcedTags: []string{"tag:hr-webserver"},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User:       types.User{Name: "joe"},
						ForcedTags: []string{"tag:hr-webserver"},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: types.User{Name: "marc"},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
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
				machines: types.Machines{
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User:       types.User{Name: "joe"},
						ForcedTags: []string{"tag:hr-webserver"},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: types.User{Name: "joe"},
						HostInfo: types.HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: types.User{Name: "marc"},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
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
				machines: types.Machines{
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: types.User{Name: "joe"},
						HostInfo: types.HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: types.User{Name: "joe"},
						HostInfo: types.HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: types.User{Name: "marc"},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
						User: types.User{Name: "joe"},
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
				test.args.machines,
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
		nodes     types.Machines
		user      string
	}
	tests := []struct {
		name    string
		args    args
		want    types.Machines
		wantErr bool
	}{
		{
			name: "exclude nodes with valid tags",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{"tag:accountant-webserver": []string{"joe"}},
				},
				nodes: types.Machines{
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: types.User{Name: "joe"},
						HostInfo: types.HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: types.User{Name: "joe"},
						HostInfo: types.HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
						User: types.User{Name: "joe"},
					},
				},
				user: "joe",
			},
			want: types.Machines{
				{
					IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.4")},
					User:        types.User{Name: "joe"},
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
				nodes: types.Machines{
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: types.User{Name: "joe"},
						HostInfo: types.HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: types.User{Name: "joe"},
						HostInfo: types.HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
						User: types.User{Name: "joe"},
					},
				},
				user: "joe",
			},
			want: types.Machines{
				{
					IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.4")},
					User:        types.User{Name: "joe"},
				},
			},
		},
		{
			name: "exclude nodes with valid tags and with forced tags",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{"tag:accountant-webserver": []string{"joe"}},
				},
				nodes: types.Machines{
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: types.User{Name: "joe"},
						HostInfo: types.HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User:       types.User{Name: "joe"},
						ForcedTags: []string{"tag:accountant-webserver"},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
						User: types.User{Name: "joe"},
					},
				},
				user: "joe",
			},
			want: types.Machines{
				{
					IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.4")},
					User:        types.User{Name: "joe"},
				},
			},
		},
		{
			name: "all nodes have invalid tags, don't exclude them",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{"tag:accountant-webserver": []string{"joe"}},
				},
				nodes: types.Machines{
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: types.User{Name: "joe"},
						HostInfo: types.HostInfo{
							OS:          "centos",
							Hostname:    "hr-web1",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: types.User{Name: "joe"},
						HostInfo: types.HostInfo{
							OS:          "centos",
							Hostname:    "hr-web2",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
						User: types.User{Name: "joe"},
					},
				},
				user: "joe",
			},
			want: types.Machines{
				{
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("100.64.0.1"),
					},
					User: types.User{Name: "joe"},
					HostInfo: types.HostInfo{
						OS:          "centos",
						Hostname:    "hr-web1",
						RequestTags: []string{"tag:hr-webserver"},
					},
				},
				{
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("100.64.0.2"),
					},
					User: types.User{Name: "joe"},
					HostInfo: types.HostInfo{
						OS:          "centos",
						Hostname:    "hr-web2",
						RequestTags: []string{"tag:hr-webserver"},
					},
				},
				{
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("100.64.0.4"),
					},
					User: types.User{Name: "joe"},
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
			if diff := cmp.Diff(test.want, got, ipComparer); diff != "" {
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
		machine types.Machine
		peers   types.Machines
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
				machine: types.Machine{
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("100.64.0.1"),
						netip.MustParseAddr("fd7a:115c:a1e0:ab12:4843:2222:6273:2221"),
					},
				},
				peers: types.Machines{},
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
				machine: types.Machine{
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("100.64.0.1"),
						netip.MustParseAddr("fd7a:115c:a1e0:ab12:4843:2222:6273:2221"),
					},
					User: types.User{Name: "mickael"},
				},
				peers: types.Machines{
					{
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
							netip.MustParseAddr("fd7a:115c:a1e0:ab12:4843:2222:6273:2222"),
						},
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
			got, err := tt.field.pol.generateFilterRules(
				&tt.args.machine,
				tt.args.peers,
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

func TestReduceFilterRules(t *testing.T) {
	tests := []struct {
		name    string
		machine types.Machine
		peers   types.Machines
		pol     ACLPolicy
		want    []tailcfg.FilterRule
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
			machine: types.Machine{
				IPAddresses: types.MachineAddresses{
					netip.MustParseAddr("100.64.0.1"),
					netip.MustParseAddr("fd7a:115c:a1e0:ab12:4843:2222:6273:2221"),
				},
				User: types.User{Name: "mickael"},
			},
			peers: types.Machines{
				{
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("100.64.0.2"),
						netip.MustParseAddr("fd7a:115c:a1e0:ab12:4843:2222:6273:2222"),
					},
					User: types.User{Name: "mickael"},
				},
			},
			want: []tailcfg.FilterRule{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, _ := tt.pol.generateFilterRules(
				&tt.machine,
				tt.peers,
			)

			got := ReduceFilterRules(&tt.machine, rules)

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
		machine   types.Machine
	}
	tests := []struct {
		name        string
		args        args
		wantInvalid []string
		wantValid   []string
	}{
		{
			name: "valid tag one machine",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{
						"tag:valid": []string{"joe"},
					},
				},
				machine: types.Machine{
					User: types.User{
						Name: "joe",
					},
					HostInfo: types.HostInfo{
						RequestTags: []string{"tag:valid"},
					},
				},
			},
			wantValid:   []string{"tag:valid"},
			wantInvalid: nil,
		},
		{
			name: "invalid tag and valid tag one machine",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{
						"tag:valid": []string{"joe"},
					},
				},
				machine: types.Machine{
					User: types.User{
						Name: "joe",
					},
					HostInfo: types.HostInfo{
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
				machine: types.Machine{
					User: types.User{
						Name: "joe",
					},
					HostInfo: types.HostInfo{
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
				machine: types.Machine{
					User: types.User{
						Name: "joe",
					},
					HostInfo: types.HostInfo{
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
				machine: types.Machine{
					User: types.User{
						Name: "joe",
					},
					HostInfo: types.HostInfo{
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
			gotValid, gotInvalid := test.args.aclPolicy.TagsOfMachine(
				test.args.machine,
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
	ipComparer := cmp.Comparer(func(x, y netip.Addr) bool {
		return x.Compare(y) == 0
	})

	type args struct {
		machines types.Machines
		rules    []tailcfg.FilterRule
		machine  *types.Machine
	}
	tests := []struct {
		name string
		args args
		want types.Machines
	}{
		{
			name: "all hosts can talk to each other",
			args: args{
				machines: types.Machines{ // list of all machines in the database
					{
						ID: 1,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: types.User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: types.User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
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
				machine: &types.Machine{ // current machine
					ID:          1,
					IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.1")},
					User:        types.User{Name: "joe"},
				},
			},
			want: types.Machines{
				{
					ID:          2,
					IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.2")},
					User:        types.User{Name: "marc"},
				},
				{
					ID:          3,
					IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.3")},
					User:        types.User{Name: "mickael"},
				},
			},
		},
		{
			name: "One host can talk to another, but not all hosts",
			args: args{
				machines: types.Machines{ // list of all machines in the database
					{
						ID: 1,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: types.User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: types.User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
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
				machine: &types.Machine{ // current machine
					ID:          1,
					IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.1")},
					User:        types.User{Name: "joe"},
				},
			},
			want: types.Machines{
				{
					ID:          2,
					IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.2")},
					User:        types.User{Name: "marc"},
				},
			},
		},
		{
			name: "host cannot directly talk to destination, but return path is authorized",
			args: args{
				machines: types.Machines{ // list of all machines in the database
					{
						ID: 1,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: types.User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: types.User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
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
				machine: &types.Machine{ // current machine
					ID:          2,
					IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.2")},
					User:        types.User{Name: "marc"},
				},
			},
			want: types.Machines{
				{
					ID:          3,
					IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.3")},
					User:        types.User{Name: "mickael"},
				},
			},
		},
		{
			name: "rules allows all hosts to reach one destination",
			args: args{
				machines: types.Machines{ // list of all machines in the database
					{
						ID: 1,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: types.User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: types.User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
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
				machine: &types.Machine{ // current machine
					ID: 1,
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("100.64.0.1"),
					},
					User: types.User{Name: "joe"},
				},
			},
			want: types.Machines{
				{
					ID: 2,
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("100.64.0.2"),
					},
					User: types.User{Name: "marc"},
				},
			},
		},
		{
			name: "rules allows all hosts to reach one destination, destination can reach all hosts",
			args: args{
				machines: types.Machines{ // list of all machines in the database
					{
						ID: 1,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: types.User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: types.User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
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
				machine: &types.Machine{ // current machine
					ID: 2,
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("100.64.0.2"),
					},
					User: types.User{Name: "marc"},
				},
			},
			want: types.Machines{
				{
					ID: 1,
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("100.64.0.1"),
					},
					User: types.User{Name: "joe"},
				},
				{
					ID: 3,
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("100.64.0.3"),
					},
					User: types.User{Name: "mickael"},
				},
			},
		},
		{
			name: "rule allows all hosts to reach all destinations",
			args: args{
				machines: types.Machines{ // list of all machines in the database
					{
						ID: 1,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: types.User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: types.User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
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
				machine: &types.Machine{ // current machine
					ID:          2,
					IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.2")},
					User:        types.User{Name: "marc"},
				},
			},
			want: types.Machines{
				{
					ID: 1,
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("100.64.0.1"),
					},
					User: types.User{Name: "joe"},
				},
				{
					ID:          3,
					IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.3")},
					User:        types.User{Name: "mickael"},
				},
			},
		},
		{
			name: "without rule all communications are forbidden",
			args: args{
				machines: types.Machines{ // list of all machines in the database
					{
						ID: 1,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: types.User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: types.User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: types.User{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
				},
				machine: &types.Machine{ // current machine
					ID:          2,
					IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.2")},
					User:        types.User{Name: "marc"},
				},
			},
			want: types.Machines{},
		},
		{
			// Investigating 699
			// Found some machines: [ts-head-8w6paa ts-unstable-lys2ib ts-head-upcrmb ts-unstable-rlwpvr] machine=ts-head-8w6paa
			// ACL rules generated ACL=[{"DstPorts":[{"Bits":null,"IP":"*","Ports":{"First":0,"Last":65535}}],"SrcIPs":["fd7a:115c:a1e0::3","100.64.0.3","fd7a:115c:a1e0::4","100.64.0.4"]}]
			// ACL Cache Map={"100.64.0.3":{"*":{}},"100.64.0.4":{"*":{}},"fd7a:115c:a1e0::3":{"*":{}},"fd7a:115c:a1e0::4":{"*":{}}}
			name: "issue-699-broken-star",
			args: args{
				machines: types.Machines{ //
					{
						ID:       1,
						Hostname: "ts-head-upcrmb",
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
							netip.MustParseAddr("fd7a:115c:a1e0::3"),
						},
						User: types.User{Name: "user1"},
					},
					{
						ID:       2,
						Hostname: "ts-unstable-rlwpvr",
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
							netip.MustParseAddr("fd7a:115c:a1e0::4"),
						},
						User: types.User{Name: "user1"},
					},
					{
						ID:       3,
						Hostname: "ts-head-8w6paa",
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
							netip.MustParseAddr("fd7a:115c:a1e0::1"),
						},
						User: types.User{Name: "user2"},
					},
					{
						ID:       4,
						Hostname: "ts-unstable-lys2ib",
						IPAddresses: types.MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
							netip.MustParseAddr("fd7a:115c:a1e0::2"),
						},
						User: types.User{Name: "user2"},
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
				machine: &types.Machine{ // current machine
					ID:       3,
					Hostname: "ts-head-8w6paa",
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("100.64.0.1"),
						netip.MustParseAddr("fd7a:115c:a1e0::1"),
					},
					User: types.User{Name: "user2"},
				},
			},
			want: types.Machines{
				{
					ID:       1,
					Hostname: "ts-head-upcrmb",
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("100.64.0.3"),
						netip.MustParseAddr("fd7a:115c:a1e0::3"),
					},
					User: types.User{Name: "user1"},
				},
				{
					ID:       2,
					Hostname: "ts-unstable-rlwpvr",
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("100.64.0.4"),
						netip.MustParseAddr("fd7a:115c:a1e0::4"),
					},
					User: types.User{Name: "user1"},
				},
			},
		},
		{
			name: "failing-edge-case-during-p3-refactor",
			args: args{
				machines: []types.Machine{
					{
						ID:          1,
						IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
						Hostname:    "peer1",
						User:        types.User{Name: "mini"},
					},
					{
						ID:          2,
						IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
						Hostname:    "peer2",
						User:        types.User{Name: "peer2"},
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
				machine: &types.Machine{
					ID:          0,
					IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
					Hostname:    "mini",
					User:        types.User{Name: "mini"},
				},
			},
			want: []types.Machine{
				{
					ID:          2,
					IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
					Hostname:    "peer2",
					User:        types.User{Name: "peer2"},
				},
			},
		},
		{
			name: "p4-host-in-netmap-user2-dest-bug",
			args: args{
				machines: []types.Machine{
					{
						ID:          1,
						IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
						Hostname:    "user1-2",
						User:        types.User{Name: "user1"},
					},
					{
						ID:          0,
						IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
						Hostname:    "user1-1",
						User:        types.User{Name: "user1"},
					},
					{
						ID:          3,
						IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.4")},
						Hostname:    "user2-2",
						User:        types.User{Name: "user2"},
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
				machine: &types.Machine{
					ID:          2,
					IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
					Hostname:    "user-2-1",
					User:        types.User{Name: "user2"},
				},
			},
			want: []types.Machine{
				{
					ID:          1,
					IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
					Hostname:    "user1-2",
					User:        types.User{Name: "user1"},
				},
				{
					ID:          0,
					IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
					Hostname:    "user1-1",
					User:        types.User{Name: "user1"},
				},
				{
					ID:          3,
					IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.4")},
					Hostname:    "user2-2",
					User:        types.User{Name: "user2"},
				},
			},
		},
		{
			name: "p4-host-in-netmap-user1-dest-bug",
			args: args{
				machines: []types.Machine{
					{
						ID:          1,
						IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
						Hostname:    "user1-2",
						User:        types.User{Name: "user1"},
					},
					{
						ID:          2,
						IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
						Hostname:    "user-2-1",
						User:        types.User{Name: "user2"},
					},
					{
						ID:          3,
						IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.4")},
						Hostname:    "user2-2",
						User:        types.User{Name: "user2"},
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
				machine: &types.Machine{
					ID:          0,
					IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
					Hostname:    "user1-1",
					User:        types.User{Name: "user1"},
				},
			},
			want: []types.Machine{
				{
					ID:          1,
					IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
					Hostname:    "user1-2",
					User:        types.User{Name: "user1"},
				},
				{
					ID:          2,
					IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
					Hostname:    "user-2-1",
					User:        types.User{Name: "user2"},
				},
				{
					ID:          3,
					IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.4")},
					Hostname:    "user2-2",
					User:        types.User{Name: "user2"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterMachinesByACL(
				tt.args.machine,
				tt.args.machines,
				tt.args.rules,
			)
			if diff := cmp.Diff(tt.want, got, ipComparer); diff != "" {
				t.Errorf("FilterMachinesByACL() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSSHRules(t *testing.T) {
	tests := []struct {
		name    string
		machine types.Machine
		peers   types.Machines
		pol     ACLPolicy
		want    []*tailcfg.SSHRule
	}{
		{
			name: "peers-can-connect",
			machine: types.Machine{
				Hostname:    "testmachine",
				IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.99.42")},
				UserID:      0,
				User: types.User{
					Name: "user1",
				},
			},
			peers: types.Machines{
				types.Machine{
					Hostname:    "testmachine2",
					IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.1")},
					UserID:      0,
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
			want: []*tailcfg.SSHRule{
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
			},
		},
		{
			name: "peers-cannot-connect",
			machine: types.Machine{
				Hostname:    "testmachine",
				IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.1")},
				UserID:      0,
				User: types.User{
					Name: "user1",
				},
			},
			peers: types.Machines{
				types.Machine{
					Hostname:    "testmachine2",
					IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.99.42")},
					UserID:      0,
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
			want: []*tailcfg.SSHRule{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.pol.generateSSHRules(&tt.machine, tt.peers)
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
		Hostname:    "testmachine",
		RequestTags: []string{"tag:test"},
	}

	machine := types.Machine{
		ID:          0,
		MachineKey:  "foo",
		NodeKey:     "bar",
		DiscoKey:    "faa",
		Hostname:    "testmachine",
		IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.1")},
		UserID:      0,
		User: types.User{
			Name: "user1",
		},
		RegisterMethod: util.RegisterMethodAuthKey,
		HostInfo:       types.HostInfo(hostInfo),
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

	got, _, err := GenerateFilterAndSSHRules(pol, &machine, types.Machines{})
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
		Hostname:    "testmachine",
		RequestTags: []string{"tag:foo"},
	}

	machine := types.Machine{
		ID:          1,
		MachineKey:  "12345",
		NodeKey:     "bar",
		DiscoKey:    "faa",
		Hostname:    "testmachine",
		IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.1")},
		UserID:      1,
		User: types.User{
			Name: "user1",
		},
		RegisterMethod: util.RegisterMethodAuthKey,
		HostInfo:       types.HostInfo(hostInfo),
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

	got, _, err := GenerateFilterAndSSHRules(pol, &machine, types.Machines{})
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
		Hostname:    "testmachine",
		RequestTags: []string{"tag:test"},
	}

	machine := types.Machine{
		ID:          1,
		MachineKey:  "12345",
		NodeKey:     "bar",
		DiscoKey:    "faa",
		Hostname:    "testmachine",
		IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.1")},
		UserID:      1,
		User: types.User{
			Name: "user1",
		},
		RegisterMethod: util.RegisterMethodAuthKey,
		HostInfo:       types.HostInfo(hostInfo),
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

	// rules, _, err := GenerateFilterRules(pol, &machine, peers, false)
	// c.Assert(err, check.IsNil)
	//
	// c.Assert(rules, check.HasLen, 1)
	// c.Assert(rules[0].DstPorts, check.HasLen, 1)
	// c.Assert(rules[0].DstPorts[0].IP, check.Equals, "100.64.0.1/32")

	got, _, err := GenerateFilterAndSSHRules(pol, &machine, types.Machines{})
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

	machine := types.Machine{
		ID:          1,
		MachineKey:  "12345",
		NodeKey:     "bar",
		DiscoKey:    "faa",
		Hostname:    "webserver",
		IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.1")},
		UserID:      1,
		User: types.User{
			Name: "user1",
		},
		RegisterMethod: util.RegisterMethodAuthKey,
		HostInfo:       types.HostInfo(hostInfo),
	}

	hostInfo2 := tailcfg.Hostinfo{
		OS:       "debian",
		Hostname: "Hostname",
	}

	machine2 := types.Machine{
		ID:          2,
		MachineKey:  "56789",
		NodeKey:     "bar2",
		DiscoKey:    "faab",
		Hostname:    "user",
		IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.2")},
		UserID:      1,
		User: types.User{
			Name: "user1",
		},
		RegisterMethod: util.RegisterMethodAuthKey,
		HostInfo:       types.HostInfo(hostInfo2),
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

	got, _, err := GenerateFilterAndSSHRules(pol, &machine, types.Machines{machine2})
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
