package v2

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	xmaps "golang.org/x/exp/maps"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

func TestUnmarshalPolicy(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *Policy
		wantErr string
	}{
		{
			name:  "empty",
			input: "{}",
			want:  &Policy{},
		},
		{
			name: "groups",
			input: `
{
	"groups": {
		"group:example": [
			"derp@headscale.net",
		],
	},
}
`,
			want: &Policy{
				Groups: Groups{
					Group("group:example"): []Username{Username("derp@headscale.net")},
				},
			},
		},
		{
			name: "basic-types",
			input: `
{
	"groups": {
		"group:example": [
			"testuser@headscale.net",
		],
		"group:other": [
			"otheruser@headscale.net",
		],
		"group:noat": [
			"noat@",
		],
	},

	"tagOwners": {
		"tag:user": ["testuser@headscale.net"],
		"tag:group": ["group:other"],
		"tag:userandgroup": ["testuser@headscale.net", "group:other"],
	},

	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
		"outside": "192.168.0.0/16",
	},

	"acls": [
	    // All
		{
			"action": "accept",
			"proto": "tcp",
			"src": ["*"],
			"dst": ["*:*"],
		},
		// Users
		{
			"action": "accept",
			"proto": "tcp",
			"src": ["testuser@headscale.net"],
			"dst": ["otheruser@headscale.net:80"],
		},
		// Groups
		{
			"action": "accept",
			"proto": "tcp",
			"src": ["group:example"],
			"dst": ["group:other:80"],
		},
		// Tailscale IP
		{
			"action": "accept",
			"proto": "tcp",
			"src": ["100.101.102.103"],
			"dst": ["100.101.102.104:80"],
		},
		// Subnet
		{
			"action": "accept",
			"proto": "udp",
			"src": ["10.0.0.0/8"],
			"dst": ["172.16.0.0/16:80"],
		},
		// Hosts
		{
			"action": "accept",
			"proto": "tcp",
			"src": ["subnet-1"],
			"dst": ["host-1:80-88"],
		},
		// Tags
		{
			"action": "accept",
			"proto": "tcp",
			"src": ["tag:group"],
			"dst": ["tag:user:80,443"],
		},
		// Autogroup
		{
			"action": "accept",
			"proto": "tcp",
			"src": ["tag:group"],
			"dst": ["autogroup:internet:80"],
		},
	],
}
`,
			want: &Policy{
				Groups: Groups{
					Group("group:example"): []Username{Username("testuser@headscale.net")},
					Group("group:other"):   []Username{Username("otheruser@headscale.net")},
					Group("group:noat"):    []Username{Username("noat@")},
				},
				TagOwners: TagOwners{
					Tag("tag:user"):         Owners{up("testuser@headscale.net")},
					Tag("tag:group"):        Owners{gp("group:other")},
					Tag("tag:userandgroup"): Owners{up("testuser@headscale.net"), gp("group:other")},
				},
				Hosts: Hosts{
					"host-1":   Prefix(mp("100.100.100.100/32")),
					"subnet-1": Prefix(mp("100.100.101.100/24")),
					"outside":  Prefix(mp("192.168.0.0/16")),
				},
				ACLs: []ACL{
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							Wildcard,
						},
						Destinations: []AliasWithPorts{
							{
								// TODO(kradalby): Should this be host?
								// It is:
								// Includes any destination (no restrictions).
								Alias: Wildcard,
								Ports: []tailcfg.PortRange{tailcfg.PortRangeAny},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							ptr.To(Username("testuser@headscale.net")),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: ptr.To(Username("otheruser@headscale.net")),
								Ports: []tailcfg.PortRange{{First: 80, Last: 80}},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							gp("group:example"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: gp("group:other"),
								Ports: []tailcfg.PortRange{{First: 80, Last: 80}},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							pp("100.101.102.103/32"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: pp("100.101.102.104/32"),
								Ports: []tailcfg.PortRange{{First: 80, Last: 80}},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "udp",
						Sources: Aliases{
							pp("10.0.0.0/8"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: pp("172.16.0.0/16"),
								Ports: []tailcfg.PortRange{{First: 80, Last: 80}},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							hp("subnet-1"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: hp("host-1"),
								Ports: []tailcfg.PortRange{{First: 80, Last: 88}},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							tp("tag:group"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: tp("tag:user"),
								Ports: []tailcfg.PortRange{
									{First: 80, Last: 80},
									{First: 443, Last: 443},
								},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							tp("tag:group"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: agp("autogroup:internet"),
								Ports: []tailcfg.PortRange{
									{First: 80, Last: 80},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "invalid-username",
			input: `
{
	"groups": {
		"group:example": [
			"valid@",
			"invalid",
		],
	},
}
`,
			wantErr: `Username has to contain @, got: "invalid"`,
		},
		{
			name: "invalid-group",
			input: `
{
	"groups": {
		"grou:example": [
			"valid@",
		],
	},
}
`,
			wantErr: `Group has to start with "group:", got: "grou:example"`,
		},
		{
			name: "group-in-group",
			input: `
{
	"groups": {
		"group:inner": [],
		"group:example": [
			"group:inner",
		],
	},
}
`,
			// wantErr: `Username has to contain @, got: "group:inner"`,
			wantErr: `Nested groups are not allowed, found "group:inner" inside "group:example"`,
		},
		{
			name: "invalid-addr",
			input: `
{
	"hosts": {
		"derp": "10.0",
	},
}
`,
			wantErr: `Hostname "derp" contains an invalid IP address: "10.0"`,
		},
		{
			name: "invalid-prefix",
			input: `
{
			"hosts": {
				"derp": "10.0/42",
			},
}
`,
			wantErr: `Hostname "derp" contains an invalid IP address: "10.0/42"`,
		},
		// TODO(kradalby): Figure out why this doesnt work.
		// 		{
		// 			name: "invalid-hostname",
		// 			input: `
		// {
		// 			"hosts": {
		// 				"derp:merp": "10.0.0.0/31",
		// 			},
		// }
		// `,
		// 			wantErr: `Hostname "derp:merp" is invalid`,
		// 		},
		{
			name: "invalid-auto-group",
			input: `
{
	"acls": [
		// Autogroup
		{
			"action": "accept",
			"proto": "tcp",
			"src": ["tag:group"],
			"dst": ["autogroup:invalid:80"],
		},
	],
}
`,
			wantErr: `AutoGroup is invalid, got: "autogroup:invalid", must be one of [autogroup:internet]`,
		},
		{
			name: "undefined-hostname-errors-2490",
			input: `
{
  "acls": [
    {
      "action": "accept",
      "src": [
        "user1"
      ],
      "dst": [
        "user1:*"
      ]
    }
  ]
}
`,
			wantErr: `Host "user1" is not defined in the Policy, please define or remove the reference to it`,
		},
		{
			name: "defined-hostname-does-not-err-2490",
			input: `
{
  "hosts": {
		"user1": "100.100.100.100",
  },
  "acls": [
    {
      "action": "accept",
      "src": [
        "user1"
      ],
      "dst": [
        "user1:*"
      ]
    }
  ]
}
`,
			want: &Policy{
				Hosts: Hosts{
					"user1": Prefix(mp("100.100.100.100/32")),
				},
				ACLs: []ACL{
					{
						Action: "accept",
						Sources: Aliases{
							hp("user1"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: hp("user1"),
								Ports: []tailcfg.PortRange{tailcfg.PortRangeAny},
							},
						},
					},
				},
			},
		},
		{
			name: "autogroup:internet-in-dst-allowed",
			input: `
{
  "acls": [
    {
      "action": "accept",
      "src": [
        "10.0.0.1"
      ],
      "dst": [
        "autogroup:internet:*"
      ]
    }
  ]
}
`,
			want: &Policy{
				ACLs: []ACL{
					{
						Action: "accept",
						Sources: Aliases{
							pp("10.0.0.1/32"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: ptr.To(AutoGroup("autogroup:internet")),
								Ports: []tailcfg.PortRange{tailcfg.PortRangeAny},
							},
						},
					},
				},
			},
		},
		{
			name: "autogroup:internet-in-src-not-allowed",
			input: `
{
  "acls": [
    {
      "action": "accept",
      "src": [
        "autogroup:internet"
      ],
      "dst": [
        "10.0.0.1:*"
      ]
    }
  ]
}
`,
			wantErr: `"autogroup:internet" used in source, it can only be used in ACL destinations`,
		},
		{
			name: "autogroup:internet-in-ssh-src-not-allowed",
			input: `
{
  "ssh": [
    {
      "action": "accept",
      "src": [
        "autogroup:internet"
      ],
      "dst": [
        "tag:test"
      ]
    }
  ]
}
`,
			wantErr: `"autogroup:internet" used in SSH source, it can only be used in ACL destinations`,
		},
		{
			name: "autogroup:internet-in-ssh-dst-not-allowed",
			input: `
{
  "ssh": [
    {
      "action": "accept",
      "src": [
        "tag:test"
      ],
      "dst": [
        "autogroup:internet"
      ]
    }
  ]
}
`,
			wantErr: `"autogroup:internet" used in SSH destination, it can only be used in ACL destinations`,
		},
		{
			name: "group-must-be-defined-acl-src",
			input: `
{
  "acls": [
    {
      "action": "accept",
      "src": [
        "group:notdefined"
      ],
      "dst": [
        "autogroup:internet:*"
      ]
    }
  ]
}
`,
			wantErr: `Group "group:notdefined" is not defined in the Policy, please define or remove the reference to it`,
		},
		{
			name: "group-must-be-defined-acl-dst",
			input: `
{
  "acls": [
    {
      "action": "accept",
      "src": [
        "*"
      ],
      "dst": [
        "group:notdefined:*"
      ]
    }
  ]
}
`,
			wantErr: `Group "group:notdefined" is not defined in the Policy, please define or remove the reference to it`,
		},
		{
			name: "group-must-be-defined-acl-ssh-src",
			input: `
{
  "ssh": [
    {
      "action": "accept",
      "src": [
        "group:notdefined"
      ],
      "dst": [
        "user@"
      ]
    }
  ]
}
`,
			wantErr: `Group "group:notdefined" is not defined in the Policy, please define or remove the reference to it`,
		},
		{
			name: "group-must-be-defined-acl-tagOwner",
			input: `
{
  "tagOwners": {
    "tag:test": ["group:notdefined"],
  },
}
`,
			wantErr: `Group "group:notdefined" is not defined in the Policy, please define or remove the reference to it`,
		},
		{
			name: "group-must-be-defined-acl-autoapprover-route",
			input: `
{
  "autoApprovers": {
    "routes": {
      "10.0.0.0/16": ["group:notdefined"]
    }
  },
}
`,
			wantErr: `Group "group:notdefined" is not defined in the Policy, please define or remove the reference to it`,
		},
		{
			name: "group-must-be-defined-acl-autoapprover-exitnode",
			input: `
{
  "autoApprovers": {
    "exitNode": ["group:notdefined"]
   },
}
`,
			wantErr: `Group "group:notdefined" is not defined in the Policy, please define or remove the reference to it`,
		},
		{
			name: "tag-must-be-defined-acl-src",
			input: `
{
  "acls": [
    {
      "action": "accept",
      "src": [
        "tag:notdefined"
      ],
      "dst": [
        "autogroup:internet:*"
      ]
    }
  ]
}
`,
			wantErr: `Tag "tag:notdefined" is not defined in the Policy, please define or remove the reference to it`,
		},
		{
			name: "tag-must-be-defined-acl-dst",
			input: `
{
  "acls": [
    {
      "action": "accept",
      "src": [
        "*"
      ],
      "dst": [
        "tag:notdefined:*"
      ]
    }
  ]
}
`,
			wantErr: `Tag "tag:notdefined" is not defined in the Policy, please define or remove the reference to it`,
		},
		{
			name: "tag-must-be-defined-acl-ssh-src",
			input: `
{
  "ssh": [
    {
      "action": "accept",
      "src": [
        "tag:notdefined"
      ],
      "dst": [
        "user@"
      ]
    }
  ]
}
`,
			wantErr: `Tag "tag:notdefined" is not defined in the Policy, please define or remove the reference to it`,
		},
		{
			name: "tag-must-be-defined-acl-ssh-dst",
			input: `
{
  "groups": {
  	"group:defined": ["user@"],
  },
  "ssh": [
    {
      "action": "accept",
      "src": [
        "group:defined"
      ],
      "dst": [
        "tag:notdefined",
      ],
    }
  ]
}
`,
			wantErr: `Tag "tag:notdefined" is not defined in the Policy, please define or remove the reference to it`,
		},
		{
			name: "tag-must-be-defined-acl-autoapprover-route",
			input: `
{
  "autoApprovers": {
    "routes": {
      "10.0.0.0/16": ["tag:notdefined"]
    }
  },
}
`,
			wantErr: `Tag "tag:notdefined" is not defined in the Policy, please define or remove the reference to it`,
		},
		{
			name: "tag-must-be-defined-acl-autoapprover-exitnode",
			input: `
{
  "autoApprovers": {
    "exitNode": ["tag:notdefined"]
   },
}
`,
			wantErr: `Tag "tag:notdefined" is not defined in the Policy, please define or remove the reference to it`,
		},
	}

	cmps := append(util.Comparers, cmp.Comparer(func(x, y Prefix) bool {
		return x == y
	}))
	cmps = append(cmps, cmpopts.IgnoreUnexported(Policy{}))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := unmarshalPolicy([]byte(tt.input))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("got %v; want no error", err)
				}
			} else {
				if err == nil {
					t.Fatalf("got nil; want error %q", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("got err %v; want error %q", err, tt.wantErr)
				}
			}

			if diff := cmp.Diff(tt.want, policy, cmps...); diff != "" {
				t.Fatalf("unexpected policy (-want +got):\n%s", diff)
			}
		})
	}
}

func gp(s string) *Group          { return ptr.To(Group(s)) }
func up(s string) *Username       { return ptr.To(Username(s)) }
func hp(s string) *Host           { return ptr.To(Host(s)) }
func tp(s string) *Tag            { return ptr.To(Tag(s)) }
func agp(s string) *AutoGroup     { return ptr.To(AutoGroup(s)) }
func mp(pref string) netip.Prefix { return netip.MustParsePrefix(pref) }
func ap(addr string) *netip.Addr  { return ptr.To(netip.MustParseAddr(addr)) }
func pp(pref string) *Prefix      { return ptr.To(Prefix(mp(pref))) }
func p(pref string) Prefix        { return Prefix(mp(pref)) }

func TestResolvePolicy(t *testing.T) {
	users := map[string]types.User{
		"testuser":   {Model: gorm.Model{ID: 1}, Name: "testuser"},
		"groupuser":  {Model: gorm.Model{ID: 2}, Name: "groupuser"},
		"groupuser1": {Model: gorm.Model{ID: 3}, Name: "groupuser1"},
		"groupuser2": {Model: gorm.Model{ID: 4}, Name: "groupuser2"},
		"notme":      {Model: gorm.Model{ID: 5}, Name: "notme"},
	}
	tests := []struct {
		name      string
		nodes     types.Nodes
		pol       *Policy
		toResolve Alias
		want      []netip.Prefix
		wantErr   string
	}{
		{
			name:      "prefix",
			toResolve: pp("100.100.101.101/32"),
			want:      []netip.Prefix{mp("100.100.101.101/32")},
		},
		{
			name: "host",
			pol: &Policy{
				Hosts: Hosts{
					"testhost": p("100.100.101.102/32"),
				},
			},
			toResolve: hp("testhost"),
			want:      []netip.Prefix{mp("100.100.101.102/32")},
		},
		{
			name:      "username",
			toResolve: ptr.To(Username("testuser@")),
			nodes: types.Nodes{
				// Not matching other user
				{
					User: users["notme"],
					IPv4: ap("100.100.101.1"),
				},
				// Not matching forced tags
				{
					User:       users["testuser"],
					ForcedTags: []string{"tag:anything"},
					IPv4:       ap("100.100.101.2"),
				},
				// not matchin pak tag
				{
					User: users["testuser"],
					AuthKey: &types.PreAuthKey{
						Tags: []string{"alsotagged"},
					},
					IPv4: ap("100.100.101.3"),
				},
				{
					User: users["testuser"],
					IPv4: ap("100.100.101.103"),
				},
				{
					User: users["testuser"],
					IPv4: ap("100.100.101.104"),
				},
			},
			want: []netip.Prefix{mp("100.100.101.103/32"), mp("100.100.101.104/32")},
		},
		{
			name:      "group",
			toResolve: ptr.To(Group("group:testgroup")),
			nodes: types.Nodes{
				// Not matching other user
				{
					User: users["notme"],
					IPv4: ap("100.100.101.4"),
				},
				// Not matching forced tags
				{
					User:       users["groupuser"],
					ForcedTags: []string{"tag:anything"},
					IPv4:       ap("100.100.101.5"),
				},
				// not matchin pak tag
				{
					User: users["groupuser"],
					AuthKey: &types.PreAuthKey{
						Tags: []string{"tag:alsotagged"},
					},
					IPv4: ap("100.100.101.6"),
				},
				{
					User: users["groupuser"],
					IPv4: ap("100.100.101.203"),
				},
				{
					User: users["groupuser"],
					IPv4: ap("100.100.101.204"),
				},
			},
			pol: &Policy{
				Groups: Groups{
					"group:testgroup":  Usernames{"groupuser"},
					"group:othergroup": Usernames{"notmetoo"},
				},
			},
			want: []netip.Prefix{mp("100.100.101.203/32"), mp("100.100.101.204/32")},
		},
		{
			name:      "tag",
			toResolve: tp("tag:test"),
			nodes: types.Nodes{
				// Not matching other user
				{
					User: users["notme"],
					IPv4: ap("100.100.101.9"),
				},
				// Not matching forced tags
				{
					ForcedTags: []string{"tag:anything"},
					IPv4:       ap("100.100.101.10"),
				},
				// not matchin pak tag
				{
					AuthKey: &types.PreAuthKey{
						Tags: []string{"tag:alsotagged"},
					},
					IPv4: ap("100.100.101.11"),
				},
				// Not matching forced tags
				{
					ForcedTags: []string{"tag:test"},
					IPv4:       ap("100.100.101.234"),
				},
				// not matchin pak tag
				{
					AuthKey: &types.PreAuthKey{
						Tags: []string{"tag:test"},
					},
					IPv4: ap("100.100.101.239"),
				},
			},
			// TODO(kradalby): tests handling TagOwners + hostinfo
			pol:  &Policy{},
			want: []netip.Prefix{mp("100.100.101.234/32"), mp("100.100.101.239/32")},
		},
		{
			name:      "empty-policy",
			toResolve: pp("100.100.101.101/32"),
			pol:       &Policy{},
			want:      []netip.Prefix{mp("100.100.101.101/32")},
		},
		{
			name:      "invalid-host",
			toResolve: hp("invalidhost"),
			pol: &Policy{
				Hosts: Hosts{
					"testhost": p("100.100.101.102/32"),
				},
			},
			wantErr: `unable to resolve host: "invalidhost"`,
		},
		{
			name:      "multiple-groups",
			toResolve: ptr.To(Group("group:testgroup")),
			nodes: types.Nodes{
				{
					User: users["groupuser1"],
					IPv4: ap("100.100.101.203"),
				},
				{
					User: users["groupuser2"],
					IPv4: ap("100.100.101.204"),
				},
			},
			pol: &Policy{
				Groups: Groups{
					"group:testgroup": Usernames{"groupuser1@", "groupuser2@"},
				},
			},
			want: []netip.Prefix{mp("100.100.101.203/32"), mp("100.100.101.204/32")},
		},
		{
			name:      "autogroup-internet",
			toResolve: agp("autogroup:internet"),
			want:      util.TheInternet().Prefixes(),
		},
		{
			name:      "invalid-username",
			toResolve: ptr.To(Username("invaliduser@")),
			nodes: types.Nodes{
				{
					User: users["testuser"],
					IPv4: ap("100.100.101.103"),
				},
			},
			wantErr: `user with token "invaliduser@" not found`,
		},
		{
			name:      "invalid-tag",
			toResolve: tp("tag:invalid"),
			nodes: types.Nodes{
				{
					ForcedTags: []string{"tag:test"},
					IPv4:       ap("100.100.101.234"),
				},
			},
		},
		{
			name:      "ipv6-address",
			toResolve: pp("fd7a:115c:a1e0::1/128"),
			want:      []netip.Prefix{mp("fd7a:115c:a1e0::1/128")},
		},
		{
			name:      "wildcard-alias",
			toResolve: Wildcard,
			want:      []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := tt.toResolve.Resolve(tt.pol,
				xmaps.Values(users),
				tt.nodes)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("got %v; want no error", err)
				}
			} else {
				if err == nil {
					t.Fatalf("got nil; want error %q", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("got err %v; want error %q", err, tt.wantErr)
				}
			}

			var prefs []netip.Prefix
			if ips != nil {
				if p := ips.Prefixes(); len(p) > 0 {
					prefs = p
				}
			}

			if diff := cmp.Diff(tt.want, prefs, util.Comparers...); diff != "" {
				t.Fatalf("unexpected prefs (-want +got):\n%s", diff)
			}
		})
	}
}

func TestResolveAutoApprovers(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
		{Model: gorm.Model{ID: 3}, Name: "user3"},
	}

	nodes := types.Nodes{
		{
			IPv4: ap("100.64.0.1"),
			User: users[0],
		},
		{
			IPv4: ap("100.64.0.2"),
			User: users[1],
		},
		{
			IPv4: ap("100.64.0.3"),
			User: users[2],
		},
		{
			IPv4:       ap("100.64.0.4"),
			ForcedTags: []string{"tag:testtag"},
		},
		{
			IPv4:       ap("100.64.0.5"),
			ForcedTags: []string{"tag:exittest"},
		},
	}

	tests := []struct {
		name            string
		policy          *Policy
		want            map[netip.Prefix]*netipx.IPSet
		wantAllIPRoutes *netipx.IPSet
		wantErr         bool
	}{
		{
			name: "single-route",
			policy: &Policy{
				AutoApprovers: AutoApproverPolicy{
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.0.0/24"): {ptr.To(Username("user1@"))},
					},
				},
			},
			want: map[netip.Prefix]*netipx.IPSet{
				mp("10.0.0.0/24"): mustIPSet("100.64.0.1/32"),
			},
			wantAllIPRoutes: nil,
			wantErr:         false,
		},
		{
			name: "multiple-routes",
			policy: &Policy{
				AutoApprovers: AutoApproverPolicy{
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.0.0/24"): {ptr.To(Username("user1@"))},
						mp("10.0.1.0/24"): {ptr.To(Username("user2@"))},
					},
				},
			},
			want: map[netip.Prefix]*netipx.IPSet{
				mp("10.0.0.0/24"): mustIPSet("100.64.0.1/32"),
				mp("10.0.1.0/24"): mustIPSet("100.64.0.2/32"),
			},
			wantAllIPRoutes: nil,
			wantErr:         false,
		},
		{
			name: "exit-node",
			policy: &Policy{
				AutoApprovers: AutoApproverPolicy{
					ExitNode: AutoApprovers{ptr.To(Username("user1@"))},
				},
			},
			want:            map[netip.Prefix]*netipx.IPSet{},
			wantAllIPRoutes: mustIPSet("100.64.0.1/32"),
			wantErr:         false,
		},
		{
			name: "group-route",
			policy: &Policy{
				Groups: Groups{
					"group:testgroup": Usernames{"user1@", "user2@"},
				},
				AutoApprovers: AutoApproverPolicy{
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.0.0/24"): {ptr.To(Group("group:testgroup"))},
					},
				},
			},
			want: map[netip.Prefix]*netipx.IPSet{
				mp("10.0.0.0/24"): mustIPSet("100.64.0.1/32", "100.64.0.2/32"),
			},
			wantAllIPRoutes: nil,
			wantErr:         false,
		},
		{
			name: "tag-route-and-exit",
			policy: &Policy{
				TagOwners: TagOwners{
					"tag:testtag": Owners{
						ptr.To(Username("user1@")),
						ptr.To(Username("user2@")),
					},
					"tag:exittest": Owners{
						ptr.To(Group("group:exitgroup")),
					},
				},
				Groups: Groups{
					"group:exitgroup": Usernames{"user2@"},
				},
				AutoApprovers: AutoApproverPolicy{
					ExitNode: AutoApprovers{ptr.To(Tag("tag:exittest"))},
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.1.0/24"): {ptr.To(Tag("tag:testtag"))},
					},
				},
			},
			want: map[netip.Prefix]*netipx.IPSet{
				mp("10.0.1.0/24"): mustIPSet("100.64.0.4/32"),
			},
			wantAllIPRoutes: mustIPSet("100.64.0.5/32"),
			wantErr:         false,
		},
		{
			name: "mixed-routes-and-exit-nodes",
			policy: &Policy{
				Groups: Groups{
					"group:testgroup": Usernames{"user1", "user2"},
				},
				AutoApprovers: AutoApproverPolicy{
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.0.0/24"): {ptr.To(Group("group:testgroup"))},
						mp("10.0.1.0/24"): {ptr.To(Username("user3@"))},
					},
					ExitNode: AutoApprovers{ptr.To(Username("user1@"))},
				},
			},
			want: map[netip.Prefix]*netipx.IPSet{
				mp("10.0.0.0/24"): mustIPSet("100.64.0.1/32", "100.64.0.2/32"),
				mp("10.0.1.0/24"): mustIPSet("100.64.0.3/32"),
			},
			wantAllIPRoutes: mustIPSet("100.64.0.1/32"),
			wantErr:         false,
		},
	}

	cmps := append(util.Comparers, cmp.Comparer(ipSetComparer))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotAllIPRoutes, err := resolveAutoApprovers(tt.policy, users, nodes)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveAutoApprovers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, cmps...); diff != "" {
				t.Errorf("resolveAutoApprovers() mismatch (-want +got):\n%s", diff)
			}
			if tt.wantAllIPRoutes != nil {
				if gotAllIPRoutes == nil {
					t.Error("resolveAutoApprovers() expected non-nil allIPRoutes, got nil")
				} else if diff := cmp.Diff(tt.wantAllIPRoutes, gotAllIPRoutes, cmps...); diff != "" {
					t.Errorf("resolveAutoApprovers() allIPRoutes mismatch (-want +got):\n%s", diff)
				}
			} else if gotAllIPRoutes != nil {
				t.Error("resolveAutoApprovers() expected nil allIPRoutes, got non-nil")
			}
		})
	}
}

func mustIPSet(prefixes ...string) *netipx.IPSet {
	var builder netipx.IPSetBuilder
	for _, p := range prefixes {
		builder.AddPrefix(mp(p))
	}
	ipSet, _ := builder.IPSet()
	return ipSet
}

func ipSetComparer(x, y *netipx.IPSet) bool {
	if x == nil || y == nil {
		return x == y
	}
	return cmp.Equal(x.Prefixes(), y.Prefixes(), util.Comparers...)
}

func TestNodeCanApproveRoute(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
		{Model: gorm.Model{ID: 3}, Name: "user3"},
	}

	nodes := types.Nodes{
		{
			IPv4: ap("100.64.0.1"),
			User: users[0],
		},
		{
			IPv4: ap("100.64.0.2"),
			User: users[1],
		},
		{
			IPv4: ap("100.64.0.3"),
			User: users[2],
		},
	}

	tests := []struct {
		name    string
		policy  *Policy
		node    *types.Node
		route   netip.Prefix
		want    bool
		wantErr bool
	}{
		{
			name: "single-route-approval",
			policy: &Policy{
				AutoApprovers: AutoApproverPolicy{
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.0.0/24"): {ptr.To(Username("user1@"))},
					},
				},
			},
			node:  nodes[0],
			route: mp("10.0.0.0/24"),
			want:  true,
		},
		{
			name: "multiple-routes-approval",
			policy: &Policy{
				AutoApprovers: AutoApproverPolicy{
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.0.0/24"): {ptr.To(Username("user1@"))},
						mp("10.0.1.0/24"): {ptr.To(Username("user2@"))},
					},
				},
			},
			node:  nodes[1],
			route: mp("10.0.1.0/24"),
			want:  true,
		},
		{
			name: "exit-node-approval",
			policy: &Policy{
				AutoApprovers: AutoApproverPolicy{
					ExitNode: AutoApprovers{ptr.To(Username("user1@"))},
				},
			},
			node:  nodes[0],
			route: tsaddr.AllIPv4(),
			want:  true,
		},
		{
			name: "group-route-approval",
			policy: &Policy{
				Groups: Groups{
					"group:testgroup": Usernames{"user1@", "user2@"},
				},
				AutoApprovers: AutoApproverPolicy{
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.0.0/24"): {ptr.To(Group("group:testgroup"))},
					},
				},
			},
			node:  nodes[1],
			route: mp("10.0.0.0/24"),
			want:  true,
		},
		{
			name: "mixed-routes-and-exit-nodes-approval",
			policy: &Policy{
				Groups: Groups{
					"group:testgroup": Usernames{"user1@", "user2@"},
				},
				AutoApprovers: AutoApproverPolicy{
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.0.0/24"): {ptr.To(Group("group:testgroup"))},
						mp("10.0.1.0/24"): {ptr.To(Username("user3@"))},
					},
					ExitNode: AutoApprovers{ptr.To(Username("user1@"))},
				},
			},
			node:  nodes[0],
			route: tsaddr.AllIPv4(),
			want:  true,
		},
		{
			name: "no-approval",
			policy: &Policy{
				AutoApprovers: AutoApproverPolicy{
					Routes: map[netip.Prefix]AutoApprovers{
						mp("10.0.0.0/24"): {ptr.To(Username("user2@"))},
					},
				},
			},
			node:  nodes[0],
			route: mp("10.0.0.0/24"),
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.policy)
			require.NoError(t, err)

			pm, err := NewPolicyManager(b, users, nodes)
			require.NoErrorf(t, err, "NewPolicyManager() error = %v", err)

			got := pm.NodeCanApproveRoute(tt.node, tt.route)
			if got != tt.want {
				t.Errorf("NodeCanApproveRoute() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveTagOwners(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
		{Model: gorm.Model{ID: 3}, Name: "user3"},
	}

	nodes := types.Nodes{
		{
			IPv4: ap("100.64.0.1"),
			User: users[0],
		},
		{
			IPv4: ap("100.64.0.2"),
			User: users[1],
		},
		{
			IPv4: ap("100.64.0.3"),
			User: users[2],
		},
	}

	tests := []struct {
		name    string
		policy  *Policy
		want    map[Tag]*netipx.IPSet
		wantErr bool
	}{
		{
			name: "single-tag-owner",
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{ptr.To(Username("user1@"))},
				},
			},
			want: map[Tag]*netipx.IPSet{
				Tag("tag:test"): mustIPSet("100.64.0.1/32"),
			},
			wantErr: false,
		},
		{
			name: "multiple-tag-owners",
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{ptr.To(Username("user1@")), ptr.To(Username("user2@"))},
				},
			},
			want: map[Tag]*netipx.IPSet{
				Tag("tag:test"): mustIPSet("100.64.0.1/32", "100.64.0.2/32"),
			},
			wantErr: false,
		},
		{
			name: "group-tag-owner",
			policy: &Policy{
				Groups: Groups{
					"group:testgroup": Usernames{"user1@", "user2@"},
				},
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{ptr.To(Group("group:testgroup"))},
				},
			},
			want: map[Tag]*netipx.IPSet{
				Tag("tag:test"): mustIPSet("100.64.0.1/32", "100.64.0.2/32"),
			},
			wantErr: false,
		},
	}

	cmps := append(util.Comparers, cmp.Comparer(ipSetComparer))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveTagOwners(tt.policy, users, nodes)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveTagOwners() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got, cmps...); diff != "" {
				t.Errorf("resolveTagOwners() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNodeCanHaveTag(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
		{Model: gorm.Model{ID: 3}, Name: "user3"},
	}

	nodes := types.Nodes{
		{
			IPv4: ap("100.64.0.1"),
			User: users[0],
		},
		{
			IPv4: ap("100.64.0.2"),
			User: users[1],
		},
		{
			IPv4: ap("100.64.0.3"),
			User: users[2],
		},
	}

	tests := []struct {
		name    string
		policy  *Policy
		node    *types.Node
		tag     string
		want    bool
		wantErr string
	}{
		{
			name: "single-tag-owner",
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{ptr.To(Username("user1@"))},
				},
			},
			node: nodes[0],
			tag:  "tag:test",
			want: true,
		},
		{
			name: "multiple-tag-owners",
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{ptr.To(Username("user1@")), ptr.To(Username("user2@"))},
				},
			},
			node: nodes[1],
			tag:  "tag:test",
			want: true,
		},
		{
			name: "group-tag-owner",
			policy: &Policy{
				Groups: Groups{
					"group:testgroup": Usernames{"user1@", "user2@"},
				},
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{ptr.To(Group("group:testgroup"))},
				},
			},
			node: nodes[1],
			tag:  "tag:test",
			want: true,
		},
		{
			name: "invalid-group",
			policy: &Policy{
				Groups: Groups{
					"group:testgroup": Usernames{"invalid"},
				},
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{ptr.To(Group("group:testgroup"))},
				},
			},
			node:    nodes[0],
			tag:     "tag:test",
			want:    false,
			wantErr: "Username has to contain @",
		},
		{
			name: "node-cannot-have-tag",
			policy: &Policy{
				TagOwners: TagOwners{
					Tag("tag:test"): Owners{ptr.To(Username("user2@"))},
				},
			},
			node: nodes[0],
			tag:  "tag:test",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.policy)
			require.NoError(t, err)

			pm, err := NewPolicyManager(b, users, nodes)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			got := pm.NodeCanHaveTag(tt.node, tt.tag)
			if got != tt.want {
				t.Errorf("NodeCanHaveTag() = %v, want %v", got, tt.want)
			}
		})
	}
}
