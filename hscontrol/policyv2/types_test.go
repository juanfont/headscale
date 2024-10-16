package policyv2

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
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
	},

	"tagOwners": {
		"tag:user": ["testuser@headscale.net"],
		"tag:group": ["group:other"],
		"tag:userandgroup": ["testuser@headscale.net" ,"group:other"],
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
				},
				TagOwners: TagOwners{
					Tag("tag:user"):         Owners{ptr.To(Username("testuser@headscale.net"))},
					Tag("tag:group"):        Owners{Group("group:other")},
					Tag("tag:userandgroup"): Owners{ptr.To(Username("testuser@headscale.net")), Group("group:other")},
				},
				Hosts: Hosts{
					"host-1":   Prefix(netip.MustParsePrefix("100.100.100.100/32")),
					"subnet-1": Prefix(netip.MustParsePrefix("100.100.101.100/24")),
					"outside":  Prefix(netip.MustParsePrefix("192.168.0.0/16")),
				},
				ACLs: []ACL{
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							// TODO(kradalby): Should this be host?
							// It is:
							// All traffic originating from Tailscale devices in your tailnet,
							// any approved subnets and autogroup:shared.
							// It does not allow traffic originating from
							// non-tailscale devices (unless it is an approved route).
							Host("*"),
						},
						Destinations: []AliasWithPorts{
							{
								// TODO(kradalby): Should this be host?
								// It is:
								// Includes any destination (no restrictions).
								Alias: Host("*"),
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
								Ports: []tailcfg.PortRange{tailcfg.PortRange{First: 80, Last: 80}},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							Group("group:example"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: Group("group:other"),
								Ports: []tailcfg.PortRange{tailcfg.PortRange{First: 80, Last: 80}},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							ptr.To(Prefix(netip.MustParsePrefix("100.101.102.103/32"))),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: ptr.To(Prefix(netip.MustParsePrefix("100.101.102.104/32"))),
								Ports: []tailcfg.PortRange{tailcfg.PortRange{First: 80, Last: 80}},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "udp",
						Sources: Aliases{
							ptr.To(Prefix(netip.MustParsePrefix("10.0.0.0/8"))),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: ptr.To(Prefix(netip.MustParsePrefix("172.16.0.0/16"))),
								Ports: []tailcfg.PortRange{tailcfg.PortRange{First: 80, Last: 80}},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							Host("subnet-1"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: Host("host-1"),
								Ports: []tailcfg.PortRange{tailcfg.PortRange{First: 80, Last: 88}},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							Tag("tag:group"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: Tag("tag:user"),
								Ports: []tailcfg.PortRange{
									tailcfg.PortRange{First: 80, Last: 80},
									tailcfg.PortRange{First: 443, Last: 443},
								},
							},
						},
					},
					{
						Action:   "accept",
						Protocol: "tcp",
						Sources: Aliases{
							Tag("tag:group"),
						},
						Destinations: []AliasWithPorts{
							{
								Alias: AutoGroup("autogroup:internet"),
								Ports: []tailcfg.PortRange{
									tailcfg.PortRange{First: 80, Last: 80},
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
			wantErr: `Username has to contain @, got: "group:inner"`,
		},
		{
			name: "invalid-prefix",
			input: `
{
	"hosts": {
		"derp": "10.0",
	},
}
`,
			wantErr: `ParseAddr("10.0"): IPv4 address too short`,
		},
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
	}

	cmps := append(util.Comparers, cmp.Comparer(func(x, y Prefix) bool {
		return x == y
	}))
	cmps = append(cmps, cmpopts.IgnoreUnexported(Policy{}))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := PolicyFromBytes([]byte(tt.input))
			// TODO(kradalby): This error checking is broken,
			// but so is my brain, #longflight
			if err == nil {
				if tt.wantErr == "" {
					return
				}
				t.Fatalf("got success; wanted error %q", tt.wantErr)
			}
			if err.Error() != tt.wantErr {
				t.Fatalf("got error %q; want %q", err, tt.wantErr)
				// } else if err.Error() == tt.wantErr {
				// 	return
			}

			if err != nil {
				t.Fatalf("unexpected err: %q", err)
			}

			if diff := cmp.Diff(tt.want, &policy, cmps...); diff != "" {
				t.Fatalf("unexpected policy (-want +got):\n%s", diff)
			}
		})
	}
}

func mp(pref string) netip.Prefix { return netip.MustParsePrefix(pref) }
func ap(addr string) *netip.Addr  { return ptr.To(netip.MustParseAddr(addr)) }
func pp(pref string) *Prefix      { return ptr.To(Prefix(netip.MustParsePrefix(pref))) }
func p(pref string) Prefix        { return Prefix(netip.MustParsePrefix(pref)) }

func TestResolvePolicy(t *testing.T) {
	tests := []struct {
		name      string
		nodes     types.Nodes
		pol       *Policy
		toResolve Alias
		want      []netip.Prefix
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
			toResolve: Host("testhost"),
			want:      []netip.Prefix{mp("100.100.101.102/32")},
		},
		{
			name:      "username",
			toResolve: ptr.To(Username("testuser")),
			nodes: types.Nodes{
				// Not matching other user
				{
					User: types.User{
						Name: "notme",
					},
					IPv4: ap("100.100.101.1"),
				},
				// Not matching forced tags
				{
					User: types.User{
						Name: "testuser",
					},
					ForcedTags: []string{"tag:anything"},
					IPv4:       ap("100.100.101.2"),
				},
				// not matchin pak tag
				{
					User: types.User{
						Name: "testuser",
					},
					AuthKey: &types.PreAuthKey{
						Tags: []string{"alsotagged"},
					},
					IPv4: ap("100.100.101.3"),
				},
				{
					User: types.User{
						Name: "testuser",
					},
					IPv4: ap("100.100.101.103"),
				},
				{
					User: types.User{
						Name: "testuser",
					},
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
					User: types.User{
						Name: "notmetoo",
					},
					IPv4: ap("100.100.101.4"),
				},
				// Not matching forced tags
				{
					User: types.User{
						Name: "groupuser",
					},
					ForcedTags: []string{"tag:anything"},
					IPv4:       ap("100.100.101.5"),
				},
				// not matchin pak tag
				{
					User: types.User{
						Name: "groupuser",
					},
					AuthKey: &types.PreAuthKey{
						Tags: []string{"tag:alsotagged"},
					},
					IPv4: ap("100.100.101.6"),
				},
				{
					User: types.User{
						Name: "groupuser",
					},
					IPv4: ap("100.100.101.203"),
				},
				{
					User: types.User{
						Name: "groupuser",
					},
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
			toResolve: Tag("tag:test"),
			nodes: types.Nodes{
				// Not matching other user
				{
					User: types.User{
						Name: "notmetoo",
					},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := tt.toResolve.Resolve(tt.pol, tt.nodes)
			if err != nil {
				t.Fatalf("failed to resolve: %s", err)
			}

			prefs := ips.Prefixes()

			if diff := cmp.Diff(tt.want, prefs, util.Comparers...); diff != "" {
				t.Fatalf("unexpected prefs (-want +got):\n%s", diff)
			}
		})
	}
}
