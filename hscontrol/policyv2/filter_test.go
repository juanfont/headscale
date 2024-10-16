package policyv2

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
)

// TODO(kradalby):
// Convert policy.TestReduceFilterRules to take JSON
// Move it here, run it against both old and new CompileFilterRules

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
			pol, err := PolicyFromBytes([]byte(tt.acl))
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
					IPv4: ap("100.100.100.100"),
				},
				&types.Node{
					IPv4: ap("200.200.200.200"),
					User: types.User{
						Name: "testuser@",
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

// hsExitNodeDestForTest is the list of destination IP ranges that are allowed when
// we use headscale "autogroup:internet".
var hsExitNodeDestForTest = []tailcfg.NetPortRange{
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

func TestReduceFilterRules(t *testing.T) {
	tests := []struct {
		name  string
		node  *types.Node
		peers types.Nodes
		pol   string
		want  []tailcfg.FilterRule
	}{
		{
			name: "host1-can-reach-host2-no-rules",
			pol: `
{
  "acls": [
    {
      "action": "accept",
      "proto": "",
      "src": [
        "100.64.0.1"
      ],
      "dst": [
        "100.64.0.2:*"
      ]
    }
  ],
}
`,
			node: &types.Node{
				IPv4: ap("100.64.0.1"),
				IPv6: ap("fd7a:115c:a1e0:ab12:4843:2222:6273:2221"),
				User: types.User{Name: "mickael"},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0:ab12:4843:2222:6273:2222"),
					User: types.User{Name: "mickael"},
				},
			},
			want: []tailcfg.FilterRule{},
		},
		{
			name: "1604-subnet-routers-are-preserved",
			pol: `
{
  "groups": {
    "group:admins": [
      "user1@"
    ]
  },
  "acls": [
    {
      "action": "accept",
      "proto": "",
      "src": [
        "group:admins"
      ],
      "dst": [
        "group:admins:*"
      ]
    },
    {
      "action": "accept",
      "proto": "",
      "src": [
        "group:admins"
      ],
      "dst": [
        "10.33.0.0/16:*"
      ]
    }
  ],
}
`,
			node: &types.Node{
				IPv4: ap("100.64.0.1"),
				IPv6: ap("fd7a:115c:a1e0::1"),
				User: types.User{Name: "user1@"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.33.0.0/16"),
					},
				},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0::2"),
					User: types.User{Name: "user1@"},
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
			pol: `
{
  "groups": {
    "group:team": [
      "user3@",
      "user2@",
      "user1@"
    ]
  },
  "hosts": {
    "internal": "100.64.0.100/32"
  },
  "acls": [
    {
      "action": "accept",
      "proto": "",
      "src": [
        "group:team"
      ],
      "dst": [
        "internal:*"
      ]
    },
    {
      "action": "accept",
      "proto": "",
      "src": [
        "group:team"
      ],
      "dst": [
        "autogroup:internet:*"
      ]
    }
  ],
}
`,
			node: &types.Node{
				IPv4: ap("100.64.0.1"),
				IPv6: ap("fd7a:115c:a1e0::1"),
				User: types.User{Name: "user1@"},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0::2"),
					User: types.User{Name: "user2@"},
				},
				// "internal" exit node
				&types.Node{
					IPv4: ap("100.64.0.100"),
					IPv6: ap("fd7a:115c:a1e0::100"),
					User: types.User{Name: "user100@"},
					Hostinfo: &tailcfg.Hostinfo{
						RoutableIPs: tsaddr.ExitRoutes(),
					},
				},
			},
			want: []tailcfg.FilterRule{},
		},
		{
			name: "1786-reducing-breaks-exit-nodes-the-exit",
			pol: `
{
  "groups": {
    "group:team": [
      "user3@",
      "user2@",
      "user1@"
    ]
  },
  "hosts": {
    "internal": "100.64.0.100/32"
  },
  "acls": [
    {
      "action": "accept",
      "proto": "",
      "src": [
        "group:team"
      ],
      "dst": [
        "internal:*"
      ]
    },
    {
      "action": "accept",
      "proto": "",
      "src": [
        "group:team"
      ],
      "dst": [
        "autogroup:internet:*"
      ]
    }
  ],
}
`,
			node: &types.Node{
				IPv4: ap("100.64.0.100"),
				IPv6: ap("fd7a:115c:a1e0::100"),
				User: types.User{Name: "user100@"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: tsaddr.ExitRoutes(),
				},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0::2"),
					User: types.User{Name: "user2@"},
				},
				&types.Node{
					IPv4: ap("100.64.0.1"),
					IPv6: ap("fd7a:115c:a1e0::1"),
					User: types.User{Name: "user1@"},
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
					DstPorts: hsExitNodeDestForTest,
				},
			},
		},
		{
			name: "1786-reducing-breaks-exit-nodes-the-example-from-issue",
			pol: `
{
  "groups": {
    "group:team": [
      "user3@",
      "user2@",
      "user1@"
    ]
  },
  "hosts": {
    "internal": "100.64.0.100/32"
  },
  "acls": [
    {
      "action": "accept",
      "proto": "",
      "src": [
        "group:team"
      ],
      "dst": [
        "internal:*"
      ]
    },
    {
      "action": "accept",
      "proto": "",
      "src": [
        "group:team"
      ],
      "dst": [
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
        "208.0.0.0/4:*"
      ]
    }
  ],
}
`,
			node: &types.Node{
				IPv4: ap("100.64.0.100"),
				IPv6: ap("fd7a:115c:a1e0::100"),
				User: types.User{Name: "user100@"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: tsaddr.ExitRoutes(),
				},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0::2"),
					User: types.User{Name: "user2@"},
				},
				&types.Node{
					IPv4: ap("100.64.0.1"),
					IPv6: ap("fd7a:115c:a1e0::1"),
					User: types.User{Name: "user1@"},
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
			pol: `
{
  "groups": {
    "group:team": [
      "user3@",
      "user2@",
      "user1@"
    ]
  },
  "hosts": {
    "internal": "100.64.0.100/32"
  },
  "acls": [
    {
      "action": "accept",
      "proto": "",
      "src": [
        "group:team"
      ],
      "dst": [
        "internal:*"
      ]
    },
    {
      "action": "accept",
      "proto": "",
      "src": [
        "group:team"
      ],
      "dst": [
        "8.0.0.0/8:*",
        "16.0.0.0/8:*"
      ]
    }
  ],
}
`,
			node: &types.Node{
				IPv4: ap("100.64.0.100"),
				IPv6: ap("fd7a:115c:a1e0::100"),
				User: types.User{Name: "user100@"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{netip.MustParsePrefix("8.0.0.0/16"), netip.MustParsePrefix("16.0.0.0/16")},
				},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0::2"),
					User: types.User{Name: "user2@"},
				},
				&types.Node{
					IPv4: ap("100.64.0.1"),
					IPv6: ap("fd7a:115c:a1e0::1"),
					User: types.User{Name: "user1@"},
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
			pol: `
{
  "groups": {
    "group:team": [
      "user3@",
      "user2@",
      "user1@"
    ]
  },
  "hosts": {
    "internal": "100.64.0.100/32"
  },
  "acls": [
    {
      "action": "accept",
      "proto": "",
      "src": [
        "group:team"
      ],
      "dst": [
        "internal:*"
      ]
    },
    {
      "action": "accept",
      "proto": "",
      "src": [
        "group:team"
      ],
      "dst": [
        "8.0.0.0/16:*",
        "16.0.0.0/16:*"
      ]
    }
  ],
}
`,
			node: &types.Node{
				IPv4: ap("100.64.0.100"),
				IPv6: ap("fd7a:115c:a1e0::100"),
				User: types.User{Name: "user100@"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{netip.MustParsePrefix("8.0.0.0/8"), netip.MustParsePrefix("16.0.0.0/8")},
				},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0::2"),
					User: types.User{Name: "user2@"},
				},
				&types.Node{
					IPv4: ap("100.64.0.1"),
					IPv6: ap("fd7a:115c:a1e0::1"),
					User: types.User{Name: "user1@"},
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
			pol: `
{
  "groups": {
    "group:access": [
      "user1@"
    ]
  },
  "hosts": {
    "dns1": "172.16.0.21/32",
    "vlan1": "172.16.0.0/24"
  },
  "acls": [
    {
      "action": "accept",
      "proto": "",
      "src": [
        "group:access"
      ],
      "dst": [
        "tag:access-servers:*",
        "dns1:*"
      ]
    }
  ],
}
`,
			node: &types.Node{
				IPv4: ap("100.64.0.100"),
				IPv6: ap("fd7a:115c:a1e0::100"),
				User: types.User{Name: "user100@"},
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{netip.MustParsePrefix("172.16.0.0/24")},
				},
				ForcedTags: []string{"tag:access-servers"},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.1"),
					IPv6: ap("fd7a:115c:a1e0::1"),
					User: types.User{Name: "user1@"},
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
			polV1, err := policy.LoadACLPolicyFromBytes([]byte(tt.pol))
			if err != nil {
				t.Fatalf("parsing policy: %s", err)
			}
			filterV1, _ := polV1.CompileFilterRules(
				append(tt.peers, tt.node),
			)
			polV2, err := PolicyFromBytes([]byte(tt.pol))
			if err != nil {
				t.Fatalf("parsing policy: %s", err)
			}
			filterV2, _ := polV2.CompileFilterRules(
				append(tt.peers, tt.node),
			)

			if diff := cmp.Diff(filterV1, filterV2); diff != "" {
				log.Trace().Interface("got", filterV2).Msg("result")
				t.Errorf("TestReduceFilterRules() unexpected diff between v1 and v2 (-want +got):\n%s", diff)
			}

			// TODO(kradalby): Move this from v1, or
			// rewrite.
			filterV2 = policy.ReduceFilterRules(tt.node, filterV2)

			if diff := cmp.Diff(tt.want, filterV2); diff != "" {
				log.Trace().Interface("got", filterV2).Msg("result")
				t.Errorf("TestReduceFilterRules() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}
