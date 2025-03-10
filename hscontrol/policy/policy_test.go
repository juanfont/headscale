package policy

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
)

var ap = func(ipStr string) *netip.Addr {
	ip := netip.MustParseAddr(ipStr)
	return &ip
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

func TestTheInternet(t *testing.T) {
	internetSet := util.TheInternet()

	internetPrefs := internetSet.Prefixes()

	for i := range internetPrefs {
		if internetPrefs[i].String() != hsExitNodeDestForTest[i].IP {
			t.Errorf(
				"prefix from internet set %q != hsExit list %q",
				internetPrefs[i].String(),
				hsExitNodeDestForTest[i].IP,
			)
		}
	}

	if len(internetPrefs) != len(hsExitNodeDestForTest) {
		t.Fatalf(
			"expected same length of prefixes, internet: %d, hsExit: %d",
			len(internetPrefs),
			len(hsExitNodeDestForTest),
		)
	}
}

// addAtForFilterV1 returns a copy of the given userslice
// and adds "@" character to the Name field.
// This is a "compatibility" move to allow the old tests
// to run against the "new" format which requires "@".
func addAtForFilterV1(users types.Users) types.Users {
	ret := make(types.Users, len(users))
	for idx := range users {
		ret[idx] = users[idx]
		ret[idx].Name = ret[idx].Name + "@"
	}
	return ret
}

func TestReduceFilterRules(t *testing.T) {
	users := types.Users{
		types.User{Model: gorm.Model{ID: 1}, Name: "mickael"},
		types.User{Model: gorm.Model{ID: 2}, Name: "user1"},
		types.User{Model: gorm.Model{ID: 3}, Name: "user2"},
		types.User{Model: gorm.Model{ID: 4}, Name: "user100"},
		types.User{Model: gorm.Model{ID: 5}, Name: "user3"},
	}

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
				User: users[0],
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0:ab12:4843:2222:6273:2222"),
					User: users[0],
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
				User: users[1],
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
					User: users[1],
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
				User: users[1],
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0::2"),
					User: users[2],
				},
				// "internal" exit node
				&types.Node{
					IPv4: ap("100.64.0.100"),
					IPv6: ap("fd7a:115c:a1e0::100"),
					User: users[3],
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
				User: users[3],
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: tsaddr.ExitRoutes(),
				},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0::2"),
					User: users[2],
				},
				&types.Node{
					IPv4: ap("100.64.0.1"),
					IPv6: ap("fd7a:115c:a1e0::1"),
					User: users[1],
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
				User: users[3],
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: tsaddr.ExitRoutes(),
				},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0::2"),
					User: users[2],
				},
				&types.Node{
					IPv4: ap("100.64.0.1"),
					IPv6: ap("fd7a:115c:a1e0::1"),
					User: users[1],
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
						// This should not be included I believe, seems like
						// this is a bug in the v1 code.
						// For example:
						// If a src or dst includes "64.0.0.0/2:*", it will include 100.64/16 range, which
						// means that it will need to fetch the IPv6 addrs of the node to include the full range.
						// Clearly, if a user sets the dst to be "64.0.0.0/2:*", it is likely more of a exit node
						// and this would be strange behaviour.
						// TODO(kradalby): Remove before launch.
						{IP: "fd7a:115c:a1e0::1/128", Ports: tailcfg.PortRangeAny},
						{IP: "fd7a:115c:a1e0::2/128", Ports: tailcfg.PortRangeAny},
						{IP: "fd7a:115c:a1e0::100/128", Ports: tailcfg.PortRangeAny},
						// End
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
				User: users[3],
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{netip.MustParsePrefix("8.0.0.0/16"), netip.MustParsePrefix("16.0.0.0/16")},
				},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0::2"),
					User: users[2],
				},
				&types.Node{
					IPv4: ap("100.64.0.1"),
					IPv6: ap("fd7a:115c:a1e0::1"),
					User: users[1],
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
				User: users[3],
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{netip.MustParsePrefix("8.0.0.0/8"), netip.MustParsePrefix("16.0.0.0/8")},
				},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0::2"),
					User: users[2],
				},
				&types.Node{
					IPv4: ap("100.64.0.1"),
					IPv6: ap("fd7a:115c:a1e0::1"),
					User: users[1],
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
				User: users[3],
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{netip.MustParsePrefix("172.16.0.0/24")},
				},
				ForcedTags: []string{"tag:access-servers"},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.1"),
					IPv6: ap("fd7a:115c:a1e0::1"),
					User: users[1],
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
		for idx, pmf := range PolicyManagerFuncsForTest([]byte(tt.pol)) {
			version := idx + 1
			t.Run(fmt.Sprintf("%s-v%d", tt.name, version), func(t *testing.T) {
				var pm PolicyManager
				var err error
				if version == 1 {
					pm, err = pmf(addAtForFilterV1(users), append(tt.peers, tt.node))
				} else {
					pm, err = pmf(users, append(tt.peers, tt.node))
				}
				require.NoError(t, err)
				got := pm.Filter()
				got = ReduceFilterRules(tt.node, got)

				if diff := cmp.Diff(tt.want, got); diff != "" {
					log.Trace().Interface("got", got).Msg("result")
					t.Errorf("TestReduceFilterRules() unexpected result (-want +got):\n%s", diff)
				}
			})
		}
	}
}

func TestFilterNodesByACL(t *testing.T) {
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
				nodes: types.Nodes{ // list of all nodes in the database
					&types.Node{
						ID:   1,
						IPv4: ap("100.64.0.1"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						ID:   2,
						IPv4: ap("100.64.0.2"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						ID:   3,
						IPv4: ap("100.64.0.3"),
						User: types.User{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{
					{
						SrcIPs: []string{"100.64.0.1", "100.64.0.2", "100.64.0.3"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*"},
						},
					},
				},
				node: &types.Node{ // current nodes
					ID:   1,
					IPv4: ap("100.64.0.1"),
					User: types.User{Name: "joe"},
				},
			},
			want: types.Nodes{
				&types.Node{
					ID:   2,
					IPv4: ap("100.64.0.2"),
					User: types.User{Name: "marc"},
				},
				&types.Node{
					ID:   3,
					IPv4: ap("100.64.0.3"),
					User: types.User{Name: "mickael"},
				},
			},
		},
		{
			name: "One host can talk to another, but not all hosts",
			args: args{
				nodes: types.Nodes{ // list of all nodes in the database
					&types.Node{
						ID:   1,
						IPv4: ap("100.64.0.1"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						ID:   2,
						IPv4: ap("100.64.0.2"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						ID:   3,
						IPv4: ap("100.64.0.3"),
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
					IPv4: ap("100.64.0.1"),
					User: types.User{Name: "joe"},
				},
			},
			want: types.Nodes{
				&types.Node{
					ID:   2,
					IPv4: ap("100.64.0.2"),
					User: types.User{Name: "marc"},
				},
			},
		},
		{
			name: "host cannot directly talk to destination, but return path is authorized",
			args: args{
				nodes: types.Nodes{ // list of all nodes in the database
					&types.Node{
						ID:   1,
						IPv4: ap("100.64.0.1"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						ID:   2,
						IPv4: ap("100.64.0.2"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						ID:   3,
						IPv4: ap("100.64.0.3"),
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
					IPv4: ap("100.64.0.2"),
					User: types.User{Name: "marc"},
				},
			},
			want: types.Nodes{
				&types.Node{
					ID:   3,
					IPv4: ap("100.64.0.3"),
					User: types.User{Name: "mickael"},
				},
			},
		},
		{
			name: "rules allows all hosts to reach one destination",
			args: args{
				nodes: types.Nodes{ // list of all nodes in the database
					&types.Node{
						ID:   1,
						IPv4: ap("100.64.0.1"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						ID:   2,
						IPv4: ap("100.64.0.2"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						ID:   3,
						IPv4: ap("100.64.0.3"),
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
					IPv4: ap("100.64.0.1"),
					User: types.User{Name: "joe"},
				},
			},
			want: types.Nodes{
				&types.Node{
					ID:   2,
					IPv4: ap("100.64.0.2"),
					User: types.User{Name: "marc"},
				},
			},
		},
		{
			name: "rules allows all hosts to reach one destination, destination can reach all hosts",
			args: args{
				nodes: types.Nodes{ // list of all nodes in the database
					&types.Node{
						ID:   1,
						IPv4: ap("100.64.0.1"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						ID:   2,
						IPv4: ap("100.64.0.2"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						ID:   3,
						IPv4: ap("100.64.0.3"),
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
					IPv4: ap("100.64.0.2"),
					User: types.User{Name: "marc"},
				},
			},
			want: types.Nodes{
				&types.Node{
					ID:   1,
					IPv4: ap("100.64.0.1"),
					User: types.User{Name: "joe"},
				},
				&types.Node{
					ID:   3,
					IPv4: ap("100.64.0.3"),
					User: types.User{Name: "mickael"},
				},
			},
		},
		{
			name: "rule allows all hosts to reach all destinations",
			args: args{
				nodes: types.Nodes{ // list of all nodes in the database
					&types.Node{
						ID:   1,
						IPv4: ap("100.64.0.1"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						ID:   2,
						IPv4: ap("100.64.0.2"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						ID:   3,
						IPv4: ap("100.64.0.3"),
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
					IPv4: ap("100.64.0.2"),
					User: types.User{Name: "marc"},
				},
			},
			want: types.Nodes{
				&types.Node{
					ID:   1,
					IPv4: ap("100.64.0.1"),
					User: types.User{Name: "joe"},
				},
				&types.Node{
					ID:   3,
					IPv4: ap("100.64.0.3"),
					User: types.User{Name: "mickael"},
				},
			},
		},
		{
			name: "without rule all communications are forbidden",
			args: args{
				nodes: types.Nodes{ // list of all nodes in the database
					&types.Node{
						ID:   1,
						IPv4: ap("100.64.0.1"),
						User: types.User{Name: "joe"},
					},
					&types.Node{
						ID:   2,
						IPv4: ap("100.64.0.2"),
						User: types.User{Name: "marc"},
					},
					&types.Node{
						ID:   3,
						IPv4: ap("100.64.0.3"),
						User: types.User{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
				},
				node: &types.Node{ // current nodes
					ID:   2,
					IPv4: ap("100.64.0.2"),
					User: types.User{Name: "marc"},
				},
			},
			want: nil,
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
						IPv4:     ap("100.64.0.3"),
						IPv6:     ap("fd7a:115c:a1e0::3"),
						User:     types.User{Name: "user1"},
					},
					&types.Node{
						ID:       2,
						Hostname: "ts-unstable-rlwpvr",
						IPv4:     ap("100.64.0.4"),
						IPv6:     ap("fd7a:115c:a1e0::4"),
						User:     types.User{Name: "user1"},
					},
					&types.Node{
						ID:       3,
						Hostname: "ts-head-8w6paa",
						IPv4:     ap("100.64.0.1"),
						IPv6:     ap("fd7a:115c:a1e0::1"),
						User:     types.User{Name: "user2"},
					},
					&types.Node{
						ID:       4,
						Hostname: "ts-unstable-lys2ib",
						IPv4:     ap("100.64.0.2"),
						IPv6:     ap("fd7a:115c:a1e0::2"),
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
					IPv4:     ap("100.64.0.1"),
					IPv6:     ap("fd7a:115c:a1e0::1"),
					User:     types.User{Name: "user2"},
				},
			},
			want: types.Nodes{
				&types.Node{
					ID:       1,
					Hostname: "ts-head-upcrmb",
					IPv4:     ap("100.64.0.3"),
					IPv6:     ap("fd7a:115c:a1e0::3"),
					User:     types.User{Name: "user1"},
				},
				&types.Node{
					ID:       2,
					Hostname: "ts-unstable-rlwpvr",
					IPv4:     ap("100.64.0.4"),
					IPv6:     ap("fd7a:115c:a1e0::4"),
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
						IPv4:     ap("100.64.0.2"),
						Hostname: "peer1",
						User:     types.User{Name: "mini"},
					},
					{
						ID:       2,
						IPv4:     ap("100.64.0.3"),
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
					IPv4:     ap("100.64.0.1"),
					Hostname: "mini",
					User:     types.User{Name: "mini"},
				},
			},
			want: []*types.Node{
				{
					ID:       2,
					IPv4:     ap("100.64.0.3"),
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
						IPv4:     ap("100.64.0.2"),
						Hostname: "user1-2",
						User:     types.User{Name: "user1"},
					},
					{
						ID:       0,
						IPv4:     ap("100.64.0.1"),
						Hostname: "user1-1",
						User:     types.User{Name: "user1"},
					},
					{
						ID:       3,
						IPv4:     ap("100.64.0.4"),
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
					IPv4:     ap("100.64.0.3"),
					Hostname: "user-2-1",
					User:     types.User{Name: "user2"},
				},
			},
			want: []*types.Node{
				{
					ID:       1,
					IPv4:     ap("100.64.0.2"),
					Hostname: "user1-2",
					User:     types.User{Name: "user1"},
				},
				{
					ID:       0,
					IPv4:     ap("100.64.0.1"),
					Hostname: "user1-1",
					User:     types.User{Name: "user1"},
				},
				{
					ID:       3,
					IPv4:     ap("100.64.0.4"),
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
						IPv4:     ap("100.64.0.2"),
						Hostname: "user1-2",
						User:     types.User{Name: "user1"},
					},
					{
						ID:       2,
						IPv4:     ap("100.64.0.3"),
						Hostname: "user-2-1",
						User:     types.User{Name: "user2"},
					},
					{
						ID:       3,
						IPv4:     ap("100.64.0.4"),
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
					IPv4:     ap("100.64.0.1"),
					Hostname: "user1-1",
					User:     types.User{Name: "user1"},
				},
			},
			want: []*types.Node{
				{
					ID:       1,
					IPv4:     ap("100.64.0.2"),
					Hostname: "user1-2",
					User:     types.User{Name: "user1"},
				},
				{
					ID:       2,
					IPv4:     ap("100.64.0.3"),
					Hostname: "user-2-1",
					User:     types.User{Name: "user2"},
				},
				{
					ID:       3,
					IPv4:     ap("100.64.0.4"),
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
						IPv4:     ap("100.64.0.1"),
						Hostname: "user1",
						User:     types.User{Name: "user1"},
					},
					{
						ID:       2,
						IPv4:     ap("100.64.0.2"),
						Hostname: "router",
						User:     types.User{Name: "router"},
						Hostinfo: &tailcfg.Hostinfo{
							RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")},
						},
						ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")},
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
					IPv4:     ap("100.64.0.1"),
					Hostname: "user1",
					User:     types.User{Name: "user1"},
				},
			},
			want: []*types.Node{
				{
					ID:       2,
					IPv4:     ap("100.64.0.2"),
					Hostname: "router",
					User:     types.User{Name: "router"},
					Hostinfo: &tailcfg.Hostinfo{
						RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")},
					},
					ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterNodesByACL(
				tt.args.node,
				tt.args.nodes,
				tt.args.rules,
			)
			if diff := cmp.Diff(tt.want, got, util.Comparers...); diff != "" {
				t.Errorf("FilterNodesByACL() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}
