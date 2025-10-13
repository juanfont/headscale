package policy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/util/must"
)

var ap = func(ipStr string) *netip.Addr {
	ip := netip.MustParseAddr(ipStr)
	return &ip
}

var p = func(prefStr string) netip.Prefix {
	ip := netip.MustParsePrefix(prefStr)
	return ip
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
					IPProto: []int{6, 17},
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
					IPProto: []int{6, 17},
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
					IPProto: []int{6, 17},
				},
				{
					SrcIPs:   []string{"100.64.0.1/32", "100.64.0.2/32", "fd7a:115c:a1e0::1/128", "fd7a:115c:a1e0::2/128"},
					DstPorts: hsExitNodeDestForTest,
					IPProto:  []int{6, 17},
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
					IPProto: []int{6, 17},
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
					IPProto: []int{6, 17},
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
					IPProto: []int{6, 17},
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
					IPProto: []int{6, 17},
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
					IPProto: []int{6, 17},
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
					IPProto: []int{6, 17},
				},
			},
		},
		{
			name: "1817-reduce-breaks-32-mask",
			pol: `
{
  "tagOwners": {
    "tag:access-servers": ["user100@"],
  },
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
					IPProto: []int{6, 17},
				},
			},
		},
		{
			name: "2365-only-route-policy",
			pol: `
{
  "hosts": {
    "router": "100.64.0.1/32",
    "node": "100.64.0.2/32"
  },
  "acls": [
    {
      "action": "accept",
      "src": [
        "*"
      ],
      "dst": [
        "router:8000"
      ]
    },
    {
      "action": "accept",
      "src": [
        "node"
      ],
      "dst": [
        "172.26.0.0/16:*"
      ]
    }
  ],
}
`,
			node: &types.Node{
				IPv4: ap("100.64.0.2"),
				IPv6: ap("fd7a:115c:a1e0::2"),
				User: users[3],
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.1"),
					IPv6: ap("fd7a:115c:a1e0::1"),
					User: users[1],
					Hostinfo: &tailcfg.Hostinfo{
						RoutableIPs: []netip.Prefix{p("172.16.0.0/24"), p("10.10.11.0/24"), p("10.10.12.0/24")},
					},
					ApprovedRoutes: []netip.Prefix{p("172.16.0.0/24"), p("10.10.11.0/24"), p("10.10.12.0/24")},
				},
			},
			want: []tailcfg.FilterRule{},
		},
	}

	for _, tt := range tests {
		for idx, pmf := range PolicyManagerFuncsForTest([]byte(tt.pol)) {
			t.Run(fmt.Sprintf("%s-index%d", tt.name, idx), func(t *testing.T) {
				var pm PolicyManager
				var err error
				pm, err = pmf(users, append(tt.peers, tt.node).ViewSlice())
				require.NoError(t, err)
				got, _ := pm.Filter()
				t.Logf("full filter:\n%s", must.Get(json.MarshalIndent(got, "", "  ")))
				got = ReduceFilterRules(tt.node.View(), got)

				if diff := cmp.Diff(tt.want, got); diff != "" {
					log.Trace().Interface("got", got).Msg("result")
					t.Errorf("TestReduceFilterRules() unexpected result (-want +got):\n%s", diff)
				}
			})
		}
	}
}

func TestReduceNodes(t *testing.T) {
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
		{
			name: "subnet-router-with-only-route-smaller-mask-2181",
			args: args{
				nodes: []*types.Node{
					{
						ID:       1,
						IPv4:     ap("100.64.0.1"),
						Hostname: "router",
						User:     types.User{Name: "router"},
						Hostinfo: &tailcfg.Hostinfo{
							RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")},
						},
						ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")},
					},
					{
						ID:       2,
						IPv4:     ap("100.64.0.2"),
						Hostname: "node",
						User:     types.User{Name: "node"},
					},
				},
				rules: []tailcfg.FilterRule{
					{
						SrcIPs: []string{
							"100.64.0.2/32",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "10.99.0.2/32", Ports: tailcfg.PortRangeAny},
						},
					},
				},
				node: &types.Node{
					ID:       1,
					IPv4:     ap("100.64.0.1"),
					Hostname: "router",
					User:     types.User{Name: "router"},
					Hostinfo: &tailcfg.Hostinfo{
						RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")},
					},
					ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")},
				},
			},
			want: []*types.Node{
				{
					ID:       2,
					IPv4:     ap("100.64.0.2"),
					Hostname: "node",
					User:     types.User{Name: "node"},
				},
			},
		},
		{
			name: "node-to-subnet-router-with-only-route-smaller-mask-2181",
			args: args{
				nodes: []*types.Node{
					{
						ID:       1,
						IPv4:     ap("100.64.0.1"),
						Hostname: "router",
						User:     types.User{Name: "router"},
						Hostinfo: &tailcfg.Hostinfo{
							RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")},
						},
						ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")},
					},
					{
						ID:       2,
						IPv4:     ap("100.64.0.2"),
						Hostname: "node",
						User:     types.User{Name: "node"},
					},
				},
				rules: []tailcfg.FilterRule{
					{
						SrcIPs: []string{
							"100.64.0.2/32",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "10.99.0.2/32", Ports: tailcfg.PortRangeAny},
						},
					},
				},
				node: &types.Node{
					ID:       2,
					IPv4:     ap("100.64.0.2"),
					Hostname: "node",
					User:     types.User{Name: "node"},
				},
			},
			want: []*types.Node{
				{
					ID:       1,
					IPv4:     ap("100.64.0.1"),
					Hostname: "router",
					User:     types.User{Name: "router"},
					Hostinfo: &tailcfg.Hostinfo{
						RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")},
					},
					ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matchers := matcher.MatchesFromFilterRules(tt.args.rules)
			gotViews := ReduceNodes(
				tt.args.node.View(),
				tt.args.nodes.ViewSlice(),
				matchers,
			)
			// Convert views back to nodes for comparison in tests
			var got types.Nodes
			for _, v := range gotViews.All() {
				got = append(got, v.AsStruct())
			}
			if diff := cmp.Diff(tt.want, got, util.Comparers...); diff != "" {
				t.Errorf("FilterNodesByACL() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSSHPolicyRules(t *testing.T) {
	users := []types.User{
		{Name: "user1", Model: gorm.Model{ID: 1}},
		{Name: "user2", Model: gorm.Model{ID: 2}},
		{Name: "user3", Model: gorm.Model{ID: 3}},
	}

	// Create standard node setups used across tests
	nodeUser1 := types.Node{
		Hostname: "user1-device",
		IPv4:     ap("100.64.0.1"),
		UserID:   1,
		User:     users[0],
	}
	nodeUser2 := types.Node{
		Hostname: "user2-device",
		IPv4:     ap("100.64.0.2"),
		UserID:   2,
		User:     users[1],
	}

	taggedClient := types.Node{
		Hostname:   "tagged-client",
		IPv4:       ap("100.64.0.4"),
		UserID:     2,
		User:       users[1],
		ForcedTags: []string{"tag:client"},
	}

	tests := []struct {
		name         string
		targetNode   types.Node
		peers        types.Nodes
		policy       string
		wantSSH      *tailcfg.SSHPolicy
		expectErr    bool
		errorMessage string
	}{
		{
			name:       "group-to-user",
			targetNode: nodeUser1,
			peers:      types.Nodes{&nodeUser2},
			policy: `{
				"groups": {
					"group:admins": ["user2@"]
				},
				"ssh": [
					{
						"action": "accept",
						"src": ["group:admins"],
						"dst": ["user1@"],
						"users": ["autogroup:nonroot"]
					}
				]
			}`,
			wantSSH: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{
						{NodeIP: "100.64.0.2"},
					},
					SSHUsers: map[string]string{
						"*":    "=",
						"root": "",
					},
					Action: &tailcfg.SSHAction{
						Accept:                    true,
						AllowAgentForwarding:      true,
						AllowLocalPortForwarding:  true,
						AllowRemotePortForwarding: true,
					},
				},
			}},
		},
		{
			name:       "check-period-specified",
			targetNode: nodeUser1,
			peers:      types.Nodes{&taggedClient},
			policy: `{
				"tagOwners": {
					"tag:client": ["user1@"],
				},
				"ssh": [
					{
						"action": "check",
						"checkPeriod": "24h",
						"src": ["tag:client"],
						"dst": ["user1@"],
						"users": ["autogroup:nonroot"]
					}
				]
			}`,
			wantSSH: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{
						{NodeIP: "100.64.0.4"},
					},
					SSHUsers: map[string]string{
						"*":    "=",
						"root": "",
					},
					Action: &tailcfg.SSHAction{
						Accept:                    true,
						SessionDuration:           24 * time.Hour,
						AllowAgentForwarding:      true,
						AllowLocalPortForwarding:  true,
						AllowRemotePortForwarding: true,
					},
				},
			}},
		},
		{
			name:       "no-matching-rules",
			targetNode: nodeUser2,
			peers:      types.Nodes{&nodeUser1},
			policy: `{
			    "tagOwners": {
			    	"tag:client": ["user1@"],
			    },
				"ssh": [
					{
						"action": "accept",
						"src": ["tag:client"],
						"dst": ["user1@"],
						"users": ["autogroup:nonroot"]
					}
				]
			}`,
			wantSSH: &tailcfg.SSHPolicy{Rules: nil},
		},
		{
			name:       "invalid-action",
			targetNode: nodeUser1,
			peers:      types.Nodes{&nodeUser2},
			policy: `{
				"ssh": [
					{
						"action": "invalid",
						"src": ["group:admins"],
						"dst": ["user1@"],
						"users": ["autogroup:nonroot"]
					}
				]
			}`,
			expectErr:    true,
			errorMessage: `invalid SSH action "invalid", must be one of: accept, check`,
		},
		{
			name:       "invalid-check-period",
			targetNode: nodeUser1,
			peers:      types.Nodes{&nodeUser2},
			policy: `{
				"ssh": [
					{
						"action": "check",
						"checkPeriod": "invalid",
						"src": ["group:admins"],
						"dst": ["user1@"],
						"users": ["autogroup:nonroot"]
					}
				]
			}`,
			expectErr:    true,
			errorMessage: "not a valid duration string",
		},
		{
			name:       "unsupported-autogroup",
			targetNode: nodeUser1,
			peers:      types.Nodes{&taggedClient},
			policy: `{
        "ssh": [
            {
                "action": "accept",
                "src": ["tag:client"],
                "dst": ["user1@"],
                "users": ["autogroup:invalid"]
            }
        ]
    }`,
			expectErr:    true,
			errorMessage: "autogroup \"autogroup:invalid\" is not supported",
		},
		{
			name:       "autogroup-nonroot-should-use-wildcard-with-root-excluded",
			targetNode: nodeUser1,
			peers:      types.Nodes{&nodeUser2},
			policy: `{
				"groups": {
					"group:admins": ["user2@"]
				},
				"ssh": [
					{
						"action": "accept",
						"src": ["group:admins"],
						"dst": ["user1@"],
						"users": ["autogroup:nonroot"]
					}
				]
			}`,
			// autogroup:nonroot should map to wildcard "*" with root excluded
			wantSSH: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{
						{NodeIP: "100.64.0.2"},
					},
					SSHUsers: map[string]string{
						"*":    "=",
						"root": "",
					},
					Action: &tailcfg.SSHAction{
						Accept:                    true,
						AllowAgentForwarding:      true,
						AllowLocalPortForwarding:  true,
						AllowRemotePortForwarding: true,
					},
				},
			}},
		},
		{
			name:       "autogroup-nonroot-plus-root-should-use-wildcard-with-root-mapped",
			targetNode: nodeUser1,
			peers:      types.Nodes{&nodeUser2},
			policy: `{
				"groups": {
					"group:admins": ["user2@"]
				},
				"ssh": [
					{
						"action": "accept",
						"src": ["group:admins"],
						"dst": ["user1@"],
						"users": ["autogroup:nonroot", "root"]
					}
				]
			}`,
			// autogroup:nonroot + root should map to wildcard "*" with root mapped to itself
			wantSSH: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{
						{NodeIP: "100.64.0.2"},
					},
					SSHUsers: map[string]string{
						"*":    "=",
						"root": "root",
					},
					Action: &tailcfg.SSHAction{
						Accept:                    true,
						AllowAgentForwarding:      true,
						AllowLocalPortForwarding:  true,
						AllowRemotePortForwarding: true,
					},
				},
			}},
		},
		{
			name:       "specific-users-should-map-to-themselves-not-equals",
			targetNode: nodeUser1,
			peers:      types.Nodes{&nodeUser2},
			policy: `{
				"groups": {
					"group:admins": ["user2@"]
				},
				"ssh": [
					{
						"action": "accept",
						"src": ["group:admins"],
						"dst": ["user1@"],
						"users": ["ubuntu", "root"]
					}
				]
			}`,
			// specific usernames should map to themselves, not "="
			wantSSH: &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{
						{NodeIP: "100.64.0.2"},
					},
					SSHUsers: map[string]string{
						"root":   "root",
						"ubuntu": "ubuntu",
					},
					Action: &tailcfg.SSHAction{
						Accept:                    true,
						AllowAgentForwarding:      true,
						AllowLocalPortForwarding:  true,
						AllowRemotePortForwarding: true,
					},
				},
			}},
		},
	}

	for _, tt := range tests {
		for idx, pmf := range PolicyManagerFuncsForTest([]byte(tt.policy)) {
			t.Run(fmt.Sprintf("%s-index%d", tt.name, idx), func(t *testing.T) {
				var pm PolicyManager
				var err error
				pm, err = pmf(users, append(tt.peers, &tt.targetNode).ViewSlice())

				if tt.expectErr {
					require.Error(t, err)
					require.Contains(t, err.Error(), tt.errorMessage)
					return
				}

				require.NoError(t, err)

				got, err := pm.SSHPolicy(tt.targetNode.View())
				require.NoError(t, err)

				if diff := cmp.Diff(tt.wantSSH, got); diff != "" {
					t.Errorf("SSHPolicy() unexpected result (-want +got):\n%s", diff)
				}
			})
		}
	}
}

func TestReduceRoutes(t *testing.T) {
	type args struct {
		node   *types.Node
		routes []netip.Prefix
		rules  []tailcfg.FilterRule
	}
	tests := []struct {
		name string
		args args
		want []netip.Prefix
	}{
		{
			name: "node-can-access-all-routes",
			args: args{
				node: &types.Node{
					ID:   1,
					IPv4: ap("100.64.0.1"),
					User: types.User{Name: "user1"},
				},
				routes: []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/24"),
					netip.MustParsePrefix("192.168.1.0/24"),
					netip.MustParsePrefix("172.16.0.0/16"),
				},
				rules: []tailcfg.FilterRule{
					{
						SrcIPs: []string{"100.64.0.1"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*"},
						},
					},
				},
			},
			want: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.1.0/24"),
				netip.MustParsePrefix("172.16.0.0/16"),
			},
		},
		{
			name: "node-can-access-specific-route",
			args: args{
				node: &types.Node{
					ID:   1,
					IPv4: ap("100.64.0.1"),
					User: types.User{Name: "user1"},
				},
				routes: []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/24"),
					netip.MustParsePrefix("192.168.1.0/24"),
					netip.MustParsePrefix("172.16.0.0/16"),
				},
				rules: []tailcfg.FilterRule{
					{
						SrcIPs: []string{"100.64.0.1"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "10.0.0.0/24"},
						},
					},
				},
			},
			want: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
		},
		{
			name: "node-can-access-multiple-specific-routes",
			args: args{
				node: &types.Node{
					ID:   1,
					IPv4: ap("100.64.0.1"),
					User: types.User{Name: "user1"},
				},
				routes: []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/24"),
					netip.MustParsePrefix("192.168.1.0/24"),
					netip.MustParsePrefix("172.16.0.0/16"),
				},
				rules: []tailcfg.FilterRule{
					{
						SrcIPs: []string{"100.64.0.1"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "10.0.0.0/24"},
							{IP: "192.168.1.0/24"},
						},
					},
				},
			},
			want: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.1.0/24"),
			},
		},
		{
			name: "node-can-access-overlapping-routes",
			args: args{
				node: &types.Node{
					ID:   1,
					IPv4: ap("100.64.0.1"),
					User: types.User{Name: "user1"},
				},
				routes: []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/24"),
					netip.MustParsePrefix("10.0.0.0/16"), // Overlaps with the first one
					netip.MustParsePrefix("192.168.1.0/24"),
				},
				rules: []tailcfg.FilterRule{
					{
						SrcIPs: []string{"100.64.0.1"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "10.0.0.0/16"},
						},
					},
				},
			},
			want: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("10.0.0.0/16"),
			},
		},
		{
			name: "node-with-no-matching-rules",
			args: args{
				node: &types.Node{
					ID:   1,
					IPv4: ap("100.64.0.1"),
					User: types.User{Name: "user1"},
				},
				routes: []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/24"),
					netip.MustParsePrefix("192.168.1.0/24"),
					netip.MustParsePrefix("172.16.0.0/16"),
				},
				rules: []tailcfg.FilterRule{
					{
						SrcIPs: []string{"100.64.0.2"}, // Different source IP
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*"},
						},
					},
				},
			},
			want: nil,
		},
		{
			name: "node-with-both-ipv4-and-ipv6",
			args: args{
				node: &types.Node{
					ID:   1,
					IPv4: ap("100.64.0.1"),
					IPv6: ap("fd7a:115c:a1e0::1"),
					User: types.User{Name: "user1"},
				},
				routes: []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/24"),
					netip.MustParsePrefix("2001:db8::/64"),
					netip.MustParsePrefix("192.168.1.0/24"),
				},
				rules: []tailcfg.FilterRule{
					{
						SrcIPs: []string{"fd7a:115c:a1e0::1"}, // IPv6 source
						DstPorts: []tailcfg.NetPortRange{
							{IP: "2001:db8::/64"}, // IPv6 destination
						},
					},
					{
						SrcIPs: []string{"100.64.0.1"}, // IPv4 source
						DstPorts: []tailcfg.NetPortRange{
							{IP: "10.0.0.0/24"}, // IPv4 destination
						},
					},
				},
			},
			want: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("2001:db8::/64"),
			},
		},
		{
			name: "router-with-multiple-routes-and-node-with-specific-access",
			args: args{
				node: &types.Node{
					ID:   2,
					IPv4: ap("100.64.0.2"), // Node IP
					User: types.User{Name: "node"},
				},
				routes: []netip.Prefix{
					netip.MustParsePrefix("10.10.10.0/24"),
					netip.MustParsePrefix("10.10.11.0/24"),
					netip.MustParsePrefix("10.10.12.0/24"),
				},
				rules: []tailcfg.FilterRule{
					{
						SrcIPs: []string{"*"}, // Any source
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.1"}, // Router node
						},
					},
					{
						SrcIPs: []string{"100.64.0.2"}, // Node IP
						DstPorts: []tailcfg.NetPortRange{
							{IP: "10.10.10.0/24"}, // Only one subnet allowed
						},
					},
				},
			},
			want: []netip.Prefix{
				netip.MustParsePrefix("10.10.10.0/24"),
			},
		},
		{
			name: "node-with-access-to-one-subnet-and-partial-overlap",
			args: args{
				node: &types.Node{
					ID:   2,
					IPv4: ap("100.64.0.2"),
					User: types.User{Name: "node"},
				},
				routes: []netip.Prefix{
					netip.MustParsePrefix("10.10.10.0/24"),
					netip.MustParsePrefix("10.10.11.0/24"),
					netip.MustParsePrefix("10.10.10.0/16"), // Overlaps with the first one
				},
				rules: []tailcfg.FilterRule{
					{
						SrcIPs: []string{"100.64.0.2"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "10.10.10.0/24"}, // Only specific subnet
						},
					},
				},
			},
			want: []netip.Prefix{
				netip.MustParsePrefix("10.10.10.0/24"),
				netip.MustParsePrefix("10.10.10.0/16"), // With current implementation, this is included because it overlaps with the allowed subnet
			},
		},
		{
			name: "node-with-access-to-wildcard-subnet",
			args: args{
				node: &types.Node{
					ID:   2,
					IPv4: ap("100.64.0.2"),
					User: types.User{Name: "node"},
				},
				routes: []netip.Prefix{
					netip.MustParsePrefix("10.10.10.0/24"),
					netip.MustParsePrefix("10.10.11.0/24"),
					netip.MustParsePrefix("10.10.12.0/24"),
				},
				rules: []tailcfg.FilterRule{
					{
						SrcIPs: []string{"100.64.0.2"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "10.10.0.0/16"}, // Broader subnet that includes all three
						},
					},
				},
			},
			want: []netip.Prefix{
				netip.MustParsePrefix("10.10.10.0/24"),
				netip.MustParsePrefix("10.10.11.0/24"),
				netip.MustParsePrefix("10.10.12.0/24"),
			},
		},
		{
			name: "multiple-nodes-with-different-subnet-permissions",
			args: args{
				node: &types.Node{
					ID:   2,
					IPv4: ap("100.64.0.2"),
					User: types.User{Name: "node"},
				},
				routes: []netip.Prefix{
					netip.MustParsePrefix("10.10.10.0/24"),
					netip.MustParsePrefix("10.10.11.0/24"),
					netip.MustParsePrefix("10.10.12.0/24"),
				},
				rules: []tailcfg.FilterRule{
					{
						SrcIPs: []string{"100.64.0.1"}, // Different node
						DstPorts: []tailcfg.NetPortRange{
							{IP: "10.10.11.0/24"},
						},
					},
					{
						SrcIPs: []string{"100.64.0.2"}, // Our node
						DstPorts: []tailcfg.NetPortRange{
							{IP: "10.10.10.0/24"},
						},
					},
					{
						SrcIPs: []string{"100.64.0.3"}, // Different node
						DstPorts: []tailcfg.NetPortRange{
							{IP: "10.10.12.0/24"},
						},
					},
				},
			},
			want: []netip.Prefix{
				netip.MustParsePrefix("10.10.10.0/24"),
			},
		},
		{
			name: "exactly-matching-users-acl-example",
			args: args{
				node: &types.Node{
					ID:   2,
					IPv4: ap("100.64.0.2"), // node with IP 100.64.0.2
					User: types.User{Name: "node"},
				},
				routes: []netip.Prefix{
					netip.MustParsePrefix("10.10.10.0/24"),
					netip.MustParsePrefix("10.10.11.0/24"),
					netip.MustParsePrefix("10.10.12.0/24"),
				},
				rules: []tailcfg.FilterRule{
					{
						// This represents the rule: action: accept, src: ["*"], dst: ["router:0"]
						SrcIPs: []string{"*"}, // Any source
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.1"}, // Router IP
						},
					},
					{
						// This represents the rule: action: accept, src: ["node"], dst: ["10.10.10.0/24:*"]
						SrcIPs: []string{"100.64.0.2"}, // Node IP
						DstPorts: []tailcfg.NetPortRange{
							{IP: "10.10.10.0/24", Ports: tailcfg.PortRangeAny}, // All ports on this subnet
						},
					},
				},
			},
			want: []netip.Prefix{
				netip.MustParsePrefix("10.10.10.0/24"),
			},
		},
		{
			name: "acl-all-source-nodes-can-access-router-only-node-can-access-10.10.10.0-24",
			args: args{
				// When testing from router node's perspective
				node: &types.Node{
					ID:   1,
					IPv4: ap("100.64.0.1"), // router with IP 100.64.0.1
					User: types.User{Name: "router"},
				},
				routes: []netip.Prefix{
					netip.MustParsePrefix("10.10.10.0/24"),
					netip.MustParsePrefix("10.10.11.0/24"),
					netip.MustParsePrefix("10.10.12.0/24"),
				},
				rules: []tailcfg.FilterRule{
					{
						SrcIPs: []string{"*"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.1"}, // Router can be accessed by all
						},
					},
					{
						SrcIPs: []string{"100.64.0.2"}, // Only node
						DstPorts: []tailcfg.NetPortRange{
							{IP: "10.10.10.0/24"}, // Can access this subnet
						},
					},
					// Add a rule for router to access its own routes
					{
						SrcIPs: []string{"100.64.0.1"}, // Router node
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*"}, // Can access everything
						},
					},
				},
			},
			// Router needs explicit rules to access routes
			want: []netip.Prefix{
				netip.MustParsePrefix("10.10.10.0/24"),
				netip.MustParsePrefix("10.10.11.0/24"),
				netip.MustParsePrefix("10.10.12.0/24"),
			},
		},
		{
			name: "acl-specific-port-ranges-for-subnets",
			args: args{
				node: &types.Node{
					ID:   2,
					IPv4: ap("100.64.0.2"), // node
					User: types.User{Name: "node"},
				},
				routes: []netip.Prefix{
					netip.MustParsePrefix("10.10.10.0/24"),
					netip.MustParsePrefix("10.10.11.0/24"),
					netip.MustParsePrefix("10.10.12.0/24"),
				},
				rules: []tailcfg.FilterRule{
					{
						SrcIPs: []string{"100.64.0.2"}, // node
						DstPorts: []tailcfg.NetPortRange{
							{IP: "10.10.10.0/24", Ports: tailcfg.PortRange{First: 22, Last: 22}}, // Only SSH
						},
					},
					{
						SrcIPs: []string{"100.64.0.2"}, // node
						DstPorts: []tailcfg.NetPortRange{
							{IP: "10.10.11.0/24", Ports: tailcfg.PortRange{First: 80, Last: 80}}, // Only HTTP
						},
					},
				},
			},
			// Should get both subnets with specific port ranges
			want: []netip.Prefix{
				netip.MustParsePrefix("10.10.10.0/24"),
				netip.MustParsePrefix("10.10.11.0/24"),
			},
		},
		{
			name: "acl-order-of-rules-and-rule-specificity",
			args: args{
				node: &types.Node{
					ID:   2,
					IPv4: ap("100.64.0.2"), // node
					User: types.User{Name: "node"},
				},
				routes: []netip.Prefix{
					netip.MustParsePrefix("10.10.10.0/24"),
					netip.MustParsePrefix("10.10.11.0/24"),
					netip.MustParsePrefix("10.10.12.0/24"),
				},
				rules: []tailcfg.FilterRule{
					// First rule allows all traffic
					{
						SrcIPs: []string{"*"}, // Any source
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny}, // Any destination and any port
						},
					},
					// Second rule is more specific but should be overridden by the first rule
					{
						SrcIPs: []string{"100.64.0.2"}, // node
						DstPorts: []tailcfg.NetPortRange{
							{IP: "10.10.10.0/24"},
						},
					},
				},
			},
			// Due to the first rule allowing all traffic, node should have access to all routes
			want: []netip.Prefix{
				netip.MustParsePrefix("10.10.10.0/24"),
				netip.MustParsePrefix("10.10.11.0/24"),
				netip.MustParsePrefix("10.10.12.0/24"),
			},
		},
		{
			name: "return-path-subnet-router-to-regular-node-issue-2608",
			args: args{
				node: &types.Node{
					ID:   2,
					IPv4: ap("100.123.45.89"), // Node B - regular node
					User: types.User{Name: "node-b"},
				},
				routes: []netip.Prefix{
					netip.MustParsePrefix("192.168.1.0/24"), // Subnet connected to Node A
				},
				rules: []tailcfg.FilterRule{
					{
						// Policy allows 192.168.1.0/24 and group:routers to access *:*
						SrcIPs: []string{
							"192.168.1.0/24", // Subnet behind router
							"100.123.45.67",  // Node A (router, part of group:routers)
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny}, // Access to everything
						},
					},
				},
			},
			// Node B should receive the 192.168.1.0/24 route for return traffic
			// even though Node B cannot initiate connections to that network
			want: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/24"),
			},
		},
		{
			name: "return-path-router-perspective-2608",
			args: args{
				node: &types.Node{
					ID:   1,
					IPv4: ap("100.123.45.67"), // Node A - router node
					User: types.User{Name: "router"},
				},
				routes: []netip.Prefix{
					netip.MustParsePrefix("192.168.1.0/24"), // Subnet connected to this router
				},
				rules: []tailcfg.FilterRule{
					{
						// Policy allows 192.168.1.0/24 and group:routers to access *:*
						SrcIPs: []string{
							"192.168.1.0/24", // Subnet behind router
							"100.123.45.67",  // Node A (router, part of group:routers)
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny}, // Access to everything
						},
					},
				},
			},
			// Router should have access to its own routes
			want: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/24"),
			},
		},
		{
			name: "subnet-behind-router-bidirectional-connectivity-issue-2608",
			args: args{
				node: &types.Node{
					ID:   2,
					IPv4: ap("100.123.45.89"), // Node B - regular node that should be reachable
					User: types.User{Name: "node-b"},
				},
				routes: []netip.Prefix{
					netip.MustParsePrefix("192.168.1.0/24"), // Subnet behind router
					netip.MustParsePrefix("10.0.0.0/24"),    // Another subnet
				},
				rules: []tailcfg.FilterRule{
					{
						// Only 192.168.1.0/24 and routers can access everything
						SrcIPs: []string{
							"192.168.1.0/24", // Subnet that can connect to Node B
							"100.123.45.67",  // Router node
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
					},
					{
						// Node B cannot access anything (no rules with Node B as source)
						SrcIPs:   []string{"100.123.45.89"},
						DstPorts: []tailcfg.NetPortRange{
							// No destinations - Node B cannot initiate connections
						},
					},
				},
			},
			// Node B should still get the 192.168.1.0/24 route for return traffic
			// but should NOT get 10.0.0.0/24 since nothing allows that subnet to connect to Node B
			want: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/24"),
			},
		},
		{
			name: "no-route-leakage-when-no-connection-allowed-2608",
			args: args{
				node: &types.Node{
					ID:   3,
					IPv4: ap("100.123.45.99"), // Node C - isolated node
					User: types.User{Name: "isolated-node"},
				},
				routes: []netip.Prefix{
					netip.MustParsePrefix("192.168.1.0/24"), // Subnet behind router
					netip.MustParsePrefix("10.0.0.0/24"),    // Another private subnet
					netip.MustParsePrefix("172.16.0.0/24"),  // Yet another subnet
				},
				rules: []tailcfg.FilterRule{
					{
						// Only specific subnets and routers can access specific destinations
						SrcIPs: []string{
							"192.168.1.0/24", // This subnet can access everything
							"100.123.45.67",  // Router node can access everything
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.123.45.89", Ports: tailcfg.PortRangeAny}, // Only to Node B
						},
					},
					{
						// 10.0.0.0/24 can only access router
						SrcIPs: []string{"10.0.0.0/24"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.123.45.67", Ports: tailcfg.PortRangeAny}, // Only to router
						},
					},
					{
						// 172.16.0.0/24 has no access rules at all
					},
				},
			},
			// Node C should get NO routes because:
			// - 192.168.1.0/24 can only connect to Node B (not Node C)
			// - 10.0.0.0/24 can only connect to router (not Node C)
			// - 172.16.0.0/24 has no rules allowing it to connect anywhere
			// - Node C is not in any rules as a destination
			want: nil,
		},
		{
			name: "original-issue-2608-with-slash14-network",
			args: args{
				node: &types.Node{
					ID:   2,
					IPv4: ap("100.123.45.89"), // Node B - regular node
					User: types.User{Name: "node-b"},
				},
				routes: []netip.Prefix{
					netip.MustParsePrefix("192.168.1.0/14"), // Network 192.168.1.0/14 as mentioned in original issue
				},
				rules: []tailcfg.FilterRule{
					{
						// Policy allows 192.168.1.0/24 (part of /14) and group:routers to access *:*
						SrcIPs: []string{
							"192.168.1.0/24", // Subnet behind router (part of the larger /14 network)
							"100.123.45.67",  // Node A (router, part of group:routers)
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny}, // Access to everything
						},
					},
				},
			},
			// Node B should receive the 192.168.1.0/14 route for return traffic
			// even though only 192.168.1.0/24 (part of /14) can connect to Node B
			// This is the exact scenario from the original issue
			want: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/14"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matchers := matcher.MatchesFromFilterRules(tt.args.rules)
			got := ReduceRoutes(
				tt.args.node.View(),
				tt.args.routes,
				matchers,
			)
			if diff := cmp.Diff(tt.want, got, util.Comparers...); diff != "" {
				t.Errorf("ReduceRoutes() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}
