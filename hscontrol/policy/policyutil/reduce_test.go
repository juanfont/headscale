package policyutil_test

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/policy/packetfilter"
	"github.com/juanfont/headscale/hscontrol/policy/policyutil"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
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

	internetPrefs := slices.Collect(internetSet.Prefixes())

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
		types.User{ID: 1, Name: "mickael"},
		types.User{ID: 2, Name: "user1"},
		types.User{ID: 3, Name: "user2"},
		types.User{ID: 4, Name: "user100"},
		types.User{ID: 5, Name: "user3"},
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
				User: new(users[0]),
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0:ab12:4843:2222:6273:2222"),
					User: new(users[0]),
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
				User: new(users[1]),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.33.0.0/16"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.33.0.0/16"),
				},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0::2"),
					User: new(users[1]),
				},
			},
			want: []tailcfg.FilterRule{
				// Merged: Both ACL rules combined (same SrcIPs)
				{
					SrcIPs: []string{
						"100.64.0.1-100.64.0.2",
						"fd7a:115c:a1e0::1-fd7a:115c:a1e0::2",
					},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "100.64.0.1",
							Ports: tailcfg.PortRangeAny,
						},
						{
							IP:    "fd7a:115c:a1e0::1",
							Ports: tailcfg.PortRangeAny,
						},
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
				User: new(users[1]),
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0::2"),
					User: new(users[2]),
				},
				// "internal" exit node
				&types.Node{
					IPv4: ap("100.64.0.100"),
					IPv6: ap("fd7a:115c:a1e0::100"),
					User: new(users[3]),
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
				User: new(users[3]),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: tsaddr.ExitRoutes(),
				},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0::2"),
					User: new(users[2]),
				},
				&types.Node{
					IPv4: ap("100.64.0.1"),
					IPv6: ap("fd7a:115c:a1e0::1"),
					User: new(users[1]),
				},
			},
			want: []tailcfg.FilterRule{
				// Only the internal:* rule generates filters.
				// autogroup:internet does NOT generate packet filters - it's handled
				// by exit node routing via AllowedIPs, not by packet filtering.
				{
					SrcIPs: []string{
						"100.64.0.1-100.64.0.2",
						"fd7a:115c:a1e0::1-fd7a:115c:a1e0::2",
					},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "100.64.0.100",
							Ports: tailcfg.PortRangeAny,
						},
					},
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
				User: new(users[3]),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: tsaddr.ExitRoutes(),
				},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0::2"),
					User: new(users[2]),
				},
				&types.Node{
					IPv4: ap("100.64.0.1"),
					IPv6: ap("fd7a:115c:a1e0::1"),
					User: new(users[1]),
				},
			},
			want: []tailcfg.FilterRule{
				// Exit routes (0.0.0.0/0, ::/0) are skipped when checking RoutableIPs
				// overlap, matching Tailscale SaaS behavior. Only destinations that
				// contain the node's own Tailscale IP (via InIPSet) are kept.
				// Here, 64.0.0.0/2 contains 100.64.0.100 (CGNAT range), so it matches.
				{
					SrcIPs: []string{
						"100.64.0.1-100.64.0.2",
						"fd7a:115c:a1e0::1-fd7a:115c:a1e0::2",
					},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "100.64.0.100",
							Ports: tailcfg.PortRangeAny,
						},
						{IP: "64.0.0.0/2", Ports: tailcfg.PortRangeAny},
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
				User: new(users[3]),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{netip.MustParsePrefix("8.0.0.0/16"), netip.MustParsePrefix("16.0.0.0/16")},
				},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("8.0.0.0/16"), netip.MustParsePrefix("16.0.0.0/16")},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0::2"),
					User: new(users[2]),
				},
				&types.Node{
					IPv4: ap("100.64.0.1"),
					IPv6: ap("fd7a:115c:a1e0::1"),
					User: new(users[1]),
				},
			},
			want: []tailcfg.FilterRule{
				// Merged: Both ACL rules combined (same SrcIPs)
				{
					SrcIPs: []string{
						"100.64.0.1-100.64.0.2",
						"fd7a:115c:a1e0::1-fd7a:115c:a1e0::2",
					},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "100.64.0.100",
							Ports: tailcfg.PortRangeAny,
						},
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
				User: new(users[3]),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{netip.MustParsePrefix("8.0.0.0/8"), netip.MustParsePrefix("16.0.0.0/8")},
				},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("8.0.0.0/8"), netip.MustParsePrefix("16.0.0.0/8")},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.2"),
					IPv6: ap("fd7a:115c:a1e0::2"),
					User: new(users[2]),
				},
				&types.Node{
					IPv4: ap("100.64.0.1"),
					IPv6: ap("fd7a:115c:a1e0::1"),
					User: new(users[1]),
				},
			},
			want: []tailcfg.FilterRule{
				// Merged: Both ACL rules combined (same SrcIPs)
				{
					SrcIPs: []string{
						"100.64.0.1-100.64.0.2",
						"fd7a:115c:a1e0::1-fd7a:115c:a1e0::2",
					},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "100.64.0.100",
							Ports: tailcfg.PortRangeAny,
						},
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
				User: new(users[3]),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{netip.MustParsePrefix("172.16.0.0/24")},
				},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("172.16.0.0/24")},
				Tags:           []string{"tag:access-servers"},
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.1"),
					IPv6: ap("fd7a:115c:a1e0::1"),
					User: new(users[1]),
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{
						"100.64.0.1",
						"fd7a:115c:a1e0::1",
					},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "100.64.0.100",
							Ports: tailcfg.PortRangeAny,
						},
						{
							IP:    "fd7a:115c:a1e0::100",
							Ports: tailcfg.PortRangeAny,
						},
						{
							IP:    "172.16.0.21",
							Ports: tailcfg.PortRangeAny,
						},
					},
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
				User: new(users[3]),
			},
			peers: types.Nodes{
				&types.Node{
					IPv4: ap("100.64.0.1"),
					IPv6: ap("fd7a:115c:a1e0::1"),
					User: new(users[1]),
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
		for idx, pmf := range policy.PolicyManagerFuncsForTest(
			[]byte(tt.pol),
		) {
			t.Run(fmt.Sprintf("%s-index%d", tt.name, idx), func(t *testing.T) {
				var (
					pm  policy.PolicyManager
					err error
				)

				pm, err = pmf(users, append(tt.peers, tt.node).ViewSlice())
				require.NoError(t, err)

				got := packetfilter.ToTailcfg(pm.PacketRules())
				t.Logf("full filter:\n%s", must.Get(json.MarshalIndent(got, "", "  ")))
				got = policyutil.ReduceFilterRules(tt.node.View(), got)

				if diff := cmp.Diff(
					semanticRulesReference(t, tt.want),
					semanticRulesReference(t, got),
				); diff != "" {
					log.Trace().Interface("got", got).Msg("result")
					t.Errorf("TestReduceFilterRules() unexpected result (-want +got):\n%s", diff)
				}
			})
		}
	}
}

// TestReduceFilterRulesPartialApproval verifies that ReduceFilterRules
// only preserves filter rules for routes that are both advertised
// (RoutableIPs) AND approved (ApprovedRoutes), matching Tailscale
// SaaS behavior. Advertised-but-unapproved routes do not cause rule
// preservation: SaaS never generates filter rules for unapproved
// routes, and headscale consults node.SubnetRoutes() (which filters
// by approval) rather than Hostinfo.RoutableIPs() (which does not).
func TestReduceFilterRulesPartialApproval(t *testing.T) {
	tests := []struct {
		name       string
		node       *types.Node
		rules      []tailcfg.FilterRule
		wantCount  int
		wantRoutes []string
	}{
		{
			name: "approved-route-included",
			node: &types.Node{
				IPv4: ap("100.64.0.1"),
				IPv6: ap("fd7a:115c:a1e0::1"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.33.0.0/16"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.33.0.0/16"),
				},
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"*"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "10.33.0.0/16", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			wantCount:  1,
			wantRoutes: []string{"10.33.0.0/16"},
		},
		{
			name: "unapproved-route-excluded",
			node: &types.Node{
				IPv4: ap("100.64.0.1"),
				IPv6: ap("fd7a:115c:a1e0::1"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.33.0.0/16"),
						// Advertised but NOT approved:
						netip.MustParsePrefix("172.16.0.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					// Only 10.33.0.0/16 approved
					netip.MustParsePrefix("10.33.0.0/16"),
				},
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"*"},
					DstPorts: []tailcfg.NetPortRange{
						// Targets the unapproved route
						{IP: "172.16.0.0/24", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			// SubnetRoutes() does NOT contain 172.16.0.0/24
			// (only approved routes), and the ACL dst does not
			// overlap the node's own IPs, so the rule is
			// dropped. This matches Tailscale SaaS behavior.
			wantCount: 0,
		},
		{
			name: "neither-advertised-nor-approved-excluded",
			node: &types.Node{
				IPv4: ap("100.64.0.1"),
				IPv6: ap("fd7a:115c:a1e0::1"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.33.0.0/16"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.33.0.0/16"),
				},
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"*"},
					DstPorts: []tailcfg.NetPortRange{
						// Not advertised, not approved
						{IP: "192.168.0.0/16", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			wantCount: 0,
		},
		{
			// Tailscale SaaS delivers every rule to an approved exit
			// node: its exit routes contain every destination.
			name: "approved-exit-route-includes-tailnet-host",
			node: &types.Node{
				IPv4:     ap("100.64.0.1"),
				IPv6:     ap("fd7a:115c:a1e0::1"),
				Hostinfo: &tailcfg.Hostinfo{RoutableIPs: tsaddr.ExitRoutes()},

				ApprovedRoutes: tsaddr.ExitRoutes(),
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.17"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.16", Ports: tailcfg.PortRange{First: 53, Last: 53}},
						{IP: "fd7a:115c:a1e0::10", Ports: tailcfg.PortRange{First: 53, Last: 53}},
					},
				},
			},
			wantCount:  1,
			wantRoutes: []string{"100.64.0.16", "fd7a:115c:a1e0::10"},
		},
		{
			name: "approved-exit-route-includes-private-subnet",
			node: &types.Node{
				IPv4:     ap("100.64.0.1"),
				IPv6:     ap("fd7a:115c:a1e0::1"),
				Hostinfo: &tailcfg.Hostinfo{RoutableIPs: tsaddr.ExitRoutes()},

				ApprovedRoutes: tsaddr.ExitRoutes(),
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.17"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "10.33.0.0/16", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			wantCount:  1,
			wantRoutes: []string{"10.33.0.0/16"},
		},
		{
			name: "unapproved-exit-route-excluded",
			node: &types.Node{
				IPv4:     ap("100.64.0.1"),
				IPv6:     ap("fd7a:115c:a1e0::1"),
				Hostinfo: &tailcfg.Hostinfo{RoutableIPs: tsaddr.ExitRoutes()},
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.17"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.16", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policyutil.ReduceFilterRules(
				tt.node.View(), tt.rules,
			)
			require.Len(t, got, tt.wantCount,
				"rule count mismatch")

			if tt.wantCount > 0 {
				var gotRoutes []string
				for _, dp := range got[0].DstPorts {
					gotRoutes = append(gotRoutes, dp.IP)
				}

				require.Equal(t, tt.wantRoutes, gotRoutes)
			}
		})
	}
}

// TestReduceFilterRulesCapGrant tests the CapGrant branch of
// ReduceFilterRules, which was previously untested. All existing
// test cases use ACL-only policies with DstPorts rules.
func TestReduceFilterRulesCapGrant(t *testing.T) {
	tests := []struct {
		name  string
		node  *types.Node
		rules []tailcfg.FilterRule
		want  []tailcfg.FilterRule
	}{
		{
			name: "capgrant-matches-node-ip-narrowed",
			node: &types.Node{
				IPv4: ap("100.64.0.1"),
				IPv6: ap("fd7a:115c:a1e0::1"),
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"10.0.0.0/8"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{
								// Broad IPv4 prefix containing node IP
								netip.MustParsePrefix("100.64.0.0/10"),
							},
							CapMap: tailcfg.PeerCapMap{
								"tailscale.com/cap/drive-sharer": nil,
							},
						},
					},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"10.0.0.0/8"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{
								// Only IPv4 narrowed (IPv6 not in /10)
								netip.MustParsePrefix("100.64.0.1/32"),
							},
							CapMap: tailcfg.PeerCapMap{
								"tailscale.com/cap/drive-sharer": nil,
							},
						},
					},
				},
			},
		},
		{
			name: "capgrant-no-match-filtered-out",
			node: &types.Node{
				IPv4: ap("100.64.0.1"),
				IPv6: ap("fd7a:115c:a1e0::1"),
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"10.0.0.0/8"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{
								// Different IP — doesn't match this node
								netip.MustParsePrefix("100.64.0.99/32"),
							},
							CapMap: tailcfg.PeerCapMap{
								"tailscale.com/cap/drive-sharer": nil,
							},
						},
					},
				},
			},
			want: []tailcfg.FilterRule{},
		},
		{
			name: "capgrant-with-subnet-route-overlap",
			node: &types.Node{
				IPv4: ap("100.64.0.1"),
				IPv6: ap("fd7a:115c:a1e0::1"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.33.0.0/16"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.33.0.0/16"),
				},
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"*"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{
								// Subnet route overlap
								netip.MustParsePrefix("10.0.0.0/8"),
							},
							CapMap: tailcfg.PeerCapMap{
								"tailscale.com/cap/relay-target": nil,
							},
						},
					},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"*"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{
								// 10.0.0.0/8 doesn't contain node's
								// CGNAT IP (100.64.0.1), so no IP
								// narrowing. Only route overlap kept
								// as original prefix.
								netip.MustParsePrefix("10.0.0.0/8"),
							},
							CapMap: tailcfg.PeerCapMap{
								"tailscale.com/cap/relay-target": nil,
							},
						},
					},
				},
			},
		},
		{
			name: "capgrant-exit-route-skipped",
			node: &types.Node{
				IPv4: ap("100.64.0.1"),
				IPv6: ap("fd7a:115c:a1e0::1"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: tsaddr.ExitRoutes(),
				},
				ApprovedRoutes: tsaddr.ExitRoutes(),
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"*"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{
								// 0.0.0.0/0 overlaps the exit route
								// but exit routes should be skipped
								netip.MustParsePrefix("0.0.0.0/0"),
							},
							CapMap: tailcfg.PeerCapMap{
								"tailscale.com/cap/drive-sharer": nil,
							},
						},
					},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"*"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{
								// Node IP narrowed (0.0.0.0/0
								// contains the node's IP)
								netip.MustParsePrefix("100.64.0.1/32"),
							},
							CapMap: tailcfg.PeerCapMap{
								"tailscale.com/cap/drive-sharer": nil,
							},
						},
					},
				},
			},
		},
		{
			name: "mixed-dstports-and-capgrant-rules",
			node: &types.Node{
				IPv4: ap("100.64.0.1"),
				IPv6: ap("fd7a:115c:a1e0::1"),
			},
			rules: []tailcfg.FilterRule{
				{
					// DstPorts rule that matches
					SrcIPs: []string{"10.0.0.0/8"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.1", Ports: tailcfg.PortRangeAny},
					},
				},
				{
					// CapGrant rule that matches
					SrcIPs: []string{"10.0.0.0/8"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{
								netip.MustParsePrefix("100.64.0.1/32"),
							},
							CapMap: tailcfg.PeerCapMap{
								"tailscale.com/cap/drive-sharer": nil,
							},
						},
					},
				},
				{
					// CapGrant rule that doesn't match
					SrcIPs: []string{"10.0.0.0/8"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{
								netip.MustParsePrefix("100.64.0.99/32"),
							},
							CapMap: tailcfg.PeerCapMap{
								"tailscale.com/cap/drive-sharer": nil,
							},
						},
					},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"10.0.0.0/8"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.1", Ports: tailcfg.PortRangeAny},
					},
				},
				{
					SrcIPs: []string{"10.0.0.0/8"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{
								netip.MustParsePrefix("100.64.0.1/32"),
							},
							CapMap: tailcfg.PeerCapMap{
								"tailscale.com/cap/drive-sharer": nil,
							},
						},
					},
				},
				// Third rule filtered out — doesn't match node
			},
		},
		{
			name: "capgrant-ipv4-only-node",
			node: &types.Node{
				IPv4: ap("100.64.0.1"),
				// IPv6 is nil, single-IP node
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"10.0.0.0/8"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{
								netip.MustParsePrefix("100.64.0.1/32"),
							},
							CapMap: tailcfg.PeerCapMap{
								"tailscale.com/cap/drive-sharer": nil,
							},
						},
					},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"10.0.0.0/8"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{
								netip.MustParsePrefix("100.64.0.1/32"),
							},
							CapMap: tailcfg.PeerCapMap{
								"tailscale.com/cap/drive-sharer": nil,
							},
						},
					},
				},
			},
		},
		{
			name: "capgrant-zero-ip-node-no-panic",
			node: &types.Node{
				// Both IPv4 and IPv6 are nil, zero IPs.
				// Must not panic.
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"10.0.0.0/8"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{
								netip.MustParsePrefix("100.64.0.1/32"),
							},
							CapMap: tailcfg.PeerCapMap{
								"tailscale.com/cap/drive-sharer": nil,
							},
						},
					},
				},
			},
			want: []tailcfg.FilterRule{},
		},
		{
			// A broad prefix that both contains the node IP (/32 narrow)
			// and overlaps one of its approved subnet routes (route
			// preserved) would otherwise be emitted twice.
			name: "capgrant-ip-and-route-overlap-dedup",
			node: &types.Node{
				IPv4: ap("100.64.0.1"),
				IPv6: ap("fd7a:115c:a1e0::1"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("100.64.0.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("100.64.0.0/24"),
				},
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"*"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{
								netip.MustParsePrefix("100.64.0.0/24"),
							},
							CapMap: tailcfg.PeerCapMap{
								"tailscale.com/cap/relay-target": nil,
							},
						},
					},
				},
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"*"},
					CapGrant: []tailcfg.CapGrant{
						{
							Dsts: []netip.Prefix{
								netip.MustParsePrefix("100.64.0.1/32"),
								netip.MustParsePrefix("100.64.0.0/24"),
							},
							CapMap: tailcfg.PeerCapMap{
								"tailscale.com/cap/relay-target": nil,
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policyutil.ReduceFilterRules(tt.node.View(), tt.rules)

			require.Len(t, got, len(tt.want),
				"rule count mismatch")

			for i := range tt.want {
				require.Equal(t, tt.want[i].SrcIPs, got[i].SrcIPs,
					"rule[%d] SrcIPs", i)
				require.Len(t, got[i].DstPorts, len(tt.want[i].DstPorts),
					"rule[%d] DstPorts count", i)
				require.Len(t, got[i].CapGrant, len(tt.want[i].CapGrant),
					"rule[%d] CapGrant count", i)

				for j := range tt.want[i].CapGrant {
					require.ElementsMatch(t,
						tt.want[i].CapGrant[j].Dsts,
						got[i].CapGrant[j].Dsts,
						"rule[%d].CapGrant[%d] Dsts", i, j,
					)
				}
			}
		})
	}
}

var reductionDestinationInputs = []string{
	"100.64.0.1",
	"100.64.0.1/32",
	"100.64.0.0/10",
	"100.64.0.1/24",
	"0.0.0.0",
	"0.0.0.0/0",
	"255.255.255.255/32",
	"100.64.0.0/0",
	"fd7a:115c:a1e0::1",
	"fd7a:115c:a1e0::1/128",
	"fd7a:115c:a1e0::/48",
	"fd7a:115c:a1e0::1/64",
	"::",
	"::1",
	"::/0",
	"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	"fe80::1%eth0",
	"fe80::1%eth-0",
	"fe80::1%eth--0",
	"fe80::1%1",
	"fe80::1%eth0/64",
	"::ffff:100.64.0.1",
	"::ffff:100.64.0.1/128",
	"::ffff:100.64.0.0/112",
	"::ffff:100.64.0.1/120",
	"100.64.0.0-100.64.0.2",
	"100.64.0.2-100.64.0.0",
	"fd7a:115c:a1e0::-fd7a:115c:a1e0::2",
	"fe80::1%eth0-fe80::2%eth0",
	"100.64.0.1-fd7a:115c:a1e0::1",
	"100.64.0.1-100.64.0.1",
	"10.0.0.0/8",
	"10.0.0.0/16",
	"10.0.0.0/25",
	"10.0.0.128/25",
	"10.0.1.0/24",
	"192.0.2.0/24",
	"fd00::/8",
	"fd00:1::/48",
	"fd00:1::/65",
	"*",
	"",
	" ",
	" 100.64.0.1",
	"100.64.0.1\n",
	"[::1]",
	"100.64.0.1:80",
	"100.064.0.1",
	"100.64.0.0/024",
	"100.64.0.1/",
	"/0",
	"bad/24",
	"0.0.0.0/33",
	"::/129",
	"100.64.0.1--100.64.0.2",
	"not-an-ip",
}

func assertReductionMatchesReference(
	t *testing.T,
	node types.NodeView,
	rules []tailcfg.FilterRule,
) {
	t.Helper()

	before := must.Get(json.Marshal(rules))
	nodeBefore := node.AsStruct()
	want := reduceFilterRulesReference(node, rules)

	got := policyutil.ReduceFilterRules(node, rules)
	if diff := cmp.Diff(
		semanticRulesReference(t, want),
		semanticRulesReference(t,
			got),
		cmpopts.EquateComparable(netip.Prefix{}),
	); diff != "" {
		t.Fatalf("reduction differs from frozen reference (-want +got):\n%s", diff)
	}

	require.Equal(t, before, must.Get(json.Marshal(rules)), "rules must not be mutated")
	require.Equal(t, nodeBefore, node.AsStruct(), "node must not be mutated")
}

func TestReduceFilterRulesReference(t *testing.T) {
	routes := []netip.Prefix{p("10.0.0.128/25"), p("10.0.1.0/24"), p("fd00:1::/64")}
	tests := []struct {
		name string
		node *types.Node
	}{
		{name: "invalid-view"},
		{name: "no-ips", node: &types.Node{}},
		{
			name: "invalid-ips",
			node: &types.Node{IPv4: new(netip.Addr), IPv6: new(netip.Addr)},
		},
		{name: "ipv4", node: &types.Node{IPv4: ap("100.64.0.1")}},
		{name: "ipv6", node: &types.Node{IPv6: ap("fd7a:115c:a1e0::1")}},
		{
			name: "dual-stack",
			node: &types.Node{IPv4: ap("100.64.0.1"), IPv6: ap("fd7a:115c:a1e0::1")},
		},
		{name: "link-local", node: &types.Node{IPv6: ap("fe80::1")}},
		{name: "zoned-node", node: &types.Node{IPv6: ap("fe80::1%eth0")}},
		{name: "mapped-ipv6", node: &types.Node{IPv6: ap("::ffff:100.64.0.1")}},
		{name: "mapped-approved-subnet", node: &types.Node{
			Hostinfo: &tailcfg.Hostinfo{
				RoutableIPs: []netip.Prefix{p("::ffff:100.64.0.0/120")},
			},
			ApprovedRoutes: []netip.Prefix{p("::ffff:100.64.0.0/120")},
		}},
		{name: "approved-subnets", node: &types.Node{
			Hostinfo: &tailcfg.Hostinfo{RoutableIPs: routes}, ApprovedRoutes: routes,
		}},
		{name: "partial-approval", node: &types.Node{
			Hostinfo: &tailcfg.Hostinfo{
				RoutableIPs: routes,
			},
			ApprovedRoutes: routes[:1],
		}},
		{
			name: "unapproved",
			node: &types.Node{Hostinfo: &tailcfg.Hostinfo{RoutableIPs: routes}},
		},
		{name: "not-announced", node: &types.Node{ApprovedRoutes: routes}},
		{name: "ipv4-exit", node: &types.Node{
			Hostinfo: &tailcfg.Hostinfo{
				RoutableIPs: []netip.Prefix{tsaddr.AllIPv4()},
			},
			ApprovedRoutes: []netip.Prefix{tsaddr.AllIPv4()},
		}},
		{name: "ipv6-exit", node: &types.Node{
			Hostinfo: &tailcfg.Hostinfo{
				RoutableIPs: []netip.Prefix{tsaddr.AllIPv6()},
			},
			ApprovedRoutes: []netip.Prefix{tsaddr.AllIPv6()},
		}},
		{name: "unapproved-exit", node: &types.Node{
			Hostinfo: &tailcfg.Hostinfo{
				RoutableIPs: []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6()},
			},
		}},
	}

	dests := make([]tailcfg.NetPortRange, 0, len(reductionDestinationInputs)+2)
	for i, ip := range reductionDestinationInputs {
		dests = append(dests, tailcfg.NetPortRange{
			IP:   ip,
			Bits: new(24),
			Ports: tailcfg.PortRange{
				First: uint16(i),
				Last:  uint16(i + 10),
			}, //nolint:gosec // bounded fixture
		})
	}

	// Repeated destinations retain their original position, ports, and metadata.
	dests = append(
		dests,
		dests[0],
		tailcfg.NetPortRange{IP: dests[0].IP, Ports: tailcfg.PortRangeAny},
	)
	ordinary := tailcfg.FilterRule{
		SrcIPs: []string{
			"*",
			"100.64.0.2",
		},
		SrcBits:  []int{0, 32},
		IPProto:  []int{6, 17, 1},
		DstPorts: dests,
		CapGrant: []tailcfg.CapGrant{},
	}
	capRule := ordinary
	capRule.CapGrant = []tailcfg.CapGrant{
		{
			Dsts: []netip.Prefix{
				p("::/0"),
				p("100.64.0.0/10"),
				p("10.0.0.0/8"),
				p("10.0.0.0/8"),
			},
			Caps: []peercap.Cap{"test/legacy"},
			CapMap: tailcfg.PeerCapMap{
				"test/nil":   nil,
				"test/empty": {},
				"test/value": {tailcfg.RawMessage(`{"value":1}`)},
			},
		},
		{Dsts: []netip.Prefix{p("100.64.0.1/32")}, CapMap: tailcfg.PeerCapMap{}},
	}
	capOnly := capRule
	capOnly.DstPorts = nil
	rules := []tailcfg.FilterRule{
		ordinary,
		{},
		capOnly,
		capRule,
		{DstPorts: []tailcfg.NetPortRange{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertReductionMatchesReference(t, tt.node.View(), nil)
			assertReductionMatchesReference(t, tt.node.View(), []tailcfg.FilterRule{})
			assertReductionMatchesReference(t, tt.node.View(), rules)
		})
	}
}

//nolint:gosec // Deterministic, bounded differential-test inputs.
func TestReduceFilterRulesReferenceRandomized(t *testing.T) {
	rng := rand.New(rand.NewPCG(0, 0))
	ips := []string{
		"100.64.0.1",
		"100.64.0.2",
		"0.0.0.0",
		"fd7a:115c:a1e0::1",
		"fe80::1",
		"fe80::1%eth0",
		"::ffff:100.64.0.1",
	}
	prefixes := []netip.Prefix{
		{},
		p("10.0.0.1/24"), p("10.0.0.128/25"), p("10.0.1.0/24"), p("100.64.0.0/24"),
		p("fd7a:115c:a1e0::/48"), p("fd00:1::/64"), tsaddr.AllIPv4(), tsaddr.AllIPv6(),
	}

	for iteration := range 1000 {
		t.Run(strconv.Itoa(iteration), func(t *testing.T) {
			var raw [16]byte
			for i := range raw {
				raw[i] = byte(rng.IntN(256))
			}

			ip4 := netip.AddrFrom4([4]byte{raw[0], raw[1], raw[2], raw[3]})
			ip6 := netip.AddrFrom16(raw)
			prefix4 := netip.PrefixFrom(ip4, rng.IntN(33))
			prefix6 := netip.PrefixFrom(ip6, rng.IntN(129))
			ipCandidates := append(slices.Clone(ips), ip4.String(), ip6.String())
			routeCandidates := append(
				slices.Clone(prefixes),
				prefix4,
				prefix4.Masked(),
				prefix6,
				prefix6.Masked(),
			)
			destCandidates := append(
				slices.Clone(reductionDestinationInputs),
				ip4.String(),
				ip6.String(),
				prefix4.String(),
				prefix4.Masked().String(),
				prefix6.String(),
				prefix6.Masked().String(),
			)

			node := &types.Node{}
			if rng.IntN(4) != 0 {
				node.IPv4 = ap(ipCandidates[rng.IntN(len(ipCandidates))])
			}

			if rng.IntN(4) != 0 {
				node.IPv6 = ap(ipCandidates[rng.IntN(len(ipCandidates))])
			}

			if rng.IntN(4) != 0 {
				node.Hostinfo = &tailcfg.Hostinfo{}
				for range rng.IntN(12) {
					node.Hostinfo.RoutableIPs = append(
						node.Hostinfo.RoutableIPs,
						routeCandidates[rng.IntN(len(routeCandidates))],
					)
				}
			}

			for range rng.IntN(12) {
				node.ApprovedRoutes = append(
					node.ApprovedRoutes,
					routeCandidates[rng.IntN(len(routeCandidates))],
				)
			}

			rules := make([]tailcfg.FilterRule, rng.IntN(12))
			for i := range rules {
				rule := &rules[i]
				rule.SrcIPs = [][]string{nil, {}, {"*", "100.64.0.2"}}[rng.IntN(3)]
				rule.SrcBits = [][]int{nil, {}, {0, 32}}[rng.IntN(3)]

				rule.IPProto = [][]int{nil, {}, {1, 6, 17}, {-1, 300}}[rng.IntN(4)]
				if rng.IntN(2) == 0 {
					rule.DstPorts = []tailcfg.NetPortRange{}
				}

				for range rng.IntN(12) {
					ip := destCandidates[rng.IntN(len(destCandidates))]
					if rng.IntN(8) == 0 {
						ip += string(rune(rng.IntN(128)))
					}

					dest := tailcfg.NetPortRange{IP: ip, Ports: tailcfg.PortRange{
						First: uint16(
							rng.IntN(65536),
						),
						Last: uint16(
							rng.IntN(65536),
						), //nolint:gosec // bounded generator
					}}
					if rng.IntN(2) == 0 {
						dest.Bits = new(rng.IntN(150) - 10)
					}

					rule.DstPorts = append(rule.DstPorts, dest)
				}

				if rng.IntN(2) == 0 {
					rule.CapGrant = []tailcfg.CapGrant{}
				}

				if rng.IntN(3) == 0 {
					for range rng.IntN(4) {
						cg := tailcfg.CapGrant{Caps: []peercap.Cap{"test/legacy"}}
						for range rng.IntN(8) {
							cg.Dsts = append(
								cg.Dsts,
								routeCandidates[rng.IntN(len(routeCandidates))],
							)
						}

						cg.CapMap = []tailcfg.PeerCapMap{nil, {}, {"test/nil": nil, "test/empty": {}, "test/value": {"true"}}}[rng.IntN(3)]
						rule.CapGrant = append(rule.CapGrant, cg)
					}
				}
			}

			assertReductionMatchesReference(t, node.View(), rules)
		})
	}
}

type reductionBenchmarkFixture struct {
	name  string
	node  types.NodeView
	rules []tailcfg.FilterRule
}

func reductionBenchmarkFixtures() []reductionBenchmarkFixture {
	var fixtures []reductionBenchmarkFixture

	plain := &types.Node{IPv4: ap("100.64.0.1"), IPv6: ap("fd7a:115c:a1e0::1")}
	router := plain.Clone()

	router.Hostinfo = &tailcfg.Hostinfo{}
	for i := range 64 {
		router.Hostinfo.RoutableIPs = append(
			router.Hostinfo.RoutableIPs,
			p(fmt.Sprintf("10.%d.0.0/16", i)),
		)
	}

	router.ApprovedRoutes = router.Hostinfo.RoutableIPs
	exit := plain.Clone()
	exit.Hostinfo = &tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6()},
	}
	exit.ApprovedRoutes = exit.Hostinfo.RoutableIPs
	matching := []string{
		"100.64.0.1", "100.64.0.0/10",
		"fd7a:115c:a1e0::1", "fd7a:115c:a1e0::/48",
	}
	fallback := []string{
		"*", "100.64.0.0-100.64.0.2",
		"fd7a:115c:a1e0::-fd7a:115c:a1e0::2", "192.0.2.0-192.0.2.255",
	}
	capDsts := []netip.Prefix{
		p("100.64.0.0/10"), p("fd7a:115c:a1e0::/48"), p("192.0.2.0/24"),
	}
	capMap := tailcfg.PeerCapMap{"test/cap": nil}

	for _, workload := range []struct {
		name string
		node *types.Node
	}{
		{"plain", plain},
		{"route-heavy", router},
		{"exit", exit},
		{"matching-dense", plain},
		{"fallback", plain},
		{"capgrant-only", plain},
	} {
		for _, unique := range []bool{false, true} {
			if unique && slices.Contains(
				[]string{"matching-dense", "fallback", "capgrant-only"}, workload.name,
			) {
				continue
			}

			for _, count := range []int{0, 1, 256, 4096} {
				var rules []tailcfg.FilterRule

				for i := range count {
					if i%16 == 0 {
						rules = append(rules, tailcfg.FilterRule{SrcIPs: []string{"*"}})
					}

					n := i
					if !unique {
						n %= 4
					}

					ip := []string{
						fmt.Sprintf("100.64.%d.%d", n/256, n%256),
						fmt.Sprintf("10.%d.%d.0/24", n%64, n/64),
						fmt.Sprintf("fd00:%x::1", n),
						fmt.Sprintf("fd00:%x::/64", n),
					}[i%4]
					// The one-destination case measures an immediate node-IP match.
					if count == 1 {
						ip = "100.64.0.1"
					}

					switch workload.name {
					case "matching-dense":
						ip = matching[i%len(matching)]
					case "fallback":
						ip = fallback[i%len(fallback)]
					}

					last := &rules[len(rules)-1]
					if workload.name == "capgrant-only" {
						last.CapGrant = append(last.CapGrant, tailcfg.CapGrant{
							Dsts: capDsts, CapMap: capMap,
						})
					} else {
						last.DstPorts = append(
							last.DstPorts,
							tailcfg.NetPortRange{IP: ip, Ports: tailcfg.PortRangeAny},
						)
					}
				}

				fixtures = append(fixtures, reductionBenchmarkFixture{
					name: fmt.Sprintf("%s/unique=%t/dests=%d", workload.name, unique, count),
					node: workload.node.View(), rules: rules,
				})
			}
		}
	}

	return fixtures
}

// Archived wire reducers are diagnostics, not the production typed reducer.
func BenchmarkArchivedWireReduction(b *testing.B) {
	for _, fixture := range reductionBenchmarkFixtures() {
		want := reduceFilterRulesReference(fixture.node, fixture.rules)
		for _, impl := range []struct {
			name string
			run  func(types.NodeView, []tailcfg.FilterRule) []tailcfg.FilterRule
		}{
			{"frozen-reference", reduceFilterRulesReference},
			{"archived-optimized", policyutil.ReduceFilterRules},
		} {
			b.Run(fixture.name+"/"+impl.name, func(b *testing.B) {
				require.Empty(b, cmp.Diff(want, impl.run(fixture.node, fixture.rules),
					cmpopts.EquateComparable(netip.Prefix{})))
				b.ReportAllocs()

				for b.Loop() {
					impl.run(fixture.node, fixture.rules)
				}
			})
		}
	}
}

func BenchmarkPacketFilterReduce(b *testing.B) {
	for _, fixture := range reductionBenchmarkFixtures() {
		b.Run(fixture.name, func(b *testing.B) {
			rules := policyutil.TypedRulesForTest(fixture.rules)
			require.Equal(b, semanticRulesReference(b, fixture.rules),
				semanticRulesReference(b, packetfilter.ToTailcfg(rules)))
			target := packetfilter.Target{
				IPv4: fixture.node.IPv4().Clone(), IPv6: fixture.node.IPv6().Clone(),
				SubnetRoutes: fixture.node.SubnetRoutes(), ExitRoutes: fixture.node.ExitRoutes(),
			}
			want := reduceFilterRulesReference(fixture.node, fixture.rules)
			require.Equal(b, semanticRulesReference(b, want),
				semanticRulesReference(b, packetfilter.ToTailcfg(packetfilter.Reduce(rules, target))))
			b.ReportAllocs()

			for b.Loop() {
				packetfilter.Reduce(rules, target)
			}
		})
	}
}

// Frozen pre-optimization reducers: keep independent for exact comparisons and benchmarks.
func reduceFilterRulesReference(node types.NodeView, rules []tailcfg.FilterRule,
) []tailcfg.FilterRule {
	ret := []tailcfg.FilterRule{}
	subnetRoutes := node.SubnetRoutes()
	exitRoutes := node.ExitRoutes()

	for _, rule := range rules {
		// Handle CapGrant rules separately — they use CapGrant[].Dsts
		// instead of DstPorts for destination matching.
		if len(rule.CapGrant) > 0 {
			reduced := reduceCapGrantRuleReference(node, rule)
			if reduced != nil {
				ret = append(ret, *reduced)
			}

			continue
		}

		// record if the rule is actually relevant for the given node.
		var dests []tailcfg.NetPortRange

		for _, dest := range rule.DstPorts {
			expanded, err := parseIPSetReference(dest.IP, nil)
			// Fail closed: unparseable dests are dropped.
			if err != nil {
				continue
			}

			if nodeInIPSetReference(node, expanded) {
				dests = append(dests, dest)
				continue
			}

			// If the node has approved subnet routes, preserve
			// filter rules targeting those routes.
			// [types.NodeView.SubnetRoutes] returns only approved,
			// non-exit routes — matching Tailscale SaaS behavior,
			// which does not generate filter rules for
			// advertised-but-unapproved routes.
			if slices.ContainsFunc(subnetRoutes, expanded.OverlapsPrefix) {
				dests = append(dests, dest)
				continue
			}

			// Approved exit routes count like subnet routes. They
			// contain every destination, so Tailscale SaaS sends an
			// exit node every rule, not only internet ones.
			if slices.ContainsFunc(exitRoutes, expanded.OverlapsPrefix) {
				dests = append(dests, dest)
			}
		}

		if len(dests) > 0 {
			// Struct-copy preserves any unknown future FilterRule
			// fields.
			out := rule
			out.DstPorts = dests
			ret = append(ret, out)
		}
	}

	return ret
}

// reduceCapGrantRuleReference filters a [tailcfg.CapGrant] rule to only include
// [tailcfg.CapGrant] entries whose Dsts match the given node's IPs. When a
// broad prefix (e.g. 100.64.0.0/10 from dst:*) contains a node's IP, it is
// narrowed to the node's specific /32 or /128 prefix. Returns nil if
// no [tailcfg.CapGrant] entries are relevant to this node.
func reduceCapGrantRuleReference(
	node types.NodeView,
	rule tailcfg.FilterRule,
) *tailcfg.FilterRule {
	var capGrants []tailcfg.CapGrant

	var nodeIPs []netip.Addr

	if node.Valid() {
		if ip, ok := node.IPv4().GetOk(); ok {
			nodeIPs = append(nodeIPs, ip)
		}

		if ip, ok := node.IPv6().GetOk(); ok {
			nodeIPs = append(nodeIPs, ip)
		}
	}

	subnetRoutes := node.SubnetRoutes()

	for _, cg := range rule.CapGrant {
		// Collect the node's IPs that fall within any of this
		// CapGrant's Dsts. Broad prefixes are narrowed to specific
		// /32 and /128 entries for the node.
		var matchingDsts []netip.Prefix

		for _, dst := range cg.Dsts {
			if dst.IsSingleIP() {
				// Already a specific IP — keep it if it matches
				// any of the node's IPs.
				if slices.Contains(nodeIPs, dst.Addr()) {
					matchingDsts = append(matchingDsts, dst)
				}
			} else {
				// Broad prefix — narrow to node's specific IPs.
				for _, ip := range nodeIPs {
					if dst.Contains(ip) {
						matchingDsts = append(matchingDsts, netip.PrefixFrom(ip, ip.BitLen()))
					}
				}
			}
		}

		// Asymmetric on purpose: the IP-match loop above narrows broad
		// prefixes to node-specific /32 or /128 so peers receive only
		// the minimum routing surface. The route-match loop below
		// preserves the original prefix so the subnet-serving node
		// receives the full CapGrant scope. [types.NodeView.SubnetRoutes]
		// excludes both unapproved and exit routes, matching Tailscale
		// SaaS behavior.
		for _, dst := range cg.Dsts {
			for _, subnetRoute := range subnetRoutes {
				if dst.Overlaps(subnetRoute) {
					// For route overlaps, keep the original prefix.
					matchingDsts = append(matchingDsts, dst)
				}
			}
		}

		if len(matchingDsts) > 0 {
			// A Dst can be appended twice when a broad prefix both
			// contains a node IP and overlaps one of its approved
			// subnet routes. Sort + Compact dedups; [netip.Prefix] is
			// comparable so Compact works with ==.
			slices.SortFunc(matchingDsts, netip.Prefix.Compare)
			matchingDsts = slices.Compact(matchingDsts)

			capGrants = append(capGrants, tailcfg.CapGrant{
				Dsts:   matchingDsts,
				CapMap: cg.CapMap,
			})
		}
	}

	if len(capGrants) == 0 {
		return nil
	}

	return &tailcfg.FilterRule{
		SrcIPs:   rule.SrcIPs,
		CapGrant: capGrants,
	}
}

// parseIPSetReference freezes util.ParseIPSet from 425f21263. Keep netipx's
// mapped-family and zone behavior independent of production address changes.
//
//nolint:err113,gosec // Preserve the legacy parser as an independent oracle.
func parseIPSetReference(arg string, bits *int) (*netipx.IPSet, error) {
	var ipSet netipx.IPSetBuilder
	if arg == "*" {
		ipSet.AddPrefix(netip.PrefixFrom(netip.IPv4Unspecified(), 0))
		ipSet.AddPrefix(netip.PrefixFrom(netip.IPv6Unspecified(), 0))

		return ipSet.IPSet()
	}

	if strings.Contains(arg, "/") {
		pfx, err := netip.ParsePrefix(arg)
		if err != nil {
			return nil, err
		}

		if pfx != pfx.Masked() {
			return nil, fmt.Errorf("%v contains non-network bits set", pfx)
		}

		ipSet.AddPrefix(pfx)

		return ipSet.IPSet()
	}

	if strings.Count(arg, "-") == 1 {
		ip1s, ip2s, _ := strings.Cut(arg, "-")

		ip1, err := netip.ParseAddr(ip1s)
		if err != nil {
			return nil, err
		}

		ip2, err := netip.ParseAddr(ip2s)
		if err != nil {
			return nil, err
		}

		r := netipx.IPRangeFrom(ip1, ip2)
		if !r.IsValid() {
			return nil, fmt.Errorf("invalid IP range %q", arg)
		}

		for _, prefix := range r.Prefixes() {
			ipSet.AddPrefix(prefix)
		}

		return ipSet.IPSet()
	}

	ip, err := netip.ParseAddr(arg)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address %q", arg)
	}

	bits8 := uint8(ip.BitLen())
	if bits != nil {
		if *bits < 0 || *bits > int(bits8) {
			return nil, fmt.Errorf("invalid CIDR size %d for IP %q", *bits, arg)
		}

		bits8 = uint8(*bits)
	}

	ipSet.AddPrefix(netip.PrefixFrom(ip, int(bits8)))

	return ipSet.IPSet()
}

// nodeInIPSetReference reads stored addresses without production membership helpers.
func nodeInIPSetReference(node types.NodeView, set *netipx.IPSet) bool {
	if !node.Valid() {
		return false
	}

	if ip, ok := node.IPv4().GetOk(); ok && set.Contains(ip) {
		return true
	}

	if ip, ok := node.IPv6().GetOk(); ok && set.Contains(ip) {
		return true
	}

	return false
}

func TestParseIPSetReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		bits    *int
		want    []string
		wantErr bool
	}{
		{name: "wildcard", input: "*", want: []string{"0.0.0.0/0", "::/0"}},
		{name: "ipv4", input: "100.64.0.1", want: []string{"100.64.0.1/32"}},
		{name: "ipv6", input: "fd00::1", want: []string{"fd00::1/128"}},
		{name: "prefix", input: "10.0.0.0/24", want: []string{"10.0.0.0/24"}},
		{name: "host-bits", input: "10.0.0.1/24", wantErr: true},
		{name: "ipv6-host-bits", input: "fd00::1/64", wantErr: true},
		{
			name:  "range",
			input: "10.0.0.1-10.0.0.3",
			want:  []string{"10.0.0.1/32", "10.0.0.2/31"},
		},
		{
			name:  "ipv6-range",
			input: "fd00::1-fd00::3",
			want:  []string{"fd00::1/128", "fd00::2/127"},
		},
		{name: "reversed-range", input: "10.0.0.3-10.0.0.1", wantErr: true},
		{name: "mixed-range", input: "10.0.0.1-fd00::1", wantErr: true},
		{name: "zone-stripped", input: "fe80::1%eth0", want: []string{"fe80::1/128"}},
		{
			name:  "zone-range",
			input: "fe80::1%eth0-fe80::2%eth0",
			want:  []string{"fe80::1/128", "fe80::2/128"},
		},
		{name: "zone-single-hyphen", input: "fe80::1%eth-0", wantErr: true},
		{
			name:  "zone-two-hyphens",
			input: "fe80::1%eth--0",
			want:  []string{"fe80::1/128"},
		},
		{name: "zone-prefix", input: "fe80::1%eth0/64", wantErr: true},
		{
			name:  "mapped-host",
			input: "::ffff:100.64.0.1",
			want:  []string{"::ffff:100.64.0.1/128"},
		},
		{
			name:  "mapped-prefix",
			input: "::ffff:100.64.0.0/112",
			want:  []string{"::ffff:100.64.0.0/112"},
		},
		{name: "mapped-host-bits", input: "::ffff:100.64.0.1/120", wantErr: true},
		{
			name:  "source-bits-mask-host",
			input: "100.64.0.1",
			bits:  new(24),
			want:  []string{"100.64.0.0/24"},
		},
		{
			name:  "source-bits-zero",
			input: "100.64.0.1",
			bits:  new(0),
			want:  []string{"0.0.0.0/0"},
		},
		{
			name:  "source-bits-ipv6",
			input: "fd00::1",
			bits:  new(64),
			want:  []string{"fd00::/64"},
		},
		{
			name:  "source-bits-mapped",
			input: "::ffff:100.64.0.1",
			bits:  new(120),
			want:  []string{"::ffff:100.64.0.0/120"},
		},
		{
			name:    "source-bits-negative",
			input:   "100.64.0.1",
			bits:    new(-1),
			wantErr: true,
		},
		{
			name:    "source-bits-too-large",
			input:   "100.64.0.1",
			bits:    new(33),
			wantErr: true,
		},
		{
			name:    "source-bits-ipv6-too-large",
			input:   "fd00::1",
			bits:    new(129),
			wantErr: true,
		},
		{
			name:  "wildcard-ignores-bits",
			input: "*",
			bits:  new(-1),
			want:  []string{"0.0.0.0/0", "::/0"},
		},
		{
			name:  "prefix-ignores-bits",
			input: "10.0.0.0/24",
			bits:  new(-1),
			want:  []string{"10.0.0.0/24"},
		},
		{
			name:  "range-ignores-bits",
			input: "10.0.0.1-10.0.0.1",
			bits:  new(-1),
			want:  []string{"10.0.0.1/32"},
		},
		{name: "empty", input: "", wantErr: true},
		{name: "whitespace", input: " 100.64.0.1", wantErr: true},
		{name: "malformed", input: "not-an-ip", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseIPSetReference(tt.input, tt.bits)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			var prefixes []string
			for _, prefix := range got.Prefixes() {
				prefixes = append(prefixes, prefix.String())
			}

			require.Equal(t, tt.want, prefixes)
		})
	}
}

func TestNodeInIPSetReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		node   *types.Node
		prefix string
		want   bool
	}{
		{name: "invalid-view", prefix: "0.0.0.0/0"},
		{name: "unallocated", node: &types.Node{}, prefix: "0.0.0.0/0"},
		{
			name:   "invalid-address",
			node:   &types.Node{IPv4: new(netip.Addr)},
			prefix: "0.0.0.0/0",
		},
		{
			name:   "ipv4",
			node:   &types.Node{IPv4: ap("100.64.0.1")},
			prefix: "100.64.0.0/24",
			want:   true,
		},
		{
			name:   "ipv6",
			node:   &types.Node{IPv6: ap("fd00::1")},
			prefix: "fd00::/64",
			want:   true,
		},
		{
			name:   "dual-stack",
			node:   &types.Node{IPv4: ap("100.64.0.1"), IPv6: ap("fd00::1")},
			prefix: "fd00::/64",
			want:   true,
		},
		{
			name:   "unmatched",
			node:   &types.Node{IPv4: ap("100.64.0.1")},
			prefix: "10.0.0.0/8",
		},
		{
			name:   "zoned-stays-zoned",
			node:   &types.Node{IPv6: ap("fe80::1%eth0")},
			prefix: "fe80::/64",
		},
		{
			name:   "mapped-stays-mapped",
			node:   &types.Node{IPv6: ap("::ffff:100.64.0.1")},
			prefix: "100.64.0.0/24",
		},
		{
			name:   "native-stays-native",
			node:   &types.Node{IPv4: ap("100.64.0.1")},
			prefix: "::ffff:100.64.0.0/120",
		},
		{
			name:   "mapped-matches-mapped",
			node:   &types.Node{IPv6: ap("::ffff:100.64.0.1")},
			prefix: "::ffff:100.64.0.0/120",
			want:   true,
		},
		{
			name:   "stored-address-family",
			node:   &types.Node{IPv4: ap("fd00::1")},
			prefix: "fd00::/64",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var builder netipx.IPSetBuilder
			builder.AddPrefix(netip.MustParsePrefix(tt.prefix))
			set, err := builder.IPSet()
			require.NoError(t, err)

			require.Equal(t, tt.want, nodeInIPSetReference(tt.node.View(), set))
		})
	}
}

func TestTypedAddressBoundaryMatchesReference(t *testing.T) {
	for _, input := range []string{
		"*", "100.64.0.1", "fd00::1", "10.0.0.0/24", "10.0.0.1/24",
		"10.0.0.1-10.0.0.3", "fd00::1-fd00::3", "10.0.0.3-10.0.0.1",
		"10.0.0.1-fd00::1", "fe80::1%eth0", "fe80::1%eth0-fe80::2%eth1",
		"fe80::1%eth-0", "fe80::1%eth--0", "fe80::1%eth0/64",
		"::ffff:100.64.0.1", "::ffff:100.64.0.0/112", "::ffff:100.64.0.1/120",
		"255.255.255.255", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "invalid", "",
	} {
		for _, bits := range []*int{nil, new(-1), new(0), new(24), new(32), new(64), new(128), new(129)} {
			want, wantErr := parseIPSetReference(input, bits)
			got, gotErr := util.ParseIPSet(input, bits)
			require.Equal(t, fmt.Sprint(wantErr), fmt.Sprint(gotErr), "input %q, bits %v", input, bits)

			if wantErr != nil {
				continue
			}

			require.Equal(t, want.Prefixes(), slices.Collect(got.Prefixes()), input)

			for _, address := range []string{"100.64.0.1", "::ffff:100.64.0.1", "fe80::1", "fe80::1%eth0", "fd00::1"} {
				node := types.Node{IPv4: new(netip.MustParseAddr(address)), IPv6: new(netip.MustParseAddr("fd00::2"))}
				require.Equal(t, nodeInIPSetReference(node.View(), want), node.InIPSet(got), input)
				require.Equal(t, nodeInIPSetReference(node.View(), want), node.View().InIPSet(got), input)
			}
		}
	}
}

// semanticRulesReference retains source/protocol/port/capability associations.
// Its parser and union operations are independent netipx implementations.
func sourcePrefixesReference(tb testing.TB, rule tailcfg.FilterRule) []netip.Prefix {
	tb.Helper()

	var builder netipx.IPSetBuilder

	for i, raw := range rule.SrcIPs {
		var bits *int
		if i < len(rule.SrcBits) {
			bits = &rule.SrcBits[i]
		}

		set, err := parseIPSetReference(raw, bits)
		if err == nil {
			builder.AddSet(set)
		}
	}

	set, err := builder.IPSet()
	require.NoError(tb, err)

	return set.Prefixes()
}

func semanticRulesReference(
	tb testing.TB,
	rules []tailcfg.FilterRule,
) map[string][]string {
	tb.Helper()

	buckets := make(map[string]*netipx.IPSetBuilder)

	for _, rule := range rules {
		protocols := slices.Clone(rule.IPProto)
		if len(protocols) == 0 {
			protocols = []int{1, 6, 17, 58}
		}

		slices.Sort(protocols)
		protocols = slices.Compact(protocols)

		base := fmt.Sprintf("%v/%v", sourcePrefixesReference(tb, rule), protocols)
		for _, destination := range rule.DstPorts {
			set, err := parseIPSetReference(destination.IP, nil)
			if err != nil {
				continue
			}

			key := fmt.Sprintf(
				"%s/network/%d/%d",
				base,
				destination.Ports.First,
				destination.Ports.Last,
			)
			if buckets[key] == nil {
				buckets[key] = new(netipx.IPSetBuilder)
			}

			buckets[key].AddSet(set)
		}

		for _, grant := range rule.CapGrant {
			payload, err := json.Marshal(struct {
				Caps   []peercap.Cap
				CapMap tailcfg.PeerCapMap
			}{grant.Caps, grant.CapMap})
			require.NoError(tb, err)

			key := base + "/capability/" + string(payload)
			if buckets[key] == nil {
				buckets[key] = new(netipx.IPSetBuilder)
			}

			for _, prefix := range grant.Dsts {
				buckets[key].AddPrefix(prefix)
			}
		}
	}

	result := make(map[string][]string, len(buckets))
	for key, builder := range buckets {
		set, err := builder.IPSet()
		require.NoError(tb, err)

		for _, prefix := range set.Prefixes() {
			result[key] = append(result[key], prefix.String())
		}
	}

	return result
}

// Typed inputs have validated protocols and canonical capability address unions.
// The archived randomized wire proof above still covers malformed legacy fields.
func TestTypedReductionMatchesFrozenOracle(t *testing.T) {
	nodes := []types.NodeView{
		(&types.Node{IPv4: mustIPPtr("100.64.0.1"), IPv6: mustIPPtr("fd7a:115c:a1e0::1")}).View(),
		(&types.Node{IPv4: mustIPPtr("100.64.0.2"), Hostinfo: &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}, ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}).View(),
		(&types.Node{IPv4: mustIPPtr("100.64.0.3"), Hostinfo: &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}, ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}).View(),
	}

	for _, source := range []string{"100.64.0.1", "100.64.0.0/24", "*"} {
		for _, destination := range []string{"100.64.0.1", "fd7a:115c:a1e0::1", "10.0.0.0/16", "10.0.0.0/25", "*", "100.64.0.1-100.64.0.3"} {
			for _, protocols := range [][]int{nil, {6}, {17}, {47}, {132}} {
				wire := []tailcfg.FilterRule{
					{
						SrcIPs: []string{source},
						DstPorts: []tailcfg.NetPortRange{
							{
								IP:    destination,
								Ports: tailcfg.PortRange{First: 22, Last: 443},
							},
							{
								IP:    "100.64.0.99",
								Ports: tailcfg.PortRange{First: 53, Last: 53},
							},
						},
						IPProto: protocols,
					},
				}
				for _, node := range nodes {
					want := reduceFilterRulesReference(node, wire)
					got := policyutil.ReduceTypedRules(node, wire)
					require.Equal(
						t,
						semanticRulesReference(t, want),
						semanticRulesReference(t, got),
						"%s to %s protocols %v",
						source,
						destination,
						protocols,
					)
				}
			}
		}
	}

	for _, prefix := range []string{"100.64.0.0/24", "10.0.0.0/16", "fd7a:115c:a1e0::/48"} {
		wire := []tailcfg.FilterRule{
			{
				SrcIPs: []string{"100.64.0.1"},
				CapGrant: []tailcfg.CapGrant{
					{
						Dsts: []netip.Prefix{netip.MustParsePrefix(prefix)},
						CapMap: tailcfg.PeerCapMap{
							"example.com/cap": {tailcfg.RawMessage(`{"role":"read"}`)},
						},
					},
				},
			},
		}
		for _, node := range nodes {
			want := reduceFilterRulesReference(node, wire)
			got := policyutil.ReduceTypedRules(node, wire)
			require.Equal(
				t,
				semanticRulesReference(t, want),
				semanticRulesReference(t, got),
			)
		}
	}
}

func mustIPPtr(
	raw string,
) *netip.Addr {
	address := netip.MustParseAddr(raw)
	return &address
}
