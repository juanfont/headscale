package v2

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
)

func TestRouteRanges(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("2001:db8::2/128"),
		netip.MustParsePrefix("10.0.0.1/32"),
		{},
		netip.MustParsePrefix("10.0.0.0/31"),
		netip.MustParsePrefix("2001:db8::1/128"),
		netip.MustParsePrefix("10.0.0.1/32"),
	}
	before := slices.Clone(prefixes)
	want := []netipx.IPRange{
		netipx.IPRangeFrom(
			netip.MustParseAddr("10.0.0.0"), netip.MustParseAddr("10.0.0.1")),
		netipx.IPRangeFrom(
			netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")),
	}

	require.Equal(t, want, types.RouteRanges(prefixes))
	require.Equal(t, before, prefixes)
	require.Empty(t, types.RouteRanges(nil))
	require.Empty(t, types.RouteRanges([]netip.Prefix{{}}))
}

func TestMatcherRouteRangesMatchPrefixes(t *testing.T) {
	prefixStrings := []string{
		"10.0.0.0/32", "10.0.0.1/32", "10.0.0.3/32", "10.0.0.0/24",
		"10.0.2.0/24", "10.0.0.7/24", "192.168.0.0/16", "100.64.0.1/32",
		"2001:db8::1/128", "2001:db8::2/128", "2001:db8::4/128",
		"2001:db8::/64", "2001:db8:1::/64", "::ffff:192.0.2.0/120",
		"0.0.0.0/0", "::/0",
	}

	prefixes := make([]netip.Prefix, len(prefixStrings)+1)
	for i, text := range prefixStrings {
		prefixes[i+1] = netip.MustParsePrefix(text)
	}

	rapid.Check(t, func(rt *rapid.T) {
		sources := rapid.SliceOfN(rapid.SampledFrom(prefixStrings), 0, 12).
			Draw(rt, "sources")
		destinations := rapid.SliceOfN(rapid.SampledFrom(prefixStrings), 0, 12).
			Draw(rt, "destinations")
		routes := rapid.SliceOfN(rapid.SampledFrom(prefixes), 0, 32).Draw(rt, "routes")
		before := slices.Clone(routes)
		ranges := types.RouteRanges(routes)
		rule := tailcfg.FilterRule{SrcIPs: sources}

		for _, destination := range destinations {
			rule.DstPorts = append(rule.DstPorts, tailcfg.NetPortRange{
				IP: destination, Ports: tailcfg.PortRangeAny,
			})
		}

		m := matcher.MatchFromFilterRule(rule)
		require.Equal(rt, m.SrcsOverlapsPrefixes(routes...),
			m.SrcsOverlapsRanges(ranges))
		require.Equal(rt, m.DestsOverlapsPrefixes(routes...),
			m.DestsOverlapsRanges(ranges))
		require.Equal(rt, before, routes)
	})
}

func TestBuildPeerMapMatchesPrefixReference(t *testing.T) {
	users := []types.User{
		{ID: 1, Name: "u1"}, {ID: 2, Name: "u2"}, {ID: 3, Name: "u3"},
	}
	routePool := []netip.Prefix{
		netip.MustParsePrefix("10.1.0.0/24"),
		netip.MustParsePrefix("10.1.1.0/24"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("2001:db8::/64"),
		netip.MustParsePrefix("2001:db8:1::/64"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}
	policies := []struct{ name, policy string }{
		{name: "global", policy: benchPolicies[0].policy},
		{name: "self", policy: benchPolicies[1].policy},
		{name: "via", policy: benchPolicies[2].policy},
		{name: "via capability only", policy: `{
		"tagOwners": {"tag:router": ["u1@"]},
		"grants": [{"src": ["u2@"], "dst": ["10.0.0.0/8"], "via": ["tag:router"],
		"app": {"example.com/cap/test": [{}]}}]}`},
		{name: "subnet source", policy: `{
		"acls": [{"action": "accept", "src": ["10.0.0.0/8", "2001:db8::/32"],
		"dst": ["u2@:*"]}]}`},
		{name: "allow all", policy: `{
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`},
	}

	rapid.Check(t, func(rt *rapid.T) {
		nodes := make(types.Nodes, rapid.IntRange(5, 12).Draw(rt, "nodes"))
		for i := range nodes {
			u := users[rapid.IntRange(0, len(users)-1).Draw(rt, "user")]

			switch i {
			case 0, 4:
				u = users[0]
			case 2:
				u = users[1]
			}

			n := node(fmt.Sprint("n", i), fmt.Sprint("100.64.0.", i+1),
				fmt.Sprintf("fd7a:115c:a1e0::%x", i+1), u)
			n.ID = types.NodeID(i + 1) //nolint:gosec

			switch rapid.IntRange(0, 2).Draw(rt, "family") {
			case 1:
				n.IPv4 = nil
			case 2:
				n.IPv6 = nil
			}

			switch i {
			case 1:
				n.Tags = []string{"tag:router"}
			case 3:
				n.Tags = []string{"tag:srv"}
			}

			if n.IsTagged() {
				n.User, n.UserID = nil, nil
			}

			n.Hostinfo = &tailcfg.Hostinfo{
				RoutableIPs: rapid.SliceOfN(rapid.SampledFrom(routePool), 0, 8).
					Draw(rt, "announced"),
			}
			n.ApprovedRoutes = rapid.SliceOfN(rapid.SampledFrom(routePool), 0, 8).
				Draw(rt, "approved")

			switch i {
			case 1:
				n.Hostinfo.RoutableIPs = append(n.Hostinfo.RoutableIPs,
					routePool[0], routePool[5])
				n.ApprovedRoutes = append(n.ApprovedRoutes, routePool[0], routePool[5])
			case 2:
				n.Hostinfo.RoutableIPs = append(n.Hostinfo.RoutableIPs,
					routePool[7:]...)
				n.ApprovedRoutes = append(n.ApprovedRoutes, routePool[7:]...)
			}

			nodes[i] = n
		}

		for _, pol := range policies {
			pm, err := NewPolicyManager([]byte(pol.policy), users, nodes.ViewSlice())
			require.NoError(rt, err)
			require.Equal(rt, peerMapPrefixReference(pm, nodes),
				pm.BuildPeerMap(nodes.ViewSlice()), pol.name)
		}
	})
}

func peerMapPrefixReference(
	pm *PolicyManager,
	nodes types.Nodes,
) map[types.NodeID][]types.NodeID {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	nodeMatchers := make(map[types.NodeID][]matcher.Match, len(nodes))
	for _, n := range nodes {
		if pm.needsPerNodeFilter {
			nodeMatchers[n.ID] = matcher.MatchesFromFilterRules(
				pm.peerRulesForNodeLocked(n.View()))
		} else {
			nodeMatchers[n.ID] = pm.matchers
		}
	}

	peers := make(map[types.NodeID][]types.NodeID)

	for i, a := range nodes {
		for _, b := range nodes[i+1:] {
			mi, mj := nodeMatchers[a.ID], nodeMatchers[b.ID]
			if canAccessPrefixReference(a, b, mi) ||
				canAccessPrefixReference(b, a, mi) ||
				canAccessPrefixReference(a, b, mj) ||
				canAccessPrefixReference(b, a, mj) {
				peers[a.ID] = append(peers[a.ID], b.ID)
				peers[b.ID] = append(peers[b.ID], a.ID)
			}
		}
	}

	return peers
}

func canAccessPrefixReference(a, b *types.Node, matchers []matcher.Match) bool {
	src, dst := a.IPs(), b.IPs()
	srcRoutes, dstRoutes := a.SubnetRoutes(), b.SubnetRoutes()

	for _, m := range matchers {
		srcMatchesIP := m.SrcsContainsIPs(src...)
		srcMatchesRoutes := len(srcRoutes) > 0 && m.SrcsOverlapsPrefixes(srcRoutes...)

		if !srcMatchesIP && !srcMatchesRoutes {
			continue
		}

		if m.DestsContainsIP(dst...) {
			return true
		}

		if len(dstRoutes) > 0 && m.DestsOverlapsPrefixes(dstRoutes...) {
			return true
		}

		if b.IsExitNode() && m.DestsIsTheInternet() {
			return true
		}
	}

	return false
}

func BenchmarkBuildPeerMapManyRoutes(b *testing.B) {
	for _, pol := range benchPolicies {
		for _, n := range []int{64, 128} {
			b.Run(fmt.Sprintf("%s/n=%d", pol.name, n), func(b *testing.B) {
				users, nodes := benchNodes(n)
				for _, node := range nodes {
					node.Hostinfo, node.ApprovedRoutes = nil, nil
				}

				routes := make([]netip.Prefix, 10000)
				for i := range routes {
					ip := netip.AddrFrom4([4]byte{
						10, 100, byte((i >> 7) & 0xff), byte((i << 1) & 0xff),
					})
					routes[i] = netip.PrefixFrom(ip, 32)
				}

				nodes[0].Hostinfo = &tailcfg.Hostinfo{RoutableIPs: routes}
				nodes[0].ApprovedRoutes = routes
				views := nodes.ViewSlice()
				pm, err := NewPolicyManager([]byte(pol.policy), users, views)
				require.NoError(b, err)

				rules, err := pm.FilterForNode(nodes[0].View())
				require.NoError(b, err)
				require.Equal(b, pol.routerFiltered, len(rules) > 0)
				b.ReportAllocs()

				for b.Loop() {
					pm.BuildPeerMap(views)
				}
			})
		}
	}
}
