package v2

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// buildPeerMapPairScan is [PolicyManager.BuildPeerMap] as it was before the
// global-filter path stopped evaluating every matcher for every pair. It is
// kept as the reference the indexed build must reproduce exactly.
func buildPeerMapPairScan(pm *PolicyManager, nodes views.Slice[types.NodeView]) map[types.NodeID][]types.NodeID {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	type nodeRoutes struct {
		subnet []netip.Prefix
		isExit bool
	}

	routeInfo := make(map[types.NodeID]nodeRoutes, nodes.Len())
	for _, n := range nodes.All() {
		routeInfo[n.ID()] = nodeRoutes{subnet: n.SubnetRoutes(), isExit: n.IsExitNode()}
	}

	ret := make(map[types.NodeID][]types.NodeID, nodes.Len())

	if !pm.needsPerNodeFilter {
		for i := range nodes.Len() {
			for j := i + 1; j < nodes.Len(); j++ {
				if nodes.At(i).ID() == nodes.At(j).ID() {
					continue
				}

				ri, rj := routeInfo[nodes.At(i).ID()], routeInfo[nodes.At(j).ID()]
				if nodes.At(i).CanAccessWithRoutes(pm.matchers, nodes.At(j), ri.subnet, rj.subnet, rj.isExit) ||
					nodes.At(j).CanAccessWithRoutes(pm.matchers, nodes.At(i), rj.subnet, ri.subnet, ri.isExit) {
					ret[nodes.At(i).ID()] = append(ret[nodes.At(i).ID()], nodes.At(j).ID())
					ret[nodes.At(j).ID()] = append(ret[nodes.At(j).ID()], nodes.At(i).ID())
				}
			}
		}

		return ret
	}

	nodeMatchers := make(map[types.NodeID][]matcher.Match, nodes.Len())
	for _, node := range nodes.All() {
		nodeMatchers[node.ID()] = matcher.MatchesFromFilterRules(pm.filterRulesForNodeLocked(node))
	}

	for i := range nodes.Len() {
		nodeI := nodes.At(i)
		matchersI, hasFilterI := nodeMatchers[nodeI.ID()]
		riI := routeInfo[nodeI.ID()]

		for j := i + 1; j < nodes.Len(); j++ {
			nodeJ := nodes.At(j)
			matchersJ, hasFilterJ := nodeMatchers[nodeJ.ID()]
			riJ := routeInfo[nodeJ.ID()]

			if hasFilterI && nodeI.CanAccessWithRoutes(matchersI, nodeJ, riI.subnet, riJ.subnet, riJ.isExit) ||
				hasFilterJ && nodeJ.CanAccessWithRoutes(matchersJ, nodeI, riJ.subnet, riI.subnet, riI.isExit) ||
				hasFilterI && nodeJ.CanAccessWithRoutes(matchersI, nodeI, riJ.subnet, riI.subnet, riI.isExit) ||
				hasFilterJ && nodeI.CanAccessWithRoutes(matchersJ, nodeJ, riI.subnet, riJ.subnet, riJ.isExit) {
				ret[nodeI.ID()] = append(ret[nodeI.ID()], nodeJ.ID())
				ret[nodeJ.ID()] = append(ret[nodeJ.ID()], nodeI.ID())
			}
		}
	}

	return ret
}

var (
	scanUsers = []types.User{
		{ID: 1, Name: "u1"},
		{ID: 2, Name: "u2"},
		{ID: 3, Name: "u3"},
		{ID: 4, Name: "u4"},
	}
	scanTags   = []string{"tag:srv", "tag:db", "tag:router", "tag:exit"}
	scanRoutes = []string{"10.1.0.0/24", "10.1.1.0/24", "10.2.0.0/16", "192.168.5.0/24", "fd00:1::/64"}
	// Aliases usable on either side of a rule.
	scanAliases = []string{
		"*", "u1@", "u2@", "u3@", "u4@", "group:a", "group:b",
		"tag:srv", "tag:db", "tag:router", "tag:exit",
		"autogroup:member", "autogroup:tagged",
		"lan", "host1", "v6net",
		"10.1.0.0/24", "10.2.0.0/16", "192.168.5.0/24", "fd00:1::/64",
		"100.64.0.0/28", "100.64.0.3", "fd7a:115c:a1e0::/124", "fd7a:115c:a1e0::5",
	}
	// Destination-only extras: the internet, written both ways, and self.
	scanDstOnly = []string{"autogroup:internet", "autogroup:internet", "0.0.0.0/0", "::/0", "autogroup:self"}
)

// scanRandomNodes returns user-owned and tagged nodes on IPv4, IPv6 or both,
// some advertising subnet routes or exit routes that are approved only in
// part, so every identity [types.Node.CanAccess] looks at is present.
func scanRandomNodes(r *rand.Rand, n int) types.Nodes {
	nodes := make(types.Nodes, 0, n)

	for i := range n {
		nd := &types.Node{ID: types.NodeID(i + 1), Hostname: fmt.Sprintf("n%d", i+1)} //nolint:gosec

		v4 := netip.AddrFrom4([4]byte{100, 64, 0, byte(i + 1)})                               //nolint:gosec
		v6 := netip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 15: byte(i + 1)}) //nolint:gosec

		switch r.IntN(7) {
		case 0:
			nd.IPv4 = &v4
		case 1:
			nd.IPv6 = &v6
		default:
			nd.IPv4, nd.IPv6 = &v4, &v6
		}

		if r.IntN(10) < 6 {
			u := scanUsers[r.IntN(len(scanUsers))]
			nd.User, nd.UserID = &u, &u.ID
		} else {
			nd.Tags = []string{scanTags[r.IntN(len(scanTags))]}
			if r.IntN(3) == 0 {
				nd.Tags = append(nd.Tags, scanTags[r.IntN(len(scanTags))])
			}
		}

		var announced []netip.Prefix

		switch r.IntN(10) {
		case 0, 1, 2:
			for range 1 + r.IntN(2) {
				announced = append(announced, netip.MustParsePrefix(scanRoutes[r.IntN(len(scanRoutes))]))
			}
		case 3:
			announced = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
		case 4:
			announced = []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
				netip.MustParsePrefix(scanRoutes[r.IntN(len(scanRoutes))]),
			}
		}

		if len(announced) > 0 {
			nd.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: announced}

			for _, p := range announced {
				if r.IntN(10) < 7 {
					nd.ApprovedRoutes = append(nd.ApprovedRoutes, p)
				}
			}
		}

		nodes = append(nodes, nd)
	}

	return nodes
}

// scanRandomPolicy returns a policy of ACLs and grants over [scanAliases].
// Some of them the policy manager rejects; the caller skips those.
func scanRandomPolicy(r *rand.Rand) []byte {
	pick := func(pool []string, n int) []string {
		out := make([]string, 0, n)
		for range n {
			out = append(out, pool[r.IntN(len(pool))])
		}

		return out
	}

	pol := map[string]any{
		"groups":    map[string][]string{"group:a": {"u1@", "u2@"}, "group:b": {"u3@"}},
		"tagOwners": map[string][]string{"tag:srv": {"u1@"}, "tag:db": {"u1@"}, "tag:router": {"u1@"}, "tag:exit": {"u1@"}},
		"hosts":     map[string]string{"lan": "10.1.0.0/16", "host1": "100.64.0.5/32", "v6net": "fd7a:115c:a1e0::/122"},
	}

	// Neither section: allow-all. Empty grants: deny-all. Otherwise rules.
	switch r.IntN(20) {
	case 0:
		return must(json.Marshal(pol))
	case 1:
		pol["grants"] = []any{}

		return must(json.Marshal(pol))
	}

	var acls, grants []any

	for range 1 + r.IntN(8) {
		src := pick(scanAliases, 1+r.IntN(3))
		dst := pick(scanAliases, 1+r.IntN(3))

		if r.IntN(4) == 0 {
			dst = append(dst, scanDstOnly[r.IntN(len(scanDstOnly))])
		}

		if r.IntN(3) == 0 {
			// ACL destinations are "alias:ports"; bare IPv6 does not fit that form.
			var aclDst []string

			for _, d := range dst {
				if netip.MustParsePrefix("::/0").Contains(parseAddrOrZero(d)) {
					continue
				}

				aclDst = append(aclDst, d+":"+[]string{"*", "22", "80,443"}[r.IntN(3)])
			}

			if len(aclDst) > 0 {
				acls = append(acls, map[string]any{"action": "accept", "src": src, "dst": aclDst})
			}

			continue
		}

		g := map[string]any{"src": src, "dst": dst, "ip": [][]string{{"*"}, {"tcp:443"}, {"icmp:*"}, {"udp:53", "tcp:22"}}[r.IntN(4)]}
		if r.IntN(8) == 0 {
			g["via"] = []string{[]string{"tag:router", "tag:exit"}[r.IntN(2)]}
		}

		grants = append(grants, g)
	}

	if acls != nil {
		pol["acls"] = acls
	}

	if grants != nil {
		pol["grants"] = grants
	}

	return must(json.Marshal(pol))
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}

	return v
}

// parseAddrOrZero returns the address of an IP or CIDR alias, or the IPv4
// zero address for anything else.
func parseAddrOrZero(alias string) netip.Addr {
	p, err := netip.ParsePrefix(alias)
	if err == nil {
		return p.Addr()
	}

	a, err := netip.ParseAddr(alias)
	if err == nil {
		return a
	}

	return netip.IPv4Unspecified()
}

// TestBuildPeerMapMatchesPairScan checks that the indexed peer-map build
// returns exactly what the pair scan it replaced returns, peer order
// included, over random tailnets and policies.
func TestBuildPeerMapMatchesPairScan(t *testing.T) {
	const iterations = 3000

	r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // reproducible test input

	var global, perNode, partial, full, empty, routeSrc, routeDst, exitDst, rejected int

	for it := range iterations {
		nodes := scanRandomNodes(r, 2+r.IntN(40))
		polB := scanRandomPolicy(r)

		pm, err := NewPolicyManager(polB, scanUsers, nodes.ViewSlice())
		if err != nil {
			rejected++
			continue
		}

		// The build takes any slice, not only the manager's own: also feed
		// it a shuffled subset, as a NodeStore snapshot would.
		subset := append(types.Nodes(nil), nodes...)
		r.Shuffle(len(subset), func(a, b int) { subset[a], subset[b] = subset[b], subset[a] })
		subset = subset[:1+r.IntN(len(subset))]

		for _, in := range []views.Slice[types.NodeView]{nodes.ViewSlice(), subset.ViewSlice()} {
			want := buildPeerMapPairScan(pm, in)
			got := pm.BuildPeerMap(in)
			require.Equalf(t, want, got, "iteration %d, policy %s", it, polB)
		}

		if pm.needsPerNodeFilter {
			perNode++
			continue
		}

		global++

		want := buildPeerMapPairScan(pm, nodes.ViewSlice())

		pairs := 0
		for _, peers := range want {
			pairs += len(peers)
		}

		switch pairs {
		case 0:
			empty++
		case len(nodes) * (len(nodes) - 1):
			full++
		default:
			partial++
		}

		// Count the inputs that reach the branches beyond plain node IPs.
		for _, n := range nodes {
			for i := range pm.matchers {
				m := &pm.matchers[i]
				if sr := n.SubnetRoutes(); len(sr) > 0 {
					if !m.SrcsContainsIPs(n.IPs()...) && m.SrcsOverlapsPrefixes(sr...) {
						routeSrc++
					}

					if !m.DestsContainsIP(n.IPs()...) && m.DestsOverlapsPrefixes(sr...) {
						routeDst++
					}
				}

				if n.IsExitNode() && !m.DestsContainsIP(n.IPs()...) && m.DestsIsTheInternet() {
					exitDst++
				}
			}
		}
	}

	t.Logf("%d policies: %d global (%d partial, %d full, %d empty peer maps), %d per-node, %d rejected; "+
		"matcher/node hits by subnet route as source %d, as destination %d, by exit node %d",
		iterations, global, partial, full, empty, perNode, rejected, routeSrc, routeDst, exitDst)

	// The comparison is only worth something if the inputs reached every branch.
	require.Greater(t, partial, iterations/10, "partial peer maps")
	require.Positive(t, full)
	require.Positive(t, empty)
	require.Positive(t, perNode)
	require.Positive(t, routeSrc)
	require.Positive(t, routeDst)
	require.Positive(t, exitDst)
}

// TestBuildPeerMapIdentities pins the pairs that only exist because of an
// identity other than the nodes' own IPs, so the indexed build cannot drop
// one of them without a named failure.
func TestBuildPeerMapIdentities(t *testing.T) {
	route := func(nd *types.Node, approved bool, prefixes ...string) *types.Node {
		ps := make([]netip.Prefix, 0, len(prefixes))
		for _, p := range prefixes {
			ps = append(ps, netip.MustParsePrefix(p))
		}

		nd.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: ps}
		if approved {
			nd.ApprovedRoutes = ps
		}

		return nd
	}
	tagged := func(id types.NodeID, v4, v6 string, tags ...string) *types.Node {
		nd := &types.Node{ID: id, Hostname: fmt.Sprintf("n%d", id), Tags: tags}
		if v4 != "" {
			nd.IPv4 = ap(v4)
		}

		if v6 != "" {
			nd.IPv6 = ap(v6)
		}

		return nd
	}

	const owners = `"tagOwners": {"tag:a": [], "tag:b": [], "tag:c": []},`

	tests := []struct {
		name   string
		policy string
		nodes  types.Nodes
		want   map[types.NodeID][]types.NodeID
	}{
		{
			name:   "subnet route as source and as destination",
			policy: `{` + owners + `"grants": [{"src": ["10.1.0.0/24"], "dst": ["10.2.0.0/16"], "ip": ["*"]}]}`,
			nodes: types.Nodes{
				route(tagged(1, "100.64.0.1", "", "tag:a"), true, "10.1.0.0/24"),
				route(tagged(2, "100.64.0.2", "", "tag:b"), true, "10.2.0.0/16"),
				route(tagged(3, "100.64.0.3", "", "tag:c"), false, "10.2.0.0/16"), // not approved
				tagged(4, "100.64.0.4", "", "tag:c"),
			},
			want: map[types.NodeID][]types.NodeID{1: {2}, 2: {1}},
		},
		{
			name:   "exit node is the internet",
			policy: `{` + owners + `"grants": [{"src": ["tag:a"], "dst": ["autogroup:internet"], "ip": ["*"]}]}`,
			nodes: types.Nodes{
				tagged(1, "100.64.0.1", "fd7a:115c:a1e0::1", "tag:a"),
				route(tagged(2, "100.64.0.2", "fd7a:115c:a1e0::2", "tag:b"), true, "0.0.0.0/0", "::/0"),
				route(tagged(3, "100.64.0.3", "fd7a:115c:a1e0::3", "tag:b"), false, "0.0.0.0/0", "::/0"),
				tagged(4, "100.64.0.4", "fd7a:115c:a1e0::4", "tag:c"),
			},
			want: map[types.NodeID][]types.NodeID{1: {2}, 2: {1}},
		},
		{
			name:   "ipv6-only and ipv4-only ends",
			policy: `{` + owners + `"grants": [{"src": ["tag:a"], "dst": ["tag:b"], "ip": ["tcp:443"]}]}`,
			nodes: types.Nodes{
				tagged(1, "", "fd7a:115c:a1e0::1", "tag:a"),
				tagged(2, "100.64.0.2", "", "tag:b"),
				tagged(3, "", "fd7a:115c:a1e0::3", "tag:c"),
			},
			want: map[types.NodeID][]types.NodeID{1: {2}, 2: {1}},
		},
		{
			name:   "one-way rule past the first 64 matchers",
			policy: scanManyRulesPolicy(100, 70),
			nodes:  scanManyRulesNodes(100),
			want:   nil, // compared against the pair scan only
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewPolicyManager([]byte(tt.policy), nil, tt.nodes.ViewSlice())
			require.NoError(t, err)
			require.False(t, pm.needsPerNodeFilter)

			got := pm.BuildPeerMap(tt.nodes.ViewSlice())
			require.Equal(t, buildPeerMapPairScan(pm, tt.nodes.ViewSlice()), got)

			if tt.want != nil {
				require.Equal(t, tt.want, got)
			} else {
				require.Greater(t, len(pm.matchers), 64)
				require.NotEmpty(t, got)
			}
		})
	}
}

// scanManyRulesNodes and scanManyRulesPolicy describe a tailnet where every
// node has a tag of its own and access is granted pair by pair: n/20
// operators, one monitor, the rest units, and per lease one operator->unit
// grant plus an ICMP grant from each end to the monitor. The filter grows
// with the number of leases while each node appears in only a few rules.
func scanManyRulesNodes(n int) types.Nodes {
	nodes := make(types.Nodes, 0, n)

	for i := range n {
		v4 := netip.AddrFrom4([4]byte{100, 64, byte(i >> 8), byte(i)})                                      //nolint:gosec
		v6 := netip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 14: byte(i >> 8), 15: byte(i)}) //nolint:gosec
		nodes = append(nodes, &types.Node{
			ID:       types.NodeID(i + 1), //nolint:gosec
			Hostname: fmt.Sprintf("n%d", i),
			IPv4:     &v4,
			IPv6:     &v6,
			Tags:     []string{fmt.Sprintf("tag:n%d", i)},
		})
	}

	return nodes
}

func scanManyRulesPolicy(n, leases int) string {
	ops := max(n/20, 1)
	owners := make(map[string][]string, n)

	for i := range n {
		owners[fmt.Sprintf("tag:n%d", i)] = []string{}
	}

	monitor := fmt.Sprintf("tag:n%d", n-1)
	grants := make([]map[string][]string, 0, leases*3)

	for l := range leases {
		op, unit := fmt.Sprintf("tag:n%d", l%ops), fmt.Sprintf("tag:n%d", ops+l)
		grants = append(grants,
			map[string][]string{"src": {op}, "dst": {unit}, "ip": {"tcp:445", "tcp:14000-16000", "udp:14000-16000", "icmp:*"}},
			map[string][]string{"src": {op}, "dst": {monitor}, "ip": {"icmp:*"}},
			map[string][]string{"src": {unit}, "dst": {monitor}, "ip": {"icmp:*"}},
		)
	}

	return string(must(json.Marshal(map[string]any{"tagOwners": owners, "grants": grants})))
}

// BenchmarkBuildPeerMapManyRules measures [PolicyManager.BuildPeerMap] on the
// many-rules shape, next to the pair scan it replaced.
func BenchmarkBuildPeerMapManyRules(b *testing.B) {
	for _, c := range []struct{ nodes, leases int }{{200, 30}, {1000, 30}, {1000, 100}, {2000, 100}} {
		nodes := scanManyRulesNodes(c.nodes)

		pm, err := NewPolicyManager([]byte(scanManyRulesPolicy(c.nodes, c.leases)), nil, nodes.ViewSlice())
		require.NoError(b, err)

		name := fmt.Sprintf("n=%d/leases=%d/matchers=%d", c.nodes, c.leases, len(pm.matchers))

		b.Run(name+"/indexed", func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				pm.BuildPeerMap(nodes.ViewSlice())
			}
		})

		b.Run(name+"/pairscan", func(b *testing.B) {
			if testing.Short() {
				b.Skip("the pair scan takes seconds per iteration")
			}

			b.ReportAllocs()

			for b.Loop() {
				buildPeerMapPairScan(pm, nodes.ViewSlice())
			}
		})
	}
}
