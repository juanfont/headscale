package v2

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/packetfilter"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// buildPeerMapPairScan is [PolicyManager.BuildPeerMap] as it was before the
// global-filter path stopped evaluating every matcher for every pair. It is
// kept as the reference the indexed build must reproduce exactly.
func buildPeerMapPairScan(pm *PolicyManager, nodes views.Slice[types.NodeView],
) map[types.NodeID][]types.NodeID {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	globalMatches := referenceMatchesFromFilterRules(
		pm.pol.legacyCompileFilterRules(pm.users, pm.nodes),
	)
	legacyGrants := pm.pol.legacyCompileGrants(pm.users, pm.nodes)
	legacyUsers := legacyBuildUserNodeIndex(pm.nodes)

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
				if referenceCanAccessWithRoutes(
					nodes.At(i),
					globalMatches, nodes.At(j), ri.subnet, rj.subnet, rj.isExit,
				) ||
					referenceCanAccessWithRoutes(
						nodes.At(j),
						globalMatches, nodes.At(i), rj.subnet, ri.subnet, ri.isExit,
					) {
					ret[nodes.At(i).ID()] = append(ret[nodes.At(i).ID()], nodes.At(j).ID())
					ret[nodes.At(j).ID()] = append(ret[nodes.At(j).ID()], nodes.At(i).ID())
				}
			}
		}

		return ret
	}

	nodeMatchers := make(map[types.NodeID][]referenceMatch, nodes.Len())
	for _, node := range nodes.All() {
		nodeMatchers[node.ID()] = referenceMatchesFromFilterRules(
			legacyFilterRulesForNode(legacyGrants, node, legacyUsers),
		)
	}

	for i := range nodes.Len() {
		nodeI := nodes.At(i)
		matchersI, hasFilterI := nodeMatchers[nodeI.ID()]
		riI := routeInfo[nodeI.ID()]

		for j := i + 1; j < nodes.Len(); j++ {
			nodeJ := nodes.At(j)
			matchersJ, hasFilterJ := nodeMatchers[nodeJ.ID()]
			riJ := routeInfo[nodeJ.ID()]

			if hasFilterI &&
				referenceCanAccessWithRoutes(
					nodeI,
					matchersI, nodeJ, riI.subnet, riJ.subnet, riJ.isExit,
				) ||
				hasFilterJ &&
					referenceCanAccessWithRoutes(
						nodeJ,
						matchersJ, nodeI, riJ.subnet, riI.subnet, riI.isExit,
					) ||
				hasFilterI &&
					referenceCanAccessWithRoutes(
						nodeJ,
						matchersI, nodeI, riJ.subnet, riI.subnet, riI.isExit,
					) ||
				hasFilterJ &&
					referenceCanAccessWithRoutes(
						nodeI,
						matchersJ, nodeJ, riI.subnet, riJ.subnet, riJ.isExit,
					) {
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
			require.Equalf(t, want, buildPeerMapSortedSlice(pm, in),
				"sorted slice: iteration %d, policy %s", it, polB)
			require.Equalf(t, want, buildPeerMapSliceMap(pm, in),
				"slice + map: iteration %d, policy %s", it, polB)
			require.Equalf(t, want, buildPeerMapTypedPairScan(pm, in),
				"typed pair scan: iteration %d, policy %s", it, polB)
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
		globalMatches := referenceMatchesFromFilterRules(
			pm.pol.legacyCompileFilterRules(pm.users, pm.nodes),
		)
		for _, n := range nodes {
			for i := range globalMatches {
				m := globalMatches[i]
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
		iterations, global, partial, full, empty, perNode, rejected, routeSrc, routeDst, exitDst,
	)

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
			require.Equal(t, got, buildPeerMapSortedSlice(pm, tt.nodes.ViewSlice()))
			require.Equal(t, got, buildPeerMapSliceMap(pm, tt.nodes.ViewSlice()))
			require.Equal(t, got, buildPeerMapTypedPairScan(pm, tt.nodes.ViewSlice()))

			if tt.want != nil {
				require.Equal(t, tt.want, got)
			} else {
				require.Greater(t, len(pm.view.generation.global), 64)
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

// buildPeerMapTypedPairScan excludes legacy compilation from the timed comparison.
// The independent buildPeerMapPairScan remains the correctness oracle.
func buildPeerMapTypedPairScan(
	pm *PolicyManager,
	nodes views.Slice[types.NodeView],
) map[types.NodeID][]types.NodeID {
	if pm == nil {
		return nil
	}

	pm.mu.RLock()

	if pm.needsPerNodeFilter {
		pm.mu.RUnlock()

		return pm.BuildPeerMap(nodes)
	}
	defer pm.mu.RUnlock()

	type nodeRoutes struct {
		subnet []netip.Prefix
		isExit bool
	}

	routeInfo := make(map[types.NodeID]nodeRoutes, nodes.Len())
	for _, n := range nodes.All() {
		routeInfo[n.ID()] = nodeRoutes{subnet: n.SubnetRoutes(), isExit: n.IsExitNode()}
	}

	canAccess := func(src, dst types.NodeView) bool {
		if !src.Valid() || !dst.Valid() {
			return false
		}

		srcRoutes, dstRoutes := routeInfo[src.ID()], routeInfo[dst.ID()]
		for _, rule := range pm.view.generation.global {
			if !slices.ContainsFunc(src.IPs(), rule.Sources().Contains) &&
				!slices.ContainsFunc(srcRoutes.subnet, rule.Sources().OverlapsPrefix) {
				continue
			}

			if slices.ContainsFunc(dst.IPs(), rule.DestinationSet().Contains) ||
				slices.ContainsFunc(
					dstRoutes.subnet,
					rule.DestinationSet().OverlapsPrefix,
				) ||
				(dstRoutes.isExit && ruleIncludesInternet(rule)) {
				return true
			}
		}

		return false
	}

	ret := make(map[types.NodeID][]types.NodeID, nodes.Len())
	for i, src := range nodes.All() {
		for j := i + 1; j < nodes.Len(); j++ {
			dst := nodes.At(j)
			if src.ID() == dst.ID() {
				continue
			}

			if canAccess(src, dst) || canAccess(dst, src) {
				ret[src.ID()] = append(ret[src.ID()], dst.ID())
				ret[dst.ID()] = append(ret[dst.ID()], src.ID())
			}
		}
	}

	return ret
}

// buildPeerMapSortedSlice benchmarks the global-filter path with sorted
// matcher IDs. Appending in matcher order keeps both indexes sorted.
func buildPeerMapSortedSlice(
	pm *PolicyManager,
	nodes views.Slice[types.NodeView],
) map[types.NodeID][]types.NodeID {
	if pm == nil {
		return nil
	}

	pm.mu.RLock()

	if pm.needsPerNodeFilter {
		pm.mu.RUnlock()

		return pm.BuildPeerMap(nodes)
	}
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
	ids := make([]types.NodeID, nodes.Len())
	srcOf := make([][]int, nodes.Len())
	dstOf := make([][]int, nodes.Len())

	for i, n := range nodes.All() {
		ids[i] = n.ID()
		if !n.Valid() {
			continue
		}

		ips, ri := n.IPs(), routeInfo[n.ID()]
		routed := len(ri.subnet) > 0

		for k := range pm.view.generation.global {
			m := pm.view.generation.global[k]

			if slices.ContainsFunc(ips, m.Sources().Contains) ||
				(routed && slices.ContainsFunc(ri.subnet, m.Sources().OverlapsPrefix)) {
				srcOf[i] = append(srcOf[i], k)
			}

			if slices.ContainsFunc(ips, m.DestinationSet().Contains) ||
				(routed && slices.ContainsFunc(ri.subnet, m.DestinationSet().OverlapsPrefix)) ||
				(ri.isExit && ruleIncludesInternet(m)) {
				dstOf[i] = append(dstOf[i], k)
			}
		}
	}

	for i := range ids {
		for j := i + 1; j < len(ids); j++ {
			if ids[i] == ids[j] {
				continue
			}

			if sortedMatcherSetsIntersect(srcOf[i], dstOf[j]) ||
				sortedMatcherSetsIntersect(srcOf[j], dstOf[i]) {
				ret[ids[i]] = append(ret[ids[i]], ids[j])
				ret[ids[j]] = append(ret[ids[j]], ids[i])
			}
		}
	}

	return ret
}

func sortedMatcherSetsIntersect(src, dst []int) bool {
	i, j := 0, 0
	for i < len(src) && j < len(dst) {
		switch {
		case src[i] == dst[j]:
			return true
		case src[i] < dst[j]:
			i++
		default:
			j++
		}
	}

	return false
}

// buildPeerMapSliceMap benchmarks the global-filter path with source matcher
// IDs in slices and destination matcher IDs in maps.
func buildPeerMapSliceMap(
	pm *PolicyManager,
	nodes views.Slice[types.NodeView],
) map[types.NodeID][]types.NodeID {
	if pm == nil {
		return nil
	}

	pm.mu.RLock()

	if pm.needsPerNodeFilter {
		pm.mu.RUnlock()

		return pm.BuildPeerMap(nodes)
	}
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
	ids := make([]types.NodeID, nodes.Len())
	srcOf := make([][]int, nodes.Len())
	dstOf := make([]map[int]struct{}, nodes.Len())

	for i, n := range nodes.All() {
		ids[i] = n.ID()
		if !n.Valid() {
			continue
		}

		ips, ri := n.IPs(), routeInfo[n.ID()]
		routed := len(ri.subnet) > 0

		for k := range pm.view.generation.global {
			m := pm.view.generation.global[k]

			if slices.ContainsFunc(ips, m.Sources().Contains) ||
				(routed && slices.ContainsFunc(ri.subnet, m.Sources().OverlapsPrefix)) {
				srcOf[i] = append(srcOf[i], k)
			}

			if slices.ContainsFunc(ips, m.DestinationSet().Contains) ||
				(routed && slices.ContainsFunc(ri.subnet, m.DestinationSet().OverlapsPrefix)) ||
				(ri.isExit && ruleIncludesInternet(m)) {
				if dstOf[i] == nil {
					dstOf[i] = make(map[int]struct{})
				}

				dstOf[i][k] = struct{}{}
			}
		}
	}

	for i := range ids {
		for j := i + 1; j < len(ids); j++ {
			if ids[i] == ids[j] {
				continue
			}

			if sliceMapMatcherSetsIntersect(srcOf[i], dstOf[j]) ||
				sliceMapMatcherSetsIntersect(srcOf[j], dstOf[i]) {
				ret[ids[i]] = append(ret[ids[i]], ids[j])
				ret[ids[j]] = append(ret[ids[j]], ids[i])
			}
		}
	}

	return ret
}

func sliceMapMatcherSetsIntersect(src []int, dst map[int]struct{}) bool {
	if len(dst) == 0 {
		return false
	}

	for _, matcherID := range src {
		if _, ok := dst[matcherID]; ok {
			return true
		}
	}

	return false
}

// scanDenseRulesPolicy makes every node match many source and destination
// rules, with either immediate, last-rule-only, or no intersection. Unique
// off-tailnet source IPs prevent the compiler from merging the dense rules.
func scanDenseRulesPolicy(matchers int, shape string) string {
	const subnet = "100.64.0.0/10"

	grants := make([]map[string][]string, 0, matchers)
	for k := range matchers {
		marker := fmt.Sprintf("10.255.%d.%d", k/256, k%256)
		src, dst := []string{marker}, []string{subnet}

		if shape == "early-overlap" || (shape == "late-overlap" && k == matchers-1) {
			src = append(src, subnet)
		} else if k%2 == 0 {
			src = append(src, subnet)
			dst = []string{marker}
		}

		grants = append(grants, map[string][]string{
			"src": src, "dst": dst, "ip": {"*"},
		})
	}

	return string(must(json.Marshal(map[string]any{"grants": grants})))
}

// TestBuildPeerMapDenseRules pins the compiled rule count and memberships so
// policy compilation cannot silently turn a dense benchmark into a sparse one.
func TestBuildPeerMapDenseRules(t *testing.T) {
	nodes := scanManyRulesNodes(8)

	for _, tt := range []struct {
		shape                     string
		sources, destinations     int
		firstShared, peersPerNode int
	}{
		{"early-overlap", 70, 70, 0, 7},
		{"late-overlap", 36, 35, 69, 7},
		{"disjoint", 35, 35, -1, 0},
	} {
		t.Run(tt.shape, func(t *testing.T) {
			pm, err := NewPolicyManager(
				[]byte(scanDenseRulesPolicy(70, tt.shape)), nil, nodes.ViewSlice(),
			)
			require.NoError(t, err)
			require.False(t, pm.needsPerNodeFilter)
			require.Len(t, pm.view.generation.global, 70)

			want := buildPeerMapPairScan(pm, nodes.ViewSlice())
			require.Equal(t, want, pm.BuildPeerMap(nodes.ViewSlice()))
			require.Equal(t, want, buildPeerMapSortedSlice(pm, nodes.ViewSlice()))
			require.Equal(t, want, buildPeerMapSliceMap(pm, nodes.ViewSlice()))
			require.Equal(t, want, buildPeerMapTypedPairScan(pm, nodes.ViewSlice()))

			for _, node := range nodes {
				sources, destinations, firstShared := 0, 0, -1

				for k, m := range pm.view.generation.global {
					src := slices.ContainsFunc(node.IPs(), m.Sources().Contains)
					dst := slices.ContainsFunc(node.IPs(), m.DestinationSet().Contains)

					if src {
						sources++
					}

					if dst {
						destinations++
					}

					if src && dst && firstShared == -1 {
						firstShared = k
					}
				}

				require.Equal(t, tt.sources, sources)
				require.Equal(t, tt.destinations, destinations)
				require.Equal(t, tt.firstShared, firstShared)
				require.Len(t, want[node.ID], tt.peersPerNode)
			}
		})
	}
}

// BenchmarkBuildPeerMapManyRules measures [PolicyManager.BuildPeerMap] on the
// many-rules shape, next to a typed pair scan over the same precompiled rules.
// Each indexed variant includes index construction and peer-map allocation.
func BenchmarkBuildPeerMapManyRules(b *testing.B) {
	for _, c := range []struct{ nodes, leases int }{{200, 30}, {1000, 30}, {1000, 100}, {2000, 100}} {
		nodes := scanManyRulesNodes(c.nodes)

		pm, err := NewPolicyManager(
			[]byte(scanManyRulesPolicy(c.nodes, c.leases)),
			nil,
			nodes.ViewSlice(),
		)
		require.NoError(b, err)
		require.False(b, pm.needsPerNodeFilter)

		name := fmt.Sprintf(
			"n=%d/leases=%d/matchers=%d",
			c.nodes,
			c.leases,
			len(pm.view.generation.global),
		)

		b.Run(name, func(b *testing.B) {
			benchmarkPeerMapBuilders(b, pm, nodes)
		})
	}
}

func BenchmarkBuildPeerMapDenseRules(b *testing.B) {
	for _, c := range []struct{ nodes, matchers int }{{200, 256}, {1000, 512}} {
		nodes := scanManyRulesNodes(c.nodes)

		for _, shape := range []string{"early-overlap", "late-overlap", "disjoint"} {
			pm, err := NewPolicyManager(
				[]byte(scanDenseRulesPolicy(c.matchers, shape)), nil, nodes.ViewSlice(),
			)
			require.NoError(b, err)
			require.False(b, pm.needsPerNodeFilter)
			require.Len(b, pm.view.generation.global, c.matchers)

			name := fmt.Sprintf("%s/n=%d/matchers=%d", shape, c.nodes, c.matchers)
			b.Run(name, func(b *testing.B) {
				benchmarkPeerMapBuilders(b, pm, nodes)
			})
		}
	}
}

func benchmarkPeerMapBuilders(b *testing.B, pm *PolicyManager, nodes types.Nodes) {
	b.Helper()

	want := buildPeerMapPairScan(pm, nodes.ViewSlice())

	for _, builder := range []struct {
		name  string
		build func(*PolicyManager, views.Slice[types.NodeView]) map[types.NodeID][]types.NodeID
	}{
		{"bitset", (*PolicyManager).BuildPeerMap},
		{"sorted-slice", buildPeerMapSortedSlice},
		{"slice-map", buildPeerMapSliceMap},
		{"pairscan", buildPeerMapTypedPairScan},
	} {
		b.Run(builder.name, func(b *testing.B) {
			if builder.name == "pairscan" && testing.Short() {
				b.Skip("the pair scan takes seconds per iteration")
			}

			require.Equal(b, want, builder.build(pm, nodes.ViewSlice()))
			b.ReportAllocs()

			for b.Loop() {
				builder.build(pm, nodes.ViewSlice())
			}
		})
	}
}

// BenchmarkBuildPeerMapManyRulesWarm measures adjacency reads after generation construction.
func BenchmarkBuildPeerMapManyRulesWarm(b *testing.B) {
	for _, c := range []struct{ nodes, leases int }{{200, 30}, {1000, 30}, {1000, 100}, {2000, 100}} {
		nodes := scanManyRulesNodes(c.nodes)
		pm, err := NewPolicyManager([]byte(scanManyRulesPolicy(c.nodes, c.leases)), nil, nodes.ViewSlice())
		require.NoError(b, err)
		require.Equal(b, buildPeerMapPairScan(pm, nodes.ViewSlice()), pm.BuildPeerMap(nodes.ViewSlice()))

		name := fmt.Sprintf("n=%d/leases=%d/matchers=%d", c.nodes, c.leases, len(pm.view.generation.global))
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				pm.BuildPeerMap(nodes.ViewSlice())
			}
		})
	}
}

// buildPeerMapPerNodeReference retains BuildPeerMap before per-node matcher
// evaluation was shared across nodes. Keep it independent of the optimized path.
//
//nolint:gocyclo // Preserve the original implementation for differential tests and benchmarks.
func buildPeerMapPerNodeReference(pm *PolicyManager, nodes views.Slice[types.NodeView],
) map[types.NodeID][]types.NodeID {
	if pm == nil {
		return nil
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	globalMatches := referenceMatchesFromFilterRules(
		pm.pol.legacyCompileFilterRules(pm.users, pm.nodes),
	)
	legacyGrants := pm.pol.legacyCompileGrants(pm.users, pm.nodes)
	legacyUsers := legacyBuildUserNodeIndex(pm.nodes)

	// Precompute each node's subnet routes and exit-node status once; the
	// O(n^2) pair scans below would otherwise recompute them for every pair.
	type nodeRoutes struct {
		subnet []netip.Prefix
		isExit bool
	}

	routeInfo := make(map[types.NodeID]nodeRoutes, nodes.Len())
	for _, n := range nodes.All() {
		routeInfo[n.ID()] = nodeRoutes{subnet: n.SubnetRoutes(), isExit: n.IsExitNode()}
	}

	// If we have a global filter, use it for all nodes (normal case).
	// Via grants require the per-node path because the global filter
	// skips via grants (compileFilterRules: if len(grant.Via) > 0 { continue }).
	if !pm.needsPerNodeFilter {
		ret := make(map[types.NodeID][]types.NodeID, nodes.Len())

		// A matcher lets a reach b when a satisfies its source side and b
		// its destination side, exactly as [types.Node.CanAccess] tests
		// them, and each side depends on one node only. So evaluate both
		// sides once per node, as bitsets over referenceMatchesFromFilterRules(pm.pol.legacyCompileFilterRules(pm.users,pm.nodes)), instead of
		// once per pair: a can reach b iff a's source set and b's
		// destination set intersect. That turns the O(n^2 * matchers)
		// scan into O(n * matchers) set lookups plus O(n^2) word ANDs.
		words := (len(pm.view.generation.global) + 63) / 64 //nolint:mnd
		ids := make([]types.NodeID, nodes.Len())
		srcOf := make([][]uint64, nodes.Len()) // nil: source of no matcher
		dstOf := make([][]uint64, nodes.Len()) // nil: destination of no matcher

		for i, n := range nodes.All() {
			ids[i] = n.ID()
			if !n.Valid() {
				continue
			}

			ips, ri := n.IPs(), routeInfo[n.ID()]
			routed := len(ri.subnet) > 0

			for k := range globalMatches {
				m := globalMatches[k]

				if m.SrcsContainsIPs(ips...) || (routed && m.SrcsOverlapsPrefixes(ri.subnet...)) {
					if srcOf[i] == nil {
						srcOf[i] = make([]uint64, words)
					}

					srcOf[i][k/64] |= 1 << (k % 64) //nolint:mnd
				}

				if m.DestsContainsIP(ips...) || (routed && m.DestsOverlapsPrefixes(ri.subnet...)) ||
					(ri.isExit && m.DestsIsTheInternet()) {
					if dstOf[i] == nil {
						dstOf[i] = make([]uint64, words)
					}

					dstOf[i][k/64] |= 1 << (k % 64) //nolint:mnd
				}
			}
		}

		canAccess := func(src, dst []uint64) bool {
			if src == nil || dst == nil {
				return false
			}

			for w := range src {
				if src[w]&dst[w] != 0 {
					return true
				}
			}

			return false
		}

		// Build the map of all peers according to the matchers.
		for i := range ids {
			for j := i + 1; j < len(ids); j++ {
				if ids[i] == ids[j] {
					continue
				}

				if canAccess(srcOf[i], dstOf[j]) || canAccess(srcOf[j], dstOf[i]) {
					ret[ids[i]] = append(ret[ids[i]], ids[j])
					ret[ids[j]] = append(ret[ids[j]], ids[i])
				}
			}
		}

		return ret
	}

	// For autogroup:self or via grants, build per-node peer relationships
	ret := make(map[types.NodeID][]types.NodeID, nodes.Len())

	// Pre-compute per-node matchers using unreduced compiled rules
	// We need unreduced rules to determine peer relationships correctly.
	// Reduced rules only show destinations where the node is the target,
	// but peer relationships require the full bidirectional access rules.
	nodeMatchers := make(map[types.NodeID][]referenceMatch, nodes.Len())
	for _, node := range nodes.All() {
		unreduced := legacyFilterRulesForNode(legacyGrants, node, legacyUsers)
		nodeMatchers[node.ID()] = referenceMatchesFromFilterRules(unreduced)
	}

	// Check each node pair for peer relationships.
	// Start j at i+1 to avoid checking the same pair twice and creating duplicates.
	// We use symmetric visibility: if EITHER node can access the other, BOTH see
	// each other. This matches the global filter path behavior and ensures that
	// one-way access rules (e.g., admin -> tagged server) still allow both nodes
	// to see each other as peers, which is required for network connectivity.
	for i := range nodes.Len() {
		nodeI := nodes.At(i)
		matchersI, hasFilterI := nodeMatchers[nodeI.ID()]
		riI := routeInfo[nodeI.ID()]

		for j := i + 1; j < nodes.Len(); j++ {
			nodeJ := nodes.At(j)
			matchersJ, hasFilterJ := nodeMatchers[nodeJ.ID()]
			riJ := routeInfo[nodeJ.ID()]

			// Check all access directions for symmetric peer visibility.
			// For via grants, filter rules exist on the via-designated node
			// (e.g., router-a) with sources being the client (group-a).
			// We need to check BOTH:
			//   1. nodeI.CanAccess(matchersI, nodeJ) — can nodeI reach nodeJ?
			//   2. nodeJ.CanAccess(matchersI, nodeI) — can nodeJ reach nodeI
			//      using nodeI's matchers? (reverse direction: the matchers
			//      on the via node accept traffic FROM the source)
			// Same for matchersJ in both directions.
			canIAccessJ := hasFilterI &&
				referenceCanAccessWithRoutes(
					nodeI,
					matchersI, nodeJ, riI.subnet, riJ.subnet, riJ.isExit,
				)
			canJAccessI := hasFilterJ &&
				referenceCanAccessWithRoutes(
					nodeJ,
					matchersJ, nodeI, riJ.subnet, riI.subnet, riI.isExit,
				)
			canJReachI := hasFilterI &&
				referenceCanAccessWithRoutes(
					nodeJ,
					matchersI, nodeI, riJ.subnet, riI.subnet, riI.isExit,
				)
			canIReachJ := hasFilterJ &&
				referenceCanAccessWithRoutes(
					nodeI,
					matchersJ, nodeJ, riI.subnet, riJ.subnet, riJ.isExit,
				)

			if canIAccessJ || canJAccessI || canJReachI || canIReachJ {
				ret[nodeI.ID()] = append(ret[nodeI.ID()], nodeJ.ID())
				ret[nodeJ.ID()] = append(ret[nodeJ.ID()], nodeI.ID())
			}
		}
	}

	return ret
}

func TestBuildPeerMapPerNodeInputs(t *testing.T) {
	users, nodes := benchNodes(70)
	reversed := append(types.Nodes(nil), nodes...)
	slices.Reverse(reversed)

	duplicate := nodes[1].View().AsStruct()
	duplicate.ID = nodes[0].ID

	for _, pol := range benchPolicies[1:] {
		t.Run(pol.name, func(t *testing.T) {
			pm, err := NewPolicyManager([]byte(pol.policy), users, nodes.ViewSlice())
			require.NoError(t, err)
			require.True(t, pm.needsPerNodeFilter)

			for _, tt := range []struct {
				name  string
				nodes types.Nodes
			}{
				{"empty", nil},
				{"full", nodes},
				{"reversed", reversed},
				{"subset", nodes[:25]},
				{"duplicate-id", append(append(types.Nodes(nil), nodes...), duplicate)},
				{"duplicate-view", append(append(types.Nodes(nil), nodes...), nodes[1])},
			} {
				t.Run(tt.name, func(t *testing.T) {
					in := tt.nodes.ViewSlice()
					want := buildPeerMapPerNodeReference(pm, in)
					require.Equal(t, want, pm.BuildPeerMap(in))
				})
			}
		})
	}
}

func TestBuildPeerMapPerNodeRuleOwnership(t *testing.T) {
	users := []types.User{{ID: 1, Name: "u1"}, {ID: 2, Name: "u2"}}
	nodes := types.Nodes{
		{
			ID: 1, IPv4: ap("100.64.0.1"), User: &users[0], UserID: &users[0].ID,
			Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{mp("10.1.0.0/24")}},
			ApprovedRoutes: []netip.Prefix{mp("10.1.0.0/24")},
		},
		{
			ID: 2, IPv4: ap("100.64.0.2"), User: &users[1], UserID: &users[1].ID,
			Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{mp("10.2.0.0/24")}},
			ApprovedRoutes: []netip.Prefix{mp("10.2.0.0/24")},
		},
		{
			ID: 3, IPv4: ap("100.64.0.3"), Tags: []string{"tag:router"},
			Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{mp("10.0.0.0/8")}},
			ApprovedRoutes: []netip.Prefix{mp("10.0.0.0/8")},
		},
		{
			ID: 4, IPv4: ap("100.64.0.4"), Tags: []string{"tag:other"},
			Hostinfo: &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{mp("10.3.0.0/24")}},
		},
		{
			ID: 5, IPv4: ap("100.64.0.5"), Tags: []string{"tag:other"},
			ApprovedRoutes: []netip.Prefix{mp("10.4.0.0/24")},
		},
	}
	pm, err := NewPolicyManager([]byte(`{
		"tagOwners": {"tag:other": [], "tag:router": []},
		"grants": [
			{"src": ["10.0.0.0/8"], "dst": ["10.0.0.0/8"],
			 "ip": ["*"], "via": ["tag:router"]},
			{"src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["*"]}
		]
	}`), users, nodes.ViewSlice())
	require.NoError(t, err)
	require.True(t, pm.needsPerNodeFilter)

	want := map[types.NodeID][]types.NodeID{1: {3}, 2: {3}, 3: {1, 2}}
	require.Equal(t, want, buildPeerMapPerNodeReference(pm, nodes.ViewSlice()))
	require.Equal(t, want, pm.BuildPeerMap(nodes.ViewSlice()))
}

func TestBuildPeerMapPerNodeInternet(t *testing.T) {
	for _, tt := range []struct {
		name        string
		dst         []string
		ipv6        bool
		compiledDst string
	}{
		{"internet", []string{"autogroup:internet"}, false, ""},
		{"merged-internet", []string{"autogroup:internet", "192.168.0.0/24"}, false, ""},
		{"ipv4-default", []string{"autogroup:internet"}, true, "0.0.0.0/0"},
		{"ipv6-default", []string{"autogroup:internet"}, false, "::/0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			user := types.User{ID: 1, Name: "u1"}
			exits := []netip.Prefix{mp("0.0.0.0/0"), mp("::/0")}

			private := mp("10.0.0.0/24")
			if tt.ipv6 {
				private = mp("fd00::/64")
			}

			nodes := types.Nodes{
				{ID: 1, User: &user, UserID: &user.ID},
				{
					ID: 2, User: &user, UserID: &user.ID, Tags: []string{"tag:exit"},
					Hostinfo: &tailcfg.Hostinfo{RoutableIPs: exits}, ApprovedRoutes: exits,
				},
				{
					ID: 3, Tags: []string{"tag:exit"},
					Hostinfo: &tailcfg.Hostinfo{RoutableIPs: exits},
				},
				{
					ID: 4, Tags: []string{"tag:router"},
					Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{private}},
					ApprovedRoutes: []netip.Prefix{private},
				},
			}
			for i, node := range nodes {
				if tt.ipv6 {
					node.IPv6 = ap(fmt.Sprintf("fd7a:115c:a1e0::%d", i+1))
				} else {
					node.IPv4 = ap(fmt.Sprintf("100.64.0.%d", i+1))
				}
			}

			policy := must(json.Marshal(map[string]any{
				"tagOwners": map[string][]string{"tag:exit": {}, "tag:router": {}},
				"grants": []map[string][]string{
					{"src": {"u1@"}, "dst": tt.dst, "ip": {"*"}},
					{"src": {"autogroup:member"}, "dst": {"autogroup:self"}, "ip": {"*"}},
				},
			}))
			pm, err := NewPolicyManager(policy, []types.User{user}, nodes.ViewSlice())
			require.NoError(t, err)
			require.True(t, pm.needsPerNodeFilter)

			if tt.compiledDst != "" {
				// The parser rejects explicit /0 aliases; test the legacy
				// compiled representation directly without changing parsing.
				pm.mu.Lock()

				g := pm.view.generation
				for i := range g.grants {
					for j := range g.grants[i].fragments {
						g.grants[i].fragments[j].destinations = []packetfilter.Destination{
							{
								Addresses: singletonPrefix(
									netip.MustParsePrefix(tt.compiledDst),
								),
								Ports: tailcfg.PortRangeAny,
							},
						}
					}
				}

				g.peer = g.buildRuleIndex(g.nodes, false)
				pm.mu.Unlock()
			}

			want := map[types.NodeID][]types.NodeID{1: {2}, 2: {1}}

			if tt.compiledDst == "" {
				if tt.compiledDst == "" {
					require.Equal(
						t,
						want,
						buildPeerMapPerNodeReference(pm, nodes.ViewSlice()),
					)
				}
			}

			require.Equal(t, want, pm.BuildPeerMap(nodes.ViewSlice()))
		})
	}
}

func TestBuildPeerMapPerNodeCapabilityOnly(t *testing.T) {
	users := []types.User{{ID: 1, Name: "u1"}, {ID: 2, Name: "u2"}}
	nodes := types.Nodes{
		{ID: 1, IPv4: ap("100.64.0.1"), User: &users[0], UserID: &users[0].ID},
		{
			ID: 2, IPv4: ap("100.64.0.2"), Tags: []string{"tag:server"},
			User: &users[0], UserID: &users[0].ID,
		},
		{ID: 3, IPv4: ap("100.64.0.3"), User: &users[1], UserID: &users[1].ID},
		{
			ID: 4, IPv4: ap("100.64.0.4"), Tags: []string{"tag:other"},
			User: &users[0], UserID: &users[0].ID,
		},
	}
	pm, err := NewPolicyManager([]byte(`{
		"tagOwners": {"tag:server": [], "tag:other": []},
		"grants": [
			{"src": ["u1@"], "dst": ["tag:server"],
			 "app": {"example.com/cap/test": [{"role": "read"}]}},
			{"src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["*"]}
		]
	}`), users, nodes.ViewSlice())
	require.NoError(t, err)
	require.True(t, pm.needsPerNodeFilter)

	want := map[types.NodeID][]types.NodeID{1: {2}, 2: {1}}
	require.Equal(t, want, buildPeerMapPerNodeReference(pm, nodes.ViewSlice()))
	require.Equal(t, want, pm.BuildPeerMap(nodes.ViewSlice()))
}

func TestBuildPeerMapPerNodeWordBoundaries(t *testing.T) {
	for _, n := range []int{1, 63, 64, 65, 127, 128, 129} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			user := types.User{ID: 1, Name: "u1"}

			_, nodes := benchNodes(n)
			for _, node := range nodes {
				node.Tags = nil
				node.User, node.UserID = &user, &user.ID
			}

			pm, err := NewPolicyManager([]byte(benchPolicies[1].policy), []types.User{user}, nodes.ViewSlice())
			require.NoError(t, err)

			got := pm.BuildPeerMap(nodes.ViewSlice())
			require.Equal(t, buildPeerMapPerNodeReference(pm, nodes.ViewSlice()), got)

			for _, node := range nodes {
				var peers []types.NodeID

				for _, other := range nodes {
					if other.ID != node.ID {
						peers = append(peers, other.ID)
					}
				}

				require.Equal(t, peers, got[node.ID])
			}
		})
	}
}

func TestBuildPeerMapPerNodeStaleViews(t *testing.T) {
	for _, pol := range benchPolicies[1:] {
		t.Run(pol.name, func(t *testing.T) {
			users, nodes := benchNodes(70)
			pm, err := NewPolicyManager([]byte(pol.policy), users, nodes.ViewSlice())
			require.NoError(t, err)

			old := nodes.ViewSlice()

			updated := make(types.Nodes, len(nodes))
			for i, node := range nodes {
				updated[i] = node.View().AsStruct()
			}

			updated[1].User, updated[1].UserID = &users[2], &users[2].ID
			updated[2].Tags = []string{"tag:srv"}
			updated[20].ApprovedRoutes = nil
			_, err = pm.SetNodes(updated.ViewSlice())
			require.NoError(t, err)

			for _, in := range []views.Slice[types.NodeView]{old, updated.ViewSlice()} {
				require.Equal(t, buildPeerMapPerNodeReference(pm, in), pm.BuildPeerMap(in))
			}
		})
	}
}

// BenchmarkBuildPeerMapPerNodeIndexesWarm excludes generation construction.
func BenchmarkBuildPeerMapPerNodeIndexesWarm(b *testing.B) {
	for _, pol := range benchPolicies[1:] {
		for _, n := range []int{100, 300, 1000} {
			users, nodes := benchNodes(n)
			pm, err := NewPolicyManager([]byte(pol.policy), users, nodes.ViewSlice())
			require.NoError(b, err)
			require.True(b, pm.needsPerNodeFilter)
			require.Equal(b, buildPeerMapPerNodeReference(pm, nodes.ViewSlice()), pm.BuildPeerMap(nodes.ViewSlice()))

			b.Run(fmt.Sprintf("%s/n=%d", pol.name, n), func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					pm.BuildPeerMap(nodes.ViewSlice())
				}
			})
		}
	}
}

func BenchmarkBuildPeerMapSelfOwnershipWarm(b *testing.B) {
	for _, userCount := range []int{1, 10, 1000} {
		users := make([]types.User, userCount)
		for i := range users {
			users[i] = types.User{ID: uint(i + 1), Name: fmt.Sprintf("u%d", i+1)}
		}

		_, nodes := benchNodes(1000)
		for i, node := range nodes {
			u := &users[i%len(users)]
			node.Tags = nil
			node.User, node.UserID = u, &u.ID
		}

		pm, err := NewPolicyManager([]byte(benchPolicies[1].policy), users, nodes.ViewSlice())
		require.NoError(b, err)
		require.True(b, pm.needsPerNodeFilter)
		require.Equal(b, buildPeerMapPerNodeReference(pm, nodes.ViewSlice()), pm.BuildPeerMap(nodes.ViewSlice()))

		b.Run(fmt.Sprintf("n=1000/users=%d", userCount), func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				pm.BuildPeerMap(nodes.ViewSlice())
			}
		})
	}
}
