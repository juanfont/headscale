package matcher

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
)

type Match struct {
	srcs  *netipx.IPSet
	dests *netipx.IPSet

	srcRanges  []netipx.IPRange
	destRanges []netipx.IPRange
}

func newMatch(srcs, dests *netipx.IPSet) Match {
	return Match{
		srcs:       srcs,
		dests:      dests,
		srcRanges:  srcs.Ranges(),
		destRanges: dests.Ranges(),
	}
}

func (m *Match) DebugString() string {
	var sb strings.Builder

	sb.WriteString("Match:\n")
	sb.WriteString("  Sources:\n")

	for _, prefix := range m.srcs.Prefixes() {
		sb.WriteString("    " + prefix.String() + "\n")
	}

	sb.WriteString("  Destinations:\n")

	for _, prefix := range m.dests.Prefixes() {
		sb.WriteString("    " + prefix.String() + "\n")
	}

	return sb.String()
}

func MatchesFromFilterRules(rules []tailcfg.FilterRule) []Match {
	matches := make([]Match, 0, len(rules))
	for _, rule := range rules {
		matches = append(matches, MatchFromFilterRule(rule))
	}

	return matches
}

// MatchFromFilterRule derives a [Match] from a [tailcfg.FilterRule]. The
// destination IP set is the union of [tailcfg.FilterRule.DstPorts][].IP
// and [tailcfg.FilterRule.CapGrant][].Dsts: cap-grant-only rules (e.g.
// tailscale.com/cap/relay) carry their destinations in CapGrant.Dsts and
// would otherwise contribute nothing to peer-visibility derivation in
// [policy.ReduceNodes], hiding the cap target
// from the source unless a companion IP-level rule also exists.
func MatchFromFilterRule(rule tailcfg.FilterRule) Match {
	dests := new(netipx.IPSetBuilder)

	for _, dp := range rule.DstPorts {
		set, _ := util.ParseIPSet(dp.IP, nil)
		dests.AddSet(set)
	}

	for _, cg := range rule.CapGrant {
		for _, pref := range cg.Dsts {
			dests.AddPrefix(pref)
		}
	}

	destsSet, _ := dests.IPSet()

	return newMatch(buildIPSet(rule.SrcIPs), destsSet)
}

// buildIPSet parses each string via [util.ParseIPSet] and unions the
// results into a single [netipx.IPSet]. Unparseable entries are silently
// dropped (fail-open): the result is narrower than the input described,
// but never wider.
func buildIPSet(addrs []string) *netipx.IPSet {
	builder := new(netipx.IPSetBuilder)

	for _, addr := range addrs {
		set, _ := util.ParseIPSet(addr, nil)
		builder.AddSet(set)
	}

	set, _ := builder.IPSet()

	return set
}

func (m *Match) SrcsContainsIPs(ips ...netip.Addr) bool {
	return slices.ContainsFunc(ips, m.srcs.Contains)
}

func (m *Match) DestsContainsIP(ips ...netip.Addr) bool {
	return slices.ContainsFunc(ips, m.dests.Contains)
}

func (m *Match) SrcsOverlapsPrefixes(prefixes ...netip.Prefix) bool {
	return slices.ContainsFunc(prefixes, func(prefix netip.Prefix) bool {
		return overlaps(m.srcRanges, netipx.RangeOfPrefix(prefix))
	})
}

func (m *Match) DestsOverlapsPrefixes(prefixes ...netip.Prefix) bool {
	return slices.ContainsFunc(prefixes, func(prefix netip.Prefix) bool {
		return overlaps(m.destRanges, netipx.RangeOfPrefix(prefix))
	})
}

// SrcsOverlapsRanges reports whether the sources overlap sorted, disjoint ranges.
func (m *Match) SrcsOverlapsRanges(ranges []netipx.IPRange) bool {
	return rangesOverlap(m.srcRanges, ranges)
}

// DestsOverlapsRanges reports whether the destinations overlap sorted, disjoint ranges.
func (m *Match) DestsOverlapsRanges(ranges []netipx.IPRange) bool {
	return rangesOverlap(m.destRanges, ranges)
}

func rangesOverlap(a, b []netipx.IPRange) bool {
	if len(a) > len(b) {
		a, b = b, a
	}

	return slices.ContainsFunc(a, func(r netipx.IPRange) bool {
		return overlaps(b, r)
	})
}

func overlaps(ranges []netipx.IPRange, r netipx.IPRange) bool {
	if !r.IsValid() {
		return false
	}

	i, _ := slices.BinarySearchFunc(ranges, r.From(),
		func(x netipx.IPRange, a netip.Addr) int {
			return x.To().Compare(a)
		})

	return i < len(ranges) && ranges[i].Overlaps(r)
}

// DestsIsTheInternet reports whether the destination covers "the
// internet" — the set represented by autogroup:internet, special-cased
// for exit nodes. See [util.CoversTheInternet].
func (m *Match) DestsIsTheInternet() bool {
	return util.CoversTheInternet(m.dests)
}
