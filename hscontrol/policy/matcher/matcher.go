package matcher

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
)

type Match struct {
	srcs  *netipx.IPSet
	dests *netipx.IPSet
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

func MatchFromFilterRule(rule tailcfg.FilterRule) Match {
	dests := make([]string, 0, len(rule.DstPorts))
	for _, dest := range rule.DstPorts {
		dests = append(dests, dest.IP)
	}

	return MatchFromStrings(rule.SrcIPs, dests)
}

// MatchFromStrings builds a Match from raw source and destination
// strings. Unparseable entries are silently dropped (fail-open): the
// resulting Match is narrower than the input described, but never
// wider. Callers that need strict validation should pre-validate
// their inputs via util.ParseIPSet.
func MatchFromStrings(sources, destinations []string) Match {
	srcs := new(netipx.IPSetBuilder)
	dests := new(netipx.IPSetBuilder)

	for _, srcIP := range sources {
		set, _ := util.ParseIPSet(srcIP, nil)

		srcs.AddSet(set)
	}

	for _, dest := range destinations {
		set, _ := util.ParseIPSet(dest, nil)

		dests.AddSet(set)
	}

	srcsSet, _ := srcs.IPSet()
	destsSet, _ := dests.IPSet()

	match := Match{
		srcs:  srcsSet,
		dests: destsSet,
	}

	return match
}

func (m *Match) SrcsContainsIPs(ips ...netip.Addr) bool {
	return slices.ContainsFunc(ips, m.srcs.Contains)
}

func (m *Match) DestsContainsIP(ips ...netip.Addr) bool {
	return slices.ContainsFunc(ips, m.dests.Contains)
}

func (m *Match) SrcsOverlapsPrefixes(prefixes ...netip.Prefix) bool {
	return slices.ContainsFunc(prefixes, m.srcs.OverlapsPrefix)
}

func (m *Match) DestsOverlapsPrefixes(prefixes ...netip.Prefix) bool {
	return slices.ContainsFunc(prefixes, m.dests.OverlapsPrefix)
}

// DestsIsTheInternet reports whether the destination covers "the
// internet" — the set represented by autogroup:internet, special-cased
// for exit nodes. Returns true if either family's /0 is contained
// (0.0.0.0/0 or ::/0), or if dests is a superset of TheInternet(). A
// single-family /0 counts because operators may write it directly and
// it still denotes the whole internet for that family.
func (m *Match) DestsIsTheInternet() bool {
	if m.dests.ContainsPrefix(tsaddr.AllIPv4()) ||
		m.dests.ContainsPrefix(tsaddr.AllIPv6()) {
		return true
	}

	// Superset-of-TheInternet check handles merged filter rules
	// where the internet prefixes are combined with other dests.
	theInternet := util.TheInternet()
	for _, prefix := range theInternet.Prefixes() {
		if !m.dests.ContainsPrefix(prefix) {
			return false
		}
	}

	return true
}
