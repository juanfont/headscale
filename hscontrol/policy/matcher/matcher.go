package matcher

import (
	"net/netip"

	"slices"

	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
)

type Match struct {
	srcs  *netipx.IPSet
	dests *netipx.IPSet
}

func MatchesFromFilterRules(rules []tailcfg.FilterRule) []Match {
	matches := make([]Match, 0, len(rules))
	for _, rule := range rules {
		matches = append(matches, MatchFromFilterRule(rule))
	}
	return matches
}

func MatchFromFilterRule(rule tailcfg.FilterRule) Match {
	dests := []string{}
	for _, dest := range rule.DstPorts {
		dests = append(dests, dest.IP)
	}

	return MatchFromStrings(rule.SrcIPs, dests)
}

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
