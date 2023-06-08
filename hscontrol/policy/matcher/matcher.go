package matcher

import (
	"net/netip"

	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
)

type Match struct {
	Srcs  *netipx.IPSet
	Dests *netipx.IPSet
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
		Srcs:  srcsSet,
		Dests: destsSet,
	}

	return match
}

func (m *Match) SrcsContainsIPs(ips []netip.Addr) bool {
	for _, ip := range ips {
		if m.Srcs.Contains(ip) {
			return true
		}
	}

	return false
}

func (m *Match) DestsContainsIP(ips []netip.Addr) bool {
	for _, ip := range ips {
		if m.Dests.Contains(ip) {
			return true
		}
	}

	return false
}
