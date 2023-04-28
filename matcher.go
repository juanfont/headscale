package headscale

import (
	"fmt"
	"net/netip"
	"strings"

	"go4.org/netipx"
	"tailscale.com/tailcfg"
)

// This is borrowed from, and updated to use IPSet
// https://github.com/tailscale/tailscale/blob/71029cea2ddf82007b80f465b256d027eab0f02d/wgengine/filter/tailcfg.go#L97-L162
// TODO(kradalby): contribute upstream and make public.
var (
	zeroIP4 = netip.AddrFrom4([4]byte{})
	zeroIP6 = netip.AddrFrom16([16]byte{})
)

// parseIPSet parses arg as one:
//
//   - an IP address (IPv4 or IPv6)
//   - the string "*" to match everything (both IPv4 & IPv6)
//   - a CIDR (e.g. "192.168.0.0/16")
//   - a range of two IPs, inclusive, separated by hyphen ("2eff::1-2eff::0800")
//
// bits, if non-nil, is the legacy SrcBits CIDR length to make a IP
// address (without a slash) treated as a CIDR of *bits length.
// nolint
func parseIPSet(arg string, bits *int) (*netipx.IPSet, error) {
	var ipSet netipx.IPSetBuilder
	if arg == "*" {
		ipSet.AddPrefix(netip.PrefixFrom(zeroIP4, 0))
		ipSet.AddPrefix(netip.PrefixFrom(zeroIP6, 0))

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

type Match struct {
	Srcs  *netipx.IPSet
	Dests *netipx.IPSet
}

func MatchFromFilterRule(rule tailcfg.FilterRule) Match {
	srcs := new(netipx.IPSetBuilder)
	dests := new(netipx.IPSetBuilder)

	for _, srcIP := range rule.SrcIPs {
		set, _ := parseIPSet(srcIP, nil)

		srcs.AddSet(set)
	}

	for _, dest := range rule.DstPorts {
		set, _ := parseIPSet(dest.IP, nil)

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
