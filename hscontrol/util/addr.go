package util

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/gaissmai/iprange"
	"github.com/juanfont/headscale/hscontrol/ipset"
	"go4.org/netipx"
)

// This is borrowed from, and updated to use [ipset.Set]
// https://github.com/tailscale/tailscale/blob/71029cea2ddf82007b80f465b256d027eab0f02d/wgengine/filter/tailcfg.go#L97-L162
// TODO(kradalby): contribute upstream and make public.

// parseIPSet parses arg as one:
//
//   - an IP address (IPv4 or IPv6)
//   - the string "*" to match everything (both IPv4 & IPv6)
//   - a CIDR (e.g. "192.168.0.0/16")
//   - a range of two IPs, inclusive, separated by hyphen ("2eff::1-2eff::0800")
//
// bits, if non-nil, is the legacy [tailcfg.FilterRule.SrcBits] CIDR length to make a IP
// address (without a slash) treated as a CIDR of *bits length.
// nolint
func ParseIPSet(arg string, bits *int) (ipset.Set, error) {
	var ipSet ipset.Builder
	if arg == "*" {
		return ipset.All(), nil
	}
	if strings.Contains(arg, "/") {
		pfx, err := netip.ParsePrefix(arg)
		if err != nil {
			return ipset.Set{}, err
		}
		if pfx != pfx.Masked() {
			return ipset.Set{}, fmt.Errorf("%v contains non-network bits set", pfx)
		}

		ipSet.AddPrefix(pfx)

		return ipSet.Build()
	}
	if strings.Count(arg, "-") == 1 {
		ip1s, ip2s, _ := strings.Cut(arg, "-")

		ip1, err := netip.ParseAddr(ip1s)
		if err != nil {
			return ipset.Set{}, err
		}

		ip2, err := netip.ParseAddr(ip2s)
		if err != nil {
			return ipset.Set{}, err
		}

		r, err := iprange.FromAddrs(ip1.WithZone(""), ip2.WithZone(""))
		if err != nil {
			return ipset.Set{}, fmt.Errorf("invalid IP range %q", arg)
		}

		ipSet.AddRange(r)

		return ipSet.Build()
	}
	ip, err := netip.ParseAddr(arg)
	if err != nil {
		return ipset.Set{}, fmt.Errorf("invalid IP address %q", arg)
	}
	bits8 := uint8(ip.BitLen())
	if bits != nil {
		if *bits < 0 || *bits > int(bits8) {
			return ipset.Set{}, fmt.Errorf("invalid CIDR size %d for IP %q", *bits, arg)
		}
		bits8 = uint8(*bits)
	}

	ipSet.AddPrefix(netip.PrefixFrom(ip, int(bits8)))

	return ipSet.Build()
}

func GetIPPrefixEndpoints(na netip.Prefix) (netip.Addr, netip.Addr) {
	ipRange := netipx.RangeOfPrefix(na)

	return ipRange.From(), ipRange.To()
}

func StringToIPPrefix(prefixes []string) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, len(prefixes))

	for index, prefixStr := range prefixes {
		prefix, err := netip.ParsePrefix(prefixStr)
		if err != nil {
			return nil, err
		}

		result[index] = prefix
	}

	return result, nil
}
