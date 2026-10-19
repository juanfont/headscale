package util

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/gaissmai/iprange"
	"github.com/juanfont/headscale/hscontrol/ipset"
)

// ParseIPSet decodes legacy filter-address syntax for compatibility tests.
// Runtime policy processing resolves typed aliases directly.
//
// It accepts an address, "*", a CIDR, or an inclusive "first-last" range.
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
