package util

import (
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"strings"

	"go4.org/netipx"
)

// This is borrowed from, and updated to use [netipx.IPSet]
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
func ParseIPSet(arg string, bits *int) (*netipx.IPSet, error) {
	var ipSet netipx.IPSetBuilder
	if arg == "*" {
		ipSet.AddPrefix(netip.PrefixFrom(netip.IPv4Unspecified(), 0))
		ipSet.AddPrefix(netip.PrefixFrom(netip.IPv6Unspecified(), 0))

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

// ParseIPRange errors.
var (
	ErrPrefixHostBits   = errors.New("prefix contains non-network bits set")
	ErrInvalidIPAddress = errors.New("invalid IP address")
)

// ParseIPRange parses what [ParseIPSet] accepts, apart from "*", as the single
// range it denotes, without building a set.
func ParseIPRange(arg string) (netipx.IPRange, error) {
	if strings.Contains(arg, "/") {
		pfx, err := netip.ParsePrefix(arg)
		if err != nil {
			return netipx.IPRange{}, err
		}

		if pfx != pfx.Masked() {
			return netipx.IPRange{}, fmt.Errorf("%w: %v", ErrPrefixHostBits, pfx)
		}

		return netipx.RangeOfPrefix(pfx), nil
	}

	if strings.Count(arg, "-") == 1 {
		return netipx.ParseIPRange(arg)
	}

	ip, err := netip.ParseAddr(arg)
	if err != nil {
		return netipx.IPRange{}, fmt.Errorf("%w: %q", ErrInvalidIPAddress, arg)
	}

	r := netipx.IPRangeFrom(ip, ip)
	if !r.IsValid() {
		return netipx.IPRange{}, fmt.Errorf("%w: %q", ErrInvalidIPAddress, arg)
	}

	return r, nil
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

var ErrRouteHostBits = errors.New("has non-address bits set")

// CheckRouteMasked refuses a route with bits set past its length: routes are
// matched as written, so it would never equal the masked prefix a client
// announces.
func CheckRouteMasked(p netip.Prefix) error {
	if masked := p.Masked(); p != masked {
		return fmt.Errorf("%w; expected %s", ErrRouteHostBits, masked)
	}

	return nil
}

// IPSetAddrIter returns a function that iterates over all the IPs in the [netipx.IPSet].
func IPSetAddrIter(ipSet *netipx.IPSet) iter.Seq[netip.Addr] {
	return func(yield func(netip.Addr) bool) {
		for _, rng := range ipSet.Ranges() {
			for ip := rng.From(); ip.Compare(rng.To()) <= 0; ip = ip.Next() {
				if !yield(ip) {
					return
				}
			}
		}
	}
}
