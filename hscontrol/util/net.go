package util

import (
	"cmp"
	"context"
	"net"
	"net/netip"
)

func GrpcSocketDialer(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer

	return d.DialContext(ctx, "unix", addr)
}

// TODO(kradalby): Remove when in stdlib;
// https://github.com/golang/go/issues/61642
// Compare returns an integer comparing two prefixes.
// The result will be 0 if p == p2, -1 if p < p2, and +1 if p > p2.
// Prefixes sort first by validity (invalid before valid), then
// address family (IPv4 before IPv6), then prefix length, then
// address.
func ComparePrefix(p, p2 netip.Prefix) int {
	if c := cmp.Compare(p.Addr().BitLen(), p2.Addr().BitLen()); c != 0 {
		return c
	}
	if c := cmp.Compare(p.Bits(), p2.Bits()); c != 0 {
		return c
	}

	return p.Addr().Compare(p2.Addr())
}

func PrefixesToString(prefixes []netip.Prefix) []string {
	ret := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		ret = append(ret, prefix.String())
	}

	return ret
}

func MustStringsToPrefixes(strings []string) []netip.Prefix {
	ret := make([]netip.Prefix, 0, len(strings))
	for _, str := range strings {
		prefix := netip.MustParsePrefix(str)
		ret = append(ret, prefix)
	}

	return ret
}
