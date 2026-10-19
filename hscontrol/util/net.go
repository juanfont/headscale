package util

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/juanfont/headscale/hscontrol/ipset"
	"tailscale.com/net/tsaddr"
)

// SocketDialer dials a local unix-domain socket, letting the HTTP CLI client
// reach the headscale API over its unix socket.
func SocketDialer(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer

	return d.DialContext(ctx, "unix", addr)
}

func PrefixesToString(prefixes []netip.Prefix) []string {
	ret := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		ret = append(ret, prefix.String())
	}

	return ret
}

func MustStringsToPrefixes(strings []string) []netip.Prefix {
	prefixes, err := StringToIPPrefix(strings)
	if err != nil {
		panic(err)
	}

	return prefixes
}

// TheInternet returns the [ipset.Set] for the Internet.
// https://www.youtube.com/watch?v=iDbyYGrswtg
var TheInternet = sync.OnceValue(func() ipset.Set {
	var internetBuilder, exclusions ipset.Builder
	internetBuilder.AddPrefix(netip.MustParsePrefix("2000::/3"))
	internetBuilder.AddPrefix(tsaddr.AllIPv4())

	// Delete Private network addresses
	// https://datatracker.ietf.org/doc/html/rfc1918
	exclusions.AddPrefix(netip.MustParsePrefix("fc00::/7"))
	exclusions.AddPrefix(netip.MustParsePrefix("10.0.0.0/8"))
	exclusions.AddPrefix(netip.MustParsePrefix("172.16.0.0/12"))
	exclusions.AddPrefix(netip.MustParsePrefix("192.168.0.0/16"))

	// Delete Tailscale networks
	exclusions.AddPrefix(tsaddr.TailscaleULARange())
	exclusions.AddPrefix(tsaddr.CGNATRange())

	// Delete "can't find DHCP networks"
	exclusions.AddPrefix(netip.MustParsePrefix("fe80::/10")) // link-local
	exclusions.AddPrefix(netip.MustParsePrefix("169.254.0.0/16"))

	theInternetSet, _ := internetBuilder.Build()
	excluded, _ := exclusions.Build()

	return theInternetSet.Subtract(excluded)
})

// Tailnet returns the Tailscale address ranges excluding ChromeOS VM addresses.
var Tailnet = sync.OnceValue(func() ipset.Set {
	var addresses, exclusions ipset.Builder
	addresses.AddPrefix(tsaddr.TailscaleULARange())
	addresses.AddPrefix(tsaddr.CGNATRange())
	exclusions.AddPrefix(tsaddr.ChromeOSVMRange())

	tailnet, _ := addresses.Build()
	chromeOS, _ := exclusions.Build()

	return tailnet.Subtract(chromeOS)
})
