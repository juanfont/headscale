package util

import (
	"context"
	"net"
	"net/netip"

	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
)

func GrpcSocketDialer(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer

	return d.DialContext(ctx, "unix", addr)
}


var theInternetSet *netipx.IPSet

// TheInternet returns the IPSet for the Internet.
// https://www.youtube.com/watch?v=iDbyYGrswtg
func TheInternet() *netipx.IPSet {
	if theInternetSet != nil {
		return theInternetSet
	}

	var internetBuilder netipx.IPSetBuilder
	internetBuilder.AddPrefix(netip.MustParsePrefix("2000::/3"))
	internetBuilder.AddPrefix(tsaddr.AllIPv4())

	// Delete Private network addresses
	// https://datatracker.ietf.org/doc/html/rfc1918
	internetBuilder.RemovePrefix(netip.MustParsePrefix("fc00::/7"))
	internetBuilder.RemovePrefix(netip.MustParsePrefix("10.0.0.0/8"))
	internetBuilder.RemovePrefix(netip.MustParsePrefix("172.16.0.0/12"))
	internetBuilder.RemovePrefix(netip.MustParsePrefix("192.168.0.0/16"))

	// Delete Tailscale networks
	internetBuilder.RemovePrefix(tsaddr.TailscaleULARange())
	internetBuilder.RemovePrefix(tsaddr.CGNATRange())

	// Delete "can't find DHCP networks"
	internetBuilder.RemovePrefix(netip.MustParsePrefix("fe80::/10")) // link-local
	internetBuilder.RemovePrefix(netip.MustParsePrefix("169.254.0.0/16"))

	theInternetSet, _ := internetBuilder.IPSet()
	return theInternetSet
}
