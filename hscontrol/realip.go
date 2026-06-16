package hscontrol

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"

	realclientip "github.com/realclientip/realclientip-go"
)

const (
	headerTrueClientIP  = "True-Client-IP"
	headerXRealIP       = "X-Real-IP"
	headerXForwardedFor = "X-Forwarded-For"
)

var proxyHeaders = [...]string{headerTrueClientIP, headerXRealIP, headerXForwardedFor}

// trustedProxyRealIP rewrites r.RemoteAddr from proxy headers when the
// peer is in trusted; for any other peer the headers are stripped so a
// downstream handler cannot read a spoofed value. X-Forwarded-For uses
// [realclientip.RightmostTrustedRangeStrategy] so prepending a value cannot win in a
// proxy chain.
func trustedProxyRealIP(trusted []netip.Prefix) (func(http.Handler) http.Handler, error) {
	ranges := make([]net.IPNet, 0, len(trusted))
	for _, p := range trusted {
		ranges = append(ranges, prefixToIPNet(p))
	}

	trueClientIP, err := realclientip.NewSingleIPHeaderStrategy(headerTrueClientIP)
	if err != nil {
		return nil, fmt.Errorf("%s strategy: %w", headerTrueClientIP, err)
	}

	xRealIP, err := realclientip.NewSingleIPHeaderStrategy(headerXRealIP)
	if err != nil {
		return nil, fmt.Errorf("%s strategy: %w", headerXRealIP, err)
	}

	xForwardedFor, err := realclientip.NewRightmostTrustedRangeStrategy(headerXForwardedFor, ranges)
	if err != nil {
		return nil, fmt.Errorf("%s strategy: %w", headerXForwardedFor, err)
	}

	strategy := realclientip.NewChainStrategy(trueClientIP, xRealIP, xForwardedFor)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !peerTrusted(r.RemoteAddr, trusted) {
				for _, h := range proxyHeaders {
					r.Header.Del(h)
				}

				next.ServeHTTP(w, r)

				return
			}

			// Proxy headers carry no port; write the IP alone so
			// `remote=` logs the resolved client, not the proxy's
			// ephemeral TCP port.
			if ip := strategy.ClientIP(r.Header, r.RemoteAddr); ip != "" {
				r.RemoteAddr = ip
			}

			next.ServeHTTP(w, r)
		})
	}, nil
}

// peerTrusted returns false on unparseable input so callers fall
// through to the header-stripping path.
func peerTrusted(remoteAddr string, trusted []netip.Prefix) bool {
	addr, ok := parsePeerAddr(remoteAddr)
	if !ok {
		return false
	}

	return slices.ContainsFunc(trusted, func(p netip.Prefix) bool {
		return p.Contains(addr)
	})
}

func parsePeerAddr(remoteAddr string) (netip.Addr, bool) {
	if remoteAddr == "" {
		return netip.Addr{}, false
	}

	ap, err := netip.ParseAddrPort(remoteAddr)
	if err == nil {
		return ap.Addr(), true
	}

	host, _, splitErr := net.SplitHostPort(remoteAddr)
	if splitErr != nil {
		host = remoteAddr
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}

	return addr, true
}

// prefixToIPNet bridges to realclientip-go, which predates net/netip.
func prefixToIPNet(p netip.Prefix) net.IPNet {
	addr := p.Addr()
	if addr.Is4() {
		b := addr.As4()

		return net.IPNet{IP: b[:], Mask: net.CIDRMask(p.Bits(), 32)}
	}

	b := addr.As16()

	return net.IPNet{IP: b[:], Mask: net.CIDRMask(p.Bits(), 128)}
}
