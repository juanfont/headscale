package funnel

import (
	"fmt"
	"net"
	"time"

	"github.com/pires/go-proxyproto"
)

// DefaultProxyHeaderTimeout bounds reading a PROXY protocol header.
const DefaultProxyHeaderTimeout = 10 * time.Second

// ProxyProtocolListener wraps ln for a relay behind a proxy that routes
// by SNI without terminating TLS. Connections from trusted, a list of IP
// addresses or CIDR ranges, must start with a PROXY protocol header (v1
// or v2), whose client address the relay then passes to the node;
// connections from any other address are dropped. Without the header,
// the node would see the proxy's address as the client's.
func ProxyProtocolListener(ln net.Listener, trusted []string) (net.Listener, error) {
	policy, err := proxyproto.TrustProxyHeaderFromRanges(trusted)
	if err != nil {
		return nil, fmt.Errorf("PROXY protocol trusted sources: %w", err)
	}

	return &proxyproto.Listener{
		Listener:          ln,
		ConnPolicy:        policy,
		ReadHeaderTimeout: DefaultProxyHeaderTimeout,
	}, nil
}
