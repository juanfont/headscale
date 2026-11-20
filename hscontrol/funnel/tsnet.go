package funnel

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"tailscale.com/client/local"
	"tailscale.com/tsnet"
)

// TSNetBackend is a [Backend] over an embedded tsnet node: it reads the
// node's status and dials through its netstack.
type TSNetBackend struct {
	*local.Client

	srv *tsnet.Server
}

// NewTSNetBackend returns the [Backend] of srv, which must be up.
func NewTSNetBackend(srv *tsnet.Server) (*TSNetBackend, error) {
	lc, err := srv.LocalClient()
	if err != nil {
		return nil, fmt.Errorf("embedded node client: %w", err)
	}

	return &TSNetBackend{Client: lc, srv: srv}, nil
}

// DialTCP dials host:port through the tsnet node.
func (b *TSNetBackend) DialTCP(ctx context.Context, host string, port uint16) (net.Conn, error) {
	return b.srv.Dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
}
