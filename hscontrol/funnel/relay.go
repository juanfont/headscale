// Package funnel implements a Tailscale Funnel relay.
//
// A relay is an ordinary tailnet node carrying one of the tags in the
// server's funnel.relay_tags. It accepts TLS connections from the
// internet on the funnel ports, reads the server name (SNI) from the
// ClientHello without terminating TLS, and hands the untouched stream to
// the node of that name through its peerapi ingress endpoint
// (POST /v0/ingress), the protocol Tailscale's own funnel ingress nodes
// speak. The node terminates TLS with its own certificate and checks that
// it funnels that name and port, so the relay never sees the content.
//
// The relay reaches the tailnet through a [Backend]: an embedded tsnet
// node, or the tailscaled already running on the machine.
package funnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"tailscale.com/ipn/ipnstate"
)

// Backend is the relay's access to the tailnet. [*local.Client] from
// tailscale.com/client/local satisfies it, for a relay using the
// tailscaled running on the machine.
type Backend interface {
	// Status returns the tailnet status, with peers.
	Status(ctx context.Context) (*ipnstate.Status, error)
	// DialTCP dials a tailnet address.
	DialTCP(ctx context.Context, host string, port uint16) (net.Conn, error)
}

// Defaults for [Relay] fields left zero.
const (
	DefaultHelloTimeout = 10 * time.Second
	DefaultDialTimeout  = 10 * time.Second
	DefaultMaxHelloSize = 16 << 10
	DefaultStatusTTL    = 5 * time.Second
)

var (
	errNoSNI      = errors.New("ClientHello without server name")
	errHelloRead  = errors.New("ClientHello read")
	errNoPeer     = errors.New("no node with that name")
	errNoPeerAPI  = errors.New("node has no peerapi address")
	errNotRelayed = errors.New("node refused the ingress request")
)

// Relay forwards funnel connections to tailnet nodes. Its zero value,
// with a Backend, is ready to use.
type Relay struct {
	Backend Backend

	// HelloTimeout bounds reading the ClientHello.
	HelloTimeout time.Duration
	// DialTimeout bounds reaching the node and its ingress answer.
	DialTimeout time.Duration
	// MaxHelloSize bounds the bytes read before the server name is known.
	MaxHelloSize int64
	// StatusTTL is how long a tailnet status serves name lookups.
	StatusTTL time.Duration

	mu       sync.Mutex
	status   *ipnstate.Status
	statusAt time.Time
}

// Serve accepts connections on ln, the listener of public port port,
// until ln is closed or ctx is done.
func (r *Relay) Serve(ctx context.Context, ln net.Listener, port uint16) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil //nolint:nilerr // closed on purpose
			}

			return fmt.Errorf("accepting on port %d: %w", port, err)
		}

		go func() {
			err := r.Handle(ctx, c, port)
			if err != nil {
				log.Debug().Err(err).Str("remote", c.RemoteAddr().String()).Uint16("port", port).Msg("funnel connection dropped")
			}
		}()
	}
}

// Handle relays one connection that arrived on public port port. It
// closes c.
func (r *Relay) Handle(ctx context.Context, c net.Conn, port uint16) error {
	defer c.Close()

	src, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return fmt.Errorf("client address: %w", err)
	}

	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())

	_ = c.SetReadDeadline(time.Now().Add(orDefault(r.HelloTimeout, DefaultHelloTimeout)))

	name, hello, err := readClientHello(ctx, io.LimitReader(c, orDefault(r.MaxHelloSize, DefaultMaxHelloSize)))
	if err != nil {
		return err
	}

	_ = c.SetReadDeadline(time.Time{})

	dctx, cancel := context.WithTimeout(ctx, orDefault(r.DialTimeout, DefaultDialTimeout))
	defer cancel()

	upstream, err := r.dialIngress(dctx, name, port, src)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	defer upstream.Close()

	_, err = upstream.Write(hello)
	if err != nil {
		return fmt.Errorf("%s: forwarding ClientHello: %w", name, err)
	}

	splice(c, upstream)

	return nil
}

// dialIngress opens an ingress stream to the node named name for
// target port port, on behalf of client src.
func (r *Relay) dialIngress(ctx context.Context, name string, port uint16, src netip.AddrPort) (net.Conn, error) {
	peerAPI, err := r.peerAPIFor(ctx, name)
	if err != nil {
		return nil, err
	}

	conn, err := r.Backend.DialTCP(ctx, peerAPI.Addr().String(), peerAPI.Port())
	if err != nil {
		return nil, fmt.Errorf("dialing peerapi %s: %w", peerAPI, err)
	}

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+peerAPI.String()+"/v0/ingress", http.NoBody)
	if err != nil {
		conn.Close()

		return nil, err
	}

	req.Header.Set("Tailscale-Ingress-Src", src.String())
	req.Header.Set("Tailscale-Ingress-Target", net.JoinHostPort(name, strconv.FormatUint(uint64(port), 10)))

	err = req.Write(conn)
	if err != nil {
		conn.Close()

		return nil, fmt.Errorf("sending ingress request: %w", err)
	}

	br := bufio.NewReader(conn)

	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()

		return nil, fmt.Errorf("reading ingress answer: %w", err)
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		resp.Body.Close()
		conn.Close()

		return nil, fmt.Errorf("%w: %s", errNotRelayed, resp.Status)
	}

	_ = conn.SetDeadline(time.Time{})

	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}

	return conn, nil
}

// peerAPIFor returns the peerapi address of the node whose MagicDNS name
// is name.
func (r *Relay) peerAPIFor(ctx context.Context, name string) (netip.AddrPort, error) {
	st, err := r.cachedStatus(ctx, false)
	if err != nil {
		return netip.AddrPort{}, err
	}

	peer := findPeer(st, name)
	if peer == nil {
		// A node that just joined may not be in a cached status yet.
		st, err = r.cachedStatus(ctx, true)
		if err != nil {
			return netip.AddrPort{}, err
		}

		peer = findPeer(st, name)
		if peer == nil {
			return netip.AddrPort{}, errNoPeer
		}
	}

	return peerAPIAddr(peer)
}

func (r *Relay) cachedStatus(ctx context.Context, refresh bool) (*ipnstate.Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !refresh && r.status != nil && time.Since(r.statusAt) < orDefault(r.StatusTTL, DefaultStatusTTL) {
		return r.status, nil
	}

	st, err := r.Backend.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("tailnet status: %w", err)
	}

	r.status, r.statusAt = st, time.Now()

	return st, nil
}

// findPeer returns the peer whose MagicDNS name is name, compared without
// the trailing dot and case.
func findPeer(st *ipnstate.Status, name string) *ipnstate.PeerStatus {
	for _, p := range st.Peer {
		if strings.EqualFold(strings.TrimSuffix(p.DNSName, "."), name) {
			return p
		}
	}

	return nil
}

// peerAPIAddr returns the first peerapi address of p, preferring IPv4.
func peerAPIAddr(p *ipnstate.PeerStatus) (netip.AddrPort, error) {
	var found netip.AddrPort

	for _, s := range p.PeerAPIURL {
		u, err := url.Parse(s)
		if err != nil {
			continue
		}

		ap, err := netip.ParseAddrPort(u.Host)
		if err != nil {
			continue
		}

		if ap.Addr().Is4() {
			return ap, nil
		}

		if !found.IsValid() {
			found = ap
		}
	}

	if !found.IsValid() {
		return netip.AddrPort{}, errNoPeerAPI
	}

	return found, nil
}

// readClientHello reads a TLS ClientHello from r and returns its server
// name, lowercased without a trailing dot, and the bytes read, to replay
// to the node.
func readClientHello(ctx context.Context, r io.Reader) (string, []byte, error) {
	var (
		buf  bytes.Buffer
		name string
	)

	err := tls.Server(readOnlyConn{r: io.TeeReader(r, &buf)}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			name = h.ServerName

			return nil, errHelloRead
		},
	}).HandshakeContext(ctx)
	if !errors.Is(err, errHelloRead) {
		return "", nil, fmt.Errorf("reading ClientHello: %w", err)
	}

	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return "", nil, errNoSNI
	}

	return name, buf.Bytes(), nil
}

// splice copies between a and b until either side is done.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)

	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)

		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}

		done <- struct{}{}
	}

	go cp(a, b)
	go cp(b, a)

	// Once one direction ends, give the other a moment to drain, then
	// close both.
	<-done

	select {
	case <-done:
	case <-time.After(30 * time.Second):
	}

	a.Close()
	b.Close()
}

func orDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}

	return v
}

// readOnlyConn is a [net.Conn] that only reads, used to parse a
// ClientHello with [tls.Server] without answering it.
type readOnlyConn struct {
	net.Conn

	r io.Reader
}

func (c readOnlyConn) Read(p []byte) (int, error)     { return c.r.Read(p) }
func (readOnlyConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (readOnlyConn) Close() error                     { return nil }
func (readOnlyConn) LocalAddr() net.Addr              { return nil }
func (readOnlyConn) RemoteAddr() net.Addr             { return nil }
func (readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (readOnlyConn) SetWriteDeadline(time.Time) error { return nil }

// bufferedConn reads first what a [bufio.Reader] already pulled from the
// connection.
type bufferedConn struct {
	net.Conn

	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
