package funnel

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

const nodeName = "laptop.ts.example.com"

// selfSigned returns a certificate for name.
func selfSigned(t *testing.T, name string) tls.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// fakeNode plays a funnel node's peerapi: it answers the ingress request
// with status, then, on 101, terminates TLS and echoes lines back.
type fakeNode struct {
	t      *testing.T
	ln     net.Listener
	status int

	mu      sync.Mutex
	headers http.Header
}

func newFakeNode(t *testing.T, status int) *fakeNode {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	n := &fakeNode{t: t, ln: ln, status: status}
	cert := selfSigned(t, nodeName)

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}

			go n.serve(c, cert)
		}
	}()

	return n
}

func (n *fakeNode) serve(c net.Conn, cert tls.Certificate) {
	defer c.Close()

	br := bufio.NewReader(c)

	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	n.mu.Lock()
	n.headers = req.Header.Clone()
	n.mu.Unlock()

	if req.Method != http.MethodPost || req.URL.Path != "/v0/ingress" || n.status != http.StatusSwitchingProtocols {
		code := n.status
		if code == http.StatusSwitchingProtocols {
			code = http.StatusNotFound
		}

		_, _ = io.WriteString(c, "HTTP/1.1 "+strconv.Itoa(code)+" "+http.StatusText(code)+"\r\nContent-Length: 0\r\n\r\n")

		return
	}

	_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\n\r\n")

	tc := tls.Server(&bufferedConn{Conn: c, r: br}, &tls.Config{Certificates: []tls.Certificate{cert}})
	if tc.HandshakeContext(n.t.Context()) != nil {
		return
	}

	line, err := bufio.NewReader(tc).ReadString('\n')
	if err != nil {
		return
	}

	_, _ = io.WriteString(tc, "echo "+line)
}

func (n *fakeNode) header(k string) string {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.headers.Get(k)
}

// fakeBackend is a tailnet of one peer, nodeName, whose peerapi is the
// fake node; dialing goes to the loopback listener.
type fakeBackend struct {
	peerAPI string
}

func (b fakeBackend) Status(context.Context) (*ipnstate.Status, error) {
	return &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{
		key.NewNode().Public(): {
			DNSName:    "Laptop.ts.example.com.",
			PeerAPIURL: []string{"http://" + b.peerAPI},
		},
	}}, nil
}

func (b fakeBackend) DialTCP(ctx context.Context, host string, port uint16) (net.Conn, error) {
	var d net.Dialer

	return d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
}

// startRelay serves a relay over backend on a loopback listener and
// returns its address.
func startRelay(t *testing.T, backend Backend) string {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	r := &Relay{Backend: backend, HelloTimeout: 2 * time.Second, DialTimeout: 2 * time.Second}

	go func() { _ = r.Serve(ctx, ln, 443) }()

	return ln.Addr().String()
}

func dialTLS(ctx context.Context, addr, serverName string) (*tls.Conn, error) {
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 3 * time.Second},
		Config: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, //nolint:gosec // self-signed test certificate
		},
	}

	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	return c.(*tls.Conn), nil //nolint:forcetypeassert // tls.Dialer returns *tls.Conn
}

func TestRelayForwardsTLSToNode(t *testing.T) {
	t.Parallel()

	node := newFakeNode(t, http.StatusSwitchingProtocols)
	addr := startRelay(t, fakeBackend{peerAPI: node.ln.Addr().String()})

	conn, err := dialTLS(t.Context(), addr, "LAPTOP.ts.example.com.")
	require.NoError(t, err)

	defer conn.Close()

	// The node, not the relay, terminated TLS.
	state := conn.ConnectionState()
	require.Len(t, state.PeerCertificates, 1)
	assert.Equal(t, nodeName, state.PeerCertificates[0].Subject.CommonName)

	_, err = io.WriteString(conn, "hello\n")
	require.NoError(t, err)

	line, err := bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "echo hello\n", line)

	assert.Equal(t, nodeName+":443", node.header("Tailscale-Ingress-Target"))

	src, err := netip.ParseAddrPort(node.header("Tailscale-Ingress-Src"))
	require.NoError(t, err)
	assert.Equal(t, conn.LocalAddr().String(), src.String())
}

func TestRelayDropsWithoutRelaying(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		status     int
		serverName string
	}{
		{name: "unknown node", status: http.StatusSwitchingProtocols, serverName: "desktop.ts.example.com"},
		{name: "node refuses ingress", status: http.StatusForbidden, serverName: nodeName},
		{name: "no server name", status: http.StatusSwitchingProtocols, serverName: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			node := newFakeNode(t, tt.status)
			addr := startRelay(t, fakeBackend{peerAPI: node.ln.Addr().String()})

			conn, err := dialTLS(t.Context(), addr, tt.serverName)
			if err == nil {
				conn.Close()
			}

			require.Error(t, err, "the relay must close the connection")
		})
	}
}

func TestPeerAPIAddrPrefersIPv4(t *testing.T) {
	t.Parallel()

	ap, err := peerAPIAddr(&ipnstate.PeerStatus{PeerAPIURL: []string{
		"http://[fd7a:115c:a1e0::1]:1234",
		"http://100.64.0.1:1234",
	}})
	require.NoError(t, err)
	assert.Equal(t, "100.64.0.1:1234", ap.String())

	_, err = peerAPIAddr(&ipnstate.PeerStatus{})
	require.ErrorIs(t, err, errNoPeerAPI)
}

// startRelayBehindProxy serves a relay that trusts PROXY headers from
// trusted on a loopback listener and returns its address.
func startRelayBehindProxy(t *testing.T, backend Backend, trusted []string) string {
	t.Helper()

	raw, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ln, err := ProxyProtocolListener(raw, trusted)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	r := &Relay{Backend: backend, HelloTimeout: 2 * time.Second, DialTimeout: 2 * time.Second}

	go func() { _ = r.Serve(ctx, ln, 443) }()

	return ln.Addr().String()
}

// dialTLSWithHeader opens a TCP connection to addr, sends header first
// when it is not empty, then speaks TLS for serverName.
func dialTLSWithHeader(ctx context.Context, addr, header string) (*tls.Conn, error) {
	raw, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	if header != "" {
		_, err = io.WriteString(raw, header)
		if err != nil {
			raw.Close()

			return nil, err
		}
	}

	tc := tls.Client(raw, &tls.Config{
		ServerName:         nodeName,
		InsecureSkipVerify: true, //nolint:gosec // self-signed test certificate
	})

	err = tc.HandshakeContext(ctx)
	if err != nil {
		raw.Close()

		return nil, err
	}

	return tc, nil
}

func TestRelayBehindProxy(t *testing.T) {
	t.Parallel()

	const header = "PROXY TCP4 203.0.113.7 127.0.0.1 51234 443\r\n"

	t.Run("client address from the header", func(t *testing.T) {
		t.Parallel()

		node := newFakeNode(t, http.StatusSwitchingProtocols)
		addr := startRelayBehindProxy(t, fakeBackend{peerAPI: node.ln.Addr().String()}, []string{"127.0.0.0/8"})

		conn, err := dialTLSWithHeader(t.Context(), addr, header)
		require.NoError(t, err)

		defer conn.Close()

		_, err = io.WriteString(conn, "hello\n")
		require.NoError(t, err)

		line, err := bufio.NewReader(conn).ReadString('\n')
		require.NoError(t, err)
		assert.Equal(t, "echo hello\n", line)
		assert.Equal(t, "203.0.113.7:51234", node.header("Tailscale-Ingress-Src"))
	})

	for _, tt := range []struct {
		name    string
		trusted []string
		header  string
	}{
		{name: "trusted source without header", trusted: []string{"127.0.0.1"}},
		{name: "untrusted source with header", trusted: []string{"192.0.2.1"}, header: header},
		{name: "untrusted source without header", trusted: []string{"192.0.2.0/24"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			node := newFakeNode(t, http.StatusSwitchingProtocols)
			addr := startRelayBehindProxy(t, fakeBackend{peerAPI: node.ln.Addr().String()}, tt.trusted)

			conn, err := dialTLSWithHeader(t.Context(), addr, tt.header)
			if err == nil {
				conn.Close()
			}

			require.Error(t, err, "the relay must drop the connection")
		})
	}

	_, err := ProxyProtocolListener(nil, []string{"not-an-address"})
	require.Error(t, err)
}
