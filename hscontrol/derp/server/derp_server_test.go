package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/envknob"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
)

// TestGenerateRegionInsecureTLS pins the contract nix/testkit.nix relies on:
// with the knob set, the embedded node advertises the TLS listener's port and
// InsecureForTests, so clients without the self-signed cert can relay.
func TestGenerateRegionInsecureTLS(t *testing.T) {
	tests := []struct {
		name         string
		knob         string
		wantPort     int
		wantInsecure bool
		wantErr      bool
	}{
		{name: "unset keeps server_url port", knob: "", wantPort: 80},
		{name: "set advertises TLS port", knob: "[::]:443", wantPort: 443, wantInsecure: true},
		{name: "named port", knob: ":https", wantPort: 443, wantInsecure: true},
		{name: "random port is refused", knob: ":0", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envknob.Setenv("HEADSCALE_DEBUG_INSECURE_TLS_LISTEN_ADDR", tt.knob)
			t.Cleanup(func() { envknob.Setenv("HEADSCALE_DEBUG_INSECURE_TLS_LISTEN_ADDR", "") })

			d := &DERPServer{
				serverURL: "http://headscale",
				cfg: &types.DERPConfig{
					Server: types.DERPServerConfig{RegionID: 999, RegionCode: "headscale", STUNAddr: "[::]:3478"},
				},
			}

			region, err := d.GenerateRegion()
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			require.Len(t, region.Nodes, 1)

			node := region.Nodes[0]
			assert.Equal(t, "headscale", node.HostName)
			assert.Equal(t, tt.wantPort, node.DERPPort)
			assert.Equal(t, tt.wantInsecure, node.InsecureForTests)
			assert.Equal(t, 3478, node.STUNPort)
		})
	}
}

// TestDERPBootstrapDNSHandlerFollowsDERPMapUpdates guards against the handler
// resolving a DERP map captured at startup: hostnames that a later
// auto-update adds must be served.
func TestDERPBootstrapDNSHandlerFollowsDERPMapUpdates(t *testing.T) {
	var current atomic.Pointer[tailcfg.DERPMap]
	current.Store(&tailcfg.DERPMap{})

	handler := DERPBootstrapDNSHandler(func() tailcfg.DERPMapView {
		return current.Load().View()
	})

	current.Store(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
		1: {RegionID: 1, Nodes: []*tailcfg.DERPNode{{Name: "1a", RegionID: 1, HostName: "localhost"}}},
	}})

	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/bootstrap-dns", nil))

	var got map[string][]net.IP
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got))
	assert.Contains(t, got, "localhost")
}

// TestSTUNServerUnmapsIPv4 pins that an IPv4 client of a dual-stack
// listener (what the default "0.0.0.0" opens) gets an IPv4
// XOR-MAPPED-ADDRESS, as Tailscale's derpers send. Raw bytes are compared
// because stun.ParseResponse unmaps and would hide the bug.
// https://github.com/juanfont/headscale/issues/3573
func TestSTUNServerUnmapsIPv4(t *testing.T) {
	// Probe for a free port and whether "0.0.0.0" opens a dual-stack socket.
	probe, err := new(net.ListenConfig).ListenPacket(t.Context(), "udp", "0.0.0.0:0")
	require.NoError(t, err)

	local, ok := probe.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)
	require.NoError(t, probe.Close())

	if !local.IP.Equal(net.IPv6unspecified) {
		t.Skipf("listener is not dual-stack: %s", local)
	}

	d := &DERPServer{cfg: &types.DERPConfig{Server: types.DERPServerConfig{STUNAddr: types.ListenAddr(fmt.Sprintf("0.0.0.0:%d", local.Port))}}}
	srv, err := d.ListenSTUN(t.Context())
	require.NoError(t, err)

	go srv.Serve() //nolint:errcheck // Serve returns nil once the test context ends

	tests := []struct {
		network string
		client  netip.Addr
	}{
		{network: "udp4", client: netip.MustParseAddr("127.0.0.1")},
		{network: "udp6", client: netip.MustParseAddr("::1")},
	}

	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			conn, err := net.DialUDP(tt.network, nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(tt.client, uint16(local.Port)))) //nolint:gosec // port is always <=65535
			if err != nil {
				t.Skipf("no %s loopback: %v", tt.network, err)
			}
			defer conn.Close()

			txid := stun.NewTxID()
			buf := make([]byte, 1024)

			var n int

			// Retry until Serve answers.
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				_, err := conn.Write(stun.Request(txid))
				require.NoError(c, err)
				require.NoError(c, conn.SetReadDeadline(time.Now().Add(100*time.Millisecond)))

				n, err = conn.Read(buf)
				require.NoError(c, err)
			}, 5*time.Second, 10*time.Millisecond)

			clientPort := conn.LocalAddr().(*net.UDPAddr).Port                             //nolint:forcetypeassert // DialUDP always yields *net.UDPAddr
			want := stun.Response(txid, netip.AddrPortFrom(tt.client, uint16(clientPort))) //nolint:gosec // port is always <=65535
			assert.Equal(t, want, buf[:n])
		})
	}
}
