package server

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/envknob"
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
					ServerRegionID:   999,
					ServerRegionCode: "headscale",
					STUNAddr:         "[::]:3478",
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

func TestGenerateRegionURLHost(t *testing.T) {
	tests := []struct {
		url      string
		wantHost string
		wantPort int
	}{
		{"https://headscale.example.com", "headscale.example.com", 443},
		{"http://headscale.example.com", "headscale.example.com", 80},
		{"https://headscale.example.com:8443", "headscale.example.com", 8443},
		{"http://192.0.2.1:8080", "192.0.2.1", 8080},
		{"https://[2001:db8::1]", "2001:db8::1", 443},
		{"http://[2001:db8::1]", "2001:db8::1", 80},
		{"https://[2001:db8::1]:8443", "2001:db8::1", 8443},
		{"https://[fe80::1%25eth0]", "fe80::1%eth0", 443},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			d := &DERPServer{
				serverURL: tt.url,
				cfg:       &types.DERPConfig{STUNAddr: "[::]:3478"},
			}
			region, err := d.GenerateRegion()
			require.NoError(t, err)
			require.Len(t, region.Nodes, 1)
			assert.Equal(t, tt.wantHost, region.Nodes[0].HostName)
			assert.Equal(t, tt.wantPort, region.Nodes[0].DERPPort)
		})
	}
}

func TestGenerateRegionRejectsInvalidPort(t *testing.T) {
	for _, serverURL := range []string{
		"https://headscale.example.com:",
		"https://[2001:db8::1]:",
		"https://headscale.example.com:invalid",
	} {
		t.Run(serverURL, func(t *testing.T) {
			d := &DERPServer{
				serverURL: serverURL,
				cfg:       &types.DERPConfig{STUNAddr: "[::]:3478"},
			}
			_, err := d.GenerateRegion()
			require.Error(t, err)
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
