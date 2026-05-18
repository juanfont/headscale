package hscontrol

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//nolint:goconst // repeated test fixtures (addresses, headers), not refactor candidates
func TestPeerTrusted(t *testing.T) {
	trusted := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/16"),
		netip.MustParsePrefix("127.0.0.1/32"),
		netip.MustParsePrefix("fd00::/8"),
	}

	tests := []struct {
		name       string
		remoteAddr string
		want       bool
	}{
		{name: "v4-in-range", remoteAddr: "10.0.0.5:1234", want: true},
		{name: "v4-edge", remoteAddr: "10.0.255.255:1", want: true},
		{name: "v4-out-of-range", remoteAddr: "10.1.0.0:1234", want: false},
		{name: "v4-loopback", remoteAddr: "127.0.0.1:443", want: true},
		{name: "v6-in-range", remoteAddr: "[fd00::1]:443", want: true},
		{name: "v6-out-of-range", remoteAddr: "[2001:db8::1]:443", want: false},
		{name: "no-port", remoteAddr: "10.0.0.5", want: true},
		{name: "empty", remoteAddr: "", want: false},
		{name: "non-ip-host", remoteAddr: "localhost:8080", want: false},
		{name: "garbage", remoteAddr: "not-a-thing", want: false},
		{name: "unix-socket", remoteAddr: "@", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := peerTrusted(tt.remoteAddr, trusted)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPrefixToIPNet(t *testing.T) {
	tests := []struct {
		name string
		in   netip.Prefix
		want string
	}{
		{name: "v4", in: netip.MustParsePrefix("10.0.0.0/16"), want: "10.0.0.0/16"},
		{name: "v4-host", in: netip.MustParsePrefix("127.0.0.1/32"), want: "127.0.0.1/32"},
		{name: "v6", in: netip.MustParsePrefix("fd00::/8"), want: "fd00::/8"},
		{name: "v6-host", in: netip.MustParsePrefix("::1/128"), want: "::1/128"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := prefixToIPNet(tt.in)
			assert.Equal(t, tt.want, got.String())
		})
	}
}

//nolint:goconst // repeated test fixtures (addresses, headers), not refactor candidates
func TestTrustedProxyRealIP(t *testing.T) {
	trusted := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/16"),
		netip.MustParsePrefix("fd00::/8"),
	}

	mw, err := trustedProxyRealIP(trusted)
	require.NoError(t, err)

	tests := []struct {
		name         string
		remoteAddr   string
		headers      map[string]string
		wantRemote   string
		wantStripped []string
		wantKept     map[string]string
	}{
		{
			name:       "untrusted/no-headers",
			remoteAddr: "203.0.113.1:1234",
			wantRemote: "203.0.113.1:1234",
		},
		{
			name:         "untrusted/strips-x-real-ip",
			remoteAddr:   "203.0.113.1:1234",
			headers:      map[string]string{"X-Real-IP": "1.2.3.4"},
			wantRemote:   "203.0.113.1:1234",
			wantStripped: []string{"X-Real-IP"},
		},
		{
			name:         "untrusted/strips-x-forwarded-for",
			remoteAddr:   "203.0.113.1:1234",
			headers:      map[string]string{"X-Forwarded-For": "1.2.3.4"},
			wantRemote:   "203.0.113.1:1234",
			wantStripped: []string{"X-Forwarded-For"},
		},
		{
			name:         "untrusted/strips-true-client-ip",
			remoteAddr:   "203.0.113.1:1234",
			headers:      map[string]string{"True-Client-IP": "1.2.3.4"},
			wantRemote:   "203.0.113.1:1234",
			wantStripped: []string{"True-Client-IP"},
		},
		{
			name:       "untrusted/strips-all-three",
			remoteAddr: "203.0.113.1:1234",
			headers: map[string]string{
				"True-Client-IP":  "1.2.3.4",
				"X-Real-IP":       "5.6.7.8",
				"X-Forwarded-For": "9.10.11.12",
			},
			wantRemote:   "203.0.113.1:1234",
			wantStripped: []string{"True-Client-IP", "X-Real-IP", "X-Forwarded-For"},
		},
		{
			name:         "untrusted/keeps-unrelated-header",
			remoteAddr:   "203.0.113.1:1234",
			headers:      map[string]string{"User-Agent": "curl/8", "X-Real-IP": "1.2.3.4"},
			wantRemote:   "203.0.113.1:1234",
			wantStripped: []string{"X-Real-IP"},
			wantKept:     map[string]string{"User-Agent": "curl/8"},
		},
		{
			name:       "trusted/no-headers",
			remoteAddr: "10.0.0.5:1234",
			wantRemote: "10.0.0.5:1234",
		},
		{
			name:       "trusted/x-real-ip",
			remoteAddr: "10.0.0.5:1234",
			headers:    map[string]string{"X-Real-IP": "1.2.3.4"},
			wantRemote: "1.2.3.4",
		},
		{
			name:       "trusted/true-client-ip-wins-over-others",
			remoteAddr: "10.0.0.5:1234",
			headers: map[string]string{
				"True-Client-IP":  "1.2.3.4",
				"X-Real-IP":       "5.6.7.8",
				"X-Forwarded-For": "9.10.11.12",
			},
			wantRemote: "1.2.3.4",
		},
		{
			name:       "trusted/x-real-ip-wins-over-xff",
			remoteAddr: "10.0.0.5:1234",
			headers: map[string]string{
				"X-Real-IP":       "1.2.3.4",
				"X-Forwarded-For": "9.10.11.12",
			},
			wantRemote: "1.2.3.4",
		},
		{
			name:       "trusted/xff-rightmost-walk-discards-trusted-hop",
			remoteAddr: "10.0.0.5:1234",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.99, 10.0.0.5"},
			wantRemote: "203.0.113.99",
		},
		{
			name:       "trusted/xff-all-trusted-leaves-remote-alone",
			remoteAddr: "10.0.0.5:1234",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.99, 10.0.0.5"},
			wantRemote: "10.0.0.5:1234",
		},
		{
			name:       "trusted/ipv6-peer-v6-real-ip",
			remoteAddr: "[fd00::1]:1234",
			headers:    map[string]string{"X-Real-IP": "2001:db8::1"},
			wantRemote: "2001:db8::1",
		},
		{
			name:         "ipv6-untrusted-strips-header",
			remoteAddr:   "[2001:db8::1]:1234",
			headers:      map[string]string{"X-Real-IP": "1.2.3.4"},
			wantRemote:   "[2001:db8::1]:1234",
			wantStripped: []string{"X-Real-IP"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var observed *http.Request

			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				observed = r
			}))

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr

			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			handler.ServeHTTP(httptest.NewRecorder(), req)

			require.NotNil(t, observed, "handler must be invoked")
			assert.Equal(t, tt.wantRemote, observed.RemoteAddr)

			for _, h := range tt.wantStripped {
				assert.Empty(t, observed.Header.Get(h), "header %s should be stripped", h)
			}

			for k, v := range tt.wantKept {
				assert.Equal(t, v, observed.Header.Get(k), "header %s should be preserved", k)
			}
		})
	}
}

func TestTrustedProxyRealIPEmptyTrusted(t *testing.T) {
	// Sanity: factory accepts an empty slice without error. Wiring code is
	// responsible for skipping the mount entirely, but the factory itself
	// must remain safe for tests that compose it manually.
	mw, err := trustedProxyRealIP(nil)
	require.NoError(t, err)
	require.NotNil(t, mw)

	var observed *http.Request

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed = r
	}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Real-IP", "1.2.3.4")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	require.NotNil(t, observed)
	// No prefix is trusted, so even an LAN-looking peer is not trusted; the
	// spoofed header must be stripped and RemoteAddr left alone.
	assert.Equal(t, "10.0.0.5:1234", observed.RemoteAddr)
	assert.Empty(t, observed.Header.Get("X-Real-IP"))
}
