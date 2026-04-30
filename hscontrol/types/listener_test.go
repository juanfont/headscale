package types

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errTestBindFailure = errors.New("listen tcp :80: bind: address already in use")

func TestPortFromAddr(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		want    int
		wantErr bool
	}{
		{"named-http", ":http", 80, false},
		{"numeric-80", ":80", 80, false},
		{"wildcard-numeric", "0.0.0.0:80", 80, false},
		{"named-https", ":https", 443, false},
		{"numeric-443", "0.0.0.0:443", 443, false},
		{"ipv6-wildcard", "[::]:8080", 8080, false},
		{"specific-ipv4", "192.168.1.1:8080", 8080, false},
		{"empty", "", 0, true},
		{"no-port", "0.0.0.0", 0, true},
		{"unknown-named", ":bogus", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := portFromAddr(tt.addr)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestListenersOverlap(t *testing.T) {
	tests := []struct {
		name        string
		a, b        string
		wantOverlap bool
		wantErr     bool
	}{
		{"different-ports", ":80", ":443", false, false},
		{"same-port-numeric", ":80", ":80", true, false},
		{"http-vs-numeric", ":http", ":80", true, false},
		{"https-vs-numeric", ":443", ":https", true, false},
		{"wildcard-vs-loopback-same-port", "0.0.0.0:80", "127.0.0.1:80", true, false},
		{"loopback-vs-wildcard-same-port", "127.0.0.1:80", "0.0.0.0:80", true, false},
		{"ipv6-wildcard-vs-numeric", "[::]:80", "0.0.0.0:80", true, false},
		{"different-specific-hosts-same-port", "192.168.1.1:80", "192.168.1.2:80", false, false},
		{"same-specific-host-same-port", "127.0.0.1:80", "127.0.0.1:80", true, false},
		{"same-specific-host-different-port", "127.0.0.1:80", "127.0.0.1:81", false, false},
		{"bad-input-a", "garbage", "", false, true},
		{"bad-input-b", ":80", "garbage", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := listenersOverlap(tt.a, tt.b)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantOverlap, got)
		})
	}
}

func TestListenerBindError_IsEADDRINUSE(t *testing.T) {
	inner := &net.OpError{
		Op:  "listen",
		Net: "tcp",
		Err: syscall.EADDRINUSE,
	}
	bindErr := &ListenerBindError{
		Listener: "main HTTP",
		YAMLKey:  "listen_addr",
		Addr:     "0.0.0.0:80",
		Err:      inner,
	}

	wrapped := fmt.Errorf("serve: %w", bindErr)

	require.ErrorIs(t, wrapped, syscall.EADDRINUSE)

	var got *ListenerBindError
	require.ErrorAs(t, wrapped, &got)
	assert.Equal(t, "main HTTP", got.Listener)
	assert.Equal(t, "listen_addr", got.YAMLKey)
	assert.Equal(t, "0.0.0.0:80", got.Addr)
}

func TestListenerBindError_Render(t *testing.T) {
	bindErr := &ListenerBindError{
		Listener: "ACME HTTP-01 challenge",
		YAMLKey:  "tls_letsencrypt_listen",
		Addr:     ":http",
		Err:      errTestBindFailure,
	}
	got := bindErr.Error()
	assert.Equal(
		t,
		`binding ACME HTTP-01 challenge listener (tls_letsencrypt_listen=":http"): listen tcp :80: bind: address already in use`,
		got,
	)
}

func TestIsWildcardHost(t *testing.T) {
	wildcards := []string{"", "0.0.0.0", "::", "[::]"}
	for _, h := range wildcards {
		t.Run("wildcard-"+h, func(t *testing.T) {
			assert.True(t, isWildcardHost(h))
		})
	}

	specifics := []string{"127.0.0.1", "192.168.1.1", "::1", "example.com"}
	for _, h := range specifics {
		t.Run("specific-"+h, func(t *testing.T) {
			assert.False(t, isWildcardHost(h))
		})
	}
}
