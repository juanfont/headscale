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
		{"highest-port", ":65535", 65535, false},
		{"port-above-range", ":65536", 0, true},
		{"negative-port", ":-1", 0, true},
		{"signed-port", ":+80", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PortFromAddr(tt.addr)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
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
