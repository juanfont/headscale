package types

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/spf13/viper"
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

func TestListenersOverlap(t *testing.T) {
	tests := []struct {
		name        string
		aHost       string
		aPort       int
		bHost       string
		bPort       int
		wantOverlap bool
	}{
		{"different-ports", "", 80, "", 443, false},
		{"same-port-wildcard", "", 80, "", 80, true},
		{"wildcard-vs-loopback-same-port", "0.0.0.0", 80, "127.0.0.1", 80, true},
		{"loopback-vs-wildcard-same-port", "127.0.0.1", 80, "0.0.0.0", 80, true},
		{"ipv6-wildcard-vs-numeric", "[::]", 80, "0.0.0.0", 80, true},
		{"different-specific-hosts-same-port", "192.168.1.1", 80, "192.168.1.2", 80, false},
		{"same-specific-host-same-port", "127.0.0.1", 80, "127.0.0.1", 80, true},
		{"same-specific-host-different-port", "127.0.0.1", 80, "127.0.0.1", 81, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := listenersOverlap(tt.aHost, tt.aPort, tt.bHost, tt.bPort)
			assert.Equal(t, tt.wantOverlap, got)
		})
	}
}

// TestValidateListenerCollisions_BlamesParseFailure pins each parse
// error to the listener whose address is malformed, even when paired
// with a well-formed sibling.
func TestValidateListenerCollisions_BlamesParseFailure(t *testing.T) {
	tests := []struct {
		name    string
		bad     string // YAML key whose addr is malformed
		good    string // sibling key with a valid addr
		badAddr string
	}{
		{"bad-listen_addr", "listen_addr", "grpc_listen_addr", "garbage"},
		{"bad-grpc_listen_addr", "grpc_listen_addr", "listen_addr", "also-garbage"},
		{"bad-metrics_listen_addr", "metrics_listen_addr", "listen_addr", "no-port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			viper.Set(tt.bad, tt.badAddr)
			viper.Set(tt.good, ":9999")

			v := &configValidator{}
			validateListenerCollisions(v)

			err := v.Err()
			require.Error(t, err)

			errs := ConfigErrors(err)
			require.Len(t, errs, 1, "expected exactly one parse error")
			assert.Equal(t, "cannot parse "+tt.bad, errs[0].Reason)
			require.Len(t, errs[0].Current, 1)
			assert.Equal(t, tt.bad, errs[0].Current[0].Key)
			assert.Equal(t, tt.badAddr, errs[0].Current[0].Value)
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
