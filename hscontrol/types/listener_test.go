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

var errClassifierUnrelated = errors.New("not a bind error")

func TestExplainBindError(t *testing.T) {
	tests := []struct {
		name              string
		err               error
		wantHintSubstr    []string
		wantHintNotSubstr []string
		wantUnchanged     bool
	}{
		{
			name: "eaddrinuse-numeric-port",
			err: &ListenerBindError{
				Listener: "main HTTP",
				YAMLKey:  "listen_addr",
				Addr:     "0.0.0.0:443",
				Err:      &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EADDRINUSE},
			},
			wantHintSubstr: []string{
				"another process on this host is bound to the same address",
				"sudo ss -tlnp 'sport = :443'",
			},
		},
		{
			name: "eaddrinuse-named-port",
			err: &ListenerBindError{
				Listener: "ACME HTTP-01 challenge",
				YAMLKey:  "tls.acme.http_listen",
				Addr:     ":http",
				Err:      &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EADDRINUSE},
			},
			wantHintSubstr: []string{"sudo ss -tlnp 'sport = :80'"},
		},
		{
			name: "eaccess-privileged-port",
			err: &ListenerBindError{
				Listener: "main HTTP",
				YAMLKey:  "listen_addr",
				Addr:     "0.0.0.0:80",
				Err:      &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EACCES},
			},
			wantHintSubstr: []string{
				"privileged port",
				"CAP_NET_BIND_SERVICE",
				"setcap cap_net_bind_service=+ep ./headscale`",
			},
		},
		{
			name:          "non-bind-error-passes-through",
			err:           errClassifierUnrelated,
			wantUnchanged: true,
		},
		{
			name: "bind-error-without-known-syscall",
			err: &ListenerBindError{
				Listener: "main HTTP",
				YAMLKey:  "listen_addr",
				Addr:     "0.0.0.0:80",
				Err:      errClassifierUnrelated,
			},
			wantUnchanged: true,
		},
		{
			name: "wrapped-eaddrinuse-still-classified",
			err: fmt.Errorf("serve: %w", &ListenerBindError{
				Listener: "metrics",
				YAMLKey:  "metrics_listen_addr",
				Addr:     "127.0.0.1:9090",
				Err:      &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EADDRINUSE},
			}),
			wantHintSubstr: []string{"sudo ss -tlnp 'sport = :9090'"},
		},
		{
			name: "eaddrinuse-unparseable-addr-omits-port",
			err: &ListenerBindError{
				Listener: "main HTTP",
				YAMLKey:  "listen_addr",
				Addr:     "garbage",
				Err:      &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EADDRINUSE},
			},
			wantHintSubstr:    []string{"sudo ss -tlnp"},
			wantHintNotSubstr: []string{":0", "sport ="},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExplainBindError(tt.err)

			if tt.wantUnchanged {
				require.ErrorIs(t, got, tt.err)
				assert.Equal(t, tt.err.Error(), got.Error())

				return
			}

			require.ErrorIs(t, got, tt.err)

			for _, want := range tt.wantHintSubstr {
				assert.Contains(t, got.Error(), want)
			}

			for _, unwanted := range tt.wantHintNotSubstr {
				assert.NotContains(t, got.Error(), unwanted)
			}
		})
	}
}
