package cli

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errClassifierUnrelated = errors.New("not a bind error")

func TestClassifyServeError(t *testing.T) {
	tests := []struct {
		name              string
		err               error
		wantHintSubstr    []string
		wantHintNotSubstr []string
		wantUnchanged     bool
	}{
		{
			name: "eaddrinuse-numeric-port",
			err: &types.ListenerBindError{
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
			err: &types.ListenerBindError{
				Listener: "ACME HTTP-01 challenge",
				YAMLKey:  "tls_letsencrypt_listen",
				Addr:     ":http",
				Err:      &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EADDRINUSE},
			},
			wantHintSubstr: []string{"sudo ss -tlnp 'sport = :80'"},
		},
		{
			name: "eaccess-privileged-port",
			err: &types.ListenerBindError{
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
			err: &types.ListenerBindError{
				Listener: "main HTTP",
				YAMLKey:  "listen_addr",
				Addr:     "0.0.0.0:80",
				Err:      errClassifierUnrelated,
			},
			wantUnchanged: true,
		},
		{
			name: "wrapped-eaddrinuse-still-classified",
			err: fmt.Errorf("serve: %w", &types.ListenerBindError{
				Listener: "gRPC",
				YAMLKey:  "grpc_listen_addr",
				Addr:     "0.0.0.0:50443",
				Err:      &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EADDRINUSE},
			}),
			wantHintSubstr: []string{"sudo ss -tlnp 'sport = :50443'"},
		},
		{
			name: "eaddrinuse-unparseable-addr-omits-port",
			err: &types.ListenerBindError{
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
			got := classifyServeError(tt.err)

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
