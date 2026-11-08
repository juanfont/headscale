package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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
				YAMLKey:  "tls.acme.http_listen",
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
				Listener: "metrics",
				YAMLKey:  "metrics_listen_addr",
				Addr:     "127.0.0.1:9090",
				Err:      &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EADDRINUSE},
			}),
			wantHintSubstr: []string{"sudo ss -tlnp 'sport = :9090'"},
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

func TestLogNoConfigFile(t *testing.T) {
	oldLogger, oldLevel := log.Logger, zerolog.GlobalLevel()

	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	t.Cleanup(func() {
		log.Logger = oldLogger

		zerolog.SetGlobalLevel(oldLevel)
	})

	type line struct{ Level, Message string }

	tests := []struct {
		name string
		file string
		want []line
	}{
		{name: "no file", want: []line{{Level: "info", Message: "no configuration file, using defaults and the environment"}}},
		{name: "file", file: "/x/config.yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			log.Logger = zerolog.New(&buf)

			logNoConfigFile(&config.Loaded{File: tt.file})

			var got []line

			for l := range strings.Lines(buf.String()) {
				var r line
				require.NoError(t, json.Unmarshal([]byte(l), &r), l)

				got = append(got, r)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("logged (-want +got):\n%s", diff)
			}
		})
	}
}
