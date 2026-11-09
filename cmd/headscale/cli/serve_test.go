package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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

// TestServeExitCode: serve exits with exitConfig only when the configuration
// file it loaded is the cause, so systemd stops restarting it; a failure that
// can heal, no file at all, and every other command exit with 1.
func TestServeExitCode(t *testing.T) {
	dir := t.TempDir()
	notADir := writeFile(t, dir, "file", "")

	const valid = "server_url: https://headscale.example.com\ndisable_check_updates: true\n"

	tests := []struct {
		name   string
		file   string // the config file's name, config.yaml when ""
		config string // written to file; "" passes a path that does not exist
		search bool   // no -c: the file is searched for, in ~/.headscale
		args   []string
		want   int
		stderr string
	}{
		{name: "rejected value", config: "server_url: ftp://headscale.example.com\ndisable_check_updates: true\n", args: []string{"serve"}, want: exitConfig, stderr: "server_url"},
		{name: "unknown key", config: valid + "bogus_key: 1\n", args: []string{"serve"}, want: exitConfig, stderr: "unknown configuration key bogus_key"},
		{name: "syntax error", config: valid + "derp: [\n", args: []string{"serve"}, want: exitConfig, stderr: "yaml: line 3"},
		{name: "missing file", args: []string{"serve"}, want: 1, stderr: "Error: loading config file"},
		{name: "no file found", search: true, args: []string{"serve"}, want: 1, stderr: "server_url is required"},
		{name: "old format found", file: "config.toml", config: "server_url = \"https://headscale.example.com\"\n", search: true, args: []string{"serve"}, want: exitConfig, stderr: "unsupported config file format"},
		{name: "unwritable noise key", config: valid + "noise:\n  private_key_path: " + notADir + "/noise.key\n", args: []string{"serve"}, want: 1, stderr: "Noise"},
		{name: "other command", config: valid + "bogus_key: 1\n", args: []string{"users", "list"}, want: 1, stderr: "unknown configuration key bogus_key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home, dir, name := t.TempDir(), t.TempDir(), tt.file
			if name == "" {
				name = "config.yaml"
			}

			if tt.search {
				dir = filepath.Join(home, ".headscale")
				require.NoError(t, os.Mkdir(dir, 0o700))
			}

			path := filepath.Join(dir, "absent", name)
			if tt.config != "" {
				path = writeFile(t, dir, name, tt.config)
			}

			args := append([]string{"-c", path}, tt.args...)
			if tt.search {
				// The search always looks in /etc/headscale; a host config there
				// would be found, or serve would start on it.
				if found, _ := filepath.Glob("/etc/headscale/config.*"); len(found) > 0 {
					t.Skipf("the search would find %v", found)
				}

				args = tt.args
			}

			env := []string{"HOME=" + home, "XDG_CONFIG_DIRS=" + t.TempDir(), "HEADSCALE_DISABLE_CHECK_UPDATES=true"}
			_, stderr, err := runHeadscale(t, env, args...)

			exitErr, ok := errors.AsType[*exec.ExitError](err)
			require.True(t, ok, "want exit %d, got %v; stderr:\n%s", tt.want, err, stderr)
			assert.Equal(t, tt.want, exitErr.ExitCode(), stderr)
			assert.Contains(t, stderr, tt.stderr)
		})
	}
}
