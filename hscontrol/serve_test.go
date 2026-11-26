package hscontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

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

// TestRunServerDropsTheCLIKey: the server never uses the CLI's key, and the
// debug config page prints the configuration the server holds, its cli
// section included; a file: reference would show its path there.
func TestRunServerDropsTheCLIKey(t *testing.T) {
	dir := t.TempDir()

	// t.TempDir is under the test's name, too long for a socket path.
	short, err := os.MkdirTemp("", "hs") //nolint:usetesting // see above
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(short) })

	derp := filepath.Join(dir, "derp.yaml")
	require.NoError(t, os.WriteFile(derp, []byte("regions:\n  900:\n    regionid: 900\n    regioncode: test\n    nodes:\n      - name: 900a\n        regionid: 900\n        hostname: derp.example.com\n"), 0o600))

	file := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(file, []byte(`server_url: http://127.0.0.1:8080
listen_addr: 127.0.0.1:0
metrics_listen_addr: ""
unix_socket: `+short+`/s
noise:
  private_key_path: `+dir+`/noise.key
database:
  type: sqlite
  sqlite:
    path: `+dir+`/db.sqlite
derp:
  urls: []
  paths: [`+derp+`]
disable_check_updates: true
cli:
  api_key: file:/run/secrets/headscale_api_key
`), 0o600))

	l, err := config.Load(file, true, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	require.NoError(t, RunServer(ctx, l, io.Discard))
	require.Empty(t, l.Config.CLI.APIKey)
}
