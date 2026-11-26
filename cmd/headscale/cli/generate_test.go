package cli

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestGenerateConfigCommand: generate config prints the example and only
// it, whatever config and variables are around.
func TestGenerateConfigCommand(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(home, ".headscale"), 0o700))
	writeFile(t, filepath.Join(home, ".headscale"), "config.yaml", "bogus_key: 1\n")

	env := []string{"HOME=" + home, "HEADSCALE_BOGUS=1"}

	tests := []struct {
		name       string
		args       []string
		wantErr    bool
		wantStdout []string
		hideStdout []string
		wantExact  string   // all of stdout, when set
		wantStderr []string // nil when stderr must be empty
		wantLoaded bool     // stdout loads to Default()
	}{
		{name: "example", args: []string{"generate", "config"}, wantStdout: []string{"# Every key"}, wantLoaded: true},
		{name: "alias", args: []string{"gen", "config"}, wantLoaded: true},
		{name: "no docs", args: []string{"generate", "config", "--no-docs"}, hideStdout: []string{"#"}, wantLoaded: true},
		{name: "minimal", args: []string{"generate", "config", "--minimal"}, wantStdout: []string{`server_url: ""`}, hideStdout: []string{"listen_addr"}, wantLoaded: true},
		{name: "minimal no docs", args: []string{"generate", "config", "--minimal", "--no-docs"}, wantExact: "server_url: \"\"\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, err := runHeadscale(t, env, tt.args...)
			if tt.wantErr {
				require.Error(t, err)
				assert.Empty(t, stdout)
			} else {
				require.NoError(t, err, stderr)

				var doc map[string]any
				require.NoError(t, yaml.Unmarshal([]byte(stdout), &doc), stdout)
				assert.NotContains(t, stdout, "HEADSCALE_BOGUS")
			}

			if tt.wantStderr == nil {
				assert.Empty(t, stderr)
			}

			for _, s := range tt.wantStderr {
				assert.Contains(t, stderr, s)
			}

			for _, s := range tt.wantStdout {
				assert.Contains(t, stdout, s)
			}

			for _, s := range tt.hideStdout {
				assert.NotContains(t, stdout, s)
			}

			if tt.wantExact != "" {
				assert.Equal(t, tt.wantExact, stdout)
			}

			if tt.wantLoaded {
				path := writeFile(t, t.TempDir(), "config.yaml", stdout)

				l, err := config.Load(path, true, nil)
				require.NoError(t, err)

				want := config.Default()
				if diff := cmp.Diff(&want, l.Config,
					cmpopts.EquateEmpty(),
					cmpopts.EquateComparable(netip.Prefix{}),
					cmpopts.IgnoreFields(types.Config{}, "ConfigDir"),
					cmpopts.IgnoreUnexported(types.Config{}),
				); diff != "" {
					t.Errorf("stdout loads as (-default +loaded):\n%s", diff)
				}
			}
		})
	}
}

// TestGenerateNixOSOptionsCommand: generate nixos-options prints the
// options and only them, whatever config is around.
func TestGenerateNixOSOptionsCommand(t *testing.T) {
	broken := writeFile(t, t.TempDir(), "broken.yaml", "bogus_key: 1\n")

	want, err := config.GenerateNixOptions(nil)
	require.NoError(t, err)

	tests := []struct {
		name       string
		args       []string
		wantStdout string
		wantStderr string // "" when stderr must be empty
	}{
		{name: "development", args: []string{"generate", "nixos-options"}, wantStdout: string(want)},
		// A test binary has no VCS stamp: commit unknown.
		{name: "release from a dev build", args: []string{"generate", "nixos-options", "--release"}, wantStderr: "commit unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, err := runHeadscale(t, []string{"HEADSCALE_BOGUS=1"}, append([]string{"-c", broken}, tt.args...)...)
			if tt.wantStderr == "" {
				require.NoError(t, err, stderr)
				assert.Empty(t, stderr)
			} else {
				require.Error(t, err)
				assert.Contains(t, stderr, tt.wantStderr)
			}

			assert.Equal(t, tt.wantStdout, stdout)
		})
	}
}
