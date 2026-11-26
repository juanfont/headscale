package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		{name: "rejected value", config: "server_url: ftp://headscale.example.com\ndisable_check_updates: true\n", args: []string{"serve"}, want: types.ExitConfig, stderr: "server_url"},
		{name: "unknown key", config: valid + "bogus_key: 1\n", args: []string{"serve"}, want: types.ExitConfig, stderr: "unknown configuration key bogus_key"},
		{name: "syntax error", config: valid + "derp: [\n", args: []string{"serve"}, want: types.ExitConfig, stderr: "yaml: line 3"},
		{name: "missing file", args: []string{"serve"}, want: 1, stderr: "Error: loading config file"},
		{name: "no file found", search: true, args: []string{"serve"}, want: 1, stderr: "server_url is required"},
		{name: "old format found", file: "config.toml", config: "server_url = \"https://headscale.example.com\"\n", search: true, args: []string{"serve"}, want: types.ExitConfig, stderr: "unsupported config file format"},
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
