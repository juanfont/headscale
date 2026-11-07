package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestSkipsInitConfig(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"check policy", []string{"check", "policy", "-f", "p"}, true},
		{"check config with config flag", []string{"-c", "x.yaml", "check", "config"}, true},
		{"check", []string{"check"}, true},
		{"policy get", []string{"policy", "get"}, false},
		{"nodes list", []string{"nodes", "list"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, skipsInitConfig(tt.args))
		})
	}
}

func newCheckPolicyCmd(t *testing.T, path string, database bool) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	cmd := &cobra.Command{}
	cmd.Flags().String("file", path, "")
	cmd.Flags().Bool("database", database, "")
	cmd.Flags().Bool("server", false, "")
	cmd.Flags().Bool("force", true, "")

	var buf bytes.Buffer

	cmd.SetOut(&buf)

	return cmd, &buf
}

func TestCheckPolicy(t *testing.T) {
	const (
		valid       = `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`
		failingTest = `{"acls":[],"tests":[{"src":"alice@","accept":["bob@:22"]}]}`
		passingTest = `{"acls":[{"action":"accept","src":["alice@"],"dst":["bob@:22"]}],"tests":[{"src":"alice@","accept":["bob@:22"]}]}` //nolint:gosec // policy fixture
	)

	writePolicy := func(t *testing.T, body string) string {
		t.Helper()

		p := filepath.Join(t.TempDir(), "policy.hujson")
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))

		return p
	}

	t.Run("valid", func(t *testing.T) {
		cmd, out := newCheckPolicyCmd(t, writePolicy(t, valid), false)
		require.NoError(t, checkPolicyCmd.RunE(cmd, nil))
		require.Equal(t, "Policy is valid\n", out.String())
	})

	t.Run("tests not run offline", func(t *testing.T) {
		cmd, out := newCheckPolicyCmd(t, writePolicy(t, failingTest), false)
		require.NoError(t, checkPolicyCmd.RunE(cmd, nil))
		require.Contains(t, out.String(), "Policy is valid")
		require.Contains(t, out.String(), "tests and sshTests were not run")
	})

	t.Run("undefined group", func(t *testing.T) {
		cmd, _ := newCheckPolicyCmd(t, writePolicy(t, `{"acls":[{"action":"accept","src":["group:missing"],"dst":["*:*"]}]}`), false)
		require.ErrorIs(t, checkPolicyCmd.RunE(cmd, nil), policyv2.ErrGroupNotDefined)
	})

	t.Run("empty file", func(t *testing.T) {
		cmd, out := newCheckPolicyCmd(t, writePolicy(t, ""), false)
		require.NoError(t, checkPolicyCmd.RunE(cmd, nil))
		require.Equal(t, "Policy is valid\n", out.String())
	})

	t.Run("broken config ignored offline", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.yaml")
		require.NoError(t, os.WriteFile(bad, []byte("server_url: ["), 0o600))
		t.Setenv("HEADSCALE_CONFIG", bad)

		cmd, _ := newCheckPolicyCmd(t, writePolicy(t, valid), false)
		require.NoError(t, checkPolicyCmd.RunE(cmd, nil))
	})

	for _, tt := range []struct {
		name    string
		policy  string
		invalid bool
	}{
		{"database passing", passingTest, false},
		{"database failing", failingTest, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)

			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.yaml")
			config := fmt.Sprintf(`server_url: https://headscale.example.com
noise:
  private_key_path: noise_private.key
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite3
  sqlite:
    path: %q
policy:
  mode: database
dns:
  magic_dns: false
  override_local_dns: false
`, filepath.Join(dir, "headscale.db"))
			require.NoError(t, os.WriteFile(configPath, []byte(config), 0o600))

			old := cfgFile
			cfgFile = configPath

			t.Cleanup(func() { cfgFile = old })

			require.NoError(t, types.LoadConfig(configPath, true))

			cfg, err := types.LoadServerConfig()
			require.NoError(t, err)

			database, err := db.NewHeadscaleDatabase(cfg)
			require.NoError(t, err)

			for _, name := range []string{"alice", "bob"} {
				user := database.CreateUserForTest(name)
				database.CreateRegisteredNodeForTest(user, name+"-node")
			}

			require.NoError(t, database.Close())
			viper.Reset()

			cmd, out := newCheckPolicyCmd(t, writePolicy(t, tt.policy), true)

			err = checkPolicyCmd.RunE(cmd, nil)
			if tt.invalid {
				require.ErrorContains(t, err, "test(s) failed")
			} else {
				require.NoError(t, err)
				require.Equal(t, "Policy is valid\n", out.String())
			}
		})
	}
}

func TestCheckConfig(t *testing.T) {
	const badGroup = `{"acls":[{"action":"accept","src":["group:missing"],"dst":["*:*"]}]}`

	setup := func(t *testing.T, serverURL, mode string) string {
		t.Helper()

		viper.Reset()
		t.Cleanup(viper.Reset)

		dir := t.TempDir()
		policyPath := filepath.Join(dir, "policy.hujson")
		require.NoError(t, os.WriteFile(policyPath, []byte(badGroup), 0o600))

		configPath := filepath.Join(dir, "config.yaml")
		config := fmt.Sprintf(`server_url: %s
noise:
  private_key_path: %q
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite3
  sqlite:
    path: %q
policy:
  mode: %s
  path: %q
dns:
  magic_dns: false
  override_local_dns: false
`, serverURL, filepath.Join(dir, "noise.key"), filepath.Join(dir, "headscale.db"), mode, policyPath)
		require.NoError(t, os.WriteFile(configPath, []byte(config), 0o600))

		old := cfgFile
		cfgFile = configPath

		t.Cleanup(func() { cfgFile = old })

		return dir
	}

	run := func(t *testing.T, noFiles, database bool) (string, error) {
		t.Helper()

		cmd := &cobra.Command{}
		cmd.Flags().Bool("no-files", noFiles, "")
		cmd.Flags().Bool("database", database, "")
		cmd.Flags().Bool("force", true, "")

		var buf bytes.Buffer

		cmd.SetOut(&buf)

		err := checkConfigCmd.RunE(cmd, nil)

		return buf.String(), err
	}

	exists := func(p string) bool {
		_, err := os.Stat(p)

		return err == nil
	}

	t.Run("valid creates nothing", func(t *testing.T) {
		dir := setup(t, "https://headscale.example.com", "database")

		out, err := run(t, false, false)
		require.NoError(t, err)
		require.Equal(t, "Configuration is valid\n", out)
		require.False(t, exists(filepath.Join(dir, "headscale.db")))
		require.False(t, exists(filepath.Join(dir, "noise.key")))
	})

	t.Run("derp server without key path", func(t *testing.T) {
		dir := setup(t, "https://headscale.example.com", "database")

		f, err := os.OpenFile(cfgFile, os.O_APPEND|os.O_WRONLY, 0o600)
		require.NoError(t, err)

		_, err = f.WriteString("derp:\n  server:\n    enabled: true\n    stun_listen_addr: \"0.0.0.0:3478\"\n")
		require.NoError(t, err)
		require.NoError(t, f.Close())

		_, err = run(t, false, false)
		require.ErrorContains(t, err, "derp.server.private_key_path is required")
		require.False(t, exists(filepath.Join(dir, "noise.key")))
		require.False(t, exists(filepath.Join(dir, "headscale.db")))
	})

	t.Run("bad server_url", func(t *testing.T) {
		setup(t, "ftp://x", "database")

		_, err := run(t, false, false)
		require.ErrorContains(t, err, "server_url")
	})

	t.Run("bad policy file", func(t *testing.T) {
		setup(t, "https://headscale.example.com", "file")

		_, err := run(t, false, false)
		require.ErrorIs(t, err, policyv2.ErrGroupNotDefined)
	})

	t.Run("no-files skips policy file", func(t *testing.T) {
		setup(t, "https://headscale.example.com", "file")

		_, err := run(t, true, false)
		require.NoError(t, err)
	})

	t.Run("database opens", func(t *testing.T) {
		dir := setup(t, "https://headscale.example.com", "database")

		_, err := run(t, false, true)
		require.NoError(t, err)
		require.True(t, exists(filepath.Join(dir, "headscale.db")))
		require.False(t, exists(filepath.Join(dir, "noise.key")))
	})

	seed := func(t *testing.T, pol string) {
		t.Helper()

		require.NoError(t, types.LoadConfig(cfgFile, true))

		cfg, err := types.LoadServerConfig()
		require.NoError(t, err)

		d, err := db.NewHeadscaleDatabase(cfg)
		require.NoError(t, err)

		_, err = d.SetPolicy(pol)
		require.NoError(t, err)
		require.NoError(t, d.Close())
	}

	t.Run("database failing tests pass like startup", func(t *testing.T) {
		setup(t, "https://headscale.example.com", "database")
		seed(t, `{"acls":[],"tests":[{"src":"alice@","accept":["bob@:22"]}]}`)

		_, err := run(t, false, true)
		require.NoError(t, err)
	})

	t.Run("database bad reference", func(t *testing.T) {
		setup(t, "https://headscale.example.com", "database")
		seed(t, badGroup)

		_, err := run(t, false, true)
		require.ErrorIs(t, err, policyv2.ErrGroupNotDefined)
	})

	t.Run("database unparsable policy", func(t *testing.T) {
		setup(t, "https://headscale.example.com", "database")
		seed(t, `{`)

		_, err := run(t, false, true)
		require.Error(t, err)
	})
}

func TestRemovedConfigtest(t *testing.T) {
	require.ErrorIs(t, removedConfigtestCmd.RunE(removedConfigtestCmd, nil), errConfigtestRemoved)
	require.True(t, skipsInitConfig([]string{"-c", "/nonexistent.yaml", "configtest"}))
}
