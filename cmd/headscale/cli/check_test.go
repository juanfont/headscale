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
