package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
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
		{"check policy with config flag", []string{"-c", "x.yaml", "check", "policy"}, true},
		{"check config with config flag", []string{"-c", "x.yaml", "check", "config"}, true},
		{"check all with file", []string{"check", "all", "-f", "x.yaml"}, true},
		{"check", []string{"check"}, true},
		{"help check policy", []string{"help", "check", "policy"}, true},
		{"policy get", []string{"policy", "get"}, false},
		{"help nodes", []string{"help", "nodes"}, false},
		{"nodes list", []string{"nodes", "list"}, false},
	}

	// Execute adds the help command; these tests call Find without it.
	rootCmd.InitDefaultHelpCmd()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, skipsInitConfig(tt.args))
		})
	}
}

func newCheckPolicyCmd(t *testing.T, path string) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	cmd := &cobra.Command{}
	cmd.Flags().String("file", path, "")

	var buf bytes.Buffer

	cmd.SetOut(&buf)

	return cmd, &buf
}

func TestCheckPolicy(t *testing.T) {
	const (
		valid       = `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`
		failingTest = `{"acls":[],"tests":[{"src":"alice@","accept":["bob@:22"]}]}`
		passingTest = `{"acls":[{"action":"accept","src":["alice@"],"dst":["bob@:22"]}],"tests":[{"src":"alice@","accept":["bob@:22"]}]}` //nolint:gosec // policy fixture
		failingSSH  = `{"tagOwners":{"tag:web":["alice@"]},"sshTests":[{"src":"alice@","dst":["tag:web"],"accept":["root"]}]}`
	)

	writePolicy := func(t *testing.T, body string) string {
		t.Helper()

		p := filepath.Join(t.TempDir(), "policy.hujson")
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))

		return p
	}

	for _, tt := range []struct {
		name    string
		policy  string
		wantErr string
	}{
		{"valid", valid, ""},
		{"empty file", "", `policy is empty, use "{}" to allow all`},
		{"tests pass", passingTest, ""},
		{"tests fail", failingTest, "test(s) failed"},
		{"sshTests fail", failingSSH, "test(s) failed"},
		{"undefined group", `{"acls":[{"action":"accept","src":["group:missing"],"dst":["*:*"]}]}`, policyv2.ErrGroupNotDefined.Error()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cmd, out := newCheckPolicyCmd(t, writePolicy(t, tt.policy))

			err := checkPolicyCmd.RunE(cmd, nil)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				require.Empty(t, out.String())

				return
			}

			require.NoError(t, err)
			require.Equal(t, "Policy is valid\n", out.String())
		})
	}

	t.Run("missing file", func(t *testing.T) {
		cmd, _ := newCheckPolicyCmd(t, filepath.Join(t.TempDir(), "nope.hujson"))
		require.ErrorIs(t, checkPolicyCmd.RunE(cmd, nil), os.ErrNotExist)
	})

	t.Run("broken config ignored", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.yaml")
		require.NoError(t, os.WriteFile(bad, []byte("server_url: ["), 0o600))
		t.Setenv("HEADSCALE_CONFIG", bad)

		cmd, _ := newCheckPolicyCmd(t, writePolicy(t, valid))
		require.NoError(t, checkPolicyCmd.RunE(cmd, nil))
	})
}

// writeServerConfig writes a valid server config with relative key and
// database paths, plus extra, to dir/config.yaml.
func writeServerConfig(t *testing.T, dir, extra string) string {
	t.Helper()

	p := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(`server_url: https://headscale.example.com
noise:
  private_key_path: noise.key
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite3
  sqlite:
    path: headscale.db
dns:
  magic_dns: false
  override_local_dns: false
`+extra), 0o600))

	return p
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()

	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))

	return p
}

func runCheck(t *testing.T, c *cobra.Command, file string) (string, error) {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)

	cmd := &cobra.Command{}
	cmd.Flags().String("file", file, "")

	var buf bytes.Buffer

	cmd.SetOut(&buf)

	err := c.RunE(cmd, nil)

	return buf.String(), err
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}

	return names
}

const badGroupPolicy = `{"acls":[{"action":"accept","src":["group:missing"],"dst":["*:*"]}]}`

func TestCheckConfig(t *testing.T) {
	t.Run("valid creates nothing", func(t *testing.T) {
		dir := t.TempDir()
		cfg := writeServerConfig(t, dir, "")

		out, err := runCheck(t, checkConfigCmd, cfg)
		require.NoError(t, err)
		require.Equal(t, "Configuration "+cfg+" is valid\n", out)
		require.Equal(t, []string{"config.yaml"}, dirNames(t, dir))
	})

	t.Run("named files are not checked", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "policy.hujson", badGroupPolicy)

		_, err := runCheck(t, checkConfigCmd, writeServerConfig(t, dir, "policy:\n  path: policy.hujson\n"))
		require.NoError(t, err)
	})

	t.Run("bad server_url", func(t *testing.T) {
		dir := t.TempDir()
		cfg := writeFile(t, dir, "config.yaml", "server_url: ftp://x\n")

		_, err := runCheck(t, checkConfigCmd, cfg)
		require.ErrorContains(t, err, "server_url")
	})

	t.Run("derp server without key path", func(t *testing.T) {
		dir := t.TempDir()

		_, err := runCheck(t, checkConfigCmd, writeServerConfig(t, dir,
			"derp:\n  server:\n    enabled: true\n    stun_listen_addr: \"0.0.0.0:3478\"\n"))
		require.ErrorContains(t, err, "derp.server.private_key_path is required")
	})

	t.Run("arguments are rejected", func(t *testing.T) {
		require.Error(t, checkConfigCmd.Args(checkConfigCmd, []string{"other.yaml"}))
	})
}

func TestCheckAll(t *testing.T) {
	t.Run("one line per file", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "policy.hujson", badGroupPolicy)
		derpMap := writeFile(t, dir, "derp.yaml", `regions:
  900:
    regionid: 900
    regioncode: test
    nodes:
      - name: 900a
        regionid: 900
        hostname: derp.example.com
`)
		cfg := writeServerConfig(t, dir, fmt.Sprintf("policy:\n  path: policy.hujson\nderp:\n  paths: [%q]\n", derpMap))

		out, err := runCheck(t, checkAllCmd, cfg)
		require.ErrorIs(t, err, errCheckFailed)
		require.ErrorContains(t, err, "1 of 3 files")

		// Keys are padded to the longest, noise.private_key_path.
		line := func(status, key, path string) string {
			return fmt.Sprintf("%-4s  %-22s  %s", status, key, path)
		}
		lines := strings.Split(out, "\n")
		require.Equal(t, line("ok", "config", cfg), lines[0])
		require.Equal(t, line("FAIL", "policy.path", filepath.Join(dir, "policy.hujson")), lines[1])
		require.True(t, strings.HasPrefix(lines[2], "      "), "error indented under its file: %q", lines[2])
		require.Contains(t, lines[2], "group:missing")
		require.Contains(t, lines, line("ok", "derp.paths", derpMap))
		require.Contains(t, lines, line("skip", "noise.private_key_path", filepath.Join(dir, "noise.key")+" (missing; startup creates it)"))

		require.Equal(t, []string{"config.yaml", "derp.yaml", "policy.hujson"}, dirNames(t, dir))
	})

	t.Run("all files valid", func(t *testing.T) {
		dir := t.TempDir()

		out, err := runCheck(t, checkAllCmd, writeServerConfig(t, dir, ""))
		require.NoError(t, err)
		require.NotContains(t, out, "FAIL")
	})

	t.Run("config fails and files are not checked", func(t *testing.T) {
		dir := t.TempDir()
		cfg := writeFile(t, dir, "config.yaml", "server_url: ftp://x\n")

		out, err := runCheck(t, checkAllCmd, cfg)
		require.ErrorIs(t, err, errCheckFailed)
		require.True(t, strings.HasPrefix(out, "FAIL  config  "+cfg+"\n"), out)
		require.Contains(t, out, "server_url")
	})
}

func TestCheckFileCommands(t *testing.T) {
	dir := t.TempDir()

	out, err := runCheck(t, checkExtraRecordsCmd,
		writeFile(t, dir, "r.json", `[{"name":"a.example.com","type":"A","value":"100.64.0.1"}]`))
	require.NoError(t, err)
	require.Equal(t, "Extra records are valid\n", out)

	_, err = runCheck(t, checkExtraRecordsCmd, writeFile(t, dir, "bad.json", "{"))
	require.ErrorContains(t, err, "bad.json")

	_, err = runCheck(t, checkDERPMapCmd, writeFile(t, dir, "d.yaml", "{}"))
	require.ErrorContains(t, err, "d.yaml")
}
