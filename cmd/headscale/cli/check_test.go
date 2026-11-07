package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/config"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
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
		{"generate config", []string{"generate", "config"}, true},
		{"generate config running", []string{"generate", "config", "--running"}, true},
		{"generate config with config flag", []string{"-c", "x.yaml", "generate", "config"}, true},
		{"gen config", []string{"gen", "config"}, true},
		{"help generate config", []string{"help", "generate", "config"}, true},
		{"generate nixos-options", []string{"generate", "nixos-options"}, true},
		{"generate nixos-options release", []string{"generate", "nixos-options", "--release"}, true},
		{"generate private-key", []string{"generate", "private-key"}, false},
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

	t.Run("server_url only", func(t *testing.T) {
		dir := t.TempDir()
		cfg := writeFile(t, dir, "config.yaml", "server_url: https://headscale.example.com\n")

		d := config.Default()
		paths := []string{filepath.Dir(d.Noise.PrivateKeyPath), d.Noise.PrivateKeyPath, d.Database.Sqlite.Path}
		before := existing(paths)

		out, err := runCheck(t, checkConfigCmd, cfg)
		require.NoError(t, err)
		require.Equal(t, "Configuration "+cfg+" is valid\n", out)
		require.Equal(t, []string{"config.yaml"}, dirNames(t, dir))
		require.Equal(t, before, existing(paths), "the check created a default path")
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

	// Each problem once: an empty server_url is not also missing a scheme.
	for _, tt := range []struct{ name, file, want string }{
		{name: "empty file", file: "# empty\n", want: "server_url is required"},
		{
			name: "empty listen_addr",
			file: "server_url: https://headscale.example.com\nlisten_addr: \"\"\n",
			want: "listen_addr is required",
		},
		{
			name: "empty sqlite path",
			file: "server_url: https://headscale.example.com\ndatabase:\n  sqlite:\n    path: \"\"\n",
			want: "database.sqlite.path is required when database.type is sqlite",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := runCheck(t, checkConfigCmd, writeFile(t, t.TempDir(), "config.yaml", tt.file))
			require.ErrorContains(t, err, tt.want)
			require.NotContains(t, err.Error(), "missing a scheme")
			require.Equal(t, 1, strings.Count(err.Error(), "Fatal config error"), err.Error())
		})
	}

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

// TestCheckConfigEnvOnly: HEADSCALE_SERVER_URL alone, without a file, is a
// valid configuration.
func TestCheckConfigEnvOnly(t *testing.T) {
	stdout, stderr, err := runHeadscale(t, []string{"HOME=" + t.TempDir(), "HEADSCALE_SERVER_URL=https://headscale.example.com"}, "check", "config")
	require.NoError(t, err, stderr)
	require.Equal(t, "Configuration (defaults and environment) is valid\n", stdout)
}

// existing reports, for each path, whether it exists.
func existing(paths []string) []bool {
	out := make([]bool, len(paths))
	for i, p := range paths {
		_, err := os.Stat(p)
		out[i] = err == nil
	}

	return out
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

// No check reads a file: secret: its file may exist only for the service
// (systemd credentials, sops, agenix). check all lists each one as skipped.
func TestCheckSecretsUnread(t *testing.T) {
	const acmeDNS = `  challenge:
    provider:
      name: acmedns
`

	t.Run("missing secret files", func(t *testing.T) {
		dir := t.TempDir()
		missing := filepath.Join(dir, "missing")

		for k, v := range map[string]string{
			"HEADSCALE_OIDC_ISSUER":                      "https://idp.example.com",
			"HEADSCALE_OIDC_CLIENT_ID":                   "headscale",
			"HEADSCALE_OIDC_CLIENT_SECRET":               "file:" + missing,
			"HEADSCALE_DATABASE_TYPE":                    "postgres",
			"HEADSCALE_DATABASE_POSTGRES_PASS":           "file:" + missing,
			"HEADSCALE_DNS_CHALLENGE_PROVIDER_NAME":      "cloudflare",
			"HEADSCALE_DNS_CHALLENGE_PROVIDER_API_TOKEN": "file:" + missing,
		} {
			t.Setenv(k, v)
		}

		cfg := writeServerConfig(t, dir, "")

		_, err := runCheck(t, checkConfigCmd, cfg)
		require.NoError(t, err)

		out, err := runCheck(t, checkAllCmd, cfg)
		require.NoError(t, err)

		lines := strings.Split(out, "\n")
		for _, key := range []string{"oidc.client_secret", "database.postgres.pass", "dns.challenge.provider.api_token"} {
			require.Contains(t, lines, fmt.Sprintf("skip  %-32s  %s (secret, not read)", key, missing))
		}
	})

	t.Run("acme-dns registrations from file", func(t *testing.T) {
		dir := t.TempDir()
		missing := filepath.Join(dir, "missing")
		cfg := writeServerConfig(t, dir, acmeDNS+`      config: "file:`+missing+`"
`)

		_, err := runCheck(t, checkConfigCmd, cfg)
		require.NoError(t, err)

		out, err := runCheck(t, checkAllCmd, cfg)
		require.NoError(t, err)
		require.Contains(t, strings.Split(out, "\n"), "skip  dns.challenge.provider.config  "+missing+" (secret, not read)")
	})

	// A URL from a file cannot be validated unread.
	for name, provider := range map[string]string{
		"account": acmeDNS + `      username: user
      password: pass
      subdomain: reg
      server_url: "file:%s"
`,
		"registration": acmeDNS + `      config:
        laptop.example.com:
          username: user
          password: pass
          subdomain: reg
          server_url: "file:%s"
`,
	} {
		t.Run("acme-dns "+name+" url from file", func(t *testing.T) {
			dir := t.TempDir()
			cfg := writeServerConfig(t, dir, fmt.Sprintf(provider, filepath.Join(dir, "missing")))

			for _, c := range []*cobra.Command{checkConfigCmd, checkAllCmd} {
				_, err := runCheck(t, c, cfg)
				require.NoError(t, err, c.Name())
			}
		})
	}

	// Setting names match case-insensitively, as the decoder matches them;
	// only the environment's JSON keeps their case.
	for _, field := range []string{"server_url", "SERVER_URL", "Server_URL"} {
		t.Run("acme-dns registration "+field+" from file in env json", func(t *testing.T) {
			dir := t.TempDir()

			t.Setenv("HEADSCALE_DNS_CHALLENGE_PROVIDER_NAME", "acmedns")
			t.Setenv("HEADSCALE_DNS_CHALLENGE_PROVIDER", fmt.Sprintf(
				`{"config":{"Node.Example.com":{"username":"user","password":"pass","subdomain":"reg",%q:"file:%s"}}}`,
				field, filepath.Join(dir, "missing")))

			cfg := writeServerConfig(t, dir, "")

			for _, c := range []*cobra.Command{checkConfigCmd, checkAllCmd} {
				_, err := runCheck(t, c, cfg)
				require.NoError(t, err, c.Name())
			}
		})
	}
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

// TestCheckConfigWarnings: the check commands report what the environment
// warns about, with a valid file and with one that fails, and on a valid
// file the configuration's advisories, in its log.format and at its
// log.level.
func TestCheckConfigWarnings(t *testing.T) {
	const (
		unknown  = "unknown environment variable HEADSCALE_BOGUS"
		removed  = "configuration variable HEADSCALE_DB_TYPE was removed"
		advisory = "listen_addr should probably end in :443"
		acme     = "tls:\n  acme:\n    hostname: example.com\n    challenge_type: TLS-ALPN-01\n"
	)

	t.Setenv("HEADSCALE_BOGUS", "1")
	t.Setenv("HEADSCALE_DB_TYPE", "sqlite")

	dir := t.TempDir()
	text := writeServerConfig(t, t.TempDir(), acme)
	jsonLogs := writeServerConfig(t, t.TempDir(), acme+"log:\n  format: json\n")
	errorLevel := writeServerConfig(t, t.TempDir(), acme+"log:\n  level: error\n")
	disabled := writeServerConfig(t, t.TempDir(), acme+"log:\n  level: disabled\n")
	invalid := writeFile(t, dir, "invalid.yaml", "log:\n  format: json\nbogus_key: 1\n")

	oldLogger, oldLevel := log.Logger, zerolog.GlobalLevel()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	t.Cleanup(func() {
		log.Logger = oldLogger

		zerolog.SetGlobalLevel(oldLevel)
	})

	for _, c := range []*cobra.Command{checkConfigCmd, checkAllCmd} {
		for _, tt := range []struct {
			name, file string
			wantErr    bool
			// json: the warnings are JSON on the command's stderr, not on
			// the logger the command started with.
			json bool
			// quiet: log.level hides every warning.
			quiet bool
		}{
			{name: "text", file: text},
			{name: "json", file: jsonLogs, json: true},
			{name: "invalid", file: invalid, wantErr: true},
			{name: "level error", file: errorLevel, quiet: true},
			{name: "level disabled", file: disabled, quiet: true},
		} {
			t.Run(c.Name()+" "+tt.name, func(t *testing.T) {
				var logged, stderr bytes.Buffer

				// As initConfig leaves it for the check commands.
				log.Logger = zerolog.New(&logged)

				zerolog.SetGlobalLevel(zerolog.InfoLevel)

				cmd := &cobra.Command{}
				cmd.Flags().String("file", tt.file, "")
				cmd.SetOut(io.Discard)
				cmd.SetErr(&stderr)

				err := c.RunE(cmd, nil)
				require.Equal(t, tt.wantErr, err != nil, "%v", err)

				out := logged.String()
				if tt.quiet {
					assert.Empty(t, out)
					assert.Empty(t, stderr.String())

					return
				}

				if tt.json {
					assert.Empty(t, out)

					out = stderr.String()
					for l := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
						var rec struct{ Level, Message string }
						require.NoError(t, json.Unmarshal([]byte(l), &rec), l)
						assert.Equal(t, "warn", rec.Level)
					}
				} else {
					assert.Empty(t, stderr.String())
				}

				assert.Contains(t, out, unknown)
				assert.Contains(t, out, removed)

				if tt.wantErr {
					assert.NotContains(t, out, advisory)
				} else {
					assert.Contains(t, out, advisory)
				}
			})
		}
	}
}
