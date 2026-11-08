package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	v23       = "0.23.0"
	v23Alpha1 = "0.23.0-alpha.1"
	v23Beta1  = "0.23.0-beta.1"
	v23RC1    = "0.23.0-rc.1"
	v23Dev    = "0.23.0-dev"
	v231      = "0.23.1"

	v24Alpha1Tag = "v0.24.0-alpha.1"
	v24RCTag     = "v0.24.0-rc.1"
	v24Tag       = "v0.24.0"
)

func TestFilterPreReleasesIfStable(t *testing.T) {
	tests := []struct {
		name           string
		currentVersion string
		tag            string
		expectedFilter bool
		description    string
	}{
		{
			name:           "stable version filters alpha tag",
			currentVersion: v23,
			tag:            v24Alpha1Tag,
			expectedFilter: true,
			description:    "When on stable release, alpha tags should be filtered",
		},
		{
			name:           "stable version filters beta tag",
			currentVersion: v23,
			tag:            "v0.24.0-beta.2",
			expectedFilter: true,
			description:    "When on stable release, beta tags should be filtered",
		},
		{
			name:           "stable version filters rc tag",
			currentVersion: v23,
			tag:            v24RCTag,
			expectedFilter: true,
			description:    "When on stable release, rc tags should be filtered",
		},
		{
			name:           "stable version allows stable tag",
			currentVersion: v23,
			tag:            v24Tag,
			expectedFilter: false,
			description:    "When on stable release, stable tags should not be filtered",
		},
		{
			name:           "alpha version allows alpha tag",
			currentVersion: v23Alpha1,
			tag:            "v0.24.0-alpha.2",
			expectedFilter: false,
			description:    "When on alpha release, alpha tags should not be filtered",
		},
		{
			name:           "alpha version allows beta tag",
			currentVersion: v23Alpha1,
			tag:            "v0.24.0-beta.1",
			expectedFilter: false,
			description:    "When on alpha release, beta tags should not be filtered",
		},
		{
			name:           "alpha version allows rc tag",
			currentVersion: v23Alpha1,
			tag:            v24RCTag,
			expectedFilter: false,
			description:    "When on alpha release, rc tags should not be filtered",
		},
		{
			name:           "alpha version allows stable tag",
			currentVersion: v23Alpha1,
			tag:            v24Tag,
			expectedFilter: false,
			description:    "When on alpha release, stable tags should not be filtered",
		},
		{
			name:           "beta version allows alpha tag",
			currentVersion: v23Beta1,
			tag:            v24Alpha1Tag,
			expectedFilter: false,
			description:    "When on beta release, alpha tags should not be filtered",
		},
		{
			name:           "beta version allows beta tag",
			currentVersion: "0.23.0-beta.2",
			tag:            "v0.24.0-beta.3",
			expectedFilter: false,
			description:    "When on beta release, beta tags should not be filtered",
		},
		{
			name:           "beta version allows rc tag",
			currentVersion: v23Beta1,
			tag:            v24RCTag,
			expectedFilter: false,
			description:    "When on beta release, rc tags should not be filtered",
		},
		{
			name:           "beta version allows stable tag",
			currentVersion: v23Beta1,
			tag:            v24Tag,
			expectedFilter: false,
			description:    "When on beta release, stable tags should not be filtered",
		},
		{
			name:           "rc version allows alpha tag",
			currentVersion: v23RC1,
			tag:            v24Alpha1Tag,
			expectedFilter: false,
			description:    "When on rc release, alpha tags should not be filtered",
		},
		{
			name:           "rc version allows beta tag",
			currentVersion: v23RC1,
			tag:            "v0.24.0-beta.1",
			expectedFilter: false,
			description:    "When on rc release, beta tags should not be filtered",
		},
		{
			name:           "rc version allows rc tag",
			currentVersion: "0.23.0-rc.2",
			tag:            "v0.24.0-rc.3",
			expectedFilter: false,
			description:    "When on rc release, rc tags should not be filtered",
		},
		{
			name:           "rc version allows stable tag",
			currentVersion: v23RC1,
			tag:            v24Tag,
			expectedFilter: false,
			description:    "When on rc release, stable tags should not be filtered",
		},
		{
			name:           "stable version with patch filters alpha",
			currentVersion: v231,
			tag:            v24Alpha1Tag,
			expectedFilter: true,
			description:    "Stable version with patch number should filter alpha tags",
		},
		{
			name:           "stable version with patch allows stable",
			currentVersion: v231,
			tag:            v24Tag,
			expectedFilter: false,
			description:    "Stable version with patch number should allow stable tags",
		},
		{
			name:           "tag with alpha substring in version number",
			currentVersion: v23,
			tag:            "v1.0.0-alpha.1",
			expectedFilter: true,
			description:    "Tags with alpha in version string should be filtered on stable",
		},
		{
			name:           "tag with beta substring in version number",
			currentVersion: v23,
			tag:            "v1.0.0-beta.1",
			expectedFilter: true,
			description:    "Tags with beta in version string should be filtered on stable",
		},
		{
			name:           "tag with rc substring in version number",
			currentVersion: v23,
			tag:            "v1.0.0-rc.1",
			expectedFilter: true,
			description:    "Tags with rc in version string should be filtered on stable",
		},
		{
			name:           "empty tag on stable version",
			currentVersion: v23,
			tag:            "",
			expectedFilter: false,
			description:    "Empty tags should not be filtered",
		},
		{
			name:           "dev version allows all tags",
			currentVersion: v23Dev,
			tag:            v24Alpha1Tag,
			expectedFilter: false,
			description:    "Dev versions should not filter any tags (pre-release allows all)",
		},
		{
			name:           "stable version filters dev tag",
			currentVersion: v23,
			tag:            "v0.24.0-dev",
			expectedFilter: true,
			description:    "When on stable release, dev tags should be filtered",
		},
		{
			name:           "dev version allows dev tag",
			currentVersion: v23Dev,
			tag:            "v0.24.0-dev.1",
			expectedFilter: false,
			description:    "When on dev release, dev tags should not be filtered",
		},
		{
			name:           "dev version allows stable tag",
			currentVersion: v23Dev,
			tag:            v24Tag,
			expectedFilter: false,
			description:    "When on dev release, stable tags should not be filtered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterPreReleasesIfStable(func() string { return tt.currentVersion })(tt.tag)
			if result != tt.expectedFilter {
				t.Errorf(
					"%s: got %v, want %v\nDescription: %s\nCurrent version: %s, Tag: %s",
					tt.name,
					result,
					tt.expectedFilter,
					tt.description,
					tt.currentVersion,
					tt.tag,
				)
			}
		})
	}
}

func TestIsPreReleaseVersion(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expected    bool
		description string
	}{
		{
			name:        "stable version",
			version:     v23,
			expected:    false,
			description: "Stable version should not be pre-release",
		},
		{
			name:        "alpha version",
			version:     v23Alpha1,
			expected:    true,
			description: "Alpha version should be pre-release",
		},
		{
			name:        "beta version",
			version:     v23Beta1,
			expected:    true,
			description: "Beta version should be pre-release",
		},
		{
			name:        "rc version",
			version:     v23RC1,
			expected:    true,
			description: "RC version should be pre-release",
		},
		{
			name:        "version with alpha substring",
			version:     "0.23.0-alphabetical",
			expected:    true,
			description: "Version containing 'alpha' should be pre-release",
		},
		{
			name:        "version with beta substring",
			version:     "0.23.0-betamax",
			expected:    true,
			description: "Version containing 'beta' should be pre-release",
		},
		{
			name:        "dev version",
			version:     v23Dev,
			expected:    true,
			description: "Dev version should be pre-release",
		},
		{
			name:        "empty version",
			version:     "",
			expected:    false,
			description: "Empty version should not be pre-release",
		},
		{
			name:        "version with patch number",
			version:     v231,
			expected:    false,
			description: "Stable version with patch should not be pre-release",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPreReleaseVersion(tt.version)
			if result != tt.expected {
				t.Errorf(
					"%s: got %v, want %v\nDescription: %s\nVersion: %s",
					tt.name,
					result,
					tt.expected,
					tt.description,
					tt.version,
				)
			}
		})
	}
}

func TestOfflineSetPolicyRunsTests(t *testing.T) {
	for _, tt := range []struct {
		name    string
		policy  string
		invalid bool
	}{
		{
			name: "passing packet test uses database nodes",
			policy: `{
  "acls": [{"action":"accept","src":["alice@"],"dst":["bob@:22"]}],
  "tests": [{"src":"alice@","accept":["bob@:22"]}]
}`,
		},
		{
			name: "failing packet test preserves stored policy",
			policy: `{
  "acls": [],
  "tests": [{"src":"alice@","accept":["bob@:22"]}]
}`,
			invalid: true,
		},
		{
			name: "failing SSH test preserves stored policy",
			policy: `{
  "acls": [{"action":"accept","src":["*"],"dst":["*:*"]}],
  "ssh": [{"action":"accept","src":["alice@"],"dst":["autogroup:self"],"users":["root"]}],
  "sshTests": [{"src":"bob@","dst":["alice@"],"accept":["root"]}]
}`,
			invalid: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
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
			useLoaded(t, configPath)

			database, err := db.NewHeadscaleDatabase(serverConfig())
			require.NoError(t, err)

			t.Cleanup(func() { _ = database.Close() })

			for _, name := range []string{"alice", "bob"} {
				user := database.CreateUserForTest(name)
				database.CreateRegisteredNodeForTest(user, name+"-node")
			}

			const oldPolicy = `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`

			before, err := database.SetPolicy(oldPolicy)
			require.NoError(t, err)

			path := filepath.Join(dir, "policy.hujson")
			require.NoError(t, os.WriteFile(path, []byte(tt.policy), 0o600))

			cmd := &cobra.Command{}
			cmd.Flags().String("file", path, "")
			cmd.Flags().Bool(bypassFlag, true, "")
			cmd.Flags().Bool("force", true, "")

			err = setPolicy.RunE(cmd, nil)
			if tt.invalid {
				require.ErrorContains(t, err, "test(s) failed")
			} else {
				require.NoError(t, err)
			}

			after, err := database.GetPolicy()
			require.NoError(t, err)

			if tt.invalid {
				require.Equal(t, before.ID, after.ID)
				require.JSONEq(t, oldPolicy, after.Data)
			} else {
				require.JSONEq(t, tt.policy, after.Data)
			}
		})
	}
}

// useLoaded loads path as initConfig does, until the test ends.
func useLoaded(t *testing.T, path string) {
	t.Helper()

	l, err := loadConfig(path)
	require.NoError(t, err)

	old := loaded
	loaded = l

	t.Cleanup(func() { loaded = old })
}

func TestInitConfigSkippedLogLevel(t *testing.T) {
	oldArgs, oldLevel := os.Args, zerolog.GlobalLevel()

	t.Cleanup(func() {
		os.Args = oldArgs

		zerolog.SetGlobalLevel(oldLevel)
	})

	os.Args = []string{"headscale", "check", "policy", "-f", "p"}

	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	initConfig()
	require.Equal(t, zerolog.InfoLevel, zerolog.GlobalLevel(), "log.level's default, as with a config")
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	conf := func(name string) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte("server_url: https://"+name+"\n"), 0o600))

		return p
	}
	flag, global, env := conf("flag.yaml"), conf("global.yaml"), conf("env.yaml")

	tests := []struct {
		name               string
		path, cfgFile, env string
		want               string
	}{
		{"path wins", flag, global, env, flag},
		{"then -c", "", global, env, global},
		{"then HEADSCALE_CONFIG", "", "", env, env},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HEADSCALE_CONFIG", tt.env)

			old := cfgFile
			cfgFile = tt.cfgFile

			t.Cleanup(func() { cfgFile = old })

			l, err := loadConfig(tt.path)
			require.NoError(t, err)
			require.Equal(t, tt.want, l.File)
		})
	}
}

// TestCLIOnlyConfig: a file with only what client commands read, as the
// NixOS module writes to /etc/headscale/config.yaml, serves them; check
// config reports what the server lacks.
func TestCLIOnlyConfig(t *testing.T) {
	path := writeFile(t, t.TempDir(), "config.yaml", `cli:
  address: headscale.example.com:443
  api_key: abc
unix_socket: /run/headscale/headscale.sock
`)

	useLoaded(t, path)

	_, _, cancel, err := newHeadscaleCLIWithConfig()
	require.NoError(t, err)
	cancel()

	_, err = runCheck(t, checkConfigCmd, path)
	require.ErrorContains(t, err, "server_url")
}

// runHeadscale runs the CLI as main does, in a child process: loading a
// config can exit it.
func runHeadscale(t *testing.T, env []string, args ...string) (string, string, error) {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHeadscaleProcess$") //nolint:gosec // this test binary

	cmd.Env = append([]string{"HEADSCALE_TEST_ARGS=" + strings.Join(args, "\n")}, env...)

	var stdout, stderr bytes.Buffer

	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()

	return stdout.String(), stderr.String(), err
}

// TestHeadscaleProcess is the child of runHeadscale.
func TestHeadscaleProcess(t *testing.T) {
	args := os.Getenv("HEADSCALE_TEST_ARGS")
	if args == "" {
		t.Skip("run by runHeadscale")
	}

	os.Args = append([]string{"headscale"}, strings.Split(args, "\n")...)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: true})

	zerolog.SetGlobalLevel(zerolog.TraceLevel)

	Execute()
	os.Exit(0)
}

// TestInitConfigWarnings: what loading warns about follows log.format, never
// reaches stdout under machine output, and is reported with a load error.
func TestInitConfigWarnings(t *testing.T) {
	const warning = "unknown environment variable HEADSCALE_BOGUS"

	env := []string{"HEADSCALE_BOGUS=1", "HEADSCALE_DISABLE_CHECK_UPDATES=true"}
	dir := t.TempDir()
	jsonLogs := writeFile(t, dir, "json.yaml", "log:\n  format: json\n")
	invalid := writeFile(t, dir, "invalid.yaml", "bogus_key: 1\n")

	// warnLine is the line holding the warning, as JSON when it is one.
	warnLine := func(t *testing.T, out string) map[string]any {
		t.Helper()

		for l := range strings.SplitSeq(out, "\n") {
			if strings.Contains(l, warning) {
				var m map[string]any

				_ = json.Unmarshal([]byte(l), &m)

				return m
			}
		}

		t.Fatalf("no %q in %q", warning, out)

		return nil
	}

	t.Run("json log format", func(t *testing.T) {
		stdout, stderr, err := runHeadscale(t, env, "-c", jsonLogs, "generate", "private-key")
		require.NoError(t, err, stderr)
		assert.Equal(t, "warn", warnLine(t, stdout+stderr)["level"])
	})

	// Every spelling Cobra accepts for --output.
	for _, format := range []string{"json", "json-line", "yaml"} {
		for _, flag := range [][]string{
			{"-o", format}, {"--output", format}, {"--output=" + format}, {"-o=" + format}, {"-o" + format},
		} {
			t.Run("machine output "+strings.Join(flag, " "), func(t *testing.T) {
				stdout, stderr, err := runHeadscale(t, env, append([]string{"-c", jsonLogs, "generate", "private-key"}, flag...)...)
				require.NoError(t, err, stderr)

				// JSON is YAML too; the result is one object.
				var out map[string]string
				require.NoError(t, yaml.Unmarshal([]byte(stdout), &out), stdout)
				assert.Equal(t, []string{"private_key"}, slices.Collect(maps.Keys(out)))
				assert.Equal(t, "warn", warnLine(t, stderr)["level"])
			})
		}
	}

	// version has its own --output, which shadows the root's.
	for _, flag := range [][]string{{"-o", "json"}, {"--output=json"}} {
		t.Run("version "+strings.Join(flag, " "), func(t *testing.T) {
			stdout, stderr, err := runHeadscale(t, env, append([]string{"-c", jsonLogs, "version"}, flag...)...)
			require.NoError(t, err, stderr)

			var out map[string]any
			require.NoError(t, json.Unmarshal([]byte(stdout), &out), stdout)
			assert.Contains(t, out, "version")
			assert.Equal(t, "warn", warnLine(t, stderr)["level"])
		})
	}

	for _, output := range [][]string{nil, {"-o", "json"}} {
		t.Run("load error "+strings.Join(output, " "), func(t *testing.T) {
			stdout, stderr, err := runHeadscale(t, env, append([]string{"-c", invalid, "generate", "private-key"}, output...)...)
			require.Error(t, err)
			assert.Empty(t, stdout)
			warnLine(t, stderr)
			assert.Contains(t, stderr, "unknown configuration key bogus_key")
			assert.NotContains(t, stderr, "panic")
		})
	}
}
