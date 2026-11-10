package config

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"math"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	hsdns "github.com/juanfont/headscale/hscontrol/dns"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/v2"
	"github.com/libdns/cloudflare"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

// TestMain runs the tests from this directory, so the relative testdata/
// paths resolve when the binary runs elsewhere (e.g. via "go tool stress").
func TestMain(m *testing.M) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("could not determine test source directory")
	}

	err := os.Chdir(filepath.Dir(filename))
	if err != nil {
		panic("could not chdir to test source directory: " + err.Error())
	}

	os.Exit(m.Run())
}

// writeConfig writes content as config.yaml and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()

	p := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))

	return p
}

func TestConfigSource(t *testing.T) {
	tests := []struct {
		name      string
		file      string // written as config.yaml unless fileName is set
		fileName  string
		emptyFile bool
		env       []string
		errs      []string // substrings of the error
		warns     []string // substrings, one per expected warning
		check     func(t *testing.T, cfg *types.Config)
	}{
		{
			name: "unknown file key",
			file: "server_url: http://x\ndns:\n  magic_dsn: true\n",
			errs: []string{"unknown configuration key dns.magic_dsn (", "config.yaml:3:3)"},
		},
		{
			name: "removed file key",
			file: "grpc_listen_addr: :50443\n",
			errs: []string{"grpc_listen_addr", "removed"},
		},
		{
			name: "removed file prefix",
			file: "dns_config:\n  magic_dns: true\n",
			errs: []string{"dns_config", "removed", "dns"},
		},
		{
			name: "all problems collected",
			file: "grpc_listen_addr: x\nbogus: 1\n",
			errs: []string{"grpc_listen_addr", "bogus"},
		},
		{
			name:  "removed env warns",
			env:   []string{"HEADSCALE_EPHEMERAL_NODE_INACTIVITY_TIMEOUT=30m"},
			warns: []string{"configuration variable HEADSCALE_EPHEMERAL_NODE_INACTIVITY_TIMEOUT was removed in 0.30; use HEADSCALE_NODE_EPHEMERAL_INACTIVITY_TIMEOUT"},
		},
		{
			name:  "unknown env warns",
			env:   []string{"HEADSCALE_SERVR_URL=x"},
			warns: []string{"unknown environment variable HEADSCALE_SERVR_URL"},
		},
		{
			name: "reserved env is silent",
			env: []string{
				"HEADSCALE_PORT=tcp://10.0.0.1:8080", "HEADSCALE_SERVICE_HOST=x", "HEADSCALE_DEBUG_FOO=1",
				"HEADSCALE_DNS_CHALLENGE_PROVIDER_API_TOKEN=x", "HEADSCALE_CONFIG=/x", "HEADSCALE_TEST_X=1",
				"HEADSCALE_INTEGRATION_X=1", "HEADSCALE_UPDATE_GOLDEN=1",
			},
		},
		{
			// What Kubernetes sets for a Service named headscale-db.
			name:  "service variable named like a removed key warns",
			env:   []string{"HEADSCALE_DB_PORT=tcp://10.0.0.5:5432"},
			warns: []string{"configuration variable HEADSCALE_DB_PORT was removed in 0.30; use HEADSCALE_DATABASE_POSTGRES_PORT"},
		},
		{
			name: "env shared with a removed key still sets the new key",
			env:  []string{"HEADSCALE_LOG_LEVEL=debug", "HEADSCALE_TLS_CERT_PATH=/c"},
			check: func(t *testing.T, cfg *types.Config) {
				t.Helper()
				assert.Equal(t, types.LogLevel("debug"), cfg.Log.Level)
				assert.Equal(t, "/c", cfg.TLS.CertPath)
			},
		},
		{
			name: "keys match only as written, in lower case",
			file: "Server_URL: https://x\nserver_url: https://y\nDNS:\n  magic_dns: true\n",
			errs: []string{
				"unknown configuration key Server_URL (", "config.yaml:1:1)",
				"unknown configuration key DNS (", "config.yaml:3:1)",
			},
		},
		{
			name: "null is unset, default stays",
			file: "server_url:\nlog:\n  level: ~\n",
			check: func(t *testing.T, cfg *types.Config) {
				t.Helper()
				assert.Empty(t, cfg.ServerURL)
				assert.Equal(t, types.LogLevel("info"), cfg.Log.Level)
			},
		},
		{
			name: "empty env is unset, env beats file",
			file: "server_url: http://file\nlisten_addr: 1.1.1.1:1\n",
			env:  []string{"HEADSCALE_SERVER_URL=http://env", "HEADSCALE_LISTEN_ADDR="},
			check: func(t *testing.T, cfg *types.Config) {
				t.Helper()
				assert.Equal(t, "http://env", cfg.ServerURL)
				assert.Equal(t, types.ListenAddr("1.1.1.1:1"), cfg.Addr)
			},
		},
		{
			name: "env lists and maps",
			env: []string{
				"HEADSCALE_DNS_NAMESERVERS_GLOBAL=1.1.1.1 8.8.8.8",
				`HEADSCALE_OIDC_EXTRA_PARAMS={"domain_hint":"example.com"}`,
			},
			check: func(t *testing.T, cfg *types.Config) {
				t.Helper()
				assert.Equal(t, []string{"1.1.1.1", "8.8.8.8"}, cfg.DNSConfig.Nameservers.Global)
				assert.Equal(t, map[string]string{"domain_hint": "example.com"}, cfg.OIDC.ExtraParams)
			},
		},
		{
			name: "open maps accept any key",
			file: "dns:\n  challenge:\n    provider:\n      name: cloudflare\n      whatever: 1\noidc:\n  extra_params:\n    a: b\n",
			check: func(t *testing.T, cfg *types.Config) {
				t.Helper()
				assert.Equal(t, "cloudflare", cfg.DNSConfig.Challenge.ProviderName())
				// Settings are text; the provider converts them to its types.
				assert.Equal(t, "1", cfg.DNSConfig.Challenge.ProviderSettings["whatever"])
			},
		},
		{
			name:     "yaml",
			fileName: "config.yaml",
			file:     yamlSample,
			check:    checkSameValues,
		},
		{
			name:     "yml",
			fileName: "config.yml",
			file:     yamlSample,
			check:    checkSameValues,
		},
		{
			name:     "json",
			fileName: "config.json",
			file:     `{"server_url":"https://x","node":{"expiry":"1h"},"dns":{"magic_dns":false,"nameservers":{"global":["1.1.1.1","8.8.8.8"]}},"oidc":{"extra_params":{"domain_hint":"example.com"}}}`,
			check:    checkSameValues,
		},
		{
			name:     "hujson",
			fileName: "config.hujson",
			file:     "{\n // c\n \"server_url\":\"https://x\",\n \"node\":{\"expiry\":\"1h\",},\n \"dns\":{\"magic_dns\":false,\"nameservers\":{\"global\":[\"1.1.1.1\",\"8.8.8.8\",],},},\n \"oidc\":{\"extra_params\":{\"domain_hint\":\"example.com\"}},\n}",
			check:    checkSameValues,
		},
		{
			name:     "hujson syntax error",
			fileName: "config.hujson",
			file:     "{\n // c\n \"server_url\": x,\n}",
			errs:     []string{"config.hujson", "line 3, column 16: not valid HuJSON"},
		},
		{
			name:     "toml is found and rejected",
			fileName: "config.toml",
			file:     "server_url = \"https://x\"\n",
			errs:     []string{`unsupported config file format ".toml": use .json, .yaml, .yml or .hujson`, "config.toml)"},
		},
		{
			name:     ".env is found and rejected",
			fileName: "config.env",
			file:     "SERVER_URL=https://x\n",
			errs:     []string{`unsupported config file format ".env": use .json, .yaml, .yml or .hujson`, "config.env)"},
		},
		{
			name:     ".dotenv is found and rejected",
			fileName: "config.dotenv",
			file:     "SERVER_URL=https://x\n",
			errs:     []string{`unsupported config file format ".dotenv": use .json, .yaml, .yml or .hujson`, "config.dotenv)"},
		},
		{
			name: "nested keys that share leaf names with removed keys",
			file: "noise:\n  private_key_path: /n\nderp:\n  server:\n    private_key_path: /d\nlog:\n  level: debug\ntls:\n  cert_path: /c\ndatabase:\n  sqlite:\n    path: /db\n",
			check: func(t *testing.T, cfg *types.Config) {
				t.Helper()
				assert.Equal(t, "/n", cfg.Noise.PrivateKeyPath)
				assert.Equal(t, "/d", cfg.DERP.Server.PrivateKeyPath)
				assert.Equal(t, types.LogLevel("debug"), cfg.Log.Level)
				assert.Equal(t, "/c", cfg.TLS.CertPath)
				assert.Equal(t, "/db", cfg.Database.Sqlite.Path)
			},
		},
		{
			name: "dotted file keys override nested defaults",
			file: "log.level: debug\ndns.magic_dns: false\ndns:\n  nameservers.split:\n    Corp.Example.com: [10.0.0.1]\n",
			check: func(t *testing.T, cfg *types.Config) {
				t.Helper()
				assert.Equal(t, types.LogLevel("debug"), cfg.Log.Level)
				assert.False(t, cfg.DNSConfig.MagicDNS)
				assert.Equal(t, map[string][]string{"corp.example.com": {"10.0.0.1"}}, cfg.DNSConfig.Nameservers.Split)
			},
		},
		{
			name: "dotted file key in a removed prefix",
			file: "dns_config.magic_dns: true\n",
			errs: []string{"dns_config", "removed"},
		},
		{
			name: "mapping under a plain setting",
			file: "tuning:\n  batcher_workers:\n    bogus: 1\nserver_url:\n  bogus: x\n",
			errs: []string{"unknown configuration key tuning.batcher_workers.bogus", "unknown configuration key server_url.bogus"},
		},
		{
			name: "non-string yaml keys are normalised",
			file: "dns:\n  nameservers:\n    split:\n      123: [1.1.1.1]\n      Corp.Example.com: [10.0.0.1]\n      Empty.Example.com: ~\n",
			check: func(t *testing.T, cfg *types.Config) {
				t.Helper()
				assert.Equal(t,
					map[string][]string{"123": {"1.1.1.1"}, "corp.example.com": {"10.0.0.1"}},
					cfg.DNSConfig.Nameservers.Split)
			},
		},
		{
			name: "removed dns_config env warns",
			env:  []string{"HEADSCALE_DNS_CONFIG_MAGIC_DNS=false", "HEADSCALE_DNS_CONFIG_NAMESERVERS=1.1.1.1"},
			warns: []string{
				"variable HEADSCALE_DNS_CONFIG_MAGIC_DNS was removed in 0.30; use HEADSCALE_DNS_MAGIC_DNS",
				"variable HEADSCALE_DNS_CONFIG_NAMESERVERS was removed in 0.30; use HEADSCALE_DNS_NAMESERVERS_GLOBAL",
			},
		},
		{
			name: "removed block env names the variables replacing it",
			env:  []string{`HEADSCALE_DNS_CONFIG={"magic_dns":true}`, "HEADSCALE_RANDOMIZE_CLIENT_PORT=true"},
			warns: []string{
				"variable HEADSCALE_DNS_CONFIG was removed in 0.30; use HEADSCALE_DNS_MAGIC_DNS, HEADSCALE_DNS_BASE_DOMAIN, " +
					"HEADSCALE_DNS_OVERRIDE_LOCAL_DNS, HEADSCALE_DNS_NAMESERVERS_GLOBAL, HEADSCALE_DNS_NAMESERVERS_SPLIT, " +
					"HEADSCALE_DNS_SEARCH_DOMAINS and HEADSCALE_DNS_EXTRA_RECORDS",
				`variable HEADSCALE_RANDOMIZE_CLIENT_PORT was removed in 0.29; set "randomizeClientPort": true at the top level of the policy file`,
			},
		},
		{
			name:  "exact reserved names do not exempt near misses",
			env:   []string{"HEADSCALE_CONFIG=/x", "HEADSCALE_UPDATE_GOLDEN=1", "HEADSCALE_DNS_CHALLENGE_PROVIDER={}", "HEADSCALE_CONFIG_TYPO=1", "HEADSCALE_UPDATE_GOLDEN_BOGUS=1"},
			warns: []string{"HEADSCALE_CONFIG_TYPO", "HEADSCALE_UPDATE_GOLDEN_BOGUS"},
		},
		{
			name:      "empty file",
			emptyFile: true,
			check: func(t *testing.T, cfg *types.Config) {
				t.Helper()
				assert.Equal(t, types.LogLevel("info"), cfg.Log.Level)
			},
		},
		{
			name:     "unsupported format",
			fileName: "config.ini",
			file:     "a=1\n",
			errs:     []string{"unsupported config file format"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path, isFile := dir, false

			if tt.file != "" || tt.fileName != "" || tt.emptyFile {
				name := cmp.Or(tt.fileName, "config.yaml")
				require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(tt.file), 0o600))

				// .ini is not searched for, so it has to be named.
				if filepath.Ext(name) == ".ini" {
					path, isFile = filepath.Join(dir, name), true
				}
			}

			l, err := Load(path, isFile, tt.env)
			if len(tt.errs) > 0 {
				require.Error(t, err)

				for _, want := range tt.errs {
					require.ErrorContains(t, err, want)
				}

				return
			}

			require.NoError(t, err)
			require.Len(t, l.Warnings, len(tt.warns))

			for i, w := range tt.warns {
				assert.Contains(t, l.Warnings[i], w)
			}

			if tt.check != nil {
				tt.check(t, l.Config)
			}
		})
	}
}

// TestFileContentErrors: a file that cannot be parsed or has an unsupported
// format is a ConfigError, so serve does not retry it, and the error quotes
// nothing from the file, which may hold secrets, whatever the parser says.
func TestFileContentErrors(t *testing.T) {
	for _, tt := range []struct{ name, file, content, want string }{
		{name: "yaml syntax", file: "config.yaml", content: "oidc:\n  client_secret: marker-secret\nderp: [\n", want: "yaml: line 3: did not find expected node content"},
		{name: "yaml scalar document", file: "config.yaml", content: "marker-secret\n", want: "why: the file is not a map of unique keys"},
		{name: "yaml duplicate key", file: "config.yaml", content: "marker-secret: 1\nmarker-secret: 2\n", want: "why: the file is not a map of unique keys"},
		{name: "yaml unknown anchor", file: "config.yaml", content: "server_url: *marker-secret\n", want: "why: not valid YAML"},
		{name: "hujson literal", file: "config.hujson", content: "{\"server_url\": marker-secret}\n", want: "why: line 1, column 16: not valid HuJSON"},
		{name: "json literal", file: "config.json", content: "{\"server_url\": marker-secret}\n", want: "why: line 1, column 16: not valid JSON"},
		{name: "json scalar document", file: "config.json", content: "\"marker-secret\"\n", want: "why: the file is not a map of unique keys"},
		{name: "unsupported format", file: "config.ini", content: "a=marker-secret\n", want: "unsupported config file format"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tt.file)
			require.NoError(t, os.WriteFile(path, []byte(tt.content), 0o600))

			_, err := Load(path, true, nil)
			require.ErrorIs(t, err, types.ErrConfig)
			require.ErrorContains(t, err, tt.want)
			// Not even a truncated value: YAML cuts a quoted value to 7 characters.
			assert.NotContains(t, err.Error(), "marker")
		})
	}

	t.Run("unreadable", func(t *testing.T) {
		_, err := Load(filepath.Join(t.TempDir(), "config.yaml"), true, nil)
		require.ErrorIs(t, err, fs.ErrNotExist)
		assert.NotErrorIs(t, err, types.ErrConfig)
	})
}

const yamlSample = "server_url: https://x\nnode:\n  expiry: 1h\ndns:\n  magic_dns: false\n  nameservers:\n    global: [1.1.1.1, 8.8.8.8]\noidc:\n  extra_params:\n    domain_hint: example.com\n"

func checkSameValues(t *testing.T, cfg *types.Config) {
	t.Helper()
	assert.Equal(t, "https://x", cfg.ServerURL)
	assert.Equal(t, time.Hour, cfg.Node.Expiry)
	assert.False(t, cfg.DNSConfig.MagicDNS)
	assert.Equal(t, []string{"1.1.1.1", "8.8.8.8"}, cfg.DNSConfig.Nameservers.Global)
	assert.Equal(t, map[string]string{"domain_hint": "example.com"}, cfg.OIDC.ExtraParams)
}

func TestConfigSearchDirs(t *testing.T) {
	got := configSearchDirs([]string{"HOME=/h", "XDG_CONFIG_HOME=/xh", "XDG_CONFIG_DIRS=/a:/b"})
	assert.Equal(t, []string{"/etc/headscale", "/xh/headscale", "/a/headscale", "/b/headscale", "/h/.headscale", "."}, got)

	got = configSearchDirs([]string{"HOME=/h"})
	assert.Equal(t, []string{"/etc/headscale", "/h/.config/headscale", "/etc/xdg/headscale", "/h/.headscale", "."}, got)

	xdg := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(xdg, "headscale"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(xdg, "headscale", "config.yaml"), nil, 0o600))
	assert.Equal(t, filepath.Join(xdg, "headscale", "config.yaml"), findConfigFile("", false, []string{"XDG_CONFIG_HOME=" + xdg}))
}

func TestConfigSourceSearch(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("server_url: http://yaml\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"server_url":"http://json"}`), 0o600))

	l, err := Load(dir, false, nil)
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(l.File, "config.json"))
	assert.Equal(t, "http://json", l.Config.ServerURL)

	l, err = Load(t.TempDir(), false, nil)
	require.NoError(t, err)
	assert.Empty(t, l.File)
	assert.Empty(t, l.Warnings)
}

// TestConfigSourceDottedOverlap reloads the file each time: map iteration
// order differs per load, so a single load could hide a nondeterministic result.
func TestConfigSourceDottedOverlap(t *testing.T) {
	tests := []struct{ name, file, a, b string }{
		{"scalar", "log:\n  level: info\nlog.level: debug\n", `"log.level"`, `"log > level"`},
		{"map shadow", "oidc:\n  extra_params:\n    a: nested\noidc.extra_params:\n  b: dotted\n", `"oidc.extra_params"`, `"oidc > extra_params"`},
		{"split fallback", "dns:\n  nameservers:\n    split:\n      a.example.com: [10.0.0.1]\ndns.nameservers:\n  global: [1.1.1.1]\n", `"dns.nameservers"`, `"dns > nameservers"`},
		{"parent map and dotted child", "oidc.extra_params:\n  prompt: login\noidc.extra_params.prompt: consent\n", `"oidc.extra_params"`, `"oidc.extra_params.prompt"`},
		{"open map entry twice", "dns:\n  nameservers:\n    split.corp.example.com: [10.0.0.1]\ndns.nameservers.split.corp.example.com: [10.0.0.2]\n", `"dns > nameservers > split.corp.example.com"`, `"dns.nameservers.split.corp.example.com"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(tt.file), 0o600))

			for range 50 {
				_, err := newConfigSource(dir, false, nil)
				require.ErrorContains(t, err, "is set both as")
				require.ErrorContains(t, err, tt.a)
				require.ErrorContains(t, err, tt.b)
				require.ErrorContains(t, err, "use one form")
			}
		})
	}
}

func TestConfigSourceDottedKeyAlone(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"),
		[]byte("log.level: debug\ndns:\n  magic_dns: false\ndns.nameservers.global: [1.1.1.1]\n"), 0o600))

	for range 50 {
		s, err := newConfigSource(dir, false, nil)
		require.NoError(t, err)

		cfg, err := s.decode()
		require.NoError(t, err)
		require.Equal(t, types.LogLevel("debug"), cfg.Log.Level)
		require.False(t, cfg.DNSConfig.MagicDNS)
		require.Equal(t, []string{"1.1.1.1"}, cfg.DNSConfig.Nameservers.Global)
	}
}

// TestConfigSourceDottedNoOverlap loads files whose dotted keys only share a
// string prefix: below an open map the entry name is one key, dots included.
func TestConfigSourceDottedNoOverlap(t *testing.T) {
	tests := []struct {
		name, file string
		check      func(t *testing.T, cfg *types.Config)
	}{
		{
			name: "dotted split domains",
			file: "dns.nameservers.split.corp.example.com: [10.0.0.1]\ndns.nameservers.split.corp.example.com.au: [10.0.0.2]\n",
			check: func(t *testing.T, cfg *types.Config) {
				t.Helper()
				assert.Equal(t,
					map[string][]string{"corp.example.com": {"10.0.0.1"}, "corp.example.com.au": {"10.0.0.2"}},
					cfg.DNSConfig.Nameservers.Split)
			},
		},
		{
			name: "dotted extra params",
			file: "oidc.extra_params.domain_hint: a\noidc.extra_params.domain_hint.extra: b\n",
			check: func(t *testing.T, cfg *types.Config) {
				t.Helper()
				assert.Equal(t, map[string]string{"domain_hint": "a", "domain_hint.extra": "b"}, cfg.OIDC.ExtraParams)
			},
		},
		{
			name: "nested split domains",
			file: "dns:\n  nameservers:\n    split:\n      corp.example.com: [10.0.0.1]\n      corp.example.com.au: [10.0.0.2]\n",
			check: func(t *testing.T, cfg *types.Config) {
				t.Helper()
				assert.Equal(t,
					map[string][]string{"corp.example.com": {"10.0.0.1"}, "corp.example.com.au": {"10.0.0.2"}},
					cfg.DNSConfig.Nameservers.Split)
			},
		},
		{
			name: "log and logtail",
			file: "log:\n  level: debug\nlog.format: json\nlogtail.enabled: true\n",
			check: func(t *testing.T, cfg *types.Config) {
				t.Helper()
				assert.Equal(t, types.LogLevel("debug"), cfg.Log.Level)
				assert.Equal(t, types.JSONLogFormat, cfg.Log.Format)
				assert.True(t, cfg.LogTail.Enabled)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(tt.file), 0o600))

			for range 50 {
				s, err := newConfigSource(dir, false, nil)
				require.NoError(t, err)

				cfg, err := s.decode()
				require.NoError(t, err)
				tt.check(t, cfg)
			}
		})
	}
}

// TestConfigSourceShapeErrorsHideValues: a block in the wrong shape may hold
// credentials, so the error names the key without its value.
func TestConfigSourceShapeErrorsHideValues(t *testing.T) {
	for name, file := range map[string]string{
		"list under oidc":            "oidc:\n  - client_secret: marker-secret\n",
		"scalar under postgres":      "database:\n  postgres: \"pass: marker-secret\"\n",
		"scalar under oidc.pkce":     "oidc:\n  pkce: marker-secret\n",
		"list under database.sqlite": "database:\n  sqlite: [marker-secret]\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newConfigSource(writeConfig(t, file), true, nil)
			require.ErrorContains(t, err, "must be a mapping")
			assert.NotContains(t, err.Error(), "marker-secret")
		})
	}
}

func TestConfigSourceStrictBeforeExpansion(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("log:\n  format:\n    typo: json\nlog.format: json\n"), 0o600))

	for range 50 {
		_, err := newConfigSource(dir, false, nil)
		require.ErrorContains(t, err, "unknown configuration key log.format.typo")
	}
}

func TestConfigSourceProviderEnv(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"),
		[]byte("dns:\n  challenge:\n    provider:\n      name: file\n      other: x\n"), 0o600))

	t.Setenv("HEADSCALE_DNS_CHALLENGE_PROVIDER", `{"api_token":"x"}`)
	t.Setenv("HEADSCALE_DNS_CHALLENGE_PROVIDER_NAME", "cloudflare")

	l, err := Load(dir, false, os.Environ())
	require.NoError(t, err)
	assert.Empty(t, l.Warnings)

	cfg := l.Config
	assert.Equal(t, "cloudflare", cfg.DNSConfig.Challenge.ProviderName())

	// The env value replaces the file's map; the per-field
	// variable is layered on top of it.
	got := cfg.DNSConfig.Challenge.ProviderSettings
	assert.Equal(t, "x", got["api_token"])
	assert.NotContains(t, got, "other")
}

// TestProviderEnvFold pins that HEADSCALE_DNS_CHALLENGE_PROVIDER_<SETTING>
// reaches the settings of the provider named anywhere, and that a variable
// no provider setting has is ignored without a word.
func TestProviderEnvFold(t *testing.T) {
	base := `---
server_url: https://headscale.example.com
noise:
  private_key_path: noise_private.key
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite
dns:
  magic_dns: true
  override_local_dns: false
  base_domain: ts.example.com
`

	tests := []struct {
		name string
		yaml string
		env  map[string]string
		want map[string]any
	}{
		{
			name: "named in the file",
			yaml: base + "  challenge:\n    provider:\n      name: cloudflare\n",
			env:  map[string]string{"HEADSCALE_DNS_CHALLENGE_PROVIDER_API_TOKEN": "x"},
			want: map[string]any{"name": "cloudflare", "api_token": "x"},
		},
		{
			name: "named by its variable",
			yaml: base,
			env: map[string]string{
				"HEADSCALE_DNS_CHALLENGE_PROVIDER_NAME":      "cloudflare",
				"HEADSCALE_DNS_CHALLENGE_PROVIDER_API_TOKEN": "x",
			},
			want: map[string]any{"name": "cloudflare", "api_token": "x"},
		},
		{
			name: "named in the json variable",
			yaml: base,
			env:  map[string]string{"HEADSCALE_DNS_CHALLENGE_PROVIDER": `{"name":"cloudflare","api_token":"json"}`},
			want: map[string]any{"name": "cloudflare", "api_token": "json"},
		},
		{
			name: "setting variable beats the json variable",
			yaml: base,
			env: map[string]string{
				"HEADSCALE_DNS_CHALLENGE_PROVIDER":           `{"name":"cloudflare","api_token":"json"}`,
				"HEADSCALE_DNS_CHALLENGE_PROVIDER_API_TOKEN": "env",
			},
			want: map[string]any{"name": "cloudflare", "api_token": "env"},
		},
		{
			name: "name variable beats the json variable",
			yaml: base + "  challenge:\n    provider:\n      name: powerdns\n",
			env: map[string]string{
				"HEADSCALE_DNS_CHALLENGE_PROVIDER":      `{"name":"rfc2136","api_token":"json"}`,
				"HEADSCALE_DNS_CHALLENGE_PROVIDER_NAME": "cloudflare",
			},
			want: map[string]any{"name": "cloudflare", "api_token": "json"},
		},
		{
			name: "variable for no setting of the provider",
			yaml: base + "  challenge:\n    provider:\n      name: cloudflare\n      api_token: tok\n",
			env:  map[string]string{"HEADSCALE_DNS_CHALLENGE_PROVIDER_BOGUS": "1"},
			want: map[string]any{"name": "cloudflare", "api_token": "tok"},
		},
		{
			name: "setting variable without a provider",
			yaml: base,
			env:  map[string]string{"HEADSCALE_DNS_CHALLENGE_PROVIDER_API_TOKEN": "x"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(tt.yaml), 0o600))
			l, err := Load(dir, false, os.Environ())
			require.NoError(t, err)
			assert.Empty(t, l.Warnings)

			cfg := l.Config
			require.NoError(t, Validate(cfg))

			if len(tt.want) == 0 {
				assert.Empty(t, cfg.DNSConfig.Challenge.ProviderSettings)

				return
			}

			assert.Equal(t, tt.want, cfg.DNSConfig.Challenge.ProviderSettings)
		})
	}
}

// decodeInput writes content as name (none when empty) and decodes it with
// env, as Load does.
func decodeInput(t *testing.T, name, content string, env ...string) (*types.Config, error) {
	t.Helper()

	dir := t.TempDir()
	if content != "" {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}

	s, err := newConfigSource(dir, false, env)
	require.NoError(t, err)

	return s.decode()
}

func TestDecodeScalars(t *testing.T) {
	tests := []struct {
		name    string
		file    string // config.yaml unless it starts with "{"
		env     []string
		check   func(t *testing.T, cfg *types.Config)
		wantErr []string
	}{
		{name: "yaml expiry 0", file: "node:\n  expiry: 0\n", check: func(t *testing.T, c *types.Config) { t.Helper(); assert.Zero(t, c.Node.Expiry) }},
		{name: "json expiry 0", file: `{"node": {"expiry": 0}}`, check: func(t *testing.T, c *types.Config) { t.Helper(); assert.Zero(t, c.Node.Expiry) }},
		{name: "env expiry 0", env: []string{"HEADSCALE_NODE_EXPIRY=0"}, check: func(t *testing.T, c *types.Config) { t.Helper(); assert.Zero(t, c.Node.Expiry) }},
		{name: "prometheus duration", file: "node:\n  expiry: 90d\n", check: func(t *testing.T, c *types.Config) {
			t.Helper()
			assert.Equal(t, 2160*time.Hour, c.Node.Expiry)
		}},
		{name: "duration without unit", file: "node:\n  expiry: 90\n", wantErr: []string{"node.expiry needs a unit (", "config.yaml:2:3)"}},
		{name: "env duration without unit", env: []string{"HEADSCALE_TUNING_BATCH_CHANGE_DELAY=800"}, wantErr: []string{"tuning.batch_change_delay needs a unit (env HEADSCALE_TUNING_BATCH_CHANGE_DELAY)"}},
		{name: "unquoted file mode", file: "unix_socket_permission: 0770\n", wantErr: []string{"unix_socket_permission must be quoted"}},
		{name: "quoted file mode", file: "unix_socket_permission: \"0770\"\n", check: func(t *testing.T, c *types.Config) {
			t.Helper()
			assert.Equal(t, types.FileMode(0o770), c.UnixSocketPermission)
		}},
		{name: "bool in a string field", file: "database:\n  postgres:\n    ssl: false\n", check: func(t *testing.T, c *types.Config) {
			t.Helper()
			assert.Equal(t, "false", c.Database.Postgres.Ssl)
		}},
		{name: "milliseconds stay a number", file: "database:\n  gorm:\n    slow_threshold: 1000\n", check: func(t *testing.T, c *types.Config) {
			t.Helper()
			assert.Equal(t, 1000, c.Database.Gorm.SlowThreshold)
		}},
		{name: "json integer", file: `{"database": {"postgres": {"port": 5432}}}`, check: func(t *testing.T, c *types.Config) {
			t.Helper()
			assert.Equal(t, 5432, c.Database.Postgres.Port)
		}},
		{name: "json fraction", file: `{"database": {"postgres": {"port": 5432.5}}}`, wantErr: []string{"database.postgres.port is not an integer"}},
		{name: "json out of range", file: `{"database": {"postgres": {"port": 1e20}}}`, wantErr: []string{"database.postgres.port is out of range"}},
		{name: "number 1 for a bool", file: "taildrop:\n  enabled: 1\nlogtail:\n  enabled: 1\n", check: func(t *testing.T, c *types.Config) {
			t.Helper()
			assert.True(t, c.Taildrop.Enabled)
			assert.True(t, c.LogTail.Enabled)
		}},
		{name: "number 0 for a bool", file: "taildrop:\n  enabled: 0\n", check: func(t *testing.T, c *types.Config) { t.Helper(); assert.False(t, c.Taildrop.Enabled) }},
		{name: "number 2 for a bool", file: "taildrop:\n  enabled: 2\n", wantErr: []string{"taildrop.enabled is not a boolean"}},
		{name: "env yes for a bool", env: []string{"HEADSCALE_TAILDROP_ENABLED=yes"}, wantErr: []string{"taildrop.enabled is not a boolean (env HEADSCALE_TAILDROP_ENABLED)"}},
		{name: "empty prefix is unset", file: "prefixes:\n  v4: \"\"\n", check: func(t *testing.T, c *types.Config) { t.Helper(); assert.Nil(t, c.Prefixes.V4) }},
		{name: "empty enum is unset", file: "log:\n  format: \"\"\n", check: func(t *testing.T, c *types.Config) { t.Helper(); assert.Empty(t, c.Log.Format) }},
		{name: "env json list", env: []string{`HEADSCALE_DNS_SEARCH_DOMAINS=["a","b"]`}, check: func(t *testing.T, c *types.Config) {
			t.Helper()
			assert.Equal(t, []string{"a", "b"}, c.DNSConfig.SearchDomains)
		}},
		{name: "env whitespace list", env: []string{"HEADSCALE_DNS_SEARCH_DOMAINS=a  b"}, check: func(t *testing.T, c *types.Config) {
			t.Helper()
			assert.Equal(t, []string{"a", "b"}, c.DNSConfig.SearchDomains)
		}},
		{name: "env map not json", env: []string{"HEADSCALE_DNS_NAMESERVERS_SPLIT=x=y"}, wantErr: []string{"dns.nameservers.split is not a JSON object (env HEADSCALE_DNS_NAMESERVERS_SPLIT)"}},
		{name: "level is case-insensitive", file: "log:\n  level: INFO\n", check: func(t *testing.T, c *types.Config) { t.Helper(); assert.Equal(t, types.LogLevel("info"), c.Log.Level) }},
		{name: "unknown extra record field", file: "dns:\n  extra_records:\n    - {name: a.example.com, type: A, value: 100.64.0.1, ttl: 60}\n", wantErr: []string{
			"dns.extra_records has invalid keys: ttl",
			`current: dns.extra_records: [{"name":"a.example.com","ttl":60,"type":"A","value":"100.64.0.1"}]`,
		}},
		{name: "empty duration", file: "node:\n  expiry: \"\"\n", wantErr: []string{"node.expiry is not a duration"}},
		{name: "empty integer", file: "database:\n  postgres:\n    port: \"\"\n", wantErr: []string{"database.postgres.port is not an integer"}},
		{name: "empty bool", file: "taildrop:\n  enabled: \"\"\n", wantErr: []string{"taildrop.enabled is not a boolean"}},
		{name: "empty string is a value", file: "server_url: \"\"\n", check: func(t *testing.T, c *types.Config) { t.Helper(); assert.Empty(t, c.ServerURL) }},
		{name: "env list not json", env: []string{"HEADSCALE_DNS_SEARCH_DOMAINS=[a"}, wantErr: []string{"dns.search_domains is not a JSON list", `hint: write the list as JSON, e.g. ["a", "b"]`}},
		{name: "dotted top-level key", file: "log.level: verbose\n", wantErr: []string{"log.level has an unsupported value (", "config.yaml:1:1)"}},
		{name: "nested then dotted key", file: "dns:\n  magic_dns: false\n  certificates.enabled: maybe\n", wantErr: []string{"dns.certificates.enabled is not a boolean (", "config.yaml:3:3)"}},
		{name: "dotted then nested key", file: "dns:\n  magic_dns: false\ndns.certificates:\n  enabled: maybe\n", wantErr: []string{"dns.certificates.enabled is not a boolean (", "config.yaml:4:3)"}},
		{name: "dotted inner list", file: "dns:\n  nameservers.global: 1\n", wantErr: []string{"dns.nameservers.global ", "config.yaml:2:3)"}},
		{name: "env extra records", env: []string{`HEADSCALE_DNS_EXTRA_RECORDS=[{"name":"a.example.com","type":"A","value":"100.64.0.1"}]`}, check: func(t *testing.T, c *types.Config) {
			t.Helper()
			assert.Equal(t, []tailcfg.DNSRecord{{Name: "a.example.com", Type: "A", Value: "100.64.0.1"}}, c.DNSConfig.ExtraRecords)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := "config.yaml"
			if strings.HasPrefix(tt.file, "{") {
				name = "config.json"
			}

			cfg, err := decodeInput(t, name, tt.file, tt.env...)
			if len(tt.wantErr) > 0 {
				for _, want := range tt.wantErr {
					require.ErrorContains(t, err, want)
				}

				return
			}

			require.NoError(t, err)
			tt.check(t, cfg)
		})
	}
}

// TestDecodeErrors pins that every bad value is reported at once, before
// any rule runs, and that a credential's value never is.
func TestDecodeErrors(t *testing.T) {
	t.Run("all bad values in one error", func(t *testing.T) {
		_, err := loadServer(writeConfig(t, "log:\n  level: verbose\nnode:\n  expiry: 90\ntaildrop:\n  enabled: maybe\n"), true)
		require.Error(t, err)

		got := reasons(types.ConfigErrors(err))
		require.Len(t, got, 3, "%v", got)
		assert.Contains(t, got[0], "log.level")
		assert.Contains(t, got[1], "node.expiry")
		assert.Contains(t, got[2], "taildrop.enabled")
		// No rule ran: server_url and the noise key are missing too.
		assert.NotContains(t, err.Error(), "server_url")
	})

	for name, tt := range map[string]struct {
		file string
		env  []string
		key  string
	}{
		"postgres pass":         {file: "database:\n  postgres:\n    pass: [marker-secret]\n", key: "database.postgres.pass"},
		"oidc client secret":    {file: "oidc:\n  client_secret: [marker-secret]\n", key: "oidc.client_secret"},
		"cli api key":           {file: "cli:\n  api_key: [marker-secret]\n", key: "cli.api_key"},
		"derp url with a token": {file: "derp:\n  urls: [\"https://marker-secret@:443\"]\n", key: "derp.urls"},
		"derp url unparsable":   {env: []string{"HEADSCALE_DERP_URLS=https://alice:marker-secret?@h"}, key: "derp.urls"},
		"oidc issuer":           {file: "oidc:\n  issuer: https://alice:marker-secret?@idp.example.com\n", key: "oidc.issuer"},
		"acme url":              {file: "tls:\n  acme:\n    url: https://alice:marker-secret@acme.example.com:port\n", key: "tls.acme.url"},
		"server url list":       {file: "server_url: [\"https://alice:marker-secret@h\"]\n", key: "server_url"},                                                         //nolint:gosec // a test marker, not a credential
		"cli address list":      {file: "cli:\n  address: [\"https://alice:marker-secret@h\"]\n", key: "cli.address"},                                                   //nolint:gosec // a test marker, not a credential
		"nameserver element":    {file: "dns:\n  nameservers:\n    global: [{url: \"https://alice:marker-secret@h\"}]\n", key: "dns.nameservers.global"},                //nolint:gosec // a test marker, not a credential
		"split element":         {file: "dns:\n  nameservers:\n    split:\n      a.example.com: [[\"https://alice:marker-secret@h\"]]\n", key: "dns.nameservers.split"}, //nolint:gosec // a test marker, not a credential
		"provider json":         {env: []string{`HEADSCALE_DNS_CHALLENGE_PROVIDER={"api_token":"marker-secret"`}, key: "dns.challenge.provider is not a JSON object (env HEADSCALE_DNS_CHALLENGE_PROVIDER)"},
		"provider scalar":       {file: "dns:\n  challenge:\n    provider: marker-secret\n", key: "dns.challenge.provider"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := decodeInput(t, "config.yaml", tt.file, tt.env...)
			require.ErrorContains(t, err, tt.key)
			requireHidden(t, err, "marker-secret")
		})
	}
}

// requireHidden fails when an error in err's tree, its text or its JSON,
// or the JSON of its ConfigErrors holds hidden: the decoder's own errors
// keep the value they rejected.
func requireHidden(t *testing.T, err error, hidden string) {
	t.Helper()

	util.WalkErrTree(err, func(e error) {
		assert.NotContains(t, e.Error(), hidden)

		b, jerr := json.Marshal(e)
		require.NoError(t, jerr)
		assert.NotContains(t, string(b), hidden)
	})

	b, jerr := json.Marshal(types.ConfigErrors(err))
	require.NoError(t, jerr)
	assert.NotContains(t, string(b), hidden)
}

func TestSchemaKeys(t *testing.T) {
	open := map[string]bool{}
	paths := map[string]bool{}

	for _, k := range schemaKeys() {
		paths[k.Path] = true
		open[k.Path] = k.Open
	}

	for _, k := range []string{"dns.nameservers.split", "oidc.extra_params", "dns.challenge.provider"} {
		assert.Truef(t, open[k], "%s is open", k)
	}

	assert.False(t, open["dns.extra_records"])
	assert.NotContains(t, paths, "derp.server.stun.enabled")
	assert.NotContains(t, paths, "dns.challenge.provider.name")

	// Two keys sharing one environment variable would shadow each other.
	envs := map[string]string{}

	for _, k := range schemaKeys() {
		name := configEnvName(k.Path)
		assert.Emptyf(t, envs[name], "%s and %s share %s", envs[name], k.Path, name)
		envs[name] = k.Path
	}
}

// TestDefaultsFitTypes: every default is a value its field's type accepts,
// so the defaults layer decodes back to Default.
func TestDefaultsFitTypes(t *testing.T) {
	d := Default()

	for _, f := range types.ConfigFields(&d) {
		e, ok := reflect.TypeAssert[interface{ Allowed() []string }](f.Value)
		if !ok {
			continue
		}

		v := f.Value.String()
		assert.Truef(t, v == "" || slices.Contains(e.Allowed(), v), "%s defaults to %q, not in %v", f.Path, v, e.Allowed())
	}

	cfg, err := decodeInput(t, "", "")
	require.NoError(t, err)

	if diff := gocmp.Diff(d, *cfg, cmpopts.IgnoreFields(types.Config{}, "ConfigDir"), cmpopts.IgnoreUnexported(types.Config{}), cmpopts.EquateComparable(netip.Prefix{})); diff != "" {
		t.Errorf("defaults layer (-Default +decoded):\n%s", diff)
	}
}

// TestDefaultsCanBeCleared: a key with a default can still be emptied with
// "" in the file or in a variable, and a list also with []. An empty
// variable counts as unset.
func TestDefaultsCanBeCleared(t *testing.T) {
	const serverURL = "server_url: https://headscale.example.com\n"

	d := Default()

	tests := []struct {
		name    string
		file    string
		env     []string
		check   func(*testing.T, *types.Config)
		wantErr string // a reason Validate gives
	}{
		{
			name:  "file derp urls",
			file:  "derp:\n  urls: []\n",
			check: func(t *testing.T, c *types.Config) { t.Helper(); assert.Empty(t, c.DERP.URLs) },
		},
		{
			name: "file prefix v4",
			file: "prefixes:\n  v4: \"\"\n",
			check: func(t *testing.T, c *types.Config) {
				t.Helper()
				assert.Nil(t, c.Prefixes.V4)
				require.NotNil(t, c.Prefixes.V6)
				assert.Equal(t, *d.Prefixes.V6, *c.Prefixes.V6)
			},
		},
		{
			name:  "file base domain",
			file:  "dns:\n  magic_dns: false\n  base_domain: \"\"\n",
			check: func(t *testing.T, c *types.Config) { t.Helper(); assert.Empty(t, c.DNSConfig.BaseDomain) },
		},
		{
			name:  "env derp urls",
			env:   []string{"HEADSCALE_DERP_URLS=[]"},
			check: func(t *testing.T, c *types.Config) { t.Helper(); assert.Empty(t, c.DERP.URLs) },
		},
		{
			name:  "empty env keeps the default",
			env:   []string{"HEADSCALE_DERP_URLS="},
			check: func(t *testing.T, c *types.Config) { t.Helper(); assert.Equal(t, d.DERP.URLs, c.DERP.URLs) },
		},
		{
			name: "empty env keeps a prefix",
			env:  []string{"HEADSCALE_PREFIXES_V6="},
			check: func(t *testing.T, c *types.Config) {
				t.Helper()
				require.NotNil(t, c.Prefixes.V6)
				assert.Equal(t, *d.Prefixes.V6, *c.Prefixes.V6)
			},
		},
		{
			name:  "env base domain",
			env:   []string{"HEADSCALE_DNS_MAGIC_DNS=false", `HEADSCALE_DNS_BASE_DOMAIN=""`},
			check: func(t *testing.T, c *types.Config) { t.Helper(); assert.Empty(t, c.DNSConfig.BaseDomain) },
		},
		{
			name: "env prefix v6",
			env:  []string{`HEADSCALE_PREFIXES_V6=""`},
			check: func(t *testing.T, c *types.Config) {
				t.Helper()
				assert.Nil(t, c.Prefixes.V6)
				require.NotNil(t, c.Prefixes.V4)
				assert.Equal(t, *d.Prefixes.V4, *c.Prefixes.V4)
			},
		},
		{
			name:  "env derp urls quotes",
			env:   []string{`HEADSCALE_DERP_URLS=""`},
			check: func(t *testing.T, c *types.Config) { t.Helper(); assert.Empty(t, c.DERP.URLs) },
		},
		{
			name:    "env base domain required by magic dns",
			env:     []string{`HEADSCALE_DNS_BASE_DOMAIN=""`},
			wantErr: "dns.base_domain is required when dns.magic_dns is true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := Load(writeConfig(t, serverURL+tt.file), true, tt.env)
			require.NoError(t, err)

			err = Validate(l.Config)
			if tt.wantErr != "" {
				assert.Equal(t, []string{tt.wantErr}, reasons(types.ConfigErrors(err)))

				return
			}

			require.NoError(t, err)
			tt.check(t, l.Config)
		})
	}
}

// TestEnvEmptyLikeFile: a variable set to "" means what `key: ""` means in
// the file, for every kind of key, errors included.
func TestEnvEmptyLikeFile(t *testing.T) {
	const serverURL = "server_url: https://headscale.example.com\n"

	// Where a load error says the value came from.
	origin := regexp.MustCompile(` \((env [A-Z0-9_]+|/[^)]*)\)$`)
	loadReasons := func(err error) []string {
		rs := reasons(types.ConfigErrors(err))
		for i, r := range rs {
			rs[i] = origin.ReplaceAllString(r, "")
		}

		return rs
	}

	tests := []struct {
		name string
		file string
		env  []string
	}{
		{name: "text", file: "dns:\n  magic_dns: false\n  base_domain: \"\"\n", env: []string{"HEADSCALE_DNS_MAGIC_DNS=false", `HEADSCALE_DNS_BASE_DOMAIN=""`}},
		{name: "prefix", file: "prefixes:\n  v6: \"\"\n", env: []string{`HEADSCALE_PREFIXES_V6=""`}},
		{name: "list", file: "derp:\n  urls: \"\"\n", env: []string{`HEADSCALE_DERP_URLS=""`}},
		{name: "list of objects", file: "dns:\n  extra_records: \"\"\n", env: []string{`HEADSCALE_DNS_EXTRA_RECORDS=""`}},
		{name: "enum", file: "log:\n  level: \"\"\n", env: []string{`HEADSCALE_LOG_LEVEL=""`}},
		{name: "integer", file: "database:\n  postgres:\n    port: \"\"\n", env: []string{`HEADSCALE_DATABASE_POSTGRES_PORT=""`}},
		{name: "boolean", file: "dns:\n  magic_dns: \"\"\n", env: []string{`HEADSCALE_DNS_MAGIC_DNS=""`}},
		{name: "duration", file: "node:\n  expiry: \"\"\n", env: []string{`HEADSCALE_NODE_EXPIRY=""`}},
		{name: "map", file: "dns:\n  nameservers:\n    split: \"\"\n", env: []string{`HEADSCALE_DNS_NAMESERVERS_SPLIT=""`}},
		{name: "secret", file: "oidc:\n  client_secret: \"\"\n", env: []string{`HEADSCALE_OIDC_CLIENT_SECRET=""`}},
		{name: "dns provider", file: "dns:\n  challenge:\n    provider: \"\"\n", env: []string{`HEADSCALE_DNS_CHALLENGE_PROVIDER=""`}},
		{
			name: "dns provider setting",
			file: "dns:\n  challenge:\n    provider:\n      name: cloudflare\n      api_token: \"\"\n",
			env:  []string{"HEADSCALE_DNS_CHALLENGE_PROVIDER_NAME=cloudflare", `HEADSCALE_DNS_CHALLENGE_PROVIDER_API_TOKEN=""`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fromFile, fileErr := Load(writeConfig(t, serverURL+tt.file), true, nil)
			fromEnv, envErr := Load(writeConfig(t, serverURL), true, tt.env)

			if fileErr != nil {
				require.Error(t, envErr)
				assert.Equal(t, loadReasons(fileErr), loadReasons(envErr))

				return
			}

			require.NoError(t, envErr)

			diff := gocmp.Diff(fromFile.Config, fromEnv.Config,
				cmpopts.IgnoreFields(types.Config{}, "ConfigDir"),
				cmpopts.IgnoreUnexported(types.Config{}),
				cmpopts.EquateComparable(netip.Prefix{}),
			)
			if diff != "" {
				t.Errorf("file and variable differ (-file +env):\n%s", diff)
			}

			assert.Equal(t, reasons(types.ConfigErrors(Validate(fromFile.Config))), reasons(types.ConfigErrors(Validate(fromEnv.Config))))
		})
	}
}

// TestNullTakesDefault: a key written with no value is unset and takes its
// default, so where that default is a non-empty text, list or prefix and
// no variable sets the key, loading warns.
func TestNullTakesDefault(t *testing.T) {
	const serverURL = "server_url: https://headscale.example.com\n"

	tests := []struct {
		name  string
		file  string
		ext   string // ".yaml" when ""
		env   []string
		warns []string
		check func(*testing.T, *types.Config)
	}{
		{
			name:  "list",
			file:  serverURL + "derp:\n  urls:\n",
			warns: []string{"derp.urls has no value in $FILE, so it takes its default ['https://controlplane.tailscale.com/derpmap/default']"},
			check: func(t *testing.T, c *types.Config) { t.Helper(); assert.Equal(t, Default().DERP.URLs, c.DERP.URLs) },
		},
		{
			name:  "prefix",
			file:  serverURL + "prefixes:\n  v6:\n",
			warns: []string{`prefixes.v6 has no value in $FILE, so it takes its default fd7a:115c:a1e0::/48`},
			check: func(t *testing.T, c *types.Config) { t.Helper(); assert.NotNil(t, c.Prefixes.V6) },
		},
		{
			name:  "text, dotted",
			file:  serverURL + "dns.magic_dns: false\ndns.base_domain:\n",
			warns: []string{`dns.base_domain has no value in $FILE, so it takes its default tailnet.internal`},
		},
		{
			name:  "required while magic_dns is on",
			file:  serverURL + "dns:\n  base_domain:\n",
			warns: []string{`dns.base_domain has no value in $FILE, so it takes its default tailnet.internal`},
		},
		{
			name:  "required",
			file:  serverURL + "noise:\n  private_key_path:\n",
			warns: []string{`noise.private_key_path has no value in $FILE, so it takes its default /var/lib/headscale/noise_private.key`},
		},
		{
			name:  "required listen address",
			file:  serverURL + "listen_addr:\n",
			warns: []string{`listen_addr has no value in $FILE, so it takes its default 0.0.0.0:8080`},
		},
		{
			name:  "required unix socket",
			file:  serverURL + "unix_socket:\n",
			warns: []string{`unix_socket has no value in $FILE, so it takes its default /var/run/headscale/headscale.sock`},
		},
		{
			name:  "required sqlite path",
			file:  serverURL + "database:\n  sqlite:\n    path:\n",
			warns: []string{`database.sqlite.path has no value in $FILE, so it takes its default /var/lib/headscale/db.sqlite`},
		},
		{
			name:  "sqlite path unused by postgres",
			file:  serverURL + "database:\n  type: postgres\n  sqlite:\n    path:\n",
			warns: []string{`database.sqlite.path has no value in $FILE, so it takes its default /var/lib/headscale/db.sqlite`},
		},
		{
			name:  "json null",
			file:  `{"server_url": "https://headscale.example.com", "dns": {"magic_dns": false, "base_domain": null}}`,
			ext:   ".json",
			warns: []string{`dns.base_domain has no value in $FILE, so it takes its default tailnet.internal`},
		},
		{
			name: "set by a variable",
			file: serverURL + "derp:\n  urls:\n",
			env:  []string{`HEADSCALE_DERP_URLS=["https://d.example.com/m.json"]`},
			check: func(t *testing.T, c *types.Config) {
				t.Helper()
				assert.Equal(t, []types.HTTPURL{"https://d.example.com/m.json"}, c.DERP.URLs)
			},
		},
		{name: "enum", file: serverURL + "log:\n  level:\n"},
		{name: "empty default", file: serverURL + "derp:\n  paths:\n"},
		{name: "section", file: serverURL + "derp:\n"},
		{name: "empty list", file: serverURL + "derp:\n  urls: []\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config"+cmp.Or(tt.ext, ".yaml"))
			require.NoError(t, os.WriteFile(path, []byte(tt.file), 0o600))

			l, err := Load(path, true, tt.env)
			require.NoError(t, err)

			var want []string
			for _, w := range tt.warns {
				want = append(want, strings.ReplaceAll(w, "$FILE", path))
			}

			assert.Equal(t, want, l.Warnings)

			if tt.check != nil {
				tt.check(t, l.Config)
			}
		})
	}
}

func TestPlainMap(t *testing.T) {
	v4 := netip.MustParsePrefix("100.64.0.0/10")
	cfg := &types.Config{
		ServerURL:            "https://h",
		UnixSocketPermission: 0,
		TrustedProxies:       []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		Prefixes:             types.PrefixesConfig{V4: &v4},
		Node:                 types.NodeConfig{Expiry: 90 * time.Minute},
		DERP:                 types.DERPConfig{URLs: []types.HTTPURL{"https://user:pass@derp.example/map"}},
		Database:             types.DatabaseConfig{Postgres: types.PostgresConfig{Pass: "marker-pass"}},
		OIDC:                 types.OIDCConfig{ClientSecret: "file:/run/secret"},
		DNSConfig: types.DNSConfig{
			ExtraRecords: []tailcfg.DNSRecord{{Name: "a.example.com", Type: "A", Value: "100.64.0.1"}},
			Challenge: types.DNSChallengeConfig{ProviderSettings: map[string]any{ //nolint:gosec // test markers, not credentials
				"name":      "acmedns",
				"api_token": 123456,
				"token":     "file:/run/token",
				"config":    map[string]any{"a.example.com": map[string]any{"password": "marker-pw", "name": "x"}},
				"list":      []any{"marker-item"},
			}},
		},
	}

	cfg.OIDC.Issuer = "https://client:marker-issuer@idp.example.com/realm"
	cfg.TLS.ACME.URL = "https://marker-token@acme.example.com/dir?x=1"
	cfg.DERP.URLs = append(cfg.DERP.URLs, "https://marker-only@derp.example/token", "https://h/%zz")
	cfg.DNSConfig.Challenge.ProviderSettings["unset"] = (*netip.Prefix)(nil)
	cfg.DNSConfig.Challenge.ProviderSettings["nothing"] = (*string)(nil)

	plain := plainMap(cfg, false)
	assert.Equal(t, "https://h", plain["server_url"])
	assert.Equal(t, "0000", plain["unix_socket_permission"])
	assert.Equal(t, []any{"10.0.0.0/8"}, plain["trusted_proxies"])

	prefixes, _ := plain["prefixes"].(map[string]any)
	assert.Equal(t, "100.64.0.0/10", prefixes["v4"])
	assert.Empty(t, prefixes["v6"], "a nil prefix prints as an explicit unset")
	assert.Contains(t, prefixes, "v6")

	node, _ := plain["node"].(map[string]any)
	assert.Equal(t, "1h30m", node["expiry"])

	derp, _ := plain["derp"].(map[string]any)
	assert.Equal(t, []any{
		"https://user:pass@derp.example/map", "https://marker-only@derp.example/token", "https://h/%zz",
	}, derp["urls"], "written as is, not as its JSON")

	oidc, _ := plain["oidc"].(map[string]any)
	assert.Equal(t, "https://client:marker-issuer@idp.example.com/realm", oidc["issuer"])

	tls, _ := plain["tls"].(map[string]any)
	acme, _ := tls["acme"].(map[string]any)
	assert.Equal(t, "https://marker-token@acme.example.com/dir?x=1", acme["url"])
	assert.NotContains(t, derp, "derpmap")

	db, _ := plain["database"].(map[string]any)
	pg, _ := db["postgres"].(map[string]any)
	assert.Equal(t, "marker-pass", pg["pass"])

	dns, _ := plain["dns"].(map[string]any)
	assert.Equal(t, []any{map[string]any{"name": "a.example.com", "type": "A", "value": "100.64.0.1"}}, dns["extra_records"])

	redacted := plainMap(cfg, true)
	db, _ = redacted["database"].(map[string]any)
	pg, _ = db["postgres"].(map[string]any)
	assert.Equal(t, "<redacted>", pg["pass"])

	oidc, _ = redacted["oidc"].(map[string]any)
	assert.Equal(t, "file:/run/secret", oidc["client_secret"])
	assert.Equal(t, "https://idp.example.com/realm", oidc["issuer"])

	tls, _ = redacted["tls"].(map[string]any)
	acme, _ = tls["acme"].(map[string]any)
	assert.Equal(t, "https://acme.example.com/dir?x=1", acme["url"])

	derp, _ = redacted["derp"].(map[string]any)
	assert.Equal(t, []any{"https://derp.example/map", "https://derp.example/token", "<redacted>"}, derp["urls"])

	dns, _ = redacted["dns"].(map[string]any)
	challenge, _ := dns["challenge"].(map[string]any)
	assert.Equal(t, map[string]any{ //nolint:gosec // test markers, not credentials
		"name":      "acmedns",
		"api_token": "<redacted>",
		"token":     "file:/run/token",
		"config":    map[string]any{"a.example.com": map[string]any{"password": "<redacted>", "name": "<redacted>"}},
		"list":      []any{"<redacted>"},
	}, challenge["provider"])
	// The caller's config is left alone.
	assert.Equal(t, 123456, cfg.DNSConfig.Challenge.ProviderSettings["api_token"])
	assert.Equal(t, types.HTTPURL("https://user:pass@derp.example/map"), cfg.DERP.URLs[0])
	assert.Equal(t, types.HTTPURL("https://client:marker-issuer@idp.example.com/realm"), cfg.OIDC.Issuer)

	plainProvider, _ := plain["dns"].(map[string]any)["challenge"].(map[string]any)["provider"].(map[string]any)
	assert.NotContains(t, plainProvider, "unset", "a typed nil is left out")
	assert.NotContains(t, plainProvider, "nothing", "a typed nil is left out")
}

// TestFormatDuration: a duration prints without trailing zero units and
// parses back to itself.
func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{3 * time.Hour, "3h"},
		{3*time.Hour + 30*time.Minute, "3h30m"},
		{time.Hour + 30*time.Second, "1h0m30s"},
		{2 * time.Minute, "2m"},
		{90 * time.Second, "1m30s"},
		{800 * time.Millisecond, "800ms"},
		{1500 * time.Millisecond, "1.5s"},
		{168 * time.Hour, "168h"},
		{-5 * time.Second, "-5s"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatDuration(tt.d)
			assert.Equal(t, tt.want, got)

			back, err := time.ParseDuration(got)
			require.NoError(t, err)
			assert.Equal(t, tt.d, back)
		})
	}
}

// TestPlainMapLargeIntegers: JSON parsers read numbers as float64, so an
// integer past 2^53 is written as text, which the integer hook takes back.
func TestPlainMapLargeIntegers(t *testing.T) {
	for _, n := range []int{1<<53 + 1, math.MaxInt64} {
		for _, ext := range []string{".json", ".hujson"} {
			t.Run(fmt.Sprintf("%d%s", n, ext), func(t *testing.T) {
				loaded, err := decodeInput(t, "config.yaml", fmt.Sprintf("tuning:\n  register_cache_max_entries: %d\n", n))
				require.NoError(t, err)
				require.Equal(t, n, loaded.Tuning.RegisterCacheMaxEntries)

				parser, err := configParser(ext)
				require.NoError(t, err)

				out, err := parser.Marshal(plainMap(loaded, false))
				require.NoError(t, err)

				again, err := decodeInput(t, "config"+ext, string(out))
				require.NoError(t, err)
				assert.Equal(t, n, again.Tuning.RegisterCacheMaxEntries)
			})
		}
	}
}

// TestBadConfigs pins how a bad value is reported: its key, what is wrong
// and where it was set. Every testdata/bad/<name>.{yaml,env} is one row;
// refresh with HEADSCALE_UPDATE_GOLDEN=1.
func TestBadConfigs(t *testing.T) {
	dir := filepath.Join("testdata", "bad")
	update := os.Getenv("HEADSCALE_UPDATE_GOLDEN") != ""

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	unsetHeadscaleEnv(t)

	for _, e := range entries {
		ext := filepath.Ext(e.Name())
		if ext == ".golden" {
			continue
		}

		name := strings.TrimSuffix(e.Name(), ext)
		t.Run(name, func(t *testing.T) {
			var file, envFile string
			if ext == ".env" {
				envFile = filepath.Join(dir, e.Name())
			} else {
				file = filepath.Join(dir, e.Name())
			}

			staged := stageCompat(t, file, envFile)
			_, err := loadServer(staged, false)
			require.Error(t, err)

			got := strings.ReplaceAll(err.Error(), staged, "$DIR")
			gpath := filepath.Join(dir, name+".golden")

			if update {
				require.NoError(t, os.WriteFile(gpath, []byte(got), 0o600))

				return
			}

			want, err := os.ReadFile(gpath)
			require.NoErrorf(t, err, "missing golden %s: run with HEADSCALE_UPDATE_GOLDEN=1", gpath)
			assert.Equal(t, string(want), got)
		})
	}
}

// TestPositionBounded: finding where a key is written follows the keys the
// file has, so a long dotted unknown key is located at once.
func TestPositionBounded(t *testing.T) {
	key := strings.Repeat("x.", 29) + "x"
	path := writeConfig(t, key+": 1\n")

	done := make(chan error, 1)

	go func() {
		_, err := newConfigSource(path, true, nil)
		done <- err
	}()

	select {
	case err := <-done:
		require.ErrorContains(t, err, "unknown configuration key "+key+" ("+path+":1:1)")
	case <-time.After(5 * time.Second):
		t.Fatal("locating a dotted key took longer than reading the file")
	}
}

func TestReadConfig(t *testing.T) {
	tests := []struct {
		name       string
		configPath string
		setup      func(*testing.T, *types.Config) (any, error)
		want       any
		wantErr    string
	}{
		{
			name:       "unmarshal-dns-full-config",
			configPath: "testdata/dns_full.yaml",
			setup: func(t *testing.T, cfg *types.Config) (any, error) { //nolint:thelper
				return cfg.DNSConfig, nil
			},
			want: types.DNSConfig{
				MagicDNS:         true,
				BaseDomain:       "example.com",
				OverrideLocalDNS: false,
				Nameservers: types.Nameservers{
					Global: []string{
						"1.1.1.1",
						"1.0.0.1",
						"2606:4700:4700::1111",
						"2606:4700:4700::1001",
						"https://dns.nextdns.io/abc123",
					},
					Split: map[string][]string{
						"darp.headscale.net": {"1.1.1.1", "8.8.8.8"},
						"foo.bar.com":        {"1.1.1.1"},
					},
				},
				ExtraRecords: []tailcfg.DNSRecord{
					{Name: "grafana.myvpn.example.com", Type: "A", Value: "100.64.0.3"},
					{Name: "prometheus.myvpn.example.com", Type: "A", Value: "100.64.0.4"},
				},
				SearchDomains: []string{"test.com", "bar.com"},
				Challenge:     types.DNSChallengeConfig{PropagationTimeout: 2 * time.Minute, Resolvers: types.DefaultChallengeResolvers()},
			},
		},
		{
			name:       "dns-to-tailcfg.DNSConfig",
			configPath: "testdata/dns_full.yaml",
			setup: func(t *testing.T, cfg *types.Config) (any, error) { //nolint:thelper
				return cfg.TailcfgDNSConfig(), nil
			},
			want: &tailcfg.DNSConfig{
				Proxied: true,
				Domains: []string{"example.com", "test.com", "bar.com"},
				FallbackResolvers: []*dnstype.Resolver{
					{Addr: "1.1.1.1"},
					{Addr: "1.0.0.1"},
					{Addr: "2606:4700:4700::1111"},
					{Addr: "2606:4700:4700::1001"},
					{Addr: "https://dns.nextdns.io/abc123"},
				},
				Routes: map[string][]*dnstype.Resolver{
					"darp.headscale.net": {{Addr: "1.1.1.1"}, {Addr: "8.8.8.8"}},
					"foo.bar.com":        {{Addr: "1.1.1.1"}},
				},
				ExtraRecords: []tailcfg.DNSRecord{
					{Name: "grafana.myvpn.example.com", Type: "A", Value: "100.64.0.3"},
					{Name: "prometheus.myvpn.example.com", Type: "A", Value: "100.64.0.4"},
				},
			},
		},
		{
			name:       "unmarshal-dns-full-no-magic",
			configPath: "testdata/dns_full_no_magic.yaml",
			setup: func(t *testing.T, cfg *types.Config) (any, error) { //nolint:thelper
				return cfg.DNSConfig, nil
			},
			want: types.DNSConfig{
				MagicDNS:         false,
				BaseDomain:       "example.com",
				OverrideLocalDNS: false,
				Nameservers: types.Nameservers{
					Global: []string{
						"1.1.1.1",
						"1.0.0.1",
						"2606:4700:4700::1111",
						"2606:4700:4700::1001",
						"https://dns.nextdns.io/abc123",
					},
					Split: map[string][]string{
						"darp.headscale.net": {"1.1.1.1", "8.8.8.8"},
						"foo.bar.com":        {"1.1.1.1"},
					},
				},
				ExtraRecords: []tailcfg.DNSRecord{
					{Name: "grafana.myvpn.example.com", Type: "A", Value: "100.64.0.3"},
					{Name: "prometheus.myvpn.example.com", Type: "A", Value: "100.64.0.4"},
				},
				SearchDomains: []string{"test.com", "bar.com"},
				Challenge:     types.DNSChallengeConfig{PropagationTimeout: 2 * time.Minute, Resolvers: types.DefaultChallengeResolvers()},
			},
		},
		{
			name:       "dns-to-tailcfg.DNSConfig",
			configPath: "testdata/dns_full_no_magic.yaml",
			setup: func(t *testing.T, cfg *types.Config) (any, error) { //nolint:thelper
				return cfg.TailcfgDNSConfig(), nil
			},
			want: &tailcfg.DNSConfig{
				Proxied: false,
				Domains: []string{"test.com", "bar.com"},
				FallbackResolvers: []*dnstype.Resolver{
					{Addr: "1.1.1.1"},
					{Addr: "1.0.0.1"},
					{Addr: "2606:4700:4700::1111"},
					{Addr: "2606:4700:4700::1001"},
					{Addr: "https://dns.nextdns.io/abc123"},
				},
				Routes: map[string][]*dnstype.Resolver{
					"darp.headscale.net": {{Addr: "1.1.1.1"}, {Addr: "8.8.8.8"}},
					"foo.bar.com":        {{Addr: "1.1.1.1"}},
				},
				ExtraRecords: []tailcfg.DNSRecord{
					{Name: "grafana.myvpn.example.com", Type: "A", Value: "100.64.0.3"},
					{Name: "prometheus.myvpn.example.com", Type: "A", Value: "100.64.0.4"},
				},
			},
		},
		{
			name:       "base-domain-in-server-url-err",
			configPath: "testdata/base-domain-in-server-url.yaml",
			setup: func(t *testing.T, cfg *types.Config) (any, error) { //nolint:thelper
				return nil, Validate(cfg)
			},
			want:    nil,
			wantErr: "server_url is a subdomain of dns.base_domain",
		},
		{
			name:       "base-domain-not-in-server-url",
			configPath: "testdata/base-domain-not-in-server-url.yaml",
			setup: func(t *testing.T, cfg *types.Config) (any, error) { //nolint:thelper
				err := Validate(cfg)
				if err != nil {
					return nil, err
				}

				return map[string]string{
					"server_url":  cfg.ServerURL,
					"base_domain": cfg.DNSConfig.BaseDomain,
				}, err
			},
			want: map[string]string{
				"server_url":  "https://derp.no",
				"base_domain": "clients.derp.no",
			},
			wantErr: "",
		},
		{
			name:       "dns-override-true",
			configPath: "testdata/dns-override-true.yaml",
			setup: func(t *testing.T, cfg *types.Config) (any, error) { //nolint:thelper
				err := Validate(cfg)
				if err != nil {
					return nil, err
				}

				return cfg.TailcfgDNSConfig(), nil
			},
			want: &tailcfg.DNSConfig{
				Proxied: true,
				Domains: []string{"derp2.no"},
				Routes:  map[string][]*dnstype.Resolver{},
				Resolvers: []*dnstype.Resolver{
					{Addr: "1.1.1.1"},
					{Addr: "1.0.0.1"},
				},
			},
		},
		{
			name:       "policy-path-is-loaded",
			configPath: "testdata/policy-path-is-loaded-strict.yaml",
			setup: func(t *testing.T, cfg *types.Config) (any, error) { //nolint:thelper // inline test closure
				err := Validate(cfg)
				if err != nil {
					return nil, err
				}

				return map[string]string{
					"policy.mode": string(cfg.Policy.Mode),
					"policy.path": cfg.Policy.Path,
				}, err
			},
			want: map[string]string{
				"policy.mode": "file",
				"policy.path": "/etc/policy.hujson",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := Load(tt.configPath, true, os.Environ())
			require.NoError(t, err)

			conf, err := tt.setup(t, l.Config)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)

				return
			}

			require.NoError(t, err)

			if diff := gocmp.Diff(tt.want, conf); diff != "" {
				t.Errorf("ReadConfig() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestReadConfigFromEnv(t *testing.T) {
	tests := []struct {
		name      string
		configEnv map[string]string
		setup     func(*testing.T, *types.Config) (any, error)
		want      any
	}{
		{
			name: "test-random-base-settings-with-env",
			configEnv: map[string]string{
				"HEADSCALE_LOG_LEVEL":                       "trace",
				"HEADSCALE_DATABASE_SQLITE_WRITE_AHEAD_LOG": "false",
				"HEADSCALE_PREFIXES_V4":                     "100.64.0.0/10",
			},
			setup: func(t *testing.T, cfg *types.Config) (any, error) { //nolint:thelper // inline test closure
				assert.Equal(t, types.LogLevel("trace"), cfg.Log.Level)
				assert.Equal(t, "100.64.0.0/10", cfg.Prefixes.V4.String())
				assert.False(t, cfg.Database.Sqlite.WriteAheadLog)

				return nil, nil //nolint:nilnil // test setup returns nil to indicate no expected value
			},
			want: nil,
		},
		{
			name: "unmarshal-dns-full-config",
			configEnv: map[string]string{
				"HEADSCALE_DNS_MAGIC_DNS":          "true",
				"HEADSCALE_DNS_BASE_DOMAIN":        "example.com",
				"HEADSCALE_DNS_OVERRIDE_LOCAL_DNS": "false",
				"HEADSCALE_DNS_NAMESERVERS_GLOBAL": `1.1.1.1 8.8.8.8`,
				"HEADSCALE_DNS_SEARCH_DOMAINS":     "test.com bar.com",

				// TODO(kradalby): Figure out how to pass these as env vars
				// "HEADSCALE_DNS_NAMESERVERS_SPLIT":  `{foo.bar.com: ["1.1.1.1"]}`,
				// "HEADSCALE_DNS_EXTRA_RECORDS":      `[{ name: "prometheus.myvpn.example.com", type: "A", value: "100.64.0.4" }]`,
			},
			setup: func(t *testing.T, cfg *types.Config) (any, error) { //nolint:thelper // inline test closure
				return cfg.DNSConfig, nil
			},
			want: types.DNSConfig{
				MagicDNS:         true,
				BaseDomain:       "example.com",
				OverrideLocalDNS: false,
				Nameservers: types.Nameservers{
					Global: []string{"1.1.1.1", "8.8.8.8"},
					Split:  map[string][]string{
						// "foo.bar.com": {"1.1.1.1"},
					},
				},
				// ExtraRecords: []tailcfg.DNSRecord{
				// 	{Name: "prometheus.myvpn.example.com", Type: "A", Value: "100.64.0.4"},
				// },
				SearchDomains: []string{"test.com", "bar.com"},
				Challenge:     types.DNSChallengeConfig{PropagationTimeout: 2 * time.Minute, Resolvers: types.DefaultChallengeResolvers()},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.configEnv {
				t.Setenv(k, v)
			}

			l, err := Load("testdata/minimal.yaml", true, os.Environ())
			require.NoError(t, err)

			conf, err := tt.setup(t, l.Config)
			require.NoError(t, err)

			if diff := gocmp.Diff(tt.want, conf, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("ReadConfig() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestTLSConfigValidation(t *testing.T) {
	tmpDir := t.TempDir()

	var err error

	configYaml := []byte(`---
tls:
  cert_path: abc.pem
  acme:
    hostname: example.com
    challenge_type: ""
noise:
  private_key_path: noise_private.key`)

	// Populate a custom config file
	configFilePath := filepath.Join(tmpDir, "config.yaml")

	err = os.WriteFile(configFilePath, configYaml, 0o600)
	if err != nil {
		t.Fatalf("Couldn't write file %s", configFilePath)
	}

	// Check configuration validation errors (1)
	_, err = loadServer(tmpDir, false)
	require.Error(t, err)
	assert.Contains(
		t,
		err.Error(),
		"Fatal config error: tls.acme.hostname and tls.cert_path/tls.key_path are mutually exclusive",
	)
	assert.Contains(
		t,
		err.Error(),
		"Fatal config error: tls.acme.challenge_type has an unsupported value",
	)
	assert.Contains(
		t,
		err.Error(),
		"Fatal config error: server_url is required",
	)

	// Check configuration validation errors (2)
	configYaml = []byte(`---
noise:
  private_key_path: noise_private.key
server_url: http://127.0.0.1:8080
tls:
  acme:
    hostname: example.com
    challenge_type: TLS-ALPN-01
`)

	err = os.WriteFile(configFilePath, configYaml, 0o600)
	if err != nil {
		t.Fatalf("Couldn't write file %s", configFilePath)
	}

	_, err = Load(tmpDir, false, os.Environ())
	require.NoError(t, err)
}

func TestPKCEMethodValidation(t *testing.T) {
	tmpDir := t.TempDir()

	// OIDC is active (issuer set) with PKCE enabled and an invalid method.
	// There is no oidc.enabled key. Loading must reject the invalid method
	// rather than silently skipping the check.
	configYaml := []byte(`---
noise:
  private_key_path: noise_private.key
server_url: http://127.0.0.1:8080
dns:
  override_local_dns: false
oidc:
  issuer: https://idp.example.com
  client_id: headscale
  pkce:
    enabled: true
    method: S256-typo
`)

	configFilePath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configFilePath, configYaml, 0o600)
	require.NoError(t, err)

	_, err = loadServer(tmpDir, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "oidc.pkce.method has an unsupported value")
}

// TestOIDCConfigValidation covers the issuer-URL and required-field checks that
// fail an unworkable OIDC setup fast at config load.
func TestOIDCConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		oidcBlock string
		wantErr   string
	}{
		{
			name: "non-http issuer",
			oidcBlock: `
  issuer: ftp://idp.example.com
  client_id: headscale
  client_secret: sekret`,
			wantErr: "oidc.issuer is not an http:// or https:// URL",
		},
		{
			name: "missing client_id",
			oidcBlock: `
  issuer: https://idp.example.com
  client_secret: sekret`,
			wantErr: "client_id is required",
		},
		{
			name: "missing client_secret",
			oidcBlock: `
  issuer: https://idp.example.com
  client_id: headscale`,
			wantErr: "client_secret",
		},
		{
			name: "valid",
			oidcBlock: `
  issuer: https://idp.example.com
  client_id: headscale
  client_secret: sekret`,
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configYaml := []byte(`---
noise:
  private_key_path: noise_private.key
server_url: http://127.0.0.1:8080
prefixes:
  v4: 100.64.0.0/10
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
oidc:` + tt.oidcBlock + "\n")

			require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "config.yaml"), configYaml, 0o600))

			_, err := loadServer(tmpDir, false)
			if tt.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestTLSACMEListenAddrCollision(t *testing.T) {
	tests := []struct {
		name          string
		listenAddr    string
		acmeListen    string
		hostname      string
		challengeType string
		wantErr       string // empty = expect no error
	}{
		{"collision-numeric", ":80", ":80", "example.com", "HTTP-01", "would bind the same TCP socket"},
		{"collision-named-vs-numeric", "0.0.0.0:80", ":http", "example.com", "HTTP-01", "would bind the same TCP socket"},
		{"collision-https-named", ":443", ":https", "example.com", "HTTP-01", "would bind the same TCP socket"},
		{"canonical", "0.0.0.0:443", ":http", "example.com", "HTTP-01", ""},
		{"no-hostname-skipped", "0.0.0.0:80", ":http", "", "HTTP-01", ""},
		{"tls-alpn-01-skipped", "0.0.0.0:80", ":http", "example.com", "TLS-ALPN-01", ""},
		{"different-numeric", ":8080", ":8081", "example.com", "HTTP-01", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			cfg := fmt.Sprintf(`---
server_url: https://example.com
listen_addr: %q
tls:
  acme:
    hostname: %q
    challenge_type: %q
    http_listen: %q
noise:
  private_key_path: noise_private.key
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite3
dns:
  magic_dns: false
  override_local_dns: false
`, tt.listenAddr, tt.hostname, tt.challengeType, tt.acmeListen)
			require.NoError(t, os.WriteFile(
				filepath.Join(tmpDir, "config.yaml"), []byte(cfg), 0o600))

			_, err := loadServer(tmpDir, false)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestLoadCollectsAcrossSubBuilders(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := `---
server_url: https://example.com
listen_addr: 0.0.0.0:8080
prefixes:
  v4: not-a-cidr
  v6: also-not-a-cidr
  allocation: bogus
noise:
  private_key_path: noise_private.key
database:
  type: sqlite3
dns:
  magic_dns: false
  override_local_dns: false
  base_domain: example.com
`
	require.NoError(t, os.WriteFile(
		filepath.Join(tmpDir, "config.yaml"), []byte(cfg), 0o600))
	_, err := loadServer(tmpDir, false)
	require.Error(t, err)

	got := types.ConfigErrors(err)
	assert.GreaterOrEqual(t, len(got), 3,
		"expected sub-builder errors collected into one report; got %d: %v",
		len(got), reasons(got))

	// Sentinels stay reachable through ConfigError.Cause.
	require.ErrorIs(t, err, types.ErrInvalidAllocationStrategy,
		"wrapped ErrInvalidAllocationStrategy not in chain")

	// Each sub-builder failure surfaces its YAML key in the rendered output.
	rendered := err.Error()
	for _, want := range []string{
		"prefixes.v4",
		"prefixes.v6",
		"prefixes.allocation",
	} {
		assert.Contains(t, rendered, want,
			"expected rendered error to mention %q", want)
	}
}

func reasons(errs []*types.ConfigError) []string {
	out := make([]string, len(errs))
	for i, e := range errs {
		out[i] = e.Reason
	}

	return out
}

// TestRemovedKeysAreRejected pins that removed keys stop the load in the file
// and warn in the environment, naming the replacement either way.
func TestRemovedKeysAreRejected(t *testing.T) {
	tests := []struct {
		name      string
		file      string
		env       map[string]string
		want      []string // substrings of the load error
		warns     []string // substrings of the warnings
		serverErr string   // from Validate after a clean load
		check     func(t *testing.T, cfg *types.Config)
	}{
		{
			name: "deprecated keys",
			file: "oidc:\n  expiry: 1h\ndns_config:\n  use_username_in_magic_dns: true\n",
			want: []string{"oidc.expiry was removed", "use node.expiry", "dns_config was removed"},
		},
		{
			name: "ignored gorm key",
			file: "database:\n  gorm:\n    prepare_stmt: true\n",
			want: []string{"database.gorm.prepare_stmt was removed"},
		},
		{
			name: "ephemeral timeout",
			file: "ephemeral_node_inactivity_timeout: 30m\n",
			want: []string{"ephemeral_node_inactivity_timeout was removed", "use node.ephemeral.inactivity_timeout"},
		},
		{
			name:  "ephemeral timeout env",
			env:   map[string]string{"HEADSCALE_EPHEMERAL_NODE_INACTIVITY_TIMEOUT": "30m"},
			warns: []string{"HEADSCALE_EPHEMERAL_NODE_INACTIVITY_TIMEOUT was removed", "use HEADSCALE_NODE_EPHEMERAL_INACTIVITY_TIMEOUT"},
		},
		{
			name: "oidc client secret path",
			file: "oidc:\n  client_secret_path: /run/secret\n",
			want: []string{"oidc.client_secret_path was removed", `oidc.client_secret: "file:<path>"`},
		},
		{
			name:  "oidc client secret path env",
			env:   map[string]string{"HEADSCALE_OIDC_CLIENT_SECRET_PATH": "/run/secret"},
			warns: []string{"HEADSCALE_OIDC_CLIENT_SECRET_PATH was removed", "use HEADSCALE_OIDC_CLIENT_SECRET=file:<path>"},
		},
		{
			// The warning alone would let OIDC start without its secret; the
			// consumer's own check stops it.
			name:      "removed secret variable leaves the secret unset",
			file:      "server_url: https://headscale.example.com\nnoise:\n  private_key_path: noise_private.key\nprefixes:\n  v4: 100.64.0.0/10\ndns:\n  magic_dns: false\noidc:\n  issuer: https://idp.example.com\n  client_id: headscale\n",
			env:       map[string]string{"HEADSCALE_OIDC_CLIENT_SECRET_PATH": "/run/secret"},
			warns:     []string{"HEADSCALE_OIDC_CLIENT_SECRET_PATH was removed in 0.30; use HEADSCALE_OIDC_CLIENT_SECRET=file:<path>"},
			serverErr: "oidc.client_secret is required when oidc.issuer is set",
		},
		{
			name:  "postgres password file env",
			env:   map[string]string{"HEADSCALE_DATABASE_POSTGRES_PASSWORD_FILE": "/run/secret"},
			warns: []string{"HEADSCALE_DATABASE_POSTGRES_PASSWORD_FILE was removed", "use HEADSCALE_DATABASE_POSTGRES_PASS=file:<path>"},
		},
		// The old NixOS module's settings, which headscale never read.
		{
			name: "nixos db password file",
			file: "db_password_file: /run/x\n",
			want: []string{"db_password_file was removed", `database.postgres.pass: "file:<path>"`},
		},
		{
			name: "nixos dns split",
			file: "dns:\n  split:\n    corp: [\"192.0.2.53\"]\n",
			want: []string{"dns.split was removed", "use dns.nameservers.split"},
		},
		{
			name:  "nixos dns split env",
			env:   map[string]string{"HEADSCALE_DNS_SPLIT": `{"corp":["192.0.2.53"]}`},
			warns: []string{"HEADSCALE_DNS_SPLIT was removed", "use HEADSCALE_DNS_NAMESERVERS_SPLIT"},
			check: func(t *testing.T, cfg *types.Config) {
				t.Helper()
				assert.Empty(t, cfg.DNSConfig.Nameservers.Split)
			},
		},
		{
			name: "env hints name variables",
			env: map[string]string{
				"HEADSCALE_IP_PREFIXES":     "100.64.0.0/10",
				"HEADSCALE_JSON_LOGS":       "true",
				"HEADSCALE_METRICS_ENABLED": "true",
			},
			warns: []string{
				"use HEADSCALE_PREFIXES_V4 and HEADSCALE_PREFIXES_V6",
				"use HEADSCALE_LOG_FORMAT=json",
				"remove HEADSCALE_METRICS_ENABLED",
			},
		},
		{
			name: "file hints name keys",
			file: "ip_prefixes: [100.64.0.0/10]\njson_logs: true\nmetrics_enabled: true\n",
			want: []string{"use prefixes.v4 and prefixes.v6", `use log.format: "json"`, "remove metrics_enabled"},
		},
		{
			name: "provider path key",
			file: "dns:\n  challenge:\n    provider:\n      name: cloudflare\n      api_token_path: /run/secret\n",
			want: []string{"dns.challenge.provider.api_token_path was removed", `dns.challenge.provider.api_token: "file:<path>"`},
		},
		{
			name: "provider path key without provider",
			file: "dns:\n  challenge:\n    provider:\n      api_token_path: /run/secret\n",
			want: []string{"dns.challenge.provider.api_token_path was removed", `dns.challenge.provider.api_token: "file:<path>"`},
		},
		{
			name:  "provider path env without provider",
			env:   map[string]string{"HEADSCALE_DNS_CHALLENGE_PROVIDER_API_TOKEN_PATH": "/run/secret"},
			warns: []string{"HEADSCALE_DNS_CHALLENGE_PROVIDER_API_TOKEN_PATH was removed", "use HEADSCALE_DNS_CHALLENGE_PROVIDER_API_TOKEN=file:<path>"},
		},
		{
			name: "provider path env for another provider",
			env: map[string]string{
				"HEADSCALE_DNS_CHALLENGE_PROVIDER_NAME":     "rfc2136",
				"HEADSCALE_DNS_CHALLENGE_PROVIDER_KEY_PATH": "/run/secret",
			},
			warns: []string{"HEADSCALE_DNS_CHALLENGE_PROVIDER_KEY_PATH was removed", "use HEADSCALE_DNS_CHALLENGE_PROVIDER_KEY=file:<path>"},
		},
		{
			name:  "provider path in env json",
			env:   map[string]string{"HEADSCALE_DNS_CHALLENGE_PROVIDER": `{"api_token_path":"/run/secret"}`},
			warns: []string{"dns.challenge.provider.api_token_path in HEADSCALE_DNS_CHALLENGE_PROVIDER was removed", `dns.challenge.provider.api_token: "file:<path>"`},
		},
		{
			name: "provider path in env json with provider",
			env: map[string]string{
				"HEADSCALE_DNS_CHALLENGE_PROVIDER":      `{"API_Token_Path":"/run/secret"}`,
				"HEADSCALE_DNS_CHALLENGE_PROVIDER_NAME": "cloudflare",
			},
			warns: []string{"dns.challenge.provider.api_token_path in HEADSCALE_DNS_CHALLENGE_PROVIDER was removed", `dns.challenge.provider.api_token: "file:<path>"`},
		},
		{
			name: "registration path key",
			file: "dns:\n  challenge:\n    provider:\n      config:\n        laptop.example.com:\n          password_path: /run/secret\n",
			want: []string{
				"dns.challenge.provider.config.laptop.example.com.password_path was removed",
				`dns.challenge.provider.config.laptop.example.com.password: "file:<path>"`,
			},
		},
		{
			// A registration's name is data, not a setting.
			name: "registration named like a path key",
			file: "dns:\n  challenge:\n    provider:\n      config:\n        node.example_path:\n          username: user\n",
		},
		{
			name: "registration named like a path key in env json",
			env:  map[string]string{"HEADSCALE_DNS_CHALLENGE_PROVIDER": `{"config":{"Node.Example_path":{"username":"user"}}}`},
		},
		{
			name: "path key in a registration named like one",
			env:  map[string]string{"HEADSCALE_DNS_CHALLENGE_PROVIDER": `{"config":{"Node.Example_path":{"Password_Path":"/run/secret"}}}`},
			warns: []string{
				"dns.challenge.provider.config.Node.Example_path.password_path in HEADSCALE_DNS_CHALLENGE_PROVIDER was removed",
				`dns.challenge.provider.config.Node.Example_path.password: "file:<path>"`,
			},
		},
		{
			name: "registration path in env json",
			env:  map[string]string{"HEADSCALE_DNS_CHALLENGE_PROVIDER": `{"config":{"laptop.example.com":{"password_path":"/run/secret"}}}`},
			warns: []string{
				"dns.challenge.provider.config.laptop.example.com.password_path in HEADSCALE_DNS_CHALLENGE_PROVIDER was removed",
				`dns.challenge.provider.config.laptop.example.com.password: "file:<path>"`,
			},
		},
		// Every spelling of the registration map gives its keys the role the
		// nested one does: registration names, then settings.
		{
			name: "registration named like a path key, nested",
			file: "dns: {challenge: {provider: {config: {node.example_path: {username: user, password: pass, subdomain: reg, server_url: https://auth.example.com}}}}}",
		},
		{
			name: "path key in a registration named config, nested",
			file: "dns: {challenge: {provider: {config: {config: {Password_Path: /run/secret}}}}}",
			want: []string{
				"dns.challenge.provider.config.config.password_path was removed",
				`dns.challenge.provider.config.config.password: "file:<path>"`,
			},
		},
		{
			name: "registration named like a path key, dotted provider",
			file: "dns.challenge.provider: {config: {node.example_path: {username: user, password: pass, subdomain: reg, server_url: https://auth.example.com}}}",
		},
		{
			name: "path key in a registration named config, dotted provider",
			file: "dns.challenge.provider: {config: {config: {Password_Path: /run/secret}}}",
			want: []string{
				"dns.challenge.provider.config.config.password_path was removed",
				`dns.challenge.provider.config.config.password: "file:<path>"`,
			},
		},
		{
			name: "registration named like a path key, dotted registration map",
			file: "dns.challenge.provider.config: {node.example_path: {username: user, password: pass, subdomain: reg, server_url: https://auth.example.com}}",
		},
		{
			name: "path key in a registration named config, dotted registration map",
			file: "dns.challenge.provider.config: {config: {Password_Path: /run/secret}}",
			want: []string{
				"dns.challenge.provider.config.config.password_path was removed",
				`dns.challenge.provider.config.config.password: "file:<path>"`,
			},
		},
		{
			name: "registration named like a path key, dotted in dns",
			file: "dns: {challenge.provider.config: {node.example_path: {username: user, password: pass, subdomain: reg, server_url: https://auth.example.com}}}",
		},
		{
			name: "path key in a registration named config, dotted in dns",
			file: "dns: {challenge.provider.config: {config: {Password_Path: /run/secret}}}",
			want: []string{
				"dns.challenge.provider.config.config.password_path was removed",
				`dns.challenge.provider.config.config.password: "file:<path>"`,
			},
		},
		{
			name: "registration named like a path key, dotted in dns.challenge",
			file: "dns.challenge: {provider.config: {node.example_path: {username: user, password: pass, subdomain: reg, server_url: https://auth.example.com}}}",
		},
		{
			name: "path key in a registration named config, dotted in dns.challenge",
			file: "dns.challenge: {provider.config: {config: {Password_Path: /run/secret}}}",
			want: []string{
				"dns.challenge.provider.config.config.password_path was removed",
				`dns.challenge.provider.config.config.password: "file:<path>"`,
			},
		},
		{
			name: "postgres password file",
			file: "database:\n  postgres:\n    password_file: /run/secret\n",
			want: []string{"database.postgres.password_file was removed", `database.postgres.pass: "file:<path>"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(tt.file), 0o600))

			l, err := Load(dir, false, os.Environ())
			if len(tt.want) == 0 {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				// A removed key's value may be a secret.
				require.NotContains(t, err.Error(), "/run/secret")
			}

			for _, want := range tt.want {
				require.ErrorContains(t, err, want)
			}

			if err != nil {
				return
			}

			warnings := strings.Join(l.Warnings, "\n")
			assert.NotContains(t, warnings, "/run/secret")

			if len(tt.warns) == 0 {
				assert.NotContains(t, warnings, "was removed")
			}

			for _, w := range tt.warns {
				assert.Contains(t, warnings, w)
			}

			if tt.serverErr != "" {
				require.ErrorContains(t, Validate(l.Config), tt.serverErr)
			}

			if tt.check != nil {
				tt.check(t, l.Config)
			}
		})
	}
}

// TestConfigSecrets pins that Load keeps each secret as written, a
// value or file:<path>, and reads no file: its consumer does
// (TestNewHeadscaleSecrets, TestCLIAPIKey).
func TestConfigSecrets(t *testing.T) {
	missing := "file:" + filepath.Join(t.TempDir(), "missing")

	base := `---
server_url: https://headscale.example.com
noise:
  private_key_path: noise_private.key
prefixes:
  v4: 100.64.0.0/10
database:
  type: postgres
dns:
  magic_dns: false
  override_local_dns: false
cli:
  address: headscale.example.com:443
oidc:
  issuer: https://idp.example.com
  client_id: headscale
`

	for name, value := range map[string]string{"literal": "literal", "missing file": missing} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("HEADSCALE_DATABASE_POSTGRES_PASS", value)
			t.Setenv("HEADSCALE_CLI_API_KEY", value)

			tmpDir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "config.yaml"), []byte(base+"  client_secret: "+value+"\n"), 0o600))
			cfg, err := loadServer(tmpDir, false)
			require.NoError(t, err)
			assert.Equal(t, types.Secret(value), cfg.OIDC.ClientSecret)
			assert.Equal(t, types.Secret(value), cfg.Database.Postgres.Pass)
			assert.Equal(t, types.Secret(value), cfg.CLI.APIKey)
		})
	}
}

// The unset case is the regression: the default is spelled "0o770", which a
// base-8 parse rejects, so the socket silently became 0700.
// https://github.com/juanfont/headscale/issues/3529
func TestUnixSocketPermission(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		env     string
		want    types.FileMode
		wantErr bool
	}{
		{name: "unset-uses-default", want: 0o770},
		{name: "null-uses-default", yaml: `unix_socket_permission: null`, want: 0o770},
		{name: "quoted-leading-zero", yaml: `unix_socket_permission: "0770"`, want: 0o770},
		{name: "quoted-plain", yaml: `unix_socket_permission: "770"`, want: 0o770},
		{name: "quoted-0o-prefix", yaml: `unix_socket_permission: "0o770"`, want: 0o770},
		{name: "quoted-0o-prefix-owner-only", yaml: `unix_socket_permission: "0o700"`, want: 0o700},
		{name: "quoted-zero", yaml: `unix_socket_permission: "0000"`, want: 0},
		{name: "env", env: "0660", want: 0o660},
		{name: "env-0o-prefix", env: "0o660", want: 0o660},
		{name: "env-overrides-file", yaml: `unix_socket_permission: "0770"`, env: "0700", want: 0o700},
		{name: "env-invalid-is-error", env: "bogus", wantErr: true},
		{name: "empty-is-error", yaml: `unix_socket_permission: ""`, wantErr: true},
		{name: "symbolic-is-error", yaml: `unix_socket_permission: "rwxrwx---"`, wantErr: true},
		{name: "special-bits-are-error", yaml: `unix_socket_permission: "1770"`, wantErr: true},
		{name: "out-of-range-is-error", yaml: `unix_socket_permission: "17777"`, wantErr: true},
		// YAML reads unquoted 0770 as int 504, indistinguishable from a literal 504.
		{name: "unquoted-leading-zero-is-error", yaml: `unix_socket_permission: 0770`, wantErr: true},
		{name: "unquoted-0o-prefix-is-error", yaml: `unix_socket_permission: 0o770`, wantErr: true},
		{name: "unquoted-plain-is-error", yaml: `unix_socket_permission: 770`, wantErr: true},
		{name: "float-is-error", yaml: `unix_socket_permission: 770.0`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				t.Setenv("HEADSCALE_UNIX_SOCKET_PERMISSION", tt.env)
			}

			tmpDir := t.TempDir()
			cfg := `---
server_url: https://example.com
listen_addr: 0.0.0.0:8080
prefixes:
  v4: 100.64.0.0/10
noise:
  private_key_path: noise_private.key
database:
  type: sqlite3
dns:
  magic_dns: false
  override_local_dns: false
` + tt.yaml + "\n"
			require.NoError(t, os.WriteFile(
				filepath.Join(tmpDir, "config.yaml"), []byte(cfg), 0o600))

			got, err := loadServer(tmpDir, false)
			if tt.wantErr {
				require.ErrorIs(t, err, util.ErrInvalidFileMode,
					"invalid unix_socket_permission must not silently fall back")
				assert.Contains(t, err.Error(), "unix_socket_permission")

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got.UnixSocketPermission,
				"got %#o, want %#o", got.UnixSocketPermission, tt.want)
		})
	}
}

func TestServerURLTrailingSlash(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "no slash", input: "https://h", want: "https://h"},
		{name: "one slash", input: "https://h/", want: "https://h"},
		{name: "two slashes", input: "https://h//", want: "https://h"},
		{name: "port", input: "https://h:8443/", want: "https://h:8443"},
		{name: "path prefix", input: "https://h/hs/", want: "https://h/hs"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := decodeValues(t, map[string]any{
				"server_url":             tt.input,
				"noise.private_key_path": "private_key.pem",
				"prefixes.v4":            "100.64.0.0/10",
				"database.type":          "sqlite3",
				"dns.magic_dns":          false,
				"dns.override_local_dns": false,
			})
			require.NoError(t, err)
			require.NoError(t, Validate(cfg))
			assert.Equal(t, tt.want, cfg.ServerURL)
		})
	}
}

//nolint:goconst // repeated CIDR strings are test fixtures, not refactor candidates
func TestTrustedProxies(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		want    []netip.Prefix
		wantErr string
	}{
		{
			name:  "unset",
			input: nil,
			want:  nil,
		},
		{
			name:  "empty",
			input: []string{},
			want:  nil,
		},
		{
			name:  "single-v4",
			input: []string{"10.0.0.0/16"},
			want:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")},
		},
		{
			name:  "single-v6",
			input: []string{"fd00::/8"},
			want:  []netip.Prefix{netip.MustParsePrefix("fd00::/8")},
		},
		{
			name:  "mixed-v4-v6",
			input: []string{"127.0.0.1/32", "::1/128", "10.0.0.0/16"},
			want: []netip.Prefix{
				netip.MustParsePrefix("127.0.0.1/32"),
				netip.MustParsePrefix("::1/128"),
				netip.MustParsePrefix("10.0.0.0/16"),
			},
		},
		{
			name:  "non-canonical-masked",
			input: []string{"10.0.0.5/16"},
			want:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")},
		},
		{
			name:    "bare-ip-rejected",
			input:   []string{"10.0.0.1"},
			wantErr: `netip.ParsePrefix("10.0.0.1")`,
		},
		{
			name:    "garbage-names-the-value",
			input:   []string{"10.0.0.0/16", "not-an-ip"},
			wantErr: `trusted_proxies is not a valid CIDR`,
		},
		{
			name:    "ipv4-zero-rejected",
			input:   []string{"0.0.0.0/0"},
			wantErr: `trusted_proxies[0] "0.0.0.0/0": 0.0.0.0/0 and ::/0 are not allowed`,
		},
		{
			name:    "ipv6-zero-rejected",
			input:   []string{"::/0"},
			wantErr: "0.0.0.0/0 and ::/0 are not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values := map[string]any{
				"server_url":             "https://headscale.example.com",
				"noise.private_key_path": "private_key.pem",
				"prefixes.v4":            "100.64.0.0/10",
				"database.type":          "sqlite3",
				"dns.magic_dns":          false,
				"dns.override_local_dns": false,
			}
			if tt.input != nil {
				values["trusted_proxies"] = tt.input
			}

			var got []netip.Prefix

			cfg, err := decodeValues(t, values)
			if err == nil {
				got, err = cfg.TrustedProxies, Validate(cfg)
			}

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)

				return
			}

			require.NoError(t, err)

			if diff := gocmp.Diff(tt.want, got, cmpopts.EquateComparable(netip.Prefix{}), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("trusted_proxies mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestNameserverWarnings pins that the config check reports a nameserver
// clients will not get, and that building the DNS config does not report it
// again.
func TestNameserverWarnings(t *testing.T) {
	yaml := `---
server_url: https://headscale.example.com
noise:
  private_key_path: noise_private.key
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite
dns:
  magic_dns: true
  base_domain: ts.example.com
  override_local_dns: true
  nameservers:
    global: ["1.1.1.1", "1.1.1.1:53"]
    split:
      corp.example.com: ["[2606:4700::1111]:53"]
`
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o600))
	cfg, err := loadServer(dir, false)
	require.NoError(t, err)

	warnings := strings.Join(Warnings(cfg), "\n")
	assert.Contains(t, warnings, `invalid nameserver "1.1.1.1:53" in dns.nameservers.global, ignoring`)
	assert.Contains(t, warnings, `invalid nameserver "[2606:4700::1111]:53" in dns.nameservers.split.corp.example.com, ignoring`)
	assert.NotContains(t, warnings, `"1.1.1.1" in`)

	var buf bytes.Buffer

	oldLogger, oldLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(&buf)

	t.Cleanup(func() {
		log.Logger = oldLogger

		zerolog.SetGlobalLevel(oldLevel)
	})

	cfg.StartDNS(nil)

	assert.Equal(t, []*dnstype.Resolver{{Addr: "1.1.1.1"}}, cfg.CloneTailcfgDNSConfig().Resolvers)
	assert.Empty(t, buf.String(), "built once, reported once: by Warnings")
}

func TestDNSChallengeConfig(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(secret, []byte("file-token\n"), 0o600))

	base := `---
server_url: https://headscale.example.com
noise:
  private_key_path: noise_private.key
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite
dns:
  magic_dns: true
  override_local_dns: false
  base_domain: ts.example.com
`

	tests := []struct {
		name          string
		yaml          string
		env           map[string]string
		wantErr       string
		fileErr       bool // only reading a file: secret fails, so the load passes
		wantWarns     []string
		wantZone      string
		wantToken     string
		wantNoProv    bool
		wantResolvers []string
		wantIsolates  string
		wantProvider  string // the provider's type, for one other than cloudflare
	}{
		{
			name: "disabled by default",
			yaml: base,
			// CertificateZone follows base_domain even when unused, so it is never empty.
			wantZone:      "ts.example.com",
			wantNoProv:    true,
			wantResolvers: []string{"9.9.9.9:53", "149.112.112.112:53"},
		},
		{
			name: "resolvers default to port 53",
			yaml: base + `  challenge:
    resolvers: ["9.9.9.9", "2620:fe::fe", "127.0.0.1:5353"]
`,
			wantZone:      "ts.example.com",
			wantNoProv:    true,
			wantResolvers: []string{"9.9.9.9:53", "[2620:fe::fe]:53", "127.0.0.1:5353"},
		},
		{
			name: "enabled with inline token",
			yaml: base + `  certificates:
    enabled: true
  challenge:
    provider:
      name: cloudflare
      api_token: yaml-token
`,
			wantZone:  "ts.example.com",
			wantToken: "yaml-token",
		},
		{
			name: "env only",
			yaml: base,
			env: map[string]string{
				"HEADSCALE_DNS_CERTIFICATES_ENABLED":         "true",
				"HEADSCALE_DNS_CERTIFICATES_ZONE":            "example.com",
				"HEADSCALE_DNS_CHALLENGE_PROVIDER_NAME":      "cloudflare",
				"HEADSCALE_DNS_CHALLENGE_PROVIDER_API_TOKEN": "file:" + secret,
			},
			wantZone:  "example.com",
			wantToken: "file-token",
		},
		{
			name: "token from file",
			yaml: base + `  challenge:
    provider:
      name: cloudflare
      api_token: "file:` + secret + `"
`,
			wantZone:  "ts.example.com",
			wantToken: "file-token",
		},
		{
			name: "acmedns registration password from file",
			yaml: base + `  certificates:
    enabled: true
  challenge:
    provider:
      name: acmedns
      config:
        laptop.ts.example.com:
          username: user
          password: "file:` + secret + `"
          subdomain: reg-laptop
          server_url: https://auth.acme-dns.io
`,
			wantZone:     "ts.example.com",
			wantIsolates: "laptop.ts.example.com",
		},
		{
			name: "acmedns registration password file missing",
			yaml: base + `  certificates:
    enabled: true
  challenge:
    provider:
      name: acmedns
      config:
        laptop.ts.example.com:
          username: user
          password: "file:/nonexistent/password"
          subdomain: reg-laptop
          server_url: https://auth.acme-dns.io
`,
			wantErr: "dns.challenge.provider.config.laptop.ts.example.com.password: ",
			fileErr: true,
		},
		{
			// Unread by the load, a file: setting counts as present.
			name: "token file missing",
			yaml: base + `  challenge:
    provider:
      name: cloudflare
      api_token: "file:/nonexistent/token"
`,
			wantErr: "dns.challenge.provider.api_token: ",
			fileErr: true,
		},
		{
			name: "provider env json",
			yaml: base,
			env: map[string]string{
				"HEADSCALE_DNS_CHALLENGE_PROVIDER_NAME": "cloudflare",
				"HEADSCALE_DNS_CHALLENGE_PROVIDER":      `{"api_token":"good","zone_token":"zone"}`,
			},
			wantZone:  "ts.example.com",
			wantToken: "good",
		},
		{
			// Named, never shown: the value holds credentials.
			name: "provider env json that does not decode",
			yaml: base,
			env: map[string]string{
				"HEADSCALE_DNS_CHALLENGE_PROVIDER_NAME": "cloudflare",
				"HEADSCALE_DNS_CHALLENGE_PROVIDER":      `{"api_token":"marker-token","zone_token":1e1000}`,
			},
			wantErr: "dns.challenge.provider is not a JSON object (env HEADSCALE_DNS_CHALLENGE_PROVIDER)",
		},
		{
			// The removed field warns and is dropped; the rest still loads.
			name: "removed field in provider env json",
			yaml: base,
			env: map[string]string{
				"HEADSCALE_DNS_CHALLENGE_PROVIDER_NAME": "cloudflare",
				"HEADSCALE_DNS_CHALLENGE_PROVIDER":      `{"name":"cloudflare","api_token":"good","api_token_path":"/old"}`,
			},
			wantWarns: []string{"dns.challenge.provider.api_token_path in HEADSCALE_DNS_CHALLENGE_PROVIDER was removed"},
			wantZone:  "ts.example.com",
			wantToken: "good",
		},
		{
			name: "removed field in a registration in provider env json",
			yaml: base,
			env: map[string]string{
				"HEADSCALE_DNS_CERTIFICATES_ENABLED":    "true",
				"HEADSCALE_DNS_CHALLENGE_PROVIDER_NAME": "acmedns",
				"HEADSCALE_DNS_CHALLENGE_PROVIDER": `{"config":{"laptop.ts.example.com":{"username":"user","password":"pass",` +
					`"subdomain":"reg-laptop","server_url":"https://auth.acme-dns.io","password_path":"/old"}}}`,
			},
			wantWarns:    []string{"dns.challenge.provider.config.laptop.ts.example.com.password_path in HEADSCALE_DNS_CHALLENGE_PROVIDER was removed"},
			wantZone:     "ts.example.com",
			wantIsolates: "laptop.ts.example.com",
		},
		{
			name: "cloudflare without api_token",
			yaml: base + `  challenge:
    provider:
      name: cloudflare
      zone_token: marker-zone-token
`,
			wantErr: "cloudflare: missing api_token",
		},
		{
			// The old variable warns and is ignored, leaving the token unset.
			name: "cloudflare token only in a removed variable",
			yaml: base + `  challenge:
    provider:
      name: cloudflare
      zone_token: marker-zone-token
`,
			env:       map[string]string{"HEADSCALE_DNS_CHALLENGE_PROVIDER_API_TOKEN_PATH": "/run/token"},
			wantWarns: []string{"HEADSCALE_DNS_CHALLENGE_PROVIDER_API_TOKEN_PATH was removed"},
			wantErr:   "cloudflare: missing api_token",
		},
		{
			name: "powerdns without api_token",
			yaml: base + `  challenge:
    provider:
      name: powerdns
      server_url: https://pdns.example.com
`,
			wantErr: "powerdns: missing api_token",
		},
		{
			name: "rfc2136 without a key",
			yaml: base + `  challenge:
    provider:
      name: rfc2136
      server: ns1.example.com:53
`,
			wantErr: "rfc2136: missing key_name, key_alg, key",
		},
		{
			name: "hetzner without api_token",
			yaml: base + `  challenge:
    provider:
      name: hetzner
`,
			env:     map[string]string{"LIBDNS_HETZNER_TOKEN": ""},
			wantErr: "hetzner: missing api_token",
		},
		{
			// The provider reads its token from this variable when api_token is unset.
			name: "hetzner token from its own variable",
			yaml: base + `  challenge:
    provider:
      name: hetzner
      api_token: ""
`,
			env:          map[string]string{"LIBDNS_HETZNER_TOKEN": "marker-token"},
			wantZone:     "ts.example.com",
			wantProvider: "*hetzner.Provider",
		},
		{
			name: "gigahost without api_key",
			yaml: base + `  challenge:
    provider:
      name: gigahost
`,
			wantErr: "gigahost: missing api_key",
		},
		{
			name: "env overrides yaml",
			yaml: base + `  challenge:
    provider:
      name: cloudflare
      api_token: yaml-token
`,
			env:       map[string]string{"HEADSCALE_DNS_CHALLENGE_PROVIDER_API_TOKEN": "env-token"},
			wantZone:  "ts.example.com",
			wantToken: "env-token",
		},
		{
			name: "typo in provider key",
			yaml: base + `  challenge:
    provider:
      name: cloudflare
      auth_token: tok
`,
			wantErr: "dns.challenge.provider is invalid",
		},
		{
			name: "unknown provider",
			yaml: base + `  challenge:
    provider:
      name: route53
`,
			wantErr: "dns.challenge.provider is invalid",
		},
		{
			name: "acmedns one account for node certificates",
			yaml: base + `  certificates:
    enabled: true
  challenge:
    provider:
      name: acmedns
      username: user
      password: pass
      subdomain: reg
      server_url: https://auth.acme-dns.io
`,
			wantErr: "registration per name",
		},
		{
			name: "acmedns registration per name",
			yaml: base + `  certificates:
    enabled: true
  challenge:
    provider:
      name: acmedns
      config:
        laptop.ts.example.com:
          username: user
          password: pass
          subdomain: reg-laptop
          server_url: https://auth.acme-dns.io
        desktop.ts.example.com:
          username: user
          password: pass
          subdomain: reg-desktop
          server_url: https://auth.acme-dns.io
`,
			wantZone:     "ts.example.com",
			wantIsolates: "laptop.ts.example.com",
		},
		{
			name: "acmedns registration shared by node names",
			yaml: base + `  certificates:
    enabled: true
  challenge:
    provider:
      name: acmedns
      config:
        laptop.ts.example.com:
          username: user
          password: pass
          subdomain: reg
          server_url: https://auth.acme-dns.io
        desktop.ts.example.com:
          username: user
          password: pass
          subdomain: reg
          server_url: https://auth.acme-dns.io
`,
			wantErr: "desktop.ts.example.com and laptop.ts.example.com share a registration",
		},
		{
			name: "acmedns one account for headscale's own certificate",
			yaml: base + `  challenge:
    provider:
      name: acmedns
      username: user
      password: pass
      subdomain: reg
      server_url: https://auth.acme-dns.io
tls:
  acme:
    hostname: headscale.example.com
    challenge_type: DNS-01
`,
			wantZone: "ts.example.com",
		},
		{
			name: "acmedns registration shared with headscale's own name",
			yaml: base + `  certificates:
    enabled: true
  challenge:
    provider:
      name: acmedns
      config:
        laptop.ts.example.com:
          username: user
          password: pass
          subdomain: reg
          server_url: https://auth.acme-dns.io
        headscale.example.com:
          username: user
          password: pass
          subdomain: reg
          server_url: https://auth.acme-dns.io
tls:
  acme:
    hostname: headscale.example.com
    challenge_type: DNS-01
`,
			wantErr: "headscale.example.com and laptop.ts.example.com share a registration",
		},
		{
			name: "enabled without magic dns",
			yaml: strings.Replace(base, "magic_dns: true", "magic_dns: false", 1) + `  certificates:
    enabled: true
  challenge:
    provider:
      name: cloudflare
      api_token: tok
`,
			wantErr: "dns.certificates requires dns.magic_dns",
		},
		{
			name: "enabled without provider",
			yaml: base + `  certificates:
    enabled: true
`,
			wantErr: "dns.certificates and tls.acme DNS-01 require dns.challenge.provider",
		},
		{
			name: "base_domain outside zone",
			yaml: base + `  certificates:
    enabled: true
    zone: notexample.com
  challenge:
    provider:
      name: cloudflare
      api_token: tok
`,
			wantErr: "dns.base_domain is not inside dns.certificates.zone",
		},
		{
			name: "zone suffix without label boundary",
			yaml: base + `  certificates:
    enabled: true
    zone: ample.com
  challenge:
    provider:
      name: cloudflare
      api_token: tok
`,
			wantErr: "dns.base_domain is not inside dns.certificates.zone",
		},
		{
			name: "uppercase base_domain",
			yaml: strings.Replace(base, "ts.example.com", "TS.example.com", 1) + `  certificates:
    enabled: true
  challenge:
    provider:
      name: cloudflare
      api_token: tok
`,
			wantErr: "dns.base_domain must be a lowercase DNS name",
		},
		{
			name: "tls DNS-01 without provider",
			yaml: base + `tls:
  acme:
    hostname: headscale.example.com
    challenge_type: DNS-01
`,
			wantErr: "dns.certificates and tls.acme DNS-01 require dns.challenge.provider",
		},
		{
			name: "negative propagation timeout",
			yaml: base + `  challenge:
    propagation_timeout: -1s
`,
			wantErr: "dns.challenge.propagation_timeout must not be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			tmpDir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "config.yaml"), []byte(tt.yaml), 0o600))
			l, err := Load(tmpDir, false, os.Environ())
			require.Len(t, l.Warnings, len(tt.wantWarns))

			for i, w := range tt.wantWarns {
				assert.Contains(t, l.Warnings[i], w)
			}

			cfg := l.Config
			if err == nil {
				err = Validate(cfg)
			}

			if tt.wantErr != "" && !tt.fileErr {
				require.ErrorContains(t, err, tt.wantErr)
				assert.NotContains(t, err.Error(), "marker-")

				return
			}

			require.NoError(t, err)

			if tt.fileErr {
				_, err = cfg.DNSConfig.Challenge.NewProvider(types.ResolveSecret)
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			assert.Equal(t, tt.wantZone, cfg.DNSConfig.CertificateZone())

			if tt.wantResolvers != nil {
				assert.Equal(t, tt.wantResolvers, cfg.DNSConfig.Challenge.ResolverAddrs())
			}

			// The loader only validates the provider; startup builds it.
			assert.Nil(t, cfg.DNSConfig.Challenge.Provider)

			if tt.wantNoProv {
				assert.Empty(t, cfg.DNSConfig.Challenge.ProviderName())

				return
			}

			built, err := cfg.DNSConfig.Challenge.NewProvider(types.ResolveSecret)
			require.NoError(t, err)

			if tt.wantProvider != "" {
				assert.Equal(t, tt.wantProvider, fmt.Sprintf("%T", built))

				return
			}

			if iso, ok := built.(hsdns.Isolator); ok {
				if tt.wantIsolates != "" {
					assert.True(t, iso.Isolates(tt.wantIsolates))
				}

				return
			}

			provider, ok := built.(*cloudflare.Provider)
			require.True(t, ok, "provider is %T", built)
			assert.Equal(t, tt.wantToken, provider.APIToken)
		})
	}
}

// TestTLSConfig pins the tls defaults and that the flat keys the tls block
// replaced, including the ones the NixOS module once wrote with TLS off, are
// rejected.
func TestTLSConfig(t *testing.T) {
	base := `---
server_url: https://headscale.example.com
noise:
  private_key_path: noise_private.key
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite
dns:
  magic_dns: false
  override_local_dns: false
`

	tests := []struct {
		name    string
		yaml    string
		env     map[string]string
		want    types.TLSConfig
		wantErr []string
	}{
		{
			name: "defaults",
			yaml: base,
			want: types.TLSConfig{ACME: types.ACMEConfig{
				ChallengeType: types.HTTP01ChallengeType,
				HTTPListen:    ":http",
				CacheDir:      "/var/lib/headscale/cache",
			}},
		},
		{
			name: "legacy keys",
			yaml: base + `tls_letsencrypt_hostname: headscale.example.com
tls_letsencrypt_challenge_type: TLS-ALPN-01
tls_letsencrypt_listen: ":8080"
tls_letsencrypt_cache_dir: /var/lib/headscale/cache
acme_url: https://acme.example.com/directory
acme_email: admin@example.com
`,
			wantErr: []string{
				"tls_letsencrypt_hostname was removed", "use tls.acme.hostname",
				"tls_letsencrypt_challenge_type was removed", "tls_letsencrypt_listen was removed",
				"tls_letsencrypt_cache_dir was removed", "acme_url was removed", "acme_email was removed",
			},
		},
		{
			name: "legacy keys next to tls keys",
			yaml: base + `tls_cert_path: /old/cert.pem
tls_key_path: /old/key.pem
tls:
  cert_path: /new/cert.pem
  key_path: /new/key.pem
`,
			wantErr: []string{"tls_cert_path was removed", "use tls.cert_path", "tls_key_path was removed"},
		},
		{
			// What the NixOS module wrote when TLS was off.
			name: "nixos defaults",
			yaml: base + `tls_letsencrypt_hostname: ""
tls_letsencrypt_challenge_type: HTTP-01
tls_letsencrypt_listen: ":http"
tls_letsencrypt_cache_dir: /var/lib/headscale/.cache
`,
			wantErr: []string{"tls_letsencrypt_hostname was removed", "tls_letsencrypt_cache_dir was removed"},
		},
		{
			name: "env",
			yaml: base,
			env: map[string]string{
				"HEADSCALE_TLS_CERT_PATH": "/env/cert.pem",
				"HEADSCALE_TLS_KEY_PATH":  "/env/key.pem",
			},
			want: types.TLSConfig{
				CertPath: "/env/cert.pem",
				KeyPath:  "/env/key.pem",
				ACME: types.ACMEConfig{
					ChallengeType: types.HTTP01ChallengeType,
					HTTPListen:    ":http",
					CacheDir:      "/var/lib/headscale/cache",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			tmpDir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "config.yaml"), []byte(tt.yaml), 0o600))

			cfg, err := loadServer(tmpDir, false)

			if tt.wantErr != nil {
				for _, want := range tt.wantErr {
					require.ErrorContains(t, err, want)
				}

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, cfg.TLS)
		})
	}
}

func TestBoolConfigValidation(t *testing.T) {
	for _, source := range []string{"file", "env"} {
		for _, tt := range []struct {
			value   string
			want    bool
			invalid bool
		}{
			{"true", true, false},
			{"false", false, false},
			{"1", true, false},
			{"0", false, false},
			{"T", true, false},
			{"f", false, false},
			{"TRUE", true, false},
			{"False", false, false},
			{"True", true, false},
			{"FALSE", false, false},
			{"", true, false},
			{"null", true, false},
			{"yes", false, true},
			{"on", false, true},
			{"ture", false, true},
			{"tRuE", false, true},
			{"2", false, true},
			{"[true]", false, true},
			{`""`, false, true},
		} {
			if source == "env" && tt.value == "null" {
				continue
			}

			t.Run(source+"/"+tt.value, func(t *testing.T) {
				t.Setenv("HEADSCALE_OIDC_EMAIL_VERIFIED_REQUIRED", "")

				config := `server_url: https://headscale.example.com
noise:
  private_key_path: noise_private.key
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite3
dns:
  magic_dns: false
  override_local_dns: false
`
				if source == "file" && tt.value != "" {
					config += "oidc:\n  email_verified_required: " + tt.value + "\n"
				}

				if source == "env" {
					t.Setenv("HEADSCALE_OIDC_EMAIL_VERIFIED_REQUIRED", tt.value)
				}

				path := filepath.Join(t.TempDir(), "config.yaml")
				require.NoError(t, os.WriteFile(path, []byte(config), 0o600))

				loaded, err := loadServer(path, true)
				if tt.invalid {
					require.Error(t, err)
					assert.Contains(t, err.Error(), "oidc.email_verified_required")

					return
				}

				require.NoError(t, err)
				assert.Equal(t, tt.want, loaded.OIDC.EmailVerifiedRequired)
			})
		}
	}
}

// TestServerConfigDisableUpdateCheck: the server config carries the setting
// as the CLI config does, for Marshal and embedders.
func TestServerConfigDisableUpdateCheck(t *testing.T) {
	for _, want := range []bool{true, false} {
		path := writeConfig(t, fmt.Sprintf(`server_url: https://headscale.example.com
noise:
  private_key_path: noise_private.key
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite
dns:
  magic_dns: false
  override_local_dns: false
disable_check_updates: %t
`, want))
		cfg, err := loadServer(path, true)
		require.NoError(t, err)
		assert.Equal(t, want, cfg.DisableUpdateCheck)
	}
}

func TestLoadRejectsNonBoolean(t *testing.T) {
	for _, key := range []string{"cli.insecure", "disable_check_updates"} {
		t.Run(key, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(path, nil, 0o600))

			env := configEnvName(key)
			t.Setenv(env, "true")

			_, err := loadCLI(path)
			require.NoError(t, err)

			t.Setenv(env, "ture")

			_, err = loadCLI(path)
			require.Error(t, err)
			assert.Contains(t, err.Error(), key)
		})
	}
}

// compatRecord is the golden for one config input: what the loader produced.
type compatRecord struct {
	Config   json.RawMessage   `json:"config,omitempty"`
	Secrets  map[string]string `json:"secrets,omitempty"` // secret strings the JSON form hides
	Warnings []string          `json:"warnings,omitempty"`
	Error    string            `json:"error,omitempty"` // an error-only golden pins today's rejection
}

type compatRow struct{ name, file, envFile string }

var compatDir = filepath.Join("testdata", "compat")

// compatRows lists every compat/<name>.{yaml,json,env} set and every
// testdata/*.yaml file.
func compatRows(t *testing.T) []compatRow {
	t.Helper()

	entries, err := os.ReadDir(compatDir)
	require.NoError(t, err)

	var rows []compatRow

	byName := map[string]int{}

	for _, e := range entries {
		f, ext := e.Name(), filepath.Ext(e.Name())
		if strings.HasSuffix(f, ".golden.json") || (ext != ".yaml" && ext != ".json" && ext != ".env") {
			continue
		}

		name := strings.TrimSuffix(f, ext)

		i, ok := byName[name]
		if !ok {
			i = len(rows)
			byName[name] = i
			rows = append(rows, compatRow{name: name})
		}

		if ext == ".env" {
			rows[i].envFile = filepath.Join(compatDir, f)
		} else {
			rows[i].file = filepath.Join(compatDir, f)
		}
	}

	legacy, err := filepath.Glob(filepath.Join("testdata", "*.yaml"))
	require.NoError(t, err)

	for _, f := range legacy {
		rows = append(rows, compatRow{name: "testdata-" + strings.TrimSuffix(filepath.Base(f), ".yaml"), file: f})
	}

	return rows
}

// unsetHeadscaleEnv removes ambient HEADSCALE_* for the test, which would
// leak into the goldens.
func unsetHeadscaleEnv(t *testing.T) {
	t.Helper()

	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "HEADSCALE_") {
			t.Setenv(k, "") // registers the restore
			require.NoError(t, os.Unsetenv(k))
		}
	}
}

// TestConfigCompat pins what real-world config inputs load to, so a loader
// change shows up as a golden diff, and each such diff needs a BREAKING
// CHANGELOG entry. Every compat/<name>.{yaml,json,env} set is one row; a name
// ending in -cli is loaded as client commands load it, unvalidated. Fixtures
// are frozen inputs: to change one, add a new fixture. Refresh with
// HEADSCALE_UPDATE_GOLDEN=1.
//
// Sources: example-<tag>.yaml is `git show <tag>:config-example.yaml`;
// example-main.yaml is a frozen copy of main's root config-example.yaml;
// nixos-*.yaml are the files `nix build` wrote for the flake module with
// the since-deleted nix/example-configuration.nix
// (services.headscale.configFile, environment.etc."headscale/config.yaml") and
// for the nixpkgs module with only server_url, dns.base_domain and
// dns.nameservers.global set; nixos-module-minimal.yaml is the flake module's
// configFile with only those three set, before the module moved to the
// generated options, and nixos-*-options.yaml the same two configFiles after
// it; nixos-module-minimal-defaults.yaml is that module's configFile again once
// it set only its state paths, socket and disable_check_updates;
// nixos-module-cli.env is what that module exports for the local CLI;
// hsic-* mirror integration/hsic's
// MinimumConfigYAML and DefaultConfigEnv. <name>-strict is the same source
// as updated for the strict loader, <name>-pruned without the keys removed
// for having no effect. hsic-default-derp-urls is hsic-default-strict with
// HEADSCALE_DERP_URLS=[], as hsic writes it to clear the default map.
// server-url-only and env-server-url-only set only server_url, in the file
// and in a variable.
func TestConfigCompat(t *testing.T) {
	rows := compatRows(t)
	update := os.Getenv("HEADSCALE_UPDATE_GOLDEN") != ""

	unsetHeadscaleEnv(t)

	for _, tt := range rows {
		t.Run(tt.name, func(t *testing.T) {
			rec := loadCompat(t, tt.file, tt.envFile, strings.HasSuffix(tt.name, "-cli"))

			out, err := json.MarshalIndent(rec, "", "  ")
			require.NoError(t, err)

			out = append(out, '\n')
			gpath := filepath.Join(compatDir, tt.name+".golden.json")

			if update {
				require.NoError(t, os.WriteFile(gpath, out, 0o600))

				return
			}

			want, err := os.ReadFile(gpath)
			require.NoErrorf(t, err, "missing golden %s: run with HEADSCALE_UPDATE_GOLDEN=1", gpath)

			if d := gocmp.Diff(string(want), string(out)); d != "" {
				t.Errorf("config compat mismatch (-golden +got):\n%s", d)
			}
		})
	}
}

// compatConfig is the JSON shape of Config the goldens were written in,
// frozen so Config can change without a golden diff; compatView renders
// into it.
type compatConfig struct {
	ServerURL            string
	Addr                 string
	MetricsAddr          string
	TrustedProxies       []netip.Prefix
	Node                 compatNodeConfig
	PreAuthKeys          compatPreAuthKeysConfig
	PrefixV4             *netip.Prefix
	PrefixV6             *netip.Prefix
	IPAllocation         string
	NoisePrivateKeyPath  string
	BaseDomain           string
	Log                  compatLogConfig
	DisableUpdateCheck   bool
	Database             compatDatabaseConfig
	DERP                 compatDERPConfig
	TLS                  compatTLSConfig
	DNSConfig            compatDNSConfig
	TailcfgDNSConfig     *tailcfg.DNSConfig
	DNSChallenge         compatDNSChallengeConfig
	UnixSocket           string
	UnixSocketPermission fs.FileMode
	OIDC                 compatOIDCConfig
	LogTail              compatLogTailConfig
	Taildrop             compatTaildropConfig
	AutoUpdate           compatAutoUpdateConfig
	CLI                  compatCLIConfig
	Policy               compatPolicyConfig
	Tuning               compatTuning
}

type compatNodeConfig struct {
	Expiry    time.Duration
	Ephemeral compatEphemeralConfig
	Routes    compatRouteConfig
}

type compatEphemeralConfig struct{ InactivityTimeout time.Duration }

type compatRouteConfig struct{ HA compatHARouteConfig }

type compatHARouteConfig struct{ ProbeInterval, ProbeTimeout time.Duration }

type compatPreAuthKeysConfig struct{ RevokedRetention time.Duration }

type compatLogConfig struct {
	Format string
	Level  zerolog.Level
}

type compatDatabaseConfig struct {
	Type     string
	Debug    bool
	Gorm     compatGormConfig
	Sqlite   compatSqliteConfig
	Postgres compatPostgresConfig
}

type compatGormConfig struct {
	Debug                 bool
	SlowThreshold         time.Duration
	SkipErrRecordNotFound bool
	ParameterizedQueries  bool
}

type compatSqliteConfig struct {
	Path              string
	WriteAheadLog     bool
	WALAutoCheckPoint int
}

type compatPostgresConfig struct {
	Host                string
	Port                int
	Name                string
	User                string
	Ssl                 string
	MaxOpenConnections  int
	MaxIdleConnections  int
	ConnMaxIdleTimeSecs int
}

type compatDERPConfig struct {
	ServerEnabled                      bool
	AutomaticallyAddEmbeddedDerpRegion bool
	ServerRegionID                     tailcfg.DERPRegionID
	ServerRegionCode                   string
	ServerRegionName                   string
	ServerPrivateKeyPath               string
	ServerVerifyClients                bool
	STUNAddr                           string
	URLs                               []url.URL
	Paths                              []string
	DERPMap                            *tailcfg.DERPMap
	AutoUpdate                         bool
	UpdateFrequency                    time.Duration
	IPv4                               string
	IPv6                               string
}

type compatTLSConfig struct {
	CertPath string
	KeyPath  string
	ACME     compatACMEConfig
}

type compatACMEConfig struct {
	Hostname      string
	ChallengeType string
	HTTPListen    string
	URL           string
	Email         string
	CacheDir      string
}

type compatDNSConfig struct {
	MagicDNS         bool
	BaseDomain       string
	OverrideLocalDNS bool
	Nameservers      compatNameservers
	SearchDomains    []string
	ExtraRecords     []tailcfg.DNSRecord
	ExtraRecordsPath string
	Certificates     compatCertificatesConfig
}

type compatNameservers struct {
	Global []string
	Split  map[string][]string
}

type compatCertificatesConfig struct {
	Enabled bool
	Zone    string
}

type compatDNSChallengeConfig struct {
	PropagationTimeout time.Duration
	Resolvers          []string
	ProviderName       string
}

type compatOIDCConfig struct {
	OnlyStartIfOIDCIsAvailable bool
	Issuer                     string
	ClientID                   string
	Scope                      []string
	ExtraParams                map[string]string
	AllowedDomains             []string
	AllowedUsers               []string
	AllowedGroups              []string
	EmailVerifiedRequired      bool
	UseExpiryFromToken         bool
	PKCE                       compatPKCEConfig
}

type compatPKCEConfig struct {
	Enabled bool
	Method  string
}

type compatLogTailConfig struct{ Enabled bool }

type compatTaildropConfig struct{ Enabled bool }

type compatAutoUpdateConfig struct{ Enabled bool }

type compatCLIConfig struct {
	Address  string
	Timeout  time.Duration
	Insecure bool
}

type compatPolicyConfig struct {
	Path string
	Mode string
}

type compatTuning struct {
	BatchChangeDelay               time.Duration
	NodeMapSessionBufferedChanSize int
	BatcherWorkers                 int
	RegisterCacheExpiration        time.Duration
	RegisterCacheMaxEntries        int
	NodeStoreBatchSize             int
	NodeStoreBatchTimeout          time.Duration
}

// compatView renders cfg in the golden shape, deriving the values the
// loader used to store resolved.
func compatView(cfg *types.Config) compatConfig {
	pg := cfg.Database.Postgres
	oidc := cfg.OIDC
	ch := cfg.DNSConfig.Challenge
	acme := cfg.TLS.ACME
	derp := cfg.DERP.Server

	dbType := cfg.Database.Type
	if cfg.Database.IsSQLite() {
		dbType = types.DatabaseSqlite
	}

	derpURLs := make([]url.URL, 0, len(cfg.DERP.URLs))
	for _, s := range cfg.DERP.URLs {
		u, err := url.Parse(string(s))
		if err == nil {
			derpURLs = append(derpURLs, *u)
		}
	}

	tuning := compatTuning(cfg.Tuning)
	tuning.BatcherWorkers = cfg.Tuning.BatcherWorkerCount()

	// Today's loader read an empty list as nil and an unset map as empty.
	trusted := cfg.TrustedProxies
	if len(trusted) == 0 {
		trusted = nil
	}

	extraParams := oidc.ExtraParams
	if extraParams == nil {
		extraParams = map[string]string{}
	}

	return compatConfig{
		ServerURL:      cfg.ServerURL,
		Addr:           string(cfg.Addr),
		MetricsAddr:    string(cfg.MetricsAddr),
		TrustedProxies: trusted,
		Node: compatNodeConfig{
			Expiry:    cfg.Node.Expiry,
			Ephemeral: compatEphemeralConfig(cfg.Node.Ephemeral),
			Routes:    compatRouteConfig{HA: compatHARouteConfig(cfg.Node.Routes.HA)},
		},
		PreAuthKeys:         compatPreAuthKeysConfig(cfg.PreAuthKeys),
		PrefixV4:            cfg.Prefixes.V4,
		PrefixV6:            cfg.Prefixes.V6,
		IPAllocation:        string(cfg.Prefixes.Allocation),
		NoisePrivateKeyPath: cfg.AbsPath(cfg.Noise.PrivateKeyPath),
		BaseDomain:          cfg.DNSConfig.BaseDomain,
		Log: compatLogConfig{
			Format: string(cfg.Log.Format),
			Level:  cfg.Log.Level.Zerolog(),
		},
		DisableUpdateCheck: cfg.DisableUpdateCheck,
		Database: compatDatabaseConfig{
			Type:  string(dbType),
			Debug: cfg.Database.Debug,
			Gorm: compatGormConfig{
				Debug:                 cfg.Database.Debug,
				SlowThreshold:         time.Duration(cfg.Database.Gorm.SlowThreshold) * time.Millisecond,
				SkipErrRecordNotFound: cfg.Database.Gorm.SkipErrRecordNotFound,
				ParameterizedQueries:  cfg.Database.Gorm.ParameterizedQueries,
			},
			Sqlite: compatSqliteConfig{
				Path:              cfg.SQLitePath(),
				WriteAheadLog:     cfg.Database.Sqlite.WriteAheadLog,
				WALAutoCheckPoint: cfg.Database.Sqlite.WALAutoCheckPoint,
			},
			Postgres: compatPostgresConfig{
				Host:                pg.Host,
				Port:                pg.Port,
				Name:                pg.Name,
				User:                pg.User,
				Ssl:                 pg.Ssl,
				MaxOpenConnections:  pg.MaxOpenConnections,
				MaxIdleConnections:  pg.MaxIdleConnections,
				ConnMaxIdleTimeSecs: pg.ConnMaxIdleTimeSecs,
			},
		},
		DERP: compatDERPConfig{
			ServerEnabled:                      derp.Enabled,
			AutomaticallyAddEmbeddedDerpRegion: derp.AutomaticallyAddEmbeddedDerpRegion,
			ServerRegionID:                     derp.RegionID,
			ServerRegionCode:                   derp.RegionCode,
			ServerRegionName:                   derp.RegionName,
			ServerPrivateKeyPath:               cfg.AbsPath(derp.PrivateKeyPath),
			ServerVerifyClients:                derp.VerifyClients,
			STUNAddr:                           string(derp.STUNAddr),
			URLs:                               derpURLs,
			Paths:                              cfg.DERP.Paths,
			DERPMap:                            cfg.DERP.DERPMap,
			AutoUpdate:                         cfg.DERP.AutoUpdate,
			UpdateFrequency:                    cfg.DERP.UpdateFrequency,
			IPv4:                               derp.IPv4,
			IPv6:                               derp.IPv6,
		},
		TLS: compatTLSConfig{
			CertPath: cfg.AbsPath(cfg.TLS.CertPath),
			KeyPath:  cfg.AbsPath(cfg.TLS.KeyPath),
			ACME: compatACMEConfig{
				Hostname:      acme.Hostname,
				ChallengeType: string(acme.ChallengeType),
				HTTPListen:    string(acme.HTTPListen),
				URL:           string(acme.URL),
				Email:         acme.Email,
				CacheDir:      cfg.AbsPath(acme.CacheDir),
			},
		},
		DNSConfig: compatDNSConfig{
			MagicDNS:         cfg.DNSConfig.MagicDNS,
			BaseDomain:       cfg.DNSConfig.BaseDomain,
			OverrideLocalDNS: cfg.DNSConfig.OverrideLocalDNS,
			Nameservers:      compatNameservers(cfg.DNSConfig.Nameservers),
			SearchDomains:    cfg.DNSConfig.SearchDomains,
			ExtraRecords:     cfg.DNSConfig.ExtraRecords,
			ExtraRecordsPath: cfg.DNSConfig.ExtraRecordsPath,
			Certificates: compatCertificatesConfig{
				Enabled: cfg.DNSConfig.Certificates.Enabled,
				Zone:    cfg.DNSConfig.CertificateZone(),
			},
		},
		TailcfgDNSConfig: cfg.TailcfgDNSConfig(),
		DNSChallenge: compatDNSChallengeConfig{
			PropagationTimeout: ch.PropagationTimeout,
			Resolvers:          ch.ResolverAddrs(),
			ProviderName:       ch.ProviderName(),
		},
		UnixSocket:           cfg.UnixSocket,
		UnixSocketPermission: fs.FileMode(cfg.UnixSocketPermission),
		OIDC: compatOIDCConfig{
			OnlyStartIfOIDCIsAvailable: oidc.OnlyStartIfOIDCIsAvailable,
			Issuer:                     string(oidc.Issuer),
			ClientID:                   oidc.ClientID,
			Scope:                      oidc.Scope,
			ExtraParams:                extraParams,
			AllowedDomains:             oidc.AllowedDomains,
			AllowedUsers:               oidc.AllowedUsers,
			AllowedGroups:              oidc.AllowedGroups,
			EmailVerifiedRequired:      oidc.EmailVerifiedRequired,
			UseExpiryFromToken:         oidc.UseExpiryFromToken,
			PKCE:                       compatPKCEConfig{Enabled: oidc.PKCE.Enabled, Method: string(oidc.PKCE.Method)},
		},
		LogTail:    compatLogTailConfig(cfg.LogTail),
		Taildrop:   compatTaildropConfig(cfg.Taildrop),
		AutoUpdate: compatAutoUpdateConfig(cfg.AutoUpdate),
		CLI: compatCLIConfig{
			Address:  cfg.CLI.Address,
			Timeout:  cfg.CLI.Timeout,
			Insecure: cfg.CLI.Insecure,
		},
		Policy: compatPolicyConfig{Path: cfg.Policy.Path, Mode: string(cfg.Policy.Mode)},
		Tuning: tuning,
	}
}

// loadCompat loads one fixture set the way headscale does, from a temp dir
// so relative paths and the error text do not depend on the checkout.
func loadCompat(t *testing.T, file, envFile string, cli bool) compatRecord {
	t.Helper()

	dir := stageCompat(t, file, envFile)

	l, err := Load(dir, false, os.Environ())
	cfg := l.Config

	norm := func(s string) string { return strings.ReplaceAll(s, dir, "$DIR") }

	var rec compatRecord

	warn := func(ws []string) {
		for _, w := range ws {
			rec.Warnings = append(rec.Warnings, norm(w))
		}
	}

	warn(l.Warnings)

	if err == nil && !cli {
		// As serve takes it: validated, advisories reported, without the
		// CLI's key.
		err = Validate(cfg)
		warn(Warnings(cfg))

		cfg.CLI.APIKey = ""
		if err != nil {
			cfg = nil
		}
	}

	if err != nil {
		rec.Error = norm(err.Error())
	}

	if cfg != nil {
		view := compatView(cfg)
		if cli {
			// Client commands read only these; compatView would derive server
			// values from the rest.
			view = compatConfig{
				Log:                view.Log,
				DisableUpdateCheck: view.DisableUpdateCheck,
				UnixSocket:         view.UnixSocket,
				CLI:                view.CLI,
			}
		}

		if view.Tuning.BatcherWorkers == types.DefaultBatcherWorkers() {
			view.Tuning.BatcherWorkers = 0 // depends on runtime.NumCPU
		}

		raw, err := json.Marshal(view)
		require.NoError(t, err)

		rec.Config = json.RawMessage(norm(string(raw)))
		// As its consumer reads it; one no consumer reads stays as written.
		secret := func(s types.Secret, active bool) string {
			if !active {
				return string(s)
			}

			v, err := s.Resolve()
			require.NoError(t, err)

			return v
		}
		rec.Secrets = map[string]string{
			"database.postgres.pass": secret(cfg.Database.Postgres.Pass, cfg.Database.Type == types.DatabasePostgres),
			"oidc.client_secret":     secret(cfg.OIDC.ClientSecret, cfg.OIDC.Issuer != ""),
			"cli.api_key":            secret(cfg.CLI.APIKey, cfg.CLI.Address != ""),
		}
		maps.DeleteFunc(rec.Secrets, func(_, v string) bool { return v == "" })
	}

	return rec
}

// stageCompat copies file into a temp dir as config.<ext> and sets the
// variables of envFile, returning the dir.
func stageCompat(t *testing.T, file, envFile string) string {
	t.Helper()

	dir := t.TempDir()

	if file != "" {
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "config"+filepath.Ext(file)), data, 0o600)) //nolint:gosec // dir is t.TempDir()
	}

	if envFile != "" {
		raw, err := os.ReadFile(envFile)
		require.NoError(t, err)

		// docker --env-file syntax: no quoting, # comments.
		for line := range strings.SplitSeq(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			k, v, ok := strings.Cut(line, "=")
			require.Truef(t, ok, "%s: %q is not KEY=VALUE", envFile, line)
			t.Setenv(k, v)
		}
	}

	return dir
}

func TestDERPServerPrivateKeyPath(t *testing.T) {
	tests := []struct {
		name    string
		derpKey string // derp.server.private_key_path line, if any
		wantErr string
	}{
		{"missing", "", "derp.server.private_key_path is required"},
		{"distinct", "    private_key_path: derp_server_private.key\n", ""},
		{"same as noise", "    private_key_path: noise_private.key\n", "must differ from noise.private_key_path"},
		{"same as noise after cleaning", "    private_key_path: ./noise_private.key\n", "must differ from noise.private_key_path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(`---
noise:
  private_key_path: noise_private.key
server_url: http://127.0.0.1:8080
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite3
dns:
  magic_dns: false
  override_local_dns: false
derp:
  server:
    enabled: true
    stun_listen_addr: "0.0.0.0:3478"
`+tt.derpKey), 0o600))

			_, err := loadServer(dir, false)
			if tt.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestPolicyMode(t *testing.T) {
	for _, tt := range []struct {
		mode    string
		wantErr bool
	}{
		{"file", false},
		{"database", false},
		{"databse", true},
		{"File", true},
		{`""`, true},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(`---
noise:
  private_key_path: noise_private.key
server_url: http://127.0.0.1:8080
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite3
dns:
  magic_dns: false
  override_local_dns: false
policy:
  mode: `+tt.mode+"\n"), 0o600))

			_, err := loadServer(dir, false)
			if !tt.wantErr {
				require.NoError(t, err)

				return
			}

			require.ErrorContains(t, err, "policy.mode has an unsupported value")
		})
	}
}

// decodeValues decodes the defaults with values layered on top.
func decodeValues(t *testing.T, values map[string]any) (*types.Config, error) {
	t.Helper()

	d := Default()
	s := &configSource{k: koanf.New(".")}
	require.NoError(t, s.k.Load(confmap.Provider(plainMap(&d, false), ""), nil))
	require.NoError(t, s.k.Load(confmap.Provider(values, "."), nil))

	return s.decode()
}

// loadServer loads path with the process environment and validates the
// result, as serve does.
func loadServer(path string, isFile bool) (*types.Config, error) {
	l, err := Load(path, isFile, os.Environ())
	if err != nil {
		return nil, err
	}

	err = Validate(l.Config)
	if err != nil {
		return nil, err
	}

	return l.Config, nil
}

// loadCLI loads the file path with the process environment, as client
// commands do.
func loadCLI(path string) (*types.Config, error) {
	l, err := Load(path, true, os.Environ())

	return l.Config, err
}

// TestConfigDirRelativePaths: relative paths resolve against the directory
// the config file was found in, not the working directory.
func TestConfigDirRelativePaths(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(`
server_url: https://headscale.example.com
noise:
  private_key_path: ./noise.key
policy:
  path: ./policy.hujson
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite
dns:
  magic_dns: false
  override_local_dns: false
`), 0o600))

	t.Chdir(t.TempDir())

	cfg, err := loadServer(dir, false)
	require.NoError(t, err)

	assert.Equal(t, "./noise.key", cfg.Noise.PrivateKeyPath)
	assert.Equal(t, filepath.Join(dir, "noise.key"), cfg.AbsPath(cfg.Noise.PrivateKeyPath))
	assert.Equal(t, "./policy.hujson", cfg.Policy.Path)
	assert.Equal(t, filepath.Join(dir, "policy.hujson"), cfg.AbsPath(cfg.Policy.Path))
}

// TestSQLiteMemoryPath: ":memory:" names SQLite's in-memory database, not a
// file to resolve against the config directory.
func TestSQLiteMemoryPath(t *testing.T) {
	for _, withFile := range []bool{false, true} {
		t.Run(fmt.Sprintf("file=%t", withFile), func(t *testing.T) {
			for k, v := range map[string]string{
				"HEADSCALE_SERVER_URL":             "https://headscale.example.com",
				"HEADSCALE_NOISE_PRIVATE_KEY_PATH": "noise.key",
				"HEADSCALE_PREFIXES_V4":            "100.64.0.0/10",
				"HEADSCALE_DATABASE_TYPE":          "sqlite",
				"HEADSCALE_DATABASE_SQLITE_PATH":   ":memory:",
				"HEADSCALE_DNS_MAGIC_DNS":          "false",
				"HEADSCALE_DNS_OVERRIDE_LOCAL_DNS": "false",
			} {
				t.Setenv(k, v)
			}

			dir := t.TempDir()
			if withFile {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), nil, 0o600))
			}

			cfg, err := loadServer(dir, false)
			require.NoError(t, err)
			assert.Equal(t, ":memory:", cfg.SQLitePath())
			assert.True(t, filepath.IsAbs(cfg.AbsPath(cfg.Noise.PrivateKeyPath)), cfg.AbsPath(cfg.Noise.PrivateKeyPath))
		})
	}
}

// TestValidate pins the rules on loaded configs and the order they report
// in.
func TestValidate(t *testing.T) {
	const valid = `server_url: https://headscale.example.com
noise:
  private_key_path: noise_private.key
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite
dns:
  magic_dns: false
  override_local_dns: false
`

	// Breaks every rule once; a rule whose empty value has its own reason
	// is broken by a set value here.
	const everyRule = `server_url: headscale.example.com
listen_addr: 0.0.0.0:8080
metrics_listen_addr: 0.0.0.0:8080
unix_socket: ""
trusted_proxies: [0.0.0.0/0]
noise:
  private_key_path: ""
prefixes:
  v4: ""
  v6: ""
  allocation: ""
policy:
  mode: ""
node:
  ephemeral:
    inactivity_timeout: 30s
  routes:
    ha:
      probe_interval: 1s
tuning:
  node_store_batch_size: 0
derp:
  server:
    enabled: true
    private_key_path: /var/lib/headscale/derp.key
database:
  type: ""
dns:
  magic_dns: true
  base_domain: ""
  override_local_dns: true
  extra_records: [{name: a.example.com, type: A, value: 100.64.0.1}]
  extra_records_path: /var/lib/headscale/records.json
  challenge:
    resolvers: [""]
    provider:
      name: bogus
tls:
  cert_path: /etc/headscale/cert.pem
  acme:
    hostname: example.com
    challenge_type: ""
    cache_dir: ""
oidc:
  issuer: https://idp.example.com
  client_id: headscale
  client_secret: secret
  pkce:
    method: ""
`

	tests := []struct {
		name string
		file string
		want []string // reasons, in order
	}{
		{name: "valid", file: valid},
		{
			// What the NixOS module writes: an explicit empty default.
			name: "empty extra records next to a path",
			file: valid + "  extra_records: []\n  extra_records_path: /var/lib/headscale/records.json\n",
		},
		{
			name: "extra records next to a path",
			file: valid + "  extra_records: [{name: a.example.com, type: A, value: 100.64.0.1}]\n  extra_records_path: /var/lib/headscale/records.json\n",
			want: []string{"dns.extra_records and dns.extra_records_path are mutually exclusive"},
		},
		{
			name: "every rule, in order",
			file: everyRule,
			want: []string{
				"dns.challenge.resolvers[0] is empty",
				"OIDC configuration is invalid",
				"dns.extra_records and dns.extra_records_path are mutually exclusive",
				"tls.acme.hostname and tls.cert_path/tls.key_path are mutually exclusive",
				"tls.acme.cache_dir is required when tls.acme.hostname is set",
				"noise.private_key_path is required",
				"unix_socket is required",
				"listen_addr and metrics_listen_addr would bind the same TCP socket",
				"tls.acme.challenge_type has an unsupported value",
				"server_url is missing a scheme",
				"node.ephemeral.inactivity_timeout is below the minimum",
				"node.routes.ha.probe_interval is below the minimum",
				"node.routes.ha.probe_timeout must be less than node.routes.ha.probe_interval",
				"tuning.node_store_batch_size must be positive",
				"derp.server.stun_listen_addr is required when the embedded DERP server is enabled",
				"database.type has an unsupported value",
				"policy.mode has an unsupported value",
				"dns.base_domain is required when dns.magic_dns is true",
				"trusted_proxies contains an invalid CIDR",
				"no IP prefix configured for the tailnet",
				"prefixes.allocation has an unsupported value",
				"dns.challenge.provider is invalid",
			},
		},
		{
			// Emptied, these keys give their required reason in place of the
			// rule their set value broke.
			name: "every rule, in order, required values empty",
			file: strings.NewReplacer(
				"server_url: headscale.example.com\nlisten_addr: 0.0.0.0:8080\n", "server_url: \"\"\nlisten_addr: \"\"\n",
				"database:\n  type: \"\"\n", "database:\n  type: sqlite\n  sqlite:\n    path: \"\"\n",
			).Replace(everyRule),
			want: []string{
				"dns.challenge.resolvers[0] is empty",
				"OIDC configuration is invalid",
				"dns.extra_records and dns.extra_records_path are mutually exclusive",
				"tls.acme.hostname and tls.cert_path/tls.key_path are mutually exclusive",
				"tls.acme.cache_dir is required when tls.acme.hostname is set",
				"noise.private_key_path is required",
				"listen_addr is required",
				"unix_socket is required",
				"tls.acme.challenge_type has an unsupported value",
				"server_url is required",
				"node.ephemeral.inactivity_timeout is below the minimum",
				"node.routes.ha.probe_interval is below the minimum",
				"node.routes.ha.probe_timeout must be less than node.routes.ha.probe_interval",
				"tuning.node_store_batch_size must be positive",
				"derp.server.stun_listen_addr is required when the embedded DERP server is enabled",
				"database.sqlite.path is required when database.type is sqlite",
				"policy.mode has an unsupported value",
				"dns.base_domain is required when dns.magic_dns is true",
				"trusted_proxies contains an invalid CIDR",
				"no IP prefix configured for the tailnet",
				"prefixes.allocation has an unsupported value",
				"dns.challenge.provider is invalid",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := loadCLI(writeConfig(t, tt.file))
			require.NoError(t, err)

			err = Validate(cfg)
			if len(tt.want) == 0 {
				require.NoError(t, err)

				return
			}

			assert.Equal(t, tt.want, reasons(types.ConfigErrors(err)))
		})
	}
}

// TestProviderNameShape: a provider name that is a map or list is rejected
// by its key alone, as its contents may be credentials, and never shown.
func TestProviderNameShape(t *testing.T) {
	const base = `server_url: https://headscale.example.com
noise:
  private_key_path: noise_private.key
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite
dns:
  magic_dns: true
  override_local_dns: false
  base_domain: ts.example.com
  certificates:
    enabled: true
`

	for name, tt := range map[string]struct {
		yaml string
		env  map[string]string
	}{
		"file map":  {yaml: base + "  challenge:\n    provider:\n      name: {api_token: marker-secret}\n"},
		"file list": {yaml: base + "  challenge:\n    provider:\n      name: [marker-secret]\n"},
		"env json":  {yaml: base, env: map[string]string{"HEADSCALE_DNS_CHALLENGE_PROVIDER": `{"name":{"api_token":"marker-secret"}}`}},
	} {
		t.Run(name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			cfg, err := loadCLI(writeConfig(t, tt.yaml))
			require.NoError(t, err)

			out, err := json.Marshal(plainMap(cfg, true))
			require.NoError(t, err)
			assert.NotContains(t, string(out), "marker-secret")

			err = Validate(cfg)
			require.Error(t, err)
			assert.Equal(t, []string{"dns.challenge.provider.name must be a provider name"}, reasons(types.ConfigErrors(err)))
			assert.NotContains(t, err.Error(), "marker-secret")
		})
	}

	// A scalar name is coerced to its text, as before.
	assert.Equal(t, "123", types.DNSChallengeConfig{ProviderSettings: map[string]any{"name": 123}}.ProviderName())
}

// TestDERPURLsMalformed: a malformed derp.urls entry stops the load, naming
// the key, instead of being skipped, as it once was after crashing startup
// on the nil *url.URL url.Parse returns.
func TestDERPURLsMalformed(t *testing.T) {
	_, err := decodeValues(t, map[string]any{"derp.urls": []string{
		"https://controlplane.tailscale.com/derpmap/default",
		"://bad",
	}})

	require.ErrorContains(t, err, "derp.urls is not an http:// or https:// URL")
}

// TestLoadKeepsWarningsOnError: a file that fails to load still reports
// what the environment said, so the caller can print it with the error.
func TestLoadKeepsWarningsOnError(t *testing.T) {
	path := writeConfig(t, "server_url: https://h\nbogus_key: 1\n")

	l, err := Load(path, true, []string{"HEADSCALE_SERVR_URL=x"})
	require.ErrorContains(t, err, "unknown configuration key bogus_key")
	require.NotNil(t, l)
	assert.Nil(t, l.Config)
	assert.Equal(t, path, l.File)
	require.Len(t, l.Warnings, 1)
	assert.Contains(t, l.Warnings[0], "unknown environment variable HEADSCALE_SERVR_URL")
}

// TestEnvNames: every key has its own variable, and setting that variable
// alone changes that key alone.
func TestEnvNames(t *testing.T) {
	keys := schemaKeys()

	byName := map[string]string{}

	for _, k := range keys {
		name := configEnvName(k.Path)
		require.NotContainsf(t, byName, name, "%s and %s share %s", byName[name], k.Path, name)
		byName[name] = k.Path
	}

	// A valid value for each type, unlike any default.
	samples := map[reflect.Type]string{
		reflect.TypeFor[time.Duration]():       "7s",
		reflect.TypeFor[*netip.Prefix]():       "100.64.0.0/16",
		reflect.TypeFor[[]netip.Prefix]():      "10.0.0.0/8 fd00::/8",
		reflect.TypeFor[types.ListenAddr]():    "127.0.0.1:7",
		reflect.TypeFor[types.HTTPURL]():       "https://example.com/x",
		reflect.TypeFor[[]types.HTTPURL]():     "https://example.com/x",
		reflect.TypeFor[types.FileMode]():      "0700",
		reflect.TypeFor[[]string]():            "a b",
		reflect.TypeFor[[]tailcfg.DNSRecord](): `[{"name":"a.example.com","type":"A","value":"100.64.0.1"}]`,
		reflect.TypeFor[map[string][]string](): `{"a.example.com":["1.1.1.1"]}`,
		reflect.TypeFor[map[string]string]():   `{"k":"v"}`,
		reflect.TypeFor[map[string]any]():      `{"name":"cloudflare"}`,
	}

	path := writeConfig(t, "")
	d := Default()
	defaults := types.ConfigFields(&d)

	for i, k := range keys {
		t.Run(k.Path, func(t *testing.T) {
			def := defaults[i].Value
			require.Equal(t, k.Path, defaults[i].Path)

			val, ok := samples[def.Type()]

			switch e, enum := reflect.TypeAssert[interface{ Allowed() []string }](def); {
			case ok:
			case enum:
				i := slices.IndexFunc(e.Allowed(), func(v string) bool { return v != def.String() })
				val = e.Allowed()[i]
			case def.Kind() == reflect.Bool:
				val = strconv.FormatBool(!def.Bool())
			case def.CanInt():
				val = strconv.FormatInt(def.Int()+1, 10)
			case def.Kind() == reflect.String:
				val = "x" + def.String()
			default:
				t.Fatalf("no sample for %s", def.Type())
			}

			l, err := Load(path, true, []string{configEnvName(k.Path) + "=" + val})
			require.NoError(t, err)
			assert.Empty(t, l.Warnings)

			for j, f := range types.ConfigFields(l.Config) {
				same := reflect.DeepEqual(f.Value.Interface(), defaults[j].Value.Interface())
				assert.Equalf(t, f.Path != k.Path, same, "%s=%s: %s", configEnvName(k.Path), val, f.Path)
			}
		})
	}
}

// FuzzLoad: no file makes Load panic, and one that loads round-trips.
func FuzzLoad(f *testing.F) {
	seeds, err := filepath.Glob(filepath.Join(compatDir, "*.yaml"))
	require.NoError(f, err)

	for _, s := range seeds {
		b, err := os.ReadFile(s)
		require.NoError(f, err)
		f.Add(b)
	}

	for _, v := range roundTripValues {
		if v.file != "" {
			f.Add([]byte(v.file))
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(path, data, 0o600))

		l, err := Load(path, true, nil)
		if err != nil {
			return
		}

		for _, ext := range fileFormats {
			got, err := roundTrip(t, l.Config, ext)
			require.NoError(t, err, ext)

			if diff := gocmp.Diff(l.Config, got, roundTripOpts); diff != "" {
				t.Errorf("%s round trip (-written +loaded):\n%s", ext, diff)
			}
		}
	})
}

// TestMapKeyCase: an open map's keys follow its rule in every format and in
// variables: oidc.extra_params keeps their case, dns.nameservers.split and
// DNS provider settings, nested ones included, are lowercased. The config
// then round-trips exactly.
func TestMapKeyCase(t *testing.T) {
	unsetHeadscaleEnv(t)

	for name, tt := range map[string]struct {
		ext, file string
		env       []string
	}{
		"yaml": {ext: ".yaml", file: "oidc:\n  extra_params:\n    Login_Hint: a\n    login_hint: b\n" +
			"dns:\n  nameservers:\n    split:\n      Corp.Example.COM: [10.0.0.1]\n" +
			"  challenge:\n    provider:\n      Name: acmedns\n      Config:\n        Laptop.Example.com:\n          Password: x\n"},
		"yaml dotted": {ext: ".yaml", file: "oidc.extra_params.Login_Hint: a\noidc.extra_params.login_hint: b\n" +
			"dns.nameservers.split.Corp.Example.COM: [10.0.0.1]\n" +
			"dns.challenge.provider: {Name: acmedns, Config: {Laptop.Example.com: {Password: x}}}\n"},
		"json": {ext: ".json", file: `{"oidc": {"extra_params": {"Login_Hint": "a", "login_hint": "b"}},
			"dns": {"nameservers": {"split": {"Corp.Example.COM": ["10.0.0.1"]}},
			"challenge": {"provider": {"Name": "acmedns", "Config": {"Laptop.Example.com": {"Password": "x"}}}}}}`},
		"yaml string objects": {ext: ".yaml", file: "oidc:\n  extra_params: '{\"Login_Hint\": \"a\", \"login_hint\": \"b\"}'\n" +
			"dns:\n  nameservers:\n    split: '{\"Corp.Example.COM\": [\"10.0.0.1\"]}'\n" +
			"  challenge:\n    provider: '{\"Name\": \"acmedns\", \"Config\": {\"Laptop.Example.com\": {\"Password\": \"x\"}}}'\n"},
		"env": {env: []string{
			`HEADSCALE_OIDC_EXTRA_PARAMS={"Login_Hint":"a","login_hint":"b"}`,
			`HEADSCALE_DNS_NAMESERVERS_SPLIT={"Corp.Example.COM":["10.0.0.1"]}`,
			`HEADSCALE_DNS_CHALLENGE_PROVIDER={"Name":"acmedns","Config":{"Laptop.Example.com":{"Password":"x"}}}`,
		}},
	} {
		t.Run(name, func(t *testing.T) {
			path := ""
			if tt.file != "" {
				path = filepath.Join(t.TempDir(), "config"+tt.ext)
				require.NoError(t, os.WriteFile(path, []byte(tt.file), 0o600))
			}

			l, err := Load(path, path != "", tt.env)
			require.NoError(t, err)

			cfg := l.Config
			assert.Equal(t, map[string]string{"Login_Hint": "a", "login_hint": "b"}, cfg.OIDC.ExtraParams)
			assert.Equal(t, map[string][]string{"corp.example.com": {"10.0.0.1"}}, cfg.DNSConfig.Nameservers.Split)
			assert.Equal(t, map[string]any{
				"name":   "acmedns",
				"config": map[string]any{"laptop.example.com": map[string]any{"password": "x"}},
			}, cfg.DNSConfig.Challenge.ProviderSettings)

			for _, ext := range fileFormats {
				got, err := roundTrip(t, cfg, ext)
				require.NoError(t, err, ext)

				if diff := gocmp.Diff(cfg, got, roundTripOpts); diff != "" {
					t.Errorf("%s round trip (-written +loaded):\n%s", ext, diff)
				}
			}
		})
	}
}

// TestMapKeyCollision: two keys that one spelling makes the same are an
// error naming both, not one picked at random, and showing no value.
func TestMapKeyCollision(t *testing.T) {
	for name, tt := range map[string]struct {
		file string
		env  []string
		want string
	}{
		"split string object": {
			file: "dns:\n  nameservers:\n    split: '{\"Corp.example.com\": [\"marker-a\"], \"corp.example.com\": [\"marker-b\"]}'\n",
			want: `configuration keys "Corp.example.com" and "corp.example.com" in dns.nameservers.split differ only in case (`,
		},
		"provider string object": {
			file: "dns:\n  challenge:\n    provider: '{\"API_TOKEN\": \"marker-a\", \"api_token\": \"marker-b\"}'\n",
			want: `configuration keys "API_TOKEN" and "api_token" in dns.challenge.provider differ only in case (`,
		},
		"split": {
			file: "dns:\n  nameservers:\n    split:\n      Corp.example.com: [10.0.0.1]\n      corp.example.com: [10.0.0.2]\n",
			want: `configuration keys "Corp.example.com" and "corp.example.com" in dns.nameservers.split differ only in case (`,
		},
		"provider setting": {
			file: "dns:\n  challenge:\n    provider:\n      API_TOKEN: marker-a\n      api_token: marker-b\n",
			want: `configuration keys "API_TOKEN" and "api_token" in dns.challenge.provider differ only in case (`,
		},
		"provider registration": {
			file: "dns:\n  challenge:\n    provider:\n      config:\n        A.example.com: {password: marker-a}\n        a.example.com: {password: marker-b}\n",
			want: `configuration keys "A.example.com" and "a.example.com" in dns.challenge.provider.config differ only in case (`,
		},
		"env split": {
			env:  []string{`HEADSCALE_DNS_NAMESERVERS_SPLIT={"Corp.example.com":["marker-a"],"corp.example.com":["marker-b"]}`},
			want: `configuration keys "Corp.example.com" and "corp.example.com" in dns.nameservers.split differ only in case (env HEADSCALE_DNS_NAMESERVERS_SPLIT)`,
		},
		"env provider": {
			env:  []string{`HEADSCALE_DNS_CHALLENGE_PROVIDER={"Name":"marker-a","name":"marker-b"}`},
			want: `configuration keys "Name" and "name" in dns.challenge.provider differ only in case (env HEADSCALE_DNS_CHALLENGE_PROVIDER)`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.file != "" {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(tt.file), 0o600))
			}

			_, err := Load(dir, false, tt.env)
			require.ErrorContains(t, err, tt.want)
			requireHidden(t, err, "marker")
		})
	}
}
