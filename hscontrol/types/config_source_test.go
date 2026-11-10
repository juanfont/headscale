package types

import (
	"cmp"
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

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
		check     func(t *testing.T, cfg *Config)
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
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				assert.Equal(t, LogLevel("debug"), cfg.Log.Level)
				assert.Equal(t, "/c", cfg.TLS.CertPath)
			},
		},
		{
			name: "keys are case-insensitive",
			file: "Server_URL: https://x\ndns:\n  Nameservers:\n    Split:\n      Corp.Example.com: [10.0.0.1]\n",
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				assert.Equal(t, "https://x", cfg.ServerURL)
				assert.Equal(t,
					map[string][]string{"corp.example.com": {"10.0.0.1"}},
					cfg.DNSConfig.Nameservers.Split)
			},
		},
		{
			name: "null is unset, default stays",
			file: "server_url:\nlog:\n  level: ~\n",
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				assert.Empty(t, cfg.ServerURL)
				assert.Equal(t, LogLevel("info"), cfg.Log.Level)
			},
		},
		{
			name: "empty env is unset, env beats file",
			file: "server_url: http://file\nlisten_addr: 1.1.1.1:1\n",
			env:  []string{"HEADSCALE_SERVER_URL=http://env", "HEADSCALE_LISTEN_ADDR="},
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				assert.Equal(t, "http://env", cfg.ServerURL)
				assert.Equal(t, ListenAddr("1.1.1.1:1"), cfg.Addr)
			},
		},
		{
			name: "env lists and maps",
			env: []string{
				"HEADSCALE_DNS_NAMESERVERS_GLOBAL=1.1.1.1 8.8.8.8",
				`HEADSCALE_OIDC_EXTRA_PARAMS={"domain_hint":"example.com"}`,
			},
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				assert.Equal(t, []string{"1.1.1.1", "8.8.8.8"}, cfg.DNSConfig.Nameservers.Global)
				assert.Equal(t, map[string]string{"domain_hint": "example.com"}, cfg.OIDC.ExtraParams)
			},
		},
		{
			name: "open maps accept any key",
			file: "dns:\n  challenge:\n    provider:\n      name: cloudflare\n      whatever: 1\noidc:\n  extra_params:\n    a: b\n",
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				assert.Equal(t, "cloudflare", cfg.DNSConfig.Challenge.ProviderName())
				assert.Equal(t, 1, cfg.DNSConfig.Challenge.ProviderSettings["whatever"])
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
			errs:     []string{"config.hujson", "hujson: line 3, column 16"},
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
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				assert.Equal(t, "/n", cfg.Noise.PrivateKeyPath)
				assert.Equal(t, "/d", cfg.DERP.Server.PrivateKeyPath)
				assert.Equal(t, LogLevel("debug"), cfg.Log.Level)
				assert.Equal(t, "/c", cfg.TLS.CertPath)
				assert.Equal(t, "/db", cfg.Database.Sqlite.Path)
			},
		},
		{
			name: "dotted file keys override nested defaults",
			file: "log.level: debug\ndns.magic_dns: false\ndns:\n  nameservers.split:\n    Corp.Example.com: [10.0.0.1]\n",
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				assert.Equal(t, LogLevel("debug"), cfg.Log.Level)
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
			check: func(t *testing.T, cfg *Config) {
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
			env:   []string{"HEADSCALE_CONFIG=/x", "HEADSCALE_UPDATE_GOLDEN=1", "HEADSCALE_DNS_CHALLENGE_PROVIDER=x", "HEADSCALE_CONFIG_TYPO=1", "HEADSCALE_UPDATE_GOLDEN_BOGUS=1"},
			warns: []string{"HEADSCALE_CONFIG_TYPO", "HEADSCALE_UPDATE_GOLDEN_BOGUS"},
		},
		{
			name:      "empty file",
			emptyFile: true,
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				assert.Equal(t, LogLevel("info"), cfg.Log.Level)
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

			s, err := newConfigSource(path, isFile, tt.env)
			if len(tt.errs) > 0 {
				require.Error(t, err)

				for _, want := range tt.errs {
					require.ErrorContains(t, err, want)
				}

				return
			}

			require.NoError(t, err)
			require.Len(t, s.Warnings(), len(tt.warns))

			for i, w := range tt.warns {
				assert.Contains(t, s.Warnings()[i], w)
			}

			if tt.check != nil {
				cfg, err := s.decode()
				require.NoError(t, err)
				tt.check(t, cfg)
			}
		})
	}
}

const yamlSample = "server_url: https://x\nnode:\n  expiry: 1h\ndns:\n  magic_dns: false\n  nameservers:\n    global: [1.1.1.1, 8.8.8.8]\noidc:\n  extra_params:\n    domain_hint: example.com\n"

func checkSameValues(t *testing.T, cfg *Config) {
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

	s, err := newConfigSource(dir, false, nil)
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(s.File(), "config.json"))

	cfg, err := s.decode()
	require.NoError(t, err)
	assert.Equal(t, "http://json", cfg.ServerURL)

	s, err = newConfigSource(t.TempDir(), false, nil)
	require.NoError(t, err)
	assert.Empty(t, s.File())
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
		require.Equal(t, LogLevel("debug"), cfg.Log.Level)
		require.False(t, cfg.DNSConfig.MagicDNS)
		require.Equal(t, []string{"1.1.1.1"}, cfg.DNSConfig.Nameservers.Global)
	}
}

// TestConfigSourceDottedNoOverlap loads files whose dotted keys only share a
// string prefix: below an open map the entry name is one key, dots included.
func TestConfigSourceDottedNoOverlap(t *testing.T) {
	tests := []struct {
		name, file string
		check      func(t *testing.T, cfg *Config)
	}{
		{
			name: "dotted split domains",
			file: "dns.nameservers.split.corp.example.com: [10.0.0.1]\ndns.nameservers.split.corp.example.com.au: [10.0.0.2]\n",
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				assert.Equal(t,
					map[string][]string{"corp.example.com": {"10.0.0.1"}, "corp.example.com.au": {"10.0.0.2"}},
					cfg.DNSConfig.Nameservers.Split)
			},
		},
		{
			name: "dotted extra params",
			file: "oidc.extra_params.domain_hint: a\noidc.extra_params.domain_hint.extra: b\n",
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				assert.Equal(t, map[string]string{"domain_hint": "a", "domain_hint.extra": "b"}, cfg.OIDC.ExtraParams)
			},
		},
		{
			name: "nested split domains",
			file: "dns:\n  nameservers:\n    split:\n      corp.example.com: [10.0.0.1]\n      corp.example.com.au: [10.0.0.2]\n",
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				assert.Equal(t,
					map[string][]string{"corp.example.com": {"10.0.0.1"}, "corp.example.com.au": {"10.0.0.2"}},
					cfg.DNSConfig.Nameservers.Split)
			},
		},
		{
			name: "log and logtail",
			file: "log:\n  level: debug\nlog.format: json\nlogtail.enabled: true\n",
			check: func(t *testing.T, cfg *Config) {
				t.Helper()
				assert.Equal(t, LogLevel("debug"), cfg.Log.Level)
				assert.Equal(t, JSONLogFormat, cfg.Log.Format)
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

	s, err := newConfigSource(dir, false, os.Environ())
	require.NoError(t, err)
	assert.Empty(t, s.Warnings())

	cfg, err := s.decode()
	require.NoError(t, err)
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
			require.NoError(t, LoadConfig(dir, false))
			assert.Empty(t, src.Warnings())

			cfg, err := LoadServerConfig()
			require.NoError(t, err)

			if len(tt.want) == 0 {
				assert.Empty(t, cfg.DNSConfig.Challenge.ProviderSettings)

				return
			}

			assert.Equal(t, tt.want, cfg.DNSConfig.Challenge.ProviderSettings)
		})
	}
}

// decodeInput writes content as name (none when empty) and decodes it with
// env, as the loaders do.
func decodeInput(t *testing.T, name, content string, env ...string) (*Config, error) {
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
		check   func(t *testing.T, cfg *Config)
		wantErr []string
	}{
		{name: "yaml expiry 0", file: "node:\n  expiry: 0\n", check: func(t *testing.T, c *Config) { t.Helper(); assert.Zero(t, c.Node.Expiry) }},
		{name: "json expiry 0", file: `{"node": {"expiry": 0}}`, check: func(t *testing.T, c *Config) { t.Helper(); assert.Zero(t, c.Node.Expiry) }},
		{name: "env expiry 0", env: []string{"HEADSCALE_NODE_EXPIRY=0"}, check: func(t *testing.T, c *Config) { t.Helper(); assert.Zero(t, c.Node.Expiry) }},
		{name: "prometheus duration", file: "node:\n  expiry: 90d\n", check: func(t *testing.T, c *Config) {
			t.Helper()
			assert.Equal(t, 2160*time.Hour, c.Node.Expiry)
		}},
		{name: "duration without unit", file: "node:\n  expiry: 90\n", wantErr: []string{"node.expiry needs a unit (", "config.yaml:2:3)"}},
		{name: "env duration without unit", env: []string{"HEADSCALE_TUNING_BATCH_CHANGE_DELAY=800"}, wantErr: []string{"tuning.batch_change_delay needs a unit (env HEADSCALE_TUNING_BATCH_CHANGE_DELAY)"}},
		{name: "unquoted file mode", file: "unix_socket_permission: 0770\n", wantErr: []string{"unix_socket_permission must be quoted"}},
		{name: "quoted file mode", file: "unix_socket_permission: \"0770\"\n", check: func(t *testing.T, c *Config) {
			t.Helper()
			assert.Equal(t, FileMode(0o770), c.UnixSocketPermission)
		}},
		{name: "bool in a string field", file: "database:\n  postgres:\n    ssl: false\n", check: func(t *testing.T, c *Config) {
			t.Helper()
			assert.Equal(t, "false", c.Database.Postgres.Ssl)
		}},
		{name: "milliseconds stay a number", file: "database:\n  gorm:\n    slow_threshold: 1000\n", check: func(t *testing.T, c *Config) {
			t.Helper()
			assert.Equal(t, 1000, c.Database.Gorm.SlowThreshold)
		}},
		{name: "json integer", file: `{"database": {"postgres": {"port": 5432}}}`, check: func(t *testing.T, c *Config) {
			t.Helper()
			assert.Equal(t, 5432, c.Database.Postgres.Port)
		}},
		{name: "json fraction", file: `{"database": {"postgres": {"port": 5432.5}}}`, wantErr: []string{"database.postgres.port is not an integer"}},
		{name: "json out of range", file: `{"database": {"postgres": {"port": 1e20}}}`, wantErr: []string{"database.postgres.port is out of range"}},
		{name: "number 1 for a bool", file: "taildrop:\n  enabled: 1\nlogtail:\n  enabled: 1\n", check: func(t *testing.T, c *Config) {
			t.Helper()
			assert.True(t, c.Taildrop.Enabled)
			assert.True(t, c.LogTail.Enabled)
		}},
		{name: "number 0 for a bool", file: "taildrop:\n  enabled: 0\n", check: func(t *testing.T, c *Config) { t.Helper(); assert.False(t, c.Taildrop.Enabled) }},
		{name: "number 2 for a bool", file: "taildrop:\n  enabled: 2\n", wantErr: []string{"taildrop.enabled is not a boolean"}},
		{name: "env yes for a bool", env: []string{"HEADSCALE_TAILDROP_ENABLED=yes"}, wantErr: []string{"taildrop.enabled is not a boolean (env HEADSCALE_TAILDROP_ENABLED)"}},
		{name: "empty prefix is unset", file: "prefixes:\n  v4: \"\"\n", check: func(t *testing.T, c *Config) { t.Helper(); assert.Nil(t, c.Prefixes.V4) }},
		{name: "empty enum is unset", file: "log:\n  format: \"\"\n", check: func(t *testing.T, c *Config) { t.Helper(); assert.Empty(t, c.Log.Format) }},
		{name: "env json list", env: []string{`HEADSCALE_DNS_SEARCH_DOMAINS=["a","b"]`}, check: func(t *testing.T, c *Config) {
			t.Helper()
			assert.Equal(t, []string{"a", "b"}, c.DNSConfig.SearchDomains)
		}},
		{name: "env whitespace list", env: []string{"HEADSCALE_DNS_SEARCH_DOMAINS=a  b"}, check: func(t *testing.T, c *Config) {
			t.Helper()
			assert.Equal(t, []string{"a", "b"}, c.DNSConfig.SearchDomains)
		}},
		{name: "env map not json", env: []string{"HEADSCALE_DNS_NAMESERVERS_SPLIT=x=y"}, wantErr: []string{"dns.nameservers.split is not a JSON object (env HEADSCALE_DNS_NAMESERVERS_SPLIT)"}},
		{name: "level is case-insensitive", file: "log:\n  level: INFO\n", check: func(t *testing.T, c *Config) { t.Helper(); assert.Equal(t, LogLevel("info"), c.Log.Level) }},
		{name: "unknown extra record field", file: "dns:\n  extra_records:\n    - {name: a.example.com, type: A, value: 100.64.0.1, ttl: 60}\n", wantErr: []string{
			"dns.extra_records has invalid keys: ttl",
			`current: dns.extra_records: [{"name":"a.example.com","ttl":60,"type":"A","value":"100.64.0.1"}]`,
		}},
		{name: "empty duration", file: "node:\n  expiry: \"\"\n", wantErr: []string{"node.expiry is not a duration"}},
		{name: "empty integer", file: "database:\n  postgres:\n    port: \"\"\n", wantErr: []string{"database.postgres.port is not an integer"}},
		{name: "empty bool", file: "taildrop:\n  enabled: \"\"\n", wantErr: []string{"taildrop.enabled is not a boolean"}},
		{name: "empty string is a value", file: "server_url: \"\"\n", check: func(t *testing.T, c *Config) { t.Helper(); assert.Empty(t, c.ServerURL) }},
		{name: "env list not json", env: []string{"HEADSCALE_DNS_SEARCH_DOMAINS=[a"}, wantErr: []string{"dns.search_domains is not a JSON list", `hint: write the list as JSON, e.g. ["a", "b"]`}},
		{name: "dotted top-level key", file: "log.level: verbose\n", wantErr: []string{"log.level has an unsupported value (", "config.yaml:1:1)"}},
		{name: "nested then dotted key", file: "dns:\n  magic_dns: false\n  certificates.enabled: maybe\n", wantErr: []string{"dns.certificates.enabled is not a boolean (", "config.yaml:3:3)"}},
		{name: "dotted then nested key", file: "dns:\n  magic_dns: false\ndns.certificates:\n  enabled: maybe\n", wantErr: []string{"dns.certificates.enabled is not a boolean (", "config.yaml:4:3)"}},
		{name: "dotted inner list", file: "dns:\n  nameservers.global: 1\n", wantErr: []string{"dns.nameservers.global ", "config.yaml:2:3)"}},
		{name: "env extra records", env: []string{`HEADSCALE_DNS_EXTRA_RECORDS=[{"name":"a.example.com","type":"A","value":"100.64.0.1"}]`}, check: func(t *testing.T, c *Config) {
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
		require.NoError(t, LoadConfig(writeConfig(t, "log:\n  level: verbose\nnode:\n  expiry: 90\ntaildrop:\n  enabled: maybe\n"), true))

		_, err := LoadServerConfig()
		require.Error(t, err)

		got := reasons(ConfigErrors(err))
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
// so the defaults layer decodes back to defaultConfig.
func TestDefaultsFitTypes(t *testing.T) {
	d := defaultConfig()

	for _, f := range ConfigFields(&d) {
		e, ok := reflect.TypeAssert[interface{ Allowed() []string }](f.Value)
		if !ok {
			continue
		}

		v := f.Value.String()
		assert.Truef(t, v == "" || slices.Contains(e.Allowed(), v), "%s defaults to %q, not in %v", f.Path, v, e.Allowed())
	}

	cfg, err := decodeInput(t, "", "")
	require.NoError(t, err)

	if diff := gocmp.Diff(d, *cfg, cmpopts.IgnoreFields(Config{}, "ConfigDir"), cmpopts.IgnoreUnexported(Config{})); diff != "" {
		t.Errorf("defaults layer (-defaultConfig +decoded):\n%s", diff)
	}
}

func TestPlainMap(t *testing.T) {
	v4 := netip.MustParsePrefix("100.64.0.0/10")
	cfg := &Config{
		ServerURL:            "https://h",
		UnixSocketPermission: 0,
		TrustedProxies:       []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		Prefixes:             PrefixesConfig{V4: &v4},
		Node:                 NodeConfig{Expiry: 90 * time.Minute},
		DERP:                 DERPConfig{URLs: []HTTPURL{"https://user:pass@derp.example/map"}},
		Database:             DatabaseConfig{Postgres: PostgresConfig{Pass: "marker-pass"}},
		OIDC:                 OIDCConfig{ClientSecret: "file:/run/secret"},
		DNSConfig: DNSConfig{
			ExtraRecords: []tailcfg.DNSRecord{{Name: "a.example.com", Type: "A", Value: "100.64.0.1"}},
			Challenge: DNSChallengeConfig{ProviderSettings: map[string]any{ //nolint:gosec // test markers, not credentials
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
	assert.Equal(t, "1h30m0s", node["expiry"])

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
	assert.Equal(t, HTTPURL("https://user:pass@derp.example/map"), cfg.DERP.URLs[0])
	assert.Equal(t, HTTPURL("https://client:marker-issuer@idp.example.com/realm"), cfg.OIDC.Issuer)

	plainProvider, _ := plain["dns"].(map[string]any)["challenge"].(map[string]any)["provider"].(map[string]any)
	assert.NotContains(t, plainProvider, "unset", "a typed nil is left out")
	assert.NotContains(t, plainProvider, "nothing", "a typed nil is left out")
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
			require.NoError(t, LoadConfig(staged, false))

			_, err := LoadServerConfig()
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
