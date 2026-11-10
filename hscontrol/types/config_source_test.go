package types

import (
	"cmp"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, name, content string) string {
	t.Helper()

	p := filepath.Join(t.TempDir(), name)
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
		check     func(t *testing.T, s *configSource)
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
			check: func(t *testing.T, s *configSource) {
				t.Helper()
				assert.Equal(t, "debug", s.String("log.level"))
				assert.Equal(t, "/c", s.String("tls.cert_path"))
			},
		},
		{
			name: "keys are case-insensitive",
			file: "Server_URL: https://x\ndns:\n  Nameservers:\n    Split:\n      Corp.Example.com: [10.0.0.1]\n",
			check: func(t *testing.T, s *configSource) {
				t.Helper()
				assert.Equal(t, "https://x", s.String("server_url"))
				assert.Equal(t,
					map[string][]string{"corp.example.com": {"10.0.0.1"}},
					s.StringMapStringSlice("dns.nameservers.split"))
			},
		},
		{
			name: "null is unset, default stays",
			file: "server_url:\nlog:\n  level: ~\n",
			check: func(t *testing.T, s *configSource) {
				t.Helper()
				assert.False(t, s.IsSet("server_url"))
				assert.Equal(t, "info", s.String("log.level"))
			},
		},
		{
			name: "empty env is unset, env beats file",
			file: "server_url: http://file\nlisten_addr: 1.1.1.1:1\n",
			env:  []string{"HEADSCALE_SERVER_URL=http://env", "HEADSCALE_LISTEN_ADDR="},
			check: func(t *testing.T, s *configSource) {
				t.Helper()
				assert.Equal(t, "http://env", s.String("server_url"))
				assert.Equal(t, "1.1.1.1:1", s.String("listen_addr"))
			},
		},
		{
			name: "env lists and maps",
			env: []string{
				"HEADSCALE_DNS_NAMESERVERS_GLOBAL=1.1.1.1 8.8.8.8",
				`HEADSCALE_OIDC_EXTRA_PARAMS={"domain_hint":"example.com"}`,
			},
			check: func(t *testing.T, s *configSource) {
				t.Helper()
				assert.Equal(t, []string{"1.1.1.1", "8.8.8.8"}, s.StringSlice("dns.nameservers.global"))
				assert.Equal(t, map[string]string{"domain_hint": "example.com"}, s.StringMapString("oidc.extra_params"))
			},
		},
		{
			name: "open maps accept any key",
			file: "dns:\n  challenge:\n    provider:\n      name: cloudflare\n      whatever: 1\noidc:\n  extra_params:\n    a: b\n",
			check: func(t *testing.T, s *configSource) {
				t.Helper()
				assert.Equal(t, "cloudflare", s.String("dns.challenge.provider.name"))
				assert.Equal(t, 1, s.Int("dns.challenge.provider.whatever"))
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
			check: func(t *testing.T, s *configSource) {
				t.Helper()
				assert.Equal(t, "/n", s.String("noise.private_key_path"))
				assert.Equal(t, "/d", s.String("derp.server.private_key_path"))
				assert.Equal(t, "debug", s.String("log.level"))
				assert.Equal(t, "/c", s.String("tls.cert_path"))
				assert.Equal(t, "/db", s.String("database.sqlite.path"))
			},
		},
		{
			name: "dotted file keys override nested defaults",
			file: "log.level: debug\ndns.magic_dns: false\ndns:\n  nameservers.split:\n    Corp.Example.com: [10.0.0.1]\n",
			check: func(t *testing.T, s *configSource) {
				t.Helper()

				for range 50 {
					assert.Equal(t, "debug", s.String("log.level"))
					assert.False(t, s.Bool("dns.magic_dns"))
				}

				assert.Equal(t, map[string][]string{"corp.example.com": {"10.0.0.1"}}, s.StringMapStringSlice("dns.nameservers.split"))
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
			check: func(t *testing.T, s *configSource) {
				t.Helper()
				assert.Equal(t,
					map[string][]string{"123": {"1.1.1.1"}, "corp.example.com": {"10.0.0.1"}},
					s.StringMapStringSlice("dns.nameservers.split"))
			},
		},
		{
			name: "key arguments are case-insensitive",
			file: "server_url: https://x\n",
			check: func(t *testing.T, s *configSource) {
				t.Helper()
				assert.True(t, s.IsSet("Server_URL"))
				assert.Equal(t, "https://x", s.String("SERVER_URL"))
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
			check: func(t *testing.T, s *configSource) {
				t.Helper()
				assert.Equal(t, "info", s.String("log.level"))
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
				tt.check(t, s)
			}
		})
	}
}

const yamlSample = "server_url: https://x\nnode:\n  expiry: 1h\ndns:\n  magic_dns: false\n  nameservers:\n    global: [1.1.1.1, 8.8.8.8]\noidc:\n  extra_params:\n    domain_hint: example.com\n"

func checkSameValues(t *testing.T, s *configSource) {
	t.Helper()
	assert.Equal(t, "https://x", s.String("server_url"))
	assert.Equal(t, time.Hour, s.Duration("node.expiry"))
	assert.False(t, s.Bool("dns.magic_dns"))
	assert.Equal(t, []string{"1.1.1.1", "8.8.8.8"}, s.StringSlice("dns.nameservers.global"))
	assert.Equal(t, map[string]string{"domain_hint": "example.com"}, s.StringMapString("oidc.extra_params"))
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
	assert.Equal(t, "http://json", s.String("server_url"))

	s, err = newConfigSource(t.TempDir(), false, nil)
	require.NoError(t, err)
	assert.Empty(t, s.File())
}

func TestConfigSourceUnmarshalKey(t *testing.T) {
	type rec struct{ Name, Type, Value string }

	tests := []struct {
		name, file string
		want       []rec
	}{
		// An empty string decodes to an empty, non-nil slice.
		{"empty string", "dns:\n  extra_records: \"\"\n", []rec{}},
		{"list", "dns:\n  extra_records:\n    - {name: a.example.com, type: A, value: 1.2.3.4}\n", []rec{{"a.example.com", "A", "1.2.3.4"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := newConfigSource(writeConfig(t, "config.yaml", tt.file), true, nil)
			require.NoError(t, err)

			var got []rec

			require.NoError(t, s.UnmarshalKey("dns.extra_records", &got))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConfigKeysComplete(t *testing.T) {
	read := map[string]bool{}

	for _, f := range []string{"config.go", "listener.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
		require.NoError(t, err)

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}

			// Every src accessor takes the key first.
			fn, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}

			if obj, ok := fn.X.(*ast.Ident); !ok || obj.Name != "src" {
				return true
			}

			if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				key, err := strconv.Unquote(lit.Value)
				require.NoError(t, err)

				read[key] = true
			}

			return true
		})
	}

	all := slices.Concat(configKeys, openMapKeys)

	for key := range read {
		ok := slices.Contains(all, key) || strings.HasPrefix(key, "dns.challenge.provider")

		assert.Truef(t, ok, "%s is read but missing from the key tables", key)
	}

	for _, key := range configKeys {
		_, hasDefault := configDefaults[key]
		assert.Truef(t, read[key] || hasDefault, "%s is listed but never read", key)
	}

	for key := range configDefaults {
		assert.Contains(t, configKeys, key, "default without a key entry")
	}

	// Two keys sharing one environment variable would shadow each other.
	envs := map[string]string{}

	for _, key := range configKeys {
		name := configEnvName(key)
		assert.Emptyf(t, envs[name], "%s and %s share %s", envs[name], key, name)
		envs[name] = key
	}
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
		require.Equal(t, "debug", s.String("log.level"))
		require.False(t, s.Bool("dns.magic_dns"))
		require.Equal(t, []string{"1.1.1.1"}, s.StringSlice("dns.nameservers.global"))
	}
}

// TestConfigSourceDottedNoOverlap loads files whose dotted keys only share a
// string prefix: below an open map the entry name is one key, dots included.
func TestConfigSourceDottedNoOverlap(t *testing.T) {
	tests := []struct {
		name, file string
		check      func(t *testing.T, s *configSource)
	}{
		{
			name: "dotted split domains",
			file: "dns.nameservers.split.corp.example.com: [10.0.0.1]\ndns.nameservers.split.corp.example.com.au: [10.0.0.2]\n",
			check: func(t *testing.T, s *configSource) {
				t.Helper()
				assert.Equal(t,
					map[string][]string{"corp.example.com": {"10.0.0.1"}, "corp.example.com.au": {"10.0.0.2"}},
					s.StringMapStringSlice("dns.nameservers.split"))
			},
		},
		{
			name: "dotted extra params",
			file: "oidc.extra_params.domain_hint: a\noidc.extra_params.domain_hint.extra: b\n",
			check: func(t *testing.T, s *configSource) {
				t.Helper()
				assert.Equal(t, map[string]string{"domain_hint": "a", "domain_hint.extra": "b"}, s.StringMapString("oidc.extra_params"))
			},
		},
		{
			name: "nested split domains",
			file: "dns:\n  nameservers:\n    split:\n      corp.example.com: [10.0.0.1]\n      corp.example.com.au: [10.0.0.2]\n",
			check: func(t *testing.T, s *configSource) {
				t.Helper()
				assert.Equal(t,
					map[string][]string{"corp.example.com": {"10.0.0.1"}, "corp.example.com.au": {"10.0.0.2"}},
					s.StringMapStringSlice("dns.nameservers.split"))
			},
		},
		{
			name: "log and logtail",
			file: "log:\n  level: debug\nlog.format: json\nlogtail.enabled: true\n",
			check: func(t *testing.T, s *configSource) {
				t.Helper()
				assert.Equal(t, "debug", s.String("log.level"))
				assert.Equal(t, "json", s.String("log.format"))
				assert.True(t, s.Bool("logtail.enabled"))
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
				tt.check(t, s)
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
			_, err := newConfigSource(writeConfig(t, "config.yaml", file), true, nil)
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

	assert.Equal(t, "cloudflare", s.String("dns.challenge.provider.name"))

	// The env value replaces the file's map; the per-field
	// variable is layered on top of it.
	got := s.StringMap("dns.challenge.provider")
	assert.Equal(t, "x", got["api_token"])
	assert.NotContains(t, got, "other")
}
