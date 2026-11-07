package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	hsdns "github.com/juanfont/headscale/hscontrol/dns"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
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

func TestReadConfig(t *testing.T) {
	tests := []struct {
		name       string
		configPath string
		setup      func(*testing.T) (any, error)
		want       any
		wantErr    string
	}{
		{
			name:       "unmarshal-dns-full-config",
			configPath: "testdata/dns_full.yaml",
			setup: func(t *testing.T) (any, error) { //nolint:thelper
				dns, err := dns()
				if err != nil {
					return nil, err
				}

				return dns, nil
			},
			want: DNSConfig{
				MagicDNS:         true,
				BaseDomain:       "example.com",
				OverrideLocalDNS: false,
				Nameservers: Nameservers{
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
			},
		},
		{
			name:       "dns-to-tailcfg.DNSConfig",
			configPath: "testdata/dns_full.yaml",
			setup: func(t *testing.T) (any, error) { //nolint:thelper
				dns, err := dns()
				if err != nil {
					return nil, err
				}

				return dnsToTailcfgDNS(dns), nil
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
			setup: func(t *testing.T) (any, error) { //nolint:thelper
				dns, err := dns()
				if err != nil {
					return nil, err
				}

				return dns, nil
			},
			want: DNSConfig{
				MagicDNS:         false,
				BaseDomain:       "example.com",
				OverrideLocalDNS: false,
				Nameservers: Nameservers{
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
			},
		},
		{
			name:       "dns-to-tailcfg.DNSConfig",
			configPath: "testdata/dns_full_no_magic.yaml",
			setup: func(t *testing.T) (any, error) { //nolint:thelper
				dns, err := dns()
				if err != nil {
					return nil, err
				}

				return dnsToTailcfgDNS(dns), nil
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
			setup: func(t *testing.T) (any, error) { //nolint:thelper
				return LoadServerConfig()
			},
			want:    nil,
			wantErr: "server_url is a subdomain of dns.base_domain",
		},
		{
			name:       "base-domain-not-in-server-url",
			configPath: "testdata/base-domain-not-in-server-url.yaml",
			setup: func(t *testing.T) (any, error) { //nolint:thelper
				cfg, err := LoadServerConfig()
				if err != nil {
					return nil, err
				}

				return map[string]string{
					"server_url":  cfg.ServerURL,
					"base_domain": cfg.BaseDomain,
				}, err
			},
			want: map[string]string{
				"server_url":  "https://derp.no",
				"base_domain": "clients.derp.no",
			},
			wantErr: "",
		},
		{
			name:       "dns-override-true-errors",
			configPath: "testdata/dns-override-true-error.yaml",
			setup: func(t *testing.T) (any, error) { //nolint:thelper
				return LoadServerConfig()
			},
			wantErr: "Fatal config error: dns.nameservers.global is required when dns.override_local_dns is true",
		},
		{
			name:       "dns-override-true",
			configPath: "testdata/dns-override-true.yaml",
			setup: func(t *testing.T) (any, error) { //nolint:thelper
				_, err := LoadServerConfig()
				if err != nil {
					return nil, err
				}

				dns, err := dns()
				if err != nil {
					return nil, err
				}

				return dnsToTailcfgDNS(dns), nil
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
			setup: func(t *testing.T) (any, error) { //nolint:thelper // inline test closure
				cfg, err := LoadServerConfig()
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
			err := LoadConfig(tt.configPath, true)
			require.NoError(t, err)

			conf, err := tt.setup(t)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)

				return
			}

			require.NoError(t, err)

			if diff := cmp.Diff(tt.want, conf); diff != "" {
				t.Errorf("ReadConfig() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestReadConfigFromEnv(t *testing.T) {
	tests := []struct {
		name      string
		configEnv map[string]string
		setup     func(*testing.T) (any, error)
		want      any
	}{
		{
			name: "test-random-base-settings-with-env",
			configEnv: map[string]string{
				"HEADSCALE_LOG_LEVEL":                       "trace",
				"HEADSCALE_DATABASE_SQLITE_WRITE_AHEAD_LOG": "false",
				"HEADSCALE_PREFIXES_V4":                     "100.64.0.0/10",
			},
			setup: func(t *testing.T) (any, error) { //nolint:thelper // inline test closure
				assert.Equal(t, "trace", src.String("log.level"))
				assert.Equal(t, "100.64.0.0/10", src.String("prefixes.v4"))
				assert.False(t, src.Bool("database.sqlite.write_ahead_log"))

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
			setup: func(t *testing.T) (any, error) { //nolint:thelper // inline test closure
				dns, err := dns()
				if err != nil {
					return nil, err
				}

				return dns, nil
			},
			want: DNSConfig{
				MagicDNS:         true,
				BaseDomain:       "example.com",
				OverrideLocalDNS: false,
				Nameservers: Nameservers{
					Global: []string{"1.1.1.1", "8.8.8.8"},
					Split:  map[string][]string{
						// "foo.bar.com": {"1.1.1.1"},
					},
				},
				// ExtraRecords: []tailcfg.DNSRecord{
				// 	{Name: "prometheus.myvpn.example.com", Type: "A", Value: "100.64.0.4"},
				// },
				SearchDomains: []string{"test.com", "bar.com"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.configEnv {
				t.Setenv(k, v)
			}

			err := LoadConfig("testdata/minimal.yaml", true)
			require.NoError(t, err)

			conf, err := tt.setup(t)
			require.NoError(t, err)

			if diff := cmp.Diff(tt.want, conf, cmpopts.EquateEmpty()); diff != "" {
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
    challenge_type: bogus
noise:
  private_key_path: noise_private.key`)

	// Populate a custom config file
	configFilePath := filepath.Join(tmpDir, "config.yaml")

	err = os.WriteFile(configFilePath, configYaml, 0o600)
	if err != nil {
		t.Fatalf("Couldn't write file %s", configFilePath)
	}

	// Check configuration validation errors (1)
	err = LoadConfig(tmpDir, false)
	require.NoError(t, err)

	err = validateServerConfig()
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
		"Fatal config error: server_url is missing a scheme",
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

	err = LoadConfig(tmpDir, false)
	require.NoError(t, err)
}

func TestPKCEMethodValidation(t *testing.T) {
	tmpDir := t.TempDir()

	// OIDC is active (issuer set) with PKCE enabled and an invalid method.
	// There is no oidc.enabled key. validateServerConfig must reject the
	// invalid method rather than silently skipping the check.
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

	err = LoadConfig(tmpDir, false)
	require.NoError(t, err)

	err = validateServerConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), errInvalidPKCEMethod.Error())
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
			wantErr: "valid http(s) URL",
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
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
oidc:` + tt.oidcBlock + "\n")

			require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "config.yaml"), configYaml, 0o600))
			require.NoError(t, LoadConfig(tmpDir, false))

			err := validateServerConfig()
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
database:
  type: sqlite3
dns:
  magic_dns: false
  override_local_dns: false
`, tt.listenAddr, tt.hostname, tt.challengeType, tt.acmeListen)
			require.NoError(t, os.WriteFile(
				filepath.Join(tmpDir, "config.yaml"), []byte(cfg), 0o600))
			require.NoError(t, LoadConfig(tmpDir, false))

			err := validateServerConfig()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestLoadServerConfig_CollectsAcrossSubBuilders(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := `---
server_url: https://example.com
listen_addr: 0.0.0.0:8080
prefixes:
  v4: not-a-cidr
  v6: also-not-a-cidr
  allocation: bogus
oidc:
  issuer: https://idp.example.com
  client_id: headscale
  client_secret: file:/nonexistent/secret
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
	require.NoError(t, LoadConfig(tmpDir, false))

	_, err := LoadServerConfig()
	require.Error(t, err)

	got := ConfigErrors(err)
	assert.GreaterOrEqual(t, len(got), 4,
		"expected sub-builder errors collected into one report; got %d: %v",
		len(got), reasons(got))

	// Sentinels stay reachable through ConfigError.Cause.
	require.ErrorIs(t, err, ErrInvalidAllocationStrategy,
		"wrapped ErrInvalidAllocationStrategy not in chain")
	require.ErrorIs(t, err, os.ErrNotExist,
		"wrapped secret read error not in chain")

	// Each sub-builder failure surfaces its YAML key in the rendered output.
	rendered := err.Error()
	for _, want := range []string{
		"prefixes.v4",
		"prefixes.v6",
		"prefixes.allocation",
		"oidc.client_secret",
	} {
		assert.Contains(t, rendered, want,
			"expected rendered error to mention %q", want)
	}
}

func reasons(errs []*ConfigError) []string {
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
		serverErr string   // from LoadServerConfig after a clean load
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

			err := LoadConfig(dir, false)
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

			warnings := strings.Join(src.Warnings(), "\n")
			assert.NotContains(t, warnings, "/run/secret")

			if len(tt.warns) == 0 {
				assert.NotContains(t, warnings, "was removed")
			}

			for _, w := range tt.warns {
				assert.Contains(t, warnings, w)
			}

			if tt.serverErr != "" {
				_, err := LoadServerConfig()
				require.ErrorContains(t, err, tt.serverErr)
			}
		})
	}
}

// TestConfigSecrets pins that the secret settings take a value or file:<path>,
// read only by the consumer that uses the secret.
func TestConfigSecrets(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"oidc", "pg", "api"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(name+"-from-file\n"), 0o600))
	}

	require.NoError(t, os.WriteFile(filepath.Join(dir, "empty"), []byte(" \n"), 0o600))

	missing := "file:" + filepath.Join(dir, "missing")

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
oidc:
  issuer: https://idp.example.com
  client_id: headscale
`
	// Postgres and a remote CLI are the consumers of the other two secrets.
	active := map[string]string{
		"HEADSCALE_DATABASE_TYPE": "postgres",
		"HEADSCALE_CLI_ADDRESS":   "headscale.example.com:443",
	}

	tests := []struct {
		name       string
		yaml       string
		env        map[string]string
		want       [3]string // server oidc.client_secret, server database.postgres.pass, CLI cli.api_key
		wantErr    string    // from LoadServerConfig
		wantCLIErr string
	}{
		{
			name: "literal values",
			yaml: base + "  client_secret: oidc\n",
			env:  map[string]string{"HEADSCALE_DATABASE_POSTGRES_PASS": "pg", "HEADSCALE_CLI_API_KEY": "api"},
			want: [3]string{"oidc", "pg", "api"},
		},
		{
			name: "file values for active consumers",
			yaml: base + "  client_secret: file:" + filepath.Join(dir, "oidc") + "\n",
			//nolint:gosec // paths to test files, not credentials
			env: map[string]string{
				"HEADSCALE_DATABASE_TYPE":          active["HEADSCALE_DATABASE_TYPE"],
				"HEADSCALE_CLI_ADDRESS":            active["HEADSCALE_CLI_ADDRESS"],
				"SECRET_DIR":                       dir,
				"HEADSCALE_DATABASE_POSTGRES_PASS": "file:$SECRET_DIR/pg",
				"HEADSCALE_CLI_API_KEY":            "file:${SECRET_DIR}/api",
			},
			want: [3]string{"oidc-from-file", "pg-from-file", "api-from-file"},
		},
		{
			// sqlite and the unix socket use neither secret.
			name: "inactive consumers read nothing",
			yaml: base + "  client_secret: oidc\n",
			env:  map[string]string{"HEADSCALE_DATABASE_POSTGRES_PASS": missing, "HEADSCALE_CLI_API_KEY": missing},
			want: [3]string{"oidc", missing, missing},
		},
		{
			// OIDC is active only with an issuer.
			name: "inactive oidc reads nothing",
			yaml: strings.Replace(base, "  issuer: https://idp.example.com\n", "", 1) + "  client_secret: " + missing + "\n",
			want: [3]string{missing, "", ""},
		},
		{
			name:    "missing oidc file",
			yaml:    base + "  client_secret: " + missing + "\n",
			wantErr: "oidc.client_secret cannot be read",
		},
		{
			name:    "empty oidc file",
			yaml:    base + "  client_secret: file:" + filepath.Join(dir, "empty") + "\n",
			wantErr: "oidc.client_secret",
		},
		{
			name: "missing postgres file",
			yaml: base + "  client_secret: oidc\n",
			env: map[string]string{
				"HEADSCALE_DATABASE_TYPE":          active["HEADSCALE_DATABASE_TYPE"],
				"HEADSCALE_DATABASE_POSTGRES_PASS": missing,
			},
			wantErr: "database.postgres.pass cannot be read",
		},
		{
			name: "missing api key file for a remote CLI",
			yaml: base + "  client_secret: oidc\n",
			env: map[string]string{
				"HEADSCALE_CLI_ADDRESS": active["HEADSCALE_CLI_ADDRESS"],
				"HEADSCALE_CLI_API_KEY": missing,
			},
			wantCLIErr: "cli.api_key cannot be read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			tmpDir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "config.yaml"), []byte(tt.yaml), 0o600))
			require.NoError(t, LoadConfig(tmpDir, false))

			cfg, err := LoadServerConfig()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)

			// The server never uses the CLI's key, so never reads it.
			assert.Empty(t, cfg.CLI.APIKey)

			cli, err := LoadCLIConfig()
			if tt.wantCLIErr != "" {
				require.ErrorContains(t, err, tt.wantCLIErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, [3]string{cfg.OIDC.ClientSecret, cfg.Database.Postgres.Pass, cli.CLI.APIKey})
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
		want    fs.FileMode
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
			require.NoError(t, LoadConfig(tmpDir, false))

			got, err := LoadServerConfig()
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
			useConfig(t, map[string]any{
				"server_url":             tt.input,
				"noise.private_key_path": "private_key.pem",
				"prefixes.v4":            "100.64.0.0/10",
				"database.type":          "sqlite3",
				"dns.magic_dns":          false,
				"dns.override_local_dns": false,
			})

			cfg, err := LoadServerConfig()
			require.NoError(t, err)
			assert.Equal(t, tt.want, cfg.ServerURL)
		})
	}
}

// OK
// server_url: headscale.com, base: clients.headscale.com
// server_url: headscale.com, base: headscale.net
//
// NOT OK
// server_url: server.headscale.com, base: headscale.com.
func TestSafeServerURL(t *testing.T) {
	tests := []struct {
		serverURL, baseDomain,
		wantErr string
	}{
		{
			serverURL:  "https://example.com",
			baseDomain: "example.org",
		},
		{
			serverURL:  "https://headscale.com",
			baseDomain: "headscale.com",
			wantErr:    errServerURLSame.Error(),
		},
		{
			serverURL:  "https://headscale.com",
			baseDomain: "clients.headscale.com",
		},
		{
			serverURL:  "https://headscale.com",
			baseDomain: "clients.subdomain.headscale.com",
		},
		{
			serverURL:  "https://headscale.kristoffer.com",
			baseDomain: "mybase",
		},
		{
			serverURL:  "https://server.headscale.com",
			baseDomain: "headscale.com",
			wantErr:    errServerURLSuffix.Error(),
		},
		{
			serverURL:  "https://server.subdomain.headscale.com",
			baseDomain: "headscale.com",
			wantErr:    errServerURLSuffix.Error(),
		},
		{
			serverURL: "http://foo\x00",
			wantErr:   `parse "http://foo\x00": net/url: invalid control character in URL`,
		},
	}

	for _, tt := range tests {
		testName := fmt.Sprintf("server=%s domain=%s", tt.serverURL, tt.baseDomain)
		t.Run(testName, func(t *testing.T) {
			err := isSafeServerURL(tt.serverURL, tt.baseDomain)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)

				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestSafeServerURLWithPort(t *testing.T) {
	tests := []struct {
		serverURL, baseDomain,
		wantErr string
	}{
		{
			serverURL:  "https://server.headscale.com:443",
			baseDomain: "headscale.com",
			wantErr:    errServerURLSuffix.Error(),
		},
		{
			serverURL:  "https://server.subdomain.headscale.com:8080",
			baseDomain: "headscale.com",
			wantErr:    errServerURLSuffix.Error(),
		},
		{
			serverURL:  "https://headscale.com:443",
			baseDomain: "headscale.com",
			wantErr:    errServerURLSame.Error(),
		},
		{
			serverURL:  "https://example.com:8080",
			baseDomain: "example.org",
		},
	}

	for _, tt := range tests {
		testName := fmt.Sprintf("server=%s domain=%s", tt.serverURL, tt.baseDomain)
		t.Run(testName, func(t *testing.T) {
			err := isSafeServerURL(tt.serverURL, tt.baseDomain)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)

				return
			}

			assert.NoError(t, err)
		})
	}
}

// TestConfigJSONOmitsSecrets verifies that marshalling a [Config] to JSON
// (as /debug/config does via [state.State.DebugConfig]) does not leak the
// Postgres password, the OIDC client secret, or the headscale admin
// API key. Operators who widen metrics_listen_addr to 0.0.0.0 should
// not be able to read these back via debug endpoints reachable over
// CGNAT/loopback.
func TestConfigJSONOmitsSecrets(t *testing.T) {
	const (
		secretPostgresPass = "p0stgres-secret-marker"
		secretClientSecret = "oidc-client-secret-marker"    //nolint:gosec // test marker, not a real credential
		secretAPIKey       = "headscale-cli-api-key-marker" //nolint:gosec // test marker, not a real credential
		secretDNSToken     = "dns-provider-token-marker"    //nolint:gosec // test marker, not a real credential
	)

	cfg := &Config{
		Database: DatabaseConfig{
			Postgres: PostgresConfig{
				Pass: secretPostgresPass,
			},
		},
		OIDC: OIDCConfig{
			ClientSecret: secretClientSecret,
		},
		CLI: CLIConfig{
			APIKey: secretAPIKey,
		},
		DNSChallenge: DNSChallengeConfig{
			ProviderSettings: map[string]any{"name": "cloudflare", "api_token": secretDNSToken},
			Provider:         &cloudflare.Provider{APIToken: secretDNSToken},
		},
	}

	out, err := json.Marshal(cfg)
	require.NoError(t, err)

	body := string(out)
	for _, secret := range []string{secretPostgresPass, secretClientSecret, secretAPIKey, secretDNSToken} {
		assert.NotContains(t, body, secret,
			"marshalled Config must not contain secret %q", secret)
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
			wantErr: `trusted_proxies[0] "10.0.0.1"`,
		},
		{
			name:    "garbage-reports-index",
			input:   []string{"10.0.0.0/16", "not-an-ip"},
			wantErr: `trusted_proxies[1] "not-an-ip"`,
		},
		{
			name:    "ipv4-zero-rejected",
			input:   []string{"0.0.0.0/0"},
			wantErr: "0.0.0.0/0 and ::/0 are not allowed",
		},
		{
			name:    "ipv6-zero-rejected",
			input:   []string{"::/0"},
			wantErr: "0.0.0.0/0 and ::/0 are not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values := map[string]any{}
			if tt.input != nil {
				values["trusted_proxies"] = tt.input
			}

			useConfig(t, values)

			got, err := trustedProxies()

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)

				return
			}

			require.NoError(t, err)

			if diff := cmp.Diff(tt.want, got, cmpopts.EquateComparable(netip.Prefix{})); diff != "" {
				t.Errorf("trustedProxies() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// DNS names are case-insensitive, but MagicDNS resolution in clients matches
// extra records by exact name, so mixed-case record names never resolve.
func TestExtraRecordsAreLowercased(t *testing.T) {
	mixed := []tailcfg.DNSRecord{
		{Name: "Printer.fritz.box", Type: "A", Value: "192.168.1.2"},
		{Name: "NAS.FRITZ.BOX", Type: "A", Value: "192.168.1.3"},
	}
	want := []tailcfg.DNSRecord{
		{Name: "printer.fritz.box", Type: "A", Value: "192.168.1.2"},
		{Name: "nas.fritz.box", Type: "A", Value: "192.168.1.3"},
	}

	tcfg := dnsToTailcfgDNS(DNSConfig{
		MagicDNS:     true,
		BaseDomain:   "example.com",
		ExtraRecords: mixed,
	})
	if diff := cmp.Diff(want, tcfg.ExtraRecords); diff != "" {
		t.Errorf("dnsToTailcfgDNS extra records mismatch (-want +got):\n%s", diff)
	}

	cfg := &Config{}
	cfg.StartDNS(nil)
	cfg.SetExtraRecords(mixed)

	if diff := cmp.Diff(want, cfg.CloneTailcfgDNSConfig().ExtraRecords); diff != "" {
		t.Errorf("SetExtraRecords mismatch (-want +got):\n%s", diff)
	}
}

func TestTailcfgDNSConfig(t *testing.T) {
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	ten := netip.MustParsePrefix("10.0.0.0/8")
	ula := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	fd00 := netip.MustParsePrefix("fd00::/48")

	tests := []struct {
		name string
		cfg  Config
		want *tailcfg.DNSConfig
	}{
		{
			name: "empty",
			want: &tailcfg.DNSConfig{Routes: map[string][]*dnstype.Resolver{}},
		},
		{
			name: "magic dns with base domain",
			cfg:  Config{DNSConfig: DNSConfig{MagicDNS: true, BaseDomain: "example.com", SearchDomains: []string{"corp.com"}}},
			want: &tailcfg.DNSConfig{
				Proxied: true,
				Domains: []string{"example.com", "corp.com"},
				Routes:  map[string][]*dnstype.Resolver{},
			},
		},
		{
			name: "override local dns",
			cfg:  Config{DNSConfig: DNSConfig{OverrideLocalDNS: true, Nameservers: Nameservers{Global: []string{"1.1.1.1"}}}},
			want: &tailcfg.DNSConfig{
				Resolvers: []*dnstype.Resolver{{Addr: "1.1.1.1"}},
				Routes:    map[string][]*dnstype.Resolver{},
			},
		},
		{
			name: "fallback resolvers",
			cfg:  Config{DNSConfig: DNSConfig{Nameservers: Nameservers{Global: []string{"1.1.1.1"}}}},
			want: &tailcfg.DNSConfig{
				FallbackResolvers: []*dnstype.Resolver{{Addr: "1.1.1.1"}},
				Routes:            map[string][]*dnstype.Resolver{},
			},
		},
		{
			name: "split dns",
			cfg:  Config{DNSConfig: DNSConfig{Nameservers: Nameservers{Split: map[string][]string{"corp.com": {"10.0.0.1"}}}}},
			want: &tailcfg.DNSConfig{
				Routes: map[string][]*dnstype.Resolver{"corp.com": {{Addr: "10.0.0.1"}}},
			},
		},
		{
			name: "magic dns reverse routes outside cgnat",
			cfg: Config{
				PrefixV4:  &ten,
				DNSConfig: DNSConfig{MagicDNS: true, BaseDomain: "example.com"},
			},
			want: &tailcfg.DNSConfig{
				Proxied: true,
				Domains: []string{"example.com"},
				Routes:  map[string][]*dnstype.Resolver{"10.in-addr.arpa": {}},
			},
		},
		{
			name: "magic dns reverse routes outside ula",
			cfg: Config{
				PrefixV6:  &fd00,
				DNSConfig: DNSConfig{MagicDNS: true, BaseDomain: "example.com"},
			},
			want: &tailcfg.DNSConfig{
				Proxied: true,
				Domains: []string{"example.com"},
				Routes:  map[string][]*dnstype.Resolver{"0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa": {}},
			},
		},
		{
			name: "magic dns inside cgnat and ula",
			cfg: Config{
				PrefixV4:  &cgnat,
				PrefixV6:  &ula,
				DNSConfig: DNSConfig{MagicDNS: true, BaseDomain: "example.com"},
			},
			want: &tailcfg.DNSConfig{
				Proxied: true,
				Domains: []string{"example.com"},
				Routes:  map[string][]*dnstype.Resolver{},
			},
		},
		{
			name: "no reverse routes without magic dns",
			cfg:  Config{PrefixV4: &ten},
			want: &tailcfg.DNSConfig{Routes: map[string][]*dnstype.Resolver{}},
		},
		{
			name: "extra record names lowercased",
			cfg: Config{DNSConfig: DNSConfig{ExtraRecords: []tailcfg.DNSRecord{
				{Name: "Grafana.Example.com", Type: "A", Value: "100.64.0.3"},
			}}},
			want: &tailcfg.DNSConfig{
				Routes:       map[string][]*dnstype.Resolver{},
				ExtraRecords: []tailcfg.DNSRecord{{Name: "grafana.example.com", Type: "A", Value: "100.64.0.3"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// No EquateEmpty: a reverse route must be an empty, non-nil slice.
			if diff := cmp.Diff(tt.want, tt.cfg.TailcfgDNSConfig()); diff != "" {
				t.Errorf("TailcfgDNSConfig() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLiveDNS(t *testing.T) {
	goOnly := &cloudflare.Provider{APIToken: "go-only"}
	cfg := &Config{
		DNSConfig: DNSConfig{
			MagicDNS:     true,
			BaseDomain:   "example.com",
			ExtraRecords: []tailcfg.DNSRecord{{Name: "Old.example.com", Type: "A", Value: "100.64.0.1"}},
		},
		DNSChallenge: DNSChallengeConfig{Provider: goOnly},
	}

	assert.Equal(t, cfg.TailcfgDNSConfig(), cfg.CloneTailcfgDNSConfig())
	assert.Same(t, goOnly, cfg.DNSProvider())
	assert.True(t, cfg.HasExtraRecord("old.example.com."))

	// Nothing holds the records before StartDNS.
	cfg.SetExtraRecords([]tailcfg.DNSRecord{{Name: "early.example.com", Type: "A", Value: "100.64.0.9"}})
	assert.False(t, cfg.HasExtraRecord("early.example.com"))
	assert.Equal(t, cfg.DNSConfig.ExtraRecords[0].Value, cfg.CloneTailcfgDNSConfig().ExtraRecords[0].Value)

	started := &cloudflare.Provider{APIToken: "started"}
	cfg.StartDNS(started)
	cfg.SetExtraRecords([]tailcfg.DNSRecord{{Name: "A.Example.com", Type: "A", Value: "100.64.0.2"}})

	clone := cfg.CloneTailcfgDNSConfig()
	assert.Equal(t, []tailcfg.DNSRecord{{Name: "a.example.com", Type: "A", Value: "100.64.0.2"}}, clone.ExtraRecords)
	assert.True(t, cfg.HasExtraRecord("A.Example.com."))
	assert.False(t, cfg.HasExtraRecord("old.example.com"))
	assert.Same(t, started, cfg.DNSProvider())

	clone.ExtraRecords = nil

	assert.Len(t, cfg.CloneTailcfgDNSConfig().ExtraRecords, 1, "a clone is a copy")
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
	require.NoError(t, LoadConfig(dir, false))

	var buf bytes.Buffer

	oldLogger, oldLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(&buf)

	t.Cleanup(func() {
		log.Logger = oldLogger

		zerolog.SetGlobalLevel(oldLevel)
	})

	cfg, err := CheckServerConfig()
	require.NoError(t, err)

	logged := buf.String()
	assert.Contains(t, logged, `invalid nameserver \"1.1.1.1:53\" in dns.nameservers.global, ignoring`)
	assert.Contains(t, logged, `invalid nameserver \"[2606:4700::1111]:53\" in dns.nameservers.split.corp.example.com, ignoring`)
	assert.NotContains(t, logged, `\"1.1.1.1\" in`)

	buf.Reset()
	cfg.StartDNS(nil)

	assert.Equal(t, []*dnstype.Resolver{{Addr: "1.1.1.1"}}, cfg.CloneTailcfgDNSConfig().Resolvers)
	assert.Empty(t, buf.String(), "built once, reported once: by the load")
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
		fileErr       bool // only reading a file: secret fails, so CheckServerConfig passes
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
			wantResolvers: []string{"1.1.1.1:53", "8.8.8.8:53"},
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
			// Unread by CheckServerConfig, a file: setting counts as present.
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
			// A failed decode can still fill part of the map; none of it is used.
			name: "provider env json that does not decode",
			yaml: base,
			env: map[string]string{
				"HEADSCALE_DNS_CHALLENGE_PROVIDER_NAME": "cloudflare",
				"HEADSCALE_DNS_CHALLENGE_PROVIDER":      `{"api_token":"marker-token","zone_token":1e1000}`,
			},
			wantErr: "dns.challenge.provider is invalid",
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
			require.NoError(t, LoadConfig(tmpDir, false))
			require.Len(t, src.Warnings(), len(tt.wantWarns))

			for i, w := range tt.wantWarns {
				assert.Contains(t, src.Warnings()[i], w)
			}

			_, checkErr := CheckServerConfig()
			if tt.wantErr != "" && !tt.fileErr {
				require.ErrorContains(t, checkErr, tt.wantErr)
				assert.NotContains(t, checkErr.Error(), "marker-")
			} else {
				require.NoError(t, checkErr)
			}

			cfg, err := LoadServerConfig()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantZone, cfg.DNSConfig.CertificateZone())

			if tt.wantResolvers != nil {
				assert.Equal(t, tt.wantResolvers, cfg.DNSChallenge.ResolverAddrs())
			}

			// The loader only validates the provider; startup builds it.
			assert.Nil(t, cfg.DNSChallenge.Provider)

			if tt.wantNoProv {
				assert.Empty(t, cfg.DNSChallenge.ProviderName())

				return
			}

			built, err := cfg.DNSChallenge.NewProvider(ResolveSecret)
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
		want    TLSConfig
		wantErr []string
	}{
		{
			name: "defaults",
			yaml: base,
			want: TLSConfig{ACME: ACMEConfig{
				ChallengeType: HTTP01ChallengeType,
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
			want: TLSConfig{
				CertPath: "/env/cert.pem",
				KeyPath:  "/env/key.pem",
				ACME: ACMEConfig{
					ChallengeType: HTTP01ChallengeType,
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

			err := LoadConfig(tmpDir, false)

			if tt.wantErr != nil {
				for _, want := range tt.wantErr {
					require.ErrorContains(t, err, want)
				}

				return
			}

			require.NoError(t, err)

			cfg, err := LoadServerConfig()
			require.NoError(t, err)
			assert.Equal(t, tt.want, cfg.TLS)
		})
	}
}

func TestPostgresConfigDSN(t *testing.T) {
	tests := []struct {
		name string
		cfg  PostgresConfig
		host string
		port string
		user string
		pass string
		path string
		want map[string]string // expected query parameters
	}{
		//nolint:gosec // test fixture, not a credential
		{
			name: "ssl false disables sslmode",
			cfg: PostgresConfig{
				Host: "localhost",
				Port: 5432,
				Name: "headscale",
				User: "hs",
				Pass: "secret",
				Ssl:  "false",
			},
			host: "localhost", port: "5432", user: "hs", pass: "secret", path: "/headscale",
			want: map[string]string{"sslmode": "disable"},
		},
		{
			name: "ssl true leaves the driver default",
			cfg:  PostgresConfig{Host: "db", Name: "headscale", User: "hs", Ssl: "true"},
			host: "db", user: "hs", path: "/headscale",
			want: map[string]string{},
		},
		{
			name: "raw sslmode is passed through",
			cfg:  PostgresConfig{Host: "db", Name: "headscale", User: "hs", Ssl: "verify-full"},
			host: "db", user: "hs", path: "/headscale",
			want: map[string]string{"sslmode": "verify-full"},
		},
		// Regression: the DSN used to be concatenated, so a space, quote
		// or backslash in the password truncated it or injected parameters.
		//nolint:gosec // test fixture, not a credential
		{
			name: "password with reserved characters survives a round trip",
			cfg: PostgresConfig{
				Host: "db",
				Name: "head scale",
				User: "h's",
				Pass: `p a'ss\w sslmode=disable #?&@`,
			},
			host: "db", user: "h's", pass: `p a'ss\w sslmode=disable #?&@`, path: "/head scale",
			want: map[string]string{},
		},
		{
			name: "unix socket directory goes in the host parameter",
			cfg: PostgresConfig{
				Host: "/var/run/postgresql",
				Port: 5433,
				Name: "headscale",
				User: "hs",
			},
			user: "hs", path: "/headscale",
			want: map[string]string{"host": "/var/run/postgresql", "port": "5433"},
		},
		{
			name: "ipv6 host is bracketed",
			cfg:  PostgresConfig{Host: "::1", Port: 5432, Name: "headscale", User: "hs"},
			host: "::1", port: "5432", user: "hs", path: "/headscale",
			want: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.cfg.DSN())
			require.NoError(t, err)

			assert.Equal(t, "postgres", u.Scheme)
			assert.Equal(t, tt.host, u.Hostname())
			assert.Equal(t, tt.port, u.Port())
			assert.Equal(t, tt.user, u.User.Username())
			assert.Equal(t, tt.path, u.Path)

			pass, _ := u.User.Password()
			assert.Equal(t, tt.pass, pass)

			query := u.Query()
			assert.Len(t, query, len(tt.want))

			for k, v := range tt.want {
				assert.Equal(t, v, query.Get(k), k)
			}
		})
	}
}

func TestServesRoute(t *testing.T) {
	v4 := netip.MustParsePrefix("100.64.0.0/10")
	v6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &Config{PrefixV4: &v4, PrefixV6: &v6}

	for route, want := range map[string]bool{
		"100.64.0.11/32":                   false,
		"fd7a:115c:a1e0::b/128":            false,
		"::ffff:100.64.0.11/128":           false,
		"100.64.1.2/31":                    true,
		"100.64.2.0/24":                    true,
		"fd7a:115c:a1e0::1:2/127":          true,
		"fd7a:115c:a1e0::2:0/120":          true,
		"::ffff:100.64.0.0/112":            true,
		"100.64.0.8/29":                    true,
		"0.0.0.0/1":                        true,
		"0.0.0.0/0":                        true,
		"10.9.0.1/32":                      true,
		"::ffff:10.9.0.1/128":              true,
		"fd00::1/128":                      true,
		"fd7a:115c:a1e0:b1a:0:7:a09:5/128": true,
	} {
		assert.Equalf(t, want, cfg.ServesRoute(netip.MustParsePrefix(route)), "%s", route)
	}

	// Only the configured ranges hold nodes.
	narrow := netip.MustParsePrefix("100.64.0.0/24")
	assert.True(t, (&Config{PrefixV4: &narrow}).ServesRoute(netip.MustParsePrefix("100.100.0.1/32")))
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
				require.NoError(t, LoadConfig(path, true))

				loaded, err := LoadServerConfig()
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
// as the CLI config does, for DumpConfig and embedders.
func TestServerConfigDisableUpdateCheck(t *testing.T) {
	for _, want := range []bool{true, false} {
		path := writeConfig(t, "config.yaml", fmt.Sprintf(`server_url: https://headscale.example.com
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
		require.NoError(t, LoadConfig(path, true))

		cfg, err := LoadServerConfig()
		require.NoError(t, err)
		assert.Equal(t, want, cfg.DisableUpdateCheck)
	}
}

func TestBoolConfigKeysComplete(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "config.go", nil, 0)
	require.NoError(t, err)

	keys := make(map[string]bool)

	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}

		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Bool" {
			return true
		}

		object, ok := selector.X.(*ast.Ident)
		if !ok || object.Name != "src" {
			return true
		}

		require.Len(t, call.Args, 1)
		literal, ok := call.Args[0].(*ast.BasicLit)
		require.True(t, ok, "boolean config keys must be string literals")

		key, err := strconv.Unquote(literal.Value)
		require.NoError(t, err)

		keys[key] = true

		return true
	})
	require.NotEmpty(t, keys)

	for _, key := range boolConfigKeys {
		assert.Contains(t, keys, key, "unused or repeated boolean config key")
		delete(keys, key)
	}

	assert.Empty(t, keys, "Bool keys missing from boolean validation")
}

func TestExampleConfigBooleanSettings(t *testing.T) {
	require.NoError(t, LoadConfig("../../config-example.yaml", true))

	_, err := LoadServerConfig()
	require.NoError(t, err)
}

func TestLoadCLIConfigRejectsNonBoolean(t *testing.T) {
	for _, key := range []string{"cli.insecure", "disable_check_updates"} {
		t.Run(key, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(path, nil, 0o600))

			env := configEnvName(key)
			t.Setenv(env, "true")
			require.NoError(t, LoadConfig(path, true))

			_, err := LoadCLIConfig()
			require.NoError(t, err)

			t.Setenv(env, "ture")
			require.NoError(t, LoadConfig(path, true))

			_, err = LoadCLIConfig()
			require.Error(t, err)
			assert.Contains(t, err.Error(), key)
		})
	}
}

// TestDNSDomainsCompat: SaaS sends the tailnet domain as a search domain with
// MagicDNS on and leaves it out with MagicDNS off.
func TestDNSDomainsCompat(t *testing.T) {
	for id, magicDNS := range map[string]bool{
		"nodeattrs-nextdns-d1-profile":  false,
		"nodeattrs-tailnet-magicdns-on": true,
	} {
		t.Run(id, func(t *testing.T) {
			c, err := testcapture.Read(filepath.Join("..", "policy", "v2", "testdata", "nodeattrs_results", id+".hujson"))
			require.NoError(t, err)

			got := dnsToTailcfgDNS(DNSConfig{MagicDNS: magicDNS, BaseDomain: "example.com"})

			for node, capture := range c.Captures {
				require.NotNil(t, capture.Netmap, node)
				assert.Equal(t, len(capture.Netmap.DNS.Domains) > 0, len(got.Domains) > 0, node)
			}
		})
	}
}

// compatRecord is the golden for one config input: what the loader produced.
type compatRecord struct {
	Config    json.RawMessage   `json:"config,omitempty"`
	Secrets   map[string]string `json:"secrets,omitempty"` // secret strings the JSON form hides
	Warnings  []string          `json:"warnings,omitempty"`
	LogErrors []string          `json:"log_errors,omitempty"` // input the loader logged and dropped
	Error     string            `json:"error,omitempty"`      // an error-only golden pins today's rejection
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
// ending in -cli uses the CLI loader. Fixtures are frozen inputs: to change
// one, add a new fixture. Refresh with HEADSCALE_UPDATE_GOLDEN=1.
//
// Sources: example-<tag>.yaml is `git show <tag>:config-example.yaml`;
// example-main.yaml is a frozen copy of the root file; nixos-*.yaml are the
// files `nix build` writes for the flake module with nix/example-configuration.nix
// (services.headscale.configFile, environment.etc."headscale/config.yaml") and
// for the nixpkgs module with only server_url, dns.base_domain and
// dns.nameservers.global set; hsic-* mirror integration/hsic's
// MinimumConfigYAML and DefaultConfigEnv. <name>-strict is the same source
// as updated for the strict loader.
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

			if d := cmp.Diff(string(want), string(out)); d != "" {
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
	NotifierSendTimeout            time.Duration
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
func compatView(cfg *Config) compatConfig {
	pg := cfg.Database.Postgres
	oidc := cfg.OIDC
	ch := cfg.DNSChallenge
	acme := cfg.TLS.ACME

	dbType := cfg.Database.Type
	if cfg.Database.IsSQLite() {
		dbType = DatabaseSqlite
	}

	tuning := compatTuning(cfg.Tuning)
	tuning.BatcherWorkers = cfg.Tuning.BatcherWorkerCount()

	return compatConfig{
		ServerURL:      cfg.ServerURL,
		Addr:           cfg.Addr,
		MetricsAddr:    cfg.MetricsAddr,
		TrustedProxies: cfg.TrustedProxies,
		Node: compatNodeConfig{
			Expiry:    cfg.Node.Expiry,
			Ephemeral: compatEphemeralConfig(cfg.Node.Ephemeral),
			Routes:    compatRouteConfig{HA: compatHARouteConfig(cfg.Node.Routes.HA)},
		},
		PreAuthKeys:         compatPreAuthKeysConfig(cfg.PreAuthKeys),
		PrefixV4:            cfg.PrefixV4,
		PrefixV6:            cfg.PrefixV6,
		IPAllocation:        string(cfg.IPAllocation),
		NoisePrivateKeyPath: cfg.AbsPath(cfg.NoisePrivateKeyPath),
		BaseDomain:          cfg.BaseDomain,
		Log:                 compatLogConfig(cfg.Log),
		DisableUpdateCheck:  cfg.DisableUpdateCheck,
		Database: compatDatabaseConfig{
			Type:  dbType,
			Debug: cfg.Database.Debug,
			Gorm:  compatGormConfig(cfg.Database.Gorm),
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
			ServerEnabled:                      cfg.DERP.ServerEnabled,
			AutomaticallyAddEmbeddedDerpRegion: cfg.DERP.AutomaticallyAddEmbeddedDerpRegion,
			ServerRegionID:                     cfg.DERP.ServerRegionID,
			ServerRegionCode:                   cfg.DERP.ServerRegionCode,
			ServerRegionName:                   cfg.DERP.ServerRegionName,
			ServerPrivateKeyPath:               cfg.AbsPath(cfg.DERP.ServerPrivateKeyPath),
			ServerVerifyClients:                cfg.DERP.ServerVerifyClients,
			STUNAddr:                           cfg.DERP.STUNAddr,
			URLs:                               cfg.DERP.URLs,
			Paths:                              cfg.DERP.Paths,
			DERPMap:                            cfg.DERP.DERPMap,
			AutoUpdate:                         cfg.DERP.AutoUpdate,
			UpdateFrequency:                    cfg.DERP.UpdateFrequency,
			IPv4:                               cfg.DERP.IPv4,
			IPv6:                               cfg.DERP.IPv6,
		},
		TLS: compatTLSConfig{
			CertPath: cfg.AbsPath(cfg.TLS.CertPath),
			KeyPath:  cfg.AbsPath(cfg.TLS.KeyPath),
			ACME: compatACMEConfig{
				Hostname:      acme.Hostname,
				ChallengeType: acme.ChallengeType,
				HTTPListen:    acme.HTTPListen,
				URL:           acme.URL,
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
		UnixSocketPermission: cfg.UnixSocketPermission,
		OIDC: compatOIDCConfig{
			OnlyStartIfOIDCIsAvailable: oidc.OnlyStartIfOIDCIsAvailable,
			Issuer:                     oidc.Issuer,
			ClientID:                   oidc.ClientID,
			Scope:                      oidc.Scope,
			ExtraParams:                oidc.ExtraParams,
			AllowedDomains:             oidc.AllowedDomains,
			AllowedUsers:               oidc.AllowedUsers,
			AllowedGroups:              oidc.AllowedGroups,
			EmailVerifiedRequired:      oidc.EmailVerifiedRequired,
			UseExpiryFromToken:         oidc.UseExpiryFromToken,
			PKCE:                       compatPKCEConfig(oidc.PKCE),
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

	var buf bytes.Buffer

	oldLogger, oldLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(&buf)

	// Tests run at ErrorLevel (testlog.go); the loaders then set the level
	// from log.level, as in production.
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	t.Cleanup(func() {
		log.Logger = oldLogger

		zerolog.SetGlobalLevel(oldLevel)
	})

	var cfg *Config

	err := LoadConfig(dir, false)
	if err == nil {
		if cli {
			cfg, err = LoadCLIConfig()
		} else {
			cfg, err = LoadServerConfig()
		}
	}

	norm := func(s string) string { return strings.ReplaceAll(s, dir, "$DIR") }

	var rec compatRecord

	for line := range strings.SplitSeq(buf.String(), "\n") {
		if line == "" {
			continue
		}

		var entry struct{ Level, Message string }

		require.NoError(t, json.Unmarshal([]byte(line), &entry))

		switch entry.Level {
		case zerolog.LevelWarnValue:
			rec.Warnings = append(rec.Warnings, norm(entry.Message))
		case zerolog.LevelErrorValue:
			rec.LogErrors = append(rec.LogErrors, norm(entry.Message))
		}
	}

	if err != nil {
		rec.Error = norm(err.Error())
	}

	if cfg != nil {
		view := compatView(cfg)
		if cli {
			// The CLI loader sets only what client commands read; compatView
			// would derive server values from the zero rest.
			view = compatConfig{
				Log:                view.Log,
				DisableUpdateCheck: view.DisableUpdateCheck,
				UnixSocket:         view.UnixSocket,
				CLI:                view.CLI,
			}
		}

		if view.Tuning.BatcherWorkers == DefaultBatcherWorkers() {
			view.Tuning.BatcherWorkers = 0 // depends on runtime.NumCPU
		}

		raw, err := json.Marshal(view)
		require.NoError(t, err)

		rec.Config = json.RawMessage(norm(string(raw)))
		rec.Secrets = map[string]string{
			"database.postgres.pass": cfg.Database.Postgres.Pass,
			"oidc.client_secret":     cfg.OIDC.ClientSecret,
			"cli.api_key":            cfg.CLI.APIKey,
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
			require.NoError(t, LoadConfig(dir, false))

			err := validateServerConfig()
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
			require.NoError(t, LoadConfig(dir, false))

			err := validateServerConfig()
			if !tt.wantErr {
				require.NoError(t, err)

				return
			}

			require.ErrorContains(t, err, "policy.mode has an unsupported value")
		})
	}
}

// TestConfigNotLoaded: an embedder that skips LoadConfig gets an error, not a panic.
func TestConfigNotLoaded(t *testing.T) {
	old := src
	src = nil

	t.Cleanup(func() { src = old })

	_, err := LoadServerConfig()
	require.ErrorIs(t, err, errConfigNotLoaded)
	_, err = CheckServerConfig()
	require.ErrorIs(t, err, errConfigNotLoaded)

	_, err = LoadCLIConfig()
	require.ErrorIs(t, err, errConfigNotLoaded)

	_, err = DumpConfig()
	require.ErrorIs(t, err, errConfigNotLoaded)
}

// useConfig points src at the defaults plus values until the test ends.
func useConfig(t *testing.T, values map[string]any) {
	t.Helper()

	s := &configSource{k: koanf.New(".")}
	require.NoError(t, s.k.Load(confmap.Provider(configDefaults, "."), nil))
	require.NoError(t, s.k.Load(confmap.Provider(values, "."), nil))

	old := src
	src = s

	t.Cleanup(func() { src = old })
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
	require.NoError(t, LoadConfig(dir, false))

	cfg, err := LoadServerConfig()
	require.NoError(t, err)

	assert.Equal(t, "./noise.key", cfg.NoisePrivateKeyPath)
	assert.Equal(t, filepath.Join(dir, "noise.key"), cfg.AbsPath(cfg.NoisePrivateKeyPath))
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

			require.NoError(t, LoadConfig(dir, false))

			cfg, err := LoadServerConfig()
			require.NoError(t, err)
			assert.Equal(t, ":memory:", cfg.SQLitePath())
			assert.True(t, filepath.IsAbs(cfg.AbsPath(cfg.NoisePrivateKeyPath)), cfg.AbsPath(cfg.NoisePrivateKeyPath))
		})
	}
}

// TestDerivedValues pins the values computed from what the configuration
// says, which the loader stores as written.
func TestDerivedValues(t *testing.T) {
	etc := &Config{ConfigDir: "/etc/hs"}
	sqlite := func(path string) *Config {
		return &Config{ConfigDir: "/etc/hs", Database: DatabaseConfig{Sqlite: SqliteConfig{Path: path}}}
	}
	resolvers := func(r ...string) DNSChallengeConfig { return DNSChallengeConfig{Resolvers: r} }

	tests := []struct {
		name      string
		got, want any
	}{
		{"relative path", etc.AbsPath("./noise.key"), "/etc/hs/noise.key"},
		{"absolute path", etc.AbsPath("/var/lib/hs/noise.key"), "/var/lib/hs/noise.key"},
		{"no config dir", (&Config{}).AbsPath("./noise.key"), "./noise.key"},
		{"empty path", etc.AbsPath(""), ""},
		{"sqlite relative", sqlite("db.sqlite").SQLitePath(), "/etc/hs/db.sqlite"},
		{"sqlite memory", sqlite(":memory:").SQLitePath(), ":memory:"},
		{"sqlite", DatabaseConfig{Type: "sqlite"}.IsSQLite(), true},
		{"sqlite3", DatabaseConfig{Type: "sqlite3"}.IsSQLite(), true},
		{"postgres", DatabaseConfig{Type: "postgres"}.IsSQLite(), false},
		{"workers unset", Tuning{}.BatcherWorkerCount(), DefaultBatcherWorkers()},
		{"workers set", Tuning{BatcherWorkers: 7}.BatcherWorkerCount(), 7},
		{"zone unset", DNSConfig{BaseDomain: "ts.example.com"}.CertificateZone(), "ts.example.com"},
		{"zone set", DNSConfig{BaseDomain: "ts.example.com", Certificates: CertificatesConfig{Zone: "example.com"}}.CertificateZone(), "example.com"},
		{"resolvers unset", resolvers().ResolverAddrs(), []string{"1.1.1.1:53", "8.8.8.8:53"}},
		{"resolver bare IPv4", resolvers("9.9.9.9").ResolverAddrs(), []string{"9.9.9.9:53"}},
		{"resolver bare IPv6", resolvers("2620:fe::fe").ResolverAddrs(), []string{"[2620:fe::fe]:53"}},
		{"resolver with port", resolvers("[::1]:5353").ResolverAddrs(), []string{"[::1]:5353"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.got)
		})
	}

	// Callers share the config, so deriving must not write to it.
	written := []string{"9.9.9.9"}
	resolvers(written...).ResolverAddrs()
	assert.Equal(t, []string{"9.9.9.9"}, written)
}
