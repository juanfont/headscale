package types

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	hsdns "github.com/juanfont/headscale/hscontrol/dns"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/libdns/cloudflare"
	"github.com/spf13/viper"
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
				Certificates:  CertificatesConfig{Zone: "example.com"},
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
				Certificates:  CertificatesConfig{Zone: "example.com"},
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
			configPath: "testdata/policy-path-is-loaded.yaml",
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
			viper.Reset()

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
				t.Logf("all settings: %#v", viper.AllSettings())

				assert.Equal(t, "trace", viper.GetString("log.level"))
				assert.Equal(t, "100.64.0.0/10", viper.GetString("prefixes.v4"))
				assert.False(t, viper.GetBool("database.sqlite.write_ahead_log"))

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
				t.Logf("all settings: %#v", viper.AllSettings())

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
				Certificates:  CertificatesConfig{Zone: "example.com"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.configEnv {
				t.Setenv(k, v)
			}

			viper.Reset()

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
	const (
		tlsKeys = `tls:
  acme:
    hostname: %q
    challenge_type: %q
    http_listen: %q
`
		legacyKeys = `tls_letsencrypt_hostname: %q
tls_letsencrypt_challenge_type: %q
tls_letsencrypt_listen: %q
`
	)

	tests := []struct {
		name          string
		listenAddr    string
		acmeListen    string
		hostname      string
		challengeType string
		keys          string
		wantErr       string // empty = expect no error
	}{
		{"collision-numeric", ":80", ":80", "example.com", "HTTP-01", tlsKeys, "would bind the same TCP socket"},
		{"collision-named-vs-numeric", "0.0.0.0:80", ":http", "example.com", "HTTP-01", tlsKeys, "would bind the same TCP socket"},
		{"collision-https-named", ":443", ":https", "example.com", "HTTP-01", tlsKeys, "would bind the same TCP socket"},
		{"collision-legacy-keys", ":80", ":80", "example.com", "HTTP-01", legacyKeys, "would bind the same TCP socket"},
		{"canonical", "0.0.0.0:443", ":http", "example.com", "HTTP-01", tlsKeys, ""},
		{"no-hostname-skipped", "0.0.0.0:80", ":http", "", "HTTP-01", tlsKeys, ""},
		{"tls-alpn-01-skipped", "0.0.0.0:80", ":http", "example.com", "TLS-ALPN-01", tlsKeys, ""},
		{"different-numeric", ":8080", ":8081", "example.com", "HTTP-01", tlsKeys, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()

			tmpDir := t.TempDir()
			cfg := fmt.Sprintf(`---
server_url: https://example.com
listen_addr: %q
`+tt.keys+`noise:
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
	viper.Reset()

	tmpDir := t.TempDir()
	cfg := `---
server_url: https://example.com
listen_addr: 0.0.0.0:8080
prefixes:
  v4: not-a-cidr
  v6: also-not-a-cidr
  allocation: bogus
oidc:
  client_secret: hunter2
  client_secret_path: /nonexistent/secret
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
	require.ErrorIs(t, err, errOidcMutuallyExclusive,
		"wrapped errOidcMutuallyExclusive not in chain")

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

func TestDeprecatedKeysFlowThroughValidator(t *testing.T) {
	viper.Reset()

	tmpDir := t.TempDir()
	cfg := `---
server_url: https://example.com
listen_addr: 0.0.0.0:8080
oidc:
  expiry: 1h
dns_config:
  use_username_in_magic_dns: true
noise:
  private_key_path: noise_private.key
database:
  type: sqlite3
dns:
  magic_dns: false
  override_local_dns: false
`
	require.NoError(t, os.WriteFile(
		filepath.Join(tmpDir, "config.yaml"), []byte(cfg), 0o600))
	require.NoError(t, LoadConfig(tmpDir, false))

	err := validateServerConfig()
	require.Error(t, err)

	got := ConfigErrors(err)
	require.GreaterOrEqual(t, len(got), 2,
		"expected fatal deprecated keys to surface as ConfigErrors; got %d", len(got))

	reasons := make([]string, 0, len(got))
	for _, ce := range got {
		reasons = append(reasons, ce.Reason)
	}

	wantSubstrs := []string{"oidc.expiry", "dns_config.use_username_in_magic_dns"}
	for _, want := range wantSubstrs {
		var found bool

		for _, r := range reasons {
			if strings.Contains(r, want) {
				found = true
				break
			}
		}

		assert.True(t, found, "expected ConfigError mentioning %q in reasons %v", want, reasons)
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
			viper.Reset()

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
			ProviderName: "cloudflare",
			Provider:     &cloudflare.Provider{APIToken: secretDNSToken},
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
			viper.Reset()

			if tt.input != nil {
				viper.Set("trusted_proxies", tt.input)
			}

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

	cfg := &Config{TailcfgDNSConfig: &tailcfg.DNSConfig{}}
	cfg.SetExtraRecords(mixed)

	if diff := cmp.Diff(want, cfg.TailcfgDNSConfig.ExtraRecords); diff != "" {
		t.Errorf("SetExtraRecords mismatch (-want +got):\n%s", diff)
	}
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
		wantZone      string
		wantToken     string
		wantNoProv    bool
		wantResolvers []string
		wantIsolates  string
	}{
		{
			name: "disabled by default",
			yaml: base,
			// Zone follows base_domain even when unused, so it is never empty.
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
				"HEADSCALE_DNS_CERTIFICATES_ENABLED":              "true",
				"HEADSCALE_DNS_CERTIFICATES_ZONE":                 "example.com",
				"HEADSCALE_DNS_CHALLENGE_PROVIDER_NAME":           "cloudflare",
				"HEADSCALE_DNS_CHALLENGE_PROVIDER_API_TOKEN_PATH": secret,
			},
			wantZone:  "example.com",
			wantToken: "file-token",
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
			wantErr: "desktop.ts.example.com and laptop.ts.example.com share registration reg",
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
			wantErr: "headscale.example.com and laptop.ts.example.com share registration reg",
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
			viper.Reset()

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
			assert.Equal(t, tt.wantZone, cfg.DNSConfig.Certificates.Zone)

			if tt.wantResolvers != nil {
				assert.Equal(t, tt.wantResolvers, cfg.DNSChallenge.Resolvers)
			}

			if tt.wantNoProv {
				assert.Nil(t, cfg.DNSChallenge.Provider)

				return
			}

			if iso, ok := cfg.DNSChallenge.Provider.(hsdns.Isolator); ok {
				if tt.wantIsolates != "" {
					assert.True(t, iso.Isolates(tt.wantIsolates))
				}

				return
			}

			provider, ok := cfg.DNSChallenge.Provider.(*cloudflare.Provider)
			require.True(t, ok, "provider is %T", cfg.DNSChallenge.Provider)
			assert.Equal(t, tt.wantToken, provider.APIToken)
		})
	}
}

// TestTLSLegacyKeys pins that the flat TLS keys keep working under the tls
// block, with the tls keys winning, and that the NixOS module's defaults
// for the flat keys leave TLS off.
func TestTLSLegacyKeys(t *testing.T) {
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
		name string
		yaml string
		env  map[string]string
		want TLSConfig
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
			want: TLSConfig{ACME: ACMEConfig{
				Hostname:      "headscale.example.com",
				ChallengeType: TLSALPN01ChallengeType,
				HTTPListen:    ":8080",
				URL:           "https://acme.example.com/directory",
				Email:         "admin@example.com",
				CacheDir:      "/var/lib/headscale/cache",
			}},
		},
		{
			name: "tls keys win over legacy keys",
			yaml: base + `tls_cert_path: /old/cert.pem
tls_key_path: /old/key.pem
tls:
  cert_path: /new/cert.pem
  key_path: /new/key.pem
`,
			want: TLSConfig{
				CertPath: "/new/cert.pem",
				KeyPath:  "/new/key.pem",
				ACME: ACMEConfig{
					ChallengeType: HTTP01ChallengeType,
					HTTPListen:    ":http",
					CacheDir:      "/var/lib/headscale/cache",
				},
			},
		},
		{
			// What the NixOS module writes when TLS is off.
			name: "nixos defaults",
			yaml: base + `tls_letsencrypt_hostname: ""
tls_letsencrypt_challenge_type: HTTP-01
tls_letsencrypt_listen: ":http"
tls_letsencrypt_cache_dir: /var/lib/headscale/.cache
`,
			want: TLSConfig{ACME: ACMEConfig{
				ChallengeType: HTTP01ChallengeType,
				HTTPListen:    ":http",
				CacheDir:      "/var/lib/headscale/.cache",
			}},
		},
		{
			// Both keys read HEADSCALE_TLS_CERT_PATH.
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
			viper.Reset()

			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			tmpDir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "config.yaml"), []byte(tt.yaml), 0o600))
			require.NoError(t, LoadConfig(tmpDir, false))

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
		{
			name: "ssl false disables sslmode",
			cfg: PostgresConfig{
				Host: "localhost",
				Port: 5432,
				Name: "headscale",
				User: "hs",
				Pass: "secret", //nolint:gosec // test fixture, not a credential
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
		{
			// Regression: the DSN used to be concatenated, so a space, quote
			// or backslash in the password truncated it or injected parameters.
			name: "password with reserved characters survives a round trip",
			cfg: PostgresConfig{
				Host: "db",
				Name: "head scale",
				User: "h's",
				//nolint:gosec // test fixture, not a credential
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
