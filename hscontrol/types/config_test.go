package types

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
			wantErr: errServerURLSuffix.Error(),
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
			wantErr: "Fatal config error: dns.nameservers.global must be set when dns.override_local_dns is true",
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
				assert.Equal(t, tt.wantErr, err.Error())

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
tls_letsencrypt_hostname: example.com
tls_letsencrypt_challenge_type: ""
tls_cert_path: abc.pem
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
		"Fatal config error: set either tls_letsencrypt_hostname or tls_cert_path/tls_key_path, not both",
	)
	assert.Contains(
		t,
		err.Error(),
		"Fatal config error: the only supported values for tls_letsencrypt_challenge_type are",
	)
	assert.Contains(
		t,
		err.Error(),
		"Fatal config error: server_url must start with https:// or http://",
	)

	// Check configuration validation errors (2)
	configYaml = []byte(`---
noise:
  private_key_path: noise_private.key
server_url: http://127.0.0.1:8080
tls_letsencrypt_hostname: example.com
tls_letsencrypt_challenge_type: TLS-ALPN-01
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
  override_local_dns: false
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
	}

	out, err := json.Marshal(cfg)
	require.NoError(t, err)

	body := string(out)
	for _, secret := range []string{secretPostgresPass, secretClientSecret, secretAPIKey} {
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
