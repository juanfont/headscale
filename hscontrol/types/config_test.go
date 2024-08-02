package types

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
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
			setup: func(t *testing.T) (any, error) {
				dns, err := DNS()
				if err != nil {
					return nil, err
				}

				return dns, nil
			},
			want: DNSConfig{
				MagicDNS:   true,
				BaseDomain: "example.com",
				Nameservers: Nameservers{
					Global: []string{"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001", "https://dns.nextdns.io/abc123"},
					Split:  map[string][]string{"darp.headscale.net": {"1.1.1.1", "8.8.8.8"}, "foo.bar.com": {"1.1.1.1"}},
				},
				ExtraRecords: []tailcfg.DNSRecord{
					{Name: "grafana.myvpn.example.com", Type: "A", Value: "100.64.0.3"},
					{Name: "prometheus.myvpn.example.com", Type: "A", Value: "100.64.0.4"},
				},
				SearchDomains:      []string{"test.com", "bar.com"},
				UserNameInMagicDNS: true,
			},
		},
		{
			name:       "dns-to-tailcfg.DNSConfig",
			configPath: "testdata/dns_full.yaml",
			setup: func(t *testing.T) (any, error) {
				dns, err := DNS()
				if err != nil {
					return nil, err
				}

				return DNSToTailcfgDNS(dns), nil
			},
			want: &tailcfg.DNSConfig{
				Proxied: true,
				Domains: []string{"example.com", "test.com", "bar.com"},
				Resolvers: []*dnstype.Resolver{
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
			setup: func(t *testing.T) (any, error) {
				dns, err := DNS()
				if err != nil {
					return nil, err
				}

				return dns, nil
			},
			want: DNSConfig{
				MagicDNS:   false,
				BaseDomain: "example.com",
				Nameservers: Nameservers{
					Global: []string{"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001", "https://dns.nextdns.io/abc123"},
					Split:  map[string][]string{"darp.headscale.net": {"1.1.1.1", "8.8.8.8"}, "foo.bar.com": {"1.1.1.1"}},
				},
				ExtraRecords: []tailcfg.DNSRecord{
					{Name: "grafana.myvpn.example.com", Type: "A", Value: "100.64.0.3"},
					{Name: "prometheus.myvpn.example.com", Type: "A", Value: "100.64.0.4"},
				},
				SearchDomains:      []string{"test.com", "bar.com"},
				UserNameInMagicDNS: true,
			},
		},
		{
			name:       "dns-to-tailcfg.DNSConfig",
			configPath: "testdata/dns_full_no_magic.yaml",
			setup: func(t *testing.T) (any, error) {
				dns, err := DNS()
				if err != nil {
					return nil, err
				}

				return DNSToTailcfgDNS(dns), nil
			},
			want: &tailcfg.DNSConfig{
				Proxied: false,
				Domains: []string{"example.com", "test.com", "bar.com"},
				Resolvers: []*dnstype.Resolver{
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
			setup: func(t *testing.T) (any, error) {
				return GetHeadscaleConfig()
			},
			want:    nil,
			wantErr: "server_url cannot contain the base_domain, this will cause the headscale server and embedded DERP to become unreachable from the Tailscale node.",
		},
		{
			name:       "base-domain-not-in-server-url",
			configPath: "testdata/base-domain-not-in-server-url.yaml",
			setup: func(t *testing.T) (any, error) {
				cfg, err := GetHeadscaleConfig()
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
			name:       "policy-path-is-loaded",
			configPath: "testdata/policy-path-is-loaded.yaml",
			setup: func(t *testing.T) (any, error) {
				cfg, err := GetHeadscaleConfig()
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
			assert.NoError(t, err)

			conf, err := tt.setup(t)

			if tt.wantErr != "" {
				assert.Equal(t, tt.wantErr, err.Error())

				return
			}

			assert.NoError(t, err)

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
			setup: func(t *testing.T) (any, error) {
				t.Logf("all settings: %#v", viper.AllSettings())

				assert.Equal(t, "trace", viper.GetString("log.level"))
				assert.Equal(t, "100.64.0.0/10", viper.GetString("prefixes.v4"))
				assert.False(t, viper.GetBool("database.sqlite.write_ahead_log"))
				return nil, nil
			},
			want: nil,
		},
		{
			name: "unmarshal-dns-full-config",
			configEnv: map[string]string{
				"HEADSCALE_DNS_MAGIC_DNS":                 "true",
				"HEADSCALE_DNS_BASE_DOMAIN":               "example.com",
				"HEADSCALE_DNS_NAMESERVERS_GLOBAL":        `1.1.1.1 8.8.8.8`,
				"HEADSCALE_DNS_SEARCH_DOMAINS":            "test.com bar.com",
				"HEADSCALE_DNS_USE_USERNAME_IN_MAGIC_DNS": "true",

				// TODO(kradalby): Figure out how to pass these as env vars
				// "HEADSCALE_DNS_NAMESERVERS_SPLIT":  `{foo.bar.com: ["1.1.1.1"]}`,
				// "HEADSCALE_DNS_EXTRA_RECORDS":      `[{ name: "prometheus.myvpn.example.com", type: "A", value: "100.64.0.4" }]`,
			},
			setup: func(t *testing.T) (any, error) {
				t.Logf("all settings: %#v", viper.AllSettings())

				dns, err := DNS()
				if err != nil {
					return nil, err
				}

				return dns, nil
			},
			want: DNSConfig{
				MagicDNS:   true,
				BaseDomain: "example.com",
				Nameservers: Nameservers{
					Global: []string{"1.1.1.1", "8.8.8.8"},
					Split:  map[string][]string{
						// "foo.bar.com": {"1.1.1.1"},
					},
				},
				ExtraRecords: []tailcfg.DNSRecord{
					// {Name: "prometheus.myvpn.example.com", Type: "A", Value: "100.64.0.4"},
				},
				SearchDomains:      []string{"test.com", "bar.com"},
				UserNameInMagicDNS: true,
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
			assert.NoError(t, err)

			conf, err := tt.setup(t)
			assert.NoError(t, err)

			if diff := cmp.Diff(tt.want, conf); diff != "" {
				t.Errorf("ReadConfig() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
