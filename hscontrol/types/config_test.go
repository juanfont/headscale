package types

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/libdns/cloudflare"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

// TestConfigJSONOmitsSecrets verifies that marshalling a [Config] to JSON
// or logging it does not leak the Postgres password, the OIDC client
// secret, the headscale admin API key, or URL credentials. Operators who
// widen metrics_listen_addr to 0.0.0.0 should not be able to read these
// back via debug endpoints reachable over CGNAT/loopback.
func TestConfigJSONOmitsSecrets(t *testing.T) {
	const (
		secretPostgresPass = "p0stgres-secret-marker"
		secretClientSecret = "oidc-client-secret-marker"    //nolint:gosec // test marker, not a real credential
		secretAPIKey       = "headscale-cli-api-key-marker" //nolint:gosec // test marker, not a real credential
		secretDNSToken     = "dns-provider-token-marker"    //nolint:gosec // test marker, not a real credential
		secretDERPUser     = "derp-url-username-marker"     //nolint:gosec // test marker, not a real credential
		secretDERPPass     = "derp-url-password-marker"     //nolint:gosec // test marker, not a real credential
		secretDERPToken    = "derp-url-token-marker"        //nolint:gosec // test marker, not a real credential
		derpMapMarker      = "go-only-derp-map-marker"
		secretServerUser   = "server-url-username-marker" //nolint:gosec // test marker, not a real credential
		secretServerPass   = "server-url-password-marker" //nolint:gosec // test marker, not a real credential
		secretCLIToken     = "cli-address-token-marker"   //nolint:gosec // test marker, not a real credential
		secretDNSUser      = "dns-url-username-marker"    //nolint:gosec // test marker, not a real credential
		secretDNSPass      = "dns-url-password-marker"    //nolint:gosec // test marker, not a real credential
		secretSplitToken   = "split-url-token-marker"     //nolint:gosec // test marker, not a real credential
	)

	cfg := &Config{
		ServerURL: "https://" + secretServerUser + ":" + secretServerPass + "@headscale.example.com",
		Database: DatabaseConfig{
			Postgres: PostgresConfig{
				Pass: secretPostgresPass,
			},
		},
		OIDC: OIDCConfig{
			ClientSecret: secretClientSecret,
		},
		CLI: CLIConfig{
			Address: "https://" + secretCLIToken + "@cli.example.com",
			APIKey:  secretAPIKey,
		},
		DNSConfig: DNSConfig{
			Nameservers: Nameservers{
				Global: []string{"1.1.1.1", "https://" + secretDNSUser + ":" + secretDNSPass + "@dns.example.com/dns-query"},
				Split:  map[string][]string{"corp.example.com": {"https://" + secretSplitToken + "@dns.example.com/q"}},
			},
			Challenge: DNSChallengeConfig{
				ProviderSettings: map[string]any{"name": "cloudflare", "api_token": secretDNSToken},
				Provider:         &cloudflare.Provider{APIToken: secretDNSToken},
			},
		},
		DERP: DERPConfig{
			URLs: []HTTPURL{
				"https://" + secretDERPUser + ":" + secretDERPPass + "@derp.example/map",
				"https://" + secretDERPToken + "@derp.example/token-map",
			},
			DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
				900: {RegionCode: derpMapMarker},
			}},
		},
	}

	secrets := []string{
		secretPostgresPass, secretClientSecret, secretAPIKey, secretDNSToken,
		secretDERPUser, secretDERPPass, secretDERPToken,
		secretServerUser, secretServerPass, secretCLIToken, secretDNSUser, secretDNSPass, secretSplitToken,
	}

	out, err := json.Marshal(cfg)
	require.NoError(t, err)

	for _, secret := range secrets {
		assert.NotContains(t, string(out), secret,
			"marshalled Config must not contain secret %q", secret)
	}

	// The URLs are still shown, without userinfo; the running values keep it.
	assert.Contains(t, string(out), `"https://derp.example/map"`)
	assert.Contains(t, string(out), `"https://derp.example/token-map"`)
	assert.Contains(t, string(out), `"ServerURL":"https://headscale.example.com"`)
	assert.Contains(t, string(out), `"Address":"https://cli.example.com"`)
	assert.Contains(t, string(out), `"Global":["1.1.1.1","https://dns.example.com/dns-query"]`)
	assert.Contains(t, string(out), `"Split":{"corp.example.com":["https://dns.example.com/q"]}`)
	assert.Contains(t, string(cfg.DERP.URLs[0]), secretDERPUser+":"+secretDERPPass)
	assert.Contains(t, string(cfg.DERP.URLs[1]), secretDERPToken)
	assert.Contains(t, cfg.ServerURL, secretServerUser+":"+secretServerPass)
	assert.Contains(t, cfg.CLI.Address, secretCLIToken)
	assert.Contains(t, cfg.DNSConfig.Nameservers.Global[1], secretDNSUser+":"+secretDNSPass)
	assert.Contains(t, cfg.DNSConfig.Nameservers.Split["corp.example.com"][0], secretSplitToken)
	// DERPMap is Go-only.
	assert.NotContains(t, string(out), derpMapMarker)

	// Secret redacts only through fmt's String; zerolog marshals it. Test
	// binaries log at Error (testlog.go), which would drop this record.
	oldLevel := zerolog.GlobalLevel()

	t.Cleanup(func() { zerolog.SetGlobalLevel(oldLevel) })
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	var logged bytes.Buffer

	logger := zerolog.New(&logged)
	logger.Info().Interface("config", cfg).Send()
	require.Contains(t, logged.String(), `"config":{`)

	for _, secret := range secrets {
		assert.NotContains(t, logged.String(), secret,
			"logged Config must not contain secret %q", secret)
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
				Prefixes:  PrefixesConfig{V4: &ten},
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
				Prefixes:  PrefixesConfig{V6: &fd00},
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
				Prefixes:  PrefixesConfig{V4: &cgnat, V6: &ula},
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
			cfg:  Config{Prefixes: PrefixesConfig{V4: &ten}},
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
			Challenge:    DNSChallengeConfig{Provider: goOnly},
		},
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
	cfg := &Config{Prefixes: PrefixesConfig{V4: &v4, V6: &v6}}

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
	assert.True(t, (&Config{Prefixes: PrefixesConfig{V4: &narrow}}).ServesRoute(netip.MustParsePrefix("100.100.0.1/32")))
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
