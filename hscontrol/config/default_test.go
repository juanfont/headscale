package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validConfig is Default with a server URL, the one key Default leaves
// empty, so it passes Validate, and its own DNS base domain and resolver.
func validConfig() types.Config {
	v4 := netip.MustParsePrefix("100.64.0.0/10")

	cfg := Default()
	cfg.ServerURL = "https://headscale.example.com"
	cfg.Noise.PrivateKeyPath = "/var/lib/headscale/noise_private.key"
	cfg.Database.Type = types.DatabaseSqlite
	cfg.Prefixes.V4 = &v4
	cfg.DNSConfig.BaseDomain = "tailnet.example.com"
	cfg.DNSConfig.Nameservers.Global = []string{"1.1.1.1"}

	return cfg
}

// TestDefaultHoldsDefaults: the defaults consumers fall back to for a zero
// value are Default's, so the loaded configuration shows them.
func TestDefaultHoldsDefaults(t *testing.T) {
	d := Default()
	assert.Equal(t, 15*time.Minute, d.Tuning.RegisterCacheExpiration)
	assert.Equal(t, 1024, d.Tuning.RegisterCacheMaxEntries)
	assert.Equal(t, 100, d.Tuning.NodeStoreBatchSize)
	assert.Equal(t, 500*time.Millisecond, d.Tuning.NodeStoreBatchTimeout)
	assert.Zero(t, d.Tuning.BatcherWorkers, "auto: its count depends on the host")
	require.Equal(t, []string{"9.9.9.9:53", "149.112.112.112:53"}, d.DNSConfig.Challenge.Resolvers)

	assert.Equal(t, types.ListenAddr("0.0.0.0:8080"), d.Addr)
	assert.Empty(t, d.MetricsAddr)
	assert.Equal(t, "/var/lib/headscale/noise_private.key", d.Noise.PrivateKeyPath)
	require.NotNil(t, d.Prefixes.V4)
	require.NotNil(t, d.Prefixes.V6)
	assert.Equal(t, netip.MustParsePrefix("100.64.0.0/10"), *d.Prefixes.V4)
	assert.Equal(t, netip.MustParsePrefix("fd7a:115c:a1e0::/48"), *d.Prefixes.V6)
	assert.Equal(t, types.DatabaseSqliteShort, d.Database.Type)
	assert.Equal(t, "/var/lib/headscale/db.sqlite", d.Database.Sqlite.Path)
	assert.Equal(t, []types.HTTPURL{"https://controlplane.tailscale.com/derpmap/default"}, d.DERP.URLs)
	assert.True(t, d.DERP.AutoUpdate)
	assert.Equal(t, 3*time.Hour, d.DERP.UpdateFrequency)
	assert.Equal(t, 30*time.Minute, d.Node.Ephemeral.InactivityTimeout)
	assert.Equal(t, "tailnet.internal", d.DNSConfig.BaseDomain)
	assert.Empty(t, d.DNSConfig.Nameservers.Global, "no third-party resolver unless the operator lists one")

	d.DNSConfig.Challenge.Resolvers[0] = "changed"
	d.DERP.URLs[0] = "https://changed.example.com/derpmap"
	*d.Prefixes.V4 = netip.MustParsePrefix("10.0.0.0/8")

	fresh := Default()
	assert.Equal(t, "9.9.9.9:53", fresh.DNSConfig.Challenge.Resolvers[0], "each Default is its own copy")
	assert.Equal(t, types.HTTPURL("https://controlplane.tailscale.com/derpmap/default"), fresh.DERP.URLs[0], "each Default is its own copy")
	assert.Equal(t, netip.MustParsePrefix("100.64.0.0/10"), *fresh.Prefixes.V4, "each Default is its own copy")
}

// TestValidateHintsNameDefaults: the defaults Validate's hints quote, which
// types cannot read from Default, are Default's.
func TestValidateHintsNameDefaults(t *testing.T) {
	d := Default()

	cfg := Default()
	cfg.Tuning.BatchChangeDelay = 0
	cfg.Tuning.NodeStoreBatchSize = 0
	cfg.Tuning.NodeStoreBatchTimeout = 0

	err := Validate(&cfg)
	require.ErrorContains(t, err, fmt.Sprintf("(default: %s)", d.Tuning.BatchChangeDelay))
	require.ErrorContains(t, err, fmt.Sprintf("(default: %d)", d.Tuning.NodeStoreBatchSize))
	require.ErrorContains(t, err, fmt.Sprintf("(default: %s)", d.Tuning.NodeStoreBatchTimeout))
}

// TestValidateGoData: a Config built in Go, which no loader parsed, is
// held to what the loader enforces.
func TestValidateGoData(t *testing.T) {
	t.Run("default needs the operator's values", func(t *testing.T) {
		d := Default()
		assert.Equal(t, []string{"server_url is required"}, reasons(types.ConfigErrors(Validate(&d))))
	})

	t.Run("zero config", func(t *testing.T) {
		require.Error(t, Validate(&types.Config{}))
	})

	tests := []struct {
		name    string
		set     func(*types.Config)
		wantErr string // "" validates
		hidden  string // never in the error
	}{
		{name: "valid", set: func(*types.Config) {}},
		{
			name:    "log level",
			set:     func(c *types.Config) { c.Log.Level = "verbose" },
			wantErr: "log.level has an unsupported value",
		},
		{
			name:    "enum",
			set:     func(c *types.Config) { c.Log.Format = "xml" },
			wantErr: "log.format has an unsupported value",
		},
		{
			name:    "file mode",
			set:     func(c *types.Config) { c.UnixSocketPermission = 0o7777 },
			wantErr: "unix_socket_permission is not a quoted octal file mode",
		},
		{
			name:    "listen address",
			set:     func(c *types.Config) { c.Addr = "nowhere" },
			wantErr: "listen_addr is not a host:port address",
		},
		{
			name:    "listen address empty",
			set:     func(c *types.Config) { c.Addr = "" },
			wantErr: "listen_addr is required",
		},
		{
			name:    "listen address blank",
			set:     func(c *types.Config) { c.Addr = " " },
			wantErr: "listen_addr is not a host:port address",
		},
		{
			name: "listen address random port",
			set:  func(c *types.Config) { c.Addr = ":0" },
		},
		{
			name: "sqlite path empty",
			set: func(c *types.Config) {
				c.Database.Type = types.DatabaseSqliteShort
				c.Database.Sqlite.Path = ""
			},
			wantErr: "database.sqlite.path is required when database.type is sqlite",
		},
		{
			name: "sqlite3 path empty",
			set: func(c *types.Config) {
				c.Database.Type = types.DatabaseSqlite
				c.Database.Sqlite.Path = ""
			},
			wantErr: "database.sqlite.path is required when database.type is sqlite",
		},
		{
			name: "postgres without sqlite path",
			set: func(c *types.Config) {
				c.Database.Type = types.DatabasePostgres
				c.Database.Sqlite.Path = ""
			},
		},
		{
			name: "url",
			set: func(c *types.Config) {
				c.OIDC.Issuer = "ftp://marker@idp.example.com"
				c.OIDC.ClientID = "headscale"
				c.OIDC.ClientSecret = "secret"
			},
			wantErr: "oidc.issuer is not an http:// or https:// URL",
			hidden:  "marker",
		},
		{
			name: "url unparsable",
			set: func(c *types.Config) {
				c.OIDC.Issuer = "https://alice:marker-pass?@idp.example.com"
				c.OIDC.ClientID = "headscale"
				c.OIDC.ClientSecret = "secret"
			},
			wantErr: "oidc.issuer is not an http:// or https:// URL",
			hidden:  "marker",
		},
		{
			name:    "url list element",
			set:     func(c *types.Config) { c.DERP.URLs = []types.HTTPURL{"https://h/map", "ftp://u:marker@h/map"} },
			wantErr: "derp.urls[1] is not an http:// or https:// URL",
			hidden:  "marker",
		},
		{
			name: "url list",
			set:  func(c *types.Config) { c.DERP.URLs = []types.HTTPURL{"https://h/map"} },
		},
		{
			name: "prefix list element",
			set: func(c *types.Config) {
				c.TrustedProxies = []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr("10.0.0.1"), 33)}
			},
			wantErr: "trusted_proxies[0] is not a valid CIDR",
		},
		{
			name:    "zero prefix list element",
			set:     func(c *types.Config) { c.TrustedProxies = []netip.Prefix{{}} },
			wantErr: "trusted_proxies[0] is not a valid CIDR",
		},
		{
			name:    "zero prefix",
			set:     func(c *types.Config) { c.Prefixes.V4 = &netip.Prefix{} },
			wantErr: "prefixes.v4 is not a valid CIDR",
		},
		{
			name:    "batch change delay",
			set:     func(c *types.Config) { c.Tuning.BatchChangeDelay = 0 },
			wantErr: "tuning.batch_change_delay must be positive",
		},
		{
			name:    "server url trailing slash",
			set:     func(c *types.Config) { c.ServerURL = "https://h/" },
			wantErr: "server_url must not end in /",
		},
		{
			name:    "server url credentials",
			set:     func(c *types.Config) { c.ServerURL = "https://marker-user:marker-pass@h/" },
			wantErr: "server_url must not end in /",
			hidden:  "marker",
		},
		{
			name:    "server url username",
			set:     func(c *types.Config) { c.ServerURL = "https://marker-user@h/" },
			wantErr: "server_url must not end in /",
			hidden:  "marker",
		},
		{
			name:    "server url malformed",
			set:     func(c *types.Config) { c.ServerURL = "https://marker-user:marker-pass@h/%zz" },
			wantErr: "server_url cannot be parsed",
			hidden:  "marker",
		},
		// The parser splits off the query and fragment first: the password
		// is read as a port, which its error quotes.
		{
			name:    "server url userinfo before query",
			set:     func(c *types.Config) { c.ServerURL = "https://alice:marker-pass?@h" },
			wantErr: "server_url cannot be parsed",
			hidden:  "marker",
		},
		{
			name:    "server url userinfo before fragment",
			set:     func(c *types.Config) { c.ServerURL = "https://alice:marker-pass#@h" },
			wantErr: "server_url cannot be parsed",
			hidden:  "marker",
		},
		{
			name:    "server url invalid port",
			set:     func(c *types.Config) { c.ServerURL = "https://alice:marker-pass@h:port" },
			wantErr: "server_url cannot be parsed",
			hidden:  "marker",
		},
		{
			name:    "server url single slash",
			set:     func(c *types.Config) { c.ServerURL = "https:/alice:marker-pass@h" },
			wantErr: "server_url is missing a scheme",
			hidden:  "marker",
		},
		{
			name:    "server url without scheme shown",
			set:     func(c *types.Config) { c.ServerURL = "headscale.example.com" },
			wantErr: `server_url: "headscale.example.com"`,
		},
		// Built in Go, `""` is the text itself, not an empty value.
		{
			name:    "base domain quotes",
			set:     func(c *types.Config) { c.DNSConfig.BaseDomain = `""` },
			wantErr: "dns.base_domain is not a DNS name",
		},
		{
			name:    "base domain underscore",
			set:     func(c *types.Config) { c.DNSConfig.BaseDomain = "tail_net.example.com" },
			wantErr: "dns.base_domain is not a DNS name",
		},
		{
			name: "base domain trailing dot",
			set:  func(c *types.Config) { c.DNSConfig.BaseDomain = "tailnet.example.com." },
		},
		{
			name: "base domain uppercase",
			set:  func(c *types.Config) { c.DNSConfig.BaseDomain = "Tailnet.Example.com" },
		},
		// One error per problem: the rules that predate the value checks
		// keep only the empty value.
		{
			name:    "policy mode",
			set:     func(c *types.Config) { c.Policy.Mode = "bogus" },
			wantErr: "policy.mode has an unsupported value",
		},
		{
			name:    "policy mode empty",
			set:     func(c *types.Config) { c.Policy.Mode = "" },
			wantErr: "policy.mode has an unsupported value",
		},
		{
			name:    "database type",
			set:     func(c *types.Config) { c.Database.Type = "bogus" },
			wantErr: "database.type has an unsupported value",
		},
		{
			name:    "allocation",
			set:     func(c *types.Config) { c.Prefixes.Allocation = "bogus" },
			wantErr: "prefixes.allocation has an unsupported value",
		},
		{
			name:    "acme challenge",
			set:     func(c *types.Config) { c.TLS.ACME.ChallengeType = "bogus" },
			wantErr: "tls.acme.challenge_type has an unsupported value",
		},
		{
			name: "pkce method",
			set: func(c *types.Config) {
				c.OIDC.Issuer = "https://idp.example.com"
				c.OIDC.ClientID = "headscale"
				c.OIDC.ClientSecret = "secret"
				c.OIDC.PKCE.Method = "bogus"
			},
			wantErr: "oidc.pkce.method has an unsupported value",
		},
		{
			name:    "metrics listen address",
			set:     func(c *types.Config) { c.MetricsAddr = "nowhere" },
			wantErr: "metrics_listen_addr is not a host:port address",
		},
		// The keys are compared as startup opens them.
		{
			name:    "derp key relative alias",
			set:     sharedKeys("shared.key", "/etc/headscale/shared.key"),
			wantErr: "derp.server.private_key_path must differ from noise.private_key_path",
		},
		{
			name:    "derp key unclean alias",
			set:     sharedKeys("/etc/headscale/shared.key", "/etc/headscale/./keys/../shared.key"),
			wantErr: "derp.server.private_key_path must differ from noise.private_key_path",
		},
		{
			name: "derp key distinct",
			set:  sharedKeys("shared.key", "/etc/shared.key"),
		},
		// An embedder's Config has no ConfigDir: startup opens a relative
		// path from the working directory.
		{
			name: "derp key alias without config dir",
			set: func(c *types.Config) {
				wd, err := os.Getwd()
				require.NoError(t, err)

				sharedKeys("shared.key", filepath.Join(wd, "shared.key"))(c)
				c.ConfigDir = ""
			},
			wantErr: "derp.server.private_key_path must differ from noise.private_key_path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.set(&cfg)

			err := Validate(&cfg)
			if tt.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.ErrorContains(t, err, tt.wantErr)
			require.ErrorIs(t, err, types.ErrConfig)
			assert.Len(t, types.ConfigErrors(err), 1, err.Error())

			if tt.hidden != "" {
				requireHidden(t, err, tt.hidden)
			}
		})
	}
}

// TestRequiredWhenBlank: each key serve cannot run without, blanked, gets
// one reason in the form requiredKeys reads, so a key whose default goes
// away shows up as required.
func TestRequiredWhenBlank(t *testing.T) {
	for _, key := range []string{"server_url", "listen_addr", "noise.private_key_path", "database.sqlite.path"} {
		t.Run(key, func(t *testing.T) {
			cfg := Default()
			if key != "server_url" {
				cfg.ServerURL = "https://headscale.example.com"
			}

			blanked := false

			for _, f := range types.ConfigFields(&cfg) {
				if f.Path == key {
					f.Value.SetZero()

					blanked = true
				}
			}

			require.True(t, blanked, "no leaf %s", key)

			var got []string

			for _, r := range reasons(types.ConfigErrors(Validate(&cfg))) {
				if strings.HasPrefix(r, key+" is required") {
					got = append(got, r)
				}
			}

			assert.Len(t, got, 1, "reasons naming %s as required: %v", key, got)
		})
	}
}

// sharedKeys enables the embedded DERP server with these noise and DERP key
// paths, relative ones resolved against /etc/headscale.
func sharedKeys(noise, derp string) func(*types.Config) {
	return func(c *types.Config) {
		c.ConfigDir = "/etc/headscale"
		c.Noise.PrivateKeyPath = noise
		c.DERP.Server.Enabled = true
		c.DERP.Server.STUNAddr = "0.0.0.0:3478"
		c.DERP.Server.PrivateKeyPath = derp
	}
}
