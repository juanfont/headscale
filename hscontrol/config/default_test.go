package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validConfig is Default with the values it leaves to the operator set, so
// it passes Validate.
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
		assert.Equal(t, []string{
			"noise.private_key_path is required",
			"server_url is missing a scheme",
			"dns.nameservers.global is required when dns.override_local_dns is true",
			"database.type has an unsupported value",
			"dns.base_domain is required when dns.magic_dns is true",
			"no IP prefix configured for the tailnet",
		}, reasons(types.ConfigErrors(Validate(&d))))
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
