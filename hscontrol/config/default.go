package config

import (
	"net/netip"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/juanfont/headscale/hscontrol/types"
)

// Default is the configuration before a file or variable sets
// anything. Every key but server_url has a value a server starts with.
func Default() types.Config {
	return types.Config{
		Addr:                 "0.0.0.0:8080",
		UnixSocket:           "/var/run/headscale/headscale.sock",
		UnixSocketPermission: 0o770,
		Noise:                types.NoiseConfig{PrivateKeyPath: "/var/lib/headscale/noise_private.key"},
		Prefixes: types.PrefixesConfig{
			V4:         new(netip.MustParsePrefix("100.64.0.0/10")),
			V6:         new(netip.MustParsePrefix("fd7a:115c:a1e0::/48")),
			Allocation: types.IPAllocationStrategySequential,
		},
		Policy: types.PolicyConfig{Mode: types.PolicyModeFile},
		Log:    types.LogConfig{Level: "info", Format: types.TextLogFormat},
		Node: types.NodeConfig{
			Ephemeral: types.EphemeralConfig{InactivityTimeout: 30 * time.Minute},
			Routes: types.RouteConfig{HA: types.HARouteConfig{
				ProbeInterval: 10 * time.Second,
				ProbeTimeout:  5 * time.Second,
			}},
		},
		PreAuthKeys: types.PreAuthKeysConfig{RevokedRetention: 168 * time.Hour},
		DERP: types.DERPConfig{
			Server: types.DERPServerConfig{
				VerifyClients:                      true,
				AutomaticallyAddEmbeddedDerpRegion: true,
			},
			URLs:            []types.HTTPURL{"https://controlplane.tailscale.com/derpmap/default"},
			AutoUpdate:      true,
			UpdateFrequency: 3 * time.Hour,
		},
		Database: types.DatabaseConfig{
			Type: types.DatabaseSqliteShort,
			Sqlite: types.SqliteConfig{
				Path:              "/var/lib/headscale/db.sqlite",
				WriteAheadLog:     true,
				WALAutoCheckPoint: 1000, // SQLite default
			},
			Postgres: types.PostgresConfig{
				Ssl:                 "false",
				MaxOpenConnections:  10,
				MaxIdleConnections:  10,
				ConnMaxIdleTimeSecs: 3600,
			},
		},
		DNSConfig: types.DNSConfig{
			MagicDNS:         true,
			BaseDomain:       types.DefaultBaseDomain,
			OverrideLocalDNS: true,
			Nameservers:      types.Nameservers{Global: []string{}, Split: map[string][]string{}},
			SearchDomains:    []string{},
			Challenge: types.DNSChallengeConfig{
				PropagationTimeout: 2 * time.Minute,
				Resolvers:          types.DefaultChallengeResolvers(),
			},
		},
		TLS: types.TLSConfig{ACME: types.ACMEConfig{
			ChallengeType: types.HTTP01ChallengeType,
			HTTPListen:    ":http",
			CacheDir:      "/var/lib/headscale/cache",
		}},
		OIDC: types.OIDCConfig{
			OnlyStartIfOIDCIsAvailable: true,
			Scope:                      []string{oidc.ScopeOpenID, "profile", "email"},
			EmailVerifiedRequired:      true,
			PKCE:                       types.PKCEConfig{Method: types.PKCEMethodS256},
		},
		Taildrop: types.TaildropConfig{Enabled: true},
		CLI:      types.CLIConfig{Timeout: 5 * time.Second},
		Tuning: types.Tuning{
			BatchChangeDelay:               800 * time.Millisecond,
			NodeMapSessionBufferedChanSize: 30,
			NodeStoreBatchSize:             100,
			NodeStoreBatchTimeout:          500 * time.Millisecond,
			RegisterCacheExpiration:        15 * time.Minute,
			RegisterCacheMaxEntries:        1024,
		},
	}
}
