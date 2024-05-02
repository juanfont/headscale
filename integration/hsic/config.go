package hsic

import "github.com/juanfont/headscale/hscontrol/types"

// const (
// 	defaultEphemeralNodeInactivityTimeout = time.Second * 30
// 	defaultNodeUpdateCheckInterval        = time.Second * 10
// )

// TODO(kradalby): This approach doesnt work because we cannot
// serialise our config object to YAML or JSON.
// func DefaultConfig() headscale.Config {
// 	derpMap, _ := url.Parse("https://controlplane.tailscale.com/derpmap/default")
//
// 	config := headscale.Config{
// 		Log: headscale.LogConfig{
// 			Level: zerolog.TraceLevel,
// 		},
// 		ACL:                            headscale.GetACLConfig(),
// 		DBtype:                         "sqlite3",
// 		EphemeralNodeInactivityTimeout: defaultEphemeralNodeInactivityTimeout,
// 		NodeUpdateCheckInterval:        defaultNodeUpdateCheckInterval,
// 		IPPrefixes: []netip.Prefix{
// 			netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
// 			netip.MustParsePrefix("100.64.0.0/10"),
// 		},
// 		DNSConfig: &tailcfg.DNSConfig{
// 			Proxied: true,
// 			Nameservers: []netip.Addr{
// 				netip.MustParseAddr("127.0.0.11"),
// 				netip.MustParseAddr("1.1.1.1"),
// 			},
// 			Resolvers: []*dnstype.Resolver{
// 				{
// 					Addr: "127.0.0.11",
// 				},
// 				{
// 					Addr: "1.1.1.1",
// 				},
// 			},
// 		},
// 		BaseDomain: "headscale.net",
//
// 		DBpath: "/tmp/integration_test_db.sqlite3",
//
// 		PrivateKeyPath:      "/tmp/integration_private.key",
// 		NoisePrivateKeyPath: "/tmp/noise_integration_private.key",
// 		Addr:                "0.0.0.0:8080",
// 		MetricsAddr:         "127.0.0.1:9090",
// 		ServerURL:           "http://headscale:8080",
//
// 		DERP: headscale.DERPConfig{
// 			URLs: []url.URL{
// 				*derpMap,
// 			},
// 			AutoUpdate:      false,
// 			UpdateFrequency: 1 * time.Minute,
// 		},
// 	}
//
// 	return config
// }

// TODO: Reuse the actual configuration object above.
// Deprecated: use env function instead as it is easier to
// override.
func DefaultConfigYAML() string {
	yaml := `
log:
  level: trace
acl_policy_path: ""
database:
  type: sqlite3
  sqlite.path: /tmp/integration_test_db.sqlite3
ephemeral_node_inactivity_timeout: 30m
prefixes:
  v6: fd7a:115c:a1e0::/48
  v4: 100.64.0.0/10
dns_config:
  base_domain: headscale.net
  magic_dns: true
  domains: []
  nameservers:
    - 127.0.0.11
    - 1.1.1.1
private_key_path: /tmp/private.key
noise:
  private_key_path: /tmp/noise_private.key
listen_addr: 0.0.0.0:8080
metrics_listen_addr: 127.0.0.1:9090
server_url: http://headscale:8080

derp:
  urls:
    - https://controlplane.tailscale.com/derpmap/default
  auto_update_enabled: false
  update_frequency: 1m
`

	return yaml
}

func MinimumConfigYAML() string {
	return `
private_key_path: /tmp/private.key
noise:
  private_key_path: /tmp/noise_private.key
`
}

func DefaultConfigEnv() map[string]string {
	return map[string]string{
		"HEADSCALE_LOG_LEVEL":                         "trace",
		"HEADSCALE_ACL_POLICY_PATH":                   "",
		"HEADSCALE_DATABASE_TYPE":                     "sqlite",
		"HEADSCALE_DATABASE_SQLITE_PATH":              "/tmp/integration_test_db.sqlite3",
		"HEADSCALE_EPHEMERAL_NODE_INACTIVITY_TIMEOUT": "30m",
		"HEADSCALE_PREFIXES_V4":                       "100.64.0.0/10",
		"HEADSCALE_PREFIXES_V6":                       "fd7a:115c:a1e0::/48",
		"HEADSCALE_DNS_CONFIG_BASE_DOMAIN":            "headscale.net",
		"HEADSCALE_DNS_CONFIG_MAGIC_DNS":              "true",
		"HEADSCALE_DNS_CONFIG_DOMAINS":                "",
		"HEADSCALE_DNS_CONFIG_NAMESERVERS":            "127.0.0.11 1.1.1.1",
		"HEADSCALE_PRIVATE_KEY_PATH":                  "/tmp/private.key",
		"HEADSCALE_NOISE_PRIVATE_KEY_PATH":            "/tmp/noise_private.key",
		"HEADSCALE_LISTEN_ADDR":                       "0.0.0.0:8080",
		"HEADSCALE_METRICS_LISTEN_ADDR":               "0.0.0.0:9090",
		"HEADSCALE_SERVER_URL":                        "http://headscale:8080",
		"HEADSCALE_DERP_URLS":                         "https://controlplane.tailscale.com/derpmap/default",
		"HEADSCALE_DERP_AUTO_UPDATE_ENABLED":          "false",
		"HEADSCALE_DERP_UPDATE_FREQUENCY":             "1m",

		// a bunch of tests (ACL/Policy) rely on predicable IP alloc,
		// so ensure the sequential alloc is used by default.
		"HEADSCALE_PREFIXES_ALLOCATION": string(types.IPAllocationStrategySequential),
	}
}
