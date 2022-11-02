package hsic

import (
	"time"
)

const (
	defaultEphemeralNodeInactivityTimeout = time.Second * 30
	defaultNodeUpdateCheckInterval        = time.Second * 10
)

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
func DefaultConfigYAML() string {
	yaml := `
log:
  level: trace
acl_policy_path: ""
db_type: sqlite3
db_path: /tmp/integration_test_db.sqlite3
ephemeral_node_inactivity_timeout: 30m
node_update_check_interval: 10s
ip_prefixes:
  - fd7a:115c:a1e0::/48
  - 100.64.0.0/10
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
