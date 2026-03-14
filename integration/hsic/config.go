package hsic

import "github.com/juanfont/headscale/hscontrol/types"

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
		"HEADSCALE_POLICY_PATH":                       "",
		"HEADSCALE_DATABASE_TYPE":                     "sqlite",
		"HEADSCALE_DATABASE_SQLITE_PATH":              "/tmp/integration_test_db.sqlite3",
		"HEADSCALE_DATABASE_DEBUG":                    "0",
		"HEADSCALE_DATABASE_GORM_SLOW_THRESHOLD":      "1",
		"HEADSCALE_EPHEMERAL_NODE_INACTIVITY_TIMEOUT": "30m",
		"HEADSCALE_PREFIXES_V4":                       "100.64.0.0/10",
		"HEADSCALE_PREFIXES_V6":                       "fd7a:115c:a1e0::/48",
		"HEADSCALE_DNS_BASE_DOMAIN":                   "headscale.net",
		"HEADSCALE_DNS_MAGIC_DNS":                     "true",
		"HEADSCALE_DNS_OVERRIDE_LOCAL_DNS":            "false",
		"HEADSCALE_DNS_NAMESERVERS_GLOBAL":            "127.0.0.11 1.1.1.1",
		"HEADSCALE_PRIVATE_KEY_PATH":                  "/tmp/private.key",
		"HEADSCALE_NOISE_PRIVATE_KEY_PATH":            "/tmp/noise_private.key",
		"HEADSCALE_METRICS_LISTEN_ADDR":               "0.0.0.0:9090",
		"HEADSCALE_DEBUG_PORT":                        "40000",

		// Embedded DERP is the default for test isolation.
		// Tests should not depend on external DERP infrastructure.
		// Use WithPublicDERP() to opt out for tests that explicitly
		// need public DERP relays.
		"HEADSCALE_DERP_URLS":                    "",
		"HEADSCALE_DERP_AUTO_UPDATE_ENABLED":     "false",
		"HEADSCALE_DERP_UPDATE_FREQUENCY":        "1m",
		"HEADSCALE_DERP_SERVER_ENABLED":          "true",
		"HEADSCALE_DERP_SERVER_REGION_ID":        "999",
		"HEADSCALE_DERP_SERVER_REGION_CODE":      "headscale",
		"HEADSCALE_DERP_SERVER_REGION_NAME":      "Headscale Embedded DERP",
		"HEADSCALE_DERP_SERVER_STUN_LISTEN_ADDR": "0.0.0.0:3478",
		"HEADSCALE_DERP_SERVER_PRIVATE_KEY_PATH": "/tmp/derp.key",
		"DERP_DEBUG_LOGS":                        "true",
		"DERP_PROBER_DEBUG_LOGS":                 "true",

		// Docker containers cannot reliably resolve other container
		// hostnames for DERP connections. Advertise the embedded DERP
		// server by IP address instead of hostname.
		"HEADSCALE_DEBUG_DERP_USE_IP": "1",

		// a bunch of tests (ACL/Policy) rely on predictable IP alloc,
		// so ensure the sequential alloc is used by default.
		"HEADSCALE_PREFIXES_ALLOCATION": string(types.IPAllocationStrategySequential),
	}
}
