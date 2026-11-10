package types

import (
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.yaml.in/yaml/v3"
)

// keyPosition returns the 1-based position of the key at path in src.
// JSON and hujson.Standardize output are valid YAML, so one parser serves all.
// Keys match case-insensitively, as viper lowercased them.
func keyPosition(src []byte, path []string) (int, int, bool) {
	var doc yaml.Node
	if yaml.Unmarshal(src, &doc) != nil || len(doc.Content) == 0 {
		return 0, 0, false
	}

	n := doc.Content[0]

	var key *yaml.Node

	for _, want := range path {
		if n.Kind != yaml.MappingNode {
			return 0, 0, false
		}

		key = nil

		// Last duplicate wins, matching the JSON parser's effective value.
		for i := len(n.Content) - 2; i >= 0; i -= 2 {
			if strings.EqualFold(n.Content[i].Value, want) {
				key, n = n.Content[i], n.Content[i+1]

				break
			}
		}

		if key == nil {
			return 0, 0, false
		}
	}

	if key == nil {
		return 0, 0, false
	}

	return key.Line, key.Column, true
}

// configKeys lists every key the loader reads, so env mapping and the strict
// pass know the schema. Open maps are in openMapKeys.
var configKeys = []string{
	"server_url",
	"listen_addr",
	"metrics_listen_addr",
	"unix_socket",
	"unix_socket_permission",
	"trusted_proxies",
	"disable_check_updates",
	"noise.private_key_path",
	"prefixes.v4",
	"prefixes.v6",
	"prefixes.allocation",
	"policy.path",
	"policy.mode",
	"log.level",
	"log.format",
	"node.expiry",
	"node.ephemeral.inactivity_timeout",
	"node.routes.ha.probe_interval",
	"node.routes.ha.probe_timeout",
	"preauth_keys.revoked_retention",
	"derp.server.enabled",
	"derp.server.region_id",
	"derp.server.region_code",
	"derp.server.region_name",
	"derp.server.verify_clients",
	"derp.server.stun.enabled",
	"derp.server.stun_listen_addr",
	"derp.server.private_key_path",
	"derp.server.ipv4",
	"derp.server.ipv6",
	"derp.server.automatically_add_embedded_derp_region",
	"derp.urls",
	"derp.paths",
	"derp.auto_update_enabled",
	"derp.update_frequency",
	"database.type",
	"database.debug",
	"database.gorm.skip_err_record_not_found",
	"database.gorm.slow_threshold",
	"database.gorm.parameterized_queries",
	"database.sqlite.path",
	"database.sqlite.write_ahead_log",
	"database.sqlite.wal_autocheckpoint",
	"database.postgres.host",
	"database.postgres.port",
	"database.postgres.name",
	"database.postgres.user",
	"database.postgres.pass",
	"database.postgres.ssl",
	"database.postgres.max_open_conns",
	"database.postgres.max_idle_conns",
	"database.postgres.conn_max_idle_time_secs",
	"dns.magic_dns",
	"dns.base_domain",
	"dns.override_local_dns",
	"dns.search_domains",
	"dns.extra_records",
	"dns.extra_records_path",
	"dns.nameservers.global",
	"dns.nameservers.split",
	"dns.certificates.enabled",
	"dns.certificates.zone",
	"dns.challenge.propagation_timeout",
	"dns.challenge.resolvers",
	"dns.challenge.provider.name",
	"tls.cert_path",
	"tls.key_path",
	"tls.acme.hostname",
	"tls.acme.challenge_type",
	"tls.acme.http_listen",
	"tls.acme.cache_dir",
	"tls.acme.url",
	"tls.acme.email",
	"oidc.issuer",
	"oidc.client_id",
	"oidc.client_secret",
	"oidc.scope",
	"oidc.extra_params",
	"oidc.allowed_domains",
	"oidc.allowed_users",
	"oidc.allowed_groups",
	"oidc.email_verified_required",
	"oidc.use_expiry_from_token",
	"oidc.only_start_if_oidc_is_available",
	"oidc.pkce.enabled",
	"oidc.pkce.method",
	"logtail.enabled",
	"taildrop.enabled",
	"auto_update.enabled",
	"cli.address",
	"cli.api_key",
	"cli.timeout",
	"cli.insecure",
	"tuning.notifier_send_timeout",
	"tuning.batch_change_delay",
	"tuning.node_mapsession_buffered_chan_size",
	"tuning.batcher_workers",
	"tuning.register_cache_expiration",
	"tuning.register_cache_max_entries",
	"tuning.node_store_batch_size",
	"tuning.node_store_batch_timeout",
}

// openMapKeys hold user-chosen subkeys, so nothing below them is checked.
var openMapKeys = []string{
	"dns.nameservers.split",
	"oidc.extra_params",
	"dns.challenge.provider",
	"dns.extra_records",
}

// configDefaults are the values used when no file or environment sets a key.
var configDefaults = map[string]any{
	"policy.mode":                       "file",
	"log.level":                         "info",
	"log.format":                        TextLogFormat,
	"dns.magic_dns":                     true,
	"dns.base_domain":                   "",
	"dns.override_local_dns":            true,
	"dns.nameservers.global":            []string{},
	"dns.nameservers.split":             map[string]string{},
	"dns.search_domains":                []string{},
	"dns.certificates.enabled":          false,
	"dns.challenge.propagation_timeout": "2m",
	"derp.server.enabled":               false,
	"derp.server.verify_clients":        true,
	"derp.server.stun.enabled":          true,
	"derp.server.automatically_add_embedded_derp_region": true,
	"derp.update_frequency":                              "3h",
	"unix_socket":                                        "/var/run/headscale/headscale.sock",
	"unix_socket_permission":                             "0o770",
	"cli.timeout":                                        "5s",
	"cli.insecure":                                       false,
	"database.postgres.ssl":                              false,
	"database.postgres.max_open_conns":                   10,
	"database.postgres.max_idle_conns":                   10,
	"database.postgres.conn_max_idle_time_secs":          3600,
	"database.sqlite.write_ahead_log":                    true,
	"database.sqlite.wal_autocheckpoint":                 1000, // SQLite default
	"oidc.scope":                                         []string{oidc.ScopeOpenID, "profile", "email"},
	"oidc.only_start_if_oidc_is_available":               true,
	"oidc.use_expiry_from_token":                         false,
	"oidc.pkce.enabled":                                  false,
	"oidc.pkce.method":                                   "S256",
	"oidc.email_verified_required":                       true,
	"logtail.enabled":                                    false,
	"taildrop.enabled":                                   true,
	"auto_update.enabled":                                false,
	"node.expiry":                                        "0",
	"node.ephemeral.inactivity_timeout":                  "120s",
	"preauth_keys.revoked_retention":                     "168h",
	"node.routes.ha.probe_interval":                      "10s",
	"node.routes.ha.probe_timeout":                       "5s",
	"tuning.notifier_send_timeout":                       "800ms",
	"tuning.batch_change_delay":                          "800ms",
	"tuning.node_mapsession_buffered_chan_size":          30,
	"tuning.node_store_batch_size":                       defaultNodeStoreBatchSize,
	"tuning.node_store_batch_timeout":                    "500ms",
	"prefixes.allocation":                                string(IPAllocationStrategySequential),
	"tls.acme.challenge_type":                            HTTP01ChallengeType,
	"tls.acme.http_listen":                               ":http",
	"tls.acme.cache_dir":                                 "/var/lib/headscale/cache",
}

// removedKey is a key that once worked and is now rejected. In files Old
// matches the key and everything beneath it; for environment variables only
// the exact name, so the old dns_config.* leaves are listed too. New holds
// the replacement keys, space separated; Value, when set, is what New takes.
// Hint is free text for what the other fields cannot say.
type removedKey struct{ Old, New, Value, Since, Hint string }

var removedKeys = []removedKey{
	{Old: "acl_policy_path", New: "policy.path", Since: "0.30"},
	{Old: "dns_config", New: "dns", Since: "0.30", Hint: "move every dns_config.* key to dns (nameservers to dns.nameservers.global, restricted_nameservers to dns.nameservers.split, domains to dns.search_domains)"},
	{Old: "dns_config.magic_dns", New: "dns.magic_dns", Since: "0.30"},
	{Old: "dns_config.base_domain", New: "dns.base_domain", Since: "0.30"},
	{Old: "dns_config.override_local_dns", New: "dns.override_local_dns", Since: "0.30"},
	{Old: "dns_config.nameservers", New: "dns.nameservers.global", Since: "0.30"},
	{Old: "dns_config.restricted_nameservers", New: "dns.nameservers.split", Since: "0.30"},
	{Old: "dns_config.domains", New: "dns.search_domains", Since: "0.30"},
	{Old: "dns_config.extra_records", New: "dns.extra_records", Since: "0.30"},
	{Old: "dns_config.use_username_in_magic_dns", Since: "0.24"},
	{Old: "dns.use_username_in_magic_dns", Since: "0.24"},
	{Old: "oidc.strip_email_domain", Since: "0.26"},
	{Old: "oidc.map_legacy_users", Since: "0.26"},
	{Old: "randomize_client_port", Since: "0.29", Hint: `set "randomizeClientPort": true at the top level of the policy file, or grant the cap per node via a "nodeAttrs" entry`},
	{Old: "oidc.expiry", New: "node.expiry", Since: "0.29"},
	{Old: "ephemeral_node_inactivity_timeout", New: "node.ephemeral.inactivity_timeout", Since: "0.30"},
	{Old: "tls_cert_path", New: "tls.cert_path", Since: "0.30"},
	{Old: "tls_key_path", New: "tls.key_path", Since: "0.30"},
	{Old: "tls_letsencrypt_hostname", New: "tls.acme.hostname", Since: "0.30"},
	{Old: "tls_letsencrypt_challenge_type", New: "tls.acme.challenge_type", Since: "0.30"},
	{Old: "tls_letsencrypt_listen", New: "tls.acme.http_listen", Since: "0.30"},
	{Old: "tls_letsencrypt_cache_dir", New: "tls.acme.cache_dir", Since: "0.30"},
	{Old: "acme_url", New: "tls.acme.url", Since: "0.30"},
	{Old: "acme_email", New: "tls.acme.email", Since: "0.30"},
	{Old: "database.gorm.prepare_stmt", Since: "0.30"},
	{Old: "grpc_listen_addr", Since: "0.30"},
	{Old: "grpc_allow_insecure", Since: "0.30"},
	{Old: "db_type", New: "database.type", Since: "0.30"},
	{Old: "db_path", New: "database.sqlite.path", Since: "0.30"},
	{Old: "db_host", New: "database.postgres.host", Since: "0.30"},
	{Old: "db_port", New: "database.postgres.port", Since: "0.30"},
	{Old: "db_name", New: "database.postgres.name", Since: "0.30"},
	{Old: "db_user", New: "database.postgres.user", Since: "0.30"},
	{Old: "db_pass", New: "database.postgres.pass", Since: "0.30"},
	{Old: "db_ssl", New: "database.postgres.ssl", Since: "0.30"},
	{Old: "private_key_path", New: "noise.private_key_path", Since: "0.23"},
	{Old: "ip_prefixes", New: "prefixes.v4 prefixes.v6", Since: "0.23"},
	{Old: "log_level", New: "log.level", Since: "0.17"},
	{Old: "json_logs", New: "log.format", Value: "json", Since: "0.30"},
	{Old: "tls_client_auth_mode", Since: "0.30"},
	{Old: "node_update_check_interval", Since: "0.30"},
	{Old: "changes_check_interval", Since: "0.30"},
	{Old: "noise_private_key_path", New: "noise.private_key_path", Since: "0.30"},
	{Old: "derp_map_path", New: "derp.paths", Since: "0.30"},
	{Old: "metrics_enabled", Since: "0.30"},
	{Old: "oidc.domain_map", Since: "0.13"},
	{Old: "oidc.namespace", Since: "0.30"},
	{Old: "oidc.user", Since: "0.30"},
	{Old: "oidc.client_secret_path", New: "oidc.client_secret", Value: "file:<path>", Since: "0.30"},
	{Old: "database.postgres.password_file", New: "database.postgres.pass", Value: "file:<path>", Since: "0.30"},
}
