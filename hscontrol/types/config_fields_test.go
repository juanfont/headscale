package types

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigFields(t *testing.T) {
	// Written out, not derived from the loader's key tables, so it pins the
	// schema on its own.
	wantPaths := []string{
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
		"database.gorm.slow_threshold",
		"database.gorm.skip_err_record_not_found",
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
		"dns.nameservers.global",
		"dns.nameservers.split",
		"dns.search_domains",
		"dns.extra_records",
		"dns.extra_records_path",
		"dns.certificates.enabled",
		"dns.certificates.zone",
		"dns.challenge.propagation_timeout",
		"dns.challenge.resolvers",
		"dns.challenge.provider",
		"tls.cert_path",
		"tls.key_path",
		"tls.acme.hostname",
		"tls.acme.challenge_type",
		"tls.acme.http_listen",
		"tls.acme.url",
		"tls.acme.email",
		"tls.acme.cache_dir",
		"oidc.only_start_if_oidc_is_available",
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
	// dns.extra_records is a list, a leaf like any other.
	wantOpen := []string{"dns.nameservers.split", "dns.challenge.provider", "oidc.extra_params"}

	var cfg Config

	fields := ConfigFields(&cfg)
	gotPaths := make([]string, 0, len(fields))

	var gotOpen []string

	for _, f := range fields {
		gotPaths = append(gotPaths, f.Path)
		if f.Open {
			gotOpen = append(gotOpen, f.Path)
		}
	}

	if diff := cmp.Diff(wantPaths, gotPaths); diff != "" {
		t.Errorf("ConfigFields paths (-want +got):\n%s", diff)
	}

	assert.Equal(t, wantOpen, gotOpen)

	t.Run("values are the config's fields", func(t *testing.T) {
		require.Equal(t, "server_url", fields[0].Path)
		require.True(t, fields[0].Value.CanSet())

		fields[0].Value.SetString("https://h")
		assert.Equal(t, "https://h", cfg.ServerURL)
		assert.Equal(t, "ServerURL", fields[0].Field.Name)
	})

	t.Run("every exported field has a koanf tag", func(t *testing.T) {
		var check func(reflect.Type, string)

		check = func(typ reflect.Type, at string) {
			for f := range typ.Fields() {
				tag := f.Tag.Get("koanf")
				if !f.IsExported() || tag == "-" {
					continue
				}

				if tag == "" {
					t.Errorf("%s.%s has no koanf tag", at, f.Name)

					continue
				}

				if f.Type.Kind() == reflect.Struct {
					check(f.Type, at+"."+f.Name)
				}
			}
		}

		check(reflect.TypeFor[Config](), "Config")
	})
}
