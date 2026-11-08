package types

import (
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestURLKeys: every key that may hold a URL is listed, so its userinfo is
// redacted and never shown in an error, and every listed key exists.
func TestURLKeys(t *testing.T) {
	paths := map[string]bool{}

	for _, f := range ConfigFields(&Config{}) {
		paths[f.Path] = true

		typ := f.Field.Type
		if typ.Kind() == reflect.Slice {
			typ = typ.Elem()
		}

		// shortcut: catches only HTTPURL leaves, lists of them and names ending
		// in url, urls or address, not maps or pointers; list any other URL
		// key in URLKeys by hand.
		name := f.Path[strings.LastIndex(f.Path, ".")+1:]
		if typ == reflect.TypeFor[HTTPURL]() || strings.HasSuffix(name, "url") || strings.HasSuffix(name, "urls") ||
			strings.HasSuffix(name, "address") {
			assert.Contains(t, URLKeys, f.Path)
		}
	}

	for _, k := range URLKeys {
		assert.True(t, paths[k], "%s is no key", k)
	}
}

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

func TestConfigTree(t *testing.T) {
	wantSections := []string{
		"noise",
		"prefixes",
		"policy",
		"log",
		"node",
		"node.ephemeral",
		"node.routes",
		"node.routes.ha",
		"preauth_keys",
		"derp",
		"derp.server",
		"database",
		"database.gorm",
		"database.sqlite",
		"database.postgres",
		"dns",
		"dns.nameservers",
		"dns.certificates",
		"dns.challenge",
		"tls",
		"tls.acme",
		"oidc",
		"oidc.pkce",
		"logtail",
		"taildrop",
		"auto_update",
		"cli",
		"tuning",
	}

	var cfg Config

	tree := ConfigTree(&cfg)

	var gotSections []string

	for i, f := range tree {
		if f.Doc == "" {
			t.Errorf("%s has no doc", f.Path)
		}

		if !f.Section {
			continue
		}

		gotSections = append(gotSections, f.Path)

		if i+1 == len(tree) || !strings.HasPrefix(tree[i+1].Path, f.Path+".") {
			t.Errorf("section %s is not directly before its first key", f.Path)
		}
	}

	if diff := cmp.Diff(wantSections, gotSections); diff != "" {
		t.Errorf("ConfigTree sections (-want +got):\n%s", diff)
	}
}

var (
	goDocLink   = regexp.MustCompile(`\[[A-Za-z][\w.]*\](\(?)`)
	codeSpan    = regexp.MustCompile("`([^`]*)`")
	linkTarget  = regexp.MustCompile(`\]\([^)]*\)`)
	docWord     = regexp.MustCompile(`[A-Za-z0-9_.]+`)
	keyLike     = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_<>]+)+$`)
	placeholder = regexp.MustCompile(`^<[a-z_]+>$`)
	angleWord   = regexp.MustCompile(`<[A-Za-z][\w-]*>`)
	snakeCase   = regexp.MustCompile(`^[a-z0-9]+(_[a-z0-9]+)+$`)
	camelCase   = regexp.MustCompile(`[a-z][A-Z]`)
)

// docSchema is what the doc style rules check a doc against.
type docSchema struct {
	paths, open, top, lastSegments, goNames map[string]bool
}

func newDocSchema(tree []ConfigField) docSchema {
	s := docSchema{
		paths: map[string]bool{}, open: map[string]bool{}, top: map[string]bool{},
		lastSegments: map[string]bool{}, goNames: map[string]bool{},
	}
	structs := []reflect.Type{reflect.TypeFor[Config]()}

	for _, f := range tree {
		s.paths[f.Path] = true
		s.open[f.Path] = f.Open

		first, _, nested := strings.Cut(f.Path, ".")
		s.top[first] = true

		if last := f.Path[strings.LastIndex(f.Path, ".")+1:]; nested && snakeCase.MatchString(last) {
			s.lastSegments[last] = true
		}

		if f.Section {
			structs = append(structs, f.Field.Type)
		}
	}

	for _, typ := range structs {
		for f := range typ.Fields() {
			if f.IsExported() && camelCase.MatchString(f.Name) && f.Name != "MagicDNS" {
				s.goNames[f.Name] = true
			}
		}
	}

	return s
}

// bare is text outside code spans and link targets.
func bare(text string) string {
	return linkTarget.ReplaceAllString(codeSpan.ReplaceAllString(text, " "), "]")
}

func bareWords(text string) []string {
	words := docWord.FindAllString(bare(text), -1)
	for i, w := range words {
		words[i] = strings.TrimRight(w, ".")
	}

	return words
}

// goDocLinks are [Name] links a Markdown renderer leaves as text.
func (docSchema) goDocLinks(text string) []string {
	var bad []string

	for _, m := range goDocLink.FindAllStringSubmatch(text, -1) {
		if m[1] == "" {
			bad = append(bad, m[0])
		}
	}

	return bad
}

// bareKeys are keys written outside backticks: a dotted or snake_case
// path, or the snake_case leaf of a nested one.
func (s docSchema) bareKeys(text string) []string {
	var bad []string

	for _, w := range bareWords(text) {
		if (strings.ContainsAny(w, "._") && s.paths[w]) || s.lastSegments[w] {
			bad = append(bad, w)
		}
	}

	return bad
}

// unknownKeys are backticked keys under a top-level key that name no key,
// nor an open map's entry placeholder.
func (s docSchema) unknownKeys(text string) []string {
	var bad []string

	for _, m := range codeSpan.FindAllStringSubmatch(text, -1) {
		key := m[1]
		first, _, _ := strings.Cut(key, ".")

		if !keyLike.MatchString(key) || !s.top[first] || s.paths[key] {
			continue
		}

		i := strings.LastIndex(key, ".")
		if !s.open[key[:i]] || !placeholder.MatchString(key[i+1:]) {
			bad = append(bad, key)
		}
	}

	return bad
}

func (s docSchema) goFieldNames(text string) []string {
	return slices.DeleteFunc(bareWords(text), func(w string) bool { return !s.goNames[w] })
}

// markup is what Markdown swallows as HTML, or a template engine runs.
func (docSchema) markup(text string) []string {
	bad := angleWord.FindAllString(bare(text), -1)

	for _, s := range []string{"{{", "{%", "{#"} {
		if strings.Contains(text, s) {
			bad = append(bad, s)
		}
	}

	return bad
}

// undocumentedValues lists the values of each enum in tree that has a
// documented value but not all of them.
func undocumentedValues(tree []ConfigField) []string {
	type enum interface{ Allowed() []string }

	var bad []string

	for _, f := range tree {
		e, ok := reflect.TypeAssert[enum](f.Value)
		prefix := f.Field.Type.Name() + "="

		if !ok || !slices.ContainsFunc(slices.Collect(maps.Keys(configValueDocs)), func(k string) bool {
			return strings.HasPrefix(k, prefix)
		}) {
			continue
		}

		for _, v := range e.Allowed() {
			if ConfigValueDoc(f.Field.Type, v) == "" {
				bad = append(bad, f.Path+": "+v)
			}
		}
	}

	return bad
}

// TestConfigDocsStyle keeps the field and value docs readable where they
// are printed: YAML comments, the reference page and NixOS descriptions.
func TestConfigDocsStyle(t *testing.T) {
	tree := ConfigTree(new(Config))
	schema := newDocSchema(tree)

	type doc struct{ at, text string }

	docs := make([]doc, 0, len(tree)+len(configValueDocs))
	for _, f := range tree {
		docs = append(docs, doc{f.Path, f.Doc})
	}

	for _, k := range slices.Sorted(maps.Keys(configValueDocs)) {
		docs = append(docs, doc{k, configValueDocs[k]})
	}

	// Each rule has docs it must reject, one per clause, so it cannot pass
	// vacuously, and docs it must accept, so it does not flag good prose.
	rules := []struct {
		name    string
		check   func(text string) []string
		rejects []string
		accepts []string
	}{
		{
			name:    "no Go doc links",
			check:   schema.goDocLinks,
			rejects: []string{"With TLS as [Config.TLS] sets it up."},
			accepts: []string{"See [DNS](https://headscale.net/stable/ref/dns/)."},
		},
		{
			name:    "keys in backticks",
			check:   schema.bareKeys,
			rejects: []string{"Requires dns.base_domain.", "Applied only when write_ahead_log is true."},
			accepts: []string{"Each node below `dns.base_domain`, as the policy allows; see [DNS](https://headscale.net/stable/ref/dns/)."},
		},
		{
			name:    "backticked keys exist",
			check:   schema.unknownKeys,
			rejects: []string{"Set `dns.challenge.provider.name`."},
			accepts: []string{"Set `dns.challenge.provider.<setting>` or `dns.base_domain`, e.g. `1.1.1.1:53` in `config.yaml`."},
		},
		{
			name:    "no Go field names",
			check:   schema.goFieldNames,
			rejects: []string{"Reloads every UpdateFrequency."},
			accepts: []string{"Requires MagicDNS and an IPv4 address."},
		},
		{
			name:    "no markup Markdown or templates eat",
			check:   schema.markup,
			rejects: []string{"Reads file:<path>.", "Shows {{ .Name }}.", "Shows {% raw %}.", "Shows {# note #}."},
			accepts: []string{"Reads `file:<path>`; shows `<redacted>`."},
		},
	}

	for _, rule := range rules {
		t.Run(rule.name, func(t *testing.T) {
			for _, text := range rule.rejects {
				assert.NotEmpty(t, rule.check(text), "rejects %q", text)
			}

			for _, text := range rule.accepts {
				assert.Empty(t, rule.check(text), "accepts %q", text)
			}

			var offenders []string

			for _, d := range docs {
				for _, bad := range rule.check(d.text) {
					offenders = append(offenders, d.at+": "+bad)
				}
			}

			assert.Empty(t, offenders)
		})
	}

	t.Run("enums document every value", func(t *testing.T) {
		assert.Empty(t, undocumentedValues(tree))
		assert.NotEmpty(t, ConfigValueDoc(reflect.TypeFor[PolicyMode](), "database"))
	})
}
