package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// keyNode is the file parsed for the positions of its keys.
type keyNode = yaml.Node

// keyTree parses src for the positions of its keys, or returns nil. JSON
// and hujson.Standardize output are valid YAML, so one parser serves all.
func keyTree(src []byte) *yaml.Node {
	var doc yaml.Node
	if yaml.Unmarshal(src, &doc) != nil || len(doc.Content) == 0 {
		return nil
	}

	return doc.Content[0]
}

// keyPosition returns the 1-based position of the key written as path, one
// name per mapping, below n. Keys match as [keyCase] spells them.
func keyPosition(n *yaml.Node, path []string) (int, int, bool) {
	var (
		key    *yaml.Node
		prefix string
	)

	for _, want := range path {
		if n == nil || n.Kind != yaml.MappingNode {
			return 0, 0, false
		}

		key = nil

		// Last duplicate wins, matching the JSON parser's effective value.
		for i := len(n.Content) - 2; i >= 0; i -= 2 {
			if keyCase(prefix, n.Content[i].Value) == want {
				key, n = n.Content[i], n.Content[i+1]

				break
			}
		}

		if key == nil {
			return 0, 0, false
		}

		prefix = joinConfigPath(prefix, want)
	}

	if key == nil {
		return 0, 0, false
	}

	return key.Line, key.Column, true
}

// dottedPosition returns the 1-based position of the key at the dotted
// path below n, written below prefix, however the file splits it into
// nested and dotted keys. Keys match as [keyCase] spells them. It follows
// only the keys n has, so the work is bounded by the file.
func dottedPosition(n *yaml.Node, prefix string, path []string) (int, int, bool) {
	if n == nil || n.Kind != yaml.MappingNode {
		return 0, 0, false
	}

	seen := map[string]bool{}

	// Last duplicate wins, matching the JSON parser's effective value; an
	// earlier one is shadowed, so its children were never loaded.
	for i := len(n.Content) - 2; i >= 0; i -= 2 {
		key := keyCase(prefix, n.Content[i].Value)
		if seen[key] {
			continue
		}

		seen[key] = true

		names := strings.Split(key, ".")
		if len(names) > len(path) || !slices.Equal(names, path[:len(names)]) {
			continue
		}

		if len(names) == len(path) {
			return n.Content[i].Line, n.Content[i].Column, true
		}

		line, col, ok := dottedPosition(n.Content[i+1], joinConfigPath(prefix, key), path[len(names):])
		if ok {
			return line, col, true
		}
	}

	return 0, 0, false
}

// yamlSyntaxError is the shape of a YAML syntax error, whose text after the
// line is one of libyaml's fixed problem descriptions.
var yamlSyntaxError = regexp.MustCompile(`^yaml: line [0-9]+: `)

// parseDetail is where and why err, from parsing b, a configuration file in
// format ext, found it invalid, in words that quote nothing from b: parser
// messages may quote a value, and a configuration holds secrets.
func parseDetail(ext string, b []byte, err error) string {
	var (
		jsonSyntax *json.SyntaxError
		jsonType   *json.UnmarshalTypeError
		yamlType   *yaml.TypeError
		line, col  int
	)

	switch ext = strings.ToLower(ext); {
	case errors.As(err, &jsonSyntax):
		// Offset counts the byte at fault.
		n := min(max(int(jsonSyntax.Offset)-1, 0), len(b))
		line = 1 + bytes.Count(b[:n], []byte("\n"))
		col = n - bytes.LastIndexByte(b[:n], '\n')
	case errors.As(err, &jsonType), errors.As(err, &yamlType):
		// Also a YAML key given twice; both messages quote the file.
		return "the file is not a map of unique keys"
	case (ext == ".yaml" || ext == ".yml") && yamlSyntaxError.MatchString(err.Error()):
		return err.Error()
	case ext == ".hujson":
		// hujson has no error type, only this prefix before its message.
		_, _ = fmt.Sscanf(err.Error(), "hujson: line %d, column %d:", &line, &col)
	}

	what := map[string]string{".json": "JSON", ".hujson": "HuJSON", ".yaml": "YAML", ".yml": "YAML"}[ext]
	if line == 0 {
		return "not valid " + what
	}

	return fmt.Sprintf("line %d, column %d: not valid %s", line, col, what)
}

// removedKey is a key that once worked and is now rejected. In files Old
// matches the key and everything beneath it; for environment variables only
// the exact name, so the old dns_config.* leaves are listed too. New holds
// the replacement keys, space separated; Value, when set, is what New takes.
// Hint is free text for what the other fields cannot say.
type removedKey struct{ Old, New, Value, Since, Hint string }

var removedKeys = []removedKey{
	{Old: "derp.server.stun.enabled", Since: "0.30", Hint: "remove it: headscale never read it; the embedded DERP server always serves STUN on derp.server.stun_listen_addr"},
	{Old: "tuning.notifier_send_timeout", Since: "0.30", Hint: "remove it: it had no effect"},
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
	// The NixOS module's name; headscale never read it.
	{Old: "dns.split", New: "dns.nameservers.split", Since: "0.30"},
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
	// The NixOS module's name; headscale never read it.
	{Old: "db_password_file", New: "database.postgres.pass", Value: "file:<path>", Since: "0.30"},
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
