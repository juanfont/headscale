package config

import (
	"encoding"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/dns"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/net/tsaddr"
	"tailscale.com/util/dnsname"
)

const dnsDocsURL = "https://headscale.net/stable/ref/dns/"

var (
	errOIDCClientIDRequired     = errors.New("oidc.client_id is required when oidc.issuer is set")
	errOIDCClientSecretRequired = errors.New("oidc.client_secret is required when oidc.issuer is set")
	errServerURLSuffix          = errors.New("server_url cannot be part of base_domain in a way that could make the DERP and headscale server unreachable")
	errServerURLSame            = errors.New("server_url cannot use the same domain as base_domain in a way that could make the DERP and headscale server unreachable")
	errInvalidPKCEMethod        = errors.New("pkce.method must be either 'plain' or 'S256'")
	errTrustedProxyZeroRange    = errors.New("0.0.0.0/0 and ::/0 are not allowed")
	errURLSyntax                = errors.New("invalid URL syntax")
)

// Validate reports every rule c breaks, in one error. It reads no file and
// logs nothing; [Warnings] holds the advisories.
func Validate(c *types.Config) error {
	v := &configValidator{}

	validateValues(c, v)

	// OIDC is activated by setting oidc.issuer (see app.go), not by a
	// dedicated oidc.enabled key. Gate validation on the real activation
	// condition so a misconfiguration fails at startup.
	if c.OIDC.Issuer != "" {
		err := validateOIDC(c.OIDC)
		if err != nil {
			v.Add(&types.ConfigError{
				Reason: "OIDC configuration is invalid",
				Detail: err.Error(),
				Hint:   "check oidc.issuer, oidc.client_id, oidc.client_secret, and oidc.pkce.method",
				Cause:  err,
			})
		}
	}

	if len(c.DNSConfig.ExtraRecords) > 0 && c.DNSConfig.ExtraRecordsPath != "" {
		v.Add(&types.ConfigError{
			Reason: "dns.extra_records and dns.extra_records_path are mutually exclusive",
			Current: []types.KV{
				{Key: "dns.extra_records_path", Value: c.DNSConfig.ExtraRecordsPath},
				{Key: "dns.extra_records", Value: "<inline records>"},
			},
			Hint: "keep one (a path is recommended for production); remove the other",
		})
	}

	acme := c.TLS.ACME
	if acme.Hostname != "" && (c.TLS.CertPath != "" || c.TLS.KeyPath != "") {
		v.Add(&types.ConfigError{
			Reason:  "tls.acme.hostname and tls.cert_path/tls.key_path are mutually exclusive",
			Current: []types.KV{{Key: "tls.acme.hostname", Value: acme.Hostname}},
			ConflictsWith: []types.KV{
				{Key: "tls.cert_path", Value: c.TLS.CertPath},
				{Key: "tls.key_path", Value: c.TLS.KeyPath},
			},
			Hint: "choose one TLS strategy and unset the other (Let's Encrypt OR a static keypair)",
			See:  "https://headscale.net/stable/ref/tls/",
		})
	}

	validateTLS(c, v)

	if c.Noise.PrivateKeyPath == "" {
		v.Add(&types.ConfigError{
			Reason: "noise.private_key_path is required",
			Hint:   "set noise.private_key_path: /var/lib/headscale/noise_private.key (or any writable path)",
			See:    "https://headscale.net/stable/setup/install/official/",
		})
	}

	if c.Addr == "" {
		v.Add(&types.ConfigError{
			Reason: "listen_addr is required",
			Hint:   `set listen_addr, e.g. "0.0.0.0:8080", or remove it for that default; ":0" picks a random port`,
		})
	}

	// Serve would bind an unnamed socket and fail to chmod it; the CLI
	// cannot dial one.
	if c.UnixSocket == "" {
		v.Add(&types.ConfigError{
			Reason: "unix_socket is required",
			Hint:   `set unix_socket, e.g. "/var/run/headscale/headscale.sock", or remove it for that default`,
		})
	}

	validateListenerCollisions(c, v)

	// Unset only: validateValues reports an unknown value, here and in the
	// other enum rules.
	if ct := acme.ChallengeType; ct == "" {
		v.Add(&types.ConfigError{
			Reason:  "tls.acme.challenge_type has an unsupported value",
			Current: []types.KV{{Key: "tls.acme.challenge_type", Value: string(ct)}},
			Allowed: ct.Allowed(),
			Hint:    "pick one of the allowed values; HTTP-01 is the default",
		})
	}

	// Shown without userinfo, which may be a credential.
	serverURL := types.HTTPURL(c.ServerURL).Redacted()

	switch {
	case c.ServerURL == "":
		v.Add(&types.ConfigError{
			Reason: "server_url is required",
			Hint:   "set server_url to the URL clients connect to, e.g. https://headscale.example.com",
		})
	case !strings.HasPrefix(c.ServerURL, "http://") && !strings.HasPrefix(c.ServerURL, "https://"):
		// Without an @ it holds no userinfo; shown, the common mistake
		// (headscale.example.com) is plain to see.
		shown := c.ServerURL
		if strings.Contains(shown, "@") {
			shown = serverURL
		}

		v.Add(&types.ConfigError{
			Reason:  "server_url is missing a scheme",
			Current: []types.KV{{Key: "server_url", Value: shown}},
			Hint:    "prefix the URL with https:// (recommended) or http://",
		})
	}

	// The loader trims it; clients would get URLs with a double slash.
	if strings.HasSuffix(c.ServerURL, "/") {
		v.Add(&types.ConfigError{
			Reason:  "server_url must not end in /",
			Current: []types.KV{{Key: "server_url", Value: serverURL}},
			Hint:    "remove the trailing slash",
		})
	}

	// Minimum inactivity time out is keepalive timeout (60s) plus a few seconds
	// to avoid races
	minInactivityTimeout := 65 * time.Second

	if ephemeralTimeout := c.Node.Ephemeral.InactivityTimeout; ephemeralTimeout <= minInactivityTimeout {
		v.Add(&types.ConfigError{
			Reason:  "node.ephemeral.inactivity_timeout is below the minimum",
			Current: []types.KV{{Key: "node.ephemeral.inactivity_timeout", Value: ephemeralTimeout.String()}},
			Minimum: minInactivityTimeout.String(),
			Hint:    "raise the value above the keepalive interval (60s) plus a safety margin",
		})
	}

	// Validate HA health probing parameters
	if ha := c.Node.Routes.HA; ha.ProbeInterval > 0 {
		if ha.ProbeInterval < 2*time.Second {
			v.Add(&types.ConfigError{
				Reason:  "node.routes.ha.probe_interval is below the minimum",
				Current: []types.KV{{Key: "node.routes.ha.probe_interval", Value: ha.ProbeInterval.String()}},
				Minimum: "2s",
				Hint:    "raise the value to at least the minimum",
			})
		}

		if ha.ProbeTimeout < 1*time.Second {
			v.Add(&types.ConfigError{
				Reason:  "node.routes.ha.probe_timeout is below the minimum",
				Current: []types.KV{{Key: "node.routes.ha.probe_timeout", Value: ha.ProbeTimeout.String()}},
				Minimum: "1s",
				Hint:    "raise the value to at least the minimum",
			})
		}

		if ha.ProbeTimeout >= ha.ProbeInterval {
			v.Add(&types.ConfigError{
				Reason: "node.routes.ha.probe_timeout must be less than node.routes.ha.probe_interval",
				Current: []types.KV{
					{Key: "node.routes.ha.probe_timeout", Value: ha.ProbeTimeout.String()},
					{Key: "node.routes.ha.probe_interval", Value: ha.ProbeInterval.String()},
				},
				Hint: "lower probe_timeout below probe_interval (a probe must finish before the next one starts)",
			})
		}
	}

	// Validate tuning parameters
	// The batcher's ticker panics on a non-positive interval.
	if delay := c.Tuning.BatchChangeDelay; delay <= 0 {
		v.Add(&types.ConfigError{
			Reason:  "tuning.batch_change_delay must be positive",
			Current: []types.KV{{Key: "tuning.batch_change_delay", Value: delay.String()}},
			Hint:    "set to a positive duration (default: 800ms)",
		})
	}

	if size := c.Tuning.NodeStoreBatchSize; size <= 0 {
		v.Add(&types.ConfigError{
			Reason:  "tuning.node_store_batch_size must be positive",
			Current: []types.KV{{Key: "tuning.node_store_batch_size", Value: size}},
			Hint:    "set to a positive integer (default: 100)",
		})
	}

	if timeout := c.Tuning.NodeStoreBatchTimeout; timeout <= 0 {
		v.Add(&types.ConfigError{
			Reason:  "tuning.node_store_batch_timeout must be positive",
			Current: []types.KV{{Key: "tuning.node_store_batch_timeout", Value: timeout.String()}},
			Hint:    "set to a positive duration (default: 500ms)",
		})
	}

	validateDERP(c, v)
	validateDatabase(c, v)
	validatePolicy(c, v)
	validateLog(c, v)
	validateMagicDNS(c, v)
	validateBaseDomain(c, v)
	validateCertificates(c, v)
	validatePrefixes(c, v)
	validateDNSProvider(c, v)

	// BaseDomain cannot be the same as the server URL.
	// This is because Tailscale takes over the domain in BaseDomain,
	// causing the headscale server and DERP to be unreachable.
	// For Tailscale upstream, the following is true:
	// - DERP run on their own domains
	// - Control plane runs on login.tailscale.com/controlplane.tailscale.com
	// - MagicDNS (BaseDomain) for users is on a *.ts.net domain per tailnet (e.g. tail-scale.ts.net)
	if base := c.DNSConfig.BaseDomain; base != "" {
		err := isSafeServerURL(c.ServerURL, base)
		if err != nil {
			addServerURLConfigError(v, serverURL, base, err)
		}
	}

	return v.Err()
}

// validateValues parses every value whose type parses text, and each
// element of a list of them, from its own text, as the loader did: a
// Config built in Go was never parsed. An empty text in a list is an error.
func validateValues(c *types.Config, v *configValidator) {
	for _, f := range types.ConfigFields(c) {
		if f.Value.Kind() != reflect.Slice {
			validateValue(v, f.Path, f.Value)

			continue
		}

		for i := range f.Value.Len() {
			key, elem := fmt.Sprintf("%s[%d]", f.Path, i), f.Value.Index(i)

			// No list gives "" a meaning: a resolver would be the local one,
			// an allowed user one without an email.
			if elem.Kind() == reflect.String && elem.Len() == 0 {
				v.Add(&types.ConfigError{Reason: key + " is empty", Hint: "remove the empty entry"})

				continue
			}

			validateValue(v, key, elem)
		}
	}
}

func validateValue(v *configValidator, key string, val reflect.Value) {
	if val.Kind() == reflect.Pointer {
		if val.IsNil() {
			return
		}

		val = val.Elem()
	}

	// The zero Prefix prints as "" and parses back.
	if p, ok := reflect.TypeAssert[netip.Prefix](val); ok {
		if !p.IsValid() {
			v.Add(&types.ConfigError{
				Reason: key + " is not a valid CIDR",
				Hint:   `use CIDR form, e.g. "100.64.0.0/10"`,
			})
		}

		return
	}

	if !reflect.PointerTo(val.Type()).Implements(textUnmarshalerType) {
		return
	}

	var (
		text []byte
		err  error
	)

	switch m, ok := reflect.TypeAssert[encoding.TextMarshaler](val); {
	case ok:
		text, err = m.MarshalText()
	case val.Kind() == reflect.String:
		text = []byte(val.String())
	default:
		return
	}

	if err == nil {
		err = reflect.New(val.Type()).Interface().(encoding.TextUnmarshaler).UnmarshalText(text) //nolint:forcetypeassert // checked above
	}

	if err == nil {
		return
	}

	// As the loader reports it: the key first, a URL's value hidden.
	var leaf *types.ConfigError
	if !errors.As(err, &leaf) {
		leaf = &types.ConfigError{Reason: err.Error(), Cause: err}
	}

	ce := *leaf
	ce.Reason = key + " " + leaf.Reason

	if val.Type() != reflect.TypeFor[types.HTTPURL]() {
		ce.Current = []types.KV{{Key: key, Value: string(text)}}
	}

	v.Add(&ce)
}

// validatePolicy records a ConfigError for an unset policy.mode: startup
// would load no policy at all and allow all traffic.
func validatePolicy(c *types.Config, v *configValidator) {
	m := c.Policy.Mode
	if m != "" {
		return
	}

	v.Add(&types.ConfigError{
		Reason:  "policy.mode has an unsupported value",
		Current: []types.KV{{Key: "policy.mode", Value: string(m)}},
		Allowed: m.Allowed(),
		See:     "https://headscale.net/stable/ref/policy/",
	})
}

// validateLog records a ConfigError for an unset log.level or log.format,
// as for the other enums: "" would run at a level or format the
// configuration does not show.
func validateLog(c *types.Config, v *configValidator) {
	if l := c.Log.Level; l == "" {
		v.Add(&types.ConfigError{
			Reason:  "log.level has an unsupported value",
			Current: []types.KV{{Key: "log.level", Value: string(l)}},
			Allowed: l.Allowed(),
			Hint:    "pick one of the allowed values; info is the default",
		})
	}

	if f := c.Log.Format; f == "" {
		v.Add(&types.ConfigError{
			Reason:  "log.format has an unsupported value",
			Current: []types.KV{{Key: "log.format", Value: string(f)}},
			Allowed: f.Allowed(),
			Hint:    "pick one of the allowed values; text is the default",
		})
	}
}

// validateDERP records ConfigErrors when the embedded DERP server is
// enabled without the addresses or paths it needs.
func validateDERP(c *types.Config, v *configValidator) {
	server := c.DERP.Server
	if !server.Enabled {
		return
	}

	// Clients never connect to region 0.
	switch id := server.RegionID; {
	case id == 0:
		v.Add(&types.ConfigError{
			Reason: "derp.server.region_id is required when the embedded DERP server is enabled",
			Current: []types.KV{
				{Key: "derp.server.enabled", Value: true},
				{Key: "derp.server.region_id", Value: 0},
			},
			Hint: "set derp.server.region_id, e.g. 999 (900-999 are for your own regions), or set derp.server.enabled: false",
			See:  "https://headscale.net/stable/ref/derp/",
		})
	case id < 0:
		v.Add(&types.ConfigError{
			Reason:  "derp.server.region_id must be positive",
			Current: []types.KV{{Key: "derp.server.region_id", Value: int(id)}},
			Hint:    "set derp.server.region_id, e.g. 999 (900-999 are for your own regions)",
			See:     "https://headscale.net/stable/ref/derp/",
		})
	}

	if server.STUNAddr == "" {
		v.Add(&types.ConfigError{
			Reason: "derp.server.stun_listen_addr is required when the embedded DERP server is enabled",
			Current: []types.KV{
				{Key: "derp.server.enabled", Value: true},
				{Key: "derp.server.stun_listen_addr", Value: ""},
			},
			Hint: `set derp.server.stun_listen_addr (e.g. "0.0.0.0:3478"), or set derp.server.enabled: false`,
			See:  "https://headscale.net/stable/ref/derp/",
		})
	}

	derpKey, noiseKey := server.PrivateKeyPath, c.Noise.PrivateKeyPath
	switch {
	case derpKey == "":
		v.Add(&types.ConfigError{
			Reason: "derp.server.private_key_path is required when the embedded DERP server is enabled",
			Current: []types.KV{
				{Key: "derp.server.enabled", Value: true},
				{Key: "derp.server.private_key_path", Value: ""},
			},
			Hint: `set derp.server.private_key_path (e.g. "/var/lib/headscale/derp_server_private.key"), or set derp.server.enabled: false`,
			See:  "https://headscale.net/stable/ref/derp/",
		})
	case keyFile(c.AbsPath(derpKey)) == keyFile(c.AbsPath(noiseKey)):
		// Resolved, as startup opens them: it would create one key file and
		// then refuse it for both uses.
		v.Add(&types.ConfigError{
			Reason: "derp.server.private_key_path must differ from noise.private_key_path",
			Current: []types.KV{
				{Key: "derp.server.private_key_path", Value: derpKey},
				{Key: "noise.private_key_path", Value: noiseKey},
			},
			Hint: `set derp.server.private_key_path to its own file (e.g. "/var/lib/headscale/derp_server_private.key")`,
			See:  "https://headscale.net/stable/ref/derp/",
		})
	}

	if !server.AutomaticallyAddEmbeddedDerpRegion && len(c.DERP.Paths) == 0 {
		v.Add(&types.ConfigError{
			Reason: "derp.paths is required when derp.server.automatically_add_embedded_derp_region is false",
			Current: []types.KV{
				{Key: "derp.server.automatically_add_embedded_derp_region", Value: false},
				{Key: "derp.paths", Value: "[]"},
			},
			Hint: "list at least one DERP map file (.yaml, .yml, .json or .hujson) in derp.paths, or set automatically_add_embedded_derp_region: true",
		})
	}
}

// validateTLS records ConfigErrors for TLS settings startup cannot use:
// half a keypair, or ACME without its HTTP-01 listener or a cache
// directory.
func validateTLS(c *types.Config, v *configValidator) {
	const see = "https://headscale.net/stable/ref/tls/"

	cert, key, acme := c.TLS.CertPath, c.TLS.KeyPath, c.TLS.ACME

	// With ACME, Validate reports any keypair path as the wrong strategy.
	if acme.Hostname == "" {
		switch {
		case cert != "" && key == "":
			v.Add(&types.ConfigError{
				Reason:  "tls.key_path is required when tls.cert_path is set",
				Current: []types.KV{{Key: "tls.cert_path", Value: cert}, {Key: "tls.key_path", Value: ""}},
				Hint:    "set tls.key_path to the certificate's PEM private key, or remove tls.cert_path to serve plain HTTP",
				See:     see,
			})
		case key != "" && cert == "":
			// Without a certificate the key is ignored and headscale serves
			// plain HTTP.
			v.Add(&types.ConfigError{
				Reason:  "tls.cert_path is required when tls.key_path is set",
				Current: []types.KV{{Key: "tls.cert_path", Value: ""}, {Key: "tls.key_path", Value: key}},
				Hint:    "set tls.cert_path to the PEM certificate, or remove tls.key_path to serve plain HTTP",
				See:     see,
			})
		}

		return
	}

	if acme.ChallengeType == types.HTTP01ChallengeType && acme.HTTPListen == "" {
		v.Add(&types.ConfigError{
			Reason:  "tls.acme.http_listen is required when tls.acme.challenge_type is HTTP-01",
			Current: []types.KV{{Key: "tls.acme.challenge_type", Value: string(acme.ChallengeType)}, {Key: "tls.acme.http_listen", Value: ""}},
			Hint:    `set tls.acme.http_listen, e.g. ":http", or remove it for that default`,
			See:     see,
		})
	}

	// Empty, certmagic keeps the account and certificate keys in the
	// working directory.
	if acme.CacheDir == "" {
		v.Add(&types.ConfigError{
			Reason:  "tls.acme.cache_dir is required when tls.acme.hostname is set",
			Current: []types.KV{{Key: "tls.acme.hostname", Value: acme.Hostname}, {Key: "tls.acme.cache_dir", Value: ""}},
			Hint:    `set tls.acme.cache_dir, e.g. "/var/lib/headscale/cache", or remove it for that default`,
			See:     see,
		})
	}
}

// keyFile is p as startup opens it, a relative path from the working
// directory (an embedder's Config has no ConfigDir).
func keyFile(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}

	return abs
}

// validateDatabase records a ConfigError when database.type is unset, or
// is sqlite without a path to open.
func validateDatabase(c *types.Config, v *configValidator) {
	const see = "https://headscale.net/stable/ref/database/"

	t := c.Database.Type

	switch {
	case t == "":
		v.Add(&types.ConfigError{
			Reason:  "database.type has an unsupported value",
			Current: []types.KV{{Key: "database.type", Value: string(t)}},
			Allowed: t.Allowed(),
			Hint:    "pick one of the allowed values; sqlite is the default for single-host deployments",
			See:     see,
		})
	case c.Database.IsSQLite() && c.Database.Sqlite.Path == "":
		v.Add(&types.ConfigError{
			Reason: "database.sqlite.path is required when database.type is sqlite",
			Current: []types.KV{
				{Key: "database.type", Value: string(t)},
				{Key: "database.sqlite.path", Value: ""},
			},
			Hint: `set database.sqlite.path, e.g. "/var/lib/headscale/db.sqlite"`,
			See:  see,
		})
	}
}

// validateMagicDNS records a ConfigError when MagicDNS is enabled without a
// base_domain.
func validateMagicDNS(c *types.Config, v *configValidator) {
	if c.DNSConfig.MagicDNS && c.DNSConfig.BaseDomain == "" {
		v.Add(&types.ConfigError{
			Reason: "dns.base_domain is required when dns.magic_dns is true",
			Current: []types.KV{
				{Key: "dns.magic_dns", Value: true},
				{Key: "dns.base_domain", Value: ""},
			},
			Hint: `set dns.base_domain to a domain you control (e.g. "ts.example.net"), or set dns.magic_dns: false`,
			See:  dnsDocsURL,
		})
	}
}

// validateBaseDomain records a ConfigError for a dns.base_domain that is
// not a DNS name.
func validateBaseDomain(c *types.Config, v *configValidator) {
	base := strings.TrimSuffix(c.DNSConfig.BaseDomain, ".")
	if base == "" || dnsname.ValidHostname(base) == nil {
		return
	}

	v.Add(&types.ConfigError{
		Reason:  "dns.base_domain is not a DNS name",
		Current: []types.KV{{Key: "dns.base_domain", Value: c.DNSConfig.BaseDomain}},
		Hint:    `use letters, digits, "-" and "."; write "" to clear it`,
		See:     dnsDocsURL,
	})
}

// validateCertificates records ConfigErrors when node certificates are
// enabled without what the Tailscale client needs: a MagicDNS name it can
// match exactly, and a provider to publish the challenge.
func validateCertificates(c *types.Config, v *configValidator) {
	ch := c.DNSConfig.Challenge
	if timeout := ch.PropagationTimeout; timeout < 0 {
		v.Add(&types.ConfigError{
			Reason:  "dns.challenge.propagation_timeout must not be negative",
			Current: []types.KV{{Key: "dns.challenge.propagation_timeout", Value: timeout.String()}},
			Hint:    "use 0 to skip waiting for the record on the zone's nameservers",
		})
	}

	enabled := c.DNSConfig.Certificates.Enabled
	challengeType := c.TLS.ACME.ChallengeType
	ownDNS01 := c.TLS.ACME.Hostname != "" && challengeType == types.DNS01ChallengeType

	if name, ok := ch.ProviderNameText(); (enabled || ownDNS01) && ok && name == "" && ch.Provider == nil {
		v.Add(&types.ConfigError{
			Reason:  "dns.certificates and tls.acme DNS-01 require dns.challenge.provider",
			Current: []types.KV{{Key: "dns.certificates.enabled", Value: enabled}, {Key: "tls.acme.challenge_type", Value: string(challengeType)}},
			Allowed: dns.ProviderNames(),
			Hint:    "configure the DNS provider that hosts dns.base_domain or tls.acme.hostname under dns.challenge.provider",
			See:     dnsDocsURL,
		})
	}

	if !enabled {
		return
	}

	if !c.DNSConfig.MagicDNS {
		v.Add(&types.ConfigError{
			Reason:  "dns.certificates requires dns.magic_dns",
			Current: []types.KV{{Key: "dns.certificates.enabled", Value: true}, {Key: "dns.magic_dns", Value: false}},
			Hint:    "certificates are issued for MagicDNS names; set dns.magic_dns: true",
			See:     dnsDocsURL,
		})
	}

	// validateBaseDomain reports a non-empty name that is not a DNS name.
	base := strings.TrimSuffix(c.DNSConfig.BaseDomain, ".")
	if base == "" || (base != strings.ToLower(base) && dnsname.ValidHostname(base) == nil) {
		v.Add(&types.ConfigError{
			Reason:  "dns.base_domain must be a lowercase DNS name for dns.certificates",
			Current: []types.KV{{Key: "dns.base_domain", Value: base}},
			Hint:    "Tailscale clients match certificate names exactly; use a lowercase public domain you control",
			See:     dnsDocsURL,
		})
	}

	zone := strings.TrimSuffix(c.DNSConfig.Certificates.Zone, ".")
	if zone != "" && base != zone && !strings.HasSuffix(base, "."+zone) {
		v.Add(&types.ConfigError{
			Reason:  "dns.base_domain is not inside dns.certificates.zone",
			Current: []types.KV{{Key: "dns.base_domain", Value: base}, {Key: "dns.certificates.zone", Value: zone}},
			Hint:    "set zone to the DNS zone that contains base_domain, or leave it empty to use base_domain",
			See:     dnsDocsURL,
		})
	}
}

// validatePrefixes records ConfigErrors for a catch-all trusted proxy, no
// node range, and no allocation strategy.
func validatePrefixes(c *types.Config, v *configValidator) {
	// 0.0.0.0/0 and ::/0 defeat the peer-trust gate and almost always
	// indicate misconfiguration.
	for i, p := range c.TrustedProxies {
		if p.Bits() == 0 {
			err := fmt.Errorf("trusted_proxies[%d] %q: %w", i, p.String(), errTrustedProxyZeroRange)
			v.Add(&types.ConfigError{
				Reason:  "trusted_proxies contains an invalid CIDR",
				Current: []types.KV{{Key: "trusted_proxies", Value: c.TrustedProxies}},
				Detail:  err.Error(),
				Hint:    "use specific proxy CIDRs; catch-all ranges are not allowed",
				Cause:   err,
			})

			break
		}
	}

	if c.Prefixes.V4 == nil && c.Prefixes.V6 == nil {
		v.Add(&types.ConfigError{
			Reason: "no IP prefix configured for the tailnet",
			Current: []types.KV{
				{Key: "prefixes.v4", Value: ""},
				{Key: "prefixes.v6", Value: ""},
			},
			Hint:  `set at least one of prefixes.v4 (default: "100.64.0.0/10") or prefixes.v6 (default: "fd7a:115c:a1e0::/48")`,
			Cause: types.ErrNoPrefixConfigured,
		})
	}

	if alloc := c.Prefixes.Allocation; alloc == "" {
		v.Add(&types.ConfigError{
			Reason:  "prefixes.allocation has an unsupported value",
			Current: []types.KV{{Key: "prefixes.allocation", Value: string(alloc)}},
			Allowed: alloc.Allowed(),
			Hint:    "pick one of the allowed values; sequential is the default",
			Cause:   types.ErrInvalidAllocationStrategy,
		})
	}
}

// validateDNSProvider builds the provider dns.challenge names, its secrets
// unread, only to report bad settings; startup builds the one it uses. A
// Go-only provider is used as it is.
func validateDNSProvider(c *types.Config, v *configValidator) {
	ch := c.DNSConfig.Challenge
	if ch.Provider != nil {
		return
	}

	name, ok := ch.ProviderNameText()
	if !ok {
		v.Add(&types.ConfigError{
			Reason:  "dns.challenge.provider.name must be a provider name",
			Allowed: dns.ProviderNames(),
			See:     dnsDocsURL,
		})

		return
	}

	if name == "" {
		return
	}

	provider, err := ch.NewProvider(keepSecret)
	// Only node certificates let a client pick what is published; a record
	// shared by headscale's own certificate alone is harmless.
	if iso, ok := provider.(dns.Isolator); ok && err == nil && c.DNSConfig.Certificates.Enabled {
		err = iso.CheckIsolation()
		if err != nil {
			err = fmt.Errorf("%w for %s: %w", dns.ErrProviderConfig, ch.ProviderName(), err)
		}
	}

	if err == nil {
		return
	}

	// The provider names only help when the name is what is wrong.
	var allowed []string
	if errors.Is(err, dns.ErrUnknownProvider) {
		allowed = dns.ProviderNames()
	}

	v.Add(&types.ConfigError{
		Reason:  "dns.challenge.provider is invalid",
		Current: []types.KV{{Key: "dns.challenge.provider.name", Value: ch.ProviderName()}},
		Detail:  err.Error(),
		Allowed: allowed,
		Hint:    `check the provider name and its settings; any string setting can be read from a file with "file:<path>"`,
		See:     dnsDocsURL,
		Cause:   err,
	})
}

// Warnings are advisories about c that do not stop headscale.
func Warnings(c *types.Config) []string {
	var warnings []string

	if c.TLS.ACME.Hostname != "" && c.TLS.ACME.ChallengeType == types.TLSALPN01ChallengeType &&
		!strings.HasSuffix(string(c.Addr), ":443") {
		// Only a warning: something in front of headscale may redirect the
		// traffic (e.g. an iptables rule).
		warnings = append(warnings, "Warning: when using tls.acme.hostname with TLS-ALPN-01 as challenge type, headscale must be reachable on port 443, i.e. listen_addr should probably end in :443")
	}

	if v4, v6 := c.Prefixes.V4, c.Prefixes.V6; (v4 != nil && outsideRange(*v4, tsaddr.CGNATRange())) ||
		(v6 != nil && outsideRange(*v6, tsaddr.TailscaleULARange())) {
		warnings = append(warnings, bannerText([]string{
			"You have overridden the default Headscale IP prefixes",
			"with a range outside of the standard CGNAT and/or ULA",
			"ranges. This is NOT a supported configuration.",
			"",
			"Using subsets of the default ranges (100.64.0.0/10 for",
			"IPv4, fd7a:115c:a1e0::/48 for IPv6) is fine. Using",
			"ranges outside of these will cause undefined behaviour",
			"as the Tailscale client is NOT designed to operate on",
			"any other ranges.",
			"",
			"Please revert your prefixes to subsets of the standard",
			"ranges as described in the example configuration.",
			"",
			"Any issue raised using a range outside of the",
			"supported range will be labelled as wontfix",
			"and closed.",
		}))
	}

	return append(warnings, c.DNSConfig.NameserverWarnings()...)
}

// outsideRange reports whether p holds addresses outside r.
func outsideRange(p, r netip.Prefix) bool {
	return p.Bits() < r.Bits() || !r.Contains(p.Addr())
}

// validatePKCEMethod rejects an unset method; validateValues reports an
// unknown one.
func validatePKCEMethod(method types.PKCEMethod) error {
	if method == "" {
		return errInvalidPKCEMethod
	}

	return nil
}

// validateOIDC checks the OIDC settings, called when oidc.issuer is set. It
// fails fast on a setup that cannot work: an invalid PKCE method or a
// missing client id/secret. The issuer's form is its type's, checked with
// every other value's.
func validateOIDC(o types.OIDCConfig) error {
	err := validatePKCEMethod(o.PKCE.Method)
	if err != nil {
		return err
	}

	if o.ClientID == "" {
		return errOIDCClientIDRequired
	}

	if o.ClientSecret == "" {
		return errOIDCClientSecretRequired
	}

	return nil
}

// listenersOverlap reports whether two parsed TCP listen addresses would
// compete for the same kernel socket. Mirrors kernel rules:
//   - different ports                              → false
//   - same port + a wildcard host on either side   → true
//   - same port + identical specific host          → true
//   - same port + different specific hosts         → false
func listenersOverlap(aHost string, aPort int, bHost string, bPort int) bool {
	if aPort != bPort {
		return false
	}

	if isWildcardHost(aHost) || isWildcardHost(bHost) {
		return true
	}

	return aHost == bHost
}

func isWildcardHost(h string) bool {
	switch h {
	case "", "0.0.0.0", "::", "[::]":
		return true
	}

	return false
}

// validateListenerCollisions records a *ConfigError for each pair of
// configured TCP listeners that would bind the same kernel socket. The
// ACME HTTP-01 challenge listener is only considered when a hostname is
// set and the HTTP-01 challenge is selected. A malformed address is
// skipped: validateValues reports it on its own key.
func validateListenerCollisions(c *types.Config, v *configValidator) {
	type spec struct {
		key, addr string
		host      string
		port      int
		parsed    bool
		active    bool
	}

	listenAddr := string(c.Addr)
	metricsAddr := string(c.MetricsAddr)
	acmeAddr := string(c.TLS.ACME.HTTPListen)

	listeners := []spec{
		{key: "listen_addr", addr: listenAddr, active: listenAddr != ""},
		{key: "metrics_listen_addr", addr: metricsAddr, active: metricsAddr != ""},
		{
			key:  "tls.acme.http_listen",
			addr: acmeAddr,
			active: acmeAddr != "" &&
				c.TLS.ACME.Hostname != "" &&
				c.TLS.ACME.ChallengeType == types.HTTP01ChallengeType,
		},
	}

	for i := range listeners {
		l := &listeners[i]
		if !l.active {
			continue
		}

		port, err := types.PortFromAddr(l.addr)
		if err != nil {
			continue
		}

		host, _, _ := net.SplitHostPort(l.addr)
		l.host = host
		l.port = port
		l.parsed = true
	}

	for i := range listeners {
		for j := i + 1; j < len(listeners); j++ {
			a, b := listeners[i], listeners[j]
			if !a.parsed || !b.parsed {
				continue
			}

			if !listenersOverlap(a.host, a.port, b.host, b.port) {
				continue
			}

			v.Add(&types.ConfigError{
				Reason:        fmt.Sprintf("%s and %s would bind the same TCP socket", a.key, b.key),
				Current:       []types.KV{{Key: a.key, Value: a.addr}},
				ConflictsWith: []types.KV{{Key: b.key, Value: b.addr}},
				Hint:          "give each listener a distinct port, or bind them to different non-wildcard hosts",
				See:           "https://headscale.net/stable/ref/tls/",
			})
		}
	}
}

// bannerText wraps lines in an ASCII-art box with a "Warning!" header, for
// critical configuration issues that users must not ignore.
func bannerText(lines []string) string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString("################################################################\n")
	b.WriteString("###      __          __              _             _         ###\n")
	b.WriteString("###      \\ \\        / /             (_)           | |        ###\n")
	b.WriteString("###       \\ \\  /\\  / /_ _ _ __ _ __  _ _ __   __ _| |        ###\n")
	b.WriteString("###        \\ \\/  \\/ / _` | '__| '_ \\| | '_ \\ / _` | |        ###\n")
	b.WriteString("###         \\  /\\  / (_| | |  | | | | | | | | (_| |_|        ###\n")
	b.WriteString("###          \\/  \\/ \\__,_|_|  |_| |_|_|_| |_|\\__, (_)        ###\n")
	b.WriteString("###                                           __/ |          ###\n")
	b.WriteString("###                                          |___/           ###\n")
	b.WriteString("################################################################\n")
	b.WriteString("###                                                          ###\n")

	for _, line := range lines {
		fmt.Fprintf(&b, "###  %-54s  ###\n", line)
	}

	b.WriteString("###                                                          ###\n")
	b.WriteString("################################################################")

	return b.String()
}

// addServerURLConfigError pushes a structured ConfigError onto v for
// each isSafeServerURL failure mode so the operator sees the issue
// rendered consistently with the rest of the config-load report.
func addServerURLConfigError(v *configValidator, serverURL, baseDomain string, err error) {
	current := []types.KV{
		{Key: "server_url", Value: serverURL},
		{Key: "dns.base_domain", Value: baseDomain},
	}

	switch {
	case errors.Is(err, errServerURLSame):
		v.Add(&types.ConfigError{
			Reason:  "server_url and dns.base_domain refer to the same hostname",
			Current: current,
			Hint:    "give server_url a host distinct from dns.base_domain (Tailscale takes over base_domain via MagicDNS)",
			See:     dnsDocsURL,
			Cause:   errServerURLSame,
		})

	case errors.Is(err, errServerURLSuffix):
		v.Add(&types.ConfigError{
			Reason:  "server_url is a subdomain of dns.base_domain",
			Current: current,
			Hint:    "host headscale on a domain outside dns.base_domain (Tailscale takes over base_domain via MagicDNS)",
			See:     dnsDocsURL,
			Cause:   errServerURLSuffix,
		})

	default:
		// Not the parser's error: it quotes the URL, or a part of it
		// (invalid port ":<password>"), userinfo included.
		v.Add(&types.ConfigError{
			Reason:  "server_url cannot be parsed",
			Current: []types.KV{{Key: "server_url", Value: serverURL}},
			Detail:  errURLSyntax.Error(),
			Hint:    "set server_url to an absolute URL, e.g. https://headscale.example.com",
			Cause:   errURLSyntax,
		})
	}
}

// BaseDomain cannot be a suffix of the server URL.
// This is because Tailscale takes over the domain in BaseDomain,
// causing the headscale server and DERP to be unreachable.
// For Tailscale upstream, the following is true:
// - DERP run on their own domains.
// - Control plane runs on login.tailscale.com/controlplane.tailscale.com.
// - MagicDNS (BaseDomain) for users is on a *.ts.net domain per tailnet (e.g. tail-scale.ts.net).
func isSafeServerURL(serverURL, baseDomain string) error {
	server, err := url.Parse(serverURL)
	if err != nil {
		return err
	}

	if server.Hostname() == baseDomain {
		return errServerURLSame
	}

	if strings.HasSuffix(server.Hostname(), "."+baseDomain) {
		return errServerURLSuffix
	}

	return nil
}

// configValidator collects ConfigError values so an operator sees every
// problem at once instead of fixing them one startup attempt at a time.
// Zero value is ready to use.
type configValidator struct {
	errs []error
}

// Add records a structured rule violation.
func (v *configValidator) Add(e *types.ConfigError) {
	v.errs = append(v.errs, e)
}

// AddErr records any error (e.g. one returned by a sub-builder helper).
// Useful when wrapping fmt.Errorf("..."): %w results that already carry
// their own wrap.
func (v *configValidator) AddErr(err error) {
	if err == nil {
		return
	}

	v.errs = append(v.errs, err)
}

// HasErrors reports whether any rule has triggered.
func (v *configValidator) HasErrors() bool { return len(v.errs) > 0 }

// Err returns nil if no rules triggered, otherwise the joined error.
// errors.Join's wrapper exposes Unwrap() []error, so errors.Is and
// errors.As walk every branch — sentinel matching and type extraction
// work uniformly across single and joined results.
func (v *configValidator) Err() error {
	if len(v.errs) == 0 {
		return nil
	}

	return errors.Join(v.errs...)
}

// keepSecret leaves a file: secret unread, for checking a config without
// reading the files it names; checks that need the secret skip it.
func keepSecret(_, value string) (string, error) {
	if strings.HasPrefix(value, "file:") {
		return value, dns.ErrSecretUnread
	}

	return value, nil
}
