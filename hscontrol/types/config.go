package types

//go:generate go run ../../tools/configgen table . config_docs_generated.go
//go:generate go run ../../tools/configgen/files ../..

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	hsdns "github.com/juanfont/headscale/hscontrol/dns"
	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
)

const (
	// PKCEMethodPlain sends the verifier itself as the challenge. Use it
	// only with a provider that does not support `S256`.
	PKCEMethodPlain PKCEMethod = "plain"
	// PKCEMethodS256 sends the base64url SHA-256 of the verifier as the
	// challenge. Recommended.
	PKCEMethodS256 PKCEMethod = "S256"

	providerKey = "dns.challenge.provider"
)

var (
	errInvalidPKCEMethod         = errors.New("pkce.method must be either 'plain' or 'S256'")
	errURLSyntax                 = errors.New("invalid URL syntax")
	ErrNoPrefixConfigured        = errors.New("no IPv4 or IPv6 prefix configured, minimum one prefix is required")
	ErrInvalidAllocationStrategy = errors.New("invalid prefix allocation strategy")
)

// DefaultBaseDomain is dns.base_domain's default. `.internal` is reserved
// for private use and never delegated, so MagicDNS shadows no public name.
const DefaultBaseDomain = "tailnet.internal"

// DefaultChallengeResolvers find a zone's nameservers when
// dns.challenge.resolvers is empty. The system resolver is not used: on a
// host running MagicDNS it answers for base_domain itself instead of
// asking the public zone.
func DefaultChallengeResolvers() []string {
	return []string{"9.9.9.9:53", "149.112.112.112:53"}
}

// IPAllocationStrategy is how new node IPs are picked. "" decodes without
// error to the zero value (unset).
type IPAllocationStrategy string //nolint:recvcheck // UnmarshalText needs a pointer; the rest read the value

const (
	// IPAllocationStrategySequential takes the next free address after
	// the last one handed out, and wraps around to reuse freed addresses.
	IPAllocationStrategySequential IPAllocationStrategy = "sequential"
	// IPAllocationStrategyRandom picks a free address at random.
	IPAllocationStrategyRandom IPAllocationStrategy = "random"
)

// PolicyMode is where the policy is stored. "" decodes without error to the
// zero value (unset).
type PolicyMode string //nolint:recvcheck // UnmarshalText needs a pointer; the rest read the value

const (
	// PolicyModeDB keeps the policy in the database, set with `headscale
	// policy set` or the API. `policy.path` is not read.
	PolicyModeDB PolicyMode = "database"
	// PolicyModeFile reads the policy from `policy.path`. Send headscale
	// `SIGHUP` to reload it after an edit.
	PolicyModeFile PolicyMode = "file"
)

// EphemeralConfig contains configuration for ephemeral node lifecycle.
type EphemeralConfig struct {
	// InactivityTimeout is how long an ephemeral node can be offline
	// before it is automatically deleted. It must exceed 65s, the client
	// keepalive plus a margin.
	InactivityTimeout time.Duration `example:"\"1h\"" koanf:"inactivity_timeout"`
}

// HARouteConfig contains configuration for HA subnet router health probing.
// When two or more nodes advertise the same route, each is pinged over
// Noise. One that does not answer in time is marked unhealthy and, if
// primary, hands that role to the next healthy node; it does not take it
// back when it recovers.
type HARouteConfig struct {
	// ProbeInterval is how often HA subnet routers are probed; a positive
	// interval must be at least 2s. Zero or negative disables probing,
	// and with it the `node.routes.ha.probe_timeout` rules.
	ProbeInterval time.Duration `example:"\"30s\"" koanf:"probe_interval"`

	// ProbeTimeout is the maximum time to wait for a probe response
	// before declaring a node unhealthy; at least 1s and less than
	// `node.routes.ha.probe_interval`.
	ProbeTimeout time.Duration `example:"\"3s\"" koanf:"probe_timeout"`
}

// RouteConfig contains configuration for route behaviour.
type RouteConfig struct {
	// HA is health probing of HA subnet routers. When two or more nodes
	// advertise the same route, headscale pings each over Noise and moves
	// the route away from one that does not answer in time. See
	// [High availability](https://headscale.net/stable/ref/routes/#high-availability).
	HA HARouteConfig `koanf:"ha"`
}

// PreAuthKeysConfig contains configuration for pre-auth key lifecycle.
type PreAuthKeysConfig struct {
	// RevokedRetention is how long a soft-revoked pre-auth key (revoked via the
	// v2 API's DELETE) is kept retrievable before the background collector
	// hard-deletes it. Keys still backing a node are kept until the node is
	// deleted. A zero or negative duration disables the collector.
	RevokedRetention time.Duration `example:"\"720h\"" koanf:"revoked_retention"`
}

// NodeConfig contains configuration for node lifecycle and expiry.
type NodeConfig struct {
	// Expiry is the key expiry given to a non-tagged node that registers
	// without one, whatever the method (auth key, CLI, web, OIDC). An
	// expiry the client asks for, `oidc.use_expiry_from_token` and an
	// admin's `headscale nodes expire` still apply. Tagged nodes never get
	// this default. Zero or negative disables the default.
	Expiry time.Duration `example:"\"2160h\"" koanf:"expiry"`

	// Ephemeral covers ephemeral nodes, which register with an ephemeral
	// auth key and are deleted once they have been offline for
	// `node.ephemeral.inactivity_timeout`.
	Ephemeral EphemeralConfig `koanf:"ephemeral"`

	// Routes covers the routes nodes advertise. See
	// [Routes](https://headscale.net/stable/ref/routes/).
	Routes RouteConfig `koanf:"routes"`
}

// Config is the Headscale configuration, nested like the configuration
// file; koanf tags name the keys. A duration needs a unit (30s, 3h, 90d),
// except 0.
type Config struct { //nolint:recvcheck // MarshalJSON reads a value, so a Config value is redacted too
	// ServerURL is the URL clients connect to, with its `http://` or
	// `https://` scheme, e.g. `https://headscale.example.com:443`. A
	// trailing slash is trimmed on load. Its host must not be
	// `dns.base_domain` or a name below it.
	ServerURL string `example:"\"https://headscale.example.com\"" koanf:"server_url"`

	// Addr is the host:port the server listens on for clients, the API and
	// the web pages. It serves HTTPS when `tls.cert_path` or
	// `tls.acme.hostname` is set, plain HTTP otherwise. The default listens
	// on every address, IPv4 and IPv6 alike.
	Addr ListenAddr `example:"\"127.0.0.1:8080\"" koanf:"listen_addr"`

	// MetricsAddr is the host:port serving `/metrics` and `/debug`; keep
	// it private. Empty disables this listener.
	MetricsAddr ListenAddr `example:"\"127.0.0.1:9090\"" koanf:"metrics_listen_addr"`

	// UnixSocket is where the server serves the API without
	// authentication, for the CLI on the same host. The CLI connects to it
	// when `cli.address` is empty.
	UnixSocket string `example:"\"/run/headscale/headscale.sock\"" koanf:"unix_socket" nix:"external"`

	// UnixSocketPermission is the file mode of `unix_socket`, in quoted
	// octal (`"0770"`): unquoted, YAML reads `0770` as the number 504.
	UnixSocketPermission FileMode `example:"\"0660\"" koanf:"unix_socket_permission"`

	// TrustedProxies are the CIDRs of reverse proxies whose
	// `True-Client-IP`, `X-Real-IP` and `X-Forwarded-For` headers are
	// honoured. Empty ignores those headers. Set without a proxy in front,
	// clients can spoof their source IP in logs and the v2 API.
	TrustedProxies []netip.Prefix `example:"[\"192.0.2.10/32\",\"2001:db8::10/128\"]" koanf:"trusted_proxies"`

	// DisableUpdateCheck skips the check for a newer headscale release
	// that commands make at start.
	DisableUpdateCheck bool `koanf:"disable_check_updates"`

	// Noise is the Noise protocol (TS2021) clients connect over.
	Noise NoiseConfig `koanf:"noise"`

	// Prefixes are the IP ranges node addresses are allocated from. Keep at
	// least one of `prefixes.v4` and `prefixes.v6`. Use the Tailscale
	// ranges, `100.64.0.0/10` and `fd7a:115c:a1e0::/48`, or ranges inside
	// them: the client assumes them, and other ranges are unsupported.
	Prefixes PrefixesConfig `koanf:"prefixes"`

	// Policy is where the access control policy is kept: in a file
	// headscale reads, or in the database. See
	// [Policy](https://headscale.net/stable/ref/policy/).
	Policy PolicyConfig `koanf:"policy"`

	// Log is headscale's own log output. See
	// [Debugging](https://headscale.net/stable/ref/debug/#application-logging).
	Log LogConfig `koanf:"log"`

	// Node covers node key expiry, ephemeral nodes and subnet routes.
	Node NodeConfig `koanf:"node"`

	// PreAuthKeys covers the cleanup of revoked pre-auth keys. See
	// [Pre authenticated key](https://headscale.net/stable/ref/registration/#pre-authenticated-key).
	PreAuthKeys PreAuthKeysConfig `koanf:"preauth_keys"`

	// DERP is the DERP map: the relay servers clients use when they cannot
	// connect directly, from `derp.urls`, `derp.paths` and the embedded
	// server in `derp.server`. A region replaces an earlier one with the
	// same ID. See [DERP](https://headscale.net/stable/ref/derp/).
	DERP DERPConfig `koanf:"derp"`

	// Database is where headscale stores nodes, users and keys. SQLite is
	// recommended; PostgreSQL is supported for legacy deployments only.
	// `database.sqlite` is read only for SQLite, `database.postgres` only
	// for PostgreSQL.
	Database DatabaseConfig `koanf:"database"`

	// DNSConfig is the DNS configuration sent to clients, MagicDNS
	// included, and TLS certificates for nodes. Clients apply it only with
	// `--accept-dns`, their default. See
	// [DNS](https://headscale.net/stable/ref/dns/).
	DNSConfig DNSConfig `koanf:"dns"`

	// TLS is headscale's own HTTPS certificate on `listen_addr`: from the
	// files `tls.cert_path` and `tls.key_path`, or from ACME in
	// `tls.acme`, not both. Without either, the server speaks plain HTTP.
	// See [TLS](https://headscale.net/stable/ref/tls/).
	TLS TLSConfig `koanf:"tls"`

	// OIDC is login through an OpenID Connect provider. Setting
	// `oidc.issuer` turns it on and requires `oidc.client_id` and
	// `oidc.client_secret`. See
	// [OpenID Connect](https://headscale.net/stable/ref/oidc/).
	OIDC OIDCConfig `koanf:"oidc"`

	// LogTail is whether nodes send their logs to Tailscale.
	LogTail LogTailConfig `koanf:"logtail"`

	// Taildrop is Taildrop, Tailscale's file sharing between nodes.
	Taildrop TaildropConfig `koanf:"taildrop"`

	// AutoUpdate is the tailnet-wide default for client auto-updates.
	AutoUpdate AutoUpdateConfig `koanf:"auto_update"`

	// CLI is how the headscale CLI reaches the server: the local
	// `unix_socket` without authentication, or a remote `cli.address`
	// with `cli.api_key`. The CLI reads these keys from its own
	// configuration, such as `~/.config/headscale/config.yaml`, or from
	// `HEADSCALE_CLI_*` variables; the server does not read them, so on
	// NixOS they do not belong in `services.headscale.settings`. See
	// [Remote control](https://headscale.net/stable/ref/api/#remote-control).
	CLI CLIConfig `koanf:"cli"`

	// Tuning holds performance settings that rarely need changing.
	Tuning Tuning `koanf:"tuning"`

	// ConfigDir is where [Config.AbsPath] resolves relative paths: the
	// configuration file's directory, or the working directory without
	// one. Set by the loader or from Go; it cannot be set from a file.
	ConfigDir string `json:"-" koanf:"-"`

	// dns is nil until [Config.StartDNS].
	dns *liveDNS
}

// NoiseConfig is the key of the Noise protocol clients connect over.
type NoiseConfig struct {
	// PrivateKeyPath is the file holding the Noise private key, which
	// encrypts traffic between headscale and clients, relative to the
	// configuration file. A missing file is created with a new key.
	PrivateKeyPath string `example:"\"/opt/headscale/noise_private.key\"" koanf:"private_key_path" nix:"external"`
}

// PrefixesConfig are the ranges node IPs are allocated from. At least one
// is required. Use the Tailscale ranges (100.64.0.0/10, fd7a:115c:a1e0::/48)
// or subsets of them: the client assumes them, and breaks in subtle ways
// outside them.
type PrefixesConfig struct {
	// V4 is the IPv4 range, e.g. `100.64.0.0/10`. Empty gives nodes no
	// IPv4 address.
	V4 *netip.Prefix `example:"\"100.64.0.0/24\"" koanf:"v4"`

	// V6 is the IPv6 range, e.g. `fd7a:115c:a1e0::/48`. Empty gives nodes
	// no IPv6 address.
	V6 *netip.Prefix `example:"\"fd7a:115c:a1e0::/64\"" koanf:"v6"`

	// Allocation is how a new node's addresses are picked.
	Allocation IPAllocationStrategy `example:"\"random\"" koanf:"allocation"`
}

// liveDNS is the DNS state of a running server: the tailcfg form, whose
// extra records the extra-records watcher replaces while map builds clone
// it, and the provider startup built.
type liveDNS struct {
	mu       sync.RWMutex
	dns      *tailcfg.DNSConfig
	provider hsdns.Provider
}

// DNSConfig is the DNS configuration clients get. To keep headscale out of
// clients' DNS, set every field to its empty value.
type DNSConfig struct {
	// MagicDNS gives each node a name below `dns.base_domain`, e.g.
	// `laptop.example.com`, resolved by the client. It requires
	// `dns.base_domain`.
	MagicDNS bool `koanf:"magic_dns"`

	// BaseDomain is the domain MagicDNS names live under, without a
	// trailing dot, e.g. `example.com`. The host of `server_url` must not
	// be this domain or a name below it: clients take the domain over.
	// The default is a private-use name, so `dns.certificates` needs a
	// public domain you control.
	BaseDomain string `example:"\"tailnet.example.com\"" koanf:"base_domain"`

	// OverrideLocalDNS makes clients use `dns.nameservers.global` instead
	// of their local DNS settings; with no global nameserver there is
	// nothing to override with, and clients keep their own. False sends
	// them only as fallback resolvers.
	OverrideLocalDNS bool `koanf:"override_local_dns"`

	// Nameservers are the upstream DNS servers sent to clients. An entry
	// that is neither an IP address nor a URL is skipped with a warning.
	Nameservers Nameservers `koanf:"nameservers"`

	// SearchDomains are DNS search domains sent to clients. With MagicDNS,
	// `dns.base_domain` comes first.
	SearchDomains []string `example:"[\"corp.example.com\",\"lab.example.net\"]" koanf:"search_domains"`

	// ExtraRecords are DNS records served to clients, each with a `name`,
	// `type` and `value`. Clients support `A` and `AAAA`. Mutually
	// exclusive with `dns.extra_records_path`. See
	// [Setting extra DNS records](https://headscale.net/stable/ref/dns/#setting-extra-dns-records).
	ExtraRecords []tailcfg.DNSRecord `example:"[{\"name\":\"grafana.tailnet.example.com\",\"type\":\"A\",\"value\":\"100.64.0.3\"},{\"name\":\"grafana.tailnet.example.com\",\"type\":\"AAAA\",\"value\":\"fd7a:115c:a1e0::3\"}]" koanf:"extra_records"`

	// ExtraRecordsPath is a file of extra records, reloaded when it
	// changes. The extension picks the format: `.json`, `.hujson`, `.yaml`
	// or `.yml`. Mutually exclusive with `dns.extra_records`.
	ExtraRecordsPath string `example:"\"/var/lib/headscale/extra-records.json\"" koanf:"extra_records_path" nix:"path"`

	// Certificates lets nodes get TLS certificates for their MagicDNS
	// names with `tailscale cert`. The node runs ACME itself; headscale
	// publishes its DNS-01 challenge through `dns.challenge.provider`.
	Certificates CertificatesConfig `koanf:"certificates"`

	// Challenge is the DNS provider answering ACME DNS-01 challenges, for
	// node certificates and for headscale's own certificate when
	// `tls.acme.challenge_type` is `DNS-01`. See
	// [DNS-01 challenge provider](https://headscale.net/stable/ref/dns/#dns-01-challenge-provider).
	Challenge DNSChallengeConfig `koanf:"challenge"`
}

// CertificatesConfig lets nodes get TLS certificates for their MagicDNS
// name with `tailscale cert`. The node runs ACME itself; headscale
// publishes its DNS-01 challenge through [DNSChallengeConfig].
type CertificatesConfig struct {
	// Enabled lets nodes run `tailscale cert`. It requires
	// `dns.magic_dns`, a lowercase `dns.base_domain` and
	// `dns.challenge.provider`.
	Enabled bool `koanf:"enabled"`

	// Zone is the public DNS zone challenge records are written to, when
	// `dns.base_domain` sits below the zone apex. It must contain
	// `dns.base_domain`. Empty uses `dns.base_domain`.
	Zone string `example:"\"example.com\"" koanf:"zone"`
}

// CertificateZone is the zone challenge records are written to:
// Certificates.Zone, else BaseDomain.
func (d DNSConfig) CertificateZone() string {
	return cmp.Or(d.Certificates.Zone, d.BaseDomain)
}

// DNSChallengeConfig is the DNS provider answering ACME DNS-01
// challenges for node certificates and headscale's own certificate.
type DNSChallengeConfig struct {
	// PropagationTimeout is how long to wait for a challenge record to
	// show up on every authoritative nameserver. Zero skips the check.
	PropagationTimeout time.Duration `example:"\"5m\"" koanf:"propagation_timeout"`

	// Resolvers are the servers asked for the zone's nameservers, each an
	// IP or host with an optional port (53 if omitted). Empty uses the
	// default public resolvers. The system resolver is never used: on a
	// host running MagicDNS it answers for `dns.base_domain` itself.
	Resolvers []string `example:"[\"9.9.9.9:53\",\"[2620:fe::fe]:53\"]" koanf:"resolvers"`

	// ProviderSettings is the DNS provider that writes challenge records:
	// `name` selects it, the other keys are its settings. Keys are
	// lowercased on load, at every depth; two that differ only in case
	// are an error. A string setting may be `file:<path>` to read it from
	// a file. `headscale generate config --running` and `/debug/config`
	// show `name` and `file:` references; every other setting is
	// `<redacted>`, as any may be a credential. See
	// [DNS-01 challenge provider](https://headscale.net/stable/ref/dns/#dns-01-challenge-provider)
	// to set a provider up, acme-dns included, and to set it from
	// environment variables.
	ProviderSettings map[string]any `example:"{\"name\":\"cloudflare\",\"api_token\":\"file:/run/secrets/cloudflare\"}" json:"-" koanf:"provider" mapkey:"setting"`

	// Provider is a DNS provider set from Go, by an embedder or a test; it
	// cannot be set from a file. It wins over ProviderSettings.
	Provider hsdns.Provider `json:"-" koanf:"-"`
}

// ProviderName is the provider ProviderSettings names, or "".
func (c DNSChallengeConfig) ProviderName() string {
	name, _ := c.ProviderNameText()

	return name
}

// ProviderNameText is the name as text, and false when it is a map or list:
// its contents may be credentials, so it is never formatted.
func (c DNSChallengeConfig) ProviderNameText() (string, bool) {
	switch name := c.ProviderSettings["name"].(type) {
	case nil:
		return "", true
	case string:
		return name, true
	default:
		return util.ScalarText(reflect.ValueOf(name))
	}
}

// NewProvider builds the provider ProviderSettings names, handing secret
// each string setting under its full config key.
func (c DNSChallengeConfig) NewProvider(secret func(key, value string) (string, error)) (hsdns.Provider, error) {
	return hsdns.NewProvider(
		c.ProviderName(),
		c.ProviderSettings,
		func(key string) (any, bool) {
			v, ok := c.ProviderSettings[key]

			return v, ok
		},
		func(key, value string) (string, error) {
			return secret(providerKey+"."+key, value)
		},
	)
}

// ResolverAddrs returns Resolvers as host:port, or the defaults when none
// are set. Like dns.nameservers, a resolver may be a bare IP.
func (c DNSChallengeConfig) ResolverAddrs() []string {
	if len(c.Resolvers) == 0 {
		return DefaultChallengeResolvers()
	}

	addrs := make([]string, len(c.Resolvers))
	for i, r := range c.Resolvers {
		addrs[i] = r

		_, _, err := net.SplitHostPort(r)
		if err != nil {
			addrs[i] = net.JoinHostPort(r, "53")
		}
	}

	return addrs
}

// Nameservers are the upstream DNS servers sent to clients. An entry that
// is neither an IP address nor a URL is skipped with a warning.
type Nameservers struct {
	// Global are the nameservers for names `dns.nameservers.split` does not
	// cover: IP addresses, or DNS-over-HTTPS URLs such as
	// `https://dns.nextdns.io/<id>`. Empty by default, so clients keep
	// their own DNS: headscale points them at no resolver you did not list.
	Global []string `example:"[\"9.9.9.9\",\"149.112.112.112\",\"2620:fe::fe\",\"2620:fe::9\"]" koanf:"global"`

	// Split maps a domain to the nameservers that answer for it (split
	// DNS). Domains are lowercased on load; two that differ only in case
	// are an error.
	Split map[string][]string `example:"{\"corp.example.com\":[\"192.0.2.53\"],\"lab.example.net\":[\"198.51.100.53\",\"2001:db8::53\"]}" koanf:"split" mapkey:"domain"`
}

// SqliteConfig configures the SQLite database.
type SqliteConfig struct {
	// Path is the database file, relative to the configuration file;
	// `:memory:` keeps the database in memory.
	Path string `example:"\"/opt/headscale/db.sqlite\"" koanf:"path" nix:"external"`

	// WriteAheadLog applies `database.sqlite.wal_autocheckpoint` and
	// compacts the database (`VACUUM`) on shutdown. SQLite runs in WAL
	// mode either way; false keeps SQLite's default checkpoint of 1000
	// frames.
	WriteAheadLog bool `koanf:"write_ahead_log"`

	// WALAutoCheckPoint is the number of WAL frames after which the WAL
	// is checkpointed automatically; zero disables automatic checkpoints.
	// Applied only when `database.sqlite.write_ahead_log` is true.
	WALAutoCheckPoint int `example:"2000" koanf:"wal_autocheckpoint"`
}

// PostgresConfig configures the PostgreSQL database, supported for legacy
// deployments only.
type PostgresConfig struct {
	// Host is the server's host name or IP, or the directory of its Unix
	// socket (a path starting with `/`).
	Host string `example:"\"db.example.com\"" koanf:"host"`

	// Port is the server's port or, with a Unix socket directory in
	// `database.postgres.host`, the port in the socket's file name. Zero
	// uses the driver's default.
	Port int `example:"5432" koanf:"port"`

	// Name is the database name.
	Name string `example:"\"headscale\"" koanf:"name"`

	// User is the user to connect as.
	User string `example:"\"headscale\"" koanf:"user"`

	// Pass is the password, or `file:<path>` to read it from a file, read
	// only when `database.type` is `postgres`. `headscale generate config
	// --running` and `/debug/config` show a literal password as
	// `<redacted>` and a `file:` reference as written.
	Pass Secret `example:"\"file:/run/secrets/postgres_password\"" json:"-" koanf:"pass"`

	// Ssl is the TLS mode: `true` keeps the driver's default `sslmode`,
	// `false` disables TLS, any other value is passed as `sslmode`
	// (`require`, `verify-full`, ...).
	Ssl string `example:"\"verify-full\"" koanf:"ssl"`

	// MaxOpenConnections caps open connections to the database.
	MaxOpenConnections int `example:"20" koanf:"max_open_conns"`

	// MaxIdleConnections caps idle connections kept in the pool.
	MaxIdleConnections int `example:"5" koanf:"max_idle_conns"`

	// ConnMaxIdleTimeSecs is how long, in seconds, a connection may stay
	// idle before it is closed.
	ConnMaxIdleTimeSecs int `example:"600" koanf:"conn_max_idle_time_secs"`
}

// DSN returns the connection string for this configuration as a
// postgres:// URL, the form lib/pq and pgx both accept. Building it with
// net/url escapes every component, so a password (or host, user or
// database name) containing spaces, quotes or other reserved characters
// is passed through intact instead of truncating the DSN or injecting
// extra parameters. A Host starting with "/" is a Unix socket directory
// and travels as the host query parameter, as the URL form requires.
//
// Ssl keeps its historical meaning: "true" leaves the driver default,
// "false" sets sslmode=disable, and any other value is used as sslmode.
func (cfg PostgresConfig) DSN() string {
	u := url.URL{
		Scheme: "postgres",
		Path:   "/" + cfg.Name,
	}

	switch {
	case cfg.Pass != "":
		u.User = url.UserPassword(cfg.User, string(cfg.Pass))
	case cfg.User != "":
		u.User = url.User(cfg.User)
	}

	query := url.Values{}
	port := strconv.Itoa(cfg.Port)

	switch {
	case strings.HasPrefix(cfg.Host, "/"):
		query.Set("host", cfg.Host)

		if cfg.Port != 0 {
			query.Set("port", port)
		}
	case cfg.Port != 0:
		u.Host = net.JoinHostPort(cfg.Host, port)
	case strings.Contains(cfg.Host, ":"):
		u.Host = "[" + cfg.Host + "]" // bare IPv6 literal
	default:
		u.Host = cfg.Host
	}

	sslEnabled, err := strconv.ParseBool(cfg.Ssl)

	switch {
	case err == nil && !sslEnabled:
		query.Set("sslmode", "disable")
	case err != nil && cfg.Ssl != "":
		query.Set("sslmode", cfg.Ssl)
	}

	u.RawQuery = query.Encode()

	return u.String()
}

// GormConfig configures query logging; it applies only with
// database.debug.
type GormConfig struct {
	// SlowThreshold is the query time, in milliseconds, above which a
	// query is logged as a warning. Zero disables the warning.
	SlowThreshold int `example:"1000" koanf:"slow_threshold"`

	// SkipErrRecordNotFound logs a query that finds no record as an
	// ordinary query, not as an error.
	SkipErrRecordNotFound bool `koanf:"skip_err_record_not_found"`

	// ParameterizedQueries logs queries without their parameter values.
	ParameterizedQueries bool `koanf:"parameterized_queries"`
}

// DatabaseConfig selects and configures the database.
type DatabaseConfig struct {
	// Type is the database backend. SQLite is recommended; PostgreSQL is
	// supported for legacy deployments only.
	Type DatabaseType `example:"\"sqlite\"" koanf:"type"`

	// Debug turns on query logging: ordinary queries at log level debug,
	// shown only when `log.level` is `debug` or `trace`, slow ones at warn
	// and failed ones at error. Off, no query is logged. `database.gorm`
	// shapes the query log. See
	// [Database logging](https://headscale.net/stable/ref/debug/#database-logging).
	Debug bool `koanf:"debug"`

	// Gorm is query logging, applied only when `database.debug` is true.
	Gorm GormConfig `koanf:"gorm"`

	// Sqlite is SQLite, read only when `database.type` is `sqlite` or
	// `sqlite3`.
	Sqlite SqliteConfig `koanf:"sqlite"`

	// Postgres is PostgreSQL, read only when `database.type` is
	// `postgres`. An empty `host`, `name`, `user`, `pass` or `ssl` leaves
	// that setting to the driver, which reads the `PG*` environment
	// variables and falls back to the defaults of libpq, PostgreSQL's
	// client library: a local socket, the OS user, and TLS if the server
	// offers it.
	Postgres PostgresConfig `koanf:"postgres"`
}

// IsSQLite reports whether Type names SQLite, in either spelling.
func (d DatabaseConfig) IsSQLite() bool {
	return d.Type == DatabaseSqlite || d.Type == DatabaseSqliteShort
}

// TLSConfig is headscale's own certificate: from files, or from ACME. The
// two are mutually exclusive.
type TLSConfig struct {
	// CertPath is the PEM certificate file, relative to the configuration
	// file. Setting it turns TLS on.
	CertPath string `example:"\"/etc/headscale/tls/cert.pem\"" koanf:"cert_path" nix:"path"`

	// KeyPath is the PEM private key file of `tls.cert_path`, relative to
	// the configuration file.
	KeyPath string `example:"\"/etc/headscale/tls/key.pem\"" koanf:"key_path" nix:"external"`

	// ACME gets the certificate from an ACME CA such as Let's Encrypt,
	// and renews it. Setting `tls.acme.hostname` turns it on.
	ACME ACMEConfig `koanf:"acme"`
}

// ACMEConfig gets headscale's own certificate from an ACME CA.
type ACMEConfig struct {
	// Hostname is the domain to request a certificate for. Setting it
	// turns ACME on.
	Hostname string `example:"\"headscale.example.com\"" koanf:"hostname"`

	// ChallengeType is how the CA verifies that headscale controls
	// `tls.acme.hostname`.
	ChallengeType ACMEChallenge `example:"\"TLS-ALPN-01\"" koanf:"challenge_type"`

	// HTTPListen is the host:port serving HTTP-01 challenges; the port
	// may be a name, as in `:http` for port 80. Other requests to it are
	// redirected to `server_url`.
	HTTPListen ListenAddr `example:"\"0.0.0.0:80\"" koanf:"http_listen"`

	// URL is the CA's ACME directory. Empty uses Let's Encrypt.
	URL HTTPURL `example:"\"https://acme-staging-v02.api.letsencrypt.org/directory\"" koanf:"url"`

	// Email is the contact address registered with the CA.
	Email string `example:"\"admin@example.com\"" koanf:"email"`

	// CacheDir is where certificates and ACME account data are stored,
	// relative to the configuration file.
	CacheDir string `example:"\"/var/cache/headscale/acme\"" koanf:"cache_dir" nix:"external"`
}

// PKCEConfig configures PKCE (RFC 7636), which protects the OIDC
// authorization code from interception.
type PKCEConfig struct {
	// Enabled sends a PKCE challenge with each login.
	Enabled bool `koanf:"enabled"`

	// Method is how the code challenge is derived from the verifier. The
	// verifier is sent as is in the token exchange.
	Method PKCEMethod `example:"\"plain\"" koanf:"method"`
}

// OIDCConfig configures login through an OpenID Connect provider.
type OIDCConfig struct {
	// OnlyStartIfOIDCIsAvailable stops startup when the provider cannot be
	// reached. False starts without OIDC, with CLI-based registration.
	OnlyStartIfOIDCIsAvailable bool `koanf:"only_start_if_oidc_is_available"`

	// Issuer is the provider's issuer URL. Setting it turns OIDC on.
	Issuer HTTPURL `example:"\"https://idp.example.com/realms/headscale\"" koanf:"issuer"`

	// ClientID is the client ID from the provider; required when
	// `oidc.issuer` is set.
	ClientID string `example:"\"headscale\"" koanf:"client_id"`

	// ClientSecret is the client secret from the provider, or
	// `file:<path>` to read it from a file; required when `oidc.issuer` is
	// set. `headscale generate config --running` and `/debug/config` show a
	// literal secret as `<redacted>` and a `file:` reference as written.
	ClientSecret Secret `example:"\"file:/run/secrets/oidc_client_secret\"" json:"-" koanf:"client_secret"`

	// Scope are the scopes requested; include `openid`.
	Scope []string `example:"[\"openid\",\"profile\",\"email\",\"groups\"]" koanf:"scope"`

	// ExtraParams are sent as is to the provider's authorization endpoint,
	// e.g. `domain_hint`; names keep their case.
	ExtraParams map[string]string `example:"{\"domain_hint\":\"example.com\",\"prompt\":\"select_account\"}" koanf:"extra_params" mapkey:"param"`

	// AllowedDomains admits only users whose email domain is listed.
	// Empty admits any domain.
	AllowedDomains []string `example:"[\"example.com\"]" koanf:"allowed_domains"`

	// AllowedUsers admits only users whose email address is listed. Empty
	// admits any user.
	AllowedUsers []string `example:"[\"alice@example.com\"]" koanf:"allowed_users"`

	// AllowedGroups admits only members of at least one listed group,
	// from the provider's `groups` claim: UserInfo first, the ID token as
	// fallback. Empty admits any group.
	AllowedGroups []string `example:"[\"headscale-users\"]" koanf:"allowed_groups"`

	// EmailVerifiedRequired trusts an email only when the provider marks
	// it verified: an unverified one fails `oidc.allowed_domains` and
	// `oidc.allowed_users` and is not copied to the user. Turn it off for a
	// provider that does not send `email_verified`.
	EmailVerifiedRequired bool `koanf:"email_verified_required"`

	// UseExpiryFromToken expires an OIDC-registered node with its token,
	// instead of `node.expiry`. Tokens are often short-lived, forcing
	// frequent logins.
	UseExpiryFromToken bool `koanf:"use_expiry_from_token"`

	// PKCE is Proof Key for Code Exchange (RFC 7636), which protects the
	// authorization code from interception. See
	// [Enable PKCE](https://headscale.net/stable/ref/oidc/#enable-pkce-recommended).
	PKCE PKCEConfig `koanf:"pkce"`
}

// DERPConfig is the DERP map: the relay servers clients use when a direct
// connection fails. Sources merge in order (DERPMap, URLs, Paths, then the
// embedded server); a region replaces an earlier one with the same ID.
type DERPConfig struct {
	// Server is the embedded DERP server, a relay and STUN server run by
	// headscale itself. See
	// [Enable embedded DERP](https://headscale.net/stable/ref/derp/#enable-embedded-derp).
	Server DERPServerConfig `koanf:"server"`

	// URLs are DERP maps in JSON to fetch. One that fails to load is
	// logged and skipped; startup fails only when no region remains. The
	// default is Tailscale's map: headscale fetches it from Tailscale and
	// clients relay through Tailscale's servers. `[]` keeps to your own.
	URLs []HTTPURL `example:"[\"https://derp.example.com/derpmap.json\"]" koanf:"urls"`

	// Paths are DERP map files. The extension picks the format: `.yaml` or
	// `.yml`, or Tailscale JSON as `.json` or `.hujson`, both accepting
	// comments and trailing commas.
	Paths []string `example:"[\"/etc/headscale/derp.yaml\"]" koanf:"paths" nix:"path"`

	// AutoUpdate reloads `derp.urls` and `derp.paths` every
	// `derp.update_frequency`.
	AutoUpdate bool `koanf:"auto_update_enabled"`

	// UpdateFrequency is how often `derp.auto_update_enabled` reloads the
	// DERP map. Zero disables reloading.
	UpdateFrequency time.Duration `example:"\"24h\"" koanf:"update_frequency"`

	// DERPMap is a DERP map set from Go, by an embedder or a test; it
	// cannot be set from a file.
	DERPMap *tailcfg.DERPMap `json:"-" koanf:"-"`
}

// DERPServerConfig is the embedded DERP server.
type DERPServerConfig struct {
	// Enabled runs the embedded DERP server. DERP needs TLS, so
	// `server_url` must be `https://`.
	Enabled bool `koanf:"enabled"`

	// RegionID is the embedded server's region ID; required and positive
	// when `derp.server.enabled` is true. Tailscale keeps 900-999 for your
	// own regions. It replaces a region with the same ID from the other
	// sources.
	RegionID tailcfg.DERPRegionID `example:"999" koanf:"region_id"`

	// RegionCode is the region's short code, shown by Tailscale clients.
	RegionCode string `example:"\"headscale\"" koanf:"region_code"`

	// RegionName is the region's name, shown by Tailscale clients.
	RegionName string `example:"\"Headscale Embedded DERP\"" koanf:"region_name"`

	// VerifyClients admits only nodes registered with this server.
	VerifyClients bool `koanf:"verify_clients"`

	// STUNAddr is the UDP host:port of the STUN server, which helps
	// clients with NAT traversal; required when `derp.server.enabled` is
	// true.
	STUNAddr ListenAddr `example:"\"0.0.0.0:3478\"" koanf:"stun_listen_addr"`

	// PrivateKeyPath is the file holding the DERP server's private key,
	// relative to the configuration file; required when
	// `derp.server.enabled` is true. A missing file is created with a new
	// key. It must differ from `noise.private_key_path`.
	PrivateKeyPath string `example:"\"/var/lib/headscale/derp_server_private.key\"" koanf:"private_key_path" nix:"external"`

	// IPv4 is the server's public IPv4 address, published in the DERP map
	// so clients reach it without DNS. Empty publishes none.
	IPv4 string `example:"\"198.51.100.1\"" koanf:"ipv4"`

	// IPv6 is the server's public IPv6 address, published in the DERP map
	// so clients reach it without DNS. Empty publishes none.
	IPv6 string `example:"\"2001:db8::1\"" koanf:"ipv6"`

	// AutomaticallyAddEmbeddedDerpRegion adds the embedded server's region
	// to the DERP map. When it is false and `derp.server.enabled` is true,
	// `derp.paths` is required: write the region there yourself.
	AutomaticallyAddEmbeddedDerpRegion bool `koanf:"automatically_add_embedded_derp_region"`
}

// LogTailConfig controls client logging to Tailscale.
type LogTailConfig struct {
	// Enabled lets nodes send their logs to Tailscale Inc.; headscale
	// cannot point them at another log server. False tells nodes not to.
	Enabled bool `koanf:"enabled"`
}

// TaildropConfig controls Taildrop, Tailscale's file sharing between
// nodes.
type TaildropConfig struct {
	// Enabled gives every node the file-sharing capability. False omits
	// it from the baseline; a policy `nodeAttrs` grant can still give it.
	Enabled bool `koanf:"enabled"`
}

// AutoUpdateConfig controls the tailnet-wide default for client
// auto-update. When Enabled is true, headscale emits the
// [tailcfg.NodeAttrDefaultAutoUpdate] cap with value [true] on every
// node's CapMap; clients fall back to that default unless they have
// opted in or out locally.
type AutoUpdateConfig struct {
	// Enabled makes auto-update the default for clients that have not
	// chosen locally. Clients store the default they first see, so a
	// later change reaches only new clients.
	Enabled bool `koanf:"enabled"`
}

// CLIConfig is how the headscale CLI reaches the server: the local
// unix_socket without authentication, or a remote address with an API key.
type CLIConfig struct {
	// Address is the remote server's host:port or URL; `https://` is
	// assumed without a scheme. Empty uses `unix_socket`.
	Address string `example:"\"headscale.example.com:443\"" koanf:"address"`

	// APIKey is the API key the CLI sends to `cli.address`, or
	// `file:<path>` to read it from a file. Read only by the CLI.
	APIKey Secret `example:"\"file:/run/secrets/headscale_api_key\"" json:"-" koanf:"api_key"`

	// Timeout bounds each CLI command's requests to the server.
	Timeout time.Duration `example:"\"30s\"" koanf:"timeout"`

	// Insecure skips TLS certificate verification of `cli.address`.
	Insecure bool `koanf:"insecure"`
}

// PolicyConfig is where the access control policy (ACLs and grants) is
// stored.
type PolicyConfig struct {
	// Path is the HuJSON policy file read when `policy.mode` is `file`,
	// relative to the configuration file. Empty starts without a policy,
	// which allows all traffic.
	Path string `example:"\"/etc/headscale/policy.hujson\"" koanf:"path" nix:"path"`

	// Mode is where the policy is kept: in the file `policy.path`, or in
	// the database, edited through the CLI or API.
	Mode PolicyMode `example:"\"database\"" koanf:"mode"`
}

func (p *PolicyConfig) IsEmpty() bool {
	return p.Mode == PolicyModeFile && p.Path == ""
}

// LogConfig configures headscale's own log output.
type LogConfig struct {
	// Level is the lowest level logged.
	Level LogLevel `example:"\"debug\"" koanf:"level"`

	// Format is how log lines are written.
	Format LogFormat `example:"\"json\"" koanf:"format"`
}

// Tuning contains advanced performance tuning parameters for Headscale.
// These settings control internal batching, timeouts, and resource allocation.
// The defaults are carefully chosen for typical deployments and should rarely
// need adjustment. Changes to these values can significantly impact performance
// and resource usage.
type Tuning struct {
	// BatchChangeDelay is how often queued changes are sent to clients
	// as one update; must be positive.
	BatchChangeDelay time.Duration `example:"\"500ms\"" koanf:"batch_change_delay"`

	// NodeMapSessionBufferedChanSize is how many map updates are queued
	// per connected client.
	NodeMapSessionBufferedChanSize int `example:"60" koanf:"node_mapsession_buffered_chan_size"`

	// BatcherWorkers is the number of workers building map updates for
	// connected clients. Zero picks the number from the CPU count.
	BatcherWorkers int `defaulttext:"three quarters of the CPU cores, at least one" example:"8" koanf:"batcher_workers"`

	// RegisterCacheExpiration is how long a pending registration waits
	// to be completed. Zero uses the default.
	RegisterCacheExpiration time.Duration `example:"\"30m\"" koanf:"register_cache_expiration"`

	// RegisterCacheMaxEntries bounds pending registrations. At capacity,
	// new registrations are refused without evicting pending ones; SSH
	// checks have a small reserve beyond it. Zero uses the default. See
	// [Pending authentication limits](https://headscale.net/stable/ref/registration/#pending-authentication-limits).
	RegisterCacheMaxEntries int `example:"4096" koanf:"register_cache_max_entries"`

	// NodeStoreBatchSize is how many node changes are batched before the
	// in-memory node state, peer relationships included, is rebuilt; must
	// be positive. Higher values save CPU on bulk changes but delay each
	// change until its batch is full or `tuning.node_store_batch_timeout`
	// passes.
	NodeStoreBatchSize int `example:"200" koanf:"node_store_batch_size"`

	// NodeStoreBatchTimeout is the longest a partial batch of node changes
	// waits before the rebuild; must be positive. Lower values answer
	// single changes faster at the cost of more rebuilds.
	NodeStoreBatchTimeout time.Duration `example:"\"1s\"" koanf:"node_store_batch_timeout"`
}

// BatcherWorkerCount is BatcherWorkers, or [DefaultBatcherWorkers] when unset.
func (t Tuning) BatcherWorkerCount() int {
	if t.BatcherWorkers > 0 {
		return t.BatcherWorkers
	}

	return DefaultBatcherWorkers()
}

// DERPShuffleSeed seeds the DERP node order: dns.base_domain, or the
// server_url host while dns.base_domain is [DefaultBaseDomain]. Empty
// seeds randomly on each start.
func (c *Config) DERPShuffleSeed() string {
	if c.DNSConfig.BaseDomain != DefaultBaseDomain {
		return c.DNSConfig.BaseDomain
	}

	// A shared default domain would give every such server the same relay order.
	u, err := url.Parse(c.ServerURL)
	if err != nil {
		return ""
	}

	return u.Hostname()
}

// Domain returns the hostname/domain part of the [Config.ServerURL].
// If the [Config.ServerURL] is not a valid URL, it returns dns.base_domain.
func (c *Config) Domain() string {
	u, err := url.Parse(c.ServerURL)
	if err != nil {
		return c.DNSConfig.BaseDomain
	}

	return u.Hostname()
}

// AbsPath resolves a path from the configuration against [Config.ConfigDir].
func (c *Config) AbsPath(p string) string {
	return util.AbsolutePath(c.ConfigDir, p)
}

// URLKeys are the keys that may hold a URL, whose userinfo may be a
// credential: [Config.RedactedURLs] redacts it and errors never show their
// values.
var URLKeys = []string{
	"server_url", "cli.address", "dns.nameservers.global", "dns.nameservers.split",
	"tls.acme.url", "oidc.issuer", "derp.urls",
}

// RedactedURLs returns c with the userinfo of the URLs that URLKeys hold
// redacted as [HTTPURL.Redacted] does; a value without an @ has none and is
// kept, a host:port or an IP included. c keeps its values.
func (c Config) RedactedURLs() Config {
	for _, f := range ConfigFields(&c) {
		if slices.Contains(URLKeys, f.Path) {
			f.Value.Set(redactedURLs(f.Value))
		}
	}

	return c
}

// redactedURLs is v, a text or a list or map of texts, with each redacted;
// a list or map is a copy.
func redactedURLs(v reflect.Value) reflect.Value {
	switch v.Kind() { //nolint:exhaustive // the kinds URLKeys hold
	case reflect.String:
		return reflect.ValueOf(redactedURL(v.String())).Convert(v.Type())
	case reflect.Slice:
		if v.IsNil() {
			return v
		}

		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := range v.Len() {
			out.Index(i).Set(redactedURLs(v.Index(i)))
		}

		return out
	case reflect.Map:
		if v.IsNil() {
			return v
		}

		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		for k, e := range v.Seq2() {
			out.SetMapIndex(k, redactedURLs(e))
		}

		return out
	}

	return v
}

func redactedURL(s string) string {
	if !strings.Contains(s, "@") {
		return s
	}

	return HTTPURL(s).Redacted()
}

// MarshalJSON writes c without credentials, for debug output and logs:
// secrets are left out and URLs lose their userinfo.
func (c Config) MarshalJSON() ([]byte, error) {
	type plain Config // without this method

	return json.Marshal(plain(c.RedactedURLs()))
}

// SQLitePath is database.sqlite.path resolved, keeping SQLite's in-memory
// name, which is not a file.
func (c *Config) SQLitePath() string {
	if c.Database.Sqlite.Path == ":memory:" {
		return c.Database.Sqlite.Path
	}

	return c.AbsPath(c.Database.Sqlite.Path)
}

// ServesRoute reports whether an approved route is handed to clients. A
// single address inside the node ranges, in either spelling, names a node
// rather than a subnet, so it stays approved but is never served. 4via6
// addresses stand for a site's IPv4 subnet, not a node.
func (c *Config) ServesRoute(p netip.Prefix) bool {
	if !p.IsSingleIP() || tsaddr.IsViaPrefix(p) {
		return true
	}

	addr := p.Addr().Unmap()

	return (c.Prefixes.V4 == nil || !c.Prefixes.V4.Contains(addr)) &&
		(c.Prefixes.V6 == nil || !c.Prefixes.V6.Contains(addr))
}

// outsideRange reports whether p holds addresses outside r.
func outsideRange(p, r netip.Prefix) bool {
	return p.Bits() < r.Bits() || !r.Contains(p.Addr())
}

// parseResolvers converts nameserver strings into DNS resolvers: an IP is a
// plain resolver, a URL a DoH one. Anything else is skipped;
// [DNSConfig.NameserverWarnings] lists it for config.Warnings.
func parseResolvers(nameservers []string) []*dnstype.Resolver {
	var resolvers []*dnstype.Resolver

	for _, ns := range nameservers {
		if validNameserver(ns) {
			resolvers = append(resolvers, &dnstype.Resolver{Addr: ns})
		}
	}

	return resolvers
}

func validNameserver(ns string) bool {
	_, addrErr := netip.ParseAddr(ns)
	_, urlErr := url.Parse(ns)

	return addrErr == nil || urlErr == nil
}

// NameserverWarnings lists each nameserver parseResolvers skips, so
// config.Warnings reports it once rather than on each build.
func (d DNSConfig) NameserverWarnings() []string {
	var warnings []string

	check := func(key string, nameservers []string) {
		for _, ns := range nameservers {
			if !validNameserver(ns) {
				warnings = append(warnings, fmt.Sprintf("invalid nameserver %q in %s, ignoring", redactedURL(ns), key))
			}
		}
	}

	check("dns.nameservers.global", d.Nameservers.Global)

	for _, domain := range slices.Sorted(maps.Keys(d.Nameservers.Split)) {
		check("dns.nameservers.split."+domain, d.Nameservers.Split[domain])
	}

	return warnings
}

// globalResolvers returns the global DNS resolvers
// defined in the config file.
func (d DNSConfig) globalResolvers() []*dnstype.Resolver {
	return parseResolvers(d.Nameservers.Global)
}

// splitResolvers returns a map of domain to DNS resolvers.
func (d DNSConfig) splitResolvers() map[string][]*dnstype.Resolver {
	routes := make(map[string][]*dnstype.Resolver)

	for domain, nameservers := range d.Nameservers.Split {
		routes[domain] = parseResolvers(nameservers)
	}

	return routes
}

func dnsToTailcfgDNS(dns DNSConfig) *tailcfg.DNSConfig {
	cfg := tailcfg.DNSConfig{}

	cfg.Proxied = dns.MagicDNS

	cfg.ExtraRecords = lowercaseRecordNames(dns.ExtraRecords)
	if dns.OverrideLocalDNS {
		cfg.Resolvers = dns.globalResolvers()
	} else {
		cfg.FallbackResolvers = dns.globalResolvers()
	}

	routes := dns.splitResolvers()

	cfg.Routes = routes
	// Only MagicDNS answers for the base domain, and SaaS sends it only then. Sent
	// alone, it left a client that writes resolv.conf itself with a search line
	// and no nameserver.
	if dns.MagicDNS && dns.BaseDomain != "" {
		cfg.Domains = []string{dns.BaseDomain}
	}

	cfg.Domains = append(cfg.Domains, dns.SearchDomains...)

	return &cfg
}

// TailcfgDNSConfig builds the DNS config clients get from DNSConfig and the
// IP prefixes. It is never nil.
func (c *Config) TailcfgDNSConfig() *tailcfg.DNSConfig {
	cfg := dnsToTailcfgDNS(c.DNSConfig)
	if !cfg.Proxied {
		return cfg
	}

	// Clients route reverse lookups for the Tailscale ranges themselves
	// (magicDNSRootDomains in tailscale.com/ipn/ipnlocal) and SaaS sends
	// no reverse routes, so only a prefix outside those ranges needs them.
	var reverse []dnsname.FQDN
	if v4 := c.Prefixes.V4; v4 != nil && outsideRange(*v4, tsaddr.CGNATRange()) {
		reverse = append(reverse, util.GenerateIPv4DNSRootDomain(*v4)...)
	}

	if v6 := c.Prefixes.V6; v6 != nil && outsideRange(*v6, tsaddr.TailscaleULARange()) {
		reverse = append(reverse, util.GenerateIPv6DNSRootDomain(*v6)...)
	}

	for _, d := range reverse {
		// Empty non-nil slice rather than nil: tailcfg.DNSConfig.Clone
		// and dns.Config.Clone in tailscale drop map entries whose
		// value is nil (see tailscale.com/tailcfg/tailcfg_clone.go and
		// tailscale.com/net/dns/dns_clone.go: `if sv == nil { continue }`).
		// Sending nil here caused the client's wgengine LinkChange:major
		// handler to clobber /etc/resolv.conf on every tunnel-IP rebind
		// — the handler reapplies a Clone of lastDNSConfig and the magic
		// DNS routes vanish, taking the resolver with them for ~6 min
		// until the next route-changing netmap. Empty slice survives
		// Clone and carries the same "resolve locally" semantics
		// ([tailcfg.DNSConfig.Routes] documents the empty-resolver form).
		cfg.Routes[d.WithoutTrailingDot()] = []*dnstype.Resolver{}
	}

	return cfg
}

// StartDNS builds the DNS config clients get, from here on changed only by
// [Config.SetExtraRecords], and keeps provider for [Config.DNSProvider].
// Call it before the config is shared.
func (c *Config) StartDNS(provider hsdns.Provider) {
	c.dns = &liveDNS{dns: c.TailcfgDNSConfig(), provider: provider}
}

// DNSProvider returns the provider [Config.StartDNS] was given, else the
// Go-only DNSConfig.Challenge.Provider.
func (c *Config) DNSProvider() hsdns.Provider {
	if c.dns != nil {
		return c.dns.provider
	}

	return c.DNSConfig.Challenge.Provider
}

// CloneTailcfgDNSConfig returns a deep copy of the started DNS config, or a
// fresh [Config.TailcfgDNSConfig] before [Config.StartDNS]. Safe for
// concurrent use with [Config.SetExtraRecords].
func (c *Config) CloneTailcfgDNSConfig() *tailcfg.DNSConfig {
	if c.dns == nil {
		return c.TailcfgDNSConfig()
	}

	c.dns.mu.RLock()
	defer c.dns.mu.RUnlock()

	return c.dns.dns.Clone()
}

// HasExtraRecord reports whether an extra DNS record is exactly name,
// ignoring case and a trailing dot. Safe for concurrent use with
// [Config.SetExtraRecords].
func (c *Config) HasExtraRecord(name string) bool {
	return c.extraRecordAt(strings.ToLower(strings.TrimSuffix(name, ".")), false)
}

// extraRecordAt reports whether an extra DNS record is name or, with orBelow,
// a subdomain of it. Case is ignored, as in TLS name matching; name is
// lowercase.
func (c *Config) extraRecordAt(name string, orBelow bool) bool {
	records := c.DNSConfig.ExtraRecords
	if c.dns != nil {
		c.dns.mu.RLock()
		defer c.dns.mu.RUnlock()

		records = c.dns.dns.ExtraRecords
	}

	for _, r := range records {
		rn := strings.ToLower(strings.TrimSuffix(r.Name, "."))
		if rn == name || (orBelow && strings.HasSuffix(rn, "."+name)) {
			return true
		}
	}

	return false
}

// TailcfgDebug returns the [tailcfg.Debug] for full map responses: nil when
// logtail is enabled, leaving client log uploads as the client set them,
// otherwise an instruction to stop uploading logs.
func (c *Config) TailcfgDebug() *tailcfg.Debug {
	if c.LogTail.Enabled {
		return nil
	}

	return &tailcfg.Debug{DisableLogTail: true}
}

// SetExtraRecords replaces the extra records of the started DNS config; it
// does nothing before [Config.StartDNS]. Safe for concurrent use with
// [Config.CloneTailcfgDNSConfig].
func (c *Config) SetExtraRecords(records []tailcfg.DNSRecord) {
	if c.dns == nil {
		return
	}

	c.dns.mu.Lock()
	defer c.dns.mu.Unlock()

	c.dns.dns.ExtraRecords = lowercaseRecordNames(records)
}

// lowercaseRecordNames normalizes DNS record names to lowercase, as DNS names
// are case-insensitive and clients match extra records by exact name.
func lowercaseRecordNames(records []tailcfg.DNSRecord) []tailcfg.DNSRecord {
	if len(records) == 0 {
		return records
	}

	normalized := make([]tailcfg.DNSRecord, len(records))
	for i, record := range records {
		record.Name = strings.ToLower(record.Name)
		normalized[i] = record
	}

	return normalized
}
