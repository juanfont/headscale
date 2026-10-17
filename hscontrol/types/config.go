package types

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	hsdns "github.com/juanfont/headscale/hscontrol/dns"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/prometheus/common/model"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/set"
)

const (
	PKCEMethodPlain string = "plain"
	PKCEMethodS256  string = "S256"

	defaultNodeStoreBatchSize = 100

	dnsDocsURL = "https://headscale.net/stable/ref/dns/"
)

var (
	errOidcMutuallyExclusive     = errors.New("oidc_client_secret and oidc_client_secret_path are mutually exclusive")
	errOIDCIssuerInvalid         = errors.New("oidc.issuer must be a valid http(s) URL")
	errOIDCClientIDRequired      = errors.New("oidc.client_id is required when oidc.issuer is set")
	errOIDCClientSecretRequired  = errors.New("oidc.client_secret or oidc.client_secret_path is required when oidc.issuer is set")
	errServerURLSuffix           = errors.New("server_url cannot be part of base_domain in a way that could make the DERP and headscale server unreachable")
	errServerURLSame             = errors.New("server_url cannot use the same domain as base_domain in a way that could make the DERP and headscale server unreachable")
	errInvalidPKCEMethod         = errors.New("pkce.method must be either 'plain' or 'S256'")
	errTrustedProxyZeroRange     = errors.New("0.0.0.0/0 and ::/0 are not allowed")
	ErrNoPrefixConfigured        = errors.New("no IPv4 or IPv6 prefix configured, minimum one prefix is required")
	ErrInvalidAllocationStrategy = errors.New("invalid prefix allocation strategy")
)

// defaultChallengeResolvers find a zone's nameservers when
// dns.challenge.resolvers is empty. The system resolver is not used: on a
// host running MagicDNS it answers for base_domain itself instead of
// asking the public zone.
var defaultChallengeResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}

type IPAllocationStrategy string

const (
	IPAllocationStrategySequential IPAllocationStrategy = "sequential"
	IPAllocationStrategyRandom     IPAllocationStrategy = "random"
)

type PolicyMode string

const (
	PolicyModeDB   = "database"
	PolicyModeFile = "file"
)

// EphemeralConfig contains configuration for ephemeral node lifecycle.
type EphemeralConfig struct {
	// InactivityTimeout is how long an ephemeral node can be offline
	// before it is automatically deleted.
	InactivityTimeout time.Duration
}

// HARouteConfig contains configuration for HA subnet router health probing.
type HARouteConfig struct {
	// ProbeInterval is how often HA subnet routers are probed.
	// A zero or negative duration disables probing.
	ProbeInterval time.Duration

	// ProbeTimeout is the maximum time to wait for a probe response
	// before declaring a node unhealthy. Must be less than [HARouteConfig.ProbeInterval].
	ProbeTimeout time.Duration
}

// RouteConfig contains configuration for route behaviour.
type RouteConfig struct {
	HA HARouteConfig
}

// PreAuthKeysConfig contains configuration for pre-auth key lifecycle.
type PreAuthKeysConfig struct {
	// RevokedRetention is how long a soft-revoked pre-auth key (revoked via the
	// v2 API's DELETE) is kept retrievable before the background collector
	// hard-deletes it. Keys still backing a node are kept until the node is
	// deleted. A zero or negative duration disables the collector.
	RevokedRetention time.Duration
}

// NodeConfig contains configuration for node lifecycle and expiry.
type NodeConfig struct {
	// Expiry is the default key expiry duration for non-tagged nodes.
	// Applies to all registration methods (auth key, CLI, web, OIDC).
	// Tagged nodes are exempt and never expire.
	// A zero/negative duration means no default expiry (nodes never expire).
	Expiry time.Duration

	// Ephemeral contains configuration for ephemeral node lifecycle.
	Ephemeral EphemeralConfig

	// Routes contains configuration for route behaviour.
	Routes RouteConfig
}

// Config contains the initial Headscale configuration.
type Config struct {
	ServerURL           string
	Addr                string
	MetricsAddr         string
	TrustedProxies      []netip.Prefix
	Node                NodeConfig
	PreAuthKeys         PreAuthKeysConfig
	PrefixV4            *netip.Prefix
	PrefixV6            *netip.Prefix
	IPAllocation        IPAllocationStrategy
	NoisePrivateKeyPath string
	BaseDomain          string
	Log                 LogConfig
	DisableUpdateCheck  bool

	Database DatabaseConfig

	DERP DERPConfig

	TLS TLSConfig

	// DNSConfig is the headscale representation of the DNS configuration.
	// It is kept in the config update for some settings that are
	// not directly converted into a [tailcfg.DNSConfig].
	DNSConfig DNSConfig

	// TailcfgDNSConfig is the tailcfg representation of the DNS configuration,
	// it can be used directly when sending Netmaps to clients.
	TailcfgDNSConfig *tailcfg.DNSConfig

	DNSChallenge DNSChallengeConfig

	UnixSocket           string
	UnixSocketPermission fs.FileMode

	OIDC OIDCConfig

	LogTail    LogTailConfig
	Taildrop   TaildropConfig
	AutoUpdate AutoUpdateConfig

	CLI CLIConfig

	Policy PolicyConfig

	Tuning Tuning
}

type DNSConfig struct {
	MagicDNS         bool   `mapstructure:"magic_dns"`
	BaseDomain       string `mapstructure:"base_domain"`
	OverrideLocalDNS bool   `mapstructure:"override_local_dns"`
	Nameservers      Nameservers
	SearchDomains    []string            `mapstructure:"search_domains"`
	ExtraRecords     []tailcfg.DNSRecord `mapstructure:"extra_records"`
	ExtraRecordsPath string              `mapstructure:"extra_records_path"`
	Certificates     CertificatesConfig
}

// CertificatesConfig lets nodes get TLS certificates for their MagicDNS
// name with `tailscale cert`. The node runs ACME itself; headscale
// publishes its DNS-01 challenge through [DNSChallengeConfig].
type CertificatesConfig struct {
	Enabled bool
	// Zone is the public DNS zone challenge records are written to. It is
	// base_domain unless base_domain sits below the zone apex.
	Zone string
}

// DNSChallengeConfig is the DNS provider answering ACME DNS-01
// challenges for node certificates and headscale's own certificate.
type DNSChallengeConfig struct {
	PropagationTimeout time.Duration
	Resolvers          []string
	ProviderName       string
	// Provider is nil when no provider is configured. It is built while
	// loading so `headscale configtest` reports bad provider settings,
	// and never serialised because it holds credentials.
	Provider hsdns.Provider `json:"-"`
}

type Nameservers struct {
	Global []string
	Split  map[string][]string
}

type SqliteConfig struct {
	Path              string
	WriteAheadLog     bool
	WALAutoCheckPoint int
}

type PostgresConfig struct {
	Host                string
	Port                int
	Name                string
	User                string
	Pass                string `json:"-"` // never serialise the database password
	Ssl                 string
	MaxOpenConnections  int
	MaxIdleConnections  int
	ConnMaxIdleTimeSecs int
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
		u.User = url.UserPassword(cfg.User, cfg.Pass)
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

type GormConfig struct {
	Debug                 bool
	SlowThreshold         time.Duration
	SkipErrRecordNotFound bool
	ParameterizedQueries  bool
}

type DatabaseConfig struct {
	// Type sets the database type, either "sqlite3" or "postgres"
	Type  string
	Debug bool

	// Type sets the gorm configuration
	Gorm GormConfig

	Sqlite   SqliteConfig
	Postgres PostgresConfig
}

type TLSConfig struct {
	CertPath string
	KeyPath  string

	ACME ACMEConfig
}

// ACMEConfig gets headscale's own certificate from an ACME CA.
type ACMEConfig struct {
	Hostname      string
	ChallengeType string
	// HTTPListen serves HTTP-01 challenges.
	HTTPListen string
	URL        string
	Email      string
	CacheDir   string
}

// legacyTLSKeys maps each tls key to the flat key it replaced. The flat
// keys keep working, so existing configs and NixOS modules still run.
var legacyTLSKeys = map[string]string{
	"tls.cert_path":           "tls_cert_path",
	"tls.key_path":            "tls_key_path",
	"tls.acme.hostname":       "tls_letsencrypt_hostname",
	"tls.acme.challenge_type": "tls_letsencrypt_challenge_type",
	"tls.acme.http_listen":    "tls_letsencrypt_listen",
	"tls.acme.cache_dir":      "tls_letsencrypt_cache_dir",
	"tls.acme.url":            "acme_url",
	"tls.acme.email":          "acme_email",
}

var tlsDefaults = map[string]string{
	"tls.acme.challenge_type": HTTP01ChallengeType,
	"tls.acme.http_listen":    ":http",
	"tls.acme.cache_dir":      "/var/lib/headscale/cache",
}

// warnLegacyTLSKeys points at the tls keys for flat keys in the config
// file that turn TLS on. NixOS writes the flat keys even with TLS off, and
// the HEADSCALE_TLS_* variables name both the flat and the tls keys.
func warnLegacyTLSKeys(depr *deprecator) {
	legacyTLSOn := func(key string) bool { return viper.InConfig(key) && viper.GetString(key) != "" }
	if !legacyTLSOn("tls_letsencrypt_hostname") && !legacyTLSOn("tls_cert_path") {
		return
	}

	for _, key := range slices.Sorted(maps.Keys(legacyTLSKeys)) {
		if viper.InConfig(legacyTLSKeys[key]) {
			depr.warnNoAlias(key, legacyTLSKeys[key])
		}
	}
}

// tlsKey reads a tls setting, falling back to the flat key it replaced and
// then to its default. The defaults are not viper defaults: those would
// shadow the flat key.
func tlsKey(key string) string {
	return cmp.Or(viper.GetString(key), viper.GetString(legacyTLSKeys[key]), tlsDefaults[key])
}

type PKCEConfig struct {
	Enabled bool
	Method  string
}

type OIDCConfig struct {
	OnlyStartIfOIDCIsAvailable bool
	Issuer                     string
	ClientID                   string
	ClientSecret               string `json:"-"` // never serialise the OIDC client secret
	Scope                      []string
	ExtraParams                map[string]string
	AllowedDomains             []string
	AllowedUsers               []string
	AllowedGroups              []string
	EmailVerifiedRequired      bool
	UseExpiryFromToken         bool
	PKCE                       PKCEConfig
}

type DERPConfig struct {
	ServerEnabled                      bool
	AutomaticallyAddEmbeddedDerpRegion bool
	ServerRegionID                     tailcfg.DERPRegionID
	ServerRegionCode                   string
	ServerRegionName                   string
	ServerPrivateKeyPath               string
	ServerVerifyClients                bool
	STUNAddr                           string
	URLs                               []url.URL
	Paths                              []string
	DERPMap                            *tailcfg.DERPMap
	AutoUpdate                         bool
	UpdateFrequency                    time.Duration
	IPv4                               string
	IPv6                               string
}

type LogTailConfig struct {
	Enabled bool
}

type TaildropConfig struct {
	Enabled bool
}

// AutoUpdateConfig controls the tailnet-wide default for client
// auto-update. When Enabled is true, headscale emits the
// [tailcfg.NodeAttrDefaultAutoUpdate] cap with value [true] on every
// node's CapMap; clients fall back to that default unless they have
// opted in or out locally.
type AutoUpdateConfig struct {
	Enabled bool
}

type CLIConfig struct {
	Address  string
	APIKey   string `json:"-"` // never serialise the headscale admin API key
	Timeout  time.Duration
	Insecure bool
}

type PolicyConfig struct {
	Path string
	Mode PolicyMode
}

func (p *PolicyConfig) IsEmpty() bool {
	return p.Mode == PolicyModeFile && p.Path == ""
}

type LogConfig struct {
	Format string
	Level  zerolog.Level
}

// Tuning contains advanced performance tuning parameters for Headscale.
// These settings control internal batching, timeouts, and resource allocation.
// The defaults are carefully chosen for typical deployments and should rarely
// need adjustment. Changes to these values can significantly impact performance
// and resource usage.
type Tuning struct {
	// NotifierSendTimeout is the maximum time to wait when sending notifications
	// to connected clients about network changes.
	NotifierSendTimeout time.Duration

	// BatchChangeDelay controls how long to wait before sending batched updates
	// to clients when multiple changes occur in rapid succession.
	BatchChangeDelay time.Duration

	// NodeMapSessionBufferedChanSize sets the buffer size for the channel that
	// queues map updates to be sent to connected clients.
	NodeMapSessionBufferedChanSize int

	// BatcherWorkers controls the number of parallel workers processing map
	// updates for connected clients.
	BatcherWorkers int

	// RegisterCacheExpiration is how long registration cache entries remain
	// valid before being eligible for eviction.
	RegisterCacheExpiration time.Duration

	// RegisterCacheMaxEntries bounds the number of pending registration
	// entries the auth cache will hold. Older entries are evicted (LRU)
	// when the cap is reached, preventing unauthenticated cache-fill DoS.
	// A value of 0 falls back to defaultRegisterCacheMaxEntries (1024).
	RegisterCacheMaxEntries int

	// NodeStoreBatchSize controls how many write operations are accumulated
	// before rebuilding the in-memory node snapshot.
	//
	// The NodeStore batches write operations (add/update/delete nodes) before
	// rebuilding its in-memory data structures. Rebuilding involves recalculating
	// peer relationships between all nodes based on the current ACL policy, which
	// is computationally expensive and scales with the square of the number of nodes.
	//
	// By batching writes, Headscale can process N operations but only rebuild once,
	// rather than rebuilding N times. This significantly reduces CPU usage during
	// bulk operations like initial sync or policy updates.
	//
	// Trade-off: Higher values reduce CPU usage from rebuilds but increase latency
	// for individual operations waiting for their batch to complete.
	NodeStoreBatchSize int

	// NodeStoreBatchTimeout is the maximum time to wait before processing a
	// partial batch of node operations.
	//
	// When [Tuning.NodeStoreBatchSize] operations haven't accumulated, this timeout ensures
	// writes don't wait indefinitely. The batch processes when either the size
	// threshold is reached OR this timeout expires, whichever comes first.
	//
	// Trade-off: Lower values provide faster response for individual operations
	// but trigger more frequent (expensive) peer map rebuilds. Higher values
	// optimize for bulk throughput at the cost of individual operation latency.
	NodeStoreBatchTimeout time.Duration
}

func validatePKCEMethod(method string) error {
	if method != PKCEMethodPlain && method != PKCEMethodS256 {
		return errInvalidPKCEMethod
	}

	return nil
}

// validateOIDCConfig validates the OIDC settings, called when oidc.issuer is
// set. It fails fast on a setup that cannot work: an invalid PKCE method, a
// malformed issuer URL (which would otherwise surface as an opaque discovery
// error or, worse, resolve to an unintended provider), or a missing client
// id/secret.
func validateOIDCConfig() error {
	err := validatePKCEMethod(viper.GetString("oidc.pkce.method"))
	if err != nil {
		return err
	}

	issuer := viper.GetString("oidc.issuer")

	u, err := url.Parse(issuer)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("%w: got %q", errOIDCIssuerInvalid, issuer)
	}

	if viper.GetString("oidc.client_id") == "" {
		return errOIDCClientIDRequired
	}

	if viper.GetString("oidc.client_secret") == "" && viper.GetString("oidc.client_secret_path") == "" {
		return errOIDCClientSecretRequired
	}

	return nil
}

// Domain returns the hostname/domain part of the [Config.ServerURL].
// If the [Config.ServerURL] is not a valid URL, it returns the [Config.BaseDomain].
func (c *Config) Domain() string {
	u, err := url.Parse(c.ServerURL)
	if err != nil {
		return c.BaseDomain
	}

	return u.Hostname()
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

	return (c.PrefixV4 == nil || !c.PrefixV4.Contains(addr)) &&
		(c.PrefixV6 == nil || !c.PrefixV6.Contains(addr))
}

// LoadConfig prepares and loads the Headscale configuration into Viper.
// This means it sets the default values, reads the configuration file and
// environment variables, and handles deprecated configuration options.
// It has to be called before [LoadServerConfig] and [LoadCLIConfig].
// The configuration is not validated and the caller should check for errors
// using a validation function.
func LoadConfig(path string, isFile bool) error {
	if isFile {
		viper.SetConfigFile(path)
	} else {
		viper.SetConfigName("config")

		if path == "" {
			viper.AddConfigPath("/etc/headscale/")
			viper.AddConfigPath("$HOME/.headscale")
			viper.AddConfigPath(".")
		} else {
			// For testing
			viper.AddConfigPath(path)
		}
	}

	envPrefix := "headscale"
	viper.SetEnvPrefix(envPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	viper.SetDefault("policy.mode", "file")

	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.format", TextLogFormat)

	viper.SetDefault("dns.magic_dns", true)
	viper.SetDefault("dns.base_domain", "")
	viper.SetDefault("dns.override_local_dns", true)
	viper.SetDefault("dns.nameservers.global", []string{})
	viper.SetDefault("dns.nameservers.split", map[string]string{})
	viper.SetDefault("dns.search_domains", []string{})
	viper.SetDefault("dns.certificates.enabled", false)

	viper.SetDefault("dns.challenge.propagation_timeout", "2m")

	viper.SetDefault("derp.server.enabled", false)
	viper.SetDefault("derp.server.verify_clients", true)
	viper.SetDefault("derp.server.stun.enabled", true)
	viper.SetDefault("derp.server.automatically_add_embedded_derp_region", true)
	viper.SetDefault("derp.update_frequency", "3h")

	viper.SetDefault("unix_socket", "/var/run/headscale/headscale.sock")
	viper.SetDefault("unix_socket_permission", "0o770")

	viper.SetDefault("cli.timeout", "5s")
	viper.SetDefault("cli.insecure", false)

	viper.SetDefault("database.postgres.ssl", false)
	viper.SetDefault("database.postgres.max_open_conns", 10)
	viper.SetDefault("database.postgres.max_idle_conns", 10)
	viper.SetDefault("database.postgres.conn_max_idle_time_secs", 3600)

	viper.SetDefault("database.sqlite.write_ahead_log", true)
	viper.SetDefault("database.sqlite.wal_autocheckpoint", 1000) // SQLite default

	viper.SetDefault("oidc.scope", []string{oidc.ScopeOpenID, "profile", "email"})
	viper.SetDefault("oidc.only_start_if_oidc_is_available", true)
	viper.SetDefault("oidc.use_expiry_from_token", false)
	viper.SetDefault("oidc.pkce.enabled", false)
	viper.SetDefault("oidc.pkce.method", "S256")
	viper.SetDefault("oidc.email_verified_required", true)

	viper.SetDefault("logtail.enabled", false)
	viper.SetDefault("taildrop.enabled", true)
	viper.SetDefault("auto_update.enabled", false)

	viper.SetDefault("node.expiry", "0")
	viper.SetDefault("node.ephemeral.inactivity_timeout", "120s")
	viper.SetDefault("preauth_keys.revoked_retention", "168h")
	viper.SetDefault("node.routes.ha.probe_interval", "10s")
	viper.SetDefault("node.routes.ha.probe_timeout", "5s")

	viper.SetDefault("tuning.notifier_send_timeout", "800ms")
	viper.SetDefault("tuning.batch_change_delay", "800ms")
	viper.SetDefault("tuning.node_mapsession_buffered_chan_size", 30)
	viper.SetDefault("tuning.node_store_batch_size", defaultNodeStoreBatchSize)
	viper.SetDefault("tuning.node_store_batch_timeout", "500ms")

	viper.SetDefault("prefixes.allocation", string(IPAllocationStrategySequential))

	err := viper.ReadInConfig()
	if err != nil {
		if _, ok := errors.AsType[viper.ConfigFileNotFoundError](err); ok {
			log.Warn().Msg("no config file found, using defaults")
			return nil
		}

		return fmt.Errorf("fatal error reading config file: %w", err)
	}

	return nil
}

// resolveEphemeralInactivityTimeout resolves the ephemeral inactivity timeout
// from config, supporting both the new key (node.ephemeral.inactivity_timeout)
// and the old key (ephemeral_node_inactivity_timeout) for backwards compatibility.
//
// We cannot use viper.RegisterAlias here because aliases silently ignore
// config values set under the alias name. If a user writes the new key in
// their config file, RegisterAlias redirects reads to the old key (which
// has no config value), returning only the default and discarding the
// user's setting.
func resolveEphemeralInactivityTimeout() time.Duration {
	// New key takes precedence if explicitly set in config.
	if viper.IsSet("node.ephemeral.inactivity_timeout") &&
		viper.GetString("node.ephemeral.inactivity_timeout") != "" {
		return viper.GetDuration("node.ephemeral.inactivity_timeout")
	}

	// Fall back to old key for backwards compatibility.
	if viper.IsSet("ephemeral_node_inactivity_timeout") {
		return viper.GetDuration("ephemeral_node_inactivity_timeout")
	}

	// Default
	return viper.GetDuration("node.ephemeral.inactivity_timeout")
}

// resolveNodeExpiry parses the node.expiry config value.
// Returns 0 if set to "0" (no default expiry) or on parse failure.
func resolveNodeExpiry() time.Duration {
	value := viper.GetString("node.expiry")
	if value == "" || value == "0" {
		return 0
	}

	expiry, err := model.ParseDuration(value)
	if err != nil {
		log.Warn().
			Str("value", value).
			Msg("failed to parse node.expiry, defaulting to no expiry")

		return 0
	}

	return time.Duration(expiry)
}

// validateServerConfig is the test-only entry point. Production code
// goes through LoadServerConfig, which lifts the validator to span
// every config-time sub-builder so the operator sees every problem
// in one render.
func validateServerConfig() error {
	v := &configValidator{}
	validateServerConfigInto(v)

	return v.Err()
}

// validateServerConfigInto runs every viper-level validation rule
// against the provided validator. Caller owns the validator and is
// responsible for inspecting v.Err() once all sub-builders have run.
func validateServerConfigInto(v *configValidator) {
	depr := deprecator{seen: make(set.Set[string])}

	// Register aliases for backward compatibility
	// Has to be called _after_ viper.ReadInConfig()
	// https://github.com/spf13/viper/issues/560

	// Alias the old ACL Policy path with the new configuration option.
	depr.fatalIfNewKeyIsNotUsed("policy.path", "acl_policy_path")

	// Move dns_config -> dns
	depr.fatalIfNewKeyIsNotUsed("dns.magic_dns", "dns_config.magic_dns")
	depr.fatalIfNewKeyIsNotUsed("dns.base_domain", "dns_config.base_domain")
	depr.fatalIfNewKeyIsNotUsed("dns.override_local_dns", "dns_config.override_local_dns")
	depr.fatalIfNewKeyIsNotUsed("dns.nameservers.global", "dns_config.nameservers")
	depr.fatalIfNewKeyIsNotUsed("dns.nameservers.split", "dns_config.restricted_nameservers")
	depr.fatalIfNewKeyIsNotUsed("dns.search_domains", "dns_config.domains")
	depr.fatalIfNewKeyIsNotUsed("dns.extra_records", "dns_config.extra_records")
	depr.fatal("dns.use_username_in_magic_dns")
	depr.fatal("dns_config.use_username_in_magic_dns")

	// Removed since version v0.26.0
	depr.fatal("oidc.strip_email_domain")
	depr.fatal("oidc.map_legacy_users")

	// Removed since v0.29.0: `randomize_client_port` moved to the ACL
	// policy as a top-level `randomizeClientPort` field, matching the
	// Tailscale-hosted control plane schema. Per-node `nodeAttrs`
	// entries granting `https://tailscale.com/cap/randomize-client-port`
	// also work.
	depr.fatalWithHint("randomize_client_port",
		`Set "randomizeClientPort": true at the top level of your policy file `+
			`(see policy.path / policy.mode), or grant the cap per-node via a `+
			`"nodeAttrs" entry. See CHANGELOG.md (BREAKING / Configuration).`)

	// Deprecated: ephemeral_node_inactivity_timeout -> node.ephemeral.inactivity_timeout
	depr.warnNoAlias("node.ephemeral.inactivity_timeout", "ephemeral_node_inactivity_timeout")

	// Removed: oidc.expiry -> node.expiry
	depr.fatalIfSet("oidc.expiry", "node.expiry")

	// Ignored: database.gorm.prepare_stmt. A warning, not a fatal, so configs
	// that shipped with it set still start.
	depr.warn("database.gorm.prepare_stmt")

	// OIDC is activated by setting oidc.issuer (see app.go), not by a
	// dedicated oidc.enabled key. Gate validation on the real activation
	// condition so a misconfiguration fails at startup.
	if viper.GetString("oidc.issuer") != "" {
		err := validateOIDCConfig()
		if err != nil {
			v.Add(&ConfigError{
				Reason: "OIDC configuration is invalid",
				Detail: err.Error(),
				Hint:   "check oidc.issuer, oidc.client_id, oidc.client_secret, and oidc.pkce.method",
				Cause:  err,
			})
		}
	}

	if viper.IsSet("dns.extra_records") && viper.IsSet("dns.extra_records_path") {
		v.Add(&ConfigError{
			Reason: "dns.extra_records and dns.extra_records_path are mutually exclusive",
			Current: []KV{
				{"dns.extra_records_path", viper.GetString("dns.extra_records_path")},
				{"dns.extra_records", "<inline records>"},
			},
			Hint: "keep one (a path is recommended for production); remove the other",
		})
	}

	warnLegacyTLSKeys(&depr)

	if tlsKey("tls.acme.hostname") != "" &&
		(tlsKey("tls.cert_path") != "" || tlsKey("tls.key_path") != "") {
		v.Add(&ConfigError{
			Reason:  "tls.acme.hostname and tls.cert_path/tls.key_path are mutually exclusive",
			Current: []KV{{"tls.acme.hostname", tlsKey("tls.acme.hostname")}},
			ConflictsWith: []KV{
				{"tls.cert_path", tlsKey("tls.cert_path")},
				{"tls.key_path", tlsKey("tls.key_path")},
			},
			Hint: "choose one TLS strategy and unset the other (Let's Encrypt OR a static keypair)",
			See:  "https://headscale.net/stable/ref/tls/",
		})
	}

	if viper.GetString("noise.private_key_path") == "" {
		v.Add(&ConfigError{
			Reason: "noise.private_key_path is required",
			Hint:   "set noise.private_key_path: /var/lib/headscale/noise_private.key (or any writable path)",
			See:    "https://headscale.net/stable/setup/install/official/",
		})
	}

	if tlsKey("tls.acme.hostname") != "" &&
		tlsKey("tls.acme.challenge_type") == TLSALPN01ChallengeType &&
		!strings.HasSuffix(viper.GetString("listen_addr"), ":443") {
		// this is only a warning because there could be something sitting in front of headscale that redirects the traffic (e.g. an iptables rule)
		log.Warn().
			Msg("Warning: when using tls.acme.hostname with TLS-ALPN-01 as challenge type, headscale must be reachable on port 443, i.e. listen_addr should probably end in :443")
	}

	validateListenerCollisions(v)

	if ct := tlsKey("tls.acme.challenge_type"); ct != HTTP01ChallengeType &&
		ct != TLSALPN01ChallengeType && ct != DNS01ChallengeType {
		v.Add(&ConfigError{
			Reason:  "tls.acme.challenge_type has an unsupported value",
			Current: []KV{{"tls.acme.challenge_type", ct}},
			Allowed: []string{HTTP01ChallengeType, TLSALPN01ChallengeType, DNS01ChallengeType},
			Hint:    "pick one of the allowed values; HTTP-01 is the default",
		})
	}

	serverURL := viper.GetString("server_url")
	if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
		v.Add(&ConfigError{
			Reason:  "server_url is missing a scheme",
			Current: []KV{{"server_url", serverURL}},
			Hint:    "prefix the URL with https:// (recommended) or http://",
		})
	}

	// Minimum inactivity time out is keepalive timeout (60s) plus a few seconds
	// to avoid races
	minInactivityTimeout := 65 * time.Second

	ephemeralTimeout := resolveEphemeralInactivityTimeout()
	if ephemeralTimeout <= minInactivityTimeout {
		v.Add(&ConfigError{
			Reason:  "node.ephemeral.inactivity_timeout is below the minimum",
			Current: []KV{{"node.ephemeral.inactivity_timeout", ephemeralTimeout.String()}},
			Minimum: minInactivityTimeout.String(),
			Hint:    "raise the value above the keepalive interval (60s) plus a safety margin",
		})
	}

	if viper.GetBool("dns.override_local_dns") {
		if global := viper.GetStringSlice("dns.nameservers.global"); len(global) == 0 {
			v.Add(&ConfigError{
				Reason: "dns.nameservers.global is required when dns.override_local_dns is true",
				Current: []KV{
					{"dns.override_local_dns", true},
					{"dns.nameservers.global", "[]"},
				},
				Hint: "list at least one upstream nameserver, or set dns.override_local_dns: false",
				See:  dnsDocsURL,
			})
		}
	}

	// Validate HA health probing parameters
	if haInterval := viper.GetDuration("node.routes.ha.probe_interval"); haInterval > 0 {
		if haInterval < 2*time.Second {
			v.Add(&ConfigError{
				Reason:  "node.routes.ha.probe_interval is below the minimum",
				Current: []KV{{"node.routes.ha.probe_interval", haInterval.String()}},
				Minimum: "2s",
				Hint:    "raise the value to at least the minimum",
			})
		}

		haTimeout := viper.GetDuration("node.routes.ha.probe_timeout")
		if haTimeout < 1*time.Second {
			v.Add(&ConfigError{
				Reason:  "node.routes.ha.probe_timeout is below the minimum",
				Current: []KV{{"node.routes.ha.probe_timeout", haTimeout.String()}},
				Minimum: "1s",
				Hint:    "raise the value to at least the minimum",
			})
		}

		if haTimeout >= haInterval {
			v.Add(&ConfigError{
				Reason: "node.routes.ha.probe_timeout must be less than node.routes.ha.probe_interval",
				Current: []KV{
					{"node.routes.ha.probe_timeout", haTimeout.String()},
					{"node.routes.ha.probe_interval", haInterval.String()},
				},
				Hint: "lower probe_timeout below probe_interval (a probe must finish before the next one starts)",
			})
		}
	}

	// Validate tuning parameters
	if size := viper.GetInt("tuning.node_store_batch_size"); size <= 0 {
		v.Add(&ConfigError{
			Reason:  "tuning.node_store_batch_size must be positive",
			Current: []KV{{"tuning.node_store_batch_size", size}},
			Hint:    fmt.Sprintf("set to a positive integer (default: %d)", defaultNodeStoreBatchSize),
		})
	}

	if timeout := viper.GetDuration("tuning.node_store_batch_timeout"); timeout <= 0 {
		v.Add(&ConfigError{
			Reason:  "tuning.node_store_batch_timeout must be positive",
			Current: []KV{{"tuning.node_store_batch_timeout", timeout.String()}},
			Hint:    "set to a positive duration (default: 500ms)",
		})
	}

	validateDERPConfig(v)
	validateDatabaseConfig(v)
	validateMagicDNSConfig(v)
	validateCertificatesConfig(v)

	depr.Apply(v)
}

// validateDERPConfig records ConfigErrors when the embedded DERP server
// is enabled without the addresses or paths it needs.
func validateDERPConfig(v *configValidator) {
	if !viper.GetBool("derp.server.enabled") {
		return
	}

	if viper.GetString("derp.server.stun_listen_addr") == "" {
		v.Add(&ConfigError{
			Reason: "derp.server.stun_listen_addr is required when the embedded DERP server is enabled",
			Current: []KV{
				{"derp.server.enabled", true},
				{"derp.server.stun_listen_addr", ""},
			},
			Hint: `set derp.server.stun_listen_addr (e.g. "0.0.0.0:3478"), or set derp.server.enabled: false`,
			See:  "https://headscale.net/stable/ref/integration/derp/",
		})
	}

	if !viper.GetBool("derp.server.automatically_add_embedded_derp_region") &&
		len(viper.GetStringSlice("derp.paths")) == 0 {
		v.Add(&ConfigError{
			Reason: "derp.paths is required when derp.server.automatically_add_embedded_derp_region is false",
			Current: []KV{
				{"derp.server.automatically_add_embedded_derp_region", false},
				{"derp.paths", "[]"},
			},
			Hint: "list at least one DERP map file (.yaml, .yml, .json or .hujson) in derp.paths, or set automatically_add_embedded_derp_region: true",
		})
	}
}

// validateDatabaseConfig records a ConfigError when database.type is not
// one of the supported backends.
func validateDatabaseConfig(v *configValidator) {
	t := viper.GetString("database.type")
	switch t {
	case DatabaseSqlite, DatabasePostgres, "sqlite":
		return
	}

	v.Add(&ConfigError{
		Reason:  "database.type has an unsupported value",
		Current: []KV{{"database.type", t}},
		Allowed: []string{"sqlite", "sqlite3", "postgres"},
		Hint:    "pick one of the allowed values; sqlite is the default for single-host deployments",
		See:     "https://headscale.net/stable/ref/database/",
	})
}

// validateMagicDNSConfig records a ConfigError when MagicDNS is enabled
// without a base_domain.
func validateMagicDNSConfig(v *configValidator) {
	if !viper.GetBool("dns.magic_dns") {
		return
	}

	if viper.GetString("dns.base_domain") == "" {
		v.Add(&ConfigError{
			Reason: "dns.base_domain is required when dns.magic_dns is true",
			Current: []KV{
				{"dns.magic_dns", true},
				{"dns.base_domain", ""},
			},
			Hint: `set dns.base_domain to a domain you control (e.g. "ts.example.net"), or set dns.magic_dns: false`,
			See:  dnsDocsURL,
		})
	}
}

// validateCertificatesConfig records ConfigErrors when node certificates
// are enabled without what the Tailscale client needs: a MagicDNS name
// it can match exactly, and a provider to publish the challenge.
func validateCertificatesConfig(v *configValidator) {
	if timeout := viper.GetDuration("dns.challenge.propagation_timeout"); timeout < 0 {
		v.Add(&ConfigError{
			Reason:  "dns.challenge.propagation_timeout must not be negative",
			Current: []KV{{"dns.challenge.propagation_timeout", timeout.String()}},
			Hint:    "use 0 to skip waiting for the record on the zone's nameservers",
		})
	}

	enabled := viper.GetBool("dns.certificates.enabled")
	challengeType := tlsKey("tls.acme.challenge_type")
	ownDNS01 := tlsKey("tls.acme.hostname") != "" && challengeType == DNS01ChallengeType

	if (enabled || ownDNS01) && viper.GetString("dns.challenge.provider.name") == "" {
		v.Add(&ConfigError{
			Reason:  "dns.certificates and tls.acme DNS-01 require dns.challenge.provider",
			Current: []KV{{"dns.certificates.enabled", enabled}, {"tls.acme.challenge_type", challengeType}},
			Allowed: hsdns.ProviderNames(),
			Hint:    "configure the DNS provider that hosts dns.base_domain or tls.acme.hostname under dns.challenge.provider",
			See:     dnsDocsURL,
		})
	}

	if !enabled {
		return
	}

	if !viper.GetBool("dns.magic_dns") {
		v.Add(&ConfigError{
			Reason:  "dns.certificates requires dns.magic_dns",
			Current: []KV{{"dns.certificates.enabled", true}, {"dns.magic_dns", false}},
			Hint:    "certificates are issued for MagicDNS names; set dns.magic_dns: true",
			See:     dnsDocsURL,
		})
	}

	base := strings.TrimSuffix(viper.GetString("dns.base_domain"), ".")
	if base != strings.ToLower(base) || dnsname.ValidHostname(base) != nil {
		v.Add(&ConfigError{
			Reason:  "dns.base_domain must be a lowercase DNS name for dns.certificates",
			Current: []KV{{"dns.base_domain", base}},
			Hint:    "Tailscale clients match certificate names exactly; use a lowercase public domain you control",
			See:     dnsDocsURL,
		})
	}

	zone := strings.TrimSuffix(viper.GetString("dns.certificates.zone"), ".")
	if zone != "" && base != zone && !strings.HasSuffix(base, "."+zone) {
		v.Add(&ConfigError{
			Reason:  "dns.base_domain is not inside dns.certificates.zone",
			Current: []KV{{"dns.base_domain", base}, {"dns.certificates.zone", zone}},
			Hint:    "set zone to the DNS zone that contains base_domain, or leave it empty to use base_domain",
			See:     dnsDocsURL,
		})
	}
}

// dnsChallengeConfig builds the DNS-01 provider. Provider keys are read
// one by one, because environment variables never reach into a map.
func dnsChallengeConfig() (DNSChallengeConfig, error) {
	cfg := DNSChallengeConfig{
		PropagationTimeout: viper.GetDuration("dns.challenge.propagation_timeout"),
		Resolvers:          viper.GetStringSlice("dns.challenge.resolvers"),
		ProviderName:       viper.GetString("dns.challenge.provider.name"),
	}

	if len(cfg.Resolvers) == 0 {
		cfg.Resolvers = slices.Clone(defaultChallengeResolvers)
	}

	// Like dns.nameservers, a resolver may be a bare IP.
	for i, r := range cfg.Resolvers {
		_, _, err := net.SplitHostPort(r)
		if err != nil {
			cfg.Resolvers[i] = net.JoinHostPort(r, "53")
		}
	}

	if cfg.ProviderName == "" {
		return cfg, nil
	}

	provider, err := hsdns.NewProvider(
		cfg.ProviderName,
		viper.GetStringMap("dns.challenge.provider"),
		func(key string) (any, bool) {
			key = "dns.challenge.provider." + key

			return viper.Get(key), viper.IsSet(key)
		},
	)
	if err != nil {
		return cfg, err
	}

	// Only node certificates let a client pick what is published; a record
	// shared by headscale's own certificate alone is harmless.
	if iso, ok := provider.(hsdns.Isolator); ok && viper.GetBool("dns.certificates.enabled") {
		err = iso.CheckIsolation()
		if err != nil {
			return cfg, fmt.Errorf("%w for %s: %w", hsdns.ErrProviderConfig, cfg.ProviderName, err)
		}
	}

	cfg.Provider = provider

	return cfg, nil
}

func tlsConfig() TLSConfig {
	return TLSConfig{
		CertPath: util.AbsolutePathFromConfigPath(tlsKey("tls.cert_path")),
		KeyPath:  util.AbsolutePathFromConfigPath(tlsKey("tls.key_path")),
		ACME: ACMEConfig{
			Hostname:      tlsKey("tls.acme.hostname"),
			ChallengeType: tlsKey("tls.acme.challenge_type"),
			HTTPListen:    tlsKey("tls.acme.http_listen"),
			URL:           tlsKey("tls.acme.url"),
			Email:         tlsKey("tls.acme.email"),
			CacheDir:      util.AbsolutePathFromConfigPath(tlsKey("tls.acme.cache_dir")),
		},
	}
}

func derpConfig() DERPConfig {
	serverEnabled := viper.GetBool("derp.server.enabled")
	serverRegionID := viper.GetInt64("derp.server.region_id")
	serverRegionCode := viper.GetString("derp.server.region_code")
	serverRegionName := viper.GetString("derp.server.region_name")
	serverVerifyClients := viper.GetBool("derp.server.verify_clients")
	stunAddr := viper.GetString("derp.server.stun_listen_addr")
	privateKeyPath := util.AbsolutePathFromConfigPath(
		viper.GetString("derp.server.private_key_path"),
	)
	ipv4 := viper.GetString("derp.server.ipv4")
	ipv6 := viper.GetString("derp.server.ipv6")
	automaticallyAddEmbeddedDerpRegion := viper.GetBool(
		"derp.server.automatically_add_embedded_derp_region",
	)

	urlStrs := viper.GetStringSlice("derp.urls")

	urls := make([]url.URL, 0, len(urlStrs))
	for _, urlStr := range urlStrs {
		urlAddr, err := url.Parse(urlStr)
		if err != nil {
			log.Error().
				Caller().
				Str("url", urlStr).
				Err(err).
				Msg("Failed to parse url, ignoring...")

			continue
		}

		urls = append(urls, *urlAddr)
	}

	paths := viper.GetStringSlice("derp.paths")

	autoUpdate := viper.GetBool("derp.auto_update_enabled")
	updateFrequency := viper.GetDuration("derp.update_frequency")

	return DERPConfig{
		ServerEnabled:                      serverEnabled,
		ServerRegionID:                     tailcfg.DERPRegionID(serverRegionID),
		ServerRegionCode:                   serverRegionCode,
		ServerRegionName:                   serverRegionName,
		ServerVerifyClients:                serverVerifyClients,
		ServerPrivateKeyPath:               privateKeyPath,
		STUNAddr:                           stunAddr,
		URLs:                               urls,
		Paths:                              paths,
		AutoUpdate:                         autoUpdate,
		UpdateFrequency:                    updateFrequency,
		IPv4:                               ipv4,
		IPv6:                               ipv6,
		AutomaticallyAddEmbeddedDerpRegion: automaticallyAddEmbeddedDerpRegion,
	}
}

func logtailConfig() LogTailConfig {
	enabled := viper.GetBool("logtail.enabled")

	return LogTailConfig{
		Enabled: enabled,
	}
}

func policyConfig() PolicyConfig {
	policyPath := viper.GetString("policy.path")
	policyMode := viper.GetString("policy.mode")

	return PolicyConfig{
		Path: policyPath,
		Mode: PolicyMode(policyMode),
	}
}

func logConfig() LogConfig {
	logLevelStr := viper.GetString("log.level")

	logLevel, err := zerolog.ParseLevel(logLevelStr)
	if err != nil {
		logLevel = zerolog.DebugLevel
	}

	logFormatOpt := viper.GetString("log.format")

	var logFormat string

	switch logFormatOpt {
	case JSONLogFormat:
		logFormat = JSONLogFormat
	case TextLogFormat:
		logFormat = TextLogFormat
	case "":
		logFormat = TextLogFormat
	default:
		log.Error().
			Caller().
			Str("func", "GetLogConfig").
			Msgf("Could not parse log format: %s. Valid choices are 'json' or 'text'", logFormatOpt)
	}

	return LogConfig{
		Format: logFormat,
		Level:  logLevel,
	}
}

func databaseConfig() DatabaseConfig {
	debug := viper.GetBool("database.debug")

	type_ := viper.GetString("database.type")

	skipErrRecordNotFound := viper.GetBool("database.gorm.skip_err_record_not_found")
	slowThreshold := time.Duration(viper.GetInt64("database.gorm.slow_threshold")) * time.Millisecond
	parameterizedQueries := viper.GetBool("database.gorm.parameterized_queries")

	switch type_ {
	case DatabaseSqlite, DatabasePostgres:
		break
	case "sqlite":
		type_ = "sqlite3"
	}

	return DatabaseConfig{
		Type:  type_,
		Debug: debug,
		Gorm: GormConfig{
			Debug:                 debug,
			SkipErrRecordNotFound: skipErrRecordNotFound,
			SlowThreshold:         slowThreshold,
			ParameterizedQueries:  parameterizedQueries,
		},
		Sqlite: SqliteConfig{
			Path: util.AbsolutePathFromConfigPath(
				viper.GetString("database.sqlite.path"),
			),
			WriteAheadLog:     viper.GetBool("database.sqlite.write_ahead_log"),
			WALAutoCheckPoint: viper.GetInt("database.sqlite.wal_autocheckpoint"),
		},
		Postgres: PostgresConfig{
			Host:               viper.GetString("database.postgres.host"),
			Port:               viper.GetInt("database.postgres.port"),
			Name:               viper.GetString("database.postgres.name"),
			User:               viper.GetString("database.postgres.user"),
			Pass:               viper.GetString("database.postgres.pass"),
			Ssl:                viper.GetString("database.postgres.ssl"),
			MaxOpenConnections: viper.GetInt("database.postgres.max_open_conns"),
			MaxIdleConnections: viper.GetInt("database.postgres.max_idle_conns"),
			ConnMaxIdleTimeSecs: viper.GetInt(
				"database.postgres.conn_max_idle_time_secs",
			),
		},
	}
}

func dns() (DNSConfig, error) {
	var dns DNSConfig

	// TODO: Use this instead of manually getting settings when
	// UnmarshalKey is compatible with Environment Variables.
	// err := viper.UnmarshalKey("dns", &dns)
	// if err != nil {
	// 	return DNSConfig{}, fmt.Errorf("unmarshalling dns config: %w", err)
	// }

	dns.MagicDNS = viper.GetBool("dns.magic_dns")
	dns.BaseDomain = viper.GetString("dns.base_domain")
	dns.OverrideLocalDNS = viper.GetBool("dns.override_local_dns")
	dns.Nameservers.Global = viper.GetStringSlice("dns.nameservers.global")
	dns.Nameservers.Split = viper.GetStringMapStringSlice("dns.nameservers.split")
	dns.SearchDomains = viper.GetStringSlice("dns.search_domains")
	dns.ExtraRecordsPath = viper.GetString("dns.extra_records_path")
	dns.Certificates.Enabled = viper.GetBool("dns.certificates.enabled")
	dns.Certificates.Zone = cmp.Or(viper.GetString("dns.certificates.zone"), dns.BaseDomain)

	if viper.IsSet("dns.extra_records") {
		var extraRecords []tailcfg.DNSRecord

		err := viper.UnmarshalKey("dns.extra_records", &extraRecords)
		if err != nil {
			return DNSConfig{}, fmt.Errorf("unmarshalling dns extra records: %w", err)
		}

		dns.ExtraRecords = extraRecords
	}

	return dns, nil
}

// parseResolvers converts nameserver strings into DNS resolvers.
// If a nameserver is a valid IP, it will be used as a regular resolver.
// If a nameserver is a valid URL, it will be used as a DoH resolver.
// If a nameserver is neither a valid URL nor a valid IP, it will be ignored.
// When domain is non-empty, it is included in the warning for invalid entries.
func parseResolvers(nameservers []string, domain string) []*dnstype.Resolver {
	var resolvers []*dnstype.Resolver

	for _, nsStr := range nameservers {
		if _, err := netip.ParseAddr(nsStr); err == nil { //nolint:noinlineerr
			resolvers = append(resolvers, &dnstype.Resolver{
				Addr: nsStr,
			})

			continue
		}

		if _, err := url.Parse(nsStr); err == nil { //nolint:noinlineerr
			resolvers = append(resolvers, &dnstype.Resolver{
				Addr: nsStr,
			})

			continue
		}

		e := log.Warn().Str("nameserver", nsStr)
		if domain != "" {
			e = e.Str("domain", domain)
		}

		e.Msg("invalid nameserver, ignoring")
	}

	return resolvers
}

// globalResolvers returns the global DNS resolvers
// defined in the config file.
func (d *DNSConfig) globalResolvers() []*dnstype.Resolver {
	return parseResolvers(d.Nameservers.Global, "")
}

// splitResolvers returns a map of domain to DNS resolvers.
func (d *DNSConfig) splitResolvers() map[string][]*dnstype.Resolver {
	routes := make(map[string][]*dnstype.Resolver)

	for domain, nameservers := range d.Nameservers.Split {
		routes[domain] = parseResolvers(nameservers, domain)
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
	if dns.BaseDomain != "" {
		cfg.Domains = []string{dns.BaseDomain}
	}

	cfg.Domains = append(cfg.Domains, dns.SearchDomains...)

	return &cfg
}

// warnBanner prints a highly visible warning banner to the log output.
// It wraps the provided lines in an ASCII-art box with a "Warning!" header.
// This is intended for critical configuration issues that users must not ignore.
func warnBanner(lines []string) {
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

	log.Warn().Msg(b.String())
}

func parsePrefixConfig(key string, standardRange netip.Prefix, family string) (*netip.Prefix, bool, error) {
	s := viper.GetString(key)

	if s == "" {
		return nil, false, nil
	}

	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return nil, false, fmt.Errorf("parsing %s prefix from config: %w", family, err)
	}

	builder := netipx.IPSetBuilder{}
	builder.AddPrefix(standardRange)

	ipSet, _ := builder.IPSet()

	return &prefix, !ipSet.ContainsPrefix(prefix), nil
}

// trustedProxies rejects 0.0.0.0/0 and ::/0 because they defeat the
// peer-trust gate and almost always indicate misconfiguration.
func trustedProxies() ([]netip.Prefix, error) {
	raw := viper.GetStringSlice("trusted_proxies")
	if len(raw) == 0 {
		return nil, nil
	}

	out := make([]netip.Prefix, 0, len(raw))
	for i, s := range raw {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("trusted_proxies[%d] %q: %w", i, s, err)
		}

		if p.Bits() == 0 {
			return nil, fmt.Errorf("trusted_proxies[%d] %q: %w", i, s, errTrustedProxyZeroRange)
		}

		out = append(out, p.Masked())
	}

	return out, nil
}

// LoadCLIConfig returns the needed configuration for the CLI client
// of Headscale to connect to a Headscale server.
func LoadCLIConfig() (*Config, error) {
	logConfig := logConfig()
	zerolog.SetGlobalLevel(logConfig.Level)

	return &Config{
		DisableUpdateCheck: viper.GetBool("disable_check_updates"),
		UnixSocket:         viper.GetString("unix_socket"),
		CLI: CLIConfig{
			Address:  viper.GetString("cli.address"),
			APIKey:   viper.GetString("cli.api_key"),
			Timeout:  viper.GetDuration("cli.timeout"),
			Insecure: viper.GetBool("cli.insecure"),
		},
		Log: logConfig,
	}, nil
}

// LoadServerConfig returns the full Headscale configuration to
// host a Headscale server. This is called as part of `headscale serve`.
func LoadServerConfig() (*Config, error) {
	v := &configValidator{}
	validateServerConfigInto(v)

	logConfig := logConfig()
	zerolog.SetGlobalLevel(logConfig.Level)

	prefix4, v4NonStandard, err := parsePrefixConfig("prefixes.v4", tsaddr.CGNATRange(), "IPv4")
	if err != nil {
		v.Add(&ConfigError{
			Reason:  "prefixes.v4 is not a valid CIDR",
			Current: []KV{{"prefixes.v4", viper.GetString("prefixes.v4")}},
			Detail:  err.Error(),
			Hint:    `use CIDR form, e.g. "100.64.0.0/10" (CGNAT, headscale default)`,
			Cause:   err,
		})
	}

	prefix6, v6NonStandard, err := parsePrefixConfig("prefixes.v6", tsaddr.TailscaleULARange(), "IPv6")
	if err != nil {
		v.Add(&ConfigError{
			Reason:  "prefixes.v6 is not a valid CIDR",
			Current: []KV{{"prefixes.v6", viper.GetString("prefixes.v6")}},
			Detail:  err.Error(),
			Hint:    `use CIDR form, e.g. "fd7a:115c:a1e0::/48" (Tailscale ULA, headscale default)`,
			Cause:   err,
		})
	}

	trusted, err := trustedProxies()
	if err != nil {
		v.Add(&ConfigError{
			Reason:  "trusted_proxies contains an invalid CIDR",
			Current: []KV{{"trusted_proxies", viper.GetStringSlice("trusted_proxies")}},
			Detail:  err.Error(),
			Hint:    "use specific proxy CIDRs; catch-all ranges are not allowed",
			Cause:   err,
		})
	}

	if prefix4 == nil && prefix6 == nil {
		v.Add(&ConfigError{
			Reason: "no IP prefix configured for the tailnet",
			Current: []KV{
				{"prefixes.v4", viper.GetString("prefixes.v4")},
				{"prefixes.v6", viper.GetString("prefixes.v6")},
			},
			Hint:  `set at least one of prefixes.v4 (default: "100.64.0.0/10") or prefixes.v6 (default: "fd7a:115c:a1e0::/48")`,
			Cause: ErrNoPrefixConfigured,
		})
	}

	if v4NonStandard || v6NonStandard {
		warnBanner([]string{
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
		})
	}

	allocStr := viper.GetString("prefixes.allocation")

	var alloc IPAllocationStrategy

	switch allocStr {
	case string(IPAllocationStrategySequential):
		alloc = IPAllocationStrategySequential
	case string(IPAllocationStrategyRandom):
		alloc = IPAllocationStrategyRandom
	default:
		v.Add(&ConfigError{
			Reason:  "prefixes.allocation has an unsupported value",
			Current: []KV{{"prefixes.allocation", allocStr}},
			Allowed: []string{
				string(IPAllocationStrategySequential),
				string(IPAllocationStrategyRandom),
			},
			Hint:  "pick one of the allowed values; sequential is the default",
			Cause: ErrInvalidAllocationStrategy,
		})
	}

	// YAML reads an unquoted 0770 as the integer 504, which cannot be told
	// apart from a literal 504, so only a string is accepted.
	socketPermRaw := viper.Get("unix_socket_permission")
	socketPermStr, _ := socketPermRaw.(string)

	socketPerm, err := util.ParseFileMode(socketPermStr)
	if err != nil {
		v.Add(&ConfigError{
			Reason:  "unix_socket_permission is not a quoted octal file mode",
			Current: []KV{{"unix_socket_permission", socketPermRaw}},
			Maximum: `"0777"`,
			Hint:    `quote the value, e.g. "0770"; unquoted, YAML reads 0770 as the number 504`,
			Cause:   err,
		})
	}

	dnsConfig, err := dns()
	if err != nil {
		v.Add(&ConfigError{
			Reason:  "dns.extra_records cannot be parsed",
			Current: []KV{{"dns.extra_records", "<inline records>"}},
			Detail:  err.Error(),
			Hint:    "check the YAML syntax; see config-example.yaml for the expected shape",
			Cause:   err,
		})
	}

	derpConfig := derpConfig()
	logTailConfig := logtailConfig()

	dnsChallenge, err := dnsChallengeConfig()
	if err != nil {
		// The provider names only help when the name is what is wrong.
		var allowed []string
		if errors.Is(err, hsdns.ErrUnknownProvider) {
			allowed = hsdns.ProviderNames()
		}

		v.Add(&ConfigError{
			Reason:  "dns.challenge.provider is invalid",
			Current: []KV{{"dns.challenge.provider.name", dnsChallenge.ProviderName}},
			Detail:  err.Error(),
			Allowed: allowed,
			Hint:    "check the provider name and its settings; any string setting can be read from a file with <setting>_path",
			See:     dnsDocsURL,
			Cause:   err,
		})
	}

	oidcClientSecret := viper.GetString("oidc.client_secret")
	oidcClientSecretPath := viper.GetString("oidc.client_secret_path")

	switch {
	case oidcClientSecretPath != "" && oidcClientSecret != "":
		v.Add(&ConfigError{
			Reason: "oidc.client_secret and oidc.client_secret_path are mutually exclusive",
			Current: []KV{
				{"oidc.client_secret", "<redacted>"},
				{"oidc.client_secret_path", oidcClientSecretPath},
			},
			Hint:  "keep one source for the secret; the path form is recommended so the secret stays out of config files",
			See:   "https://headscale.net/stable/ref/oidc/",
			Cause: errOidcMutuallyExclusive,
		})

	case oidcClientSecretPath != "":
		secretBytes, err := os.ReadFile(os.ExpandEnv(oidcClientSecretPath))
		if err != nil {
			v.Add(&ConfigError{
				Reason:  "oidc.client_secret_path cannot be read",
				Current: []KV{{"oidc.client_secret_path", oidcClientSecretPath}},
				Detail:  err.Error(),
				Hint:    "ensure the file exists and is readable by the headscale user",
				Cause:   err,
			})
		} else {
			oidcClientSecret = strings.TrimSpace(string(secretBytes))
		}
	}

	serverURL := viper.GetString("server_url")

	// BaseDomain cannot be the same as the server URL.
	// This is because Tailscale takes over the domain in BaseDomain,
	// causing the headscale server and DERP to be unreachable.
	// For Tailscale upstream, the following is true:
	// - DERP run on their own domains
	// - Control plane runs on login.tailscale.com/controlplane.tailscale.com
	// - MagicDNS (BaseDomain) for users is on a *.ts.net domain per tailnet (e.g. tail-scale.ts.net)
	if dnsConfig.BaseDomain != "" {
		err := isSafeServerURL(serverURL, dnsConfig.BaseDomain)
		if err != nil {
			addServerURLConfigError(v, serverURL, dnsConfig.BaseDomain, err)
		}
	}

	err = v.Err()
	if err != nil {
		return nil, err
	}

	return &Config{
		ServerURL:          serverURL,
		Addr:               viper.GetString("listen_addr"),
		MetricsAddr:        viper.GetString("metrics_listen_addr"),
		TrustedProxies:     trusted,
		DisableUpdateCheck: false,

		PrefixV4:     prefix4,
		PrefixV6:     prefix6,
		IPAllocation: alloc,

		NoisePrivateKeyPath: util.AbsolutePathFromConfigPath(
			viper.GetString("noise.private_key_path"),
		),
		BaseDomain: dnsConfig.BaseDomain,

		DERP: derpConfig,

		Node: NodeConfig{
			Expiry: resolveNodeExpiry(),
			Ephemeral: EphemeralConfig{
				InactivityTimeout: resolveEphemeralInactivityTimeout(),
			},
			Routes: RouteConfig{
				HA: HARouteConfig{
					ProbeInterval: viper.GetDuration("node.routes.ha.probe_interval"),
					ProbeTimeout:  viper.GetDuration("node.routes.ha.probe_timeout"),
				},
			},
		},

		PreAuthKeys: PreAuthKeysConfig{
			RevokedRetention: viper.GetDuration("preauth_keys.revoked_retention"),
		},

		Database: databaseConfig(),

		TLS: tlsConfig(),

		DNSConfig:        dnsConfig,
		TailcfgDNSConfig: dnsToTailcfgDNS(dnsConfig),
		DNSChallenge:     dnsChallenge,

		UnixSocket:           viper.GetString("unix_socket"),
		UnixSocketPermission: socketPerm,

		OIDC: OIDCConfig{
			OnlyStartIfOIDCIsAvailable: viper.GetBool(
				"oidc.only_start_if_oidc_is_available",
			),
			Issuer:                viper.GetString("oidc.issuer"),
			ClientID:              viper.GetString("oidc.client_id"),
			ClientSecret:          oidcClientSecret,
			Scope:                 viper.GetStringSlice("oidc.scope"),
			ExtraParams:           viper.GetStringMapString("oidc.extra_params"),
			AllowedDomains:        viper.GetStringSlice("oidc.allowed_domains"),
			AllowedUsers:          viper.GetStringSlice("oidc.allowed_users"),
			AllowedGroups:         viper.GetStringSlice("oidc.allowed_groups"),
			EmailVerifiedRequired: viper.GetBool("oidc.email_verified_required"),
			UseExpiryFromToken:    viper.GetBool("oidc.use_expiry_from_token"),
			PKCE: PKCEConfig{
				Enabled: viper.GetBool("oidc.pkce.enabled"),
				Method:  viper.GetString("oidc.pkce.method"),
			},
		},

		LogTail: logTailConfig,
		Taildrop: TaildropConfig{
			Enabled: viper.GetBool("taildrop.enabled"),
		},
		AutoUpdate: AutoUpdateConfig{
			Enabled: viper.GetBool("auto_update.enabled"),
		},

		Policy: policyConfig(),

		CLI: CLIConfig{
			Address:  viper.GetString("cli.address"),
			APIKey:   viper.GetString("cli.api_key"),
			Timeout:  viper.GetDuration("cli.timeout"),
			Insecure: viper.GetBool("cli.insecure"),
		},

		Log: logConfig,

		Tuning: Tuning{
			NotifierSendTimeout: viper.GetDuration("tuning.notifier_send_timeout"),
			BatchChangeDelay:    viper.GetDuration("tuning.batch_change_delay"),
			NodeMapSessionBufferedChanSize: viper.GetInt(
				"tuning.node_mapsession_buffered_chan_size",
			),
			BatcherWorkers: func() int {
				if workers := viper.GetInt("tuning.batcher_workers"); workers > 0 {
					return workers
				}

				return DefaultBatcherWorkers()
			}(),
			RegisterCacheExpiration: viper.GetDuration("tuning.register_cache_expiration"),
			RegisterCacheMaxEntries: viper.GetInt("tuning.register_cache_max_entries"),
			NodeStoreBatchSize:      viper.GetInt("tuning.node_store_batch_size"),
			NodeStoreBatchTimeout:   viper.GetDuration("tuning.node_store_batch_timeout"),
		},
	}, nil
}

// addServerURLConfigError pushes a structured ConfigError onto v for
// each isSafeServerURL failure mode so the operator sees the issue
// rendered consistently with the rest of the config-load report.
func addServerURLConfigError(v *configValidator, serverURL, baseDomain string, err error) {
	current := []KV{
		{"server_url", serverURL},
		{"dns.base_domain", baseDomain},
	}

	switch {
	case errors.Is(err, errServerURLSame):
		v.Add(&ConfigError{
			Reason:  "server_url and dns.base_domain refer to the same hostname",
			Current: current,
			Hint:    "give server_url a host distinct from dns.base_domain (Tailscale takes over base_domain via MagicDNS)",
			See:     dnsDocsURL,
			Cause:   errServerURLSame,
		})

	case errors.Is(err, errServerURLSuffix):
		v.Add(&ConfigError{
			Reason:  "server_url is a subdomain of dns.base_domain",
			Current: current,
			Hint:    "host headscale on a domain outside dns.base_domain (Tailscale takes over base_domain via MagicDNS)",
			See:     dnsDocsURL,
			Cause:   errServerURLSuffix,
		})

	default:
		v.Add(&ConfigError{
			Reason:  "server_url cannot be parsed",
			Current: []KV{{"server_url", serverURL}},
			Detail:  err.Error(),
			Hint:    "set server_url to an absolute URL, e.g. https://headscale.example.com",
			Cause:   err,
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

// deprecation describes a configuration key that is no longer
// supported. NewKey is the replacement (when one exists) or empty
// when the key has been removed without a replacement.
type deprecation struct {
	OldKey string
	NewKey string
	Hint   string
}

// deprecator collects deprecated configuration keys observed in the
// current viper config. Warns are non-blocking and surface via
// log.Warn; fatals are pushed onto a configValidator as ConfigError
// entries so they merge with the rest of the validation report
// instead of pre-empting it via log.Fatal.
type deprecator struct {
	seen   set.Set[string]
	warns  []deprecation
	fatals []deprecation
}

func (d *deprecator) addWarn(dep deprecation) {
	if d.seen.Contains(dep.OldKey) {
		return
	}

	d.seen.Add(dep.OldKey)
	d.warns = append(d.warns, dep)
}

func (d *deprecator) addFatal(dep deprecation) {
	if d.seen.Contains(dep.OldKey) {
		return
	}

	d.seen.Add(dep.OldKey)
	d.fatals = append(d.fatals, dep)
}

// warnWithAlias registers an alias from newKey to oldKey and records
// a non-blocking warning when oldKey is set.
//
//nolint:unused
func (d *deprecator) warnWithAlias(newKey, oldKey string) {
	// NOTE: RegisterAlias is called with NEW KEY -> OLD KEY
	viper.RegisterAlias(newKey, oldKey)

	if viper.IsSet(oldKey) {
		d.addWarn(deprecation{OldKey: oldKey, NewKey: newKey})
	}
}

// fatal records a removed key (no replacement) as a config error.
func (d *deprecator) fatal(oldKey string) {
	if viper.IsSet(oldKey) {
		d.addFatal(deprecation{OldKey: oldKey})
	}
}

// fatalWithHint behaves like fatal but appends a remediation pointer to
// the message so operators see exactly what to do without leaving the
// terminal. Use it when the removed key has a clean replacement on the
// policy side.
func (d *deprecator) fatalWithHint(oldKey, hint string) {
	if viper.IsSet(oldKey) {
		d.addFatal(deprecation{OldKey: oldKey, Hint: hint})
	}
}

// fatalIfNewKeyIsNotUsed records a config error when oldKey is set
// without newKey, or a warning when both are set (oldKey ignored,
// newKey takes precedence).
func (d *deprecator) fatalIfNewKeyIsNotUsed(newKey, oldKey string) {
	if !viper.IsSet(oldKey) {
		return
	}

	if !viper.IsSet(newKey) {
		d.addFatal(deprecation{OldKey: oldKey, NewKey: newKey})

		return
	}

	d.addWarn(deprecation{OldKey: oldKey, NewKey: newKey})
}

// fatalIfSet records a config error any time oldKey is set, naming
// newKey as the replacement.
func (d *deprecator) fatalIfSet(oldKey, newKey string) {
	if viper.IsSet(oldKey) {
		d.addFatal(deprecation{OldKey: oldKey, NewKey: newKey})
	}
}

// warnNoAlias records a non-blocking warning when oldKey is set,
// pointing operators at newKey.
//
//nolint:unused
func (d *deprecator) warnNoAlias(newKey, oldKey string) {
	if viper.IsSet(oldKey) {
		d.addWarn(deprecation{OldKey: oldKey, NewKey: newKey})
	}
}

// warn records a non-blocking warning when oldKey is set, with no
// replacement to point at.
func (d *deprecator) warn(oldKey string) {
	if viper.IsSet(oldKey) {
		d.addWarn(deprecation{OldKey: oldKey})
	}
}

// Apply emits warns via log.Warn and pushes one *ConfigError per
// fatal onto v. Run after the rest of validation so deprecated-key
// failures surface alongside the other config errors in a single
// pass.
func (d *deprecator) Apply(v *configValidator) {
	for _, w := range d.warns {
		if w.NewKey != "" {
			log.Warn().Msgf(
				"configuration key %q is deprecated; use %q instead",
				w.OldKey, w.NewKey)

			continue
		}

		log.Warn().Msgf("configuration key %q is ignored", w.OldKey)
	}

	for _, f := range d.fatals {
		ce := &ConfigError{
			Current: []KV{{f.OldKey, viper.Get(f.OldKey)}},
		}

		if f.NewKey != "" {
			ce.Reason = fmt.Sprintf(
				"configuration key %s has been removed; use %s instead",
				f.OldKey, f.NewKey)
			ce.Hint = fmt.Sprintf("remove %s and set %s", f.OldKey, f.NewKey)
		} else {
			ce.Reason = fmt.Sprintf("configuration key %s has been removed", f.OldKey)
			if f.Hint != "" {
				ce.Hint = f.Hint
			} else {
				ce.Hint = fmt.Sprintf("remove %s; see the CHANGELOG for context", f.OldKey)
			}
		}

		v.Add(ce)
	}
}

// tailcfgDNSMu guards concurrent access to the mutable ExtraRecords of
// [Config.TailcfgDNSConfig] between the extra-records file watcher (writer)
// and the per-client map builds that clone it (readers). It is a package-level
// lock so [Config] stays freely copyable during construction.
var tailcfgDNSMu sync.RWMutex

// CloneTailcfgDNSConfig returns a deep copy of [Config.TailcfgDNSConfig], or
// nil if none is set. Safe for concurrent use with [Config.SetExtraRecords].
func (c *Config) CloneTailcfgDNSConfig() *tailcfg.DNSConfig {
	tailcfgDNSMu.RLock()
	defer tailcfgDNSMu.RUnlock()

	if c.TailcfgDNSConfig == nil {
		return nil
	}

	return c.TailcfgDNSConfig.Clone()
}

// extraRecordAtOrBelow reports whether an extra DNS record is name or a
// subdomain of it. Case is ignored, as in TLS name matching; name is
// lowercase.
func (c *Config) extraRecordAtOrBelow(name string) bool {
	tailcfgDNSMu.RLock()
	defer tailcfgDNSMu.RUnlock()

	if c.TailcfgDNSConfig == nil {
		return false
	}

	for _, r := range c.TailcfgDNSConfig.ExtraRecords {
		rn := strings.ToLower(strings.TrimSuffix(r.Name, "."))
		if rn == name || strings.HasSuffix(rn, "."+name) {
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

// SetExtraRecords replaces the ExtraRecords of [Config.TailcfgDNSConfig]. Safe
// for concurrent use with [Config.CloneTailcfgDNSConfig].
func (c *Config) SetExtraRecords(records []tailcfg.DNSRecord) {
	tailcfgDNSMu.Lock()
	defer tailcfgDNSMu.Unlock()

	if c.TailcfgDNSConfig != nil {
		c.TailcfgDNSConfig.ExtraRecords = lowercaseRecordNames(records)
	}
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
