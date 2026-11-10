package types

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	hsdns "github.com/juanfont/headscale/hscontrol/dns"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/prometheus/common/model"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
)

const (
	PKCEMethodPlain string = "plain"
	PKCEMethodS256  string = "S256"

	defaultNodeStoreBatchSize = 100

	dnsDocsURL = "https://headscale.net/stable/ref/dns/"
)

var (
	errOIDCIssuerInvalid         = errors.New("oidc.issuer must be a valid http(s) URL")
	errOIDCClientIDRequired      = errors.New("oidc.client_id is required when oidc.issuer is set")
	errOIDCClientSecretRequired  = errors.New("oidc.client_secret is required when oidc.issuer is set")
	errServerURLSuffix           = errors.New("server_url cannot be part of base_domain in a way that could make the DERP and headscale server unreachable")
	errServerURLSame             = errors.New("server_url cannot use the same domain as base_domain in a way that could make the DERP and headscale server unreachable")
	errInvalidPKCEMethod         = errors.New("pkce.method must be either 'plain' or 'S256'")
	errTrustedProxyZeroRange     = errors.New("0.0.0.0/0 and ::/0 are not allowed")
	ErrNoPrefixConfigured        = errors.New("no IPv4 or IPv6 prefix configured, minimum one prefix is required")
	ErrInvalidAllocationStrategy = errors.New("invalid prefix allocation strategy")
	errConfigNotLoaded           = errors.New("configuration not loaded: call types.LoadConfig first")
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

	// ConfigDir resolves relative paths such as policy.path.
	ConfigDir string `json:"-"`

	// UnreadSecrets are the file: secrets [CheckServerConfig] left unread,
	// each as key and path.
	UnreadSecrets []KV `json:"-"`
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
	// loading so `headscale check config` reports bad provider settings,
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
	// ShuffleSeed orders DERP nodes the same on every server of a tailnet.
	ShuffleSeed string `json:"-"`
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

	// RegisterCacheMaxEntries bounds pending registrations. At capacity, new
	// registrations are refused without evicting admitted sessions. SSH checks
	// can also use 64 reserved slots beyond this limit.
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
	err := validatePKCEMethod(src.String("oidc.pkce.method"))
	if err != nil {
		return err
	}

	issuer := src.String("oidc.issuer")

	u, err := url.Parse(issuer)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("%w: got %q", errOIDCIssuerInvalid, issuer)
	}

	if src.String("oidc.client_id") == "" {
		return errOIDCClientIDRequired
	}

	if src.String("oidc.client_secret") == "" {
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

// src is the configuration [LoadConfig] loaded.
var src *configSource

// configFile is the file [LoadConfig] last loaded or failed to load.
var configFile string

// LoadConfig loads defaults, the configuration file and HEADSCALE_*
// environment variables, rejecting unknown and removed keys. It has to be
// called before [LoadServerConfig] and [LoadCLIConfig], which validate the
// values.
func LoadConfig(path string, isFile bool) error {
	configFile = findConfigFile(path, isFile, os.Environ())

	s, err := newConfigSource(path, isFile, os.Environ())
	if err != nil {
		return err
	}

	for _, w := range s.Warnings() {
		log.Warn().Msg(w)
	}

	src = s

	return nil
}

// configDir is where relative paths in the configuration are resolved: the
// config file's directory, or the working directory without a file.
func configDir() string {
	dir := "."
	if src.File() != "" {
		dir = filepath.Dir(src.File())
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return dir
	}

	return abs
}

// ConfigFile returns the file the last [LoadConfig] loaded or failed to
// load, or "" when it found none.
func ConfigFile() string { return configFile }

// LogFormat returns the configured log.format.
func LogFormat() string { return src.String("log.format") }

// UpdateCheckDisabled reports whether disable_check_updates is set.
func UpdateCheckDisabled() bool { return src.Bool("disable_check_updates") }

// DumpConfig renders the loaded configuration, defaults included, as YAML.
func DumpConfig() ([]byte, error) {
	if src == nil {
		return nil, errConfigNotLoaded
	}

	return src.k.Marshal(yaml.Parser())
}

// resolveNodeExpiry parses the node.expiry config value.
// Returns 0 if set to "0" (no default expiry) or on parse failure.
func resolveNodeExpiry() time.Duration {
	value := src.String("node.expiry")
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

var boolConfigKeys = []string{
	"auto_update.enabled",
	"cli.insecure",
	"database.debug",
	"database.gorm.parameterized_queries",
	"database.gorm.skip_err_record_not_found",
	"database.sqlite.write_ahead_log",
	"derp.auto_update_enabled",
	"derp.server.automatically_add_embedded_derp_region",
	"derp.server.enabled",
	"derp.server.verify_clients",
	"disable_check_updates",
	"dns.certificates.enabled",
	"dns.magic_dns",
	"dns.override_local_dns",
	"logtail.enabled",
	"oidc.email_verified_required",
	"oidc.only_start_if_oidc_is_available",
	"oidc.pkce.enabled",
	"oidc.use_expiry_from_token",
	"taildrop.enabled",
}

// Validate raw values before GetBool can discard conversion errors.
func validateBoolConfig(v *configValidator, keys ...string) {
	for _, key := range keys {
		value := src.Get(key)
		if value == nil {
			continue
		}

		_, err := strconv.ParseBool(fmt.Sprint(value))
		if err != nil {
			v.Add(&ConfigError{
				Reason:  key + " is not a boolean",
				Current: []KV{{key, value}},
				Hint:    "use true or false",
				Cause:   err,
			})
		}
	}
}

// validateServerConfigInto runs every config-level validation rule
// against the provided validator. Caller owns the validator and is
// responsible for inspecting v.Err() once all sub-builders have run.
func validateServerConfigInto(v *configValidator) {
	validateBoolConfig(v, boolConfigKeys...)

	// OIDC is activated by setting oidc.issuer (see app.go), not by a
	// dedicated oidc.enabled key. Gate validation on the real activation
	// condition so a misconfiguration fails at startup.
	if src.String("oidc.issuer") != "" {
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

	if src.IsSet("dns.extra_records") && src.IsSet("dns.extra_records_path") {
		v.Add(&ConfigError{
			Reason: "dns.extra_records and dns.extra_records_path are mutually exclusive",
			Current: []KV{
				{"dns.extra_records_path", src.String("dns.extra_records_path")},
				{"dns.extra_records", "<inline records>"},
			},
			Hint: "keep one (a path is recommended for production); remove the other",
		})
	}

	if src.String("tls.acme.hostname") != "" &&
		(src.String("tls.cert_path") != "" || src.String("tls.key_path") != "") {
		v.Add(&ConfigError{
			Reason:  "tls.acme.hostname and tls.cert_path/tls.key_path are mutually exclusive",
			Current: []KV{{"tls.acme.hostname", src.String("tls.acme.hostname")}},
			ConflictsWith: []KV{
				{"tls.cert_path", src.String("tls.cert_path")},
				{"tls.key_path", src.String("tls.key_path")},
			},
			Hint: "choose one TLS strategy and unset the other (Let's Encrypt OR a static keypair)",
			See:  "https://headscale.net/stable/ref/tls/",
		})
	}

	if src.String("noise.private_key_path") == "" {
		v.Add(&ConfigError{
			Reason: "noise.private_key_path is required",
			Hint:   "set noise.private_key_path: /var/lib/headscale/noise_private.key (or any writable path)",
			See:    "https://headscale.net/stable/setup/install/official/",
		})
	}

	if src.String("tls.acme.hostname") != "" &&
		src.String("tls.acme.challenge_type") == TLSALPN01ChallengeType &&
		!strings.HasSuffix(src.String("listen_addr"), ":443") {
		// this is only a warning because there could be something sitting in front of headscale that redirects the traffic (e.g. an iptables rule)
		log.Warn().
			Msg("Warning: when using tls.acme.hostname with TLS-ALPN-01 as challenge type, headscale must be reachable on port 443, i.e. listen_addr should probably end in :443")
	}

	validateListenerCollisions(v)

	if ct := src.String("tls.acme.challenge_type"); ct != HTTP01ChallengeType &&
		ct != TLSALPN01ChallengeType && ct != DNS01ChallengeType {
		v.Add(&ConfigError{
			Reason:  "tls.acme.challenge_type has an unsupported value",
			Current: []KV{{"tls.acme.challenge_type", ct}},
			Allowed: []string{HTTP01ChallengeType, TLSALPN01ChallengeType, DNS01ChallengeType},
			Hint:    "pick one of the allowed values; HTTP-01 is the default",
		})
	}

	serverURL := src.String("server_url")
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

	ephemeralTimeout := src.Duration("node.ephemeral.inactivity_timeout")
	if ephemeralTimeout <= minInactivityTimeout {
		v.Add(&ConfigError{
			Reason:  "node.ephemeral.inactivity_timeout is below the minimum",
			Current: []KV{{"node.ephemeral.inactivity_timeout", ephemeralTimeout.String()}},
			Minimum: minInactivityTimeout.String(),
			Hint:    "raise the value above the keepalive interval (60s) plus a safety margin",
		})
	}

	if src.Bool("dns.override_local_dns") {
		if global := src.StringSlice("dns.nameservers.global"); len(global) == 0 {
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
	if haInterval := src.Duration("node.routes.ha.probe_interval"); haInterval > 0 {
		if haInterval < 2*time.Second {
			v.Add(&ConfigError{
				Reason:  "node.routes.ha.probe_interval is below the minimum",
				Current: []KV{{"node.routes.ha.probe_interval", haInterval.String()}},
				Minimum: "2s",
				Hint:    "raise the value to at least the minimum",
			})
		}

		haTimeout := src.Duration("node.routes.ha.probe_timeout")
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
	if size := src.Int("tuning.node_store_batch_size"); size <= 0 {
		v.Add(&ConfigError{
			Reason:  "tuning.node_store_batch_size must be positive",
			Current: []KV{{"tuning.node_store_batch_size", size}},
			Hint:    fmt.Sprintf("set to a positive integer (default: %d)", defaultNodeStoreBatchSize),
		})
	}

	if timeout := src.Duration("tuning.node_store_batch_timeout"); timeout <= 0 {
		v.Add(&ConfigError{
			Reason:  "tuning.node_store_batch_timeout must be positive",
			Current: []KV{{"tuning.node_store_batch_timeout", timeout.String()}},
			Hint:    "set to a positive duration (default: 500ms)",
		})
	}

	validateDERPConfig(v)
	validateDatabaseConfig(v)
	validatePolicyConfig(v)
	validateMagicDNSConfig(v)
	validateCertificatesConfig(v)
}

// validatePolicyConfig records a ConfigError for an unknown policy.mode:
// startup would load no policy at all and allow all traffic.
func validatePolicyConfig(v *configValidator) {
	m := src.String("policy.mode")
	if m == PolicyModeFile || m == PolicyModeDB {
		return
	}

	v.Add(&ConfigError{
		Reason:  "policy.mode has an unsupported value",
		Current: []KV{{"policy.mode", m}},
		Allowed: []string{PolicyModeFile, PolicyModeDB},
		See:     "https://headscale.net/stable/ref/policy/",
	})
}

// validateDERPConfig records ConfigErrors when the embedded DERP server
// is enabled without the addresses or paths it needs.
func validateDERPConfig(v *configValidator) {
	if !src.Bool("derp.server.enabled") {
		return
	}

	if src.String("derp.server.stun_listen_addr") == "" {
		v.Add(&ConfigError{
			Reason: "derp.server.stun_listen_addr is required when the embedded DERP server is enabled",
			Current: []KV{
				{"derp.server.enabled", true},
				{"derp.server.stun_listen_addr", ""},
			},
			Hint: `set derp.server.stun_listen_addr (e.g. "0.0.0.0:3478"), or set derp.server.enabled: false`,
			See:  "https://headscale.net/stable/ref/derp/",
		})
	}

	derpKey, noiseKey := src.String("derp.server.private_key_path"), src.String("noise.private_key_path")
	switch {
	case derpKey == "":
		v.Add(&ConfigError{
			Reason: "derp.server.private_key_path is required when the embedded DERP server is enabled",
			Current: []KV{
				{"derp.server.enabled", true},
				{"derp.server.private_key_path", ""},
			},
			Hint: `set derp.server.private_key_path (e.g. "/var/lib/headscale/derp_server_private.key"), or set derp.server.enabled: false`,
			See:  "https://headscale.net/stable/ref/derp/",
		})
	case filepath.Clean(derpKey) == filepath.Clean(noiseKey):
		// Startup would create one key and then refuse it for both uses.
		v.Add(&ConfigError{
			Reason: "derp.server.private_key_path must differ from noise.private_key_path",
			Current: []KV{
				{"derp.server.private_key_path", derpKey},
				{"noise.private_key_path", noiseKey},
			},
			Hint: `set derp.server.private_key_path to its own file (e.g. "/var/lib/headscale/derp_server_private.key")`,
			See:  "https://headscale.net/stable/ref/derp/",
		})
	}

	if !src.Bool("derp.server.automatically_add_embedded_derp_region") &&
		len(src.StringSlice("derp.paths")) == 0 {
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
	t := src.String("database.type")
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
	if !src.Bool("dns.magic_dns") {
		return
	}

	if src.String("dns.base_domain") == "" {
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
	if timeout := src.Duration("dns.challenge.propagation_timeout"); timeout < 0 {
		v.Add(&ConfigError{
			Reason:  "dns.challenge.propagation_timeout must not be negative",
			Current: []KV{{"dns.challenge.propagation_timeout", timeout.String()}},
			Hint:    "use 0 to skip waiting for the record on the zone's nameservers",
		})
	}

	enabled := src.Bool("dns.certificates.enabled")
	challengeType := src.String("tls.acme.challenge_type")
	ownDNS01 := src.String("tls.acme.hostname") != "" && challengeType == DNS01ChallengeType

	if (enabled || ownDNS01) && src.String("dns.challenge.provider.name") == "" {
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

	if !src.Bool("dns.magic_dns") {
		v.Add(&ConfigError{
			Reason:  "dns.certificates requires dns.magic_dns",
			Current: []KV{{"dns.certificates.enabled", true}, {"dns.magic_dns", false}},
			Hint:    "certificates are issued for MagicDNS names; set dns.magic_dns: true",
			See:     dnsDocsURL,
		})
	}

	base := strings.TrimSuffix(src.String("dns.base_domain"), ".")
	if base != strings.ToLower(base) || dnsname.ValidHostname(base) != nil {
		v.Add(&ConfigError{
			Reason:  "dns.base_domain must be a lowercase DNS name for dns.certificates",
			Current: []KV{{"dns.base_domain", base}},
			Hint:    "Tailscale clients match certificate names exactly; use a lowercase public domain you control",
			See:     dnsDocsURL,
		})
	}

	zone := strings.TrimSuffix(src.String("dns.certificates.zone"), ".")
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
func dnsChallengeConfig(secret func(key, value string) (string, error)) (DNSChallengeConfig, error) {
	cfg := DNSChallengeConfig{
		PropagationTimeout: src.Duration("dns.challenge.propagation_timeout"),
		Resolvers:          src.StringSlice("dns.challenge.resolvers"),
		ProviderName:       src.String("dns.challenge.provider.name"),
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
		src.StringMap("dns.challenge.provider"),
		func(key string) (any, bool) {
			key = "dns.challenge.provider." + key

			// Provider fields are not in configKeys, so the source never
			// maps their variables.
			if v := os.Getenv(configEnvName(key)); v != "" {
				return v, true
			}

			return src.Get(key), src.IsSet(key)
		},
		func(key, value string) (string, error) {
			return secret("dns.challenge.provider."+key, value)
		},
	)
	if err != nil {
		return cfg, err
	}

	// Only node certificates let a client pick what is published; a record
	// shared by headscale's own certificate alone is harmless.
	if iso, ok := provider.(hsdns.Isolator); ok && src.Bool("dns.certificates.enabled") {
		err = iso.CheckIsolation()
		if err != nil {
			return cfg, fmt.Errorf("%w for %s: %w", hsdns.ErrProviderConfig, cfg.ProviderName, err)
		}
	}

	cfg.Provider = provider

	return cfg, nil
}

func tlsConfig(dir string) TLSConfig {
	return TLSConfig{
		CertPath: util.AbsolutePath(dir, src.String("tls.cert_path")),
		KeyPath:  util.AbsolutePath(dir, src.String("tls.key_path")),
		ACME: ACMEConfig{
			Hostname:      src.String("tls.acme.hostname"),
			ChallengeType: src.String("tls.acme.challenge_type"),
			HTTPListen:    src.String("tls.acme.http_listen"),
			URL:           src.String("tls.acme.url"),
			Email:         src.String("tls.acme.email"),
			CacheDir:      util.AbsolutePath(dir, src.String("tls.acme.cache_dir")),
		},
	}
}

func derpConfig(dir string) DERPConfig {
	serverEnabled := src.Bool("derp.server.enabled")
	serverRegionID := src.Int64("derp.server.region_id")
	serverRegionCode := src.String("derp.server.region_code")
	serverRegionName := src.String("derp.server.region_name")
	serverVerifyClients := src.Bool("derp.server.verify_clients")
	stunAddr := src.String("derp.server.stun_listen_addr")
	privateKeyPath := util.AbsolutePath(dir, src.String("derp.server.private_key_path"))
	ipv4 := src.String("derp.server.ipv4")
	ipv6 := src.String("derp.server.ipv6")
	automaticallyAddEmbeddedDerpRegion := src.Bool(
		"derp.server.automatically_add_embedded_derp_region",
	)

	urlStrs := src.StringSlice("derp.urls")

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

	paths := src.StringSlice("derp.paths")

	autoUpdate := src.Bool("derp.auto_update_enabled")
	updateFrequency := src.Duration("derp.update_frequency")

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
		ShuffleSeed:                        src.String("dns.base_domain"),
	}
}

func logtailConfig() LogTailConfig {
	enabled := src.Bool("logtail.enabled")

	return LogTailConfig{
		Enabled: enabled,
	}
}

func policyConfig() PolicyConfig {
	policyPath := src.String("policy.path")
	policyMode := src.String("policy.mode")

	return PolicyConfig{
		Path: policyPath,
		Mode: PolicyMode(policyMode),
	}
}

func logConfig() LogConfig {
	logLevelStr := src.String("log.level")

	logLevel, err := zerolog.ParseLevel(logLevelStr)
	if err != nil {
		logLevel = zerolog.DebugLevel
	}

	logFormatOpt := src.String("log.format")

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

// sqlitePath resolves database.sqlite.path, keeping SQLite's in-memory
// name, which is not a file.
func sqlitePath(dir string) string {
	path := src.String("database.sqlite.path")
	if path == ":memory:" {
		return path
	}

	return util.AbsolutePath(dir, path)
}

func databaseConfig(v *configValidator, secret func(key, value string) (string, error), dir string) DatabaseConfig {
	debug := src.Bool("database.debug")

	type_ := src.String("database.type")

	skipErrRecordNotFound := src.Bool("database.gorm.skip_err_record_not_found")
	slowThreshold := time.Duration(src.Int64("database.gorm.slow_threshold")) * time.Millisecond
	parameterizedQueries := src.Bool("database.gorm.parameterized_queries")

	switch type_ {
	case DatabaseSqlite, DatabasePostgres:
		break
	case "sqlite":
		type_ = "sqlite3"
	}

	pass := src.String("database.postgres.pass")
	if type_ == DatabasePostgres {
		pass = configSecret(v, secret, "database.postgres.pass", pass)
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
			Path:              sqlitePath(dir),
			WriteAheadLog:     src.Bool("database.sqlite.write_ahead_log"),
			WALAutoCheckPoint: src.Int("database.sqlite.wal_autocheckpoint"),
		},
		Postgres: PostgresConfig{
			Host:               src.String("database.postgres.host"),
			Port:               src.Int("database.postgres.port"),
			Name:               src.String("database.postgres.name"),
			User:               src.String("database.postgres.user"),
			Pass:               pass,
			Ssl:                src.String("database.postgres.ssl"),
			MaxOpenConnections: src.Int("database.postgres.max_open_conns"),
			MaxIdleConnections: src.Int("database.postgres.max_idle_conns"),
			ConnMaxIdleTimeSecs: src.Int(
				"database.postgres.conn_max_idle_time_secs",
			),
		},
	}
}

func dns() (DNSConfig, error) {
	var dns DNSConfig

	// TODO: Use this instead of manually getting settings when
	// UnmarshalKey is compatible with Environment Variables.
	// err := src.UnmarshalKey("dns", &dns)
	// if err != nil {
	// 	return DNSConfig{}, fmt.Errorf("unmarshalling dns config: %w", err)
	// }

	dns.MagicDNS = src.Bool("dns.magic_dns")
	dns.BaseDomain = src.String("dns.base_domain")
	dns.OverrideLocalDNS = src.Bool("dns.override_local_dns")
	dns.Nameservers.Global = src.StringSlice("dns.nameservers.global")
	dns.Nameservers.Split = src.StringMapStringSlice("dns.nameservers.split")
	dns.SearchDomains = src.StringSlice("dns.search_domains")
	dns.ExtraRecordsPath = src.String("dns.extra_records_path")
	dns.Certificates.Enabled = src.Bool("dns.certificates.enabled")
	dns.Certificates.Zone = cmp.Or(src.String("dns.certificates.zone"), dns.BaseDomain)

	if src.IsSet("dns.extra_records") {
		var extraRecords []tailcfg.DNSRecord

		err := src.UnmarshalKey("dns.extra_records", &extraRecords)
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
	// Only MagicDNS answers for the base domain, and SaaS sends it only then. Sent
	// alone, it left a client that writes resolv.conf itself with a search line
	// and no nameserver.
	if dns.MagicDNS && dns.BaseDomain != "" {
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
	s := src.String(key)

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
	raw := src.StringSlice("trusted_proxies")
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
	if src == nil {
		return nil, errConfigNotLoaded
	}

	v := &configValidator{}
	validateBoolConfig(v, "cli.insecure", "disable_check_updates")
	// Over the unix socket the CLI needs no key, so it is not read.
	cliAPIKey := src.String("cli.api_key")
	if src.String("cli.address") != "" {
		cliAPIKey = configSecret(v, resolveSecret, "cli.api_key", cliAPIKey)
	}

	err := v.Err()
	if err != nil {
		return nil, err
	}

	logConfig := logConfig()
	zerolog.SetGlobalLevel(logConfig.Level)

	return &Config{
		DisableUpdateCheck: src.Bool("disable_check_updates"),
		UnixSocket:         src.String("unix_socket"),
		CLI: CLIConfig{
			Address:  src.String("cli.address"),
			APIKey:   cliAPIKey,
			Timeout:  src.Duration("cli.timeout"),
			Insecure: src.Bool("cli.insecure"),
		},
		Log: logConfig,
	}, nil
}

// LoadServerConfig returns the full Headscale configuration to
// host a Headscale server. This is called as part of `headscale serve`.
func LoadServerConfig() (*Config, error) {
	return loadServerConfig(resolveSecret)
}

// CheckServerConfig validates the server configuration as
// LoadServerConfig does, without reading the files file: secrets name; it
// lists them in UnreadSecrets instead.
func CheckServerConfig() (*Config, error) {
	var unread []KV

	cfg, err := loadServerConfig(func(key, value string) (string, error) {
		s, err := keepSecret(key, value)
		if errors.Is(err, hsdns.ErrSecretUnread) {
			unread = append(unread, KV{key, strings.TrimPrefix(value, "file:")})
		}

		return s, err
	})
	if cfg != nil {
		// Provider settings are visited in map order.
		slices.SortFunc(unread, func(a, b KV) int { return strings.Compare(a.Key, b.Key) })
		cfg.UnreadSecrets = unread
	}

	return cfg, err
}

func loadServerConfig(secret func(key, value string) (string, error)) (*Config, error) {
	if src == nil {
		return nil, errConfigNotLoaded
	}

	v := &configValidator{}
	validateServerConfigInto(v)

	logConfig := logConfig()
	zerolog.SetGlobalLevel(logConfig.Level)

	prefix4, v4NonStandard, err := parsePrefixConfig("prefixes.v4", tsaddr.CGNATRange(), "IPv4")
	if err != nil {
		v.Add(&ConfigError{
			Reason:  "prefixes.v4 is not a valid CIDR",
			Current: []KV{{"prefixes.v4", src.String("prefixes.v4")}},
			Detail:  err.Error(),
			Hint:    `use CIDR form, e.g. "100.64.0.0/10" (CGNAT, headscale default)`,
			Cause:   err,
		})
	}

	prefix6, v6NonStandard, err := parsePrefixConfig("prefixes.v6", tsaddr.TailscaleULARange(), "IPv6")
	if err != nil {
		v.Add(&ConfigError{
			Reason:  "prefixes.v6 is not a valid CIDR",
			Current: []KV{{"prefixes.v6", src.String("prefixes.v6")}},
			Detail:  err.Error(),
			Hint:    `use CIDR form, e.g. "fd7a:115c:a1e0::/48" (Tailscale ULA, headscale default)`,
			Cause:   err,
		})
	}

	trusted, err := trustedProxies()
	if err != nil {
		v.Add(&ConfigError{
			Reason:  "trusted_proxies contains an invalid CIDR",
			Current: []KV{{"trusted_proxies", src.StringSlice("trusted_proxies")}},
			Detail:  err.Error(),
			Hint:    "use specific proxy CIDRs; catch-all ranges are not allowed",
			Cause:   err,
		})
	}

	if prefix4 == nil && prefix6 == nil {
		v.Add(&ConfigError{
			Reason: "no IP prefix configured for the tailnet",
			Current: []KV{
				{"prefixes.v4", src.String("prefixes.v4")},
				{"prefixes.v6", src.String("prefixes.v6")},
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

	allocStr := src.String("prefixes.allocation")

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
	socketPermRaw := src.Get("unix_socket_permission")
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

	dir := configDir()
	derpConfig := derpConfig(dir)
	logTailConfig := logtailConfig()

	dnsChallenge, err := dnsChallengeConfig(secret)
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
			Hint:    `check the provider name and its settings; any string setting can be read from a file with "file:<path>"`,
			See:     dnsDocsURL,
			Cause:   err,
		})
	}

	// OIDC is active only with an issuer; see validateServerConfigInto.
	oidcClientSecret := src.String("oidc.client_secret")
	if src.String("oidc.issuer") != "" {
		oidcClientSecret = configSecret(v, secret, "oidc.client_secret", oidcClientSecret)
	}

	database := databaseConfig(v, secret, dir)

	serverURL := strings.TrimRight(src.String("server_url"), "/")

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
		Addr:               src.String("listen_addr"),
		MetricsAddr:        src.String("metrics_listen_addr"),
		TrustedProxies:     trusted,
		ConfigDir:          dir,
		DisableUpdateCheck: src.Bool("disable_check_updates"),

		PrefixV4:     prefix4,
		PrefixV6:     prefix6,
		IPAllocation: alloc,

		NoisePrivateKeyPath: util.AbsolutePath(dir, src.String("noise.private_key_path")),
		BaseDomain:          dnsConfig.BaseDomain,

		DERP: derpConfig,

		Node: NodeConfig{
			Expiry: resolveNodeExpiry(),
			Ephemeral: EphemeralConfig{
				InactivityTimeout: src.Duration("node.ephemeral.inactivity_timeout"),
			},
			Routes: RouteConfig{
				HA: HARouteConfig{
					ProbeInterval: src.Duration("node.routes.ha.probe_interval"),
					ProbeTimeout:  src.Duration("node.routes.ha.probe_timeout"),
				},
			},
		},

		PreAuthKeys: PreAuthKeysConfig{
			RevokedRetention: src.Duration("preauth_keys.revoked_retention"),
		},

		Database: database,

		TLS: tlsConfig(dir),

		DNSConfig:        dnsConfig,
		TailcfgDNSConfig: dnsToTailcfgDNS(dnsConfig),
		DNSChallenge:     dnsChallenge,

		UnixSocket:           src.String("unix_socket"),
		UnixSocketPermission: socketPerm,

		OIDC: OIDCConfig{
			OnlyStartIfOIDCIsAvailable: src.Bool(
				"oidc.only_start_if_oidc_is_available",
			),
			Issuer:                src.String("oidc.issuer"),
			ClientID:              src.String("oidc.client_id"),
			ClientSecret:          oidcClientSecret,
			Scope:                 src.StringSlice("oidc.scope"),
			ExtraParams:           src.StringMapString("oidc.extra_params"),
			AllowedDomains:        src.StringSlice("oidc.allowed_domains"),
			AllowedUsers:          src.StringSlice("oidc.allowed_users"),
			AllowedGroups:         src.StringSlice("oidc.allowed_groups"),
			EmailVerifiedRequired: src.Bool("oidc.email_verified_required"),
			UseExpiryFromToken:    src.Bool("oidc.use_expiry_from_token"),
			PKCE: PKCEConfig{
				Enabled: src.Bool("oidc.pkce.enabled"),
				Method:  src.String("oidc.pkce.method"),
			},
		},

		LogTail: logTailConfig,
		Taildrop: TaildropConfig{
			Enabled: src.Bool("taildrop.enabled"),
		},
		AutoUpdate: AutoUpdateConfig{
			Enabled: src.Bool("auto_update.enabled"),
		},

		Policy: policyConfig(),

		// No APIKey: the server never uses the CLI's key, which may be an
		// unresolved file: reference here.
		CLI: CLIConfig{
			Address:  src.String("cli.address"),
			Timeout:  src.Duration("cli.timeout"),
			Insecure: src.Bool("cli.insecure"),
		},

		Log: logConfig,

		Tuning: Tuning{
			NotifierSendTimeout: src.Duration("tuning.notifier_send_timeout"),
			BatchChangeDelay:    src.Duration("tuning.batch_change_delay"),
			NodeMapSessionBufferedChanSize: src.Int(
				"tuning.node_mapsession_buffered_chan_size",
			),
			BatcherWorkers: func() int {
				if workers := src.Int("tuning.batcher_workers"); workers > 0 {
					return workers
				}

				return DefaultBatcherWorkers()
			}(),
			RegisterCacheExpiration: src.Duration("tuning.register_cache_expiration"),
			RegisterCacheMaxEntries: src.Int("tuning.register_cache_max_entries"),
			NodeStoreBatchSize:      src.Int("tuning.node_store_batch_size"),
			NodeStoreBatchTimeout:   src.Duration("tuning.node_store_batch_timeout"),
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
	tailcfgDNSMu.RLock()
	defer tailcfgDNSMu.RUnlock()

	if c.TailcfgDNSConfig == nil {
		return false
	}

	for _, r := range c.TailcfgDNSConfig.ExtraRecords {
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
