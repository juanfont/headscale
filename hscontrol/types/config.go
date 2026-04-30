package types

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/prometheus/common/model"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/set"
)

const (
	PKCEMethodPlain string = "plain"
	PKCEMethodS256  string = "S256"

	defaultNodeStoreBatchSize = 100
)

var (
	errOidcMutuallyExclusive     = errors.New("oidc_client_secret and oidc_client_secret_path are mutually exclusive")
	errServerURLSuffix           = errors.New("server_url cannot be part of base_domain in a way that could make the DERP and headscale server unreachable")
	errServerURLSame             = errors.New("server_url cannot use the same domain as base_domain in a way that could make the DERP and headscale server unreachable")
	errInvalidPKCEMethod         = errors.New("pkce.method must be either 'plain' or 'S256'")
	ErrNoPrefixConfigured        = errors.New("no IPv4 or IPv6 prefix configured, minimum one prefix is required")
	ErrInvalidAllocationStrategy = errors.New("invalid prefix allocation strategy")
)

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
	// before declaring a node unhealthy. Must be less than ProbeInterval.
	ProbeTimeout time.Duration
}

// RouteConfig contains configuration for route behaviour.
type RouteConfig struct {
	HA HARouteConfig
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
	GRPCAddr            string
	GRPCAllowInsecure   bool
	Node                NodeConfig
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

	ACMEURL   string
	ACMEEmail string

	// DNSConfig is the headscale representation of the DNS configuration.
	// It is kept in the config update for some settings that are
	// not directly converted into a tailcfg.DNSConfig.
	DNSConfig DNSConfig

	// TailcfgDNSConfig is the tailcfg representation of the DNS configuration,
	// it can be used directly when sending Netmaps to clients.
	TailcfgDNSConfig *tailcfg.DNSConfig

	UnixSocket           string
	UnixSocketPermission fs.FileMode

	OIDC OIDCConfig

	LogTail             LogTailConfig
	RandomizeClientPort bool
	Taildrop            TaildropConfig

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

type GormConfig struct {
	Debug                 bool
	SlowThreshold         time.Duration
	SkipErrRecordNotFound bool
	ParameterizedQueries  bool
	PrepareStmt           bool
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

	LetsEncrypt LetsEncryptConfig
}

type LetsEncryptConfig struct {
	Listen        string
	Hostname      string
	CacheDir      string
	ChallengeType string
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
	ServerRegionID                     int
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
	// When NodeStoreBatchSize operations haven't accumulated, this timeout ensures
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

// Domain returns the hostname/domain part of the ServerURL.
// If the ServerURL is not a valid URL, it returns the BaseDomain.
func (c *Config) Domain() string {
	u, err := url.Parse(c.ServerURL)
	if err != nil {
		return c.BaseDomain
	}

	return u.Hostname()
}

// LoadConfig prepares and loads the Headscale configuration into Viper.
// This means it sets the default values, reads the configuration file and
// environment variables, and handles deprecated configuration options.
// It has to be called before LoadServerConfig and LoadCLIConfig.
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

	viper.SetDefault("tls_letsencrypt_cache_dir", "/var/www/.cache")
	viper.SetDefault("tls_letsencrypt_challenge_type", HTTP01ChallengeType)
	viper.SetDefault("tls_letsencrypt_listen", ":http")

	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.format", TextLogFormat)

	viper.SetDefault("dns.magic_dns", true)
	viper.SetDefault("dns.base_domain", "")
	viper.SetDefault("dns.override_local_dns", true)
	viper.SetDefault("dns.nameservers.global", []string{})
	viper.SetDefault("dns.nameservers.split", map[string]string{})
	viper.SetDefault("dns.search_domains", []string{})

	viper.SetDefault("derp.server.enabled", false)
	viper.SetDefault("derp.server.verify_clients", true)
	viper.SetDefault("derp.server.stun.enabled", true)
	viper.SetDefault("derp.server.automatically_add_embedded_derp_region", true)
	viper.SetDefault("derp.update_frequency", "3h")

	viper.SetDefault("unix_socket", "/var/run/headscale/headscale.sock")
	viper.SetDefault("unix_socket_permission", "0o770")

	viper.SetDefault("grpc_listen_addr", ":50443")
	viper.SetDefault("grpc_allow_insecure", false)

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
	viper.SetDefault("randomize_client_port", false)
	viper.SetDefault("taildrop.enabled", true)

	viper.SetDefault("node.expiry", "0")
	viper.SetDefault("node.ephemeral.inactivity_timeout", "120s")
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

func validateServerConfig() error {
	depr := deprecator{
		warns:  make(set.Set[string]),
		fatals: make(set.Set[string]),
	}

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

	// Deprecated: ephemeral_node_inactivity_timeout -> node.ephemeral.inactivity_timeout
	depr.warnNoAlias("node.ephemeral.inactivity_timeout", "ephemeral_node_inactivity_timeout")

	// Removed: oidc.expiry -> node.expiry
	depr.fatalIfSet("oidc.expiry", "node.expiry")

	if viper.GetBool("oidc.enabled") {
		err := validatePKCEMethod(viper.GetString("oidc.pkce.method"))
		if err != nil {
			return err
		}
	}

	depr.Log()

	v := &configValidator{}

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

	if (viper.GetString("tls_letsencrypt_hostname") != "") &&
		((viper.GetString("tls_cert_path") != "") || (viper.GetString("tls_key_path") != "")) {
		v.Add(&ConfigError{
			Reason:  "tls_letsencrypt_hostname and tls_cert_path/tls_key_path are mutually exclusive",
			Current: []KV{{"tls_letsencrypt_hostname", viper.GetString("tls_letsencrypt_hostname")}},
			ConflictsWith: []KV{
				{"tls_cert_path", viper.GetString("tls_cert_path")},
				{"tls_key_path", viper.GetString("tls_key_path")},
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

	if (viper.GetString("tls_letsencrypt_hostname") != "") &&
		(viper.GetString("tls_letsencrypt_challenge_type") == TLSALPN01ChallengeType) &&
		(!strings.HasSuffix(viper.GetString("listen_addr"), ":443")) {
		// this is only a warning because there could be something sitting in front of headscale that redirects the traffic (e.g. an iptables rule)
		log.Warn().
			Msg("Warning: when using tls_letsencrypt_hostname with TLS-ALPN-01 as challenge type, headscale must be reachable on port 443, i.e. listen_addr should probably end in :443")
	}

	validateListenerCollisions(v)

	if ct := viper.GetString("tls_letsencrypt_challenge_type"); ct != HTTP01ChallengeType && ct != TLSALPN01ChallengeType {
		v.Add(&ConfigError{
			Reason:  "tls_letsencrypt_challenge_type has an unsupported value",
			Current: []KV{{"tls_letsencrypt_challenge_type", ct}},
			Allowed: []string{HTTP01ChallengeType, TLSALPN01ChallengeType},
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
	minInactivityTimeout, _ := time.ParseDuration("65s")

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
				See:  "https://headscale.net/stable/ref/dns/",
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

	return v.Err()
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
			Hint: "list at least one DERP map JSON file in derp.paths, or set automatically_add_embedded_derp_region: true",
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
			See:  "https://headscale.net/stable/ref/dns/",
		})
	}
}

func tlsConfig() TLSConfig {
	return TLSConfig{
		LetsEncrypt: LetsEncryptConfig{
			Hostname: viper.GetString("tls_letsencrypt_hostname"),
			Listen:   viper.GetString("tls_letsencrypt_listen"),
			CacheDir: util.AbsolutePathFromConfigPath(
				viper.GetString("tls_letsencrypt_cache_dir"),
			),
			ChallengeType: viper.GetString("tls_letsencrypt_challenge_type"),
		},
		CertPath: util.AbsolutePathFromConfigPath(
			viper.GetString("tls_cert_path"),
		),
		KeyPath: util.AbsolutePathFromConfigPath(
			viper.GetString("tls_key_path"),
		),
	}
}

func derpConfig() DERPConfig {
	serverEnabled := viper.GetBool("derp.server.enabled")
	serverRegionID := viper.GetInt("derp.server.region_id")
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

	urls := make([]url.URL, len(urlStrs))
	for index, urlStr := range urlStrs {
		urlAddr, err := url.Parse(urlStr)
		if err != nil {
			log.Error().
				Caller().
				Str("url", urlStr).
				Err(err).
				Msg("Failed to parse url, ignoring...")
		}

		urls[index] = *urlAddr
	}

	paths := viper.GetStringSlice("derp.paths")

	autoUpdate := viper.GetBool("derp.auto_update_enabled")
	updateFrequency := viper.GetDuration("derp.update_frequency")

	return DERPConfig{
		ServerEnabled:                      serverEnabled,
		ServerRegionID:                     serverRegionID,
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
	prepareStmt := viper.GetBool("database.gorm.prepare_stmt")

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
			PrepareStmt:           prepareStmt,
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

// globalResolvers returns the global DNS resolvers
// defined in the config file.
// If a nameserver is a valid IP, it will be used as a regular resolver.
// If a nameserver is a valid URL, it will be used as a DoH resolver.
// If a nameserver is neither a valid URL nor a valid IP, it will be ignored.
func (d *DNSConfig) globalResolvers() []*dnstype.Resolver {
	var resolvers []*dnstype.Resolver

	for _, nsStr := range d.Nameservers.Global {
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

		log.Warn().Str("nameserver", nsStr).Msg("invalid global nameserver, ignoring")
	}

	return resolvers
}

// splitResolvers returns a map of domain to DNS resolvers.
// If a nameserver is a valid IP, it will be used as a regular resolver.
// If a nameserver is a valid URL, it will be used as a DoH resolver.
// If a nameserver is neither a valid URL nor a valid IP, it will be ignored.
func (d *DNSConfig) splitResolvers() map[string][]*dnstype.Resolver {
	routes := make(map[string][]*dnstype.Resolver)

	for domain, nameservers := range d.Nameservers.Split {
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

			log.Warn().Str("nameserver", nsStr).Str("domain", domain).Msg("invalid split dns nameserver, ignoring")
		}

		routes[domain] = resolvers
	}

	return routes
}

func dnsToTailcfgDNS(dns DNSConfig) *tailcfg.DNSConfig {
	cfg := tailcfg.DNSConfig{}

	cfg.Proxied = dns.MagicDNS

	cfg.ExtraRecords = dns.ExtraRecords
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

func prefixV4() (*netip.Prefix, bool, error) {
	prefixV4Str := viper.GetString("prefixes.v4")

	if prefixV4Str == "" {
		return nil, false, nil
	}

	prefixV4, err := netip.ParsePrefix(prefixV4Str)
	if err != nil {
		return nil, false, fmt.Errorf("parsing IPv4 prefix from config: %w", err)
	}

	builder := netipx.IPSetBuilder{}
	builder.AddPrefix(tsaddr.CGNATRange())

	ipSet, _ := builder.IPSet()

	return &prefixV4, !ipSet.ContainsPrefix(prefixV4), nil
}

func prefixV6() (*netip.Prefix, bool, error) {
	prefixV6Str := viper.GetString("prefixes.v6")

	if prefixV6Str == "" {
		return nil, false, nil
	}

	prefixV6, err := netip.ParsePrefix(prefixV6Str)
	if err != nil {
		return nil, false, fmt.Errorf("parsing IPv6 prefix from config: %w", err)
	}

	builder := netipx.IPSetBuilder{}
	builder.AddPrefix(tsaddr.TailscaleULARange())
	ipSet, _ := builder.IPSet()

	return &prefixV6, !ipSet.ContainsPrefix(prefixV6), nil
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
	if err := validateServerConfig(); err != nil { //nolint:noinlineerr
		return nil, err
	}

	logConfig := logConfig()
	zerolog.SetGlobalLevel(logConfig.Level)

	prefix4, v4NonStandard, err := prefixV4()
	if err != nil {
		return nil, err
	}

	prefix6, v6NonStandard, err := prefixV6()
	if err != nil {
		return nil, err
	}

	if prefix4 == nil && prefix6 == nil {
		return nil, ErrNoPrefixConfigured
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
		return nil, fmt.Errorf(
			"%w: %q, allowed options: %s, %s",
			ErrInvalidAllocationStrategy,
			allocStr,
			IPAllocationStrategySequential,
			IPAllocationStrategyRandom,
		)
	}

	dnsConfig, err := dns()
	if err != nil {
		return nil, err
	}

	derpConfig := derpConfig()
	logTailConfig := logtailConfig()
	randomizeClientPort := viper.GetBool("randomize_client_port")

	oidcClientSecret := viper.GetString("oidc.client_secret")

	oidcClientSecretPath := viper.GetString("oidc.client_secret_path")
	if oidcClientSecretPath != "" && oidcClientSecret != "" {
		return nil, errOidcMutuallyExclusive
	}

	if oidcClientSecretPath != "" {
		secretBytes, err := os.ReadFile(os.ExpandEnv(oidcClientSecretPath))
		if err != nil {
			return nil, err
		}

		oidcClientSecret = strings.TrimSpace(string(secretBytes))
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
			return nil, err
		}
	}

	return &Config{
		ServerURL:          serverURL,
		Addr:               viper.GetString("listen_addr"),
		MetricsAddr:        viper.GetString("metrics_listen_addr"),
		GRPCAddr:           viper.GetString("grpc_listen_addr"),
		GRPCAllowInsecure:  viper.GetBool("grpc_allow_insecure"),
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

		Database: databaseConfig(),

		TLS: tlsConfig(),

		DNSConfig:        dnsConfig,
		TailcfgDNSConfig: dnsToTailcfgDNS(dnsConfig),

		ACMEEmail: viper.GetString("acme_email"),
		ACMEURL:   viper.GetString("acme_url"),

		UnixSocket:           viper.GetString("unix_socket"),
		UnixSocketPermission: util.GetFileMode("unix_socket_permission"),

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

		LogTail:             logTailConfig,
		RandomizeClientPort: randomizeClientPort,
		Taildrop: TaildropConfig{
			Enabled: viper.GetBool("taildrop.enabled"),
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

	serverDomainParts := strings.Split(server.Host, ".")
	baseDomainParts := strings.Split(baseDomain, ".")

	if len(serverDomainParts) <= len(baseDomainParts) {
		return nil
	}

	s := len(serverDomainParts)

	b := len(baseDomainParts)
	for i := range baseDomainParts {
		if serverDomainParts[s-i-1] != baseDomainParts[b-i-1] {
			return nil
		}
	}

	return errServerURLSuffix
}

type deprecator struct {
	warns  set.Set[string]
	fatals set.Set[string]
}

// warnWithAlias will register an alias between the newKey and the oldKey,
// and log a deprecation warning if the oldKey is set.
//
//nolint:unused
func (d *deprecator) warnWithAlias(newKey, oldKey string) {
	// NOTE: RegisterAlias is called with NEW KEY -> OLD KEY
	viper.RegisterAlias(newKey, oldKey)

	if viper.IsSet(oldKey) {
		d.warns.Add(
			fmt.Sprintf(
				"The %q configuration key is deprecated. Please use %q instead. %q will be removed in the future.",
				oldKey,
				newKey,
				oldKey,
			),
		)
	}
}

// fatal deprecates and adds an entry to the fatal list of options if the oldKey is set.
func (d *deprecator) fatal(oldKey string) {
	if viper.IsSet(oldKey) {
		d.fatals.Add(
			fmt.Sprintf(
				"The %q configuration key has been removed. Please see the changelog for more details.",
				oldKey,
			),
		)
	}
}

// fatalIfNewKeyIsNotUsed deprecates and adds an entry to the fatal list of options if the oldKey is set and the new key is _not_ set.
// If the new key is set, a warning is emitted instead.
func (d *deprecator) fatalIfNewKeyIsNotUsed(newKey, oldKey string) {
	if viper.IsSet(oldKey) && !viper.IsSet(newKey) {
		d.fatals.Add(
			fmt.Sprintf(
				"The %q configuration key is deprecated. Please use %q instead. %q has been removed.",
				oldKey,
				newKey,
				oldKey,
			),
		)
	} else if viper.IsSet(oldKey) {
		d.warns.Add(fmt.Sprintf("The %q configuration key is deprecated. Please use %q instead. %q has been removed.", oldKey, newKey, oldKey))
	}
}

// fatalIfSet fatals if the oldKey is set at all, regardless of whether
// the newKey is set. Use this when the old key has been fully removed
// and any use of it should be a hard error.
func (d *deprecator) fatalIfSet(oldKey, newKey string) {
	if viper.IsSet(oldKey) {
		d.fatals.Add(
			fmt.Sprintf(
				"The %q configuration key has been removed. Please use %q instead.",
				oldKey,
				newKey,
			),
		)
	}
}

// warn deprecates and adds an option to log a warning if the oldKey is set.
//
//nolint:unused
func (d *deprecator) warnNoAlias(newKey, oldKey string) {
	if viper.IsSet(oldKey) {
		d.warns.Add(
			fmt.Sprintf(
				"The %q configuration key is deprecated. Please use %q instead. %q has been removed.",
				oldKey,
				newKey,
				oldKey,
			),
		)
	}
}

// warn deprecates and adds an entry to the warn list of options if the oldKey is set.
//
//nolint:unused
func (d *deprecator) warn(oldKey string) {
	if viper.IsSet(oldKey) {
		d.warns.Add(
			fmt.Sprintf(
				"The %q configuration key is deprecated and has been removed. Please see the changelog for more details.",
				oldKey,
			),
		)
	}
}

func (d *deprecator) String() string {
	var b strings.Builder

	for _, w := range d.warns.Slice() {
		fmt.Fprintf(&b, "WARN: %s\n", w)
	}

	for _, f := range d.fatals.Slice() {
		fmt.Fprintf(&b, "FATAL: %s\n", f)
	}

	return b.String()
}

func (d *deprecator) Log() {
	if len(d.fatals) > 0 {
		log.Fatal().Msg("\n" + d.String())
	} else if len(d.warns) > 0 {
		log.Warn().Msg("\n" + d.String())
	}
}
