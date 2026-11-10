package types

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	hsdns "github.com/juanfont/headscale/hscontrol/dns"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
)

const (
	PKCEMethodPlain PKCEMethod = "plain"
	PKCEMethodS256  PKCEMethod = "S256"

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
	errURLSyntax                 = errors.New("invalid URL syntax")
	ErrNoPrefixConfigured        = errors.New("no IPv4 or IPv6 prefix configured, minimum one prefix is required")
	ErrInvalidAllocationStrategy = errors.New("invalid prefix allocation strategy")
	errConfigNotLoaded           = errors.New("configuration not loaded: call types.LoadConfig first")
)

// defaultChallengeResolvers find a zone's nameservers when
// dns.challenge.resolvers is empty. The system resolver is not used: on a
// host running MagicDNS it answers for base_domain itself instead of
// asking the public zone.
var defaultChallengeResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// IPAllocationStrategy is how new node IPs are picked. "" decodes without
// error to the zero value (unset).
type IPAllocationStrategy string //nolint:recvcheck // UnmarshalText needs a pointer; the rest read the value

const (
	IPAllocationStrategySequential IPAllocationStrategy = "sequential"
	IPAllocationStrategyRandom     IPAllocationStrategy = "random"
)

// PolicyMode is where the policy is stored. "" decodes without error to the
// zero value (unset).
type PolicyMode string //nolint:recvcheck // UnmarshalText needs a pointer; the rest read the value

const (
	PolicyModeDB   PolicyMode = "database"
	PolicyModeFile PolicyMode = "file"
)

// EphemeralConfig contains configuration for ephemeral node lifecycle.
type EphemeralConfig struct {
	// InactivityTimeout is how long an ephemeral node can be offline
	// before it is automatically deleted.
	InactivityTimeout time.Duration `koanf:"inactivity_timeout"`
}

// HARouteConfig contains configuration for HA subnet router health probing.
type HARouteConfig struct {
	// ProbeInterval is how often HA subnet routers are probed.
	// A zero or negative duration disables probing.
	ProbeInterval time.Duration `koanf:"probe_interval"`

	// ProbeTimeout is the maximum time to wait for a probe response
	// before declaring a node unhealthy. Must be less than [HARouteConfig.ProbeInterval].
	ProbeTimeout time.Duration `koanf:"probe_timeout"`
}

// RouteConfig contains configuration for route behaviour.
type RouteConfig struct {
	HA HARouteConfig `koanf:"ha"`
}

// PreAuthKeysConfig contains configuration for pre-auth key lifecycle.
type PreAuthKeysConfig struct {
	// RevokedRetention is how long a soft-revoked pre-auth key (revoked via the
	// v2 API's DELETE) is kept retrievable before the background collector
	// hard-deletes it. Keys still backing a node are kept until the node is
	// deleted. A zero or negative duration disables the collector.
	RevokedRetention time.Duration `koanf:"revoked_retention"`
}

// NodeConfig contains configuration for node lifecycle and expiry.
type NodeConfig struct {
	// Expiry is the default key expiry duration for non-tagged nodes.
	// Applies to all registration methods (auth key, CLI, web, OIDC).
	// Tagged nodes are exempt and never expire.
	// A zero/negative duration means no default expiry (nodes never expire).
	Expiry time.Duration `koanf:"expiry"`

	// Ephemeral contains configuration for ephemeral node lifecycle.
	Ephemeral EphemeralConfig `koanf:"ephemeral"`

	// Routes contains configuration for route behaviour.
	Routes RouteConfig `koanf:"routes"`
}

// Config is the Headscale configuration, nested like the configuration
// file; koanf tags name the keys.
type Config struct { //nolint:recvcheck // MarshalJSON reads a value, so a Config value is redacted too
	ServerURL            string            `koanf:"server_url"`
	Addr                 ListenAddr        `koanf:"listen_addr"`
	MetricsAddr          ListenAddr        `koanf:"metrics_listen_addr"`
	UnixSocket           string            `koanf:"unix_socket"`
	UnixSocketPermission FileMode          `koanf:"unix_socket_permission"`
	TrustedProxies       []netip.Prefix    `koanf:"trusted_proxies"`
	DisableUpdateCheck   bool              `koanf:"disable_check_updates"`
	Noise                NoiseConfig       `koanf:"noise"`
	Prefixes             PrefixesConfig    `koanf:"prefixes"`
	Policy               PolicyConfig      `koanf:"policy"`
	Log                  LogConfig         `koanf:"log"`
	Node                 NodeConfig        `koanf:"node"`
	PreAuthKeys          PreAuthKeysConfig `koanf:"preauth_keys"`
	DERP                 DERPConfig        `koanf:"derp"`
	Database             DatabaseConfig    `koanf:"database"`
	DNSConfig            DNSConfig         `koanf:"dns"`
	TLS                  TLSConfig         `koanf:"tls"`
	OIDC                 OIDCConfig        `koanf:"oidc"`
	LogTail              LogTailConfig     `koanf:"logtail"`
	Taildrop             TaildropConfig    `koanf:"taildrop"`
	AutoUpdate           AutoUpdateConfig  `koanf:"auto_update"`
	CLI                  CLIConfig         `koanf:"cli"`
	Tuning               Tuning            `koanf:"tuning"`

	// ConfigDir is where [Config.AbsPath] resolves relative paths.
	ConfigDir string `json:"-" koanf:"-"`

	// dns is nil until [Config.StartDNS].
	dns *liveDNS
}

// NoiseConfig is the key of the Noise protocol clients connect over.
type NoiseConfig struct {
	PrivateKeyPath string `koanf:"private_key_path"`
}

// PrefixesConfig are the ranges node IPs are allocated from.
type PrefixesConfig struct {
	V4         *netip.Prefix        `koanf:"v4"`
	V6         *netip.Prefix        `koanf:"v6"`
	Allocation IPAllocationStrategy `koanf:"allocation"`
}

// liveDNS is the DNS state of a running server: the tailcfg form, whose
// extra records the extra-records watcher replaces while map builds clone
// it, and the provider startup built.
type liveDNS struct {
	mu       sync.RWMutex
	dns      *tailcfg.DNSConfig
	provider hsdns.Provider
}

type DNSConfig struct {
	MagicDNS         bool                `koanf:"magic_dns"`
	BaseDomain       string              `koanf:"base_domain"`
	OverrideLocalDNS bool                `koanf:"override_local_dns"`
	Nameservers      Nameservers         `koanf:"nameservers"`
	SearchDomains    []string            `koanf:"search_domains"`
	ExtraRecords     []tailcfg.DNSRecord `koanf:"extra_records"`
	ExtraRecordsPath string              `koanf:"extra_records_path"`
	Certificates     CertificatesConfig  `koanf:"certificates"`
	Challenge        DNSChallengeConfig  `koanf:"challenge"`
}

// CertificatesConfig lets nodes get TLS certificates for their MagicDNS
// name with `tailscale cert`. The node runs ACME itself; headscale
// publishes its DNS-01 challenge through [DNSChallengeConfig].
type CertificatesConfig struct {
	Enabled bool `koanf:"enabled"`
	// Zone is the public DNS zone challenge records are written to, when
	// base_domain sits below the zone apex. See [DNSConfig.CertificateZone].
	Zone string `koanf:"zone"`
}

// CertificateZone is the zone challenge records are written to:
// Certificates.Zone, else BaseDomain.
func (d DNSConfig) CertificateZone() string {
	return cmp.Or(d.Certificates.Zone, d.BaseDomain)
}

// DNSChallengeConfig is the DNS provider answering ACME DNS-01
// challenges for node certificates and headscale's own certificate.
type DNSChallengeConfig struct {
	PropagationTimeout time.Duration `koanf:"propagation_timeout"`
	Resolvers          []string      `koanf:"resolvers"`
	// ProviderSettings is dns.challenge.provider, name included. Never
	// serialised: its settings are credentials.
	ProviderSettings map[string]any `json:"-" koanf:"provider"`
	// Provider is set only from Go, by an embedder or a test, and wins
	// over ProviderSettings. The loader never sets it.
	Provider hsdns.Provider `json:"-" koanf:"-"`
}

// ProviderName is the provider ProviderSettings names, or "".
func (c DNSChallengeConfig) ProviderName() string {
	name, _ := c.providerName()

	return name
}

// providerName is the name as text, and false when it is a map or list:
// its contents may be credentials, so it is never formatted.
func (c DNSChallengeConfig) providerName() (string, bool) {
	switch name := c.ProviderSettings["name"].(type) {
	case nil:
		return "", true
	case string:
		return name, true
	default:
		return scalarText(reflect.ValueOf(name))
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
		return slices.Clone(defaultChallengeResolvers)
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

type Nameservers struct {
	Global []string            `koanf:"global"`
	Split  map[string][]string `koanf:"split"`
}

type SqliteConfig struct {
	Path              string `koanf:"path"`
	WriteAheadLog     bool   `koanf:"write_ahead_log"`
	WALAutoCheckPoint int    `koanf:"wal_autocheckpoint"`
}

type PostgresConfig struct {
	Host                string `koanf:"host"`
	Port                int    `koanf:"port"`
	Name                string `koanf:"name"`
	User                string `koanf:"user"`
	Pass                Secret `json:"-"                        koanf:"pass"` // never serialise the database password
	Ssl                 string `koanf:"ssl"`
	MaxOpenConnections  int    `koanf:"max_open_conns"`
	MaxIdleConnections  int    `koanf:"max_idle_conns"`
	ConnMaxIdleTimeSecs int    `koanf:"conn_max_idle_time_secs"`
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

type GormConfig struct {
	// SlowThreshold is in milliseconds.
	SlowThreshold         int  `koanf:"slow_threshold"`
	SkipErrRecordNotFound bool `koanf:"skip_err_record_not_found"`
	ParameterizedQueries  bool `koanf:"parameterized_queries"`
}

type DatabaseConfig struct {
	Type DatabaseType `koanf:"type"`
	// Debug logs queries through [GormConfig].
	Debug bool `koanf:"debug"`

	Gorm GormConfig `koanf:"gorm"`

	Sqlite   SqliteConfig   `koanf:"sqlite"`
	Postgres PostgresConfig `koanf:"postgres"`
}

// IsSQLite reports whether Type names SQLite, in either spelling.
func (d DatabaseConfig) IsSQLite() bool {
	return d.Type == DatabaseSqlite || d.Type == "sqlite"
}

type TLSConfig struct {
	CertPath string `koanf:"cert_path"`
	KeyPath  string `koanf:"key_path"`

	ACME ACMEConfig `koanf:"acme"`
}

// ACMEConfig gets headscale's own certificate from an ACME CA.
type ACMEConfig struct {
	Hostname      string        `koanf:"hostname"`
	ChallengeType ACMEChallenge `koanf:"challenge_type"`
	// HTTPListen serves HTTP-01 challenges.
	HTTPListen ListenAddr `koanf:"http_listen"`
	URL        HTTPURL    `koanf:"url"`
	Email      string     `koanf:"email"`
	CacheDir   string     `koanf:"cache_dir"`
}

type PKCEConfig struct {
	Enabled bool       `koanf:"enabled"`
	Method  PKCEMethod `koanf:"method"`
}

type OIDCConfig struct {
	OnlyStartIfOIDCIsAvailable bool              `koanf:"only_start_if_oidc_is_available"`
	Issuer                     HTTPURL           `koanf:"issuer"`
	ClientID                   string            `koanf:"client_id"`
	ClientSecret               Secret            `json:"-"                                koanf:"client_secret"` // never serialise the OIDC client secret
	Scope                      []string          `koanf:"scope"`
	ExtraParams                map[string]string `koanf:"extra_params"`
	AllowedDomains             []string          `koanf:"allowed_domains"`
	AllowedUsers               []string          `koanf:"allowed_users"`
	AllowedGroups              []string          `koanf:"allowed_groups"`
	EmailVerifiedRequired      bool              `koanf:"email_verified_required"`
	UseExpiryFromToken         bool              `koanf:"use_expiry_from_token"`
	PKCE                       PKCEConfig        `koanf:"pkce"`
}

type DERPConfig struct {
	Server          DERPServerConfig `koanf:"server"`
	URLs            []HTTPURL        `koanf:"urls"`
	Paths           []string         `koanf:"paths"`
	AutoUpdate      bool             `koanf:"auto_update_enabled"`
	UpdateFrequency time.Duration    `koanf:"update_frequency"`
	// DERPMap is set only from Go, by an embedder or a test.
	DERPMap *tailcfg.DERPMap `json:"-" koanf:"-"`
}

// DERPServerConfig is the embedded DERP server.
type DERPServerConfig struct {
	Enabled                            bool                 `koanf:"enabled"`
	RegionID                           tailcfg.DERPRegionID `koanf:"region_id"`
	RegionCode                         string               `koanf:"region_code"`
	RegionName                         string               `koanf:"region_name"`
	VerifyClients                      bool                 `koanf:"verify_clients"`
	STUNAddr                           ListenAddr           `koanf:"stun_listen_addr"`
	PrivateKeyPath                     string               `koanf:"private_key_path"`
	IPv4                               string               `koanf:"ipv4"`
	IPv6                               string               `koanf:"ipv6"`
	AutomaticallyAddEmbeddedDerpRegion bool                 `koanf:"automatically_add_embedded_derp_region"`
}

type LogTailConfig struct {
	Enabled bool `koanf:"enabled"`
}

type TaildropConfig struct {
	Enabled bool `koanf:"enabled"`
}

// AutoUpdateConfig controls the tailnet-wide default for client
// auto-update. When Enabled is true, headscale emits the
// [tailcfg.NodeAttrDefaultAutoUpdate] cap with value [true] on every
// node's CapMap; clients fall back to that default unless they have
// opted in or out locally.
type AutoUpdateConfig struct {
	Enabled bool `koanf:"enabled"`
}

type CLIConfig struct {
	Address  string        `koanf:"address"`
	APIKey   Secret        `json:"-"         koanf:"api_key"` // never serialise the headscale admin API key
	Timeout  time.Duration `koanf:"timeout"`
	Insecure bool          `koanf:"insecure"`
}

type PolicyConfig struct {
	Path string     `koanf:"path"`
	Mode PolicyMode `koanf:"mode"`
}

func (p *PolicyConfig) IsEmpty() bool {
	return p.Mode == PolicyModeFile && p.Path == ""
}

type LogConfig struct {
	Level  LogLevel  `koanf:"level"`
	Format LogFormat `koanf:"format"`
}

// Tuning contains advanced performance tuning parameters for Headscale.
// These settings control internal batching, timeouts, and resource allocation.
// The defaults are carefully chosen for typical deployments and should rarely
// need adjustment. Changes to these values can significantly impact performance
// and resource usage.
type Tuning struct {
	// BatchChangeDelay controls how long to wait before sending batched updates
	// to clients when multiple changes occur in rapid succession.
	BatchChangeDelay time.Duration `koanf:"batch_change_delay"`

	// NodeMapSessionBufferedChanSize sets the buffer size for the channel that
	// queues map updates to be sent to connected clients.
	NodeMapSessionBufferedChanSize int `koanf:"node_mapsession_buffered_chan_size"`

	// BatcherWorkers controls the number of parallel workers processing map
	// updates for connected clients. See [Tuning.BatcherWorkerCount].
	BatcherWorkers int `koanf:"batcher_workers"`

	// RegisterCacheExpiration is how long registration cache entries remain
	// valid before being eligible for eviction.
	RegisterCacheExpiration time.Duration `koanf:"register_cache_expiration"`

	// RegisterCacheMaxEntries bounds pending registrations. At capacity, new
	// registrations are refused without evicting admitted sessions. SSH checks
	// can also use 64 reserved slots beyond this limit.
	// A value of 0 falls back to defaultRegisterCacheMaxEntries (1024).
	RegisterCacheMaxEntries int `koanf:"register_cache_max_entries"`

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
	NodeStoreBatchSize int `koanf:"node_store_batch_size"`

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
	NodeStoreBatchTimeout time.Duration `koanf:"node_store_batch_timeout"`
}

// BatcherWorkerCount is BatcherWorkers, or [DefaultBatcherWorkers] when unset.
func (t Tuning) BatcherWorkerCount() int {
	if t.BatcherWorkers > 0 {
		return t.BatcherWorkers
	}

	return DefaultBatcherWorkers()
}

func validatePKCEMethod(method PKCEMethod) error {
	if method != PKCEMethodPlain && method != PKCEMethodS256 {
		return errInvalidPKCEMethod
	}

	return nil
}

// validate checks the OIDC settings, called when oidc.issuer is set. It
// fails fast on a setup that cannot work: an invalid PKCE method, a
// malformed issuer URL (which would otherwise surface as an opaque discovery
// error or, worse, resolve to an unintended provider), or a missing client
// id/secret.
func (o OIDCConfig) validate() error {
	err := validatePKCEMethod(o.PKCE.Method)
	if err != nil {
		return err
	}

	u, err := url.Parse(string(o.Issuer))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("%w: got %q", errOIDCIssuerInvalid, string(o.Issuer))
	}

	if o.ClientID == "" {
		return errOIDCClientIDRequired
	}

	if o.ClientSecret == "" {
		return errOIDCClientSecretRequired
	}

	return nil
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

// src is the configuration [LoadConfig] loaded.
var src *configSource

// configFile is the file [LoadConfig] last loaded or failed to load.
var configFile string

// LoadConfig loads defaults, the configuration file and HEADSCALE_*
// environment variables, rejecting unknown and removed keys. It has to be
// called before [LoadServerConfig] and [LoadCLIConfig], which decode the
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

// ConfigFile returns the file the last [LoadConfig] loaded or failed to
// load, or "" when it found none.
func ConfigFile() string { return configFile }

// LogFormatSetting returns the configured log.format, or "" when the
// configuration does not decode.
func LogFormatSetting() LogFormat {
	cfg, err := src.decode()
	if err != nil {
		return ""
	}

	return cfg.Log.Format
}

// UpdateCheckDisabled reports whether disable_check_updates is set.
// A configuration that does not decode disables it too: the command reports
// the error instead.
func UpdateCheckDisabled() bool {
	cfg, err := src.decode()

	return err != nil || cfg.DisableUpdateCheck
}

// DumpConfig renders the loaded configuration, defaults included, as YAML.
func DumpConfig() ([]byte, error) {
	if src == nil {
		return nil, errConfigNotLoaded
	}

	return src.k.Marshal(yaml.Parser())
}

// defaultConfig is the configuration before a file or variable sets
// anything. database.type has no default.
func defaultConfig() Config {
	return Config{
		UnixSocket:           "/var/run/headscale/headscale.sock",
		UnixSocketPermission: 0o770,
		Prefixes:             PrefixesConfig{Allocation: IPAllocationStrategySequential},
		Policy:               PolicyConfig{Mode: PolicyModeFile},
		Log:                  LogConfig{Level: "info", Format: TextLogFormat},
		Node: NodeConfig{
			Ephemeral: EphemeralConfig{InactivityTimeout: 120 * time.Second},
			Routes: RouteConfig{HA: HARouteConfig{
				ProbeInterval: 10 * time.Second,
				ProbeTimeout:  5 * time.Second,
			}},
		},
		PreAuthKeys: PreAuthKeysConfig{RevokedRetention: 168 * time.Hour},
		DERP: DERPConfig{
			Server: DERPServerConfig{
				VerifyClients:                      true,
				AutomaticallyAddEmbeddedDerpRegion: true,
			},
			UpdateFrequency: 3 * time.Hour,
		},
		Database: DatabaseConfig{
			Sqlite: SqliteConfig{
				WriteAheadLog:     true,
				WALAutoCheckPoint: 1000, // SQLite default
			},
			Postgres: PostgresConfig{
				Ssl:                 "false",
				MaxOpenConnections:  10,
				MaxIdleConnections:  10,
				ConnMaxIdleTimeSecs: 3600,
			},
		},
		DNSConfig: DNSConfig{
			MagicDNS:         true,
			OverrideLocalDNS: true,
			Nameservers:      Nameservers{Global: []string{}, Split: map[string][]string{}},
			SearchDomains:    []string{},
			Challenge:        DNSChallengeConfig{PropagationTimeout: 2 * time.Minute},
		},
		TLS: TLSConfig{ACME: ACMEConfig{
			ChallengeType: HTTP01ChallengeType,
			HTTPListen:    ":http",
			CacheDir:      "/var/lib/headscale/cache",
		}},
		OIDC: OIDCConfig{
			OnlyStartIfOIDCIsAvailable: true,
			Scope:                      []string{oidc.ScopeOpenID, "profile", "email"},
			EmailVerifiedRequired:      true,
			PKCE:                       PKCEConfig{Method: PKCEMethodS256},
		},
		Taildrop: TaildropConfig{Enabled: true},
		CLI:      CLIConfig{Timeout: 5 * time.Second},
		Tuning: Tuning{
			BatchChangeDelay:               800 * time.Millisecond,
			NodeMapSessionBufferedChanSize: 30,
			NodeStoreBatchSize:             defaultNodeStoreBatchSize,
			NodeStoreBatchTimeout:          500 * time.Millisecond,
		},
	}
}

// Validate reports every rule c breaks, in one error. It reads no file and
// logs nothing; [Config.Warnings] holds the advisories.
func (c *Config) Validate() error {
	v := &configValidator{}

	// OIDC is activated by setting oidc.issuer (see app.go), not by a
	// dedicated oidc.enabled key. Gate validation on the real activation
	// condition so a misconfiguration fails at startup.
	if c.OIDC.Issuer != "" {
		err := c.OIDC.validate()
		if err != nil {
			v.Add(&ConfigError{
				Reason: "OIDC configuration is invalid",
				Detail: err.Error(),
				Hint:   "check oidc.issuer, oidc.client_id, oidc.client_secret, and oidc.pkce.method",
				Cause:  err,
			})
		}
	}

	if len(c.DNSConfig.ExtraRecords) > 0 && c.DNSConfig.ExtraRecordsPath != "" {
		v.Add(&ConfigError{
			Reason: "dns.extra_records and dns.extra_records_path are mutually exclusive",
			Current: []KV{
				{"dns.extra_records_path", c.DNSConfig.ExtraRecordsPath},
				{"dns.extra_records", "<inline records>"},
			},
			Hint: "keep one (a path is recommended for production); remove the other",
		})
	}

	acme := c.TLS.ACME
	if acme.Hostname != "" && (c.TLS.CertPath != "" || c.TLS.KeyPath != "") {
		v.Add(&ConfigError{
			Reason:  "tls.acme.hostname and tls.cert_path/tls.key_path are mutually exclusive",
			Current: []KV{{"tls.acme.hostname", acme.Hostname}},
			ConflictsWith: []KV{
				{"tls.cert_path", c.TLS.CertPath},
				{"tls.key_path", c.TLS.KeyPath},
			},
			Hint: "choose one TLS strategy and unset the other (Let's Encrypt OR a static keypair)",
			See:  "https://headscale.net/stable/ref/tls/",
		})
	}

	if c.Noise.PrivateKeyPath == "" {
		v.Add(&ConfigError{
			Reason: "noise.private_key_path is required",
			Hint:   "set noise.private_key_path: /var/lib/headscale/noise_private.key (or any writable path)",
			See:    "https://headscale.net/stable/setup/install/official/",
		})
	}

	c.validateListenerCollisions(v)

	if ct := acme.ChallengeType; ct != HTTP01ChallengeType &&
		ct != TLSALPN01ChallengeType && ct != DNS01ChallengeType {
		v.Add(&ConfigError{
			Reason:  "tls.acme.challenge_type has an unsupported value",
			Current: []KV{{"tls.acme.challenge_type", string(ct)}},
			Allowed: ct.Allowed(),
			Hint:    "pick one of the allowed values; HTTP-01 is the default",
		})
	}

	if !strings.HasPrefix(c.ServerURL, "http://") && !strings.HasPrefix(c.ServerURL, "https://") {
		v.Add(&ConfigError{
			Reason:  "server_url is missing a scheme",
			Current: []KV{{"server_url", c.ServerURL}},
			Hint:    "prefix the URL with https:// (recommended) or http://",
		})
	}

	// Minimum inactivity time out is keepalive timeout (60s) plus a few seconds
	// to avoid races
	minInactivityTimeout := 65 * time.Second

	if ephemeralTimeout := c.Node.Ephemeral.InactivityTimeout; ephemeralTimeout <= minInactivityTimeout {
		v.Add(&ConfigError{
			Reason:  "node.ephemeral.inactivity_timeout is below the minimum",
			Current: []KV{{"node.ephemeral.inactivity_timeout", ephemeralTimeout.String()}},
			Minimum: minInactivityTimeout.String(),
			Hint:    "raise the value above the keepalive interval (60s) plus a safety margin",
		})
	}

	if c.DNSConfig.OverrideLocalDNS && len(c.DNSConfig.Nameservers.Global) == 0 {
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

	// Validate HA health probing parameters
	if ha := c.Node.Routes.HA; ha.ProbeInterval > 0 {
		if ha.ProbeInterval < 2*time.Second {
			v.Add(&ConfigError{
				Reason:  "node.routes.ha.probe_interval is below the minimum",
				Current: []KV{{"node.routes.ha.probe_interval", ha.ProbeInterval.String()}},
				Minimum: "2s",
				Hint:    "raise the value to at least the minimum",
			})
		}

		if ha.ProbeTimeout < 1*time.Second {
			v.Add(&ConfigError{
				Reason:  "node.routes.ha.probe_timeout is below the minimum",
				Current: []KV{{"node.routes.ha.probe_timeout", ha.ProbeTimeout.String()}},
				Minimum: "1s",
				Hint:    "raise the value to at least the minimum",
			})
		}

		if ha.ProbeTimeout >= ha.ProbeInterval {
			v.Add(&ConfigError{
				Reason: "node.routes.ha.probe_timeout must be less than node.routes.ha.probe_interval",
				Current: []KV{
					{"node.routes.ha.probe_timeout", ha.ProbeTimeout.String()},
					{"node.routes.ha.probe_interval", ha.ProbeInterval.String()},
				},
				Hint: "lower probe_timeout below probe_interval (a probe must finish before the next one starts)",
			})
		}
	}

	// Validate tuning parameters
	if size := c.Tuning.NodeStoreBatchSize; size <= 0 {
		v.Add(&ConfigError{
			Reason:  "tuning.node_store_batch_size must be positive",
			Current: []KV{{"tuning.node_store_batch_size", size}},
			Hint:    fmt.Sprintf("set to a positive integer (default: %d)", defaultNodeStoreBatchSize),
		})
	}

	if timeout := c.Tuning.NodeStoreBatchTimeout; timeout <= 0 {
		v.Add(&ConfigError{
			Reason:  "tuning.node_store_batch_timeout must be positive",
			Current: []KV{{"tuning.node_store_batch_timeout", timeout.String()}},
			Hint:    "set to a positive duration (default: 500ms)",
		})
	}

	c.validateDERP(v)
	c.validateDatabase(v)
	c.validatePolicy(v)
	c.validateMagicDNS(v)
	c.validateCertificates(v)
	c.validatePrefixes(v)
	c.validateDNSProvider(v)

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
			addServerURLConfigError(v, c.ServerURL, base, err)
		}
	}

	return v.Err()
}

// validatePolicy records a ConfigError for an unknown policy.mode:
// startup would load no policy at all and allow all traffic.
func (c *Config) validatePolicy(v *configValidator) {
	m := c.Policy.Mode
	if m == PolicyModeFile || m == PolicyModeDB {
		return
	}

	v.Add(&ConfigError{
		Reason:  "policy.mode has an unsupported value",
		Current: []KV{{"policy.mode", string(m)}},
		Allowed: m.Allowed(),
		See:     "https://headscale.net/stable/ref/policy/",
	})
}

// validateDERP records ConfigErrors when the embedded DERP server is
// enabled without the addresses or paths it needs.
func (c *Config) validateDERP(v *configValidator) {
	server := c.DERP.Server
	if !server.Enabled {
		return
	}

	if server.STUNAddr == "" {
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

	derpKey, noiseKey := server.PrivateKeyPath, c.Noise.PrivateKeyPath
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

	if !server.AutomaticallyAddEmbeddedDerpRegion && len(c.DERP.Paths) == 0 {
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

// validateDatabase records a ConfigError when database.type is not one of
// the supported backends.
func (c *Config) validateDatabase(v *configValidator) {
	t := c.Database.Type
	switch t {
	case DatabaseSqlite, DatabasePostgres, "sqlite":
		return
	}

	v.Add(&ConfigError{
		Reason:  "database.type has an unsupported value",
		Current: []KV{{"database.type", string(t)}},
		Allowed: t.Allowed(),
		Hint:    "pick one of the allowed values; sqlite is the default for single-host deployments",
		See:     "https://headscale.net/stable/ref/database/",
	})
}

// validateMagicDNS records a ConfigError when MagicDNS is enabled without a
// base_domain.
func (c *Config) validateMagicDNS(v *configValidator) {
	if c.DNSConfig.MagicDNS && c.DNSConfig.BaseDomain == "" {
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

// validateCertificates records ConfigErrors when node certificates are
// enabled without what the Tailscale client needs: a MagicDNS name it can
// match exactly, and a provider to publish the challenge.
func (c *Config) validateCertificates(v *configValidator) {
	ch := c.DNSConfig.Challenge
	if timeout := ch.PropagationTimeout; timeout < 0 {
		v.Add(&ConfigError{
			Reason:  "dns.challenge.propagation_timeout must not be negative",
			Current: []KV{{"dns.challenge.propagation_timeout", timeout.String()}},
			Hint:    "use 0 to skip waiting for the record on the zone's nameservers",
		})
	}

	enabled := c.DNSConfig.Certificates.Enabled
	challengeType := c.TLS.ACME.ChallengeType
	ownDNS01 := c.TLS.ACME.Hostname != "" && challengeType == DNS01ChallengeType

	if name, ok := ch.providerName(); (enabled || ownDNS01) && ok && name == "" && ch.Provider == nil {
		v.Add(&ConfigError{
			Reason:  "dns.certificates and tls.acme DNS-01 require dns.challenge.provider",
			Current: []KV{{"dns.certificates.enabled", enabled}, {"tls.acme.challenge_type", string(challengeType)}},
			Allowed: hsdns.ProviderNames(),
			Hint:    "configure the DNS provider that hosts dns.base_domain or tls.acme.hostname under dns.challenge.provider",
			See:     dnsDocsURL,
		})
	}

	if !enabled {
		return
	}

	if !c.DNSConfig.MagicDNS {
		v.Add(&ConfigError{
			Reason:  "dns.certificates requires dns.magic_dns",
			Current: []KV{{"dns.certificates.enabled", true}, {"dns.magic_dns", false}},
			Hint:    "certificates are issued for MagicDNS names; set dns.magic_dns: true",
			See:     dnsDocsURL,
		})
	}

	base := strings.TrimSuffix(c.DNSConfig.BaseDomain, ".")
	if base != strings.ToLower(base) || dnsname.ValidHostname(base) != nil {
		v.Add(&ConfigError{
			Reason:  "dns.base_domain must be a lowercase DNS name for dns.certificates",
			Current: []KV{{"dns.base_domain", base}},
			Hint:    "Tailscale clients match certificate names exactly; use a lowercase public domain you control",
			See:     dnsDocsURL,
		})
	}

	zone := strings.TrimSuffix(c.DNSConfig.Certificates.Zone, ".")
	if zone != "" && base != zone && !strings.HasSuffix(base, "."+zone) {
		v.Add(&ConfigError{
			Reason:  "dns.base_domain is not inside dns.certificates.zone",
			Current: []KV{{"dns.base_domain", base}, {"dns.certificates.zone", zone}},
			Hint:    "set zone to the DNS zone that contains base_domain, or leave it empty to use base_domain",
			See:     dnsDocsURL,
		})
	}
}

// validatePrefixes records ConfigErrors for a catch-all trusted proxy, no
// node range, and no allocation strategy.
func (c *Config) validatePrefixes(v *configValidator) {
	// 0.0.0.0/0 and ::/0 defeat the peer-trust gate and almost always
	// indicate misconfiguration.
	for i, p := range c.TrustedProxies {
		if p.Bits() == 0 {
			err := fmt.Errorf("trusted_proxies[%d] %q: %w", i, p.String(), errTrustedProxyZeroRange)
			v.Add(&ConfigError{
				Reason:  "trusted_proxies contains an invalid CIDR",
				Current: []KV{{"trusted_proxies", c.TrustedProxies}},
				Detail:  err.Error(),
				Hint:    "use specific proxy CIDRs; catch-all ranges are not allowed",
				Cause:   err,
			})

			break
		}
	}

	if c.Prefixes.V4 == nil && c.Prefixes.V6 == nil {
		v.Add(&ConfigError{
			Reason: "no IP prefix configured for the tailnet",
			Current: []KV{
				{"prefixes.v4", ""},
				{"prefixes.v6", ""},
			},
			Hint:  `set at least one of prefixes.v4 (default: "100.64.0.0/10") or prefixes.v6 (default: "fd7a:115c:a1e0::/48")`,
			Cause: ErrNoPrefixConfigured,
		})
	}

	switch alloc := c.Prefixes.Allocation; alloc {
	case IPAllocationStrategySequential, IPAllocationStrategyRandom:
	default:
		v.Add(&ConfigError{
			Reason:  "prefixes.allocation has an unsupported value",
			Current: []KV{{"prefixes.allocation", string(alloc)}},
			Allowed: alloc.Allowed(),
			Hint:    "pick one of the allowed values; sequential is the default",
			Cause:   ErrInvalidAllocationStrategy,
		})
	}
}

// validateDNSProvider builds the provider dns.challenge names, its secrets
// unread, only to report bad settings; startup builds the one it uses. A
// Go-only provider is used as it is.
func (c *Config) validateDNSProvider(v *configValidator) {
	ch := c.DNSConfig.Challenge
	if ch.Provider != nil {
		return
	}

	name, ok := ch.providerName()
	if !ok {
		v.Add(&ConfigError{
			Reason:  "dns.challenge.provider.name must be a provider name",
			Allowed: hsdns.ProviderNames(),
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
	if iso, ok := provider.(hsdns.Isolator); ok && err == nil && c.DNSConfig.Certificates.Enabled {
		err = iso.CheckIsolation()
		if err != nil {
			err = fmt.Errorf("%w for %s: %w", hsdns.ErrProviderConfig, ch.ProviderName(), err)
		}
	}

	if err == nil {
		return
	}

	// The provider names only help when the name is what is wrong.
	var allowed []string
	if errors.Is(err, hsdns.ErrUnknownProvider) {
		allowed = hsdns.ProviderNames()
	}

	v.Add(&ConfigError{
		Reason:  "dns.challenge.provider is invalid",
		Current: []KV{{"dns.challenge.provider.name", ch.ProviderName()}},
		Detail:  err.Error(),
		Allowed: allowed,
		Hint:    `check the provider name and its settings; any string setting can be read from a file with "file:<path>"`,
		See:     dnsDocsURL,
		Cause:   err,
	})
}

// Warnings are advisories about c that do not stop headscale.
func (c *Config) Warnings() []string {
	var warnings []string

	if c.TLS.ACME.Hostname != "" && c.TLS.ACME.ChallengeType == TLSALPN01ChallengeType &&
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

	return append(warnings, c.DNSConfig.nameserverWarnings()...)
}

// outsideRange reports whether p holds addresses outside r.
func outsideRange(p, r netip.Prefix) bool {
	return p.Bits() < r.Bits() || !r.Contains(p.Addr())
}

// parseResolvers converts nameserver strings into DNS resolvers: an IP is a
// plain resolver, a URL a DoH one. Anything else is skipped; the loader
// warns about it, see [DNSConfig.nameserverWarnings].
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

// nameserverWarnings lists each nameserver parseResolvers skips, so the
// load that reads the config reports it rather than each build of it.
func (d DNSConfig) nameserverWarnings() []string {
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

// LoadCLIConfig decodes the configuration [LoadConfig] loaded, for client
// commands, which need no server rule to hold.
func LoadCLIConfig() (*Config, error) {
	if src == nil {
		return nil, errConfigNotLoaded
	}

	cfg, err := src.decode()
	if err != nil {
		return nil, err
	}

	zerolog.SetGlobalLevel(cfg.Log.Level.Zerolog())

	return cfg, nil
}

// LoadServerConfig decodes the configuration [LoadConfig] loaded and, when
// every value decoded, validates it and logs its warnings. It reads no
// file: secret; each consumer reads its own.
func LoadServerConfig() (*Config, error) {
	if src == nil {
		return nil, errConfigNotLoaded
	}

	cfg, err := src.decode()
	if err != nil {
		return nil, err
	}

	zerolog.SetGlobalLevel(cfg.Log.Level.Zerolog())

	err = cfg.Validate()

	for _, w := range cfg.Warnings() {
		log.Warn().Msg(w)
	}

	if err != nil {
		return nil, err
	}

	// The server never uses the CLI's key, which may be an unread file:
	// reference.
	cfg.CLI.APIKey = ""

	return cfg, nil
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
