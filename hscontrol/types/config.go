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
)

const (
	defaultOIDCExpiryTime               = 180 * 24 * time.Hour // 180 Days
	maxDuration           time.Duration = 1<<63 - 1
)

var errOidcMutuallyExclusive = errors.New(
	"oidc_client_secret and oidc_client_secret_path are mutually exclusive",
)

type IPAllocationStrategy string

const (
	IPAllocationStrategySequential IPAllocationStrategy = "sequential"
	IPAllocationStrategyRandom     IPAllocationStrategy = "random"
)

// Config contains the initial Headscale configuration.
type Config struct {
	ServerURL                      string
	Addr                           string
	MetricsAddr                    string
	GRPCAddr                       string
	GRPCAllowInsecure              bool
	EphemeralNodeInactivityTimeout time.Duration
	PrefixV4                       *netip.Prefix
	PrefixV6                       *netip.Prefix
	IPAllocation                   IPAllocationStrategy
	NoisePrivateKeyPath            string
	BaseDomain                     string
	Log                            LogConfig
	DisableUpdateCheck             bool

	Database DatabaseConfig

	DERP DERPConfig

	TLS TLSConfig

	ACMEURL   string
	ACMEEmail string

	DNSConfig *tailcfg.DNSConfig

	UnixSocket           string
	UnixSocketPermission fs.FileMode

	OIDC OIDCConfig

	LogTail             LogTailConfig
	RandomizeClientPort bool

	CLI CLIConfig

	ACL ACLConfig

	Tuning Tuning
}

type SqliteConfig struct {
	Path string
}

type PostgresConfig struct {
	Host                string
	Port                int
	Name                string
	User                string
	Pass                string
	Ssl                 string
	MaxOpenConnections  int
	MaxIdleConnections  int
	ConnMaxIdleTimeSecs int
}

type DatabaseConfig struct {
	// Type sets the database type, either "sqlite3" or "postgres"
	Type  string
	Debug bool

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

type OIDCConfig struct {
	OnlyStartIfOIDCIsAvailable bool
	Issuer                     string
	ClientID                   string
	ClientSecret               string
	Scope                      []string
	ExtraParams                map[string]string
	AllowedDomains             []string
	AllowedUsers               []string
	AllowedGroups              []string
	StripEmaildomain           bool
	Expiry                     time.Duration
	UseExpiryFromToken         bool
}

type DERPConfig struct {
	ServerEnabled                      bool
	AutomaticallyAddEmbeddedDerpRegion bool
	ServerRegionID                     int
	ServerRegionCode                   string
	ServerRegionName                   string
	ServerPrivateKeyPath               string
	STUNAddr                           string
	URLs                               []url.URL
	Paths                              []string
	AutoUpdate                         bool
	UpdateFrequency                    time.Duration
	IPv4                               string
	IPv6                               string
}

type LogTailConfig struct {
	Enabled bool
}

type CLIConfig struct {
	Address  string
	APIKey   string
	Timeout  time.Duration
	Insecure bool
}

type ACLConfig struct {
	PolicyPath string
}

type LogConfig struct {
	Format string
	Level  zerolog.Level
}

type Tuning struct {
	BatchChangeDelay               time.Duration
	NodeMapSessionBufferedChanSize int
}

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

	viper.SetEnvPrefix("headscale")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	viper.SetDefault("tls_letsencrypt_cache_dir", "/var/www/.cache")
	viper.SetDefault("tls_letsencrypt_challenge_type", HTTP01ChallengeType)

	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.format", TextLogFormat)

	viper.SetDefault("dns_config", nil)
	viper.SetDefault("dns_config.override_local_dns", true)

	viper.SetDefault("derp.server.enabled", false)
	viper.SetDefault("derp.server.stun.enabled", true)
	viper.SetDefault("derp.server.automatically_add_embedded_derp_region", true)

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

	viper.SetDefault("oidc.scope", []string{oidc.ScopeOpenID, "profile", "email"})
	viper.SetDefault("oidc.strip_email_domain", true)
	viper.SetDefault("oidc.only_start_if_oidc_is_available", true)
	viper.SetDefault("oidc.expiry", "180d")
	viper.SetDefault("oidc.use_expiry_from_token", false)

	viper.SetDefault("logtail.enabled", false)
	viper.SetDefault("randomize_client_port", false)

	viper.SetDefault("ephemeral_node_inactivity_timeout", "120s")

	viper.SetDefault("tuning.batch_change_delay", "800ms")
	viper.SetDefault("tuning.node_mapsession_buffered_chan_size", 30)

	viper.SetDefault("prefixes.allocation", string(IPAllocationStrategySequential))

	if IsCLIConfigured() {
		return nil
	}

	if err := viper.ReadInConfig(); err != nil {
		log.Warn().Err(err).Msg("Failed to read configuration from disk")

		return fmt.Errorf("fatal error reading config file: %w", err)
	}

	// Collect any validation errors and return them all at once
	var errorText string
	if (viper.GetString("tls_letsencrypt_hostname") != "") &&
		((viper.GetString("tls_cert_path") != "") || (viper.GetString("tls_key_path") != "")) {
		errorText += "Fatal config error: set either tls_letsencrypt_hostname or tls_cert_path/tls_key_path, not both\n"
	}

	if !viper.IsSet("noise") || viper.GetString("noise.private_key_path") == "" {
		errorText += "Fatal config error: headscale now requires a new `noise.private_key_path` field in the config file for the Tailscale v2 protocol\n"
	}

	if (viper.GetString("tls_letsencrypt_hostname") != "") &&
		(viper.GetString("tls_letsencrypt_challenge_type") == TLSALPN01ChallengeType) &&
		(!strings.HasSuffix(viper.GetString("listen_addr"), ":443")) {
		// this is only a warning because there could be something sitting in front of headscale that redirects the traffic (e.g. an iptables rule)
		log.Warn().
			Msg("Warning: when using tls_letsencrypt_hostname with TLS-ALPN-01 as challenge type, headscale must be reachable on port 443, i.e. listen_addr should probably end in :443")
	}

	if (viper.GetString("tls_letsencrypt_challenge_type") != HTTP01ChallengeType) &&
		(viper.GetString("tls_letsencrypt_challenge_type") != TLSALPN01ChallengeType) {
		errorText += "Fatal config error: the only supported values for tls_letsencrypt_challenge_type are HTTP-01 and TLS-ALPN-01\n"
	}

	if !strings.HasPrefix(viper.GetString("server_url"), "http://") &&
		!strings.HasPrefix(viper.GetString("server_url"), "https://") {
		errorText += "Fatal config error: server_url must start with https:// or http://\n"
	}

	// Minimum inactivity time out is keepalive timeout (60s) plus a few seconds
	// to avoid races
	minInactivityTimeout, _ := time.ParseDuration("65s")
	if viper.GetDuration("ephemeral_node_inactivity_timeout") <= minInactivityTimeout {
		errorText += fmt.Sprintf(
			"Fatal config error: ephemeral_node_inactivity_timeout (%s) is set too low, must be more than %s",
			viper.GetString("ephemeral_node_inactivity_timeout"),
			minInactivityTimeout,
		)
	}

	if errorText != "" {
		// nolint
		return errors.New(strings.TrimSuffix(errorText, "\n"))
	} else {
		return nil
	}
}

func GetTLSConfig() TLSConfig {
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

func GetDERPConfig() DERPConfig {
	serverEnabled := viper.GetBool("derp.server.enabled")
	serverRegionID := viper.GetInt("derp.server.region_id")
	serverRegionCode := viper.GetString("derp.server.region_code")
	serverRegionName := viper.GetString("derp.server.region_name")
	stunAddr := viper.GetString("derp.server.stun_listen_addr")
	privateKeyPath := util.AbsolutePathFromConfigPath(
		viper.GetString("derp.server.private_key_path"),
	)
	ipv4 := viper.GetString("derp.server.ipv4")
	ipv6 := viper.GetString("derp.server.ipv6")
	automaticallyAddEmbeddedDerpRegion := viper.GetBool(
		"derp.server.automatically_add_embedded_derp_region",
	)
	if serverEnabled && stunAddr == "" {
		log.Fatal().
			Msg("derp.server.stun_listen_addr must be set if derp.server.enabled is true")
	}

	urlStrs := viper.GetStringSlice("derp.urls")

	urls := make([]url.URL, len(urlStrs))
	for index, urlStr := range urlStrs {
		urlAddr, err := url.Parse(urlStr)
		if err != nil {
			log.Error().
				Str("url", urlStr).
				Err(err).
				Msg("Failed to parse url, ignoring...")
		}

		urls[index] = *urlAddr
	}

	paths := viper.GetStringSlice("derp.paths")

	if serverEnabled && !automaticallyAddEmbeddedDerpRegion && len(paths) == 0 {
		log.Fatal().
			Msg("Disabling derp.server.automatically_add_embedded_derp_region requires to configure the derp server in derp.paths")
	}

	autoUpdate := viper.GetBool("derp.auto_update_enabled")
	updateFrequency := viper.GetDuration("derp.update_frequency")

	return DERPConfig{
		ServerEnabled:                      serverEnabled,
		ServerRegionID:                     serverRegionID,
		ServerRegionCode:                   serverRegionCode,
		ServerRegionName:                   serverRegionName,
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

func GetLogTailConfig() LogTailConfig {
	enabled := viper.GetBool("logtail.enabled")

	return LogTailConfig{
		Enabled: enabled,
	}
}

func GetACLConfig() ACLConfig {
	policyPath := viper.GetString("acl_policy_path")

	return ACLConfig{
		PolicyPath: policyPath,
	}
}

func GetLogConfig() LogConfig {
	logLevelStr := viper.GetString("log.level")
	logLevel, err := zerolog.ParseLevel(logLevelStr)
	if err != nil {
		logLevel = zerolog.DebugLevel
	}

	logFormatOpt := viper.GetString("log.format")
	var logFormat string
	switch logFormatOpt {
	case "json":
		logFormat = JSONLogFormat
	case "text":
		logFormat = TextLogFormat
	case "":
		logFormat = TextLogFormat
	default:
		log.Error().
			Str("func", "GetLogConfig").
			Msgf("Could not parse log format: %s. Valid choices are 'json' or 'text'", logFormatOpt)
	}

	return LogConfig{
		Format: logFormat,
		Level:  logLevel,
	}
}

func GetDatabaseConfig() DatabaseConfig {
	debug := viper.GetBool("database.debug")

	type_ := viper.GetString("database.type")

	switch type_ {
	case DatabaseSqlite, DatabasePostgres:
		break
	case "sqlite":
		type_ = "sqlite3"
	default:
		log.Fatal().
			Msgf("invalid database type %q, must be sqlite, sqlite3 or postgres", type_)
	}

	return DatabaseConfig{
		Type:  type_,
		Debug: debug,
		Sqlite: SqliteConfig{
			Path: util.AbsolutePathFromConfigPath(
				viper.GetString("database.sqlite.path"),
			),
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

func GetDNSConfig() (*tailcfg.DNSConfig, string) {
	if viper.IsSet("dns_config") {
		dnsConfig := &tailcfg.DNSConfig{}

		overrideLocalDNS := viper.GetBool("dns_config.override_local_dns")

		if viper.IsSet("dns_config.nameservers") {
			nameserversStr := viper.GetStringSlice("dns_config.nameservers")

			nameservers := []netip.Addr{}
			resolvers := []*dnstype.Resolver{}

			for _, nameserverStr := range nameserversStr {
				// Search for explicit DNS-over-HTTPS resolvers
				if strings.HasPrefix(nameserverStr, "https://") {
					resolvers = append(resolvers, &dnstype.Resolver{
						Addr: nameserverStr,
					})

					// This nameserver can not be parsed as an IP address
					continue
				}

				// Parse nameserver as a regular IP
				nameserver, err := netip.ParseAddr(nameserverStr)
				if err != nil {
					log.Error().
						Str("func", "getDNSConfig").
						Err(err).
						Msgf("Could not parse nameserver IP: %s", nameserverStr)
				}

				nameservers = append(nameservers, nameserver)
				resolvers = append(resolvers, &dnstype.Resolver{
					Addr: nameserver.String(),
				})
			}

			dnsConfig.Nameservers = nameservers

			if overrideLocalDNS {
				dnsConfig.Resolvers = resolvers
			} else {
				dnsConfig.FallbackResolvers = resolvers
			}
		}

		if viper.IsSet("dns_config.restricted_nameservers") {
			dnsConfig.Routes = make(map[string][]*dnstype.Resolver)
			domains := []string{}
			restrictedDNS := viper.GetStringMapStringSlice(
				"dns_config.restricted_nameservers",
			)
			for domain, restrictedNameservers := range restrictedDNS {
				restrictedResolvers := make(
					[]*dnstype.Resolver,
					len(restrictedNameservers),
				)
				for index, nameserverStr := range restrictedNameservers {
					nameserver, err := netip.ParseAddr(nameserverStr)
					if err != nil {
						log.Error().
							Str("func", "getDNSConfig").
							Err(err).
							Msgf("Could not parse restricted nameserver IP: %s", nameserverStr)
					}
					restrictedResolvers[index] = &dnstype.Resolver{
						Addr: nameserver.String(),
					}
				}
				dnsConfig.Routes[domain] = restrictedResolvers
				domains = append(domains, domain)
			}
			dnsConfig.Domains = domains
		}

		if viper.IsSet("dns_config.domains") {
			domains := viper.GetStringSlice("dns_config.domains")
			if len(dnsConfig.Resolvers) > 0 {
				dnsConfig.Domains = domains
			} else if domains != nil {
				log.Warn().
					Msg("Warning: dns_config.domains is set, but no nameservers are configured. Ignoring domains.")
			}
		}

		if viper.IsSet("dns_config.extra_records") {
			var extraRecords []tailcfg.DNSRecord

			err := viper.UnmarshalKey("dns_config.extra_records", &extraRecords)
			if err != nil {
				log.Error().
					Str("func", "getDNSConfig").
					Err(err).
					Msgf("Could not parse dns_config.extra_records")
			}

			dnsConfig.ExtraRecords = extraRecords
		}

		if viper.IsSet("dns_config.magic_dns") {
			dnsConfig.Proxied = viper.GetBool("dns_config.magic_dns")
		}

		var baseDomain string
		if viper.IsSet("dns_config.base_domain") {
			baseDomain = viper.GetString("dns_config.base_domain")
		} else {
			baseDomain = "headscale.net" // does not really matter when MagicDNS is not enabled
		}

		log.Trace().Interface("dns_config", dnsConfig).Msg("DNS configuration loaded")

		return dnsConfig, baseDomain
	}

	return nil, ""
}

func PrefixV4() (*netip.Prefix, error) {
	prefixV4Str := viper.GetString("prefixes.v4")

	if prefixV4Str == "" {
		return nil, nil
	}

	prefixV4, err := netip.ParsePrefix(prefixV4Str)
	if err != nil {
		return nil, fmt.Errorf("parsing IPv4 prefix from config: %w", err)
	}

	builder := netipx.IPSetBuilder{}
	builder.AddPrefix(tsaddr.CGNATRange())
	builder.AddPrefix(tsaddr.TailscaleULARange())
	ipSet, _ := builder.IPSet()
	if !ipSet.ContainsPrefix(prefixV4) {
		log.Warn().
			Msgf("Prefix %s is not in the %s range. This is an unsupported configuration.",
				prefixV4Str, tsaddr.CGNATRange())
	}

	return &prefixV4, nil
}

func PrefixV6() (*netip.Prefix, error) {
	prefixV6Str := viper.GetString("prefixes.v6")

	if prefixV6Str == "" {
		return nil, nil
	}

	prefixV6, err := netip.ParsePrefix(prefixV6Str)
	if err != nil {
		return nil, fmt.Errorf("parsing IPv6 prefix from config: %w", err)
	}

	builder := netipx.IPSetBuilder{}
	builder.AddPrefix(tsaddr.CGNATRange())
	builder.AddPrefix(tsaddr.TailscaleULARange())
	ipSet, _ := builder.IPSet()

	if !ipSet.ContainsPrefix(prefixV6) {
		log.Warn().
			Msgf("Prefix %s is not in the %s range. This is an unsupported configuration.",
				prefixV6Str, tsaddr.TailscaleULARange())
	}

	return &prefixV6, nil
}

func GetHeadscaleConfig() (*Config, error) {
	if IsCLIConfigured() {
		return &Config{
			CLI: CLIConfig{
				Address:  viper.GetString("cli.address"),
				APIKey:   viper.GetString("cli.api_key"),
				Timeout:  viper.GetDuration("cli.timeout"),
				Insecure: viper.GetBool("cli.insecure"),
			},
		}, nil
	}

	prefix4, err := PrefixV4()
	if err != nil {
		return nil, err
	}

	prefix6, err := PrefixV6()
	if err != nil {
		return nil, err
	}

	if prefix4 == nil && prefix6 == nil {
		return nil, fmt.Errorf("no IPv4 or IPv6 prefix configured, minimum one prefix is required")
	}

	allocStr := viper.GetString("prefixes.allocation")
	var alloc IPAllocationStrategy
	switch allocStr {
	case string(IPAllocationStrategySequential):
		alloc = IPAllocationStrategySequential
	case string(IPAllocationStrategyRandom):
		alloc = IPAllocationStrategyRandom
	default:
		return nil, fmt.Errorf("config error, prefixes.allocation is set to %s, which is not a valid strategy, allowed options: %s, %s", allocStr, IPAllocationStrategySequential, IPAllocationStrategyRandom)
	}

	dnsConfig, baseDomain := GetDNSConfig()
	derpConfig := GetDERPConfig()
	logConfig := GetLogTailConfig()
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

	return &Config{
		ServerURL:          viper.GetString("server_url"),
		Addr:               viper.GetString("listen_addr"),
		MetricsAddr:        viper.GetString("metrics_listen_addr"),
		GRPCAddr:           viper.GetString("grpc_listen_addr"),
		GRPCAllowInsecure:  viper.GetBool("grpc_allow_insecure"),
		DisableUpdateCheck: viper.GetBool("disable_check_updates"),

		PrefixV4:     prefix4,
		PrefixV6:     prefix6,
		IPAllocation: IPAllocationStrategy(alloc),

		NoisePrivateKeyPath: util.AbsolutePathFromConfigPath(
			viper.GetString("noise.private_key_path"),
		),
		BaseDomain: baseDomain,

		DERP: derpConfig,

		EphemeralNodeInactivityTimeout: viper.GetDuration(
			"ephemeral_node_inactivity_timeout",
		),

		Database: GetDatabaseConfig(),

		TLS: GetTLSConfig(),

		DNSConfig: dnsConfig,

		ACMEEmail: viper.GetString("acme_email"),
		ACMEURL:   viper.GetString("acme_url"),

		UnixSocket:           viper.GetString("unix_socket"),
		UnixSocketPermission: util.GetFileMode("unix_socket_permission"),

		OIDC: OIDCConfig{
			OnlyStartIfOIDCIsAvailable: viper.GetBool(
				"oidc.only_start_if_oidc_is_available",
			),
			Issuer:           viper.GetString("oidc.issuer"),
			ClientID:         viper.GetString("oidc.client_id"),
			ClientSecret:     oidcClientSecret,
			Scope:            viper.GetStringSlice("oidc.scope"),
			ExtraParams:      viper.GetStringMapString("oidc.extra_params"),
			AllowedDomains:   viper.GetStringSlice("oidc.allowed_domains"),
			AllowedUsers:     viper.GetStringSlice("oidc.allowed_users"),
			AllowedGroups:    viper.GetStringSlice("oidc.allowed_groups"),
			StripEmaildomain: viper.GetBool("oidc.strip_email_domain"),
			Expiry: func() time.Duration {
				// if set to 0, we assume no expiry
				if value := viper.GetString("oidc.expiry"); value == "0" {
					return maxDuration
				} else {
					expiry, err := model.ParseDuration(value)
					if err != nil {
						log.Warn().Msg("failed to parse oidc.expiry, defaulting back to 180 days")

						return defaultOIDCExpiryTime
					}

					return time.Duration(expiry)
				}
			}(),
			UseExpiryFromToken: viper.GetBool("oidc.use_expiry_from_token"),
		},

		LogTail:             logConfig,
		RandomizeClientPort: randomizeClientPort,

		ACL: GetACLConfig(),

		CLI: CLIConfig{
			Address:  viper.GetString("cli.address"),
			APIKey:   viper.GetString("cli.api_key"),
			Timeout:  viper.GetDuration("cli.timeout"),
			Insecure: viper.GetBool("cli.insecure"),
		},

		Log: GetLogConfig(),

		// TODO(kradalby): Document these settings when more stable
		Tuning: Tuning{
			BatchChangeDelay:               viper.GetDuration("tuning.batch_change_delay"),
			NodeMapSessionBufferedChanSize: viper.GetInt("tuning.node_mapsession_buffered_chan_size"),
		},
	}, nil
}

func IsCLIConfigured() bool {
	return viper.GetString("cli.address") != "" && viper.GetString("cli.api_key") != ""
}
