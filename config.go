package headscale

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

// Config contains the initial Headscale configuration.
type Config struct {
	ServerURL                      string
	Addr                           string
	MetricsAddr                    string
	GRPCAddr                       string
	GRPCAllowInsecure              bool
	EphemeralNodeInactivityTimeout time.Duration
	NodeUpdateCheckInterval        time.Duration
	IPPrefixes                     []netaddr.IPPrefix
	PrivateKeyPath                 string
	BaseDomain                     string
	LogLevel                       zerolog.Level
	DisableUpdateCheck             bool

	DERP DERPConfig

	DBtype string
	DBpath string
	DBhost string
	DBport int
	DBname string
	DBuser string
	DBpass string

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
}

type TLSConfig struct {
	CertPath       string
	KeyPath        string
	ClientAuthMode tls.ClientAuthType

	LetsEncrypt LetsEncryptConfig
}

type LetsEncryptConfig struct {
	Listen        string
	Hostname      string
	CacheDir      string
	ChallengeType string
}

type OIDCConfig struct {
	Issuer           string
	ClientID         string
	ClientSecret     string
	Scope            []string
	ExtraParams      map[string]string
	AllowedDomains   []string
	AllowedUsers     []string
	StripEmaildomain bool
}

type DERPConfig struct {
	ServerEnabled    bool
	ServerRegionID   int
	ServerRegionCode string
	ServerRegionName string
	STUNAddr         string
	URLs             []url.URL
	Paths            []string
	AutoUpdate       bool
	UpdateFrequency  time.Duration
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
	viper.SetDefault("tls_letsencrypt_challenge_type", "HTTP-01")
	viper.SetDefault("tls_client_auth_mode", "relaxed")

	viper.SetDefault("log_level", "info")

	viper.SetDefault("dns_config", nil)

	viper.SetDefault("derp.server.enabled", false)
	viper.SetDefault("derp.server.stun.enabled", true)

	viper.SetDefault("unix_socket", "/var/run/headscale.sock")
	viper.SetDefault("unix_socket_permission", "0o770")

	viper.SetDefault("grpc_listen_addr", ":50443")
	viper.SetDefault("grpc_allow_insecure", false)

	viper.SetDefault("cli.timeout", "5s")
	viper.SetDefault("cli.insecure", false)

	viper.SetDefault("oidc.scope", []string{oidc.ScopeOpenID, "profile", "email"})
	viper.SetDefault("oidc.strip_email_domain", true)

	viper.SetDefault("logtail.enabled", false)
	viper.SetDefault("randomize_client_port", false)

	viper.SetDefault("ephemeral_node_inactivity_timeout", "120s")

	viper.SetDefault("node_update_check_interval", "10s")

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

	if (viper.GetString("tls_letsencrypt_hostname") != "") &&
		(viper.GetString("tls_letsencrypt_challenge_type") == "TLS-ALPN-01") &&
		(!strings.HasSuffix(viper.GetString("listen_addr"), ":443")) {
		// this is only a warning because there could be something sitting in front of headscale that redirects the traffic (e.g. an iptables rule)
		log.Warn().
			Msg("Warning: when using tls_letsencrypt_hostname with TLS-ALPN-01 as challenge type, headscale must be reachable on port 443, i.e. listen_addr should probably end in :443")
	}

	if (viper.GetString("tls_letsencrypt_challenge_type") != "HTTP-01") &&
		(viper.GetString("tls_letsencrypt_challenge_type") != "TLS-ALPN-01") {
		errorText += "Fatal config error: the only supported values for tls_letsencrypt_challenge_type are HTTP-01 and TLS-ALPN-01\n"
	}

	if !strings.HasPrefix(viper.GetString("server_url"), "http://") &&
		!strings.HasPrefix(viper.GetString("server_url"), "https://") {
		errorText += "Fatal config error: server_url must start with https:// or http://\n"
	}

	_, authModeValid := LookupTLSClientAuthMode(
		viper.GetString("tls_client_auth_mode"),
	)

	if !authModeValid {
		errorText += fmt.Sprintf(
			"Invalid tls_client_auth_mode supplied: %s. Accepted values: %s, %s, %s.",
			viper.GetString("tls_client_auth_mode"),
			DisabledClientAuth,
			RelaxedClientAuth,
			EnforcedClientAuth)
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

	maxNodeUpdateCheckInterval, _ := time.ParseDuration("60s")
	if viper.GetDuration("node_update_check_interval") > maxNodeUpdateCheckInterval {
		errorText += fmt.Sprintf(
			"Fatal config error: node_update_check_interval (%s) is set too high, must be less than %s",
			viper.GetString("node_update_check_interval"),
			maxNodeUpdateCheckInterval,
		)
	}

	if errorText != "" {
		//nolint
		return errors.New(strings.TrimSuffix(errorText, "\n"))
	} else {
		return nil
	}
}

func GetTLSConfig() TLSConfig {
	tlsClientAuthMode, _ := LookupTLSClientAuthMode(
		viper.GetString("tls_client_auth_mode"),
	)

	return TLSConfig{
		LetsEncrypt: LetsEncryptConfig{
			Hostname: viper.GetString("tls_letsencrypt_hostname"),
			Listen:   viper.GetString("tls_letsencrypt_listen"),
			CacheDir: AbsolutePathFromConfigPath(
				viper.GetString("tls_letsencrypt_cache_dir"),
			),
			ChallengeType: viper.GetString("tls_letsencrypt_challenge_type"),
		},
		CertPath: AbsolutePathFromConfigPath(
			viper.GetString("tls_cert_path"),
		),
		KeyPath: AbsolutePathFromConfigPath(
			viper.GetString("tls_key_path"),
		),
		ClientAuthMode: tlsClientAuthMode,
	}
}

func GetDERPConfig() DERPConfig {
	serverEnabled := viper.GetBool("derp.server.enabled")
	serverRegionID := viper.GetInt("derp.server.region_id")
	serverRegionCode := viper.GetString("derp.server.region_code")
	serverRegionName := viper.GetString("derp.server.region_name")
	stunAddr := viper.GetString("derp.server.stun_listen_addr")

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

	autoUpdate := viper.GetBool("derp.auto_update_enabled")
	updateFrequency := viper.GetDuration("derp.update_frequency")

	return DERPConfig{
		ServerEnabled:    serverEnabled,
		ServerRegionID:   serverRegionID,
		ServerRegionCode: serverRegionCode,
		ServerRegionName: serverRegionName,
		STUNAddr:         stunAddr,
		URLs:             urls,
		Paths:            paths,
		AutoUpdate:       autoUpdate,
		UpdateFrequency:  updateFrequency,
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

func GetDNSConfig() (*tailcfg.DNSConfig, string) {
	if viper.IsSet("dns_config") {
		dnsConfig := &tailcfg.DNSConfig{}

		if viper.IsSet("dns_config.nameservers") {
			nameserversStr := viper.GetStringSlice("dns_config.nameservers")

			nameservers := make([]netaddr.IP, len(nameserversStr))
			resolvers := make([]*dnstype.Resolver, len(nameserversStr))

			for index, nameserverStr := range nameserversStr {
				nameserver, err := netaddr.ParseIP(nameserverStr)
				if err != nil {
					log.Error().
						Str("func", "getDNSConfig").
						Err(err).
						Msgf("Could not parse nameserver IP: %s", nameserverStr)
				}

				nameservers[index] = nameserver
				resolvers[index] = &dnstype.Resolver{
					Addr: nameserver.String(),
				}
			}

			dnsConfig.Nameservers = nameservers
			dnsConfig.Resolvers = resolvers
		}

		if viper.IsSet("dns_config.restricted_nameservers") {
			if len(dnsConfig.Nameservers) > 0 {
				dnsConfig.Routes = make(map[string][]*dnstype.Resolver)
				restrictedDNS := viper.GetStringMapStringSlice(
					"dns_config.restricted_nameservers",
				)
				for domain, restrictedNameservers := range restrictedDNS {
					restrictedResolvers := make(
						[]*dnstype.Resolver,
						len(restrictedNameservers),
					)
					for index, nameserverStr := range restrictedNameservers {
						nameserver, err := netaddr.ParseIP(nameserverStr)
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
				}
			} else {
				log.Warn().
					Msg("Warning: dns_config.restricted_nameservers is set, but no nameservers are configured. Ignoring restricted_nameservers.")
			}
		}

		if viper.IsSet("dns_config.domains") {
			dnsConfig.Domains = viper.GetStringSlice("dns_config.domains")
		}

		if viper.IsSet("dns_config.magic_dns") {
			magicDNS := viper.GetBool("dns_config.magic_dns")
			if len(dnsConfig.Nameservers) > 0 {
				dnsConfig.Proxied = magicDNS
			} else if magicDNS {
				log.Warn().
					Msg("Warning: dns_config.magic_dns is set, but no nameservers are configured. Ignoring magic_dns.")
			}
		}

		var baseDomain string
		if viper.IsSet("dns_config.base_domain") {
			baseDomain = viper.GetString("dns_config.base_domain")
		} else {
			baseDomain = "headscale.net" // does not really matter when MagicDNS is not enabled
		}

		return dnsConfig, baseDomain
	}

	return nil, ""
}

func GetHeadscaleConfig() (*Config, error) {
	dnsConfig, baseDomain := GetDNSConfig()
	derpConfig := GetDERPConfig()
	logConfig := GetLogTailConfig()
	randomizeClientPort := viper.GetBool("randomize_client_port")

	configuredPrefixes := viper.GetStringSlice("ip_prefixes")
	parsedPrefixes := make([]netaddr.IPPrefix, 0, len(configuredPrefixes)+1)

	logLevelStr := viper.GetString("log_level")
	logLevel, err := zerolog.ParseLevel(logLevelStr)
	if err != nil {
		logLevel = zerolog.DebugLevel
	}

	legacyPrefixField := viper.GetString("ip_prefix")
	if len(legacyPrefixField) > 0 {
		log.
			Warn().
			Msgf(
				"%s, %s",
				"use of 'ip_prefix' for configuration is deprecated",
				"please see 'ip_prefixes' in the shipped example.",
			)
		legacyPrefix, err := netaddr.ParseIPPrefix(legacyPrefixField)
		if err != nil {
			panic(fmt.Errorf("failed to parse ip_prefix: %w", err))
		}
		parsedPrefixes = append(parsedPrefixes, legacyPrefix)
	}

	for i, prefixInConfig := range configuredPrefixes {
		prefix, err := netaddr.ParseIPPrefix(prefixInConfig)
		if err != nil {
			panic(fmt.Errorf("failed to parse ip_prefixes[%d]: %w", i, err))
		}
		parsedPrefixes = append(parsedPrefixes, prefix)
	}

	prefixes := make([]netaddr.IPPrefix, 0, len(parsedPrefixes))
	{
		// dedup
		normalizedPrefixes := make(map[string]int, len(parsedPrefixes))
		for i, p := range parsedPrefixes {
			normalized, _ := p.Range().Prefix()
			normalizedPrefixes[normalized.String()] = i
		}

		// convert back to list
		for _, i := range normalizedPrefixes {
			prefixes = append(prefixes, parsedPrefixes[i])
		}
	}

	if len(prefixes) < 1 {
		prefixes = append(prefixes, netaddr.MustParseIPPrefix("100.64.0.0/10"))
		log.Warn().
			Msgf("'ip_prefixes' not configured, falling back to default: %v", prefixes)
	}

	return &Config{
		ServerURL:          viper.GetString("server_url"),
		Addr:               viper.GetString("listen_addr"),
		MetricsAddr:        viper.GetString("metrics_listen_addr"),
		GRPCAddr:           viper.GetString("grpc_listen_addr"),
		GRPCAllowInsecure:  viper.GetBool("grpc_allow_insecure"),
		DisableUpdateCheck: viper.GetBool("disable_check_updates"),
		LogLevel:           logLevel,

		IPPrefixes: prefixes,
		PrivateKeyPath: AbsolutePathFromConfigPath(
			viper.GetString("private_key_path"),
		),
		BaseDomain: baseDomain,

		DERP: derpConfig,

		EphemeralNodeInactivityTimeout: viper.GetDuration(
			"ephemeral_node_inactivity_timeout",
		),

		NodeUpdateCheckInterval: viper.GetDuration(
			"node_update_check_interval",
		),

		DBtype: viper.GetString("db_type"),
		DBpath: AbsolutePathFromConfigPath(viper.GetString("db_path")),
		DBhost: viper.GetString("db_host"),
		DBport: viper.GetInt("db_port"),
		DBname: viper.GetString("db_name"),
		DBuser: viper.GetString("db_user"),
		DBpass: viper.GetString("db_pass"),

		TLS: GetTLSConfig(),

		DNSConfig: dnsConfig,

		ACMEEmail: viper.GetString("acme_email"),
		ACMEURL:   viper.GetString("acme_url"),

		UnixSocket:           viper.GetString("unix_socket"),
		UnixSocketPermission: GetFileMode("unix_socket_permission"),

		OIDC: OIDCConfig{
			Issuer:           viper.GetString("oidc.issuer"),
			ClientID:         viper.GetString("oidc.client_id"),
			ClientSecret:     viper.GetString("oidc.client_secret"),
			Scope:            viper.GetStringSlice("oidc.scope"),
			ExtraParams:      viper.GetStringMapString("oidc.extra_params"),
			AllowedDomains:   viper.GetStringSlice("oidc.allowed_domains"),
			AllowedUsers:     viper.GetStringSlice("oidc.allowed_users"),
			StripEmaildomain: viper.GetBool("oidc.strip_email_domain"),
		},

		LogTail:             logConfig,
		RandomizeClientPort: randomizeClientPort,

		CLI: CLIConfig{
			Address:  viper.GetString("cli.address"),
			APIKey:   viper.GetString("cli.api_key"),
			Timeout:  viper.GetDuration("cli.timeout"),
			Insecure: viper.GetBool("cli.insecure"),
		},

		ACL: GetACLConfig(),
	}, nil
}
