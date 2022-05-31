package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/juanfont/headscale"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v2"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

const (
	PermissionFallback      = 0o700
	HeadscaleDateTimeFormat = "2006-01-02 15:04:05"
)

func LoadConfig(path string) error {
	viper.SetConfigName("config")
	if path == "" {
		viper.AddConfigPath("/etc/headscale/")
		viper.AddConfigPath("$HOME/.headscale")
		viper.AddConfigPath(".")
	} else {
		// For testing
		viper.AddConfigPath(path)
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

	if err := viper.ReadInConfig(); err != nil {
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

	_, authModeValid := headscale.LookupTLSClientAuthMode(
		viper.GetString("tls_client_auth_mode"),
	)

	if !authModeValid {
		errorText += fmt.Sprintf(
			"Invalid tls_client_auth_mode supplied: %s. Accepted values: %s, %s, %s.",
			viper.GetString("tls_client_auth_mode"),
			headscale.DisabledClientAuth,
			headscale.RelaxedClientAuth,
			headscale.EnforcedClientAuth)
	}

	if errorText != "" {
		//nolint
		return errors.New(strings.TrimSuffix(errorText, "\n"))
	} else {
		return nil
	}
}

func GetDERPConfig() headscale.DERPConfig {
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

	return headscale.DERPConfig{
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

func GetLogTailConfig() headscale.LogTailConfig {
	enabled := viper.GetBool("logtail.enabled")

	return headscale.LogTailConfig{
		Enabled: enabled,
	}
}

func GetACLConfig() headscale.ACLConfig {
	policyPath := viper.GetString("acl_policy_path")

	return headscale.ACLConfig{
		PolicyPath: policyPath,
	}
}

func GetDNSConfig() (*tailcfg.DNSConfig, string) {
	if viper.IsSet("dns_config") {
		dnsConfig := &tailcfg.DNSConfig{}

		if viper.IsSet("dns_config.nameservers") {
			nameserversStr := viper.GetStringSlice("dns_config.nameservers")

			nameservers := make([]netaddr.IP, len(nameserversStr))
			resolvers := make([]dnstype.Resolver, len(nameserversStr))

			for index, nameserverStr := range nameserversStr {
				nameserver, err := netaddr.ParseIP(nameserverStr)
				if err != nil {
					log.Error().
						Str("func", "getDNSConfig").
						Err(err).
						Msgf("Could not parse nameserver IP: %s", nameserverStr)
				}

				nameservers[index] = nameserver
				resolvers[index] = dnstype.Resolver{
					Addr: nameserver.String(),
				}
			}

			dnsConfig.Nameservers = nameservers
			dnsConfig.Resolvers = resolvers
		}

		if viper.IsSet("dns_config.restricted_nameservers") {
			if len(dnsConfig.Nameservers) > 0 {
				dnsConfig.Routes = make(map[string][]dnstype.Resolver)
				restrictedDNS := viper.GetStringMapStringSlice(
					"dns_config.restricted_nameservers",
				)
				for domain, restrictedNameservers := range restrictedDNS {
					restrictedResolvers := make(
						[]dnstype.Resolver,
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
						restrictedResolvers[index] = dnstype.Resolver{
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

func GetHeadscaleConfig() headscale.Config {
	dnsConfig, baseDomain := GetDNSConfig()
	derpConfig := GetDERPConfig()
	logConfig := GetLogTailConfig()

	configuredPrefixes := viper.GetStringSlice("ip_prefixes")
	parsedPrefixes := make([]netaddr.IPPrefix, 0, len(configuredPrefixes)+1)

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

	tlsClientAuthMode, _ := headscale.LookupTLSClientAuthMode(
		viper.GetString("tls_client_auth_mode"),
	)

	return headscale.Config{
		ServerURL:         viper.GetString("server_url"),
		Addr:              viper.GetString("listen_addr"),
		MetricsAddr:       viper.GetString("metrics_listen_addr"),
		GRPCAddr:          viper.GetString("grpc_listen_addr"),
		GRPCAllowInsecure: viper.GetBool("grpc_allow_insecure"),

		IPPrefixes:     prefixes,
		PrivateKeyPath: headscale.AbsolutePathFromConfigPath(viper.GetString("private_key_path")),
		BaseDomain:     baseDomain,

		DERP: derpConfig,

		EphemeralNodeInactivityTimeout: viper.GetDuration(
			"ephemeral_node_inactivity_timeout",
		),

		DBtype: viper.GetString("db_type"),
		DBpath: headscale.AbsolutePathFromConfigPath(viper.GetString("db_path")),
		DBhost: viper.GetString("db_host"),
		DBport: viper.GetInt("db_port"),
		DBname: viper.GetString("db_name"),
		DBuser: viper.GetString("db_user"),
		DBpass: viper.GetString("db_pass"),

		TLSLetsEncryptHostname: viper.GetString("tls_letsencrypt_hostname"),
		TLSLetsEncryptListen:   viper.GetString("tls_letsencrypt_listen"),
		TLSLetsEncryptCacheDir: headscale.AbsolutePathFromConfigPath(
			viper.GetString("tls_letsencrypt_cache_dir"),
		),
		TLSLetsEncryptChallengeType: viper.GetString("tls_letsencrypt_challenge_type"),

		TLSCertPath:       headscale.AbsolutePathFromConfigPath(viper.GetString("tls_cert_path")),
		TLSKeyPath:        headscale.AbsolutePathFromConfigPath(viper.GetString("tls_key_path")),
		TLSClientAuthMode: tlsClientAuthMode,

		DNSConfig: dnsConfig,

		ACMEEmail: viper.GetString("acme_email"),
		ACMEURL:   viper.GetString("acme_url"),

		UnixSocket:           viper.GetString("unix_socket"),
		UnixSocketPermission: GetFileMode("unix_socket_permission"),

		OIDC: headscale.OIDCConfig{
			Issuer:           viper.GetString("oidc.issuer"),
			ClientID:         viper.GetString("oidc.client_id"),
			ClientSecret:     viper.GetString("oidc.client_secret"),
			Scope:            viper.GetStringSlice("oidc.scope"),
			ExtraParams:      viper.GetStringMapString("oidc.extra_params"),
			AllowedDomains:   viper.GetStringSlice("oidc.allowed_domains"),
			AllowedUsers:     viper.GetStringSlice("oidc.allowed_users"),
			StripEmaildomain: viper.GetBool("oidc.strip_email_domain"),
		},

		LogTail: logConfig,

		CLI: headscale.CLIConfig{
			Address:  viper.GetString("cli.address"),
			APIKey:   viper.GetString("cli.api_key"),
			Timeout:  viper.GetDuration("cli.timeout"),
			Insecure: viper.GetBool("cli.insecure"),
		},

		ACL: GetACLConfig(),
	}
}

func getHeadscaleApp() (*headscale.Headscale, error) {
	// Minimum inactivity time out is keepalive timeout (60s) plus a few seconds
	// to avoid races
	minInactivityTimeout, _ := time.ParseDuration("65s")
	if viper.GetDuration("ephemeral_node_inactivity_timeout") <= minInactivityTimeout {
		// TODO: Find a better way to return this text
		//nolint
		err := fmt.Errorf(
			"ephemeral_node_inactivity_timeout (%s) is set too low, must be more than %s",
			viper.GetString("ephemeral_node_inactivity_timeout"),
			minInactivityTimeout,
		)

		return nil, err
	}

	cfg := GetHeadscaleConfig()

	app, err := headscale.NewHeadscale(cfg)
	if err != nil {
		return nil, err
	}

	// We are doing this here, as in the future could be cool to have it also hot-reload

	if cfg.ACL.PolicyPath != "" {
		aclPath := headscale.AbsolutePathFromConfigPath(cfg.ACL.PolicyPath)
		err = app.LoadACLPolicy(aclPath)
		if err != nil {
			log.Fatal().
				Str("path", aclPath).
				Err(err).
				Msg("Could not load the ACL policy")
		}
	}

	return app, nil
}

func getHeadscaleCLIClient() (context.Context, v1.HeadscaleServiceClient, *grpc.ClientConn, context.CancelFunc) {
	cfg := GetHeadscaleConfig()

	log.Debug().
		Dur("timeout", cfg.CLI.Timeout).
		Msgf("Setting timeout")

	ctx, cancel := context.WithTimeout(context.Background(), cfg.CLI.Timeout)

	grpcOptions := []grpc.DialOption{
		grpc.WithBlock(),
	}

	address := cfg.CLI.Address

	// If the address is not set, we assume that we are on the server hosting headscale.
	if address == "" {
		log.Debug().
			Str("socket", cfg.UnixSocket).
			Msgf("HEADSCALE_CLI_ADDRESS environment is not set, connecting to unix socket.")

		address = cfg.UnixSocket

		grpcOptions = append(
			grpcOptions,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(headscale.GrpcSocketDialer),
		)
	} else {
		// If we are not connecting to a local server, require an API key for authentication
		apiKey := cfg.CLI.APIKey
		if apiKey == "" {
			log.Fatal().Caller().Msgf("HEADSCALE_CLI_API_KEY environment variable needs to be set.")
		}
		grpcOptions = append(grpcOptions,
			grpc.WithPerRPCCredentials(tokenAuth{
				token: apiKey,
			}),
		)

		if cfg.CLI.Insecure {
			tlsConfig := &tls.Config{
				// turn of gosec as we are intentionally setting
				// insecure.
				//nolint:gosec
				InsecureSkipVerify: true,
			}

			grpcOptions = append(grpcOptions,
				grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
			)
		} else {
			grpcOptions = append(grpcOptions,
				grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")),
			)
		}
	}

	log.Trace().Caller().Str("address", address).Msg("Connecting via gRPC")
	conn, err := grpc.DialContext(ctx, address, grpcOptions...)
	if err != nil {
		log.Fatal().Caller().Err(err).Msgf("Could not connect: %v", err)
	}

	client := v1.NewHeadscaleServiceClient(conn)

	return ctx, client, conn, cancel
}

func SuccessOutput(result interface{}, override string, outputFormat string) {
	var jsonBytes []byte
	var err error
	switch outputFormat {
	case "json":
		jsonBytes, err = json.MarshalIndent(result, "", "\t")
		if err != nil {
			log.Fatal().Err(err)
		}
	case "json-line":
		jsonBytes, err = json.Marshal(result)
		if err != nil {
			log.Fatal().Err(err)
		}
	case "yaml":
		jsonBytes, err = yaml.Marshal(result)
		if err != nil {
			log.Fatal().Err(err)
		}
	default:
		//nolint
		fmt.Println(override)

		return
	}

	//nolint
	fmt.Println(string(jsonBytes))
}

func ErrorOutput(errResult error, override string, outputFormat string) {
	type errOutput struct {
		Error string `json:"error"`
	}

	SuccessOutput(errOutput{errResult.Error()}, override, outputFormat)
}

func HasMachineOutputFlag() bool {
	for _, arg := range os.Args {
		if arg == "json" || arg == "json-line" || arg == "yaml" {
			return true
		}
	}

	return false
}

type tokenAuth struct {
	token string
}

// Return value is mapped to request headers.
func (t tokenAuth) GetRequestMetadata(
	ctx context.Context,
	in ...string,
) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + t.token,
	}, nil
}

func (tokenAuth) RequireTransportSecurity() bool {
	return true
}

func GetFileMode(key string) fs.FileMode {
	modeStr := viper.GetString(key)

	mode, err := strconv.ParseUint(modeStr, headscale.Base8, headscale.BitSize64)
	if err != nil {
		return PermissionFallback
	}

	return fs.FileMode(mode)
}

func contains[T string](ts []T, t T) bool {
	for _, v := range ts {
		if reflect.DeepEqual(v, t) {
			return true
		}
	}

	return false
}
