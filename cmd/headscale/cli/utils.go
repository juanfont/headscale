package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/juanfont/headscale"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v2"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
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

	viper.SetDefault("ip_prefix", "100.64.0.0/10")

	viper.SetDefault("log_level", "info")

	viper.SetDefault("dns_config", nil)

	viper.SetDefault("unix_socket", "/var/run/headscale.sock")

	viper.SetDefault("cli.insecure", false)
	viper.SetDefault("cli.timeout", "5s")

	err := viper.ReadInConfig()
	if err != nil {
		return fmt.Errorf("Fatal error reading config file: %s \n", err)
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
	if errorText != "" {
		return errors.New(strings.TrimSuffix(errorText, "\n"))
	} else {
		return nil
	}
}

func GetDERPConfig() headscale.DERPConfig {
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
		URLs:            urls,
		Paths:           paths,
		AutoUpdate:      autoUpdate,
		UpdateFrequency: updateFrequency,
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

func absPath(path string) string {
	// If a relative path is provided, prefix it with the the directory where
	// the config file was found.
	if (path != "") && !strings.HasPrefix(path, string(os.PathSeparator)) {
		dir, _ := filepath.Split(viper.ConfigFileUsed())
		if dir != "" {
			path = filepath.Join(dir, path)
		}
	}
	return path
}

func getHeadscaleConfig() headscale.Config {
	// maxMachineRegistrationDuration is the maximum time headscale will allow a client to (optionally) request for
	// the machine key expiry time. RegisterRequests with Expiry times that are more than
	// maxMachineRegistrationDuration in the future will be clamped to (now + maxMachineRegistrationDuration)
	maxMachineRegistrationDuration, _ := time.ParseDuration(
		"10h",
	) // use 10h here because it is the length of a standard business day plus a small amount of leeway
	if viper.GetDuration("max_machine_registration_duration") >= time.Second {
		maxMachineRegistrationDuration = viper.GetDuration(
			"max_machine_registration_duration",
		)
	}

	// defaultMachineRegistrationDuration is the default time assigned to a machine registration if one is not
	// specified by the tailscale client. It is the default amount of time a machine registration is valid for
	// (ie the amount of time before the user has to re-authenticate when requesting a connection)
	defaultMachineRegistrationDuration, _ := time.ParseDuration(
		"8h",
	) // use 8h here because it's the length of a standard business day
	if viper.GetDuration("default_machine_registration_duration") >= time.Second {
		defaultMachineRegistrationDuration = viper.GetDuration(
			"default_machine_registration_duration",
		)
	}

	dnsConfig, baseDomain := GetDNSConfig()
	derpConfig := GetDERPConfig()

	return headscale.Config{
		ServerURL:      viper.GetString("server_url"),
		Addr:           viper.GetString("listen_addr"),
		PrivateKeyPath: absPath(viper.GetString("private_key_path")),
		IPPrefix:       netaddr.MustParseIPPrefix(viper.GetString("ip_prefix")),
		BaseDomain:     baseDomain,

		DERP: derpConfig,

		EphemeralNodeInactivityTimeout: viper.GetDuration(
			"ephemeral_node_inactivity_timeout",
		),

		DBtype: viper.GetString("db_type"),
		DBpath: absPath(viper.GetString("db_path")),
		DBhost: viper.GetString("db_host"),
		DBport: viper.GetInt("db_port"),
		DBname: viper.GetString("db_name"),
		DBuser: viper.GetString("db_user"),
		DBpass: viper.GetString("db_pass"),

		TLSLetsEncryptHostname: viper.GetString("tls_letsencrypt_hostname"),
		TLSLetsEncryptListen:   viper.GetString("tls_letsencrypt_listen"),
		TLSLetsEncryptCacheDir: absPath(
			viper.GetString("tls_letsencrypt_cache_dir"),
		),
		TLSLetsEncryptChallengeType: viper.GetString("tls_letsencrypt_challenge_type"),

		TLSCertPath: absPath(viper.GetString("tls_cert_path")),
		TLSKeyPath:  absPath(viper.GetString("tls_key_path")),

		DNSConfig: dnsConfig,

		ACMEEmail: viper.GetString("acme_email"),
		ACMEURL:   viper.GetString("acme_url"),

		UnixSocket: viper.GetString("unix_socket"),

		OIDC: headscale.OIDCConfig{
			Issuer:       viper.GetString("oidc.issuer"),
			ClientID:     viper.GetString("oidc.client_id"),
			ClientSecret: viper.GetString("oidc.client_secret"),
		},

		CLI: headscale.CLIConfig{
			Address:  viper.GetString("cli.address"),
			APIKey:   viper.GetString("cli.api_key"),
			Insecure: viper.GetBool("cli.insecure"),
			Timeout:  viper.GetDuration("cli.timeout"),
		},

		MaxMachineRegistrationDuration:     maxMachineRegistrationDuration,
		DefaultMachineRegistrationDuration: defaultMachineRegistrationDuration,
	}
}

func getHeadscaleApp() (*headscale.Headscale, error) {
	// Minimum inactivity time out is keepalive timeout (60s) plus a few seconds
	// to avoid races
	minInactivityTimeout, _ := time.ParseDuration("65s")
	if viper.GetDuration("ephemeral_node_inactivity_timeout") <= minInactivityTimeout {
		err := fmt.Errorf(
			"ephemeral_node_inactivity_timeout (%s) is set too low, must be more than %s\n",
			viper.GetString("ephemeral_node_inactivity_timeout"),
			minInactivityTimeout,
		)
		return nil, err
	}

	cfg := getHeadscaleConfig()

	cfg.OIDC.MatchMap = loadOIDCMatchMap()

	h, err := headscale.NewHeadscale(cfg)
	if err != nil {
		return nil, err
	}

	// We are doing this here, as in the future could be cool to have it also hot-reload

	if viper.GetString("acl_policy_path") != "" {
		aclPath := absPath(viper.GetString("acl_policy_path"))
		err = h.LoadACLPolicy(aclPath)
		if err != nil {
			log.Error().
				Str("path", aclPath).
				Err(err).
				Msg("Could not load the ACL policy")
		}
	}

	return h, nil
}

func getHeadscaleCLIClient() (context.Context, v1.HeadscaleServiceClient, *grpc.ClientConn, context.CancelFunc) {
	cfg := getHeadscaleConfig()

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
			grpc.WithInsecure(),
			grpc.WithContextDialer(headscale.GrpcSocketDialer),
		)
	} else {
		// If we are not connecting to a local server, require an API key for authentication
		apiKey := cfg.CLI.APIKey
		if apiKey == "" {
			log.Fatal().Msgf("HEADSCALE_CLI_API_KEY environment variable needs to be set.")
		}
		grpcOptions = append(grpcOptions,
			grpc.WithPerRPCCredentials(tokenAuth{
				token: apiKey,
			}),
		)

		if cfg.CLI.Insecure {
			grpcOptions = append(grpcOptions, grpc.WithInsecure())
		}
	}

	log.Trace().Caller().Str("address", address).Msg("Connecting via gRPC")
	conn, err := grpc.DialContext(ctx, address, grpcOptions...)
	if err != nil {
		log.Fatal().Err(err).Msgf("Could not connect: %v", err)
	}

	client := v1.NewHeadscaleServiceClient(conn)

	return ctx, client, conn, cancel
}

func SuccessOutput(result interface{}, override string, outputFormat string) {
	var j []byte
	var err error
	switch outputFormat {
	case "json":
		j, err = json.MarshalIndent(result, "", "\t")
		if err != nil {
			log.Fatal().Err(err)
		}
	case "json-line":
		j, err = json.Marshal(result)
		if err != nil {
			log.Fatal().Err(err)
		}
	case "yaml":
		j, err = yaml.Marshal(result)
		if err != nil {
			log.Fatal().Err(err)
		}
	default:
		fmt.Println(override)
		return
	}

	fmt.Println(string(j))
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

// loadOIDCMatchMap is a wrapper around viper to verifies that the keys in
// the match map is valid regex strings.
func loadOIDCMatchMap() map[string]string {
	strMap := viper.GetStringMapString("oidc.domain_map")

	for oidcMatcher := range strMap {
		_ = regexp.MustCompile(oidcMatcher)
	}

	return strMap
}
