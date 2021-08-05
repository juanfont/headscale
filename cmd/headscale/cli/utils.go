package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/juanfont/headscale"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
)

type ErrorOutput struct {
	Error string
}

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
	viper.AutomaticEnv()

	viper.SetDefault("tls_letsencrypt_cache_dir", "/var/www/.cache")
	viper.SetDefault("tls_letsencrypt_challenge_type", "HTTP-01")

	viper.SetDefault("ip_prefix", "100.64.0.0/10")

	viper.SetDefault("log_level", "debug")

	err := viper.ReadInConfig()
	if err != nil {
		return fmt.Errorf("Fatal error reading config file: %s \n", err)
	}

	// Collect any validation errors and return them all at once
	var errorText string
	if (viper.GetString("tls_letsencrypt_hostname") != "") && ((viper.GetString("tls_cert_path") != "") || (viper.GetString("tls_key_path") != "")) {
		errorText += "Fatal config error: set either tls_letsencrypt_hostname or tls_cert_path/tls_key_path, not both\n"
	}

	if (viper.GetString("tls_letsencrypt_hostname") != "") && (viper.GetString("tls_letsencrypt_challenge_type") == "TLS-ALPN-01") && (!strings.HasSuffix(viper.GetString("listen_addr"), ":443")) {
		// this is only a warning because there could be something sitting in front of headscale that redirects the traffic (e.g. an iptables rule)
		log.Warn().
			Msg("Warning: when using tls_letsencrypt_hostname with TLS-ALPN-01 as challenge type, headscale must be reachable on port 443, i.e. listen_addr should probably end in :443")
	}

	if (viper.GetString("tls_letsencrypt_challenge_type") != "HTTP-01") && (viper.GetString("tls_letsencrypt_challenge_type") != "TLS-ALPN-01") {
		errorText += "Fatal config error: the only supported values for tls_letsencrypt_challenge_type are HTTP-01 and TLS-ALPN-01\n"
	}

	if !strings.HasPrefix(viper.GetString("server_url"), "http://") && !strings.HasPrefix(viper.GetString("server_url"), "https://") {
		errorText += "Fatal config error: server_url must start with https:// or http://\n"
	}
	if errorText != "" {
		return errors.New(strings.TrimSuffix(errorText, "\n"))
	} else {
		return nil
	}
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

func getHeadscaleApp() (*headscale.Headscale, error) {
	derpPath := absPath(viper.GetString("derp_map_path"))
	derpMap, err := loadDerpMap(derpPath)
	if err != nil {
		log.Error().
			Str("Path", derpPath).
			Err(err).
			Msg("Could not load DERP servers map file")
	}

	// Minimum inactivity time out is keepalive timeout (60s) plus a few seconds
	// to avoid races
	minInactivityTimeout, _ := time.ParseDuration("65s")
	if viper.GetDuration("ephemeral_node_inactivity_timeout") <= minInactivityTimeout {
		err = fmt.Errorf("ephemeral_node_inactivity_timeout (%s) is set too low, must be more than %s\n", viper.GetString("ephemeral_node_inactivity_timeout"), minInactivityTimeout)
		return nil, err
	}

	cfg := headscale.Config{
		ServerURL:      viper.GetString("server_url"),
		Addr:           viper.GetString("listen_addr"),
		PrivateKeyPath: absPath(viper.GetString("private_key_path")),
		DerpMap:        derpMap,
		IPPrefix:       netaddr.MustParseIPPrefix(viper.GetString("ip_prefix")),

		EphemeralNodeInactivityTimeout: viper.GetDuration("ephemeral_node_inactivity_timeout"),

		DBtype: viper.GetString("db_type"),
		DBpath: absPath(viper.GetString("db_path")),
		DBhost: viper.GetString("db_host"),
		DBport: viper.GetInt("db_port"),
		DBname: viper.GetString("db_name"),
		DBuser: viper.GetString("db_user"),
		DBpass: viper.GetString("db_pass"),

		TLSLetsEncryptHostname:      viper.GetString("tls_letsencrypt_hostname"),
		TLSLetsEncryptListen:        viper.GetString("tls_letsencrypt_listen"),
		TLSLetsEncryptCacheDir:      absPath(viper.GetString("tls_letsencrypt_cache_dir")),
		TLSLetsEncryptChallengeType: viper.GetString("tls_letsencrypt_challenge_type"),

		TLSCertPath: absPath(viper.GetString("tls_cert_path")),
		TLSKeyPath:  absPath(viper.GetString("tls_key_path")),
	}

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
				Str("Path", aclPath).
				Err(err).
				Msg("Could not load the ACL policy")
		}
	}

	return h, nil
}

func loadDerpMap(path string) (*tailcfg.DERPMap, error) {
	derpFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer derpFile.Close()
	var derpMap tailcfg.DERPMap
	b, err := io.ReadAll(derpFile)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(b, &derpMap)
	return &derpMap, err
}

func JsonOutput(result interface{}, errResult error, outputFormat string) {
	var j []byte
	var err error
	switch outputFormat {
	case "json":
		if errResult != nil {
			j, err = json.MarshalIndent(ErrorOutput{errResult.Error()}, "", "\t")
			if err != nil {
				log.Fatal().Err(err)
			}
		} else {
			j, err = json.MarshalIndent(result, "", "\t")
			if err != nil {
				log.Fatal().Err(err)
			}
		}
	case "json-line":
		if errResult != nil {
			j, err = json.Marshal(ErrorOutput{errResult.Error()})
			if err != nil {
				log.Fatal().Err(err)
			}
		} else {
			j, err = json.Marshal(result)
			if err != nil {
				log.Fatal().Err(err)
			}
		}
	}
	fmt.Println(string(j))
}
