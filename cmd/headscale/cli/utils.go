package cli

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/juanfont/headscale"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
	"tailscale.com/tailcfg"
)

func absPath(path string) string {
	// If a relative path is provided, prefix it with the the directory where
	// the config file was found.
	if (path != "") && !strings.HasPrefix(path, "/") {
		dir, _ := filepath.Split(viper.ConfigFileUsed())
		if dir != "" {
			path = dir + "/" + path
		}
	}
	return path
}

func getHeadscaleApp() (*headscale.Headscale, error) {
	derpMap, err := loadDerpMap(absPath(viper.GetString("derp_map_path")))
	if err != nil {
		log.Printf("Could not load DERP servers map file: %s", err)
	}

	cfg := headscale.Config{
		ServerURL:      viper.GetString("server_url"),
		Addr:           viper.GetString("listen_addr"),
		PrivateKeyPath: absPath(viper.GetString("private_key_path")),
		DerpMap:        derpMap,

		DBhost: viper.GetString("db_host"),
		DBport: viper.GetInt("db_port"),
		DBname: viper.GetString("db_name"),
		DBuser: viper.GetString("db_user"),
		DBpass: viper.GetString("db_pass"),

		TLSLetsEncryptHostname:      viper.GetString("tls_letsencrypt_hostname"),
		TLSLetsEncryptCacheDir:      absPath(viper.GetString("tls_letsencrypt_cache_dir")),
		TLSLetsEncryptChallengeType: viper.GetString("tls_letsencrypt_challenge_type"),

		TLSCertPath: absPath(viper.GetString("tls_cert_path")),
		TLSKeyPath:  absPath(viper.GetString("tls_key_path")),
	}

	h, err := headscale.NewHeadscale(cfg)
	if err != nil {
		return nil, err
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
