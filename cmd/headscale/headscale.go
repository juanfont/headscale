package main

import (
	"io"
	"log"
	"os"

	"github.com/juanfont/headscale"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
	"tailscale.com/tailcfg"
)

func main() {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Fatal error config file: %s \n", err)
	}

	derpMap, err := loadDerpMap(viper.GetString("derp_map_path"))
	if err != nil {
		log.Printf("Could not load DERP servers map file: %s", err)
	}

	cfg := headscale.Config{
		ServerURL:      viper.GetString("server_url"),
		Addr:           viper.GetString("listen_addr"),
		PrivateKeyPath: viper.GetString("private_key_path"),
		DerpMap:        derpMap,

		DBhost: viper.GetString("db_host"),
		DBport: viper.GetInt("db_port"),
		DBname: viper.GetString("db_name"),
		DBuser: viper.GetString("db_user"),
		DBpass: viper.GetString("db_pass"),
	}
	h, err := headscale.NewHeadscale(cfg)
	if err != nil {
		log.Fatalln(err)
	}
	h.Serve()
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
