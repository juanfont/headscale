package main

import (
	"log"

	"github.com/juanfont/headscale"
	"github.com/spf13/viper"
)

func main() {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Fatal error config file: %s \n", err)
	}

	cfg := headscale.Config{
		ServerURL:      viper.GetString("server_url"),
		Addr:           viper.GetString("listen_addr"),
		PrivateKeyPath: viper.GetString("private_key_path"),

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
