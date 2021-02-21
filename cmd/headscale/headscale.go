package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/juanfont/headscale"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
	"tailscale.com/tailcfg"
)

const version = "0.1"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version.",
	Long:  "The version of headscale.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version)
	},
}

var headscaleCmd = &cobra.Command{
	Use:   "headscale",
	Short: "headscale - a Tailscale control server",
	Long: fmt.Sprintf(`
headscale is an open source implementation of the Tailscale control server

Juan Font Alonso <juanfontalonso@gmail.com> - 2021
https://gitlab.com/juanfont/headscale`),
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Launches the headscale server",
	Args: func(cmd *cobra.Command, args []string) error {
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}
		h.Serve()
	},
}

var registerCmd = &cobra.Command{
	Use:   "register machineID",
	Short: "Registers a machine to your network",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("Missing parameters")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}
		h.RegisterMachine(args[0])
	},
}

func main() {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Fatal error config file: %s \n", err)
	}

	headscaleCmd.AddCommand(versionCmd)
	headscaleCmd.AddCommand(serveCmd)
	headscaleCmd.AddCommand(registerCmd)

	if err := headscaleCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

}

func getHeadscaleApp() (*headscale.Headscale, error) {
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
