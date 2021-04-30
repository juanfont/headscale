package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/juanfont/headscale/cmd/headscale/cli"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var version = "dev"

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
	Long: `
headscale is an open source implementation of the Tailscale control server

Juan Font Alonso <juanfontalonso@gmail.com> - 2021
https://gitlab.com/juanfont/headscale`,
}

func loadConfig(path string) error {
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

	err := viper.ReadInConfig()
	if err != nil {
		return errors.New(fmt.Sprintf("Fatal error reading config file: %s \n", err))
	}

	// Collect any validation errors and return them all at once
	var errorText string
	if (viper.GetString("tls_letsencrypt_hostname") != "") && ((viper.GetString("tls_cert_path") != "") || (viper.GetString("tls_key_path") != "")) {
		errorText += "Fatal config error: set either tls_letsencrypt_hostname or tls_cert_path/tls_key_path, not both\n"
	}

	if (viper.GetString("tls_letsencrypt_hostname") != "") && (viper.GetString("tls_letsencrypt_challenge_type") == "TLS-ALPN-01") && (!strings.HasSuffix(viper.GetString("listen_addr"), ":443")) {
		errorText += "Fatal config error: when using tls_letsencrypt_hostname with TLS-ALPN-01 as challenge type, listen_addr must end in :443\n"
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

func main() {
	err := loadConfig("")
	if err != nil {
		log.Fatalf(err.Error())
	}

	headscaleCmd.AddCommand(cli.NamespaceCmd)
	headscaleCmd.AddCommand(cli.NodeCmd)
	headscaleCmd.AddCommand(cli.PreauthkeysCmd)
	headscaleCmd.AddCommand(cli.RegisterCmd)
	headscaleCmd.AddCommand(cli.RoutesCmd)
	headscaleCmd.AddCommand(cli.ServeCmd)
	headscaleCmd.AddCommand(versionCmd)

	cli.NodeCmd.PersistentFlags().StringP("namespace", "n", "", "Namespace")
	err = cli.NodeCmd.MarkPersistentFlagRequired("namespace")
	if err != nil {
		log.Fatalf(err.Error())
	}

	cli.PreauthkeysCmd.PersistentFlags().StringP("namespace", "n", "", "Namespace")
	err = cli.PreauthkeysCmd.MarkPersistentFlagRequired("namespace")
	if err != nil {
		log.Fatalf(err.Error())
	}

	cli.RegisterCmd.PersistentFlags().StringP("namespace", "n", "", "Namespace")
	err = cli.RegisterCmd.MarkPersistentFlagRequired("namespace")
	if err != nil {
		log.Fatalf(err.Error())
	}

	cli.RoutesCmd.PersistentFlags().StringP("namespace", "n", "", "Namespace")
	err = cli.RoutesCmd.MarkPersistentFlagRequired("namespace")
	if err != nil {
		log.Fatalf(err.Error())
	}

	cli.NamespaceCmd.AddCommand(cli.CreateNamespaceCmd)
	cli.NamespaceCmd.AddCommand(cli.ListNamespacesCmd)

	cli.RoutesCmd.AddCommand(cli.ListRoutesCmd)
	cli.RoutesCmd.AddCommand(cli.EnableRouteCmd)

	cli.PreauthkeysCmd.AddCommand(cli.ListPreAuthKeys)
	cli.PreauthkeysCmd.AddCommand(cli.CreatePreAuthKeyCmd)

	cli.CreatePreAuthKeyCmd.PersistentFlags().Bool("reusable", false, "Make the preauthkey reusable")
	cli.CreatePreAuthKeyCmd.Flags().StringP("expiration", "e", "", "Human-readable expiration of the key (30m, 24h, 365d...)")

	if err := headscaleCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
