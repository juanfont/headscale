package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hako/durafmt"
	"github.com/juanfont/headscale"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
	"tailscale.com/tailcfg"
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
		err = h.Serve()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}
	},
}

var registerCmd = &cobra.Command{
	Use:   "register machineID namespace",
	Short: "Registers a machine to your network",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("Missing parameters")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}
		err = h.RegisterMachine(args[0], args[1])
		if err != nil {
			fmt.Printf("Error: %s", err)
			return
		}
		fmt.Println("Ook.")
	},
}

var namespaceCmd = &cobra.Command{
	Use:   "namespace",
	Short: "Manage the namespaces of Headscale",
}

var createNamespaceCmd = &cobra.Command{
	Use:   "create NAME",
	Short: "Creates a new namespace",
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
		_, err = h.CreateNamespace(args[0])
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("Ook.\n")
	},
}

var listNamespacesCmd = &cobra.Command{
	Use:   "list",
	Short: "List all the namespaces",
	Run: func(cmd *cobra.Command, args []string) {
		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}
		ns, err := h.ListNamespaces()
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("ID\tName\n")
		for _, n := range *ns {
			fmt.Printf("%d\t%s\n", n.ID, n.Name)
		}
	},
}

var nodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Manage the nodes of Headscale",
}

var listRoutesCmd = &cobra.Command{
	Use:   "list-routes NAMESPACE NODE",
	Short: "List the routes exposed by this node",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("Missing parameters")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}
		err = h.ListNodeRoutes(args[0], args[1])
		if err != nil {
			fmt.Println(err)
			return
		}
	},
}

var enableRouteCmd = &cobra.Command{
	Use:   "enable-route",
	Short: "Allows exposing a route declared by this node to the rest of the nodes",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 3 {
			return fmt.Errorf("Missing parameters")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}
		err = h.EnableNodeRoute(args[0], args[1], args[2])
		if err != nil {
			fmt.Println(err)
			return
		}
	},
}

var preauthkeysCmd = &cobra.Command{
	Use:   "preauthkey",
	Short: "Handle the preauthkeys in Headscale",
}

var listPreAuthKeys = &cobra.Command{
	Use:   "list NAMESPACE",
	Short: "List the preauthkeys for this namespace",
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
		keys, err := h.GetPreAuthKeys(args[0])
		if err != nil {
			fmt.Println(err)
			return
		}
		for _, k := range *keys {
			fmt.Printf(
				"key: %s, namespace: %s, reusable: %v, expiration: %s, created_at: %s\n",
				k.Key,
				k.Namespace.Name,
				k.Reusable,
				k.Expiration.Format("2006-01-02 15:04:05"),
				k.CreatedAt.Format("2006-01-02 15:04:05"),
			)
		}
	},
}

var createPreAuthKeyCmd = &cobra.Command{
	Use:   "create NAMESPACE",
	Short: "Creates a new preauthkey in the specified namespace",
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
		reusable, _ := cmd.Flags().GetBool("reusable")

		e, _ := cmd.Flags().GetString("expiration")
		var expiration *time.Time
		if e != "" {
			duration, err := durafmt.ParseStringShort(e)
			if err != nil {
				log.Fatalf("Error parsing expiration: %s", err)
			}
			exp := time.Now().UTC().Add(duration.Duration())
			expiration = &exp
		}

		_, err = h.CreatePreAuthKey(args[0], reusable, expiration)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("Ook.\n")
	},
}

func loadConfig(path string) {
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
		log.Fatalf("Fatal error config file: %s \n", err)
	}

	if (viper.GetString("tls_letsencrypt_hostname") != "") && ((viper.GetString("tls_cert_path") != "") || (viper.GetString("tls_key_path") != "")) {
		log.Fatalf("Fatal config error: set either tls_letsencrypt_hostname or tls_cert_path/tls_key_path, not both")
	}

	if (viper.GetString("tls_letsencrypt_hostname") != "") && (viper.GetString("tls_letsencrypt_challenge_type") == "TLS-ALPN-01") && (!strings.HasSuffix(viper.GetString("listen_addr"), ":443")) {
		log.Fatalf("Fatal config error: when using tls_letsencrypt_hostname with TLS-ALPN-01 as challenge type, listen_addr must end in :443")
	}

	if (viper.GetString("tls_letsencrypt_challenge_type") != "HTTP-01") && (viper.GetString("tls_letsencrypt_challenge_type") != "TLS-ALPN-01") {
		log.Fatalf("Fatal config error: the only supported values for tls_letsencrypt_challenge_type are HTTP-01 and TLS-ALPN-01")
	}

	if !strings.HasPrefix(viper.GetString("server_url"), "http://") && !strings.HasPrefix(viper.GetString("server_url"), "https://") {
		log.Fatalf("Fatal config error: server_url must start with https:// or http://")
	}
}

func main() {
	loadConfig("")

	headscaleCmd.AddCommand(versionCmd)
	headscaleCmd.AddCommand(serveCmd)
	headscaleCmd.AddCommand(registerCmd)
	headscaleCmd.AddCommand(preauthkeysCmd)
	headscaleCmd.AddCommand(namespaceCmd)
	headscaleCmd.AddCommand(nodeCmd)

	namespaceCmd.AddCommand(createNamespaceCmd)
	namespaceCmd.AddCommand(listNamespacesCmd)

	nodeCmd.AddCommand(listRoutesCmd)
	nodeCmd.AddCommand(enableRouteCmd)

	preauthkeysCmd.AddCommand(listPreAuthKeys)
	preauthkeysCmd.AddCommand(createPreAuthKeyCmd)
	createPreAuthKeyCmd.PersistentFlags().Bool("reusable", false, "Make the preauthkey reusable")
	createPreAuthKeyCmd.Flags().StringP("expiration", "e", "", "Human-readable expiration of the key (30m, 24h, 365d...)")

	if err := headscaleCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

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
