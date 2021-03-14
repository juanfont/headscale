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
	headscaleCmd.AddCommand(namespaceCmd)
	namespaceCmd.AddCommand(createNamespaceCmd)
	namespaceCmd.AddCommand(listNamespacesCmd)

	headscaleCmd.AddCommand(nodeCmd)
	nodeCmd.AddCommand(listRoutesCmd)
	nodeCmd.AddCommand(enableRouteCmd)

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
