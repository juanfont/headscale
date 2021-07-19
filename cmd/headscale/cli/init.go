package cli

import (
	"fmt"
	"log"
	"os"

	"github.com/juanfont/headscale"
	"github.com/spf13/cobra"
	"tailscale.com/types/wgkey"
)

var InitCmd = &cobra.Command{
	Use:   "init",
	Short: "Creates a basic Headscale env",
}

var InitSqliteCmd = &cobra.Command{
	Use:   "sqlite",
	Short: "Creates a headscale env using SQLite as database",
	Run: func(cmd *cobra.Command, args []string) {
		force, _ := cmd.Flags().GetBool("force")
		if !force {
			if _, err := os.Stat("config.json"); err == nil {
				fmt.Println("config.json already exists")
				return
			}
			if _, err := os.Stat("private.key"); err == nil {
				fmt.Println("private.key already exists")
				return
			}
			if _, err := os.Stat("derp.yaml"); err == nil {
				fmt.Println("derp.yaml already exists")
				return
			}
		}

		fmt.Println("Creating config.json")
		cfg := `{
		"server_url": "http://127.0.0.1:8000",
		"listen_addr": "0.0.0.0:8000",
		"private_key_path": "private.key",
		"derp_map_path": "derp.yaml",
		"ephemeral_node_inactivity_timeout": "30m",
		"db_type": "sqlite3",
		"db_path": "db.sqlite",
		"tls_letsencrypt_hostname": "",
		"tls_letsencrypt_cache_dir": ".cache",
		"tls_letsencrypt_challenge_type": "HTTP-01",
		"tls_cert_path": "",
		"tls_key_path": "",
		"acl_policy_path": ""
	}`
		err := os.WriteFile("config.json", []byte(cfg), 0644)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Generate the Wireguard private.key")
		privk, err := wgkey.NewPrivate()
		if err != nil {
			log.Fatal(err)
		}
		err = os.WriteFile("private.key", []byte(privk.String()), 0644)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Writing basic derp.yaml")
		err = os.WriteFile("derp.yaml", []byte(headscale.BaseDerp), 0644)
		if err != nil {
			log.Fatal(err)
		}
	},
}
