package main

import (
	"fmt"
	"log"
	"os"

	"github.com/juanfont/headscale/cmd/headscale/cli"
	"github.com/spf13/cobra"
)

var headscaleCmd = &cobra.Command{
	Use:   "headscale",
	Short: "headscale - a Tailscale control server",
	Long: `
headscale is an open source implementation of the Tailscale control server

Juan Font Alonso <juanfontalonso@gmail.com> - 2021
https://gitlab.com/juanfont/headscale`,
}

func main() {
	err := cli.LoadConfig("")
	if err != nil {
		log.Fatalf(err.Error())
	}

	headscaleCmd.AddCommand(cli.NamespaceCmd)
	headscaleCmd.AddCommand(cli.NodeCmd)
	headscaleCmd.AddCommand(cli.PreauthkeysCmd)
	headscaleCmd.AddCommand(cli.RoutesCmd)
	headscaleCmd.AddCommand(cli.ServeCmd)
	headscaleCmd.AddCommand(cli.VersionCmd)

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

	cli.RoutesCmd.PersistentFlags().StringP("namespace", "n", "", "Namespace")
	err = cli.RoutesCmd.MarkPersistentFlagRequired("namespace")
	if err != nil {
		log.Fatalf(err.Error())
	}

	cli.NamespaceCmd.AddCommand(cli.CreateNamespaceCmd)
	cli.NamespaceCmd.AddCommand(cli.ListNamespacesCmd)
	cli.NamespaceCmd.AddCommand(cli.DestroyNamespaceCmd)

	cli.NodeCmd.AddCommand(cli.ListNodesCmd)
	cli.NodeCmd.AddCommand(cli.RegisterCmd)
	cli.NodeCmd.AddCommand(cli.DeleteCmd)

	cli.RoutesCmd.AddCommand(cli.ListRoutesCmd)
	cli.RoutesCmd.AddCommand(cli.EnableRouteCmd)

	cli.PreauthkeysCmd.AddCommand(cli.ListPreAuthKeys)
	cli.PreauthkeysCmd.AddCommand(cli.CreatePreAuthKeyCmd)

	cli.CreatePreAuthKeyCmd.PersistentFlags().Bool("reusable", false, "Make the preauthkey reusable")
	cli.CreatePreAuthKeyCmd.PersistentFlags().Bool("ephemeral", false, "Preauthkey for ephemeral nodes")
	cli.CreatePreAuthKeyCmd.Flags().StringP("expiration", "e", "", "Human-readable expiration of the key (30m, 24h, 365d...)")

	headscaleCmd.PersistentFlags().StringP("output", "o", "", "Output format. Empty for human-readable, 'json' or 'json-line'")

	if err := headscaleCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
