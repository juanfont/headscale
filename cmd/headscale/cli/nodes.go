package cli

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var RegisterCmd = &cobra.Command{
	Use:   "register machineID",
	Short: "Registers a machine to your network",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("Missing parameters")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		n, err := cmd.Flags().GetString("namespace")
		if err != nil {
			log.Fatalf("Error getting namespace: %s", err)
		}

		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}
		err = h.RegisterMachine(args[0], n)
		if err != nil {
			fmt.Printf("Error: %s", err)
			return
		}
		fmt.Println("Ook.")
	},
}

var NodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Manage the nodes of Headscale",
}
