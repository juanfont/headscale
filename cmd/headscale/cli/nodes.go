package cli

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var RegisterCmd = &cobra.Command{
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

var NodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Manage the nodes of Headscale",
}
