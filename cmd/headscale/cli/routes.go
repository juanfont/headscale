package cli

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var RoutesCmd = &cobra.Command{
	Use:   "routes",
	Short: "Manage the routes of Headscale",
}

var ListRoutesCmd = &cobra.Command{
	Use:   "list NODE",
	Short: "List the routes exposed by this node",
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
		routes, err := h.GetNodeRoutes(n, args[0])
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(routes)
	},
}

var EnableRouteCmd = &cobra.Command{
	Use:   "enable node-name route",
	Short: "Allows exposing a route declared by this node to the rest of the nodes",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
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
		err = h.EnableNodeRoute(n, args[0], args[1])
		if err != nil {
			fmt.Println(err)
			return
		}
	},
}
