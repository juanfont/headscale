package cli

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var ListRoutesCmd = &cobra.Command{
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
		routes, err := h.GetNodeRoutes(args[0], args[1])
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(routes)
	},
}

var EnableRouteCmd = &cobra.Command{
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
