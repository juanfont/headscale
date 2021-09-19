package cli

import (
	"fmt"
	"log"
	"strings"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(routesCmd)
	routesCmd.PersistentFlags().StringP("namespace", "n", "", "Namespace")
	err := routesCmd.MarkPersistentFlagRequired("namespace")
	if err != nil {
		log.Fatalf(err.Error())
	}

	enableRouteCmd.Flags().BoolP("all", "a", false, "Enable all routes advertised by the node")

	routesCmd.AddCommand(listRoutesCmd)
	routesCmd.AddCommand(enableRouteCmd)
}

var routesCmd = &cobra.Command{
	Use:   "routes",
	Short: "Manage the routes of Headscale",
}

var listRoutesCmd = &cobra.Command{
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
		o, _ := cmd.Flags().GetString("output")

		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}

		availableRoutes, err := h.GetAdvertisedNodeRoutes(n, args[0])
		if err != nil {
			fmt.Println(err)
			return
		}

		if strings.HasPrefix(o, "json") {
			// TODO: Add enable/disabled information to this interface
			JsonOutput(availableRoutes, err, o)
			return
		}

		d := h.RoutesToPtables(n, args[0], *availableRoutes)

		err = pterm.DefaultTable.WithHasHeader().WithData(d).Render()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var enableRouteCmd = &cobra.Command{
	Use:   "enable node-name route",
	Short: "Allows exposing a route declared by this node to the rest of the nodes",
	Args: func(cmd *cobra.Command, args []string) error {
		all, err := cmd.Flags().GetBool("all")
		if err != nil {
			log.Fatalf("Error getting namespace: %s", err)
		}

		if all {
			if len(args) < 1 {
				return fmt.Errorf("Missing parameters")
			}
			return nil
		} else {
			if len(args) < 2 {
				return fmt.Errorf("Missing parameters")
			}
			return nil
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		n, err := cmd.Flags().GetString("namespace")
		if err != nil {
			log.Fatalf("Error getting namespace: %s", err)
		}

		o, _ := cmd.Flags().GetString("output")

		all, err := cmd.Flags().GetBool("all")
		if err != nil {
			log.Fatalf("Error getting namespace: %s", err)
		}

		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}

		if all {
			availableRoutes, err := h.GetAdvertisedNodeRoutes(n, args[0])
			if err != nil {
				fmt.Println(err)
				return
			}

			for _, availableRoute := range *availableRoutes {
				err = h.EnableNodeRoute(n, args[0], availableRoute.String())
				if err != nil {
					fmt.Println(err)
					return
				}

				if strings.HasPrefix(o, "json") {
					JsonOutput(availableRoute, err, o)
				} else {
					fmt.Printf("Enabled route %s\n", availableRoute)
				}
			}
		} else {
			err = h.EnableNodeRoute(n, args[0], args[1])

			if strings.HasPrefix(o, "json") {
				JsonOutput(args[1], err, o)
				return
			}

			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Printf("Enabled route %s\n", args[1])
		}
	},
}
