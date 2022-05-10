package cli

import (
	"fmt"
	"log"
	"strconv"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
)

func init() {
	rootCmd.AddCommand(routesCmd)

	listRoutesCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	err := listRoutesCmd.MarkFlagRequired("identifier")
	if err != nil {
		log.Fatalf(err.Error())
	}
	routesCmd.AddCommand(listRoutesCmd)

	enableRouteCmd.Flags().
		StringSliceP("route", "r", []string{}, "List (or repeated flags) of routes to enable")
	enableRouteCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	enableRouteCmd.Flags().BoolP("all", "a", false, "All routes from host")

	err = enableRouteCmd.MarkFlagRequired("identifier")
	if err != nil {
		log.Fatalf(err.Error())
	}

	routesCmd.AddCommand(enableRouteCmd)

	nodeCmd.AddCommand(routesCmd)
}

var routesCmd = &cobra.Command{
	Use:     "routes",
	Short:   "Manage the routes of Headscale",
	Aliases: []string{"r", "route"},
}

var listRoutesCmd = &cobra.Command{
	Use:     "list",
	Short:   "List routes advertised and enabled by a given node",
	Aliases: []string{"ls", "show"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		machineID, err := cmd.Flags().GetUint64("identifier")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting machine id from flag: %s", err),
				output,
			)

			return
		}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		request := &v1.GetMachineRouteRequest{
			MachineId: machineID,
		}

		response, err := client.GetMachineRoute(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot get nodes: %s", status.Convert(err).Message()),
				output,
			)

			return
		}

		if output != "" {
			SuccessOutput(response.Routes, "", output)

			return
		}

		tableData := routesToPtables(response.Routes)
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error converting to table: %s", err), output)

			return
		}

		err = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Failed to render pterm table: %s", err),
				output,
			)

			return
		}
	},
}

var enableRouteCmd = &cobra.Command{
	Use:   "enable",
	Short: "Set the enabled routes for a given node",
	Long: `This command will take a list of routes that will _replace_ 
the current set of routes on a given node.
If you would like to disable a route, simply run the command again, but 
omit the route you do not want to enable.
	`,
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		machineID, err := cmd.Flags().GetUint64("identifier")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting machine id from flag: %s", err),
				output,
			)

			return
		}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		var routes []string

		isAll, _ := cmd.Flags().GetBool("all")
		if isAll {
			response, err := client.GetMachineRoute(ctx, &v1.GetMachineRouteRequest{
				MachineId: machineID,
			})
			if err != nil {
				ErrorOutput(
					err,
					fmt.Sprintf(
						"Cannot get machine routes: %s\n",
						status.Convert(err).Message(),
					),
					output,
				)

				return
			}
			routes = response.GetRoutes().GetAdvertisedRoutes()
		} else {
			routes, err = cmd.Flags().GetStringSlice("route")
			if err != nil {
				ErrorOutput(
					err,
					fmt.Sprintf("Error getting routes from flag: %s", err),
					output,
				)

				return
			}
		}

		request := &v1.EnableMachineRoutesRequest{
			MachineId: machineID,
			Routes:    routes,
		}

		response, err := client.EnableMachineRoutes(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf(
					"Cannot register machine: %s\n",
					status.Convert(err).Message(),
				),
				output,
			)

			return
		}

		if output != "" {
			SuccessOutput(response.Routes, "", output)

			return
		}

		tableData := routesToPtables(response.Routes)
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error converting to table: %s", err), output)

			return
		}

		err = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Failed to render pterm table: %s", err),
				output,
			)

			return
		}
	},
}

// routesToPtables converts the list of routes to a nice table.
func routesToPtables(routes *v1.Routes) pterm.TableData {
	tableData := pterm.TableData{{"Route", "Enabled"}}

	for _, route := range routes.GetAdvertisedRoutes() {
		enabled := isStringInSlice(routes.EnabledRoutes, route)

		tableData = append(tableData, []string{route, strconv.FormatBool(enabled)})
	}

	return tableData
}

func isStringInSlice(strs []string, s string) bool {
	for _, s2 := range strs {
		if s == s2 {
			return true
		}
	}

	return false
}
