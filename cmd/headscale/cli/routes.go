package cli

import (
	"fmt"
	"log"
	"net/netip"
	"strconv"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
)

const (
	Base10 = 10
)

func init() {
	rootCmd.AddCommand(routesCmd)
	listRoutesCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	routesCmd.AddCommand(listRoutesCmd)

	enableRouteCmd.Flags().Uint64P("route", "r", 0, "Route identifier (ID)")
	err := enableRouteCmd.MarkFlagRequired("route")
	if err != nil {
		log.Fatalf(err.Error())
	}
	routesCmd.AddCommand(enableRouteCmd)

	disableRouteCmd.Flags().Uint64P("route", "r", 0, "Route identifier (ID)")
	err = disableRouteCmd.MarkFlagRequired("route")
	if err != nil {
		log.Fatalf(err.Error())
	}
	routesCmd.AddCommand(disableRouteCmd)

	deleteRouteCmd.Flags().Uint64P("route", "r", 0, "Route identifier (ID)")
	err = deleteRouteCmd.MarkFlagRequired("route")
	if err != nil {
		log.Fatalf(err.Error())
	}
	routesCmd.AddCommand(deleteRouteCmd)
}

var routesCmd = &cobra.Command{
	Use:     "routes",
	Short:   "Manage the routes of Headscale",
	Aliases: []string{"r", "route"},
}

var listRoutesCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all routes",
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

		var routes []*v1.Route

		if machineID == 0 {
			response, err := client.GetRoutes(ctx, &v1.GetRoutesRequest{})
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

			routes = response.Routes
		} else {
			response, err := client.GetMachineRoutes(ctx, &v1.GetMachineRoutesRequest{
				MachineId: machineID,
			})
			if err != nil {
				ErrorOutput(
					err,
					fmt.Sprintf("Cannot get routes for machine %d: %s", machineID, status.Convert(err).Message()),
					output,
				)

				return
			}

			if output != "" {
				SuccessOutput(response.Routes, "", output)

				return
			}

			routes = response.Routes
		}

		tableData := routesToPtables(routes)
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
	Short: "Set a route as enabled",
	Long:  `This command will make as enabled a given route.`,
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		routeID, err := cmd.Flags().GetUint64("route")
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

		response, err := client.EnableRoute(ctx, &v1.EnableRouteRequest{
			RouteId: routeID,
		})
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot enable route %d: %s", routeID, status.Convert(err).Message()),
				output,
			)

			return
		}

		if output != "" {
			SuccessOutput(response, "", output)

			return
		}
	},
}

var disableRouteCmd = &cobra.Command{
	Use:   "disable",
	Short: "Set as disabled a given route",
	Long:  `This command will make as disabled a given route.`,
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		routeID, err := cmd.Flags().GetUint64("route")
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

		response, err := client.DisableRoute(ctx, &v1.DisableRouteRequest{
			RouteId: routeID,
		})
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot disable route %d: %s", routeID, status.Convert(err).Message()),
				output,
			)

			return
		}

		if output != "" {
			SuccessOutput(response, "", output)

			return
		}
	},
}

var deleteRouteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a given route",
	Long:  `This command will delete a given route.`,
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		routeID, err := cmd.Flags().GetUint64("route")
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

		response, err := client.DeleteRoute(ctx, &v1.DeleteRouteRequest{
			RouteId: routeID,
		})
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot delete route %d: %s", routeID, status.Convert(err).Message()),
				output,
			)

			return
		}

		if output != "" {
			SuccessOutput(response, "", output)

			return
		}
	},
}

// routesToPtables converts the list of routes to a nice table.
func routesToPtables(routes []*v1.Route) pterm.TableData {
	tableData := pterm.TableData{{"ID", "Machine", "Prefix", "Advertised", "Enabled", "Primary"}}

	for _, route := range routes {
		var isPrimaryStr string
		prefix, err := netip.ParsePrefix(route.Prefix)
		if err != nil {
			log.Printf("Error parsing prefix %s: %s", route.Prefix, err)

			continue
		}
		if prefix == hscontrol.ExitRouteV4 || prefix == hscontrol.ExitRouteV6 {
			isPrimaryStr = "-"
		} else {
			isPrimaryStr = strconv.FormatBool(route.IsPrimary)
		}

		tableData = append(tableData,
			[]string{
				strconv.FormatUint(route.Id, Base10),
				route.Machine.GivenName,
				route.Prefix,
				strconv.FormatBool(route.Advertised),
				strconv.FormatBool(route.Enabled),
				isPrimaryStr,
			})
	}

	return tableData
}
