package cli

import (
	"fmt"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
)

func init() {
	rootCmd.AddCommand(debugCmd)

	createNodeCmd.Flags().StringP("name", "", "", "Name")
	err := createNodeCmd.MarkFlagRequired("name")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
	createNodeCmd.Flags().StringP("namespace", "n", "", "Namespace")
	err = createNodeCmd.MarkFlagRequired("namespace")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
	createNodeCmd.Flags().StringP("key", "k", "", "Key")
	err = createNodeCmd.MarkFlagRequired("key")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
	createNodeCmd.Flags().
		StringSliceP("route", "r", []string{}, "List (or repeated flags) of routes to advertise")

	debugCmd.AddCommand(createNodeCmd)
}

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "debug and testing commands",
	Long:  "debug contains extra commands used for debugging and testing headscale",
}

var createNodeCmd = &cobra.Command{
	Use:   "create-node",
	Short: "Create a node (machine) that can be registered with `nodes register <>` command",
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		namespace, err := cmd.Flags().GetString("namespace")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting namespace: %s", err), output)

			return
		}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		name, err := cmd.Flags().GetString("name")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting node from flag: %s", err),
				output,
			)

			return
		}

		machineKey, err := cmd.Flags().GetString("key")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting key from flag: %s", err),
				output,
			)

			return
		}

		routes, err := cmd.Flags().GetStringSlice("route")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting routes from flag: %s", err),
				output,
			)

			return
		}

		request := &v1.DebugCreateMachineRequest{
			Key:       machineKey,
			Name:      name,
			Namespace: namespace,
			Routes:    routes,
		}

		response, err := client.DebugCreateMachine(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot create machine: %s", status.Convert(err).Message()),
				output,
			)

			return
		}

		SuccessOutput(response.Machine, "Machine created", output)
	},
}
