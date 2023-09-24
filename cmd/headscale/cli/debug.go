package cli

import (
	"fmt"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
)

const (
	errPreAuthKeyMalformed = Error("key is malformed. expected 64 hex characters with `nodekey` prefix")
)

// Error is used to compare errors as per https://dave.cheney.net/2016/04/07/constant-errors
type Error string

func (e Error) Error() string { return string(e) }

func init() {
	rootCmd.AddCommand(debugCmd)

	createNodeCmd.Flags().StringP("name", "", "", "Name")
	err := createNodeCmd.MarkFlagRequired("name")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
	createNodeCmd.Flags().StringP("user", "u", "", "User")

	createNodeCmd.Flags().StringP("namespace", "n", "", "User")
	createNodeNamespaceFlag := createNodeCmd.Flags().Lookup("namespace")
	createNodeNamespaceFlag.Deprecated = deprecateNamespaceMessage
	createNodeNamespaceFlag.Hidden = true

	err = createNodeCmd.MarkFlagRequired("user")
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
	Short: "Create a node that can be registered with `nodes register <>` command",
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		user, err := cmd.Flags().GetString("user")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting user: %s", err), output)

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
		if !util.NodePublicKeyRegex.Match([]byte(machineKey)) {
			err = errPreAuthKeyMalformed
			ErrorOutput(
				err,
				fmt.Sprintf("Error: %s", err),
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

		request := &v1.DebugCreateNodeRequest{
			Key:    machineKey,
			Name:   name,
			User:   user,
			Routes: routes,
		}

		response, err := client.DebugCreateNode(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot create node: %s", status.Convert(err).Message()),
				output,
			)

			return
		}

		SuccessOutput(response.Node, "Node created", output)
	},
}
