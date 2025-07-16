package cli

import (
	"context"
	"fmt"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
)

const (
	errPreAuthKeyMalformed = Error("key is malformed. expected 64 hex characters with `nodekey` prefix")
)

func init() {
	rootCmd.AddCommand(debugCmd)

	createNodeCmd.Flags().StringP("name", "", "", "Name")
	err := createNodeCmd.MarkFlagRequired("name")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
	createNodeCmd.Flags().StringP("user", "u", "", "User")

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
		output := GetOutputFlag(cmd)

		user, err := cmd.Flags().GetString("user")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting user: %s", err), output)
			return
		}

		name, err := cmd.Flags().GetString("name")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting node from flag: %s", err),
				output,
			)
			return
		}

		registrationID, err := cmd.Flags().GetString("key")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting key from flag: %s", err),
				output,
			)
			return
		}

		_, err = types.RegistrationIDFromString(registrationID)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Failed to parse machine key from flag: %s", err),
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

		err = WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
			request := &v1.DebugCreateNodeRequest{
				Key:    registrationID,
				Name:   name,
				User:   user,
				Routes: routes,
			}

			response, err := client.DebugCreateNode(ctx, request)
			if err != nil {
				ErrorOutput(
					err,
					"Cannot create node: "+status.Convert(err).Message(),
					output,
				)
				return err
			}

			SuccessOutput(response.GetNode(), "Node created", output)
			return nil
		})
		if err != nil {
			return
		}
	},
}
