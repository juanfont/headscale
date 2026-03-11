package cli

import (
	"context"
	"fmt"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(debugCmd)

	createNodeCmd.Flags().StringP("name", "", "", "Name")
	createNodeCmd.Flags().StringP("user", "u", "", "User")
	createNodeCmd.Flags().StringP("key", "k", "", "Key")
	mustMarkRequired(createNodeCmd, "name", "user", "key")

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
	Short: "Create a node that can be registered with `auth register <>` command",
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		user, _ := cmd.Flags().GetString("user")
		name, _ := cmd.Flags().GetString("name")
		registrationID, _ := cmd.Flags().GetString("key")

		_, err := types.AuthIDFromString(registrationID)
		if err != nil {
			return fmt.Errorf("parsing machine key: %w", err)
		}

		routes, _ := cmd.Flags().GetStringSlice("route")

		request := &v1.DebugCreateNodeRequest{
			Key:    registrationID,
			Name:   name,
			User:   user,
			Routes: routes,
		}

		response, err := client.DebugCreateNode(ctx, request)
		if err != nil {
			return fmt.Errorf("creating node: %w", err)
		}

		return printOutput(cmd, response.GetNode(), "Node created")
	}),
}
