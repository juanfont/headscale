package cli

import (
	"context"
	"fmt"
	"net/http"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
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
	RunE: clientRunE(func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
		user, _ := cmd.Flags().GetString("user")
		name, _ := cmd.Flags().GetString("name")
		registrationID, _ := cmd.Flags().GetString("key")

		_, err := types.AuthIDFromString(registrationID)
		if err != nil {
			return fmt.Errorf("parsing machine key: %w", err)
		}

		routes, _ := cmd.Flags().GetStringSlice("route")

		resp, err := client.DebugCreateNodeWithResponse(ctx, clientv1.DebugCreateNodeJSONRequestBody{
			Key:    &registrationID,
			Name:   &name,
			User:   &user,
			Routes: &routes,
		})
		if err != nil {
			return fmt.Errorf("creating node: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		return printOutput(cmd, resp.JSON200.Node, "Node created")
	}),
}
