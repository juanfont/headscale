package cli

import (
	"context"
	"fmt"
	"net/http"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(authCmd)

	authRegisterCmd.Flags().StringP("user", "u", "", "User")
	authRegisterCmd.Flags().String("auth-id", "", "Auth ID")
	mustMarkRequired(authRegisterCmd, "user", "auth-id")
	authCmd.AddCommand(authRegisterCmd)

	authApproveCmd.Flags().String("auth-id", "", "Auth ID")
	mustMarkRequired(authApproveCmd, "auth-id")
	authCmd.AddCommand(authApproveCmd)

	authRejectCmd.Flags().String("auth-id", "", "Auth ID")
	mustMarkRequired(authRejectCmd, "auth-id")
	authCmd.AddCommand(authRejectCmd)
}

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage node authentication and approval",
}

var authRegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a node to your network",
	RunE: clientRunE(func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
		user, _ := cmd.Flags().GetString("user")
		authID, _ := cmd.Flags().GetString("auth-id")

		resp, err := client.AuthRegisterWithResponse(ctx, clientv1.AuthRegisterJSONRequestBody{
			AuthId: &authID,
			User:   &user,
		})
		if err != nil {
			return fmt.Errorf("registering node: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		node := resp.JSON200.Node

		return printOutput(
			cmd,
			node,
			fmt.Sprintf("Node %s registered", node.GivenName),
		)
	}),
}

var authApproveCmd = &cobra.Command{
	Use:   "approve",
	Short: "Approve a pending authentication request",
	RunE: clientRunE(func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
		authID, _ := cmd.Flags().GetString("auth-id")

		resp, err := client.AuthApproveWithResponse(ctx, clientv1.AuthApproveJSONRequestBody{AuthId: &authID})
		if err != nil {
			return fmt.Errorf("approving auth request: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		return printOutput(cmd, resp.JSON200, "Auth request approved")
	}),
}

var authRejectCmd = &cobra.Command{
	Use:   "reject",
	Short: "Reject a pending authentication request",
	RunE: clientRunE(func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
		authID, _ := cmd.Flags().GetString("auth-id")

		resp, err := client.AuthRejectWithResponse(ctx, clientv1.AuthRejectJSONRequestBody{AuthId: &authID})
		if err != nil {
			return fmt.Errorf("rejecting auth request: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		return printOutput(cmd, resp.JSON200, "Auth request rejected")
	}),
}
