package cli

import (
	"context"
	"fmt"

	apiv1 "github.com/juanfont/headscale/gen/api/v1"
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
	RunE: apiRunE(func(ctx context.Context, client *apiv1.Client, cmd *cobra.Command, args []string) error {
		user, _ := cmd.Flags().GetString("user")
		authID, _ := cmd.Flags().GetString("auth-id")

		resp, err := client.AuthRegister(ctx, &apiv1.AuthRegisterReq{
			AuthId: apiv1.NewOptString(authID),
			User:   apiv1.NewOptString(user),
		})
		if err != nil {
			return fmt.Errorf("registering node: %w", err)
		}

		return printOutput(
			cmd,
			resp.Node.Value,
			fmt.Sprintf("Node %s registered", resp.Node.Value.GivenName.Value),
		)
	}),
}

// authDecisionRunE builds a RunE for an auth decision command (approve or
// reject) that reads the auth-id flag, invokes the given API call, and prints a
// result. errVerb is used in the error message; okMsg is printed on success.
func authDecisionRunE(
	errVerb, okMsg string,
	call func(ctx context.Context, client *apiv1.Client, authID string) error,
) func(*cobra.Command, []string) error {
	return apiRunE(func(ctx context.Context, client *apiv1.Client, cmd *cobra.Command, args []string) error {
		authID, _ := cmd.Flags().GetString("auth-id")

		err := call(ctx, client, authID)
		if err != nil {
			return fmt.Errorf("%s auth request: %w", errVerb, err)
		}

		return printOutput(cmd, map[string]string{colResult: okMsg}, okMsg)
	})
}

var authApproveCmd = &cobra.Command{
	Use:   "approve",
	Short: "Approve a pending authentication request",
	RunE: authDecisionRunE("approving", "Auth request approved",
		func(ctx context.Context, client *apiv1.Client, authID string) error {
			return client.AuthApprove(ctx, &apiv1.AuthApproveReq{AuthId: apiv1.NewOptString(authID)})
		}),
}

var authRejectCmd = &cobra.Command{
	Use:   "reject",
	Short: "Reject a pending authentication request",
	RunE: authDecisionRunE("rejecting", "Auth request rejected",
		func(ctx context.Context, client *apiv1.Client, authID string) error {
			return client.AuthReject(ctx, &apiv1.AuthRejectReq{AuthId: apiv1.NewOptString(authID)})
		}),
}
