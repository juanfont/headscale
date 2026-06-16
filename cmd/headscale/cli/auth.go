package cli

import (
	"context"
	"fmt"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
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
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		user, _ := cmd.Flags().GetString("user")
		authID, _ := cmd.Flags().GetString("auth-id")

		request := &v1.AuthRegisterRequest{
			AuthId: authID,
			User:   user,
		}

		response, err := client.AuthRegister(ctx, request)
		if err != nil {
			return fmt.Errorf("registering node: %w", err)
		}

		return printOutput(
			cmd,
			response.GetNode(),
			fmt.Sprintf("Node %s registered", response.GetNode().GetGivenName()),
		)
	}),
}

// authDecisionRunE builds a RunE for an auth decision command (approve or
// reject) that reads the auth-id flag, invokes the given gRPC call, and prints
// the response. errVerb is used in the error message; okMsg is printed on
// success.
func authDecisionRunE[Resp any](
	errVerb, okMsg string,
	call func(ctx context.Context, client v1.HeadscaleServiceClient, authID string) (Resp, error),
) func(*cobra.Command, []string) error {
	return grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		authID, _ := cmd.Flags().GetString("auth-id")

		response, err := call(ctx, client, authID)
		if err != nil {
			return fmt.Errorf("%s auth request: %w", errVerb, err)
		}

		return printOutput(cmd, response, okMsg)
	})
}

var authApproveCmd = &cobra.Command{
	Use:   "approve",
	Short: "Approve a pending authentication request",
	RunE: authDecisionRunE("approving", "Auth request approved",
		func(ctx context.Context, client v1.HeadscaleServiceClient, authID string) (*v1.AuthApproveResponse, error) {
			return client.AuthApprove(ctx, &v1.AuthApproveRequest{AuthId: authID})
		}),
}

var authRejectCmd = &cobra.Command{
	Use:   "reject",
	Short: "Reject a pending authentication request",
	RunE: authDecisionRunE("rejecting", "Auth request rejected",
		func(ctx context.Context, client v1.HeadscaleServiceClient, authID string) (*v1.AuthRejectResponse, error) {
			return client.AuthReject(ctx, &v1.AuthRejectRequest{AuthId: authID})
		}),
}
