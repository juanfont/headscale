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
			fmt.Sprintf("Node %s registered", response.GetNode().GetGivenName()))
	}),
}

var authApproveCmd = &cobra.Command{
	Use:   "approve",
	Short: "Approve a pending authentication request",
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		authID, _ := cmd.Flags().GetString("auth-id")

		request := &v1.AuthApproveRequest{
			AuthId: authID,
		}

		response, err := client.AuthApprove(ctx, request)
		if err != nil {
			return fmt.Errorf("approving auth request: %w", err)
		}

		return printOutput(cmd, response, "Auth request approved")
	}),
}

var authRejectCmd = &cobra.Command{
	Use:   "reject",
	Short: "Reject a pending authentication request",
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		authID, _ := cmd.Flags().GetString("auth-id")

		request := &v1.AuthRejectRequest{
			AuthId: authID,
		}

		response, err := client.AuthReject(ctx, request)
		if err != nil {
			return fmt.Errorf("rejecting auth request: %w", err)
		}

		return printOutput(cmd, response, "Auth request rejected")
	}),
}
