package cli

import (
	"context"
	"fmt"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(healthCmd)
}

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check the health of the Headscale server",
	Long:  "Check the health of the Headscale server. This command will return an exit code of 0 if the server is healthy, or 1 if it is not.",
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		response, err := client.Health(ctx, &v1.HealthRequest{})
		if err != nil {
			return fmt.Errorf("checking health: %w", err)
		}

		return printOutput(cmd, response, "")
	}),
}
