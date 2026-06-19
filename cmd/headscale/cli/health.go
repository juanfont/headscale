package cli

import (
	"context"
	"fmt"
	"net/http"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(healthCmd)
}

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check the health of the Headscale server",
	Long:  "Check the health of the Headscale server. This command will return an exit code of 0 if the server is healthy, or 1 if it is not.",
	RunE: clientRunE(func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
		resp, err := client.HealthWithResponse(ctx)
		if err != nil {
			return fmt.Errorf("checking health: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		return printOutput(cmd, resp.JSON200, "")
	}),
}
