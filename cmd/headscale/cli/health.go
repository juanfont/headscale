package cli

import (
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
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
		defer cancel()
		defer conn.Close()

		response, err := client.Health(ctx, &v1.HealthRequest{})
		if err != nil {
			ErrorOutput(err, "Error checking health", output)
		}

		if response.Status == v1.HealthStatus_Pass {
			SuccessOutput("Headscale server is healthy", "", output)
		}

		ErrorOutput(
			fmt.Errorf("server health check failed: %s", response.Status),
			"Headscale server is unhealthy",
			output,
		)
	},
}
