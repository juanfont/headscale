package cli

import (
	"fmt"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
)

func init() {
	rootCmd.AddCommand(pingCmd)

	pingCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	err := pingCmd.MarkFlagRequired("identifier")
	if err != nil {
		panic(err)
	}

	pingCmd.Flags().StringP("target", "t", "", "Target IP address to ping (optional, uses node's primary IP if not specified)")
}

var pingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Ping a node to check if it's online and responsive",
	Long: `Send a ping request to a node to verify it's online and measure connectivity.

The ping command sends a health check ping to the specified node. If no target IP
is specified, the node will ping itself using its primary IP address. You can also
specify a target IP to test connectivity to another node or address.

Examples:
  # Ping a node using its identifier
  headscale ping --identifier 123

  # Ping a node with a specific target IP
  headscale ping --identifier 123 --target 100.64.0.5
`,
	Aliases: []string{"p"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		identifier, err := cmd.Flags().GetUint64("identifier")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting node identifier: %s", err),
				output,
			)
			return
		}

		targetIP, err := cmd.Flags().GetString("target")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting target IP: %s", err),
				output,
			)
			return
		}

		ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
		defer cancel()
		defer conn.Close()

		request := &v1.PingNodeRequest{
			NodeId:   identifier,
			TargetIp: targetIP,
		}

		response, err := client.PingNode(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf(
					"Cannot ping node: %s",
					status.Convert(err).Message(),
				),
				output,
			)
			return
		}

		if !response.GetSuccess() {
			ErrorOutput(
				fmt.Errorf("ping failed: %s", response.GetError()),
				fmt.Sprintf("Ping failed: %s", response.GetError()),
				output,
			)
			return
		}

		// Build success message with details
		message := fmt.Sprintf("Ping successful to node %d", identifier)
		if response.GetNodeIp() != "" {
			message += fmt.Sprintf(" (IP: %s)", response.GetNodeIp())
		}
		if response.GetPingType() != "" {
			message += fmt.Sprintf(" using %s", response.GetPingType())
		}
		if response.GetIsLocal() {
			message += " [direct connection]"
		} else if response.GetDerpRegionId() > 0 {
			message += fmt.Sprintf(" [via DERP region %d]", response.GetDerpRegionId())
		}
		if response.GetEndpoint() != "" {
			message += fmt.Sprintf(" from endpoint %s", response.GetEndpoint())
		}
		if response.GetLatencyMs() > 0 {
			message += fmt.Sprintf(", latency: %dms", response.GetLatencyMs())
		}

		SuccessOutput(response, message, output)
	},
}
