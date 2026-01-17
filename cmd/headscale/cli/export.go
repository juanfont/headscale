package cli

import (
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
)

func init() {
	rootCmd.AddCommand(exportCmd)
}

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export all configuration data (nodes, users, preauth keys, api keys)",
	Long: `Export all configuration data from Headscale in JSON or YAML format.
This is useful for backup, migration, or auditing purposes.

The export includes:
- All users
- All nodes
- All preauth keys
- All API keys`,
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
		defer cancel()
		defer conn.Close()

		// Export all data
		exportData := make(map[string]interface{})

		// 1. Export users
		usersResp, err := client.ListUsers(ctx, &v1.ListUsersRequest{})
		if err != nil {
			ErrorOutput(
				err,
				"Cannot get users: "+status.Convert(err).Message(),
				output,
			)
			return
		}
		exportData["users"] = usersResp.GetUsers()

		// 2. Export nodes
		nodesResp, err := client.ListNodes(ctx, &v1.ListNodesRequest{})
		if err != nil {
			ErrorOutput(
				err,
				"Cannot get nodes: "+status.Convert(err).Message(),
				output,
			)
			return
		}
		exportData["nodes"] = nodesResp.GetNodes()

		// 3. Export API keys
		apiKeysResp, err := client.ListApiKeys(ctx, &v1.ListApiKeysRequest{})
		if err != nil {
			ErrorOutput(
				err,
				"Cannot get API keys: "+status.Convert(err).Message(),
				output,
			)
			return
		}
		exportData["api_keys"] = apiKeysResp.GetApiKeys()

		// 4. Export preauth keys
		preAuthKeysResp, err := client.ListPreAuthKeys(ctx, &v1.ListPreAuthKeysRequest{})
		if err != nil {
			ErrorOutput(
				err,
				"Cannot get preauth keys: "+status.Convert(err).Message(),
				output,
			)
			return
		}
		exportData["preauth_keys"] = preAuthKeysResp.GetPreAuthKeys()

		// Output the export using standard CLI output mechanism
		// The --output flag (json, yaml, json-line) controls the format
		SuccessOutput(exportData, "Export completed successfully", output)
	},
}
