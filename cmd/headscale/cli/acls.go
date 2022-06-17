package cli

import (
	"fmt"

	// "github.com/juanfont/headscale".
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(aclsCmd)
	aclsCmd.AddCommand(listAclsCmd)
}

var aclsCmd = &cobra.Command{
	Use:     "acls",
	Short:   "Manage Access Control Lists (ACLs)",
	Aliases: []string{"access-lists", "acl"},
}

var listAclsCmd = &cobra.Command{
	Use:     "list",
	Short:   "List ACLs",
	Aliases: []string{"ls", "show"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		if output == `` {
			output = `json`
		}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		request := &v1.ListACLPolicyRequest{}

		response, err := client.ListACLPolicy(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting headscale app: %s", err),
				output,
			)

			return
		}

		if response == nil {
			SuccessOutput(
				``,
				`No policy defined.`,
				``,
			)

			return
		}

		SuccessOutput(
			response,
			``,
			output,
		)

		return
	},
}
