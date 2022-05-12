package cli

import (
	"fmt"
	
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(aclsCmd)
	aclsCmd.AddCommand(listAclsCmd)

}

var aclsCmd = &cobra.Command{
	Use:     "acls",
	Short:   "Manage Access Control Lists (ACLs)",
	Aliases: []string{"access-lists","acl"},
}

var listAclsCmd = &cobra.Command{
	Use:     "list",
	Short:   "List ACLs",
	Aliases: []string{"ls","show"},
	Run:      func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		if output == `` {
			output = `json`
		}
		h, err := getHeadscaleApp()
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting headscale app: %s", err),
				output,
			)

			return
		}
		policy := h.GetACLPolicy()
		if policy == nil {
			SuccessOutput(
				``,
				`No policy defined.`,
				``,
			)

			return 
		} 

		SuccessOutput(
			policy,
			``,
			output,
		)

		return
	},

}