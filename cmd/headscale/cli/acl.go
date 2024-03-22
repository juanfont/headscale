package cli

import (
	"io"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/types"
)

func init() {
	rootCmd.AddCommand(aclCmd)
	aclCmd.AddCommand(getACL)

	setACL.Flags().StringP("policy", "p", "", "Path to a policy file in JSON format")
	if err := setACL.MarkFlagRequired("policy"); err != nil {
		log.Fatal().Err(err).Msg("")
	}
	aclCmd.AddCommand(setACL)
}

var aclCmd = &cobra.Command{
	Use:   "acl",
	Short: "Manage the Headscale ACL Policy",
}

var getACL = &cobra.Command{
	Use:     "get",
	Short:   "Print the current ACL Policy JSON",
	Aliases: []string{"show", "view", "fetch"},
	Run: func(cmd *cobra.Command, args []string) {
		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		request := &v1.GetACLRequest{}

		response, err := client.GetACL(ctx, request)
		if err != nil {
			log.Fatal().Err(err).Msg("Cannot get ACL Policy")

			return
		}

		SuccessOutput(response.GetPolicy(), "", "json")
	},
}

var setACL = &cobra.Command{
	Use:   "set",
	Short: "Updates the ACL Policy",
	Long: `
	Updates the existing ACL Policy with the provided policy. The policy must be a valid JSON object.
	This command only works when the acl.policy_mode is set to "db", and the policy will be stored in the database.`,
	Aliases: []string{"put", "update"},
	Run: func(cmd *cobra.Command, args []string) {
		policyPath, _ := cmd.Flags().GetString("policy")

		f, err := os.Open(policyPath)
		if err != nil {
			log.Fatal().Err(err).Msg("Error opening the policy file")

			return
		}
		defer f.Close()

		policyBytes, err := io.ReadAll(f)
		if err != nil {
			log.Fatal().Err(err).Msg("Error reading the policy file")

			return
		}

		acl := types.ACL{Policy: policyBytes}

		request := &v1.SetACLRequest{Policy: acl.Proto().GetPolicy()}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		if _, err := client.SetACL(ctx, request); err != nil {
			log.Fatal().Err(err).Msg("Failed to set ACL Policy")

			return
		}

		SuccessOutput(nil, "ACL Policy updated.", "")
	},
}
