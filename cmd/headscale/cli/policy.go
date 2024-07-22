package cli

import (
	"io"
	"os"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(policyCmd)
	policyCmd.AddCommand(getPolicy)

	setPolicy.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")
	if err := setPolicy.MarkFlagRequired("file"); err != nil {
		log.Fatal().Err(err).Msg("")
	}
	policyCmd.AddCommand(setPolicy)
}

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage the Headscale ACL Policy",
}

var getPolicy = &cobra.Command{
	Use:     "get",
	Short:   "Print the current ACL Policy",
	Aliases: []string{"show", "view", "fetch"},
	Run: func(cmd *cobra.Command, args []string) {
		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		request := &v1.GetPolicyRequest{}

		response, err := client.GetPolicy(ctx, request)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get the policy")

			return
		}

		// TODO(pallabpain): Maybe print this better?
		SuccessOutput("", response.GetPolicy(), "hujson")
	},
}

var setPolicy = &cobra.Command{
	Use:   "set",
	Short: "Updates the ACL Policy",
	Long: `
	Updates the existing ACL Policy with the provided policy. The policy must be a valid HuJSON object.
	This command only works when the acl.policy_mode is set to "db", and the policy will be stored in the database.`,
	Aliases: []string{"put", "update"},
	Run: func(cmd *cobra.Command, args []string) {
		policyPath, _ := cmd.Flags().GetString("file")

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

		request := &v1.SetPolicyRequest{Policy: string(policyBytes)}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		if _, err := client.SetPolicy(ctx, request); err != nil {
			log.Fatal().Err(err).Msg("Failed to set ACL Policy")

			return
		}

		SuccessOutput(nil, "Policy updated.", "")
	},
}
