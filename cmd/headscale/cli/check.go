package cli

import (
	"fmt"
	"os"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(checkCmd)

	checkPolicyCmd.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")
	mustMarkRequired(checkPolicyCmd, "file")
	checkCmd.AddCommand(checkPolicyCmd)
}

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check configuration or policy files",
}

var checkPolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Check a policy file for errors",
	Long: `
	Check the policy file for errors and run its "tests" and "sshTests".

	The tests run against one node for each user and tag the policy names,
	not against your tailnet, so "headscale policy set" can still disagree
	with them.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		policyPath, _ := cmd.Flags().GetString("file")

		policyBytes, err := os.ReadFile(policyPath)
		if err != nil {
			return fmt.Errorf("reading policy file: %w", err)
		}

		err = policyv2.CheckPolicy(policyBytes)
		if err != nil {
			return err
		}

		fmt.Fprintln(cmd.OutOrStdout(), "Policy is valid")

		return nil
	},
}
