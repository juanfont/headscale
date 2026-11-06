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
	Short: "Check the Policy file for errors",
	Long: `
	Check runs every check "headscale policy set" runs, including the
	policy's "tests" and "sshTests", without a server, database or config.

	Instead of a tailnet, it builds stand-ins from the policy: a user, with
	one node, for every user the policy names, and a node for every tag it
	declares. So:

	  - every user the policy names is taken to exist;
	  - an IP address or hosts entry matches no stand-in node;
	  - no user has two nodes, and no node has two tags;
	  - "alice@" and "alice@example.com" are two different users.

	"headscale policy set" checks the policy against the live tailnet.`,
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
