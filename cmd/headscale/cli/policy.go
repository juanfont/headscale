package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"tailscale.com/types/views"
)

func init() {
	rootCmd.AddCommand(policyCmd)
	policyCmd.AddCommand(getPolicy)

	setPolicy.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")
	if err := setPolicy.MarkFlagRequired("file"); err != nil {
		log.Fatal().Err(err).Msg("")
	}
	policyCmd.AddCommand(setPolicy)

	checkPolicy.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")
	if err := checkPolicy.MarkFlagRequired("file"); err != nil {
		log.Fatal().Err(err).Msg("")
	}
	policyCmd.AddCommand(checkPolicy)
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
		output, _ := cmd.Flags().GetString("output")
		
		err := WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
			request := &v1.GetPolicyRequest{}

			response, err := client.GetPolicy(ctx, request)
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Failed loading ACL Policy: %s", err), output)
				return err
			}

			// TODO(pallabpain): Maybe print this better?
			// This does not pass output as we dont support yaml, json or json-line
			// output for this command. It is HuJSON already.
			SuccessOutput("", response.GetPolicy(), "")
			return nil
		})
		
		if err != nil {
			return
		}
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
		output, _ := cmd.Flags().GetString("output")
		policyPath, _ := cmd.Flags().GetString("file")

		f, err := os.Open(policyPath)
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error opening the policy file: %s", err), output)
			return
		}
		defer f.Close()

		policyBytes, err := io.ReadAll(f)
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error reading the policy file: %s", err), output)
			return
		}

		request := &v1.SetPolicyRequest{Policy: string(policyBytes)}

		err = WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
			if _, err := client.SetPolicy(ctx, request); err != nil {
				ErrorOutput(err, fmt.Sprintf("Failed to set ACL Policy: %s", err), output)
				return err
			}

			SuccessOutput(nil, "Policy updated.", "")
			return nil
		})
		
		if err != nil {
			return
		}
	},
}

var checkPolicy = &cobra.Command{
	Use:   "check",
	Short: "Check the Policy file for errors",
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		policyPath, _ := cmd.Flags().GetString("file")

		f, err := os.Open(policyPath)
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error opening the policy file: %s", err), output)
		}
		defer f.Close()

		policyBytes, err := io.ReadAll(f)
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error reading the policy file: %s", err), output)
		}

		_, err = policy.NewPolicyManager(policyBytes, nil, views.Slice[types.NodeView]{})
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error parsing the policy file: %s", err), output)
		}

		SuccessOutput(nil, "Policy is valid", "")
	},
}
