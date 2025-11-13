package cli

import (
	"fmt"
	"io"
	"os"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"tailscale.com/types/views"
)

const (
	bypassFlag = "bypass-grpc-and-access-database-directly"
)

func init() {
	rootCmd.AddCommand(policyCmd)

	getPolicy.Flags().BoolP(bypassFlag, "", false, "Uses the headscale config to directly access the database, bypassing gRPC and does not require the server to be running")
	policyCmd.AddCommand(getPolicy)

	setPolicy.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")
	if err := setPolicy.MarkFlagRequired("file"); err != nil {
		log.Fatal().Err(err).Msg("")
	}
	setPolicy.Flags().BoolP(bypassFlag, "", false, "Uses the headscale config to directly access the database, bypassing gRPC and does not require the server to be running")
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
		var policy string
		if bypass, _ := cmd.Flags().GetBool(bypassFlag); bypass {
			confirm := false
			force, _ := cmd.Flags().GetBool("force")
			if !force {
				confirm = util.YesNo("DO NOT run this command if an instance of headscale is running, are you sure headscale is not running?")
			}

			if !confirm && !force {
				ErrorOutput(nil, "Aborting command", output)
				return
			}

			cfg, err := types.LoadServerConfig()
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Failed loading config: %s", err), output)
			}

			d, err := db.NewHeadscaleDatabase(
				cfg.Database,
				cfg.BaseDomain,
				nil,
			)
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Failed to open database: %s", err), output)
			}

			pol, err := d.GetPolicy()
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Failed loading Policy from database: %s", err), output)
			}

			policy = pol.Data
		} else {
			ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
			defer cancel()
			defer conn.Close()

			request := &v1.GetPolicyRequest{}

			response, err := client.GetPolicy(ctx, request)
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Failed loading ACL Policy: %s", err), output)
			}

			policy = response.GetPolicy()
		}

		// TODO(pallabpain): Maybe print this better?
		// This does not pass output as we dont support yaml, json or json-line
		// output for this command. It is HuJSON already.
		SuccessOutput("", policy, "")
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
		}
		defer f.Close()

		policyBytes, err := io.ReadAll(f)
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error reading the policy file: %s", err), output)
		}

		if bypass, _ := cmd.Flags().GetBool(bypassFlag); bypass {
			confirm := false
			force, _ := cmd.Flags().GetBool("force")
			if !force {
				confirm = util.YesNo("DO NOT run this command if an instance of headscale is running, are you sure headscale is not running?")
			}

			if !confirm && !force {
				ErrorOutput(nil, "Aborting command", output)
				return
			}

			cfg, err := types.LoadServerConfig()
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Failed loading config: %s", err), output)
			}

			d, err := db.NewHeadscaleDatabase(
				cfg.Database,
				cfg.BaseDomain,
				nil,
			)
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Failed to open database: %s", err), output)
			}

			users, err := d.ListUsers()
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Failed to load users for policy validation: %s", err), output)
			}

			_, err = policy.NewPolicyManager(policyBytes, users, views.Slice[types.NodeView]{})
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Error parsing the policy file: %s", err), output)
				return
			}

			_, err = d.SetPolicy(string(policyBytes))
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Failed to set ACL Policy: %s", err), output)
			}
		} else {
			request := &v1.SetPolicyRequest{Policy: string(policyBytes)}

			ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
			defer cancel()
			defer conn.Close()

			if _, err := client.SetPolicy(ctx, request); err != nil {
				ErrorOutput(err, fmt.Sprintf("Failed to set ACL Policy: %s", err), output)
			}
		}

		SuccessOutput(nil, "Policy updated.", "")
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
