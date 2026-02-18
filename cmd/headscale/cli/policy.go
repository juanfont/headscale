package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/spf13/cobra"
	"tailscale.com/types/views"
)

const (
	bypassFlag = "bypass-grpc-and-access-database-directly" //nolint:gosec // not a credential
)

var errAborted = errors.New("command aborted by user")

func init() {
	rootCmd.AddCommand(policyCmd)

	getPolicy.Flags().BoolP(bypassFlag, "", false, "Uses the headscale config to directly access the database, bypassing gRPC and does not require the server to be running")
	policyCmd.AddCommand(getPolicy)

	setPolicy.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")
	setPolicy.Flags().BoolP(bypassFlag, "", false, "Uses the headscale config to directly access the database, bypassing gRPC and does not require the server to be running")
	mustMarkRequired(setPolicy, "file")
	policyCmd.AddCommand(setPolicy)

	checkPolicy.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")
	mustMarkRequired(checkPolicy, "file")
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
	RunE: func(cmd *cobra.Command, args []string) error {
		var policyData string
		if bypass, _ := cmd.Flags().GetBool(bypassFlag); bypass {
			confirm := false

			force, _ := cmd.Flags().GetBool("force")
			if !force {
				confirm = util.YesNo("DO NOT run this command if an instance of headscale is running, are you sure headscale is not running?")
			}

			if !confirm && !force {
				return errAborted
			}

			cfg, err := types.LoadServerConfig()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			d, err := db.NewHeadscaleDatabase(cfg, nil)
			if err != nil {
				return fmt.Errorf("opening database: %w", err)
			}

			pol, err := d.GetPolicy()
			if err != nil {
				return fmt.Errorf("loading policy from database: %w", err)
			}

			policyData = pol.Data
		} else {
			ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig()
			if err != nil {
				return fmt.Errorf("connecting to headscale: %w", err)
			}
			defer cancel()
			defer conn.Close()

			response, err := client.GetPolicy(ctx, &v1.GetPolicyRequest{})
			if err != nil {
				return fmt.Errorf("loading ACL policy: %w", err)
			}

			policyData = response.GetPolicy()
		}

		// This does not pass output format as we don't support yaml, json or
		// json-line output for this command. It is HuJSON already.
		fmt.Println(policyData)

		return nil
	},
}

var setPolicy = &cobra.Command{
	Use:   "set",
	Short: "Updates the ACL Policy",
	Long: `
	Updates the existing ACL Policy with the provided policy. The policy must be a valid HuJSON object.
	This command only works when the acl.policy_mode is set to "db", and the policy will be stored in the database.`,
	Aliases: []string{"put", "update"},
	RunE: func(cmd *cobra.Command, args []string) error {
		policyPath, _ := cmd.Flags().GetString("file")

		f, err := os.Open(policyPath)
		if err != nil {
			return fmt.Errorf("opening policy file: %w", err)
		}
		defer f.Close()

		policyBytes, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("reading policy file: %w", err)
		}

		if bypass, _ := cmd.Flags().GetBool(bypassFlag); bypass {
			confirm := false

			force, _ := cmd.Flags().GetBool("force")
			if !force {
				confirm = util.YesNo("DO NOT run this command if an instance of headscale is running, are you sure headscale is not running?")
			}

			if !confirm && !force {
				return errAborted
			}

			cfg, err := types.LoadServerConfig()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			d, err := db.NewHeadscaleDatabase(cfg, nil)
			if err != nil {
				return fmt.Errorf("opening database: %w", err)
			}

			users, err := d.ListUsers()
			if err != nil {
				return fmt.Errorf("loading users for policy validation: %w", err)
			}

			_, err = policy.NewPolicyManager(policyBytes, users, views.Slice[types.NodeView]{})
			if err != nil {
				return fmt.Errorf("parsing policy file: %w", err)
			}

			_, err = d.SetPolicy(string(policyBytes))
			if err != nil {
				return fmt.Errorf("setting ACL policy: %w", err)
			}
		} else {
			request := &v1.SetPolicyRequest{Policy: string(policyBytes)}

			ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig()
			if err != nil {
				return fmt.Errorf("connecting to headscale: %w", err)
			}
			defer cancel()
			defer conn.Close()

			_, err = client.SetPolicy(ctx, request)
			if err != nil {
				return fmt.Errorf("setting ACL policy: %w", err)
			}
		}

		fmt.Println("Policy updated.")

		return nil
	},
}

var checkPolicy = &cobra.Command{
	Use:   "check",
	Short: "Check the Policy file for errors",
	RunE: func(cmd *cobra.Command, args []string) error {
		policyPath, _ := cmd.Flags().GetString("file")

		f, err := os.Open(policyPath)
		if err != nil {
			return fmt.Errorf("opening policy file: %w", err)
		}
		defer f.Close()

		policyBytes, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("reading policy file: %w", err)
		}

		_, err = policy.NewPolicyManager(policyBytes, nil, views.Slice[types.NodeView]{})
		if err != nil {
			return fmt.Errorf("parsing policy file: %w", err)
		}

		fmt.Println("Policy is valid")

		return nil
	},
}
