package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/cobra"
	"tailscale.com/types/views"
)

const (
	bypassFlag = "bypass-grpc-and-access-database-directly" //nolint:gosec // not a credential
)

var errAborted = errors.New("command aborted by user")

// bypassDatabase loads the server config and opens the database directly,
// bypassing the gRPC server. The caller is responsible for closing the
// returned database handle.
func bypassDatabase() (*db.HSDatabase, error) {
	cfg, err := types.LoadServerConfig()
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	d, err := db.NewHeadscaleDatabase(cfg)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	return d, nil
}

// openBypassDB confirms the destructive bypass action and opens the database
// directly. The caller is responsible for closing the returned handle.
func openBypassDB(cmd *cobra.Command) (*db.HSDatabase, error) {
	if !confirmAction(cmd, "DO NOT run this command if an instance of headscale is running, are you sure headscale is not running?") {
		return nil, errAborted
	}

	return bypassDatabase()
}

func init() {
	rootCmd.AddCommand(policyCmd)

	getPolicy.Flags().BoolP(bypassFlag, "", false, "Uses the headscale config to directly access the database, bypassing gRPC and does not require the server to be running")
	policyCmd.AddCommand(getPolicy)

	setPolicy.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")
	setPolicy.Flags().BoolP(bypassFlag, "", false, "Uses the headscale config to directly access the database, bypassing gRPC and does not require the server to be running")
	mustMarkRequired(setPolicy, "file")
	policyCmd.AddCommand(setPolicy)

	checkPolicy.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")
	checkPolicy.Flags().BoolP(bypassFlag, "", false, "Open the database directly (no gRPC, no running server) to resolve user references and to evaluate the policy's tests and sshTests blocks. Required when those checks are needed.")
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
	Aliases: []string{cmdShow, "view", "fetch"},
	RunE: func(cmd *cobra.Command, args []string) error {
		var policyData string

		if bypass, _ := cmd.Flags().GetBool(bypassFlag); bypass {
			d, err := openBypassDB(cmd)
			if err != nil {
				return err
			}
			defer d.Close()

			pol, err := d.GetPolicy()
			if err != nil {
				return fmt.Errorf("loading policy from database: %w", err)
			}

			policyData = pol.Data
		} else {
			err := withGRPC(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
				response, err := client.GetPolicy(ctx, &v1.GetPolicyRequest{})
				if err != nil {
					return fmt.Errorf("loading ACL policy: %w", err)
				}

				policyData = response.GetPolicy()

				return nil
			})
			if err != nil {
				return err
			}
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

		policyBytes, err := os.ReadFile(policyPath)
		if err != nil {
			return fmt.Errorf("reading policy file: %w", err)
		}

		if bypass, _ := cmd.Flags().GetBool(bypassFlag); bypass {
			d, err := openBypassDB(cmd)
			if err != nil {
				return err
			}
			defer d.Close()

			users, err := d.ListUsers(nil)
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

			err := withGRPC(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
				_, err := client.SetPolicy(ctx, request)
				if err != nil {
					return fmt.Errorf("setting ACL policy: %w", err)
				}

				return nil
			})
			if err != nil {
				return err
			}
		}

		fmt.Println("Policy updated.")

		return nil
	},
}

var checkPolicy = &cobra.Command{
	Use:   "check",
	Short: "Check the Policy file for errors",
	Long: `
	Check validates the policy against the server's live users and nodes,
	running any "tests" or "sshTests" block. By default the command is a
	thin frontend for a gRPC call to a running headscale; pass --` + bypassFlag + ` to
	open the database directly when headscale is not running.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		policyPath, _ := cmd.Flags().GetString("file")

		policyBytes, err := os.ReadFile(policyPath)
		if err != nil {
			return fmt.Errorf("reading policy file: %w", err)
		}

		if bypass, _ := cmd.Flags().GetBool(bypassFlag); bypass {
			d, err := openBypassDB(cmd)
			if err != nil {
				return err
			}
			defer d.Close()

			users, err := d.ListUsers(nil)
			if err != nil {
				return fmt.Errorf("loading users: %w", err)
			}

			nodes, err := d.ListNodes()
			if err != nil {
				return fmt.Errorf("loading nodes: %w", err)
			}

			// [policy.NewPolicyManager] validates structure and user references
			// but intentionally skips test evaluation (boot path).
			// [policy.PolicyManager.SetPolicy] is the user-write boundary and is what runs the
			// tests and sshTests blocks.
			pm, err := policy.NewPolicyManager(policyBytes, users, nodes.ViewSlice())
			if err != nil {
				return fmt.Errorf("parsing policy file: %w", err)
			}

			_, err = pm.SetPolicy(policyBytes)
			if err != nil {
				return err
			}

			fmt.Println("Policy is valid")

			return nil
		}

		err = withGRPC(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
			_, err := client.CheckPolicy(ctx, &v1.CheckPolicyRequest{Policy: string(policyBytes)})

			return err
		})
		if err != nil {
			return err
		}

		fmt.Println("Policy is valid")

		return nil
	},
}
