package cli

import (
	"bytes"
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

var (
	errAborted            = errors.New("command aborted by user")
	errTestsRequireBypass = errors.New("policy contains a tests block; rerun with --" + bypassFlag + " to evaluate it (headscale must not be running)")
)

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

func init() {
	rootCmd.AddCommand(policyCmd)

	getPolicy.Flags().BoolP(bypassFlag, "", false, "Uses the headscale config to directly access the database, bypassing gRPC and does not require the server to be running")
	policyCmd.AddCommand(getPolicy)

	setPolicy.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")
	setPolicy.Flags().BoolP(bypassFlag, "", false, "Uses the headscale config to directly access the database, bypassing gRPC and does not require the server to be running")
	mustMarkRequired(setPolicy, "file")
	policyCmd.AddCommand(setPolicy)

	checkPolicy.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")
	checkPolicy.Flags().BoolP(bypassFlag, "", false, "Open the database directly to evaluate the policy's tests block. Required when the policy contains tests and headscale is not running.")
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
			if !confirmAction(cmd, "DO NOT run this command if an instance of headscale is running, are you sure headscale is not running?") {
				return errAborted
			}

			d, err := bypassDatabase()
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

		policyBytes, err := os.ReadFile(policyPath)
		if err != nil {
			return fmt.Errorf("reading policy file: %w", err)
		}

		if bypass, _ := cmd.Flags().GetBool(bypassFlag); bypass {
			if !confirmAction(cmd, "DO NOT run this command if an instance of headscale is running, are you sure headscale is not running?") {
				return errAborted
			}

			d, err := bypassDatabase()
			if err != nil {
				return err
			}
			defer d.Close()

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
	Long: `
	Check parses the policy and validates its structure. If the policy contains a
	"tests" block, those tests are evaluated against the live users and nodes:
	pass --` + bypassFlag + ` to open the database directly when headscale is not running.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		policyPath, _ := cmd.Flags().GetString("file")

		policyBytes, err := os.ReadFile(policyPath)
		if err != nil {
			return fmt.Errorf("reading policy file: %w", err)
		}

		bypass, _ := cmd.Flags().GetBool(bypassFlag)

		// Without bypass we don't have users or nodes to resolve test
		// aliases against. Validate structure and warn explicitly if
		// tests are present, rather than running them with empty data
		// and reporting spurious failures.
		if !bypass {
			_, err = policy.NewPolicyManager(policyBytes, nil, views.Slice[types.NodeView]{})
			if err != nil {
				return fmt.Errorf("parsing policy file: %w", err)
			}

			if policyHasTestsBlock(policyBytes) {
				return errTestsRequireBypass
			}

			fmt.Println("Policy is valid")

			return nil
		}

		if !confirmAction(cmd, "DO NOT run this command if an instance of headscale is running, are you sure headscale is not running?") {
			return errAborted
		}

		d, err := bypassDatabase()
		if err != nil {
			return err
		}
		defer d.Close()

		users, err := d.ListUsers()
		if err != nil {
			return fmt.Errorf("loading users: %w", err)
		}

		nodes, err := d.ListNodes()
		if err != nil {
			return fmt.Errorf("loading nodes: %w", err)
		}

		// NewPolicyManager validates structure but intentionally skips
		// test evaluation (boot path). SetPolicy is the user-write
		// boundary and is what runs the tests block.
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
	},
}

// policyHasTestsBlock is a cheap textual probe for `"tests"` so callers
// can warn the user when they need to rerun with bypass. False positives
// (e.g. a comment containing the word) are harmless: the user is told to
// pass a flag they could have passed anyway.
func policyHasTestsBlock(b []byte) bool {
	return bytes.Contains(b, []byte(`"tests"`))
}
