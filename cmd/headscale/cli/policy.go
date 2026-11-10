package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/spf13/cobra"
)

const (
	bypassFlag = "bypass-server-and-access-database-directly" //nolint:gosec // not a credential
)

var errAborted = errors.New("command aborted by user")

// bypassDatabase opens the database directly, bypassing the running server.
// The caller must close the returned handle.
func bypassDatabase() (*db.HSDatabase, error) {
	cfg, err := serverConfig()
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	d, err := db.NewHeadscaleDatabase(cfg)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	return d, nil
}

// validateLocalPolicy checks policyBytes against the database's users and
// nodes as a server-side policy write would.
func validateLocalPolicy(d *db.HSDatabase, policyBytes []byte) error {
	users, err := d.ListUsers(nil)
	if err != nil {
		return fmt.Errorf("loading users for policy validation: %w", err)
	}

	nodes, err := d.ListNodes()
	if err != nil {
		return fmt.Errorf("loading nodes for policy validation: %w", err)
	}

	return policy.ValidatePolicy(policyBytes, users, nodes.ViewSlice())
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

	getPolicy.Flags().BoolP(bypassFlag, "", false, "Uses the headscale config to directly access the database, bypassing the API and does not require the server to be running")
	policyCmd.AddCommand(getPolicy)

	setPolicy.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")
	setPolicy.Flags().BoolP(bypassFlag, "", false, "Uses the headscale config to directly access the database, bypassing the API and does not require the server to be running")
	mustMarkRequired(setPolicy, "file")
	policyCmd.AddCommand(setPolicy)
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
			err := withClient(func(ctx context.Context, client *clientv1.ClientWithResponses) error {
				resp, err := client.GetPolicyWithResponse(ctx)
				if err != nil {
					return fmt.Errorf("loading ACL policy: %w", err)
				}

				if resp.StatusCode() != http.StatusOK {
					return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
				}

				policyData = resp.JSON200.Policy

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

			err = validateLocalPolicy(d, policyBytes)
			if err != nil {
				return err
			}

			_, err = d.SetPolicy(string(policyBytes))
			if err != nil {
				return fmt.Errorf("setting ACL policy: %w", err)
			}
		} else {
			policyStr := string(policyBytes)

			err := withClient(func(ctx context.Context, client *clientv1.ClientWithResponses) error {
				resp, err := client.SetPolicyWithResponse(ctx, clientv1.SetPolicyJSONRequestBody{
					Policy: &policyStr,
				})
				if err != nil {
					return fmt.Errorf("setting ACL policy: %w", err)
				}

				if resp.StatusCode() != http.StatusOK {
					return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
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
