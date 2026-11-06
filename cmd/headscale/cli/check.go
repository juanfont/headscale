package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(checkCmd)

	checkPolicyCmd.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")
	checkPolicyCmd.Flags().Bool("database", false, "Open the database directly (no running server required) to resolve users and run tests and sshTests. This runs migrations and may modify the database: use a copy")
	checkPolicyCmd.Flags().Bool("server", false, "Ask a running server to check the policy, including tests and sshTests")
	checkPolicyCmd.MarkFlagsMutuallyExclusive("database", "server")
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
	Check validates the policy's syntax, shape and references without a server,
	database or config. Pass --database to open the database directly, or
	--server to ask a running headscale, to also run "tests" and "sshTests"
	against the live users and nodes. --database runs migrations and may
	modify the database, so point it at a copy.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		policyPath, _ := cmd.Flags().GetString("file")

		policyBytes, err := os.ReadFile(policyPath)
		if err != nil {
			return fmt.Errorf("reading policy file: %w", err)
		}

		out := cmd.OutOrStdout()
		useDB, _ := cmd.Flags().GetBool("database")
		useServer, _ := cmd.Flags().GetBool("server")

		switch {
		case useDB:
			err = loadConfig()
			if err != nil {
				return err
			}

			d, err := openBypassDB(cmd)
			if err != nil {
				return err
			}
			defer d.Close()

			err = validateOfflinePolicy(d, policyBytes)
			if err != nil {
				return err
			}
		case useServer:
			err = loadConfig()
			if err != nil {
				return err
			}

			policyStr := string(policyBytes)

			err = withClient(func(ctx context.Context, client *clientv1.ClientWithResponses) error {
				resp, err := client.CheckPolicyWithResponse(ctx, clientv1.CheckPolicyJSONRequestBody{
					Policy: &policyStr,
				})
				if err != nil {
					return err
				}

				if resp.StatusCode() != http.StatusOK {
					return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
				}

				return nil
			})
			if err != nil {
				return err
			}
		default:
			var pol *policyv2.Policy

			pol, err = policyv2.ParsePolicy(policyBytes)
			if err != nil {
				return err
			}

			fmt.Fprintln(out, "Policy is valid")

			if pol != nil && (len(pol.Tests) > 0 || len(pol.SSHTests) > 0) {
				fmt.Fprintln(out, "tests and sshTests were not run; use --database or --server to run them")
			}

			return nil
		}

		fmt.Fprintln(out, "Policy is valid")

		return nil
	},
}
