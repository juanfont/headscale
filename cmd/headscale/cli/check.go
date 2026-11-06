package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	"github.com/juanfont/headscale/hscontrol"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/cobra"
)

var errConfigtestRemoved = errors.New(`"configtest" was removed in 0.30, use "headscale check config"`)

// removedConfigtestCmd points the old name at its replacement.
var removedConfigtestCmd = &cobra.Command{
	Use:                "configtest",
	Hidden:             true,
	DisableFlagParsing: true,
	Args:               cobra.ArbitraryArgs,
	RunE: func(*cobra.Command, []string) error {
		return errConfigtestRemoved
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(removedConfigtestCmd)

	checkPolicyCmd.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")
	checkPolicyCmd.Flags().Bool("database", false, "Open the database directly (no running server required) to resolve users and run tests and sshTests. This runs migrations and may modify the database: use a copy")
	checkPolicyCmd.Flags().Bool("server", false, "Ask a running server to check the policy, including tests and sshTests")
	checkPolicyCmd.MarkFlagsMutuallyExclusive("database", "server")
	mustMarkRequired(checkPolicyCmd, "file")
	checkCmd.AddCommand(checkPolicyCmd)

	checkConfigCmd.Flags().Bool("no-files", false, "Skip the separate checks of the files the config names (policy, DERP map, ...); --database still loads the configured policy. Secret *_path files (oidc.client_secret_path, DNS provider *_path) are still read while the config loads")
	checkConfigCmd.Flags().Bool("database", false, "Also open the database, run migrations and load the policy against its users and nodes. Migrations modify the database: point it at a copy")
	checkCmd.AddCommand(checkConfigCmd)
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

var checkConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Check the configuration for errors",
	Long: `
	Check loads the configuration and parses the files it names. It never
	creates key files or contacts the OIDC provider. --database also runs
	startup's state initialisation: it opens the database, runs migrations and
	loads the policy (its file in file mode), even with --no-files.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		noFiles, _ := cmd.Flags().GetBool("no-files")
		useDB, _ := cmd.Flags().GetBool("database")

		err := loadConfig()
		if err != nil {
			return err
		}

		cfg, err := types.LoadServerConfig()
		if err != nil {
			return err
		}

		if !noFiles {
			err = hscontrol.CheckFiles(cfg)
			if err != nil {
				return err
			}
		}

		if useDB {
			if !confirmAction(cmd, "check config --database runs migrations on the configured database. Point it at a copy, not a live database. Continue?") {
				return errAborted
			}

			err = checkConfigDatabase(cfg)
			if err != nil {
				return err
			}
		}

		fmt.Fprintln(cmd.OutOrStdout(), "Configuration is valid")

		return nil
	},
}

// checkConfigDatabase builds the state as startup does, so it shares startup's
// state-initialisation failure conditions.
func checkConfigDatabase(cfg *types.Config) error {
	s, err := state.NewState(cfg)
	if err != nil {
		return fmt.Errorf("opening state: %w", err)
	}

	return s.Close()
}
