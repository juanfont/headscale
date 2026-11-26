package cli

import (
	"cmp"
	"fmt"
	"os"

	"github.com/juanfont/headscale/hscontrol"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(checkCmd)

	checkPolicyCmd.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")
	mustMarkRequired(checkPolicyCmd, "file")
	checkCmd.AddCommand(checkPolicyCmd)

	for _, c := range []*cobra.Command{checkConfigCmd, checkAllCmd} {
		c.Flags().StringP("file", "f", "", "Path to the config file (default: found as serve finds it: -c, HEADSCALE_CONFIG, /etc/headscale, $XDG_CONFIG_HOME/headscale, headscale under each $XDG_CONFIG_DIRS entry, ~/.headscale, .)")
		checkCmd.AddCommand(c)
	}

	for _, c := range []*cobra.Command{checkDERPMapCmd, checkExtraRecordsCmd} {
		c.Flags().StringP("file", "f", "", "Path to the file")
		mustMarkRequired(c, "file")
		checkCmd.AddCommand(c)
	}
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

		_, err := config.CheckPolicy(policyPath)
		if err != nil {
			return err
		}

		fmt.Fprintln(cmd.OutOrStdout(), "Policy is valid")

		return nil
	},
}

var checkConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Check the configuration for errors",
	Long: `
	Config validates the configuration: its syntax, keys and values. It does
	not check the files the configuration names; "headscale check all" does.
	Without --file it finds the configuration as "headscale serve" does.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		_, src, err := loadCheckedConfig(cmd)
		if err != nil {
			return err
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Configuration %s is valid\n", src)

		return nil
	},
}

var checkAllCmd = &cobra.Command{
	Use:   "all",
	Short: "Check the configuration and every file it names",
	Long: `
	All checks the configuration, then each file it names, and lists every file
	with ok, FAIL (the error below it) or skip. Skip is a key file that startup
	creates when it is missing, or a "file:<path>" secret. It exits non-zero
	when any line is FAIL.

	A derp.paths file that fails to parse is FAIL here, although startup only
	skips it with a warning.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, src, err := loadCheckedConfig(cmd)

		return config.CheckAll(cmd.OutOrStdout(), cfg, src, err)
	},
}

var (
	checkDERPMapCmd = fileCheckCmd("derp-map",
		"Check a DERP map file (derp.paths) for errors", "DERP map is valid", config.CheckDERPMapFile)
	checkExtraRecordsCmd = fileCheckCmd("extra-records",
		"Check an extra records file (dns.extra_records_path) for errors", "Extra records are valid", config.CheckExtraRecordsFile)
)

// fileCheckCmd checks one file of one kind; it needs no config.
func fileCheckCmd(use, short, valid string, check func(string) error) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, _ := cmd.Flags().GetString("file")

			err := check(path)
			if err != nil {
				return err
			}

			fmt.Fprintln(cmd.OutOrStdout(), valid)

			return nil
		},
	}
}

// loadCheckedConfig loads the server config from --file, or finds it as
// serve does, logs what loading and the config warn about at its log.level
// and in its log.format, and names where it came from.
func loadCheckedConfig(cmd *cobra.Command) (*types.Config, string, error) {
	path, _ := cmd.Flags().GetString("file")

	l, err := config.CheckConfig(cmp.Or(path, cfgFile, os.Getenv("HEADSCALE_CONFIG")), os.Environ())
	if l.Config != nil {
		// As initConfig does; a config that failed to load keeps the
		// console logger and the default level.
		hscontrol.UseLogConfig(l.Config, cmd.ErrOrStderr())
	}

	hscontrol.LogWarnings(l.Warnings)

	if err != nil {
		return nil, l.Source(), err
	}

	return l.Config, l.Source(), nil
}
