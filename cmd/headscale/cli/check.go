package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/juanfont/headscale/hscontrol/config"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var errCheckFailed = errors.New("check failed")

func init() {
	rootCmd.AddCommand(checkCmd)

	checkPolicyCmd.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")
	mustMarkRequired(checkPolicyCmd, "file")
	checkCmd.AddCommand(checkPolicyCmd)

	for _, c := range []*cobra.Command{checkConfigCmd, checkAllCmd} {
		c.Flags().StringP("file", "f", "", "Path to the config file (default: found as serve finds it: -c, HEADSCALE_CONFIG, /etc/headscale, ~/.headscale, .)")
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

var checkConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Check the configuration for errors",
	Long: `
	Config loads and validates the configuration offline: no database, no
	network, nothing created or written. It does not read the files the
	configuration names; "headscale check all" does. Without --file it finds
	the configuration as "headscale serve" does. Secret files named by
	oidc.client_secret_path and the DNS provider *_path settings are still read
	while the configuration loads.`,
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
	All checks the configuration, then each file it names, one line per file:
	ok, FAIL with the error below it, or skip for a missing key file that
	startup creates. It exits non-zero when any line is FAIL. Like "check
	config" it is offline and creates or writes nothing.

	A derp.paths file that fails to parse is FAIL here, although startup only
	skips it with a warning.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		out := cmd.OutOrStdout()

		cfg, src, err := loadCheckedConfig(cmd)
		if err != nil {
			printCheckLine(out, "FAIL", "config", src, len("config"), err)

			return fmt.Errorf("%w: config, files not checked", errCheckFailed)
		}

		files := config.Files(cfg)

		width := len("config")
		for _, f := range files {
			width = max(width, len(f.Key))
		}

		printCheckLine(out, "ok", "config", src, width, nil)

		failed := 0

		for _, f := range files {
			err := f.Check()

			switch {
			case err == nil:
				printCheckLine(out, "ok", f.Key, f.Path, width, nil)
			case f.CreatedAtStartup && errors.Is(err, os.ErrNotExist):
				printCheckLine(out, "skip", f.Key, f.Path+" (missing; startup creates it)", width, nil)
			default:
				failed++

				printCheckLine(out, "FAIL", f.Key, f.Path, width, err)
			}
		}

		if failed > 0 {
			return fmt.Errorf("%w: %d of %d files", errCheckFailed, failed, len(files))
		}

		return nil
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
// serve does, and names where it came from.
func loadCheckedConfig(cmd *cobra.Command) (*types.Config, string, error) {
	path, _ := cmd.Flags().GetString("file")

	err := loadConfig(path)

	src := viper.ConfigFileUsed()
	if src == "" {
		src = "(defaults and environment)"
	}

	if err != nil {
		return nil, src, err
	}

	cfg, err := types.LoadServerConfig()

	return cfg, src, err
}

// printCheckLine prints one result; an error goes indented below it.
func printCheckLine(w io.Writer, status, key, path string, width int, err error) {
	fmt.Fprintf(w, "%-4s  %-*s  %s\n", status, width, key, path)

	if err != nil {
		for l := range strings.SplitSeq(err.Error(), "\n") {
			fmt.Fprintf(w, "      %s\n", l)
		}
	}
}
