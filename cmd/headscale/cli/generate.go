package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"

	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/cobra"
	"tailscale.com/types/key"
)

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.AddCommand(generatePrivateKeyCmd)

	generateConfigCmd.Flags().Bool("no-docs", false, "Leave out the documentation comments")
	generateConfigCmd.Flags().Bool("running", false, "Print the running server's configuration, secrets redacted, instead of the defaults")
	generateConfigCmd.Flags().Bool("minimal", false, "Print only the keys every server must set")
	generateConfigCmd.MarkFlagsMutuallyExclusive("minimal", "running")
	generateCmd.AddCommand(generateConfigCmd)

	generateNixOSOptionsCmd.Flags().Bool("release", false, "Stamp the version and commit of this binary, which must be a clean build of a known commit")
	generateCmd.AddCommand(generateNixOSOptionsCmd)
}

var errNotRelease = errors.New("--release needs a binary built from a clean, known commit")

var generateCmd = &cobra.Command{
	Use:     "generate",
	Short:   "Generate commands",
	Aliases: []string{"gen"},
}

var generatePrivateKeyCmd = &cobra.Command{
	Use:   "private-key",
	Short: "Generate a private key for the headscale server",
	RunE: func(cmd *cobra.Command, args []string) error {
		machineKey := key.NewMachine()

		machineKeyStr, err := machineKey.MarshalText()
		if err != nil {
			return fmt.Errorf("marshalling machine key: %w", err)
		}

		return printOutput(cmd, map[string]string{
			"private_key": string(machineKeyStr),
		},
			string(machineKeyStr))
	},
}

var generateConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Print a configuration file with every key",
	Long: `Print a YAML configuration with every key, its default and its
documentation as comments, e.g. for "> /etc/headscale/config.yaml". Set the
keys marked "Required" before starting headscale. With --minimal, print only
those keys.

With --running, print instead the configuration of the running server,
without the client-only cli section: literal secrets, DNS provider settings
other than its name, and URL credentials are redacted, "file:" references
kept as written.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		noDocs, _ := cmd.Flags().GetBool("no-docs")
		running, _ := cmd.Flags().GetBool("running")
		minimal, _ := cmd.Flags().GetBool("minimal")

		if running {
			return printRunningConfig(cmd, !noDocs)
		}

		d := config.Default()

		out, err := config.GenerateExample(&d, config.ExampleOptions{Docs: !noDocs, Minimal: minimal})
		if err != nil {
			return fmt.Errorf("generating config: %w", err)
		}

		_, err = cmd.OutOrStdout().Write(out)

		return err
	},
}

// printRunningConfig writes the running server's configuration, as the
// server renders it, to stdout. generate config skips initConfig, so this
// loads the CLI's own settings to reach the server.
func printRunningConfig(cmd *cobra.Command, docs bool) error {
	// Its log settings stay unapplied: a warning may explain which server
	// answers, whatever log.level says.
	l, err := loadConfig("")
	logWarnings(l.Warnings)

	if err != nil {
		return err
	}

	loaded = l

	return withClient(func(ctx context.Context, client *clientv1.ClientWithResponses) error {
		resp, err := client.GetConfigWithResponse(ctx, &clientv1.GetConfigParams{Docs: &docs})
		if err != nil {
			return fmt.Errorf("asking the server for its configuration: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		_, err = cmd.OutOrStdout().Write(resp.Body)

		return err
	})
}

var generateNixOSOptionsCmd = &cobra.Command{
	Use:   "nixos-options",
	Short: "Print the NixOS options for services.headscale.settings",
	Long: `Print the NixOS options for services.headscale.settings: one option per
configuration key, with its type, default, documentation and an example. The
output is a function of lib only, not a module:

    options = import ./options.generated.nix { inherit lib; };

With --release, its header names this binary's version and commit instead
of the development tree.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		release, err := cmd.Flags().GetBool("release")
		if err != nil {
			return err
		}

		var stamp *types.VersionInfo

		if release {
			stamp, err = releaseStamp(types.GetVersionInfo())
			if err != nil {
				return err
			}
		}

		out, err := config.GenerateNixOptions(stamp)
		if err != nil {
			return fmt.Errorf("generating NixOS options: %w", err)
		}

		_, err = cmd.OutOrStdout().Write(out)

		return err
	},
}

// releaseStamp is v, if it can stamp a release: built from a known commit
// without local changes.
func releaseStamp(v *types.VersionInfo) (*types.VersionInfo, error) {
	if v.Dirty || v.Commit == "unknown" {
		return nil, fmt.Errorf("%w: commit %s, dirty %t", errNotRelease, v.Commit, v.Dirty)
	}

	return v, nil
}
