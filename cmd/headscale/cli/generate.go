package cli

import (
	"errors"
	"fmt"

	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/cobra"
	"tailscale.com/types/key"
)

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.AddCommand(generatePrivateKeyCmd)

	generateConfigCmd.Flags().Bool("no-docs", false, "Leave out the documentation comments")
	generateConfigCmd.Flags().Bool("minimal", false, "Print only the keys every server must set")
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
those keys.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		noDocs, _ := cmd.Flags().GetBool("no-docs")
		minimal, _ := cmd.Flags().GetBool("minimal")

		d := config.Default()

		out, err := config.GenerateExample(&d, config.ExampleOptions{Docs: !noDocs, Minimal: minimal})
		if err != nil {
			return fmt.Errorf("generating config: %w", err)
		}

		_, err = cmd.OutOrStdout().Write(out)

		return err
	},
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
