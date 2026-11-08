package cli

import (
	"context"
	"fmt"
	"net/http"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"

	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/spf13/cobra"
	"tailscale.com/types/key"
)

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.AddCommand(generatePrivateKeyCmd)

	generateConfigCmd.Flags().Bool("no-docs", false, "Leave out the documentation comments")
	generateConfigCmd.Flags().Bool("running", false, "Print the running server's configuration, secrets redacted, instead of the defaults")
	generateCmd.AddCommand(generateConfigCmd)
}

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
keys marked "Required" before starting headscale.

With --running, print instead the configuration of the running server,
without the client-only cli section: literal secrets, DNS provider settings
other than its name, and URL credentials are redacted, "file:" references
kept as written.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		noDocs, _ := cmd.Flags().GetBool("no-docs")
		running, _ := cmd.Flags().GetBool("running")

		if running {
			return printRunningConfig(cmd, !noDocs)
		}

		d := config.Default()

		out, err := config.GenerateExample(&d, config.ExampleOptions{Docs: !noDocs})
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
