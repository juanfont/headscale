package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"tailscale.com/types/key"
)

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.AddCommand(generatePrivateKeyCmd)
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
