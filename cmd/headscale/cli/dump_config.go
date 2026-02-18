package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(dumpConfigCmd)
}

var dumpConfigCmd = &cobra.Command{
	Use:    "dumpConfig",
	Short:  "dump current config to /etc/headscale/config.dump.yaml, integration test only",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		err := viper.WriteConfigAs("/etc/headscale/config.dump.yaml")
		if err != nil {
			return fmt.Errorf("dumping config: %w", err)
		}

		return nil
	},
}
