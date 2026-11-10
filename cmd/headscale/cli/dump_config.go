package cli

import (
	"fmt"
	"os"

	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(dumpConfigCmd)
}

var dumpConfigCmd = &cobra.Command{
	Use:    "dumpConfig",
	Short:  "dump current config to /etc/headscale/config.dump.yaml, integration test only",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		out, err := config.Marshal(loaded.Config, ".yaml")
		if err != nil {
			return fmt.Errorf("dumping config: %w", err)
		}

		err = os.WriteFile("/etc/headscale/config.dump.yaml", out, 0o600)
		if err != nil {
			return fmt.Errorf("dumping config: %w", err)
		}

		return nil
	},
}
