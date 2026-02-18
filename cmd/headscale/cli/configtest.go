package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(configTestCmd)
}

var configTestCmd = &cobra.Command{
	Use:   "configtest",
	Short: "Test the configuration.",
	Long:  "Run a test of the configuration and exit.",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := newHeadscaleServerWithConfig()
		if err != nil {
			return fmt.Errorf("configuration error: %w", err)
		}

		return nil
	},
}
