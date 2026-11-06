package cli

import "github.com/spf13/cobra"

func init() {
	rootCmd.AddCommand(checkCmd)
}

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check configuration or policy files",
}
