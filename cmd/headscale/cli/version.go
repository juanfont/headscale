package cli

import (
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(versionCmd)
	versionCmd.Flags().StringP("output", "o", "", "Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'")
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version.",
	Long:  "The version of headscale.",
	RunE: func(cmd *cobra.Command, args []string) error {
		info := types.GetVersionInfo()

		return printOutput(cmd, info, info.String())
	},
}
