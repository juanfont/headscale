package cli

import (
	"github.com/skitzo2000/headscale/hscontrol/types"
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
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		info := types.GetVersionInfo()

		SuccessOutput(info, info.String(), output)
	},
}
