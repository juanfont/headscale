package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var Version = "dev"

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version.",
	Long:  "The version of headscale.",
	Run: func(cmd *cobra.Command, args []string) {
		o, _ := cmd.Flags().GetString("output")
		if strings.HasPrefix(o, "json") {
			JsonOutput(map[string]string{"version": Version}, nil, o)
			return
		}
		fmt.Println(Version)
	},
}
