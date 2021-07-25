package cli

import (
	"fmt"
	"github.com/spf13/cobra"
	"strings"
)

var version = "dev"

var VersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version.",
	Long:  "The version of headscale.",
	Run: func(cmd *cobra.Command, args []string) {
		o, _ := cmd.Flags().GetString("output")
		if strings.HasPrefix(o, "json") {
			JsonOutput(map[string]string{"version": version}, nil, o)
			return
		}
		fmt.Println(version)
	},
}
