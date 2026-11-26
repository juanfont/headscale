package cli

import (
	"os"

	"github.com/juanfont/headscale/hscontrol"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(serveCmd)
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Launches the headscale server",
	RunE: func(cmd *cobra.Command, args []string) error {
		return hscontrol.RunServer(cmd.Context(), loaded, os.Stdout)
	},
}

// exitCode is how cmd exits on err, file being the configuration file it
// loaded: serve's own rule, and 1 for every other command.
func exitCode(cmd *cobra.Command, file string, err error) int {
	if cmd == serveCmd {
		return types.ServeExitCode(file, err)
	}

	return 1
}
