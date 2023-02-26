package cli

import (
	"github.com/spf13/cobra"
	"github.com/rs/zerolog/log"
)

func init() {
	rootCmd.AddCommand(configTestCmd)
}

var configTestCmd = &cobra.Command{
	Use:   "configtest",
	Short: "Test the configuration.",
	Long:  "Run a test of the configuration and exit.",
	Run: func(cmd *cobra.Command, args []string) {
		_, err := getHeadscaleApp()
		if err != nil {
			log.Fatal().Caller().Err(err).Msg("Error initializing")
		}
	},
}
