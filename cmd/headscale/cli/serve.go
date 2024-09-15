package cli

import (
	"errors"
	"net/http"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(serveCmd)
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Launches the headscale server",
	Args: func(cmd *cobra.Command, args []string) error {
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		app, err := newHeadscaleServerWithConfig()
		if err != nil {
			log.Fatal().Caller().Err(err).Msg("Error initializing")
		}

		err = app.Serve()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Caller().Err(err).Msg("Headscale ran into an error and had to shut down.")
		}
	},
}
