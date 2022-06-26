package cli

import (
	"github.com/prometheus/common/model"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"time"
)

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().
		String("api-key-prefix", "", "Initial API Key prefix")
	serveCmd.Flags().
		String("api-key-pass", "", "Initial API Key password")
	serveCmd.Flags().
		String("api-key-expiration", DefaultAPIKeyExpiry, "Human-readable expiration for initial API key (e.g. 30m, 24h)")
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Launches the headscale server",
	Args: func(cmd *cobra.Command, args []string) error {
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		app, err := getHeadscaleApp()
		if err != nil {
			log.Fatal().Caller().Err(err).Msg("Error initializing")
		}

		// Save API key if provided
		prefix, _ := cmd.Flags().GetString("api-key-prefix")
		password, _ := cmd.Flags().GetString("api-key-pass")
		if prefix != "" || password != "" {
			if !(prefix != "" && password != "") {
				log.Fatal().Caller().Msg("For initial API key both prefix and password should be provided")
			}

			durationStr, _ := cmd.Flags().GetString("api-key-expiration")
			duration, err := model.ParseDuration(durationStr)
			if err != nil {
				log.Fatal().Caller().Err(err).Msg("Could not parse duration")
			}
			expiration := time.Now().UTC().Add(time.Duration(duration))

			if _, err := app.SaveAPIKey(prefix, password, &expiration); err != nil {
				log.Fatal().Caller().Err(err).Msg("Error while saving initial API key")
			}
		}

		err = app.Serve()
		if err != nil {
			log.Fatal().Caller().Err(err).Msg("Error starting server")
		}
	},
}
