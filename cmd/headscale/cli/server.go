package cli

import (
	"log"

	"github.com/spf13/cobra"
)

var ServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Launches the headscale server",
	Args: func(cmd *cobra.Command, args []string) error {
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}
		go h.ExpireEphemeralNodes(5000)
		err = h.Serve()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}
	},
}
