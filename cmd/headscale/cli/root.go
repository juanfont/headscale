package cli

import (
	"fmt"
	"os"
	"runtime"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/tcnksm/go-latest"
)

const (
	deprecateNamespaceMessage = "use --user"
)

var cfgFile string = ""

func init() {
	if len(os.Args) > 1 &&
		(os.Args[1] == "version" || os.Args[1] == "mockoidc" || os.Args[1] == "completion") {
		return
	}

	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().
		StringVarP(&cfgFile, "config", "c", "", "config file (default is /etc/headscale/config.yaml)")
	rootCmd.PersistentFlags().
		StringP("output", "o", "", "Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'")
	rootCmd.PersistentFlags().
		Bool("force", false, "Disable prompts and forces the execution")
}

func initConfig() {
	if cfgFile == "" {
		cfgFile = os.Getenv("HEADSCALE_CONFIG")
	}
	if cfgFile != "" {
		err := types.LoadConfig(cfgFile, true)
		if err != nil {
			log.Fatal().Caller().Err(err).Msgf("Error loading config file %s", cfgFile)
		}
	} else {
		err := types.LoadConfig("", false)
		if err != nil {
			log.Fatal().Caller().Err(err).Msgf("Error loading config")
		}
	}

	cfg, err := types.GetHeadscaleConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to read headscale configuration")
	}

	machineOutput := HasMachineOutputFlag()

	zerolog.SetGlobalLevel(cfg.Log.Level)

	// If the user has requested a "node" readable format,
	// then disable login so the output remains valid.
	if machineOutput {
		zerolog.SetGlobalLevel(zerolog.Disabled)
	}

	if cfg.Log.Format == types.JSONLogFormat {
		log.Logger = log.Output(os.Stdout)
	}

	if !cfg.DisableUpdateCheck && !machineOutput {
		if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") &&
			Version != "dev" {
			githubTag := &latest.GithubTag{
				Owner:      "juanfont",
				Repository: "headscale",
			}
			res, err := latest.Check(githubTag, Version)
			if err == nil && res.Outdated {
				//nolint
				log.Warn().Msgf(
					"An updated version of Headscale has been found (%s vs. your current %s). Check it out https://github.com/juanfont/headscale/releases\n",
					res.Current,
					Version,
				)
			}
		}
	}
}

var rootCmd = &cobra.Command{
	Use:   "headscale",
	Short: "headscale - a Tailscale control server",
	Long: `
headscale is an open source implementation of the Tailscale control server

https://github.com/juanfont/headscale`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
