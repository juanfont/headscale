package cli

import (
	"fmt"
	"os"
	"runtime"

	"github.com/juanfont/headscale"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/tcnksm/go-latest"
)

var cfgFile string = ""

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().
		StringVarP(&cfgFile, "config", "c", "", "config file (default is /etc/headscale/config.yaml)")
	rootCmd.PersistentFlags().
		StringP("output", "o", "", "Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'")
	rootCmd.PersistentFlags().
		Bool("force", false, "Disable prompts and forces the execution")
}

func initConfig() {
	if cfgFile != "" {
		err := headscale.LoadConfig(cfgFile, true)
		if err != nil {
			log.Fatal().Caller().Err(err)
		}
	} else {
		err := headscale.LoadConfig("", false)
		if err != nil {
			log.Fatal().Caller().Err(err)
		}
	}

	cfg, err := headscale.GetHeadscaleConfig()
	if err != nil {
		log.Fatal().Caller().Err(err)
	}

	machineOutput := HasMachineOutputFlag()

	zerolog.SetGlobalLevel(cfg.LogLevel)

	// If the user has requested a "machine" readable format,
	// then disable login so the output remains valid.
	if machineOutput {
		zerolog.SetGlobalLevel(zerolog.Disabled)
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
				fmt.Printf(
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
