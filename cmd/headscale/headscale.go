package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/efekarakus/termcolor"
	"github.com/juanfont/headscale/cmd/headscale/cli"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/tcnksm/go-latest"
)

func main() {
	var colors bool
	switch l := termcolor.SupportLevel(os.Stderr); l {
	case termcolor.Level16M:
		colors = true
	case termcolor.Level256:
		colors = true
	case termcolor.LevelBasic:
		colors = true
	case termcolor.LevelNone:
		colors = false
	default:
		// no color, return text as is.
		colors = false
	}

	// Adhere to no-color.org manifesto of allowing users to
	// turn off color in cli/services
	if _, noColorIsSet := os.LookupEnv("NO_COLOR"); noColorIsSet {
		colors = false
	}

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
		NoColor:    !colors,
	})

	if err := cli.LoadConfig(""); err != nil {
		log.Fatal().Err(err)
	}

	machineOutput := cli.HasMachineOutputFlag()

	logLevel := viper.GetString("log_level")
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(level)
	}

	// If the user has requested a "machine" readable format,
	// then disable login so the output remains valid.
	if machineOutput {
		zerolog.SetGlobalLevel(zerolog.Disabled)
	}

	if !viper.GetBool("disable_check_updates") && !machineOutput {
		if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") &&
			cli.Version != "dev" {
			githubTag := &latest.GithubTag{
				Owner:      "juanfont",
				Repository: "headscale",
			}
			res, err := latest.Check(githubTag, cli.Version)
			if err == nil && res.Outdated {
				//nolint
				fmt.Printf(
					"An updated version of Headscale has been found (%s vs. your current %s). Check it out https://github.com/juanfont/headscale/releases\n",
					res.Current,
					cli.Version,
				)
			}
		}
	}

	cli.Execute()
}
