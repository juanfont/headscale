package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/efekarakus/termcolor"
	"github.com/juanfont/headscale"
	"github.com/juanfont/headscale/cmd/headscale/cli"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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

	cfg, err := headscale.GetHeadscaleConfig()
	if err != nil {
		log.Fatal().Caller().Err(err)
	}

	machineOutput := cli.HasMachineOutputFlag()

	zerolog.SetGlobalLevel(cfg.LogLevel)

	// If the user has requested a "machine" readable format,
	// then disable login so the output remains valid.
	if machineOutput {
		zerolog.SetGlobalLevel(zerolog.Disabled)
	}

	if !cfg.DisableUpdateCheck && !machineOutput {
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
