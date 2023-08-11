package main

import (
	"os"
	"time"

	"github.com/efekarakus/termcolor"
	"github.com/juanfont/headscale/cmd/headscale/cli"
	"github.com/pkg/profile"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	if _, enableProfile := os.LookupEnv("HEADSCALE_PROFILING_ENABLED"); enableProfile {
		if profilePath, ok := os.LookupEnv("HEADSCALE_PROFILING_PATH"); ok {
			err := os.MkdirAll(profilePath, os.ModePerm)
			if err != nil {
				log.Fatal().Err(err).Msg("failed to create profiling directory")
			}

			defer profile.Start(profile.ProfilePath(profilePath)).Stop()
		} else {
			defer profile.Start().Stop()
		}
	}

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
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
		NoColor:    !colors,
	})

	cli.Execute()
}
