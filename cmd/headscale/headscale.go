package main

import (
	"os"
	"time"

	"github.com/jagottsicher/termcolor"
	"github.com/juanfont/headscale/cmd/headscale/cli"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	colors := termcolor.SupportLevel(os.Stderr) != termcolor.LevelNone

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
