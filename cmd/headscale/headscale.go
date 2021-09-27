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

	err := cli.LoadConfig("")
	if err != nil {
		log.Fatal().Err(err)
	}

	logLevel := viper.GetString("log_level")
	switch logLevel {
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	if !viper.GetBool("disable_check_updates") {
		if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && cli.Version != "dev" {
			githubTag := &latest.GithubTag{
				Owner:      "juanfont",
				Repository: "headscale",
			}
			res, err := latest.Check(githubTag, cli.Version)
			if err == nil && res.Outdated {
				fmt.Printf("An updated version of Headscale has been found (%s vs. your current %s). Check it out https://github.com/juanfont/headscale/releases\n",
					res.Current, cli.Version)
			}
		}
	}

	cli.Execute()
}
