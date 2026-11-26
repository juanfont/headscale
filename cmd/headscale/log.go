package main

import (
	"os"
	"time"

	"github.com/jagottsicher/termcolor"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// consoleLog logs to stderr for a person at level: in colour when stderr
// shows it, unless NO_COLOR is set (no-color.org). serve replaces it with
// JSON when the configuration says log.format: json, and the level with
// log.level. The level is set here, not left to zerolog's default, so a
// test that runs a CLI as main does starts where main starts: a test
// binary starts at error (hscontrol/types testlog.go).
func consoleLog(level zerolog.Level) {
	zerolog.SetGlobalLevel(level)

	colors := termcolor.SupportLevel(os.Stderr) != termcolor.LevelNone

	if _, noColorIsSet := os.LookupEnv("NO_COLOR"); noColorIsSet {
		colors = false
	}

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
		NoColor:    !colors,
	})
}
