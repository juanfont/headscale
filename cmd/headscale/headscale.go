package main

import (
	"context"
	"os"
	"time"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/jagottsicher/termcolor"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Set up colored output
	var colors bool
	switch l := termcolor.SupportLevel(os.Stderr); l {
	case termcolor.Level16M, termcolor.Level256, termcolor.LevelBasic:
		colors = true
	default:
		colors = false
	}

	// Adhere to no-color.org manifesto
	if _, noColorIsSet := os.LookupEnv("NO_COLOR"); noColorIsSet {
		colors = false
	}

	// Set up logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
		NoColor:    !colors,
	})

	// Build all commands
	var commands []*command.C

	// Add core commands
	commands = append(commands, serveCommands()...)
	commands = append(commands, configCommands()...)

	// Add management commands
	commands = append(commands, userCommands()...)
	commands = append(commands, nodeCommands()...)
	commands = append(commands, preAuthKeyCommands()...)
	commands = append(commands, apiKeyCommands()...)
	commands = append(commands, policyCommands()...)
	commands = append(commands, devCommands()...)

	// Create root command
	root := &command.C{
		Name: "headscale",
		Usage: `<command> [flags] [args...]
  serve
  version
  config test
  users <subcommand> [flags] [args...]
  nodes <subcommand> [flags] [args...]
  preauth-keys <subcommand> [flags] [args...]
  api-keys <subcommand> [flags] [args...]
  policy <subcommand> [flags] [args...]`,

		Help: `headscale - a Tailscale control server

headscale is an open source implementation of the Tailscale control server

https://github.com/juanfont/headscale`,

		SetFlags: command.Flags(flax.MustBind, &globalArgs),
		Commands: commands,
	}

	// Execute the command
	env := root.NewEnv(nil).SetContext(context.Background())
	command.RunOrFail(env, os.Args[1:])
}
