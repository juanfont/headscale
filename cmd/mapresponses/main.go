package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/integration/integrationutil"
)

type MapConfig struct {
	Directory string `flag:"directory,Directory to read map responses from"`
}

var mapConfig MapConfig

func main() {
	root := command.C{
		Name: "mapresponses",
		Help: "MapResponses is a tool to map and compare map responses from a directory",
		Commands: []*command.C{
			{
				Name:     "online",
				Help:     "",
				Usage:    "run [test-pattern] [flags]",
				SetFlags: command.Flags(flax.MustBind, &mapConfig),
				Run:      runOnline,
			},
			command.HelpCommand(nil),
		},
	}

	env := root.NewEnv(nil).MergeFlags(true)
	command.RunOrFail(env, os.Args[1:])
}

// runIntegrationTest executes the integration test workflow.
func runOnline(env *command.Env) error {
	if mapConfig.Directory == "" {
		return fmt.Errorf("directory is required")
	}

	resps, err := mapper.ReadMapResponsesFromDirectory(mapConfig.Directory)
	if err != nil {
		return fmt.Errorf("reading map responses from directory: %w", err)
	}

	expected := integrationutil.BuildExpectedOnlineMap(resps)

	out, err := json.MarshalIndent(expected, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling expected online map: %w", err)
	}

	os.Stderr.Write(out)
	os.Stderr.Write([]byte("\n"))
	return nil
}
