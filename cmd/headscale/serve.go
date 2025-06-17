package main

import (
	"fmt"

	"github.com/creachadair/command"
)

// Serve and config command implementations

func serveCommand(env *command.Env) error {
	server, err := newHeadscaleServerWithConfig(globalArgs.Config)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	return server.Serve()
}

func configTestCommand(env *command.Env) error {
	_, err := newHeadscaleServerWithConfig(globalArgs.Config)
	if err != nil {
		return fmt.Errorf("configuration test failed: %w", err)
	}

	fmt.Println("Configuration is valid")
	return nil
}

func versionCommand(env *command.Env) error {
	versionInfo := map[string]string{
		"version": "dev", // This should be replaced with actual version info
		"commit":  "unknown",
		"date":    "unknown",
	}

	return outputResult(versionInfo, "Version", globalArgs.Output)
}

// Serve and config command definitions

func serveCommands() []*command.C {
	return []*command.C{
		{
			Name:  "serve",
			Usage: "",
			Help:  "Start the headscale server",
			Run:   serveCommand,
		},
		{
			Name:  "version",
			Usage: "",
			Help:  "Show version information",
			Run:   versionCommand,
		},
	}
}

func configCommands() []*command.C {
	return []*command.C{
		{
			Name:  "config",
			Usage: "test",
			Help:  "Configuration management commands",
			Commands: []*command.C{
				{
					Name:  "test",
					Usage: "",
					Help:  "Test the configuration file",
					Run:   configTestCommand,
				},
			},
		},
	}
}
