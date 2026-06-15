package main

import (
	"context"
	"os"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
)

var runConfig RunConfig

func main() {
	root := command.C{
		Name: "hi",
		Help: "Headscale Integration test runner",
		Commands: []*command.C{
			{
				Name:     "run",
				Help:     "Run integration tests",
				Usage:    "run [test-pattern] [flags]",
				SetFlags: command.Flags(flax.MustBind, &runConfig),
				Run:      runIntegrationTest,
			},
			{
				Name: "doctor",
				Help: "Check system requirements for running integration tests",
				Run: func(env *command.Env) error {
					return runDoctorCheck(env.Context())
				},
			},
			{
				Name:     "list-versions",
				Help:     "Print Tailscale versions used by integration tests",
				Usage:    "list-versions [flags]",
				SetFlags: command.Flags(flax.MustBind, &listVersionsConfig),
				Run:      listVersions,
			},
			{
				Name: "clean",
				Help: "Clean Docker resources",
				Commands: []*command.C{
					{
						Name: "networks",
						Help: "Prune unused Docker networks",
						Run: func(env *command.Env) error {
							return pruneDockerNetworks(env.Context())
						},
					},
					{
						Name: "images",
						Help: "Clean old test images",
						Run: func(env *command.Env) error {
							return cleanOldImages(env.Context())
						},
					},
					{
						Name: "containers",
						Help: "Kill all test containers",
						Run: func(env *command.Env) error {
							return killTestContainers(env.Context())
						},
					},
					{
						Name: "cache",
						Help: "Clean Go module cache volume",
						Run: func(env *command.Env) error {
							return cleanCacheVolume(env.Context())
						},
					},
					{
						Name: "all",
						Help: "Run all cleanup operations",
						Run: func(env *command.Env) error {
							return cleanAll(env.Context())
						},
					},
				},
			},
			command.HelpCommand(nil),
		},
	}

	env := root.NewEnv(nil).MergeFlags(true)
	command.RunOrFail(env, os.Args[1:])
}

func cleanAll(ctx context.Context) error {
	for _, step := range []func(context.Context) error{
		killTestContainers,
		pruneDockerNetworks,
		cleanOldImages,
		cleanCacheVolume,
	} {
		err := step(ctx)
		if err != nil {
			return err
		}
	}

	return nil
}
