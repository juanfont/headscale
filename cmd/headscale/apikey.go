package main

import (
	"context"
	"fmt"
	"time"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// API key command flags
var apiKeyArgs struct {
	Prefix     string `flag:"prefix,p,API key prefix"`
	Expiration string `flag:"expiration,e,default=24h,Expiration duration"`
}

// API key command implementations

func listAPIKeysCommand(env *command.Env) error {
	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		request := &v1.ListApiKeysRequest{}

		response, err := client.ListApiKeys(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot list API keys: %w", err)
		}

		return outputResult(response.GetApiKeys(), "API Keys", globalArgs.Output)
	})
}

func createAPIKeyCommand(env *command.Env) error {
	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		// Parse expiration using helper
		expiration, err := parseDurationWithDefault(apiKeyArgs.Expiration, 24*time.Hour)
		if err != nil {
			return err
		}

		request := &v1.CreateApiKeyRequest{
			Expiration: timestamppb.New(expiration),
		}

		response, err := client.CreateApiKey(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot create API key: %w", err)
		}

		return outputResult(response.GetApiKey(), "API Key created", globalArgs.Output)
	})
}

func expireAPIKeyCommand(env *command.Env) error {
	if err := requireString(apiKeyArgs.Prefix, "prefix"); err != nil {
		return err
	}

	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		request := &v1.ExpireApiKeyRequest{
			Prefix: apiKeyArgs.Prefix,
		}

		response, err := client.ExpireApiKey(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot expire API key: %w", err)
		}

		return outputResult(response, "API Key expired", globalArgs.Output)
	})
}

func deleteAPIKeyCommand(env *command.Env) error {
	if err := requireString(apiKeyArgs.Prefix, "prefix"); err != nil {
		return err
	}

	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		request := &v1.DeleteApiKeyRequest{
			Prefix: apiKeyArgs.Prefix,
		}

		response, err := client.DeleteApiKey(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot delete API key: %w", err)
		}

		return outputResult(response, "API Key deleted", globalArgs.Output)
	})
}

// API key command definitions

func apiKeyCommands() []*command.C {
	apiKeyCommand := &command.C{
		Name:     "api-keys",
		Usage:    "<subcommand> [flags] [args...]",
		Help:     "Manage API keys",
		SetFlags: command.Flags(flax.MustBind, &globalArgs, &apiKeyArgs),
		Commands: []*command.C{
			{
				Name:  "list",
				Usage: "",
				Help:  "List API keys",
				Run:   listAPIKeysCommand,
			},
			createSubcommandAlias(listAPIKeysCommand, "ls", "", "List API keys (alias)"),
			{
				Name:  "create",
				Usage: "[--expiration <duration>]",
				Help:  "Create a new API key",
				Run:   createAPIKeyCommand,
			},
			{
				Name:  "expire",
				Usage: "--prefix <prefix>",
				Help:  "Expire an API key",
				Run:   expireAPIKeyCommand,
			},
			{
				Name:  "delete",
				Usage: "--prefix <prefix>",
				Help:  "Delete an API key",
				Run:   deleteAPIKeyCommand,
			},
			createSubcommandAlias(deleteAPIKeyCommand, "destroy", "--prefix <prefix>", "Delete an API key (alias)"),
		},
	}

	return []*command.C{
		apiKeyCommand,
		// API key management aliases
		createCommandAlias(apiKeyCommand, "api-key", "Manage API keys (alias)"),
		createCommandAlias(apiKeyCommand, "apikeys", "Manage API keys (backward compatibility alias)"),
	}
}
