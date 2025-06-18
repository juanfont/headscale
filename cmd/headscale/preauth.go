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

// PreAuth key command flags
var preAuthArgs struct {
	User       string `flag:"user,u,User identifier (required)"`
	Key        string `flag:"key,k,PreAuth key"`
	Expiration string `flag:"expiration,e,default=24h,Expiration duration"`
	Reusable   bool   `flag:"reusable,Make the key reusable"`
	Ephemeral  bool   `flag:"ephemeral,Create key for ephemeral nodes"`
	Tags       string `flag:"tags,Comma-separated tags to assign"`
}

// PreAuth key command implementations

func listPreAuthKeysCommand(env *command.Env) error {
	if err := requireString(preAuthArgs.User, "user"); err != nil {
		return err
	}

	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		// Resolve user identifier to ID with fallback
		userID, err := resolveUserWithFallback(ctx, client, preAuthArgs.User)
		if err != nil {
			return err
		}

		request := &v1.ListPreAuthKeysRequest{
			User: userID,
		}

		response, err := client.ListPreAuthKeys(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot list pre auth keys: %w", err)
		}

		return outputResult(response.GetPreAuthKeys(), "PreAuth Keys", globalArgs.Output)
	})
}

func createPreAuthKeyCommand(env *command.Env) error {
	if err := requireString(preAuthArgs.User, "user"); err != nil {
		return err
	}

	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		// Resolve user identifier to ID with fallback
		userID, err := resolveUserWithFallback(ctx, client, preAuthArgs.User)
		if err != nil {
			return err
		}

		// Parse expiration using helper
		expiration, err := parseDurationWithDefault(preAuthArgs.Expiration, 24*time.Hour)
		if err != nil {
			return err
		}

		request := &v1.CreatePreAuthKeyRequest{
			User:       userID,
			Reusable:   preAuthArgs.Reusable,
			Ephemeral:  preAuthArgs.Ephemeral,
			AclTags:    parseCommaSeparated(preAuthArgs.Tags),
			Expiration: timestamppb.New(expiration),
		}

		response, err := client.CreatePreAuthKey(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot create pre auth key: %w", err)
		}

		return outputResult(response.GetPreAuthKey(), "PreAuth Key created", globalArgs.Output)
	})
}

func expirePreAuthKeyCommand(env *command.Env) error {
	if err := requireString(preAuthArgs.User, "user"); err != nil {
		return err
	}
	if err := requireString(preAuthArgs.Key, "key"); err != nil {
		return err
	}

	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		// Resolve user identifier to ID with fallback
		userID, err := resolveUserWithFallback(ctx, client, preAuthArgs.User)
		if err != nil {
			return err
		}

		request := &v1.ExpirePreAuthKeyRequest{
			User: userID,
			Key:  preAuthArgs.Key,
		}

		response, err := client.ExpirePreAuthKey(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot expire pre auth key: %w", err)
		}

		return outputResult(response, "PreAuth Key expired", globalArgs.Output)
	})
}

// PreAuth key command definitions

func preAuthKeyCommands() []*command.C {
	preAuthCommand := &command.C{
		Name:     "preauth-keys",
		Usage:    "<subcommand> [flags] [args...]",
		Help:     "Manage pre-authentication keys",
		SetFlags: command.Flags(flax.MustBind, &globalArgs, &preAuthArgs),
		Commands: []*command.C{
			{
				Name:  "list",
				Usage: "--user <user>",
				Help:  "List pre-authentication keys for a user",
				Run:   listPreAuthKeysCommand,
			},
			createSubcommandAlias(listPreAuthKeysCommand, "ls", "--user <user>", "List pre-authentication keys for a user (alias)"),
			{
				Name:  "create",
				Usage: "--user <user> [flags]",
				Help:  "Create a new pre-authentication key",
				Run:   createPreAuthKeyCommand,
			},
			{
				Name:  "expire",
				Usage: "--user <user> --key <key>",
				Help:  "Expire a pre-authentication key",
				Run:   expirePreAuthKeyCommand,
			},
		},
	}

	return []*command.C{
		preAuthCommand,
		// PreAuth key aliases
		createCommandAlias(preAuthCommand, "preauthkeys", "Manage pre-authentication keys (alias)"),
		createCommandAlias(preAuthCommand, "preauth", "Manage pre-authentication keys (alias)"),
	}
}
