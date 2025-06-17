package main

import (
	"context"
	"fmt"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

// User command flags
var userArgs struct {
	ID         uint64 `flag:"id,i,User ID"`
	Identifier uint64 `flag:"identifier,User ID (backward compatibility alias for --id)"`
	Name       string `flag:"name,n,User name"`
	Email      string `flag:"email,e,Email address"`
	NewName    string `flag:"new-name,New name for rename operations"`
}

// Helper function to get user ID from either --id or --identifier flags
// Prioritizes --id but falls back to --identifier for backward compatibility
func getIDFromUserFlags() uint64 {
	if userArgs.ID != 0 {
		return userArgs.ID
	}
	return userArgs.Identifier
}

// User command implementations

func createUserCommand(env *command.Env, username string) error {
	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		request := &v1.CreateUserRequest{Name: username}

		if userArgs.Email != "" {
			request.Email = userArgs.Email
		}

		response, err := client.CreateUser(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot create user: %w", err)
		}

		return outputResult(response.GetUser(), "User created", globalArgs.Output)
	})
}

func listUsersCommand(env *command.Env) error {
	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		request := &v1.ListUsersRequest{}

		// Apply filters if specified
		userID := getIDFromUserFlags()
		if userID != 0 {
			request.Id = userID
		}
		if userArgs.Name != "" {
			request.Name = userArgs.Name
		}
		if userArgs.Email != "" {
			request.Email = userArgs.Email
		}

		response, err := client.ListUsers(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot list users: %w", err)
		}

		return outputResult(response.GetUsers(), "Users", globalArgs.Output)
	})
}

func renameUserCommand(env *command.Env) error {
	// Get new name from flag
	newName := userArgs.NewName
	if newName == "" {
		return fmt.Errorf("--new-name flag is required")
	}

	// Get user ID from either --id or --identifier
	userID := getIDFromUserFlags()
	if userID == 0 && userArgs.Name == "" {
		return fmt.Errorf("either --id/--identifier or --name flag is required")
	}

	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		// Get the user ID using the helper
		finalUserID, err := getUserIDFromIdentifier(ctx, client, userID, userArgs.Name)
		if err != nil {
			return err
		}

		request := &v1.RenameUserRequest{
			OldId:   finalUserID,
			NewName: newName,
		}

		response, err := client.RenameUser(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot rename user: %w", err)
		}

		return outputResult(response.GetUser(), "User renamed", globalArgs.Output)
	})
}

func deleteUserCommand(env *command.Env) error {
	// Get user ID from either --id or --identifier
	userID := getIDFromUserFlags()
	if userID == 0 && userArgs.Name == "" {
		return fmt.Errorf("either --id/--identifier or --name flag is required")
	}

	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		// Get the user ID using the helper
		finalUserID, err := getUserIDFromIdentifier(ctx, client, userID, userArgs.Name)
		if err != nil {
			return err
		}

		// Determine the display name for confirmation
		displayName := fmt.Sprintf("ID %d", finalUserID)
		if userArgs.Name != "" {
			displayName = userArgs.Name
		}

		// Confirm deletion using the helper
		shouldProceed, err := confirmDeletion("user", displayName, globalArgs.Force)
		if err != nil {
			return err
		}
		if !shouldProceed {
			return nil
		}

		request := &v1.DeleteUserRequest{Id: finalUserID}

		_, err = client.DeleteUser(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot delete user: %w", err)
		}

		return outputResult(map[string]interface{}{"user_id": finalUserID}, "User destroyed", globalArgs.Output)
	})
}

// User command definitions

func userCommands() []*command.C {
	userCommand := &command.C{
		Name:     "users",
		Usage:    "<subcommand> [flags] [args...]",
		Help:     "Manage users in Headscale",
		SetFlags: command.Flags(flax.MustBind, &globalArgs, &userArgs),
		Commands: []*command.C{
			{
				Name:     "create",
				Usage:    "<username> [--email <email>]",
				Help:     "Create a new user with optional email address",
				SetFlags: command.Flags(flax.MustBind, &globalArgs, &userArgs),
				Run:      command.Adapt(createUserCommand),
			},
			{
				Name:     "list",
				Usage:    "[--output json|yaml|table]",
				Help:     "List all users in the system",
				SetFlags: command.Flags(flax.MustBind, &globalArgs, &userArgs),
				Run:      listUsersCommand,
			},
			createSubcommandAlias(listUsersCommand, "ls", "[flags]", "List users (alias)"),
			{
				Name:     "rename",
				Usage:    "--id <id> | --name <n> --new-name <new-name>",
				Help:     "Rename an existing user to a new name",
				SetFlags: command.Flags(flax.MustBind, &globalArgs, &userArgs),
				Run:      renameUserCommand,
			},
			{
				Name:     "delete",
				Usage:    "--id <id> | --name <n> [--force]",
				Help:     "Delete a user (prompts for confirmation unless --force is used)",
				SetFlags: command.Flags(flax.MustBind, &globalArgs, &userArgs),
				Run:      deleteUserCommand,
			},
			createSubcommandAlias(deleteUserCommand, "destroy", "--id <id> | --name <n> [--force]", "Delete a user (alias for delete)"),
		},
	}

	return []*command.C{
		userCommand,
		// User management alias
		createCommandAlias(userCommand, "user", "Manage users in Headscale (alias)"),
	}
}
