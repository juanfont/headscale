package cli

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	apiv1 "github.com/juanfont/headscale/gen/api/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/spf13/cobra"
)

// CLI user errors.
var (
	errFlagRequired       = errors.New("--name or --identifier flag is required")
	errMultipleUsersMatch = errors.New("multiple users match query, specify an ID")
)

func usernameAndIDFlag(cmd *cobra.Command) {
	cmd.Flags().Int64P("identifier", "i", -1, "User identifier (ID)")
	cmd.Flags().StringP("name", "n", "", "Username")
}

// usernameAndIDFromFlag returns the username and ID from the flags of the command.
func usernameAndIDFromFlag(cmd *cobra.Command) (uint64, string, error) {
	username, _ := cmd.Flags().GetString("name")

	identifier, _ := cmd.Flags().GetInt64("identifier")
	if username == "" && identifier < 0 {
		return 0, "", errFlagRequired
	}

	// Normalise unset/negative identifiers to 0 so the uint64
	// conversion does not produce a bogus large value.
	identifier = max(identifier, 0)

	return uint64(identifier), username, nil //nolint:gosec // identifier is clamped to >= 0 above
}

// resolveSingleUser resolves exactly one user from the --name/--id flags,
// returning the raw flag id and the matched user.
func resolveSingleUser(
	ctx context.Context,
	client *apiv1.Client,
	cmd *cobra.Command,
) (uint64, *apiv1.User, error) {
	id, username, err := usernameAndIDFromFlag(cmd)
	if err != nil {
		return 0, nil, err
	}

	resp, err := client.ListUsers(ctx, apiv1.ListUsersParams{
		Name: optString(username),
		ID:   optUint64(id),
	})
	if err != nil {
		return 0, nil, fmt.Errorf("listing users: %w", err)
	}

	if len(resp.Users) != 1 {
		return 0, nil, errMultipleUsersMatch
	}

	return id, &resp.Users[0], nil
}

func init() {
	rootCmd.AddCommand(userCmd)
	userCmd.AddCommand(createUserCmd)
	createUserCmd.Flags().StringP("display-name", "d", "", "Display name")
	createUserCmd.Flags().StringP("email", "e", "", "Email")
	createUserCmd.Flags().StringP("picture-url", "p", "", "Profile picture URL")
	userCmd.AddCommand(listUsersCmd)
	usernameAndIDFlag(listUsersCmd)
	listUsersCmd.Flags().StringP("email", "e", "", "Email")
	userCmd.AddCommand(destroyUserCmd)
	usernameAndIDFlag(destroyUserCmd)
	userCmd.AddCommand(renameUserCmd)
	usernameAndIDFlag(renameUserCmd)
	renameUserCmd.Flags().StringP("new-name", "r", "", "New username")
	mustMarkRequired(renameUserCmd, "new-name")
}

var userCmd = &cobra.Command{
	Use:     "users",
	Short:   "Manage the users of Headscale",
	Aliases: []string{"user"},
}

var createUserCmd = &cobra.Command{
	Use:     "create NAME",
	Short:   "Creates a new user",
	Aliases: []string{"c", cmdNew},
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errMissingParameter
		}

		return nil
	},
	RunE: apiRunE(func(ctx context.Context, client *apiv1.Client, cmd *cobra.Command, args []string) error {
		req := &apiv1.CreateUserReq{Name: apiv1.NewOptString(args[0])}

		if displayName, _ := cmd.Flags().GetString("display-name"); displayName != "" {
			req.DisplayName = apiv1.NewOptString(displayName)
		}

		if email, _ := cmd.Flags().GetString("email"); email != "" {
			req.Email = apiv1.NewOptString(email)
		}

		if pictureURL, _ := cmd.Flags().GetString("picture-url"); pictureURL != "" {
			_, err := url.Parse(pictureURL)
			if err != nil {
				return fmt.Errorf("invalid picture URL: %w", err)
			}

			req.PictureUrl = apiv1.NewOptString(pictureURL)
		}

		resp, err := client.CreateUser(ctx, req)
		if err != nil {
			return fmt.Errorf("creating user: %w", err)
		}

		return printOutput(cmd, resp.User.Value, "User created")
	}),
}

var destroyUserCmd = &cobra.Command{
	Use:     "destroy --identifier ID or --name NAME",
	Short:   "Destroys a user",
	Aliases: []string{cmdDelete},
	RunE: apiRunE(func(ctx context.Context, client *apiv1.Client, cmd *cobra.Command, args []string) error {
		_, user, err := resolveSingleUser(ctx, client, cmd)
		if err != nil {
			return err
		}

		if !confirmAction(cmd, fmt.Sprintf(
			"Do you want to remove the user %q (%d) and any associated preauthkeys?",
			user.Name.Value, user.ID.Value,
		)) {
			return printOutput(cmd, map[string]string{colResult: "User not destroyed"}, "User not destroyed")
		}

		err = client.DeleteUser(ctx, apiv1.DeleteUserParams{ID: user.ID.Value})
		if err != nil {
			return fmt.Errorf("destroying user: %w", err)
		}

		return printOutput(cmd, map[string]string{colResult: "User destroyed"}, "User destroyed")
	}),
}

var listUsersCmd = &cobra.Command{
	Use:     cmdList,
	Short:   "List all the users",
	Aliases: []string{"ls", cmdShow},
	RunE: apiRunE(func(ctx context.Context, client *apiv1.Client, cmd *cobra.Command, args []string) error {
		var params apiv1.ListUsersParams

		id, _ := cmd.Flags().GetInt64("identifier")
		username, _ := cmd.Flags().GetString("name")
		email, _ := cmd.Flags().GetString("email")

		// filter by one param at most
		switch {
		case id > 0:
			params.ID = apiv1.NewOptUint64(uint64(id))
		case username != "":
			params.Name = apiv1.NewOptString(username)
		case email != "":
			params.Email = apiv1.NewOptString(email)
		}

		resp, err := client.ListUsers(ctx, params)
		if err != nil {
			return fmt.Errorf("listing users: %w", err)
		}

		return printListOutput(cmd, resp.Users, func() error {
			rows := make([][]string, 0, len(resp.Users))
			for _, user := range resp.Users {
				rows = append(
					rows,
					[]string{
						strconv.FormatUint(user.ID.Value, util.Base10),
						user.DisplayName.Value,
						user.Name.Value,
						user.Email.Value,
						user.CreatedAt.Value.Format(HeadscaleDateTimeFormat),
					},
				)
			}

			return renderTable([]string{"ID", "Name", "Username", "Email", colCreated}, rows)
		})
	}),
}

var renameUserCmd = &cobra.Command{
	Use:     "rename",
	Short:   "Renames a user",
	Aliases: []string{"mv"},
	RunE: apiRunE(func(ctx context.Context, client *apiv1.Client, cmd *cobra.Command, args []string) error {
		id, _, err := resolveSingleUser(ctx, client, cmd)
		if err != nil {
			return err
		}

		newName, _ := cmd.Flags().GetString("new-name")

		resp, err := client.RenameUser(ctx, apiv1.RenameUserParams{
			OldID:   id,
			NewName: newName,
		})
		if err != nil {
			return fmt.Errorf("renaming user: %w", err)
		}

		return printOutput(cmd, resp.User.Value, "User renamed")
	}),
}
