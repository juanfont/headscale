package cli

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/pterm/pterm"
	"github.com/rs/zerolog/log"
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
	if identifier < 0 {
		identifier = 0
	}

	return uint64(identifier), username, nil //nolint:gosec // identifier is clamped to >= 0 above
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
	Aliases: []string{"c", "new"},
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errMissingParameter
		}

		return nil
	},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		userName := args[0]

		log.Trace().Interface(zf.Client, client).Msg("obtained gRPC client")

		request := &v1.CreateUserRequest{Name: userName}

		if displayName, _ := cmd.Flags().GetString("display-name"); displayName != "" {
			request.DisplayName = displayName
		}

		if email, _ := cmd.Flags().GetString("email"); email != "" {
			request.Email = email
		}

		if pictureURL, _ := cmd.Flags().GetString("picture-url"); pictureURL != "" {
			if _, err := url.Parse(pictureURL); err != nil { //nolint:noinlineerr
				return fmt.Errorf("invalid picture URL: %w", err)
			}

			request.PictureUrl = pictureURL
		}

		log.Trace().Interface(zf.Request, request).Msg("sending CreateUser request")

		response, err := client.CreateUser(ctx, request)
		if err != nil {
			return fmt.Errorf("creating user: %w", err)
		}

		return printOutput(cmd, response.GetUser(), "User created")
	}),
}

var destroyUserCmd = &cobra.Command{
	Use:     "destroy --identifier ID or --name NAME",
	Short:   "Destroys a user",
	Aliases: []string{"delete"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		id, username, err := usernameAndIDFromFlag(cmd)
		if err != nil {
			return err
		}

		request := &v1.ListUsersRequest{
			Name: username,
			Id:   id,
		}

		users, err := client.ListUsers(ctx, request)
		if err != nil {
			return fmt.Errorf("listing users: %w", err)
		}

		if len(users.GetUsers()) != 1 {
			return errMultipleUsersMatch
		}

		user := users.GetUsers()[0]

		if !confirmAction(cmd, fmt.Sprintf(
			"Do you want to remove the user %q (%d) and any associated preauthkeys?",
			user.GetName(), user.GetId(),
		)) {
			return printOutput(cmd, map[string]string{"Result": "User not destroyed"}, "User not destroyed")
		}

		deleteRequest := &v1.DeleteUserRequest{Id: user.GetId()}

		response, err := client.DeleteUser(ctx, deleteRequest)
		if err != nil {
			return fmt.Errorf("destroying user: %w", err)
		}

		return printOutput(cmd, response, "User destroyed")
	}),
}

var listUsersCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all the users",
	Aliases: []string{"ls", "show"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		request := &v1.ListUsersRequest{}

		id, _ := cmd.Flags().GetInt64("identifier")
		username, _ := cmd.Flags().GetString("name")
		email, _ := cmd.Flags().GetString("email")

		// filter by one param at most
		switch {
		case id > 0:
			request.Id = uint64(id)
		case username != "":
			request.Name = username
		case email != "":
			request.Email = email
		}

		response, err := client.ListUsers(ctx, request)
		if err != nil {
			return fmt.Errorf("listing users: %w", err)
		}

		return printListOutput(cmd, response.GetUsers(), func() error {
			tableData := pterm.TableData{{"ID", "Name", "Username", "Email", "Created"}}
			for _, user := range response.GetUsers() {
				tableData = append(
					tableData,
					[]string{
						strconv.FormatUint(user.GetId(), util.Base10),
						user.GetDisplayName(),
						user.GetName(),
						user.GetEmail(),
						user.GetCreatedAt().AsTime().Format(HeadscaleDateTimeFormat),
					},
				)
			}

			return pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
		})
	}),
}

var renameUserCmd = &cobra.Command{
	Use:     "rename",
	Short:   "Renames a user",
	Aliases: []string{"mv"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		id, username, err := usernameAndIDFromFlag(cmd)
		if err != nil {
			return err
		}

		listReq := &v1.ListUsersRequest{
			Name: username,
			Id:   id,
		}

		users, err := client.ListUsers(ctx, listReq)
		if err != nil {
			return fmt.Errorf("listing users: %w", err)
		}

		if len(users.GetUsers()) != 1 {
			return errMultipleUsersMatch
		}

		newName, _ := cmd.Flags().GetString("new-name")

		renameReq := &v1.RenameUserRequest{
			OldId:   id,
			NewName: newName,
		}

		response, err := client.RenameUser(ctx, renameReq)
		if err != nil {
			return fmt.Errorf("renaming user: %w", err)
		}

		return printOutput(cmd, response.GetUser(), "User renamed")
	}),
}
