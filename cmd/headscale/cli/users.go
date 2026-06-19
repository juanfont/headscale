package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
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
	identifier = max(identifier, 0)

	return uint64(identifier), username, nil //nolint:gosec // identifier is clamped to >= 0 above
}

// resolveSingleUser resolves exactly one user from the --name/--id flags,
// returning the raw flag id and the matched user.
func resolveSingleUser(
	ctx context.Context,
	client *clientv1.ClientWithResponses,
	cmd *cobra.Command,
) (uint64, *clientv1.User, error) {
	id, username, err := usernameAndIDFromFlag(cmd)
	if err != nil {
		return 0, nil, err
	}

	params := &clientv1.ListUsersParams{}
	if username != "" {
		params.Name = &username
	}

	if id != 0 {
		idStr := strconv.FormatUint(id, util.Base10)
		params.Id = &idStr
	}

	resp, err := client.ListUsersWithResponse(ctx, params)
	if err != nil {
		return 0, nil, fmt.Errorf("listing users: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return 0, nil, apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
	}

	users := resp.JSON200.Users
	if len(users) != 1 {
		return 0, nil, errMultipleUsersMatch
	}

	return id, &users[0], nil
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
	RunE: clientRunE(func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
		userName := args[0]

		log.Trace().Interface(zf.Client, client).Msg("obtained API client")

		request := clientv1.CreateUserJSONRequestBody{Name: &userName}

		if displayName, _ := cmd.Flags().GetString("display-name"); displayName != "" {
			request.DisplayName = &displayName
		}

		if email, _ := cmd.Flags().GetString("email"); email != "" {
			request.Email = &email
		}

		if pictureURL, _ := cmd.Flags().GetString("picture-url"); pictureURL != "" {
			if _, err := url.Parse(pictureURL); err != nil { //nolint:noinlineerr
				return fmt.Errorf("invalid picture URL: %w", err)
			}

			request.PictureUrl = &pictureURL
		}

		log.Trace().Interface(zf.Request, request).Msg("sending CreateUser request")

		resp, err := client.CreateUserWithResponse(ctx, request)
		if err != nil {
			return fmt.Errorf("creating user: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		return printOutput(cmd, resp.JSON200.User, "User created")
	}),
}

var destroyUserCmd = &cobra.Command{
	Use:     "destroy --identifier ID or --name NAME",
	Short:   "Destroys a user",
	Aliases: []string{cmdDelete},
	RunE: clientRunE(func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
		_, user, err := resolveSingleUser(ctx, client, cmd)
		if err != nil {
			return err
		}

		if !confirmAction(cmd, fmt.Sprintf(
			"Do you want to remove the user %q (%s) and any associated preauthkeys?",
			user.Name, user.Id,
		)) {
			return printOutput(cmd, map[string]string{colResult: "User not destroyed"}, "User not destroyed")
		}

		resp, err := client.DeleteUserWithResponse(ctx, user.Id)
		if err != nil {
			return fmt.Errorf("destroying user: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		return printOutput(cmd, resp.JSON200, "User destroyed")
	}),
}

var listUsersCmd = &cobra.Command{
	Use:     cmdList,
	Short:   "List all the users",
	Aliases: []string{"ls", cmdShow},
	RunE: clientRunE(func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
		params := &clientv1.ListUsersParams{}

		id, _ := cmd.Flags().GetInt64("identifier")
		username, _ := cmd.Flags().GetString("name")
		email, _ := cmd.Flags().GetString("email")

		// filter by one param at most
		switch {
		case id > 0:
			idStr := strconv.FormatInt(id, util.Base10)
			params.Id = &idStr
		case username != "":
			params.Name = &username
		case email != "":
			params.Email = &email
		}

		resp, err := client.ListUsersWithResponse(ctx, params)
		if err != nil {
			return fmt.Errorf("listing users: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		users := resp.JSON200.Users

		return printListOutput(cmd, users, func() error {
			rows := make([][]string, 0, len(users))
			for _, user := range users {
				rows = append(
					rows,
					[]string{
						user.Id,
						user.DisplayName,
						user.Name,
						user.Email,
						user.CreatedAt.Format(HeadscaleDateTimeFormat),
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
	RunE: clientRunE(func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
		id, _, err := resolveSingleUser(ctx, client, cmd)
		if err != nil {
			return err
		}

		newName, _ := cmd.Flags().GetString("new-name")

		resp, err := client.RenameUserWithResponse(ctx, strconv.FormatUint(id, util.Base10), newName)
		if err != nil {
			return fmt.Errorf("renaming user: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		return printOutput(cmd, resp.JSON200.User, "User renamed")
	}),
}
