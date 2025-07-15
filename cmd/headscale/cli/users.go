package cli

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	survey "github.com/AlecAivazis/survey/v2"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/pterm/pterm"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
)

func usernameAndIDFlag(cmd *cobra.Command) {
	cmd.Flags().StringP("user", "u", "", "User identifier (ID, name, or email)")
	cmd.Flags().Uint64P("identifier", "i", 0, "User identifier (ID) - deprecated, use --user")
	identifierFlag := cmd.Flags().Lookup("identifier")
	identifierFlag.Deprecated = "use --user"
	identifierFlag.Hidden = true
	cmd.Flags().StringP("name", "n", "", "Username")
}

// usernameAndIDFromFlag returns the user ID using smart lookup.
// If no user is specified, it will exit the program with an error.
func usernameAndIDFromFlag(cmd *cobra.Command) (uint64, string) {
	userID, err := GetUserIdentifier(cmd)
	if err != nil {
		ErrorOutput(
			err,
			"Cannot identify user: "+err.Error(),
			GetOutputFlag(cmd),
		)
	}

	return userID, ""
}

func init() {
	rootCmd.AddCommand(userCmd)
	userCmd.AddCommand(createUserCmd)
	createUserCmd.Flags().StringP("display-name", "d", "", "Display name")
	createUserCmd.Flags().StringP("email", "e", "", "Email")
	createUserCmd.Flags().StringP("picture-url", "p", "", "Profile picture URL")
	userCmd.AddCommand(listUsersCmd)
	// Smart lookup filters - can be used individually or combined
	listUsersCmd.Flags().StringP("user", "u", "", "Filter by user (ID, name, or email)")
	listUsersCmd.Flags().Uint64P("id", "", 0, "Filter by user ID")
	listUsersCmd.Flags().StringP("name", "n", "", "Filter by username")
	listUsersCmd.Flags().StringP("email", "e", "", "Filter by email address")
	// Backward compatibility (deprecated)
	listUsersCmd.Flags().Uint64P("identifier", "i", 0, "Filter by user ID - deprecated, use --id")
	identifierFlag := listUsersCmd.Flags().Lookup("identifier")
	identifierFlag.Deprecated = "use --id"
	identifierFlag.Hidden = true
	listUsersCmd.Flags().String("columns", "", "Comma-separated list of columns to display (ID,Name,Username,Email,Created)")
	userCmd.AddCommand(destroyUserCmd)
	usernameAndIDFlag(destroyUserCmd)
	userCmd.AddCommand(renameUserCmd)
	usernameAndIDFlag(renameUserCmd)
	renameUserCmd.Flags().StringP("new-name", "r", "", "New username")
	renameUserCmd.MarkFlagRequired("new-name")
}

var errMissingParameter = errors.New("missing parameters")

var userCmd = &cobra.Command{
	Use:     "users",
	Short:   "Manage the users of Headscale",
	Aliases: []string{"user", "namespace", "namespaces", "ns"},
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
	Run: func(cmd *cobra.Command, args []string) {
		output := GetOutputFlag(cmd)
		userName := args[0]

		request := &v1.CreateUserRequest{Name: userName}

		if displayName, _ := cmd.Flags().GetString("display-name"); displayName != "" {
			request.DisplayName = displayName
		}

		if email, _ := cmd.Flags().GetString("email"); email != "" {
			request.Email = email
		}

		if pictureURL, _ := cmd.Flags().GetString("picture-url"); pictureURL != "" {
			if _, err := url.Parse(pictureURL); err != nil {
				ErrorOutput(
					err,
					fmt.Sprintf(
						"Invalid Picture URL: %s",
						err,
					),
					output,
				)
				return
			}
			request.PictureUrl = pictureURL
		}

		err := WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
			log.Trace().Interface("client", client).Msg("Obtained gRPC client")
			log.Trace().Interface("request", request).Msg("Sending CreateUser request")
			
			response, err := client.CreateUser(ctx, request)
			if err != nil {
				ErrorOutput(
					err,
					"Cannot create user: "+status.Convert(err).Message(),
					output,
				)
				return err
			}

			SuccessOutput(response.GetUser(), "User created", output)
			return nil
		})
		
		if err != nil {
			return
		}
	},
}

var destroyUserCmd = &cobra.Command{
	Use:     "destroy --identifier ID or --name NAME",
	Short:   "Destroys a user",
	Aliases: []string{"delete"},
	Run: func(cmd *cobra.Command, args []string) {
		output := GetOutputFlag(cmd)

		id, username := usernameAndIDFromFlag(cmd)
		request := &v1.ListUsersRequest{
			Name: username,
			Id:   id,
		}

		var user *v1.User
		err := WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
			users, err := client.ListUsers(ctx, request)
			if err != nil {
				ErrorOutput(
					err,
					"Error: "+status.Convert(err).Message(),
					output,
				)
				return err
			}

			if len(users.GetUsers()) != 1 {
				err := errors.New("Unable to determine user to delete, query returned multiple users, use ID")
				ErrorOutput(
					err,
					"Error: "+status.Convert(err).Message(),
					output,
				)
				return err
			}

			user = users.GetUsers()[0]
			return nil
		})
		
		if err != nil {
			return
		}

		confirm := false
		force, _ := cmd.Flags().GetBool("force")
		if !force {
			prompt := &survey.Confirm{
				Message: fmt.Sprintf(
					"Do you want to remove the user %q (%d) and any associated preauthkeys?",
					user.GetName(), user.GetId(),
				),
			}
			err := survey.AskOne(prompt, &confirm)
			if err != nil {
				return
			}
		}

		if confirm || force {
			err = WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
				request := &v1.DeleteUserRequest{Id: user.GetId()}

				response, err := client.DeleteUser(ctx, request)
				if err != nil {
					ErrorOutput(
						err,
						"Cannot destroy user: "+status.Convert(err).Message(),
						output,
					)
					return err
				}
				SuccessOutput(response, "User destroyed", output)
				return nil
			})
			
			if err != nil {
				return
			}
		} else {
			SuccessOutput(map[string]string{"Result": "User not destroyed"}, "User not destroyed", output)
		}
	},
}

var listUsersCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all the users",
	Aliases: []string{"ls", "show"},
	Run: func(cmd *cobra.Command, args []string) {
		output := GetOutputFlag(cmd)

		err := WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
			request := &v1.ListUsersRequest{}

			// Check for smart lookup flag first
			userFlag, _ := cmd.Flags().GetString("user")
			if userFlag != "" {
				// Use smart lookup to determine filter type
				if id, err := strconv.ParseUint(userFlag, 10, 64); err == nil && id > 0 {
					request.Id = id
				} else if strings.Contains(userFlag, "@") {
					request.Email = userFlag
				} else {
					request.Name = userFlag
				}
			} else {
				// Check specific filter flags
				if id, _ := cmd.Flags().GetUint64("id"); id > 0 {
					request.Id = id
				} else if identifier, _ := cmd.Flags().GetUint64("identifier"); identifier > 0 {
					request.Id = identifier // backward compatibility
				} else if name, _ := cmd.Flags().GetString("name"); name != "" {
					request.Name = name
				} else if email, _ := cmd.Flags().GetString("email"); email != "" {
					request.Email = email
				}
			}

			response, err := client.ListUsers(ctx, request)
			if err != nil {
				ErrorOutput(
					err,
					"Cannot get users: "+status.Convert(err).Message(),
					output,
				)
				return err
			}

			if output != "" {
				SuccessOutput(response.GetUsers(), "", output)
				return nil
			}

			tableData := pterm.TableData{{"ID", "Name", "Username", "Email", "Created"}}
			for _, user := range response.GetUsers() {
				tableData = append(
					tableData,
					[]string{
						strconv.FormatUint(user.GetId(), 10),
						user.GetDisplayName(),
						user.GetName(),
						user.GetEmail(),
						user.GetCreatedAt().AsTime().Format(HeadscaleDateTimeFormat),
					},
				)
			}
			tableData = FilterTableColumns(cmd, tableData)
			err = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
			if err != nil {
				ErrorOutput(
					err,
					fmt.Sprintf("Failed to render pterm table: %s", err),
					output,
				)
				return err
			}
			return nil
		})
		
		if err != nil {
			// Error already handled in closure
			return
		}
	},
}

var renameUserCmd = &cobra.Command{
	Use:     "rename",
	Short:   "Renames a user",
	Aliases: []string{"mv"},
	Run: func(cmd *cobra.Command, args []string) {
		output := GetOutputFlag(cmd)

		id, username := usernameAndIDFromFlag(cmd)
		newName, _ := cmd.Flags().GetString("new-name")
		
		err := WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
			listReq := &v1.ListUsersRequest{
				Name: username,
				Id:   id,
			}

			users, err := client.ListUsers(ctx, listReq)
			if err != nil {
				ErrorOutput(
					err,
					"Error: "+status.Convert(err).Message(),
					output,
				)
				return err
			}

			if len(users.GetUsers()) != 1 {
				err := errors.New("Unable to determine user to delete, query returned multiple users, use ID")
				ErrorOutput(
					err,
					"Error: "+status.Convert(err).Message(),
					output,
				)
				return err
			}

			renameReq := &v1.RenameUserRequest{
				OldId:   id,
				NewName: newName,
			}

			response, err := client.RenameUser(ctx, renameReq)
			if err != nil {
				ErrorOutput(
					err,
					"Cannot rename user: "+status.Convert(err).Message(),
					output,
				)
				return err
			}

			SuccessOutput(response.GetUser(), "User renamed", output)
			return nil
		})
		
		if err != nil {
			return
		}
	},
}
