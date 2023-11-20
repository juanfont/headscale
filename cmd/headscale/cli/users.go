package cli

import (
	"errors"
	"fmt"

	survey "github.com/AlecAivazis/survey/v2"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/pterm/pterm"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
)

func init() {
	rootCmd.AddCommand(userCmd)
	userCmd.AddCommand(createUserCmd)
	userCmd.AddCommand(listUsersCmd)
	userCmd.AddCommand(destroyUserCmd)
	userCmd.AddCommand(renameUserCmd)
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
		output, _ := cmd.Flags().GetString("output")

		userName := args[0]

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		log.Trace().Interface("client", client).Msg("Obtained gRPC client")

		request := &v1.CreateUserRequest{Name: userName}

		log.Trace().Interface("request", request).Msg("Sending CreateUser request")
		response, err := client.CreateUser(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf(
					"Cannot create user: %s",
					status.Convert(err).Message(),
				),
				output,
			)

			return
		}

		SuccessOutput(response.GetUser(), "User created", output)
	},
}

var destroyUserCmd = &cobra.Command{
	Use:     "destroy NAME",
	Short:   "Destroys a user",
	Aliases: []string{"delete"},
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errMissingParameter
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		userName := args[0]

		request := &v1.GetUserRequest{
			Name: userName,
		}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		_, err := client.GetUser(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error: %s", status.Convert(err).Message()),
				output,
			)

			return
		}

		confirm := false
		force, _ := cmd.Flags().GetBool("force")
		if !force {
			prompt := &survey.Confirm{
				Message: fmt.Sprintf(
					"Do you want to remove the user '%s' and any associated preauthkeys?",
					userName,
				),
			}
			err := survey.AskOne(prompt, &confirm)
			if err != nil {
				return
			}
		}

		if confirm || force {
			request := &v1.DeleteUserRequest{Name: userName}

			response, err := client.DeleteUser(ctx, request)
			if err != nil {
				ErrorOutput(
					err,
					fmt.Sprintf(
						"Cannot destroy user: %s",
						status.Convert(err).Message(),
					),
					output,
				)

				return
			}
			SuccessOutput(response, "User destroyed", output)
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
		output, _ := cmd.Flags().GetString("output")

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		request := &v1.ListUsersRequest{}

		response, err := client.ListUsers(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot get users: %s", status.Convert(err).Message()),
				output,
			)

			return
		}

		if output != "" {
			SuccessOutput(response.GetUsers(), "", output)

			return
		}

		tableData := pterm.TableData{{"ID", "Name", "Created"}}
		for _, user := range response.GetUsers() {
			tableData = append(
				tableData,
				[]string{
					user.GetId(),
					user.GetName(),
					user.GetCreatedAt().AsTime().Format("2006-01-02 15:04:05"),
				},
			)
		}
		err = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Failed to render pterm table: %s", err),
				output,
			)

			return
		}
	},
}

var renameUserCmd = &cobra.Command{
	Use:     "rename OLD_NAME NEW_NAME",
	Short:   "Renames a user",
	Aliases: []string{"mv"},
	Args: func(cmd *cobra.Command, args []string) error {
		expectedArguments := 2
		if len(args) < expectedArguments {
			return errMissingParameter
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		request := &v1.RenameUserRequest{
			OldName: args[0],
			NewName: args[1],
		}

		response, err := client.RenameUser(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf(
					"Cannot rename user: %s",
					status.Convert(err).Message(),
				),
				output,
			)

			return
		}

		SuccessOutput(response.GetUser(), "User renamed", output)
	},
}
