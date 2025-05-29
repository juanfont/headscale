package cli

import (
	"context"
	"errors"
	"fmt"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
)

// usernameAndIDFlag adds the common user identification flags to a command
func usernameAndIDFlag(cmd *cobra.Command, opts ...string) {
	idHelp := "User identifier (ID)"
	nameHelp := "Username"

	if len(opts) > 0 && opts[0] != "" {
		idHelp = opts[0]
	}
	if len(opts) > 1 && opts[1] != "" {
		nameHelp = opts[1]
	}
	cmd.PersistentFlags().Int64P("identifier", "i", -1, idHelp)
	cmd.PersistentFlags().StringP("name", "n", "", nameHelp)
}

// usernameAndIDFromFlag returns the username and ID from the flags of the command.
// If both are empty, it will exit the program with an error.
func usernameAndIDFromFlag(cmd *cobra.Command) (uint64, string) {
	username, _ := cmd.Flags().GetString("name")
	identifier, _ := cmd.Flags().GetInt64("identifier")
	if username == "" && identifier < 0 {
		err := errors.New("--name or --identifier flag is required")
		ErrorOutput(
			err,
			fmt.Sprintf(
				"User identification error: %s",
				status.Convert(err).Message(),
			),
			"",
		)
	}

	return uint64(identifier), username
}

// findSingleUser takes command flags and returns a single user
// It handles all error checking and ensures exactly one user is found
func findSingleUser(
	ctx context.Context,
	client v1.HeadscaleServiceClient,
	cmd *cobra.Command,
	operationName string,
	output string,
) (*v1.User, error) {
	id, username := usernameAndIDFromFlag(cmd)
	listReq := &v1.ListUsersRequest{
		Name: username,
		Id:   id,
	}

	users, err := client.ListUsers(ctx, listReq)
	if err != nil {
		ErrorOutput(
			err,
			fmt.Sprintf("Error: %s", status.Convert(err).Message()),
			output,
		)
		return nil, err
	}

	if len(users.GetUsers()) != 1 {
		err := fmt.Errorf("Unable to determine user to %s, query returned multiple users, use ID", operationName)
		ErrorOutput(
			err,
			fmt.Sprintf("Error: %s", status.Convert(err).Message()),
			output,
		)
		return nil, err
	}

	return users.GetUsers()[0], nil
}
