package cli

import (
	"context"
	"fmt"
	"strconv"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/prometheus/common/model"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// DefaultAPIKeyExpiry is 90 days.
	DefaultAPIKeyExpiry = "90d"
)

func init() {
	rootCmd.AddCommand(apiKeysCmd)
	apiKeysCmd.AddCommand(listAPIKeys)

	createAPIKeyCmd.Flags().
		StringP("expiration", "e", DefaultAPIKeyExpiry, "Human-readable expiration of the key (e.g. 30m, 24h)")

	apiKeysCmd.AddCommand(createAPIKeyCmd)

	expireAPIKeyCmd.Flags().StringP("prefix", "p", "", "ApiKey prefix")
	expireAPIKeyCmd.Flags().Uint64P("id", "i", 0, "ApiKey ID")
	apiKeysCmd.AddCommand(expireAPIKeyCmd)

	deleteAPIKeyCmd.Flags().StringP("prefix", "p", "", "ApiKey prefix")
	deleteAPIKeyCmd.Flags().Uint64P("id", "i", 0, "ApiKey ID")
	apiKeysCmd.AddCommand(deleteAPIKeyCmd)
}

var apiKeysCmd = &cobra.Command{
	Use:     "apikeys",
	Short:   "Handle the Api keys in Headscale",
	Aliases: []string{"apikey", "api"},
}

var listAPIKeys = &cobra.Command{
	Use:     "list",
	Short:   "List the Api keys for headscale",
	Aliases: []string{"ls", "show"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		format, _ := cmd.Flags().GetString("output")

		request := &v1.ListApiKeysRequest{}

		response, err := client.ListApiKeys(ctx, request)
		if err != nil {
			return fmt.Errorf("listing api keys: %w", err)
		}

		if format != "" {
			return printOutput(cmd, response.GetApiKeys(), "")
		}

		tableData := pterm.TableData{
			{"ID", "Prefix", "Expiration", "Created"},
		}

		for _, key := range response.GetApiKeys() {
			expiration := "-"

			if key.GetExpiration() != nil {
				expiration = ColourTime(key.GetExpiration().AsTime())
			}

			tableData = append(tableData, []string{
				strconv.FormatUint(key.GetId(), util.Base10),
				key.GetPrefix(),
				expiration,
				key.GetCreatedAt().AsTime().Format(HeadscaleDateTimeFormat),
			})
		}

		err = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
		if err != nil {
			return fmt.Errorf("rendering table: %w", err)
		}

		return nil
	}),
}

var createAPIKeyCmd = &cobra.Command{
	Use:   "create",
	Short: "Creates a new Api key",
	Long: `
Creates a new Api key, the Api key is only visible on creation
and cannot be retrieved again.
If you loose a key, create a new one and revoke (expire) the old one.`,
	Aliases: []string{"c", "new"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		request := &v1.CreateApiKeyRequest{}

		durationStr, _ := cmd.Flags().GetString("expiration")

		duration, err := model.ParseDuration(durationStr)
		if err != nil {
			return fmt.Errorf("parsing duration: %w", err)
		}

		expiration := time.Now().UTC().Add(time.Duration(duration))

		request.Expiration = timestamppb.New(expiration)

		response, err := client.CreateApiKey(ctx, request)
		if err != nil {
			return fmt.Errorf("creating api key: %w", err)
		}

		return printOutput(cmd, response.GetApiKey(), response.GetApiKey())
	}),
}

var expireAPIKeyCmd = &cobra.Command{
	Use:     "expire",
	Short:   "Expire an ApiKey",
	Aliases: []string{"revoke", "exp", "e"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetUint64("id")
		prefix, _ := cmd.Flags().GetString("prefix")

		switch {
		case id == 0 && prefix == "":
			return fmt.Errorf("either --id or --prefix must be provided: %w", errMissingParameter)
		case id != 0 && prefix != "":
			return fmt.Errorf("only one of --id or --prefix can be provided: %w", errMissingParameter)
		}

		request := &v1.ExpireApiKeyRequest{}
		if id != 0 {
			request.Id = id
		} else {
			request.Prefix = prefix
		}

		response, err := client.ExpireApiKey(ctx, request)
		if err != nil {
			return fmt.Errorf("expiring api key: %w", err)
		}

		return printOutput(cmd, response, "Key expired")
	}),
}

var deleteAPIKeyCmd = &cobra.Command{
	Use:     "delete",
	Short:   "Delete an ApiKey",
	Aliases: []string{"remove", "del"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetUint64("id")
		prefix, _ := cmd.Flags().GetString("prefix")

		switch {
		case id == 0 && prefix == "":
			return fmt.Errorf("either --id or --prefix must be provided: %w", errMissingParameter)
		case id != 0 && prefix != "":
			return fmt.Errorf("only one of --id or --prefix can be provided: %w", errMissingParameter)
		}

		request := &v1.DeleteApiKeyRequest{}
		if id != 0 {
			request.Id = id
		} else {
			request.Prefix = prefix
		}

		response, err := client.DeleteApiKey(ctx, request)
		if err != nil {
			return fmt.Errorf("deleting api key: %w", err)
		}

		return printOutput(cmd, response, "Key deleted")
	}),
}
