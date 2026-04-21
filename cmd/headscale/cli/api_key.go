package cli

import (
	"context"
	"fmt"
	"strconv"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
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
		response, err := client.ListApiKeys(ctx, &v1.ListApiKeysRequest{})
		if err != nil {
			return fmt.Errorf("listing api keys: %w", err)
		}

		return printListOutput(cmd, response.GetApiKeys(), func() error {
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

			return pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
		})
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
		expiration, err := expirationFromFlag(cmd)
		if err != nil {
			return err
		}

		response, err := client.CreateApiKey(ctx, &v1.CreateApiKeyRequest{
			Expiration: expiration,
		})
		if err != nil {
			return fmt.Errorf("creating api key: %w", err)
		}

		return printOutput(cmd, response.GetApiKey(), response.GetApiKey())
	}),
}

// apiKeyIDOrPrefix reads --id and --prefix from cmd and validates that
// exactly one is provided.
func apiKeyIDOrPrefix(cmd *cobra.Command) (uint64, string, error) {
	id, _ := cmd.Flags().GetUint64("id")
	prefix, _ := cmd.Flags().GetString("prefix")

	switch {
	case id == 0 && prefix == "":
		return 0, "", fmt.Errorf("either --id or --prefix must be provided: %w", errMissingParameter)
	case id != 0 && prefix != "":
		return 0, "", fmt.Errorf("only one of --id or --prefix can be provided: %w", errMissingParameter)
	}

	return id, prefix, nil
}

var expireAPIKeyCmd = &cobra.Command{
	Use:     "expire",
	Short:   "Expire an ApiKey",
	Aliases: []string{"revoke", "exp", "e"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		id, prefix, err := apiKeyIDOrPrefix(cmd)
		if err != nil {
			return err
		}

		response, err := client.ExpireApiKey(ctx, &v1.ExpireApiKeyRequest{
			Id:     id,
			Prefix: prefix,
		})
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
		id, prefix, err := apiKeyIDOrPrefix(cmd)
		if err != nil {
			return err
		}

		response, err := client.DeleteApiKey(ctx, &v1.DeleteApiKeyRequest{
			Id:     id,
			Prefix: prefix,
		})
		if err != nil {
			return fmt.Errorf("deleting api key: %w", err)
		}

		return printOutput(cmd, response, "Key deleted")
	}),
}
