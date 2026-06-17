package cli

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	apiv1 "github.com/juanfont/headscale/gen/api/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/spf13/cobra"
)

const (
	// DefaultAPIKeyExpiry is 90 days.
	DefaultAPIKeyExpiry = "90d"
)

var errAPIKeyIDNotFound = errors.New("no api key with id")

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
	Use:     cmdList,
	Short:   "List the Api keys for headscale",
	Aliases: []string{"ls", cmdShow},
	RunE: apiRunE(func(ctx context.Context, client *apiv1.Client, cmd *cobra.Command, args []string) error {
		resp, err := client.ListApiKeys(ctx)
		if err != nil {
			return fmt.Errorf("listing api keys: %w", err)
		}

		return printListOutput(cmd, resp.ApiKeys, func() error {
			rows := make([][]string, 0, len(resp.ApiKeys))
			for _, key := range resp.ApiKeys {
				expiration := "-"

				if key.Expiration.Set {
					expiration = ColourTime(key.Expiration.Value)
				}

				rows = append(rows, []string{
					strconv.FormatUint(key.ID.Value, util.Base10),
					key.Prefix.Value,
					expiration,
					key.CreatedAt.Value.Format(HeadscaleDateTimeFormat),
				})
			}

			return renderTable([]string{"ID", "Prefix", colExpiration, colCreated}, rows)
		})
	}),
}

var createAPIKeyCmd = &cobra.Command{
	Use:   "create",
	Short: "Creates a new Api key",
	Long: `
Creates a new Api key, the Api key is only visible on creation
and cannot be retrieved again.
If you lose a key, create a new one and revoke (expire) the old one.`,
	Aliases: []string{"c", cmdNew},
	RunE: apiRunE(func(ctx context.Context, client *apiv1.Client, cmd *cobra.Command, args []string) error {
		expiration, err := expirationFromFlag(cmd)
		if err != nil {
			return err
		}

		resp, err := client.CreateApiKey(ctx, &apiv1.CreateApiKeyReq{
			Expiration: expiration,
		})
		if err != nil {
			return fmt.Errorf("creating api key: %w", err)
		}

		return printOutput(cmd, resp.ApiKey.Value, resp.ApiKey.Value)
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
	Use:     cmdExpire,
	Short:   "Expire an ApiKey",
	Aliases: []string{"revoke", aliasExp, "e"},
	RunE: apiRunE(func(ctx context.Context, client *apiv1.Client, cmd *cobra.Command, args []string) error {
		id, prefix, err := apiKeyIDOrPrefix(cmd)
		if err != nil {
			return err
		}

		err = client.ExpireApiKey(ctx, &apiv1.ExpireApiKeyReq{
			ID:     optUint64(id),
			Prefix: optString(prefix),
		})
		if err != nil {
			return fmt.Errorf("expiring api key: %w", err)
		}

		return printOutput(cmd, map[string]string{colResult: "Key expired"}, "Key expired")
	}),
}

var deleteAPIKeyCmd = &cobra.Command{
	Use:     cmdDelete,
	Short:   "Delete an ApiKey",
	Aliases: []string{"remove", aliasDel},
	RunE: apiRunE(func(ctx context.Context, client *apiv1.Client, cmd *cobra.Command, args []string) error {
		id, prefix, err := apiKeyIDOrPrefix(cmd)
		if err != nil {
			return err
		}

		// Delete is routed by prefix in the path, so resolve an --id to its
		// prefix first; an empty path segment would 404 at the router.
		if prefix == "" {
			prefix, err = apiKeyPrefixByID(ctx, client, id)
			if err != nil {
				return err
			}
		}

		err = client.DeleteApiKey(ctx, apiv1.DeleteApiKeyParams{Prefix: prefix})
		if err != nil {
			return fmt.Errorf("deleting api key: %w", err)
		}

		return printOutput(cmd, map[string]string{colResult: "Key deleted"}, "Key deleted")
	}),
}

// apiKeyPrefixByID looks up an API key's prefix by its numeric ID.
func apiKeyPrefixByID(ctx context.Context, client *apiv1.Client, id uint64) (string, error) {
	resp, err := client.ListApiKeys(ctx)
	if err != nil {
		return "", fmt.Errorf("listing api keys: %w", err)
	}

	for _, key := range resp.GetApiKeys() {
		if key.GetID().Or(0) == id {
			return key.GetPrefix().Or(""), nil
		}
	}

	return "", fmt.Errorf("%w: %d", errAPIKeyIDNotFound, id)
}
