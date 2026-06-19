package cli

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	"github.com/juanfont/headscale/hscontrol/util"
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
	Use:     cmdList,
	Short:   "List the Api keys for headscale",
	Aliases: []string{"ls", cmdShow},
	RunE: clientRunE(func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
		resp, err := client.ListApiKeysWithResponse(ctx)
		if err != nil {
			return fmt.Errorf("listing api keys: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		apiKeys := resp.JSON200.ApiKeys

		return printListOutput(cmd, apiKeys, func() error {
			rows := make([][]string, 0, len(apiKeys))
			for _, key := range apiKeys {
				expiration := "-"
				if key.Expiration != nil {
					expiration = ColourTime(*key.Expiration)
				}

				var created string
				if key.CreatedAt != nil {
					created = key.CreatedAt.Format(HeadscaleDateTimeFormat)
				}

				rows = append(rows, []string{
					key.Id,
					key.Prefix,
					expiration,
					created,
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
	RunE: clientRunE(func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
		expiryTime, err := expirationFromFlag(cmd)
		if err != nil {
			return err
		}

		resp, err := client.CreateApiKeyWithResponse(ctx, clientv1.CreateApiKeyJSONRequestBody{
			Expiration: &expiryTime,
		})
		if err != nil {
			return fmt.Errorf("creating api key: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		return printOutput(cmd, resp.JSON200.ApiKey, resp.JSON200.ApiKey)
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
	RunE: clientRunE(func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
		id, prefix, err := apiKeyIDOrPrefix(cmd)
		if err != nil {
			return err
		}

		body := clientv1.ExpireApiKeyJSONRequestBody{}

		if id != 0 {
			idStr := strconv.FormatUint(id, util.Base10)
			body.Id = &idStr
		}

		if prefix != "" {
			body.Prefix = &prefix
		}

		resp, err := client.ExpireApiKeyWithResponse(ctx, body)
		if err != nil {
			return fmt.Errorf("expiring api key: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		return printOutput(cmd, resp.JSON200, "Key expired")
	}),
}

var deleteAPIKeyCmd = &cobra.Command{
	Use:     cmdDelete,
	Short:   "Delete an ApiKey",
	Aliases: []string{"remove", aliasDel},
	RunE: clientRunE(func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
		id, prefix, err := apiKeyIDOrPrefix(cmd)
		if err != nil {
			return err
		}

		// The DELETE route addresses the key by its prefix in the path. When the
		// user deletes by --id we resolve the id to its (masked) prefix first,
		// since the path segment is required and a query-only id cannot be routed.
		if prefix == "" {
			prefix, err = apiKeyPrefixForID(ctx, client, id)
			if err != nil {
				return err
			}
		}

		resp, err := client.DeleteApiKeyWithResponse(ctx, prefix, &clientv1.DeleteApiKeyParams{})
		if err != nil {
			return fmt.Errorf("deleting api key: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		return printOutput(cmd, resp.JSON200, "Key deleted")
	}),
}

// apiKeyPrefixForID resolves an API key id to its display prefix by listing the
// keys. The DELETE endpoint addresses keys by prefix in the URL path, so a
// delete by --id needs the prefix; the returned masked prefix is accepted by
// the server's lookup.
func apiKeyPrefixForID(
	ctx context.Context,
	client *clientv1.ClientWithResponses,
	id uint64,
) (string, error) {
	resp, err := client.ListApiKeysWithResponse(ctx)
	if err != nil {
		return "", fmt.Errorf("listing api keys: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return "", apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
	}

	idStr := strconv.FormatUint(id, util.Base10)
	for _, key := range resp.JSON200.ApiKeys {
		if key.Id == idStr {
			return key.Prefix, nil
		}
	}

	return "", fmt.Errorf("%w: api key %d not found", errMissingParameter, id)
}
