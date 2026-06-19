package cli

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/spf13/cobra"
)

const (
	DefaultPreAuthKeyExpiry = "1h"
)

func init() {
	rootCmd.AddCommand(preauthkeysCmd)
	preauthkeysCmd.AddCommand(listPreAuthKeys)
	preauthkeysCmd.AddCommand(createPreAuthKeyCmd)
	preauthkeysCmd.AddCommand(expirePreAuthKeyCmd)
	preauthkeysCmd.AddCommand(deletePreAuthKeyCmd)
	createPreAuthKeyCmd.PersistentFlags().
		Bool("reusable", false, "Make the preauthkey reusable")
	createPreAuthKeyCmd.PersistentFlags().
		Bool("ephemeral", false, "Preauthkey for ephemeral nodes")
	createPreAuthKeyCmd.Flags().
		StringP("expiration", "e", DefaultPreAuthKeyExpiry, "Human-readable expiration of the key (e.g. 30m, 24h)")
	createPreAuthKeyCmd.Flags().
		StringSlice("tags", []string{}, "Tags to automatically assign to node")
	createPreAuthKeyCmd.PersistentFlags().Uint64P("user", "u", 0, "User identifier (ID)")
	expirePreAuthKeyCmd.PersistentFlags().Uint64P("id", "i", 0, "Authkey ID")
	deletePreAuthKeyCmd.PersistentFlags().Uint64P("id", "i", 0, "Authkey ID")
}

var preauthkeysCmd = &cobra.Command{
	Use:     "preauthkeys",
	Short:   "Handle the preauthkeys in Headscale",
	Aliases: []string{"preauthkey", "authkey", "pre"},
}

var listPreAuthKeys = &cobra.Command{
	Use:     cmdList,
	Short:   "List all preauthkeys",
	Aliases: []string{"ls", cmdShow},
	RunE: clientRunE(func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
		resp, err := client.ListPreAuthKeysWithResponse(ctx)
		if err != nil {
			return fmt.Errorf("listing preauthkeys: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		preAuthKeys := resp.JSON200.PreAuthKeys

		return printListOutput(cmd, preAuthKeys, func() error {
			rows := make([][]string, 0, len(preAuthKeys))
			for _, key := range preAuthKeys {
				expiration := ColourTime(key.Expiration)

				owner := "-"

				switch {
				case len(key.AclTags) > 0:
					owner = strings.Join(key.AclTags, "\n")
				case key.User.Id != "":
					owner = key.User.Name
				}

				rows = append(rows, []string{
					key.Id,
					key.Key,
					strconv.FormatBool(key.Reusable),
					strconv.FormatBool(key.Ephemeral),
					strconv.FormatBool(key.Used),
					expiration,
					key.CreatedAt.Format(HeadscaleDateTimeFormat),
					owner,
				})
			}

			return renderTable([]string{
				"ID",
				"Key/Prefix",
				"Reusable",
				"Ephemeral",
				"Used",
				colExpiration,
				colCreated,
				"Owner",
			}, rows)
		})
	}),
}

var createPreAuthKeyCmd = &cobra.Command{
	Use:     "create",
	Short:   "Creates a new preauthkey",
	Aliases: []string{"c", cmdNew},
	RunE: clientRunE(func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
		user, _ := cmd.Flags().GetUint64("user")
		reusable, _ := cmd.Flags().GetBool("reusable")
		ephemeral, _ := cmd.Flags().GetBool("ephemeral")
		tags, _ := cmd.Flags().GetStringSlice("tags")

		expiryTime, err := expirationFromFlag(cmd)
		if err != nil {
			return err
		}

		userStr := strconv.FormatUint(user, util.Base10)

		request := clientv1.CreatePreAuthKeyJSONRequestBody{
			User:       &userStr,
			Reusable:   &reusable,
			Ephemeral:  &ephemeral,
			AclTags:    &tags,
			Expiration: &expiryTime,
		}

		resp, err := client.CreatePreAuthKeyWithResponse(ctx, request)
		if err != nil {
			return fmt.Errorf("creating preauthkey: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		preAuthKey := resp.JSON200.PreAuthKey

		return printOutput(cmd, preAuthKey, preAuthKey.Key)
	}),
}

// preAuthKeyID reads the required --id flag for preauthkey commands.
func preAuthKeyID(cmd *cobra.Command) (uint64, error) {
	id, _ := cmd.Flags().GetUint64("id")
	if id == 0 {
		return 0, fmt.Errorf("missing --id parameter: %w", errMissingParameter)
	}

	return id, nil
}

var expirePreAuthKeyCmd = &cobra.Command{
	Use:     cmdExpire,
	Short:   "Expire a preauthkey",
	Aliases: []string{"revoke", aliasExp, "e"},
	RunE: clientRunE(func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
		id, err := preAuthKeyID(cmd)
		if err != nil {
			return err
		}

		idStr := strconv.FormatUint(id, util.Base10)

		resp, err := client.ExpirePreAuthKeyWithResponse(ctx, clientv1.ExpirePreAuthKeyJSONRequestBody{
			Id: &idStr,
		})
		if err != nil {
			return fmt.Errorf("expiring preauthkey: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		return printOutput(cmd, resp.JSON200, "Key expired")
	}),
}

var deletePreAuthKeyCmd = &cobra.Command{
	Use:     cmdDelete,
	Short:   "Delete a preauthkey",
	Aliases: []string{aliasDel, "rm", "d"},
	RunE: clientRunE(func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error {
		id, err := preAuthKeyID(cmd)
		if err != nil {
			return err
		}

		idStr := strconv.FormatUint(id, util.Base10)

		resp, err := client.DeletePreAuthKeyWithResponse(ctx, &clientv1.DeletePreAuthKeyParams{
			Id: &idStr,
		})
		if err != nil {
			return fmt.Errorf("deleting preauthkey: %w", err)
		}

		if resp.StatusCode() != http.StatusOK {
			return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
		}

		return printOutput(cmd, resp.JSON200, "Key deleted")
	}),
}
