package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	apiv1 "github.com/juanfont/headscale/gen/api/v1"
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
	RunE: apiRunE(func(ctx context.Context, client *apiv1.Client, cmd *cobra.Command, args []string) error {
		resp, err := client.ListPreAuthKeys(ctx)
		if err != nil {
			return fmt.Errorf("listing preauthkeys: %w", err)
		}

		return printListOutput(cmd, resp.PreAuthKeys, func() error {
			rows := make([][]string, 0, len(resp.PreAuthKeys))
			for _, key := range resp.PreAuthKeys {
				expiration := "-"
				if key.Expiration.Set {
					expiration = ColourTime(key.Expiration.Value)
				}

				var owner string

				switch {
				case len(key.AclTags) > 0:
					owner = strings.Join(key.AclTags, "\n")
				case key.User.Set:
					owner = key.User.Value.Name.Value
				default:
					owner = "-"
				}

				rows = append(rows, []string{
					strconv.FormatUint(key.ID.Value, util.Base10),
					key.Key.Value,
					strconv.FormatBool(key.Reusable.Value),
					strconv.FormatBool(key.Ephemeral.Value),
					strconv.FormatBool(key.Used.Value),
					expiration,
					key.CreatedAt.Value.Format(HeadscaleDateTimeFormat),
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
	RunE: apiRunE(func(ctx context.Context, client *apiv1.Client, cmd *cobra.Command, args []string) error {
		user, _ := cmd.Flags().GetUint64("user")
		reusable, _ := cmd.Flags().GetBool("reusable")
		ephemeral, _ := cmd.Flags().GetBool("ephemeral")
		tags, _ := cmd.Flags().GetStringSlice("tags")

		expiration, err := expirationFromFlag(cmd)
		if err != nil {
			return err
		}

		resp, err := client.CreatePreAuthKey(ctx, &apiv1.CreatePreAuthKeyReq{
			User:       optUint64(user),
			Reusable:   apiv1.NewOptBool(reusable),
			Ephemeral:  apiv1.NewOptBool(ephemeral),
			AclTags:    tags,
			Expiration: expiration,
		})
		if err != nil {
			return fmt.Errorf("creating preauthkey: %w", err)
		}

		return printOutput(cmd, resp.PreAuthKey.Value, resp.PreAuthKey.Value.Key.Value)
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
	RunE: apiRunE(func(ctx context.Context, client *apiv1.Client, cmd *cobra.Command, args []string) error {
		id, err := preAuthKeyID(cmd)
		if err != nil {
			return err
		}

		err = client.ExpirePreAuthKey(ctx, &apiv1.ExpirePreAuthKeyReq{ID: apiv1.NewOptUint64(id)})
		if err != nil {
			return fmt.Errorf("expiring preauthkey: %w", err)
		}

		return printOutput(cmd, map[string]string{colResult: "Key expired"}, "Key expired")
	}),
}

var deletePreAuthKeyCmd = &cobra.Command{
	Use:     cmdDelete,
	Short:   "Delete a preauthkey",
	Aliases: []string{aliasDel, "rm", "d"},
	RunE: apiRunE(func(ctx context.Context, client *apiv1.Client, cmd *cobra.Command, args []string) error {
		id, err := preAuthKeyID(cmd)
		if err != nil {
			return err
		}

		err = client.DeletePreAuthKey(ctx, apiv1.DeletePreAuthKeyParams{ID: apiv1.NewOptUint64(id)})
		if err != nil {
			return fmt.Errorf("deleting preauthkey: %w", err)
		}

		return printOutput(cmd, map[string]string{colResult: "Key deleted"}, "Key deleted")
	}),
}
