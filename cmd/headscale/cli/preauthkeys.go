package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
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
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		response, err := client.ListPreAuthKeys(ctx, &v1.ListPreAuthKeysRequest{})
		if err != nil {
			return fmt.Errorf("listing preauthkeys: %w", err)
		}

		return printListOutput(cmd, response.GetPreAuthKeys(), func() error {
			rows := make([][]string, 0, len(response.GetPreAuthKeys()))
			for _, key := range response.GetPreAuthKeys() {
				expiration := "-"
				if key.GetExpiration() != nil {
					expiration = ColourTime(key.GetExpiration().AsTime())
				}

				var owner string
				if len(key.GetAclTags()) > 0 {
					owner = strings.Join(key.GetAclTags(), "\n")
				} else if key.GetUser() != nil {
					owner = key.GetUser().GetName()
				} else {
					owner = "-"
				}

				rows = append(rows, []string{
					strconv.FormatUint(key.GetId(), util.Base10),
					key.GetKey(),
					strconv.FormatBool(key.GetReusable()),
					strconv.FormatBool(key.GetEphemeral()),
					strconv.FormatBool(key.GetUsed()),
					expiration,
					key.GetCreatedAt().AsTime().Format(HeadscaleDateTimeFormat),
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
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		user, _ := cmd.Flags().GetUint64("user")
		reusable, _ := cmd.Flags().GetBool("reusable")
		ephemeral, _ := cmd.Flags().GetBool("ephemeral")
		tags, _ := cmd.Flags().GetStringSlice("tags")

		expiration, err := expirationFromFlag(cmd)
		if err != nil {
			return err
		}

		request := &v1.CreatePreAuthKeyRequest{
			User:       user,
			Reusable:   reusable,
			Ephemeral:  ephemeral,
			AclTags:    tags,
			Expiration: expiration,
		}

		response, err := client.CreatePreAuthKey(ctx, request)
		if err != nil {
			return fmt.Errorf("creating preauthkey: %w", err)
		}

		return printOutput(cmd, response.GetPreAuthKey(), response.GetPreAuthKey().GetKey())
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
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		id, err := preAuthKeyID(cmd)
		if err != nil {
			return err
		}

		request := &v1.ExpirePreAuthKeyRequest{
			Id: id,
		}

		response, err := client.ExpirePreAuthKey(ctx, request)
		if err != nil {
			return fmt.Errorf("expiring preauthkey: %w", err)
		}

		return printOutput(cmd, response, "Key expired")
	}),
}

var deletePreAuthKeyCmd = &cobra.Command{
	Use:     cmdDelete,
	Short:   "Delete a preauthkey",
	Aliases: []string{aliasDel, "rm", "d"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		id, err := preAuthKeyID(cmd)
		if err != nil {
			return err
		}

		request := &v1.DeletePreAuthKeyRequest{
			Id: id,
		}

		response, err := client.DeletePreAuthKey(ctx, request)
		if err != nil {
			return fmt.Errorf("deleting preauthkey: %w", err)
		}

		return printOutput(cmd, response, "Key deleted")
	}),
}
