package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/prometheus/common/model"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	Use:     "list",
	Short:   "List all preauthkeys",
	Aliases: []string{"ls", "show"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		format, _ := cmd.Flags().GetString("output")

		response, err := client.ListPreAuthKeys(ctx, &v1.ListPreAuthKeysRequest{})
		if err != nil {
			return fmt.Errorf("listing preauthkeys: %w", err)
		}

		if format != "" {
			return printOutput(cmd, response.GetPreAuthKeys(), "")
		}

		tableData := pterm.TableData{
			{
				"ID",
				"Key/Prefix",
				"Reusable",
				"Ephemeral",
				"Used",
				"Expiration",
				"Created",
				"Owner",
			},
		}

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

			tableData = append(tableData, []string{
				strconv.FormatUint(key.GetId(), 10),
				key.GetKey(),
				strconv.FormatBool(key.GetReusable()),
				strconv.FormatBool(key.GetEphemeral()),
				strconv.FormatBool(key.GetUsed()),
				expiration,
				key.GetCreatedAt().AsTime().Format("2006-01-02 15:04:05"),
				owner,
			})
		}

		err = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
		if err != nil {
			return fmt.Errorf("rendering table: %w", err)
		}

		return nil
	}),
}

var createPreAuthKeyCmd = &cobra.Command{
	Use:     "create",
	Short:   "Creates a new preauthkey",
	Aliases: []string{"c", "new"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		user, _ := cmd.Flags().GetUint64("user")
		reusable, _ := cmd.Flags().GetBool("reusable")
		ephemeral, _ := cmd.Flags().GetBool("ephemeral")
		tags, _ := cmd.Flags().GetStringSlice("tags")

		request := &v1.CreatePreAuthKeyRequest{
			User:      user,
			Reusable:  reusable,
			Ephemeral: ephemeral,
			AclTags:   tags,
		}

		durationStr, _ := cmd.Flags().GetString("expiration")

		duration, err := model.ParseDuration(durationStr)
		if err != nil {
			return fmt.Errorf("parsing duration: %w", err)
		}

		expiration := time.Now().UTC().Add(time.Duration(duration))

		request.Expiration = timestamppb.New(expiration)

		response, err := client.CreatePreAuthKey(ctx, request)
		if err != nil {
			return fmt.Errorf("creating preauthkey: %w", err)
		}

		return printOutput(cmd, response.GetPreAuthKey(), response.GetPreAuthKey().GetKey())
	}),
}

var expirePreAuthKeyCmd = &cobra.Command{
	Use:     "expire",
	Short:   "Expire a preauthkey",
	Aliases: []string{"revoke", "exp", "e"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetUint64("id")

		if id == 0 {
			return fmt.Errorf("missing --id parameter: %w", errMissingParameter)
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
	Use:     "delete",
	Short:   "Delete a preauthkey",
	Aliases: []string{"del", "rm", "d"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		id, _ := cmd.Flags().GetUint64("id")

		if id == 0 {
			return fmt.Errorf("missing --id parameter: %w", errMissingParameter)
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
