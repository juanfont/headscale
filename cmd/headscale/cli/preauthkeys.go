package cli

import (
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
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
		defer cancel()
		defer conn.Close()

		response, err := client.ListPreAuthKeys(ctx, &v1.ListPreAuthKeysRequest{})
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting the list of keys: %s", err),
				output,
			)

			return
		}

		if output != "" {
			SuccessOutput(response.GetPreAuthKeys(), "", output)
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
			ErrorOutput(
				err,
				fmt.Sprintf("Failed to render pterm table: %s", err),
				output,
			)
		}
	},
}

var createPreAuthKeyCmd = &cobra.Command{
	Use:     "create",
	Short:   "Creates a new preauthkey",
	Aliases: []string{"c", "new"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

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
			ErrorOutput(
				err,
				fmt.Sprintf("Could not parse duration: %s\n", err),
				output,
			)
		}

		expiration := time.Now().UTC().Add(time.Duration(duration))

		request.Expiration = timestamppb.New(expiration)

		ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
		defer cancel()
		defer conn.Close()

		response, err := client.CreatePreAuthKey(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot create Pre Auth Key: %s\n", err),
				output,
			)
		}

		SuccessOutput(response.GetPreAuthKey(), response.GetPreAuthKey().GetKey(), output)
	},
}

var expirePreAuthKeyCmd = &cobra.Command{
	Use:     "expire",
	Short:   "Expire a preauthkey",
	Aliases: []string{"revoke", "exp", "e"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		id, _ := cmd.Flags().GetUint64("id")

		if id == 0 {
			ErrorOutput(
				errMissingParameter,
				"Error: missing --id parameter",
				output,
			)

			return
		}

		ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
		defer cancel()
		defer conn.Close()

		request := &v1.ExpirePreAuthKeyRequest{
			Id: id,
		}

		response, err := client.ExpirePreAuthKey(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot expire Pre Auth Key: %s\n", err),
				output,
			)
		}

		SuccessOutput(response, "Key expired", output)
	},
}

var deletePreAuthKeyCmd = &cobra.Command{
	Use:     "delete",
	Short:   "Delete a preauthkey",
	Aliases: []string{"del", "rm", "d"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		id, _ := cmd.Flags().GetUint64("id")

		if id == 0 {
			ErrorOutput(
				errMissingParameter,
				"Error: missing --id parameter",
				output,
			)

			return
		}

		ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
		defer cancel()
		defer conn.Close()

		request := &v1.DeletePreAuthKeyRequest{
			Id: id,
		}

		response, err := client.DeletePreAuthKey(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot delete Pre Auth Key: %s\n", err),
				output,
			)
		}

		SuccessOutput(response, "Key deleted", output)
	},
}
