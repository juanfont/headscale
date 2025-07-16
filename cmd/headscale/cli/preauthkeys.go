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
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func init() {
	rootCmd.AddCommand(preauthkeysCmd)
	preauthkeysCmd.PersistentFlags().Uint64P("user", "u", 0, "User identifier (ID)")

	err := preauthkeysCmd.MarkPersistentFlagRequired("user")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
	preauthkeysCmd.AddCommand(listPreAuthKeys)
	preauthkeysCmd.AddCommand(createPreAuthKeyCmd)
	preauthkeysCmd.AddCommand(expirePreAuthKeyCmd)
	createPreAuthKeyCmd.PersistentFlags().
		Bool("reusable", false, "Make the preauthkey reusable")
	createPreAuthKeyCmd.PersistentFlags().
		Bool("ephemeral", false, "Preauthkey for ephemeral nodes")
	createPreAuthKeyCmd.Flags().
		StringP("expiration", "e", DefaultPreAuthKeyExpiry, "Human-readable expiration of the key (e.g. 30m, 24h)")
	createPreAuthKeyCmd.Flags().
		StringSlice("tags", []string{}, "Tags to automatically assign to node")
}

var preauthkeysCmd = &cobra.Command{
	Use:     "preauthkeys",
	Short:   "Handle the preauthkeys in Headscale",
	Aliases: []string{"preauthkey", "authkey", "pre"},
}

var listPreAuthKeys = &cobra.Command{
	Use:     "list",
	Short:   "List the preauthkeys for this user",
	Aliases: []string{"ls", "show"},
	Run: func(cmd *cobra.Command, args []string) {
		output := GetOutputFlag(cmd)

		user, err := cmd.Flags().GetUint64("user")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting user: %s", err), output)
			return
		}

		err = WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
			request := &v1.ListPreAuthKeysRequest{
				User: user,
			}

			response, err := client.ListPreAuthKeys(ctx, request)
			if err != nil {
				ErrorOutput(
					err,
					fmt.Sprintf("Error getting the list of keys: %s", err),
					output,
				)
				return err
			}

			if output != "" {
				SuccessOutput(response.GetPreAuthKeys(), "", output)
				return nil
			}

			tableData := pterm.TableData{
				{
					"ID",
					"Key",
					"Reusable",
					"Ephemeral",
					"Used",
					"Expiration",
					"Created",
					"Tags",
				},
			}
			for _, key := range response.GetPreAuthKeys() {
				expiration := "-"
				if key.GetExpiration() != nil {
					expiration = ColourTime(key.GetExpiration().AsTime())
				}

				aclTags := ""

				for _, tag := range key.GetAclTags() {
					aclTags += "," + tag
				}

				aclTags = strings.TrimLeft(aclTags, ",")

				tableData = append(tableData, []string{
					strconv.FormatUint(key.GetId(), 10),
					key.GetKey(),
					strconv.FormatBool(key.GetReusable()),
					strconv.FormatBool(key.GetEphemeral()),
					strconv.FormatBool(key.GetUsed()),
					expiration,
					key.GetCreatedAt().AsTime().Format(HeadscaleDateTimeFormat),
					aclTags,
				})

			}
			err = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
			if err != nil {
				ErrorOutput(
					err,
					fmt.Sprintf("Failed to render pterm table: %s", err),
					output,
				)
				return err
			}
			return nil
		})
		if err != nil {
			return
		}
	},
}

var createPreAuthKeyCmd = &cobra.Command{
	Use:     "create",
	Short:   "Creates a new preauthkey in the specified user",
	Aliases: []string{"c", "new"},
	Run: func(cmd *cobra.Command, args []string) {
		output := GetOutputFlag(cmd)

		user, err := cmd.Flags().GetUint64("user")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting user: %s", err), output)
			return
		}

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
			return
		}

		expiration := time.Now().UTC().Add(time.Duration(duration))

		log.Trace().
			Dur("expiration", time.Duration(duration)).
			Msg("expiration has been set")

		request.Expiration = timestamppb.New(expiration)

		err = WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
			response, err := client.CreatePreAuthKey(ctx, request)
			if err != nil {
				ErrorOutput(
					err,
					fmt.Sprintf("Cannot create Pre Auth Key: %s\n", err),
					output,
				)
				return err
			}

			SuccessOutput(response.GetPreAuthKey(), response.GetPreAuthKey().GetKey(), output)
			return nil
		})
		if err != nil {
			return
		}
	},
}

var expirePreAuthKeyCmd = &cobra.Command{
	Use:     "expire KEY",
	Short:   "Expire a preauthkey",
	Aliases: []string{"revoke", "exp", "e"},
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errMissingParameter
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		output := GetOutputFlag(cmd)
		user, err := cmd.Flags().GetUint64("user")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting user: %s", err), output)
			return
		}

		err = WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
			request := &v1.ExpirePreAuthKeyRequest{
				User: user,
				Key:  args[0],
			}

			response, err := client.ExpirePreAuthKey(ctx, request)
			if err != nil {
				ErrorOutput(
					err,
					fmt.Sprintf("Cannot expire Pre Auth Key: %s\n", err),
					output,
				)
				return err
			}

			SuccessOutput(response, "Key expired", output)
			return nil
		})
		if err != nil {
			return
		}
	},
}
