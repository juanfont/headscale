package cli

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/hako/durafmt"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func init() {
	rootCmd.AddCommand(preauthkeysCmd)
	preauthkeysCmd.PersistentFlags().StringP("namespace", "n", "", "Namespace")
	err := preauthkeysCmd.MarkPersistentFlagRequired("namespace")
	if err != nil {
		log.Fatalf(err.Error())
	}
	preauthkeysCmd.AddCommand(listPreAuthKeys)
	preauthkeysCmd.AddCommand(createPreAuthKeyCmd)
	preauthkeysCmd.AddCommand(expirePreAuthKeyCmd)
	createPreAuthKeyCmd.PersistentFlags().Bool("reusable", false, "Make the preauthkey reusable")
	createPreAuthKeyCmd.PersistentFlags().Bool("ephemeral", false, "Preauthkey for ephemeral nodes")
	createPreAuthKeyCmd.Flags().
		StringP("expiration", "e", "", "Human-readable expiration of the key (30m, 24h, 365d...)")
}

var preauthkeysCmd = &cobra.Command{
	Use:   "preauthkeys",
	Short: "Handle the preauthkeys in Headscale",
}

var listPreAuthKeys = &cobra.Command{
	Use:   "list",
	Short: "List the preauthkeys for this namespace",
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		n, err := cmd.Flags().GetString("namespace")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting namespace: %s", err), output)
			return
		}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		request := &v1.ListPreAuthKeysRequest{
			Namespace: n,
		}

		response, err := client.ListPreAuthKeys(ctx, request)
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting the list of keys: %s", err), output)
			return
		}

		if output != "" {
			SuccessOutput(response.PreAuthKeys, "", output)
			return
		}

		d := pterm.TableData{{"ID", "Key", "Reusable", "Ephemeral", "Used", "Expiration", "Created"}}
		for _, k := range response.PreAuthKeys {
			expiration := "-"
			if k.GetExpiration() != nil {
				expiration = k.Expiration.AsTime().Format("2006-01-02 15:04:05")
			}

			var reusable string
			if k.GetEphemeral() {
				reusable = "N/A"
			} else {
				reusable = fmt.Sprintf("%v", k.GetResuable())
			}

			d = append(d, []string{
				k.GetId(),
				k.GetKey(),
				reusable,
				strconv.FormatBool(k.GetEphemeral()),
				strconv.FormatBool(k.GetUsed()),
				expiration,
				k.GetCreatedAt().AsTime().Format("2006-01-02 15:04:05"),
			})

		}
		err = pterm.DefaultTable.WithHasHeader().WithData(d).Render()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var createPreAuthKeyCmd = &cobra.Command{
	Use:   "create",
	Short: "Creates a new preauthkey in the specified namespace",
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		n, err := cmd.Flags().GetString("namespace")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting namespace: %s", err), output)
			return
		}

		reusable, _ := cmd.Flags().GetBool("reusable")
		ephemeral, _ := cmd.Flags().GetBool("ephemeral")

		e, _ := cmd.Flags().GetString("expiration")
		var expiration *time.Time
		if e != "" {
			duration, err := durafmt.ParseStringShort(e)
			if err != nil {
				log.Fatalf("Error parsing expiration: %s", err)
			}
			exp := time.Now().UTC().Add(duration.Duration())
			expiration = &exp
		}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		request := &v1.CreatePreAuthKeyRequest{
			Namespace:  n,
			Resuable:   reusable,
			Ephemeral:  ephemeral,
			Expiration: timestamppb.New(*expiration),
		}

		response, err := client.CreatePreAuthKey(ctx, request)
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Cannot create Pre Auth Key: %s\n", err), output)
			return
		}

		SuccessOutput(response.PreAuthKey, response.PreAuthKey.Key, output)
	},
}

var expirePreAuthKeyCmd = &cobra.Command{
	Use:   "expire KEY",
	Short: "Expire a preauthkey",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("missing parameters")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		n, err := cmd.Flags().GetString("namespace")
		if err != nil {
			log.Fatalf("Error getting namespace: %s", err)
		}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		request := &v1.ExpirePreAuthKeyRequest{
			Namespace: n,
			Key:       args[0],
		}

		response, err := client.ExpirePreAuthKey(ctx, request)
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Cannot expire Pre Auth Key: %s\n", err), output)
			return
		}

		SuccessOutput(response, "Key expired", output)
	},
}
