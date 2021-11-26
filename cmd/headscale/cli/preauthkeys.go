package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/pterm/pterm"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	DefaultPreAuthKeyExpiry = 24 * time.Hour
)

func init() {
	rootCmd.AddCommand(preauthkeysCmd)
	preauthkeysCmd.PersistentFlags().StringP("namespace", "n", "", "Namespace")
	err := preauthkeysCmd.MarkPersistentFlagRequired("namespace")
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
		DurationP("expiration", "e", DefaultPreAuthKeyExpiry, "Human-readable expiration of the key (30m, 24h, 365d...)")
	createPreAuthKeyCmd.Flags().
		StringP("subnet", "", "", "Subnet to assign new nodes to")
	createPreAuthKeyCmd.Flags().
		String("ip", "", "IP to assign a node to (only supported for non-resuable keys)")
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

		namespace, err := cmd.Flags().GetString("namespace")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting namespace: %s", err), output)

			return
		}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		request := &v1.ListPreAuthKeysRequest{
			Namespace: namespace,
		}

		response, err := client.ListPreAuthKeys(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting the list of keys: %s", err),
				output,
			)

			return
		}

		if output != "" {
			SuccessOutput(response.PreAuthKeys, "", output)

			return
		}

		tableData := pterm.TableData{
			{"ID", "Key", "Reusable", "Ephemeral", "Used", "Subnet", "Expiration", "Created"},
		}
		for _, key := range response.PreAuthKeys {
			expiration := "-"
			if key.GetExpiration() != nil {
				expiration = key.Expiration.AsTime().Format("2006-01-02 15:04:05")
			}

			var reusable string
			if key.GetEphemeral() {
				reusable = "N/A"
			} else {
				reusable = fmt.Sprintf("%v", key.GetReusable())
			}

			tableData = append(tableData, []string{
				key.GetId(),
				key.GetKey(),
				reusable,
				strconv.FormatBool(key.GetEphemeral()),
				strconv.FormatBool(key.GetUsed()),
				key.GetSubnet(),
				expiration,
				key.GetCreatedAt().AsTime().Format("2006-01-02 15:04:05"),
			})

		}
		err = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Failed to render pterm table: %s", err),
				output,
			)

			return
		}
	},
}

var createPreAuthKeyCmd = &cobra.Command{
	Use:   "create",
	Short: "Creates a new preauthkey in the specified namespace",
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		namespace, err := cmd.Flags().GetString("namespace")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting namespace: %s", err), output)

			return
		}

		reusable, _ := cmd.Flags().GetBool("reusable")
		ephemeral, _ := cmd.Flags().GetBool("ephemeral")

		subnet, _ := cmd.Flags().GetString("subnet")

		if !reusable && subnet == "" {
			ip, _ := cmd.Flags().GetString("ip")
			if ip != "" {
				// If IP is in CIDR notation, strip the last octet
				if strings.Contains(ip, "/") {
					ip = strings.Split(ip, "/")[0]
				}

				subnet = ip + "/32"
			}
		}

		log.Trace().
			Bool("reusable", reusable).
			Bool("ephemeral", ephemeral).
			Str("namespace", namespace).
			Str("subnet", subnet).
			Msg("Preparing to create preauthkey")

		request := &v1.CreatePreAuthKeyRequest{
			Namespace: namespace,
			Reusable:  reusable,
			Ephemeral: ephemeral,
			Subnet:    subnet,
		}

		if cmd.Flags().Changed("expiration") {
			duration, _ := cmd.Flags().GetDuration("expiration")
			expiration := time.Now().UTC().Add(duration)

			log.Trace().Dur("expiration", duration).Msg("expiration has been set")

			request.Expiration = timestamppb.New(expiration)
		}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		response, err := client.CreatePreAuthKey(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot create Pre Auth Key: %s\n", err),
				output,
			)

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
			return errMissingParameter
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		namespace, err := cmd.Flags().GetString("namespace")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting namespace: %s", err), output)

			return
		}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		request := &v1.ExpirePreAuthKeyRequest{
			Namespace: namespace,
			Key:       args[0],
		}

		response, err := client.ExpirePreAuthKey(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot expire Pre Auth Key: %s\n", err),
				output,
			)

			return
		}

		SuccessOutput(response, "Key expired", output)
	},
}
