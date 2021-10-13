package cli

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/hako/durafmt"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
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
	createPreAuthKeyCmd.Flags().StringP("expiration", "e", "", "Human-readable expiration of the key (30m, 24h, 365d...)")
}

var preauthkeysCmd = &cobra.Command{
	Use:   "preauthkeys",
	Short: "Handle the preauthkeys in Headscale",
}

var listPreAuthKeys = &cobra.Command{
	Use:   "list",
	Short: "List the preauthkeys for this namespace",
	Run: func(cmd *cobra.Command, args []string) {
		n, err := cmd.Flags().GetString("namespace")
		if err != nil {
			log.Fatalf("Error getting namespace: %s", err)
		}
		o, _ := cmd.Flags().GetString("output")

		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}
		keys, err := h.GetPreAuthKeys(n)
		if strings.HasPrefix(o, "json") {
			JsonOutput(keys, err, o)
			return
		}

		if err != nil {
			fmt.Printf("Error getting the list of keys: %s\n", err)
			return
		}

		d := pterm.TableData{{"ID", "Key", "Reusable", "Ephemeral", "Used", "Expiration", "Created"}}
		for _, k := range *keys {
			expiration := "-"
			if k.Expiration != nil {
				expiration = k.Expiration.Format("2006-01-02 15:04:05")
			}

			var reusable string
			if k.Ephemeral {
				reusable = "N/A"
			} else {
				reusable = fmt.Sprintf("%v", k.Reusable)
			}

			d = append(d, []string{
				strconv.FormatUint(k.ID, 10),
				k.Key,
				reusable,
				strconv.FormatBool(k.Ephemeral),
				fmt.Sprintf("%v", k.Used),
				expiration,
				k.CreatedAt.Format("2006-01-02 15:04:05"),
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
		n, err := cmd.Flags().GetString("namespace")
		if err != nil {
			log.Fatalf("Error getting namespace: %s", err)
		}
		o, _ := cmd.Flags().GetString("output")

		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
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

		k, err := h.CreatePreAuthKey(n, reusable, ephemeral, expiration)
		if strings.HasPrefix(o, "json") {
			JsonOutput(k, err, o)
			return
		}
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("%s\n", k.Key)
	},
}

var expirePreAuthKeyCmd = &cobra.Command{
	Use:   "expire",
	Short: "Expire a preauthkey",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("missing parameters")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		n, err := cmd.Flags().GetString("namespace")
		if err != nil {
			log.Fatalf("Error getting namespace: %s", err)
		}
		o, _ := cmd.Flags().GetString("output")

		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}

		k, err := h.GetPreAuthKey(n, args[0])
		if err != nil {
			log.Fatalf("Error getting the key: %s", err)
		}

		err = h.MarkExpirePreAuthKey(k)
		if strings.HasPrefix(o, "json") {
			JsonOutput(k, err, o)
			return
		}
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("Expired")
	},
}
