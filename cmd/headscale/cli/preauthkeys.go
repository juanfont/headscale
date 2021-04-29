package cli

import (
	"fmt"
	"log"
	"time"

	"github.com/hako/durafmt"
	"github.com/spf13/cobra"
)

var PreauthkeysCmd = &cobra.Command{
	Use:   "preauthkey",
	Short: "Handle the preauthkeys in Headscale",
}

var ListPreAuthKeys = &cobra.Command{
	Use:   "list NAMESPACE",
	Short: "List the preauthkeys for this namespace",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("Missing parameters")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}
		keys, err := h.GetPreAuthKeys(args[0])
		if err != nil {
			fmt.Println(err)
			return
		}
		for _, k := range *keys {
			fmt.Printf(
				"key: %s, namespace: %s, reusable: %v, expiration: %s, created_at: %s\n",
				k.Key,
				k.Namespace.Name,
				k.Reusable,
				k.Expiration.Format("2006-01-02 15:04:05"),
				k.CreatedAt.Format("2006-01-02 15:04:05"),
			)
		}
	},
}

var CreatePreAuthKeyCmd = &cobra.Command{
	Use:   "create NAMESPACE",
	Short: "Creates a new preauthkey in the specified namespace",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("Missing parameters")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}
		reusable, _ := cmd.Flags().GetBool("reusable")

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

		_, err = h.CreatePreAuthKey(args[0], reusable, expiration)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("Ook.\n")
	},
}
