package cli

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var RegisterCmd = &cobra.Command{
	Use:   "register machineID",
	Short: "Registers a machine to your network",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("Missing parameters")
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
		m, err := h.RegisterMachine(args[0], n)
		if strings.HasPrefix(o, "json") {
			JsonOutput(m, err, o)
			return
		}
		if err != nil {
			fmt.Printf("Cannot register machine: %s\n", err)
			return
		}
		fmt.Printf("Machine registered\n")
	},
}

var ListNodesCmd = &cobra.Command{
	Use:   "list",
	Short: "List the nodes in a given namespace",
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
		machines, err := h.ListMachinesInNamespace(n)
		if strings.HasPrefix(o, "json") {
			JsonOutput(machines, err, o)
			return
		}

		if err != nil {
			log.Fatalf("Error getting nodes: %s", err)
		}

		fmt.Printf("name\t\tlast seen\t\tephemeral\n")
		for _, m := range *machines {
			var ephemeral bool
			if m.AuthKey != nil && m.AuthKey.Ephemeral {
				ephemeral = true
			}
			var lastSeen time.Time
			if m.LastSeen != nil {
				lastSeen = *m.LastSeen
			}
			fmt.Printf("%s\t%s\t%t\n", m.Name, lastSeen.Format("2006-01-02 15:04:05"), ephemeral)
		}

	},
}

var NodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Manage the nodes of Headscale",
}
