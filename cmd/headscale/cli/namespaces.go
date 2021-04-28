package cli

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

var NamespaceCmd = &cobra.Command{
	Use:   "namespace",
	Short: "Manage the namespaces of Headscale",
}

var CreateNamespaceCmd = &cobra.Command{
	Use:   "create NAME",
	Short: "Creates a new namespace",
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
		_, err = h.CreateNamespace(args[0])
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("Ook.\n")
	},
}

var ListNamespacesCmd = &cobra.Command{
	Use:   "list",
	Short: "List all the namespaces",
	Run: func(cmd *cobra.Command, args []string) {
		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}
		ns, err := h.ListNamespaces()
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("ID\tName\n")
		for _, n := range *ns {
			fmt.Printf("%d\t%s\n", n.ID, n.Name)
		}
	},
}
