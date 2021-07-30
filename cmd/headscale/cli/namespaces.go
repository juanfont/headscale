package cli

import (
	"fmt"
	"log"
	"strings"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(namespaceCmd)
	namespaceCmd.AddCommand(createNamespaceCmd)
	namespaceCmd.AddCommand(listNamespacesCmd)
	namespaceCmd.AddCommand(destroyNamespaceCmd)
}

var namespaceCmd = &cobra.Command{
	Use:   "namespaces",
	Short: "Manage the namespaces of Headscale",
}

var createNamespaceCmd = &cobra.Command{
	Use:   "create NAME",
	Short: "Creates a new namespace",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("Missing parameters")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		o, _ := cmd.Flags().GetString("output")
		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}
		namespace, err := h.CreateNamespace(args[0])
		if strings.HasPrefix(o, "json") {
			JsonOutput(namespace, err, o)
			return
		}
		if err != nil {
			fmt.Printf("Error creating namespace: %s\n", err)
			return
		}
		fmt.Printf("Namespace created\n")
	},
}

var destroyNamespaceCmd = &cobra.Command{
	Use:   "destroy NAME",
	Short: "Destroys a namespace",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("Missing parameters")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		o, _ := cmd.Flags().GetString("output")
		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}
		err = h.DestroyNamespace(args[0])
		if strings.HasPrefix(o, "json") {
			JsonOutput(map[string]string{"Result": "Namespace destroyed"}, err, o)
			return
		}
		if err != nil {
			fmt.Printf("Error destroying namespace: %s\n", err)
			return
		}
		fmt.Printf("Namespace destroyed\n")
	},
}

var listNamespacesCmd = &cobra.Command{
	Use:   "list",
	Short: "List all the namespaces",
	Run: func(cmd *cobra.Command, args []string) {
		o, _ := cmd.Flags().GetString("output")
		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}
		namespaces, err := h.ListNamespaces()
		if strings.HasPrefix(o, "json") {
			JsonOutput(namespaces, err, o)
			return
		}
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("ID\tName\n")
		for _, n := range *namespaces {
			fmt.Printf("%d\t%s\n", n.ID, n.Name)
		}
	},
}
