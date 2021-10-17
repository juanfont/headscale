package cli

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(namespaceCmd)
	namespaceCmd.AddCommand(createNamespaceCmd)
	namespaceCmd.AddCommand(listNamespacesCmd)
	namespaceCmd.AddCommand(destroyNamespaceCmd)
	namespaceCmd.AddCommand(renameNamespaceCmd)
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

		d := pterm.TableData{{"ID", "Name", "Created"}}
		for _, n := range *namespaces {
			d = append(d, []string{strconv.FormatUint(uint64(n.ID), 10), n.Name, n.CreatedAt.Format("2006-01-02 15:04:05")})
		}
		err = pterm.DefaultTable.WithHasHeader().WithData(d).Render()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var renameNamespaceCmd = &cobra.Command{
	Use:   "rename OLD_NAME NEW_NAME",
	Short: "Renames a namespace",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
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
		err = h.RenameNamespace(args[0], args[1])
		if strings.HasPrefix(o, "json") {
			JsonOutput(map[string]string{"Result": "Namespace renamed"}, err, o)
			return
		}
		if err != nil {
			fmt.Printf("Error renaming namespace: %s\n", err)
			return
		}
		fmt.Printf("Namespace renamed\n")
	},
}
