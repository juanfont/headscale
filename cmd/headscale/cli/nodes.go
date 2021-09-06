package cli

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	survey "github.com/AlecAivazis/survey/v2"
	"github.com/juanfont/headscale"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"tailscale.com/tailcfg"
	"tailscale.com/types/wgkey"
)

func init() {
	rootCmd.AddCommand(nodeCmd)
	nodeCmd.PersistentFlags().StringP("namespace", "n", "", "Namespace")
	err := nodeCmd.MarkPersistentFlagRequired("namespace")
	if err != nil {
		log.Fatalf(err.Error())
	}
	nodeCmd.AddCommand(listNodesCmd)
	nodeCmd.AddCommand(registerNodeCmd)
	nodeCmd.AddCommand(deleteNodeCmd)
	nodeCmd.AddCommand(shareNodeCmd)
}

var nodeCmd = &cobra.Command{
	Use:   "nodes",
	Short: "Manage the nodes of Headscale",
}

var registerNodeCmd = &cobra.Command{
	Use:   "register machineID",
	Short: "Registers a machine to your network",
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

var listNodesCmd = &cobra.Command{
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

		ns, err := h.GetNamespace(n)
		if err != nil {
			log.Fatalf("Error fetching namespace: %s", err)
		}

		machines, err := h.ListMachinesInNamespace(n)
		if err != nil {
			log.Fatalf("Error fetching machines: %s", err)
		}

		sharedMachines, err := h.ListSharedMachinesInNamespace(n)
		if err != nil {
			log.Fatalf("Error fetching shared machines: %s", err)
		}

		allMachines := append(*machines, *sharedMachines...)

		if strings.HasPrefix(o, "json") {
			JsonOutput(allMachines, err, o)
			return
		}

		if err != nil {
			log.Fatalf("Error getting nodes: %s", err)
		}

		d, err := nodesToPtables(*ns, allMachines)
		if err != nil {
			log.Fatalf("Error converting to table: %s", err)
		}

		err = pterm.DefaultTable.WithHasHeader().WithData(d).Render()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var deleteNodeCmd = &cobra.Command{
	Use:   "delete ID",
	Short: "Delete a node",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("missing parameters")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		h, err := getHeadscaleApp()
		if err != nil {
			log.Fatalf("Error initializing: %s", err)
		}
		id, err := strconv.Atoi(args[0])
		if err != nil {
			log.Fatalf("Error converting ID to integer: %s", err)
		}
		m, err := h.GetMachineByID(uint64(id))
		if err != nil {
			log.Fatalf("Error getting node: %s", err)
		}

		confirm := false
		prompt := &survey.Confirm{
			Message: fmt.Sprintf("Do you want to remove the node %s?", m.Name),
		}
		err = survey.AskOne(prompt, &confirm)
		if err != nil {
			return
		}

		if confirm {
			err = h.DeleteMachine(m)
			if err != nil {
				log.Fatalf("Error deleting node: %s", err)
			}
			fmt.Printf("Node deleted\n")
		} else {
			fmt.Printf("Node not deleted\n")
		}
	},
}

var shareNodeCmd = &cobra.Command{
	Use:   "share ID namespace",
	Short: "Shares a node from the current namespace to the specified one",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
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

		_, err = h.GetNamespace(n)
		if err != nil {
			log.Fatalf("Error fetching origin namespace: %s", err)
		}

		destNs, err := h.GetNamespace(args[1])
		if err != nil {
			log.Fatalf("Error fetching destination namespace: %s", err)
		}

		id, err := strconv.Atoi(args[0])
		if err != nil {
			log.Fatalf("Error converting ID to integer: %s", err)
		}
		m, err := h.GetMachineByID(uint64(id))
		if err != nil {
			log.Fatalf("Error getting node: %s", err)
		}

		err = h.AddSharedMachineToNamespace(m, destNs)
		if strings.HasPrefix(o, "json") {
			JsonOutput(map[string]string{"Result": "Node shared"}, err, o)
			return
		}
		if err != nil {
			fmt.Printf("Error sharing node: %s\n", err)
			return
		}

		fmt.Println("Node shared!")
	},
}

func nodesToPtables(currNs headscale.Namespace, m []headscale.Machine) (pterm.TableData, error) {
	d := pterm.TableData{{"ID", "Name", "NodeKey", "Namespace", "IP address", "Ephemeral", "Last seen", "Online"}}

	for _, m := range m {
		var ephemeral bool
		if m.AuthKey != nil && m.AuthKey.Ephemeral {
			ephemeral = true
		}
		var lastSeen time.Time
		if m.LastSeen != nil {
			lastSeen = *m.LastSeen
		}
		nKey, err := wgkey.ParseHex(m.NodeKey)
		if err != nil {
			return nil, err
		}
		nodeKey := tailcfg.NodeKey(nKey)

		var online string
		if m.LastSeen.After(time.Now().Add(-5 * time.Minute)) { // TODO: Find a better way to reliably show if online
			online = pterm.LightGreen("true")
		} else {
			online = pterm.LightRed("false")
		}

		var namespace string
		if currNs.ID == m.NamespaceID {
			namespace = pterm.LightMagenta(m.Namespace.Name)
		} else {
			namespace = pterm.LightYellow(m.Namespace.Name)
		}
		d = append(d, []string{strconv.FormatUint(m.ID, 10), m.Name, nodeKey.ShortString(), namespace, m.IPAddress, strconv.FormatBool(ephemeral), lastSeen.Format("2006-01-02 15:04:05"), online})
	}
	return d, nil
}
