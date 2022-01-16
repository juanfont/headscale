package cli

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	survey "github.com/AlecAivazis/survey/v2"
	"github.com/juanfont/headscale"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
	"tailscale.com/types/key"
)

func init() {
	rootCmd.AddCommand(nodeCmd)
	listNodesCmd.Flags().StringP("namespace", "n", "", "Filter by namespace")
	nodeCmd.AddCommand(listNodesCmd)

	registerNodeCmd.Flags().StringP("namespace", "n", "", "Namespace")
	err := registerNodeCmd.MarkFlagRequired("namespace")
	if err != nil {
		log.Fatalf(err.Error())
	}
	registerNodeCmd.Flags().StringP("key", "k", "", "Key")
	err = registerNodeCmd.MarkFlagRequired("key")
	if err != nil {
		log.Fatalf(err.Error())
	}
	nodeCmd.AddCommand(registerNodeCmd)

	expireNodeCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	err = expireNodeCmd.MarkFlagRequired("identifier")
	if err != nil {
		log.Fatalf(err.Error())
	}
	nodeCmd.AddCommand(expireNodeCmd)

	deleteNodeCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	err = deleteNodeCmd.MarkFlagRequired("identifier")
	if err != nil {
		log.Fatalf(err.Error())
	}
	nodeCmd.AddCommand(deleteNodeCmd)

	shareMachineCmd.Flags().StringP("namespace", "n", "", "Namespace")
	err = shareMachineCmd.MarkFlagRequired("namespace")
	if err != nil {
		log.Fatalf(err.Error())
	}
	shareMachineCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	err = shareMachineCmd.MarkFlagRequired("identifier")
	if err != nil {
		log.Fatalf(err.Error())
	}
	nodeCmd.AddCommand(shareMachineCmd)

	unshareMachineCmd.Flags().StringP("namespace", "n", "", "Namespace")
	err = unshareMachineCmd.MarkFlagRequired("namespace")
	if err != nil {
		log.Fatalf(err.Error())
	}
	unshareMachineCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	err = unshareMachineCmd.MarkFlagRequired("identifier")
	if err != nil {
		log.Fatalf(err.Error())
	}
	nodeCmd.AddCommand(unshareMachineCmd)
}

var nodeCmd = &cobra.Command{
	Use:   "nodes",
	Short: "Manage the nodes of Headscale",
}

var registerNodeCmd = &cobra.Command{
	Use:   "register",
	Short: "Registers a machine to your network",
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

		machineKey, err := cmd.Flags().GetString("key")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting machine key from flag: %s", err),
				output,
			)

			return
		}

		request := &v1.RegisterMachineRequest{
			Key:       machineKey,
			Namespace: namespace,
		}

		response, err := client.RegisterMachine(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf(
					"Cannot register machine: %s\n",
					status.Convert(err).Message(),
				),
				output,
			)

			return
		}

		SuccessOutput(response.Machine, "Machine register", output)
	},
}

var listNodesCmd = &cobra.Command{
	Use:   "list",
	Short: "List nodes",
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

		request := &v1.ListMachinesRequest{
			Namespace: namespace,
		}

		response, err := client.ListMachines(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot get nodes: %s", status.Convert(err).Message()),
				output,
			)

			return
		}

		if output != "" {
			SuccessOutput(response.Machines, "", output)

			return
		}

		tableData, err := nodesToPtables(namespace, response.Machines)
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error converting to table: %s", err), output)

			return
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

var expireNodeCmd = &cobra.Command{
	Use:     "expire",
	Short:   "Expire (log out) a machine in your network",
	Long:    "Expiring a node will keep the node in the database and force it to reauthenticate.",
	Aliases: []string{"logout"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		identifier, err := cmd.Flags().GetUint64("identifier")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error converting ID to integer: %s", err),
				output,
			)

			return
		}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		request := &v1.ExpireMachineRequest{
			MachineId: identifier,
		}

		response, err := client.ExpireMachine(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf(
					"Cannot expire machine: %s\n",
					status.Convert(err).Message(),
				),
				output,
			)

			return
		}

		SuccessOutput(response.Machine, "Machine expired", output)
	},
}

var deleteNodeCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a node",
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		identifier, err := cmd.Flags().GetUint64("identifier")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error converting ID to integer: %s", err),
				output,
			)

			return
		}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		getRequest := &v1.GetMachineRequest{
			MachineId: identifier,
		}

		getResponse, err := client.GetMachine(ctx, getRequest)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf(
					"Error getting node node: %s",
					status.Convert(err).Message(),
				),
				output,
			)

			return
		}

		deleteRequest := &v1.DeleteMachineRequest{
			MachineId: identifier,
		}

		confirm := false
		force, _ := cmd.Flags().GetBool("force")
		if !force {
			prompt := &survey.Confirm{
				Message: fmt.Sprintf(
					"Do you want to remove the node %s?",
					getResponse.GetMachine().Name,
				),
			}
			err = survey.AskOne(prompt, &confirm)
			if err != nil {
				return
			}
		}

		if confirm || force {
			response, err := client.DeleteMachine(ctx, deleteRequest)
			if output != "" {
				SuccessOutput(response, "", output)

				return
			}
			if err != nil {
				ErrorOutput(
					err,
					fmt.Sprintf(
						"Error deleting node: %s",
						status.Convert(err).Message(),
					),
					output,
				)

				return
			}
			SuccessOutput(
				map[string]string{"Result": "Node deleted"},
				"Node deleted",
				output,
			)
		} else {
			SuccessOutput(map[string]string{"Result": "Node not deleted"}, "Node not deleted", output)
		}
	},
}

func sharingWorker(
	cmd *cobra.Command,
) (string, *v1.Machine, *v1.Namespace, error) {
	output, _ := cmd.Flags().GetString("output")
	namespaceStr, err := cmd.Flags().GetString("namespace")
	if err != nil {
		ErrorOutput(err, fmt.Sprintf("Error getting namespace: %s", err), output)

		return "", nil, nil, err
	}

	ctx, client, conn, cancel := getHeadscaleCLIClient()
	defer cancel()
	defer conn.Close()

	identifier, err := cmd.Flags().GetUint64("identifier")
	if err != nil {
		ErrorOutput(err, fmt.Sprintf("Error converting ID to integer: %s", err), output)

		return "", nil, nil, err
	}

	machineRequest := &v1.GetMachineRequest{
		MachineId: identifier,
	}

	machineResponse, err := client.GetMachine(ctx, machineRequest)
	if err != nil {
		ErrorOutput(
			err,
			fmt.Sprintf("Error getting node node: %s", status.Convert(err).Message()),
			output,
		)

		return "", nil, nil, err
	}

	namespaceRequest := &v1.GetNamespaceRequest{
		Name: namespaceStr,
	}

	namespaceResponse, err := client.GetNamespace(ctx, namespaceRequest)
	if err != nil {
		ErrorOutput(
			err,
			fmt.Sprintf("Error getting node node: %s", status.Convert(err).Message()),
			output,
		)

		return "", nil, nil, err
	}

	return output, machineResponse.GetMachine(), namespaceResponse.GetNamespace(), nil
}

var shareMachineCmd = &cobra.Command{
	Use:   "share",
	Short: "Shares a node from the current namespace to the specified one",
	Run: func(cmd *cobra.Command, args []string) {
		output, machine, namespace, err := sharingWorker(cmd)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Failed to fetch namespace or machine: %s", err),
				output,
			)

			return
		}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		request := &v1.ShareMachineRequest{
			MachineId: machine.Id,
			Namespace: namespace.Name,
		}

		response, err := client.ShareMachine(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error sharing node: %s", status.Convert(err).Message()),
				output,
			)

			return
		}

		SuccessOutput(response.Machine, "Node shared", output)
	},
}

var unshareMachineCmd = &cobra.Command{
	Use:   "unshare",
	Short: "Unshares a node from the specified namespace",
	Run: func(cmd *cobra.Command, args []string) {
		output, machine, namespace, err := sharingWorker(cmd)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Failed to fetch namespace or machine: %s", err),
				output,
			)

			return
		}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		request := &v1.UnshareMachineRequest{
			MachineId: machine.Id,
			Namespace: namespace.Name,
		}

		response, err := client.UnshareMachine(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error unsharing node: %s", status.Convert(err).Message()),
				output,
			)

			return
		}

		SuccessOutput(response.Machine, "Node unshared", output)
	},
}

func nodesToPtables(
	currentNamespace string,
	machines []*v1.Machine,
) (pterm.TableData, error) {
	tableData := pterm.TableData{
		{
			"ID",
			"Name",
			"NodeKey",
			"Namespace",
			"IP addresses",
			"Ephemeral",
			"Last seen",
			"Online",
			"Expired",
		},
	}

	for _, machine := range machines {
		var ephemeral bool
		if machine.PreAuthKey != nil && machine.PreAuthKey.Ephemeral {
			ephemeral = true
		}

		var lastSeen time.Time
		var lastSeenTime string
		if machine.LastSeen != nil {
			lastSeen = machine.LastSeen.AsTime()
			lastSeenTime = lastSeen.Format("2006-01-02 15:04:05")
		}

		var expiry time.Time
		if machine.Expiry != nil {
			expiry = machine.Expiry.AsTime()
		}

		var nodeKey key.NodePublic
		err := nodeKey.UnmarshalText(
			[]byte(headscale.NodePublicKeyEnsurePrefix(machine.NodeKey)),
		)
		if err != nil {
			return nil, err
		}

		var online string
		if lastSeen.After(
			time.Now().Add(-5 * time.Minute),
		) { // TODO: Find a better way to reliably show if online
			online = pterm.LightGreen("online")
		} else {
			online = pterm.LightRed("offline")
		}

		var expired string
		if expiry.IsZero() || expiry.After(time.Now()) {
			expired = pterm.LightGreen("no")
		} else {
			expired = pterm.LightRed("yes")
		}

		var namespace string
		if currentNamespace == "" || (currentNamespace == machine.Namespace.Name) {
			namespace = pterm.LightMagenta(machine.Namespace.Name)
		} else {
			// Shared into this namespace
			namespace = pterm.LightYellow(machine.Namespace.Name)
		}
		tableData = append(
			tableData,
			[]string{
				strconv.FormatUint(machine.Id, headscale.Base10),
				machine.Name,
				nodeKey.ShortString(),
				namespace,
				strings.Join(machine.IpAddresses, ", "),
				strconv.FormatBool(ephemeral),
				lastSeenTime,
				online,
				expired,
			},
		)
	}

	return tableData, nil
}
