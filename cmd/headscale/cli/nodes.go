package cli

import (
	"fmt"
	"log"
	"strconv"
	"time"

	survey "github.com/AlecAivazis/survey/v2"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
	"tailscale.com/tailcfg"
	"tailscale.com/types/wgkey"
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

	deleteNodeCmd.Flags().IntP("identifier", "i", 0, "Node identifier (ID)")
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
	shareMachineCmd.Flags().IntP("identifier", "i", 0, "Node identifier (ID)")
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
	unshareMachineCmd.Flags().IntP("identifier", "i", 0, "Node identifier (ID)")
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

		d, err := nodesToPtables(namespace, response.Machines)
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error converting to table: %s", err), output)

			return
		}

		err = pterm.DefaultTable.WithHasHeader().WithData(d).Render()
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

var deleteNodeCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a node",
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		id, err := cmd.Flags().GetInt("identifier")
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
			MachineId: uint64(id),
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
			MachineId: uint64(id),
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

	id, err := cmd.Flags().GetInt("identifier")
	if err != nil {
		ErrorOutput(err, fmt.Sprintf("Error converting ID to integer: %s", err), output)

		return "", nil, nil, err
	}

	machineRequest := &v1.GetMachineRequest{
		MachineId: uint64(id),
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
	d := pterm.TableData{
		{
			"ID",
			"Name",
			"NodeKey",
			"Namespace",
			"IP address",
			"Ephemeral",
			"Last seen",
			"Online",
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
		nKey, err := wgkey.ParseHex(machine.NodeKey)
		if err != nil {
			return nil, err
		}
		nodeKey := tailcfg.NodeKey(nKey)

		var online string
		if lastSeen.After(
			time.Now().Add(-5 * time.Minute),
		) { // TODO: Find a better way to reliably show if online
			online = pterm.LightGreen("true")
		} else {
			online = pterm.LightRed("false")
		}

		var namespace string
		if currentNamespace == "" || (currentNamespace == machine.Namespace.Name) {
			namespace = pterm.LightMagenta(machine.Namespace.Name)
		} else {
			// Shared into this namespace
			namespace = pterm.LightYellow(machine.Namespace.Name)
		}
		d = append(
			d,
			[]string{
				strconv.FormatUint(machine.Id, 10),
				machine.Name,
				nodeKey.ShortString(),
				namespace,
				machine.IpAddress,
				strconv.FormatBool(ephemeral),
				lastSeenTime,
				online,
			},
		)
	}

	return d, nil
}
