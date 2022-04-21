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

	nodeCmd.AddCommand(tagCmd)
	addTagCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	err = addTagCmd.MarkFlagRequired("identifier")
	if err != nil {
		log.Fatalf(err.Error())
	}
	addTagCmd.Flags().
		StringSliceP("tags", "t", []string{}, "List of tags to add to the node")
	tagCmd.AddCommand(addTagCmd)

	delTagCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	err = delTagCmd.MarkFlagRequired("identifier")
	if err != nil {
		log.Fatalf(err.Error())
	}
	delTagCmd.Flags().
		StringSliceP("tags", "t", []string{}, "List of tags to remove from the node")
	tagCmd.AddCommand(delTagCmd)
}

var nodeCmd = &cobra.Command{
	Use:     "nodes",
	Short:   "Manage the nodes of Headscale",
	Aliases: []string{"node", "machine", "machines"},
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
	Use:     "list",
	Short:   "List nodes",
	Aliases: []string{"ls", "show"},
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
	Aliases: []string{"logout", "exp", "e"},
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
	Use:     "delete",
	Short:   "Delete a node",
	Aliases: []string{"del"},
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
			"Tags",
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

		var tags string
		for _, tag := range machine.ForcedTags {
			tags += "," + tag
		}
		for _, tag := range machine.InvalidTags {
			if !containsString(machine.ForcedTags, tag) {
				tags += "," + pterm.LightRed(tag)
			}
		}
		for _, tag := range machine.ValidTags {
			if !containsString(machine.ForcedTags, tag) {
				tags += "," + pterm.LightGreen(tag)
			}
		}
		tags = strings.TrimLeft(tags, ",")

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
				tags,
			},
		)
	}

	return tableData, nil
}

var tagCmd = &cobra.Command{
	Use:     "tags",
	Short:   "Manage the tags of Headscale",
	Aliases: []string{"t", "tag"},
}

var addTagCmd = &cobra.Command{
	Use:   "add",
	Short: "Add tags to a node in your network",
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		// retrieve flags from CLI
		identifier, err := cmd.Flags().GetUint64("identifier")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error converting ID to integer: %s", err),
				output,
			)

			return
		}
		tagsToAdd, err := cmd.Flags().GetStringSlice("tags")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error retrieving list of tags to add to machine, %v", err),
				output,
			)

			return
		}

		// retrieve machine informations
		request := &v1.GetMachineRequest{
			MachineId: identifier,
		}
		resp, err := client.GetMachine(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error retrieving machine: %s", err),
				output,
			)
		}

		// update machine
		mergedTags := resp.Machine.GetForcedTags()
		for _, tag := range tagsToAdd {
			if !containsString(mergedTags, tag) {
				mergedTags = append(mergedTags, tag)
			}
		}

		machine := resp.GetMachine()
		machine.ForcedTags = mergedTags

		updateReq := &v1.UpdateMachineRequest{
			Machine: machine,
		}

		// send updated machine upstream
		updateResponse, err := client.UpdateMachine(ctx, updateReq)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error while updating machine: %s", err),
				output,
			)
		}

		if updateResponse != nil {
			SuccessOutput(
				updateResponse.GetMachine(),
				"Machine updated",
				output,
			)
		}
	},
}

var delTagCmd = &cobra.Command{
	Use:     "del",
	Short:   "remove tags to a node in your network",
	Aliases: []string{"remove", "rm"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		// retrieve flags from CLI
		identifier, err := cmd.Flags().GetUint64("identifier")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error converting ID to integer: %s", err),
				output,
			)

			return
		}
		tagsToRemove, err := cmd.Flags().GetStringSlice("tags")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error retrieving list of tags to add to machine: %v", err),
				output,
			)

			return
		}

		// retrieve machine informations
		request := &v1.GetMachineRequest{
			MachineId: identifier,
		}
		resp, err := client.GetMachine(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error retrieving machine: %s", err),
				output,
			)
		}

		// update machine
		keepTags := resp.Machine.GetForcedTags()
		for _, tag := range tagsToRemove {
			for i, t := range keepTags {
				if t == tag {
					keepTags = append(keepTags[:i], keepTags[i+1:]...)
				}
			}
		}

		machine := resp.GetMachine()
		machine.ForcedTags = keepTags

		updateReq := &v1.UpdateMachineRequest{
			Machine: machine,
		}

		// send updated machine upstream
		updateResponse, err := client.UpdateMachine(ctx, updateReq)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error while updating machine: %s", err),
				output,
			)
		}

		if updateResponse != nil {
			SuccessOutput(
				updateResponse.GetMachine(),
				"Machine updated",
				output,
			)
		}
	},
}
