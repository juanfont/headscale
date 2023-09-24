package cli

import (
	"fmt"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"time"

	survey "github.com/AlecAivazis/survey/v2"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
	"tailscale.com/types/key"
)

func init() {
	rootCmd.AddCommand(nodeCmd)
	listNodesCmd.Flags().StringP("user", "u", "", "Filter by user")
	listNodesCmd.Flags().BoolP("tags", "t", false, "Show tags")

	listNodesCmd.Flags().StringP("namespace", "n", "", "User")
	listNodesNamespaceFlag := listNodesCmd.Flags().Lookup("namespace")
	listNodesNamespaceFlag.Deprecated = deprecateNamespaceMessage
	listNodesNamespaceFlag.Hidden = true

	nodeCmd.AddCommand(listNodesCmd)

	registerNodeCmd.Flags().StringP("user", "u", "", "User")

	registerNodeCmd.Flags().StringP("namespace", "n", "", "User")
	registerNodeNamespaceFlag := registerNodeCmd.Flags().Lookup("namespace")
	registerNodeNamespaceFlag.Deprecated = deprecateNamespaceMessage
	registerNodeNamespaceFlag.Hidden = true

	err := registerNodeCmd.MarkFlagRequired("user")
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

	renameNodeCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	err = renameNodeCmd.MarkFlagRequired("identifier")
	if err != nil {
		log.Fatalf(err.Error())
	}
	nodeCmd.AddCommand(renameNodeCmd)

	deleteNodeCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	err = deleteNodeCmd.MarkFlagRequired("identifier")
	if err != nil {
		log.Fatalf(err.Error())
	}
	nodeCmd.AddCommand(deleteNodeCmd)

	moveNodeCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")

	err = moveNodeCmd.MarkFlagRequired("identifier")
	if err != nil {
		log.Fatalf(err.Error())
	}

	moveNodeCmd.Flags().StringP("user", "u", "", "New user")

	moveNodeCmd.Flags().StringP("namespace", "n", "", "User")
	moveNodeNamespaceFlag := moveNodeCmd.Flags().Lookup("namespace")
	moveNodeNamespaceFlag.Deprecated = deprecateNamespaceMessage
	moveNodeNamespaceFlag.Hidden = true

	err = moveNodeCmd.MarkFlagRequired("user")
	if err != nil {
		log.Fatalf(err.Error())
	}
	nodeCmd.AddCommand(moveNodeCmd)

	tagCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")

	err = tagCmd.MarkFlagRequired("identifier")
	if err != nil {
		log.Fatalf(err.Error())
	}
	tagCmd.Flags().
		StringSliceP("tags", "t", []string{}, "List of tags to add to the node")
	nodeCmd.AddCommand(tagCmd)
}

var nodeCmd = &cobra.Command{
	Use:     "nodes",
	Short:   "Manage the nodes of Headscale",
	Aliases: []string{"node", "machine", "machines"},
}

var registerNodeCmd = &cobra.Command{
	Use:   "register",
	Short: "Registers a node to your network",
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		user, err := cmd.Flags().GetString("user")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting user: %s", err), output)

			return
		}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		machineKey, err := cmd.Flags().GetString("key")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting node key from flag: %s", err),
				output,
			)

			return
		}

		request := &v1.RegisterNodeRequest{
			Key:  machineKey,
			User: user,
		}

		response, err := client.RegisterNode(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf(
					"Cannot register node: %s\n",
					status.Convert(err).Message(),
				),
				output,
			)

			return
		}

		SuccessOutput(
			response.Node,
			fmt.Sprintf("Node %s registered", response.Node.GivenName), output)
	},
}

var listNodesCmd = &cobra.Command{
	Use:     "list",
	Short:   "List nodes",
	Aliases: []string{"ls", "show"},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		user, err := cmd.Flags().GetString("user")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting user: %s", err), output)

			return
		}
		showTags, err := cmd.Flags().GetBool("tags")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting tags flag: %s", err), output)

			return
		}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		request := &v1.ListNodesRequest{
			User: user,
		}

		response, err := client.ListNodes(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Cannot get nodes: %s", status.Convert(err).Message()),
				output,
			)

			return
		}

		if output != "" {
			SuccessOutput(response.Nodes, "", output)

			return
		}

		tableData, err := nodesToPtables(user, showTags, response.Nodes)
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
	Short:   "Expire (log out) a node in your network",
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

		request := &v1.ExpireNodeRequest{
			NodeId: identifier,
		}

		response, err := client.ExpireNode(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf(
					"Cannot expire node: %s\n",
					status.Convert(err).Message(),
				),
				output,
			)

			return
		}

		SuccessOutput(response.Node, "Node expired", output)
	},
}

var renameNodeCmd = &cobra.Command{
	Use:   "rename NEW_NAME",
	Short: "Renames a node in your network",
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

		newName := ""
		if len(args) > 0 {
			newName = args[0]
		}
		request := &v1.RenameNodeRequest{
			NodeId:  identifier,
			NewName: newName,
		}

		response, err := client.RenameNode(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf(
					"Cannot rename node: %s\n",
					status.Convert(err).Message(),
				),
				output,
			)

			return
		}

		SuccessOutput(response.Node, "Node renamed", output)
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

		getRequest := &v1.GetNodeRequest{
			NodeId: identifier,
		}

		getResponse, err := client.GetNode(ctx, getRequest)
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

		deleteRequest := &v1.DeleteNodeRequest{
			NodeId: identifier,
		}

		confirm := false
		force, _ := cmd.Flags().GetBool("force")
		if !force {
			prompt := &survey.Confirm{
				Message: fmt.Sprintf(
					"Do you want to remove the node %s?",
					getResponse.GetNode().Name,
				),
			}
			err = survey.AskOne(prompt, &confirm)
			if err != nil {
				return
			}
		}

		if confirm || force {
			response, err := client.DeleteNode(ctx, deleteRequest)
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

var moveNodeCmd = &cobra.Command{
	Use:     "move",
	Short:   "Move node to another user",
	Aliases: []string{"mv"},
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

		user, err := cmd.Flags().GetString("user")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting user: %s", err),
				output,
			)

			return
		}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		getRequest := &v1.GetNodeRequest{
			NodeId: identifier,
		}

		_, err = client.GetNode(ctx, getRequest)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf(
					"Error getting node: %s",
					status.Convert(err).Message(),
				),
				output,
			)

			return
		}

		moveRequest := &v1.MoveNodeRequest{
			NodeId: identifier,
			User:   user,
		}

		moveResponse, err := client.MoveNode(ctx, moveRequest)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf(
					"Error moving node: %s",
					status.Convert(err).Message(),
				),
				output,
			)

			return
		}

		SuccessOutput(moveResponse.Node, "Node moved to another user", output)
	},
}

func nodesToPtables(
	currentUser string,
	showTags bool,
	nodes []*v1.Node,
) (pterm.TableData, error) {
	tableHeader := []string{
		"ID",
		"Hostname",
		"Name",
		"MachineKey",
		"NodeKey",
		"User",
		"IP addresses",
		"Ephemeral",
		"Last seen",
		"Expiration",
		"Online",
		"Expired",
	}
	if showTags {
		tableHeader = append(tableHeader, []string{
			"ForcedTags",
			"InvalidTags",
			"ValidTags",
		}...)
	}
	tableData := pterm.TableData{tableHeader}

	for _, node := range nodes {
		var ephemeral bool
		if node.PreAuthKey != nil && node.PreAuthKey.Ephemeral {
			ephemeral = true
		}

		var lastSeen time.Time
		var lastSeenTime string
		if node.LastSeen != nil {
			lastSeen = node.LastSeen.AsTime()
			lastSeenTime = lastSeen.Format("2006-01-02 15:04:05")
		}

		var expiry time.Time
		var expiryTime string
		if node.Expiry != nil {
			expiry = node.Expiry.AsTime()
			expiryTime = expiry.Format("2006-01-02 15:04:05")
		} else {
			expiryTime = "N/A"
		}

		var machineKey key.MachinePublic
		err := machineKey.UnmarshalText(
			[]byte(util.MachinePublicKeyEnsurePrefix(node.MachineKey)),
		)
		if err != nil {
			machineKey = key.MachinePublic{}
		}

		var nodeKey key.NodePublic
		err = nodeKey.UnmarshalText(
			[]byte(util.NodePublicKeyEnsurePrefix(node.NodeKey)),
		)
		if err != nil {
			return nil, err
		}

		var online string
		if node.Online {
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

		var forcedTags string
		for _, tag := range node.ForcedTags {
			forcedTags += "," + tag
		}
		forcedTags = strings.TrimLeft(forcedTags, ",")
		var invalidTags string
		for _, tag := range node.InvalidTags {
			if !contains(node.ForcedTags, tag) {
				invalidTags += "," + pterm.LightRed(tag)
			}
		}
		invalidTags = strings.TrimLeft(invalidTags, ",")
		var validTags string
		for _, tag := range node.ValidTags {
			if !contains(node.ForcedTags, tag) {
				validTags += "," + pterm.LightGreen(tag)
			}
		}
		validTags = strings.TrimLeft(validTags, ",")

		var user string
		if currentUser == "" || (currentUser == node.User.Name) {
			user = pterm.LightMagenta(node.User.Name)
		} else {
			// Shared into this user
			user = pterm.LightYellow(node.User.Name)
		}

		var IPV4Address string
		var IPV6Address string
		for _, addr := range node.IpAddresses {
			if netip.MustParseAddr(addr).Is4() {
				IPV4Address = addr
			} else {
				IPV6Address = addr
			}
		}

		nodeData := []string{
			strconv.FormatUint(node.Id, util.Base10),
			node.Name,
			node.GetGivenName(),
			machineKey.ShortString(),
			nodeKey.ShortString(),
			user,
			strings.Join([]string{IPV4Address, IPV6Address}, ", "),
			strconv.FormatBool(ephemeral),
			lastSeenTime,
			expiryTime,
			online,
			expired,
		}
		if showTags {
			nodeData = append(nodeData, []string{forcedTags, invalidTags, validTags}...)
		}
		tableData = append(
			tableData,
			nodeData,
		)
	}

	return tableData, nil
}

var tagCmd = &cobra.Command{
	Use:     "tag",
	Short:   "Manage the tags of a node",
	Aliases: []string{"tags", "t"},
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
		tagsToSet, err := cmd.Flags().GetStringSlice("tags")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error retrieving list of tags to add to node, %v", err),
				output,
			)

			return
		}

		// Sending tags to node
		request := &v1.SetTagsRequest{
			NodeId: identifier,
			Tags:   tagsToSet,
		}
		resp, err := client.SetTags(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error while sending tags to headscale: %s", err),
				output,
			)

			return
		}

		if resp != nil {
			SuccessOutput(
				resp.GetNode(),
				"Node updated",
				output,
			)
		}
	},
}
