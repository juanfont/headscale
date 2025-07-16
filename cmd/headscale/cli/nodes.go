package cli

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	survey "github.com/AlecAivazis/survey/v2"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/pterm/pterm"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
	"tailscale.com/types/key"
)

func init() {
	rootCmd.AddCommand(nodeCmd)
	// User filtering
	listNodesCmd.Flags().StringP("user", "u", "", "Filter by user")
	// Node filtering
	listNodesCmd.Flags().StringP("node", "", "", "Filter by node (ID, name, hostname, or IP)")
	listNodesCmd.Flags().Uint64P("id", "", 0, "Filter by node ID")
	listNodesCmd.Flags().StringP("name", "", "", "Filter by node hostname")
	listNodesCmd.Flags().StringP("ip", "", "", "Filter by node IP address")
	// Display options
	listNodesCmd.Flags().BoolP("tags", "t", false, "Show tags")
	listNodesCmd.Flags().String("columns", "", "Comma-separated list of columns to display")
	nodeCmd.AddCommand(listNodesCmd)

	listNodeRoutesCmd.Flags().StringP("node", "n", "", "Node identifier (ID, name, hostname, or IP)")
	nodeCmd.AddCommand(listNodeRoutesCmd)

	registerNodeCmd.Flags().StringP("user", "u", "", "User")

	err := registerNodeCmd.MarkFlagRequired("user")
	if err != nil {
		log.Fatal(err.Error())
	}
	registerNodeCmd.Flags().StringP("key", "k", "", "Key")
	err = registerNodeCmd.MarkFlagRequired("key")
	if err != nil {
		log.Fatal(err.Error())
	}
	nodeCmd.AddCommand(registerNodeCmd)

	expireNodeCmd.Flags().StringP("node", "n", "", "Node identifier (ID, name, hostname, or IP)")
	if err != nil {
		log.Fatal(err.Error())
	}
	nodeCmd.AddCommand(expireNodeCmd)

	renameNodeCmd.Flags().StringP("node", "n", "", "Node identifier (ID, name, hostname, or IP)")
	if err != nil {
		log.Fatal(err.Error())
	}
	nodeCmd.AddCommand(renameNodeCmd)

	deleteNodeCmd.Flags().StringP("node", "n", "", "Node identifier (ID, name, hostname, or IP)")
	if err != nil {
		log.Fatal(err.Error())
	}
	nodeCmd.AddCommand(deleteNodeCmd)

	moveNodeCmd.Flags().StringP("node", "n", "", "Node identifier (ID, name, hostname, or IP)")

	if err != nil {
		log.Fatal(err.Error())
	}

	moveNodeCmd.Flags().StringP("user", "u", "", "New user (ID, name, or email)")
	moveNodeCmd.Flags().String("name", "", "New username")

	// One of --user or --name is required (checked in GetUserIdentifier)
	nodeCmd.AddCommand(moveNodeCmd)

	tagCmd.Flags().StringP("node", "n", "", "Node identifier (ID, name, hostname, or IP)")
	tagCmd.MarkFlagRequired("node")
	tagCmd.Flags().StringSliceP("tags", "t", []string{}, "List of tags to add to the node")
	nodeCmd.AddCommand(tagCmd)

	approveRoutesCmd.Flags().StringP("node", "n", "", "Node identifier (ID, name, hostname, or IP)")
	approveRoutesCmd.MarkFlagRequired("node")
	approveRoutesCmd.Flags().StringSliceP("routes", "r", []string{}, `List of routes that will be approved (comma-separated, e.g. "10.0.0.0/8,192.168.0.0/24" or empty string to remove all approved routes)`)
	nodeCmd.AddCommand(approveRoutesCmd)

	nodeCmd.AddCommand(backfillNodeIPsCmd)
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
		output := GetOutputFlag(cmd)
		user, err := cmd.Flags().GetString("user")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting user: %s", err), output)
			return
		}

		registrationID, err := cmd.Flags().GetString("key")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting node key from flag: %s", err),
				output,
			)
			return
		}

		err = WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
			request := &v1.RegisterNodeRequest{
				Key:  registrationID,
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
				return err
			}

			SuccessOutput(
				response.GetNode(),
				fmt.Sprintf("Node %s registered", response.GetNode().GetGivenName()), output)
			return nil
		})
		if err != nil {
			return
		}
	},
}

var listNodesCmd = &cobra.Command{
	Use:     "list",
	Short:   "List nodes",
	Aliases: []string{"ls", "show"},
	Run: func(cmd *cobra.Command, args []string) {
		output := GetOutputFlag(cmd)
		showTags, err := cmd.Flags().GetBool("tags")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting tags flag: %s", err), output)
			return
		}

		err = WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
			request := &v1.ListNodesRequest{}

			// Handle user filtering (existing functionality)
			if user, _ := cmd.Flags().GetString("user"); user != "" {
				request.User = user
			}

			// Handle node filtering (new functionality)
			if nodeFlag, _ := cmd.Flags().GetString("node"); nodeFlag != "" {
				// Use smart lookup to determine filter type
				if id, err := strconv.ParseUint(nodeFlag, 10, 64); err == nil && id > 0 {
					request.Id = id
				} else if isIPAddress(nodeFlag) {
					request.IpAddresses = []string{nodeFlag}
				} else {
					request.Name = nodeFlag
				}
			} else {
				// Check specific filter flags
				if id, _ := cmd.Flags().GetUint64("id"); id > 0 {
					request.Id = id
				} else if name, _ := cmd.Flags().GetString("name"); name != "" {
					request.Name = name
				} else if ip, _ := cmd.Flags().GetString("ip"); ip != "" {
					request.IpAddresses = []string{ip}
				}
			}

			response, err := client.ListNodes(ctx, request)
			if err != nil {
				ErrorOutput(
					err,
					"Cannot get nodes: "+status.Convert(err).Message(),
					output,
				)
				return err
			}

			if output != "" {
				SuccessOutput(response.GetNodes(), "", output)
				return nil
			}

			// Get user for table display (if filtering by user)
			userFilter := request.User
			tableData, err := nodesToPtables(userFilter, showTags, response.GetNodes())
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Error converting to table: %s", err), output)
				return err
			}

			tableData = FilterTableColumns(cmd, tableData)
			err = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
			if err != nil {
				ErrorOutput(
					err,
					fmt.Sprintf("Failed to render pterm table: %s", err),
					output,
				)
				return err
			}
			return nil
		})
		if err != nil {
			return
		}
	},
}

var listNodeRoutesCmd = &cobra.Command{
	Use:     "list-routes",
	Short:   "List routes available on nodes",
	Aliases: []string{"lsr", "routes"},
	Run: func(cmd *cobra.Command, args []string) {
		output := GetOutputFlag(cmd)
		identifier, err := GetNodeIdentifier(cmd)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting node identifier: %s", err),
				output,
			)
			return
		}

		err = WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
			request := &v1.ListNodesRequest{}

			response, err := client.ListNodes(ctx, request)
			if err != nil {
				ErrorOutput(
					err,
					"Cannot get nodes: "+status.Convert(err).Message(),
					output,
				)
				return err
			}

			if output != "" {
				SuccessOutput(response.GetNodes(), "", output)
				return nil
			}

			nodes := response.GetNodes()
			if identifier != 0 {
				for _, node := range response.GetNodes() {
					if node.GetId() == identifier {
						nodes = []*v1.Node{node}
						break
					}
				}
			}

			nodes = lo.Filter(nodes, func(n *v1.Node, _ int) bool {
				return (n.GetSubnetRoutes() != nil && len(n.GetSubnetRoutes()) > 0) || (n.GetApprovedRoutes() != nil && len(n.GetApprovedRoutes()) > 0) || (n.GetAvailableRoutes() != nil && len(n.GetAvailableRoutes()) > 0)
			})

			tableData, err := nodeRoutesToPtables(nodes)
			if err != nil {
				ErrorOutput(err, fmt.Sprintf("Error converting to table: %s", err), output)
				return err
			}

			err = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
			if err != nil {
				ErrorOutput(
					err,
					fmt.Sprintf("Failed to render pterm table: %s", err),
					output,
				)
				return err
			}
			return nil
		})
		if err != nil {
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
		output := GetOutputFlag(cmd)

		identifier, err := GetNodeIdentifier(cmd)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting node identifier: %s", err),
				output,
			)
			return
		}

		err = WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
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
				return err
			}

			SuccessOutput(response.GetNode(), "Node expired", output)
			return nil
		})
		if err != nil {
			return
		}
	},
}

var renameNodeCmd = &cobra.Command{
	Use:   "rename NEW_NAME",
	Short: "Renames a node in your network",
	Run: func(cmd *cobra.Command, args []string) {
		output := GetOutputFlag(cmd)

		identifier, err := GetNodeIdentifier(cmd)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting node identifier: %s", err),
				output,
			)
			return
		}

		newName := ""
		if len(args) > 0 {
			newName = args[0]
		}

		err = WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
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
				return err
			}

			SuccessOutput(response.GetNode(), "Node renamed", output)
			return nil
		})
		if err != nil {
			return
		}
	},
}

var deleteNodeCmd = &cobra.Command{
	Use:     "delete",
	Short:   "Delete a node",
	Aliases: []string{"del"},
	Run: func(cmd *cobra.Command, args []string) {
		output := GetOutputFlag(cmd)

		identifier, err := GetNodeIdentifier(cmd)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting node identifier: %s", err),
				output,
			)
			return
		}

		var nodeName string
		err = WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
			getRequest := &v1.GetNodeRequest{
				NodeId: identifier,
			}

			getResponse, err := client.GetNode(ctx, getRequest)
			if err != nil {
				ErrorOutput(
					err,
					"Error getting node node: "+status.Convert(err).Message(),
					output,
				)
				return err
			}
			nodeName = getResponse.GetNode().GetName()
			return nil
		})
		if err != nil {
			return
		}

		confirm := false
		force, _ := cmd.Flags().GetBool("force")
		if !force {
			prompt := &survey.Confirm{
				Message: fmt.Sprintf(
					"Do you want to remove the node %s?",
					nodeName,
				),
			}
			err = survey.AskOne(prompt, &confirm)
			if err != nil {
				return
			}
		}

		if confirm || force {
			err = WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
				deleteRequest := &v1.DeleteNodeRequest{
					NodeId: identifier,
				}

				response, err := client.DeleteNode(ctx, deleteRequest)
				if output != "" {
					SuccessOutput(response, "", output)
					return nil
				}
				if err != nil {
					ErrorOutput(
						err,
						"Error deleting node: "+status.Convert(err).Message(),
						output,
					)
					return err
				}
				SuccessOutput(
					map[string]string{"Result": "Node deleted"},
					"Node deleted",
					output,
				)
				return nil
			})
			if err != nil {
				return
			}
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
		output := GetOutputFlag(cmd)

		identifier, err := GetNodeIdentifier(cmd)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting node identifier: %s", err),
				output,
			)
			return
		}

		userID, err := GetUserIdentifier(cmd)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting user: %s", err),
				output,
			)
			return
		}

		err = WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
			getRequest := &v1.GetNodeRequest{
				NodeId: identifier,
			}

			_, err := client.GetNode(ctx, getRequest)
			if err != nil {
				ErrorOutput(
					err,
					"Error getting node: "+status.Convert(err).Message(),
					output,
				)
				return err
			}

			moveRequest := &v1.MoveNodeRequest{
				NodeId: identifier,
				User:   userID,
			}

			moveResponse, err := client.MoveNode(ctx, moveRequest)
			if err != nil {
				ErrorOutput(
					err,
					"Error moving node: "+status.Convert(err).Message(),
					output,
				)
				return err
			}

			SuccessOutput(moveResponse.GetNode(), "Node moved to another user", output)
			return nil
		})
		if err != nil {
			return
		}
	},
}

var backfillNodeIPsCmd = &cobra.Command{
	Use:     "backfill-ips",
	Short:   "Backfill IPs missing from nodes",
	Aliases: []string{"backfillips"},
	Long: `
Backfill IPs can be used to add/remove IPs from nodes
based on the current configuration of Headscale.

If there are nodes that does not have IPv4 or IPv6
even if prefixes for both are configured in the config,
this command can be used to assign IPs of the sort to
all nodes that are missing.

If you remove IPv4 or IPv6 prefixes from the config,
it can be run to remove the IPs that should no longer
be assigned to nodes.`,
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		output := GetOutputFlag(cmd)

		confirm := false
		prompt := &survey.Confirm{
			Message: "Are you sure that you want to assign/remove IPs to/from nodes?",
		}
		err = survey.AskOne(prompt, &confirm)
		if err != nil {
			return
		}
		if confirm {
			err = WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
				changes, err := client.BackfillNodeIPs(ctx, &v1.BackfillNodeIPsRequest{Confirmed: confirm})
				if err != nil {
					ErrorOutput(
						err,
						"Error backfilling IPs: "+status.Convert(err).Message(),
						output,
					)
					return err
				}

				SuccessOutput(changes, "Node IPs backfilled successfully", output)
				return nil
			})
			if err != nil {
				return
			}
		}
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
		"Connected",
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
		if node.GetPreAuthKey() != nil && node.GetPreAuthKey().GetEphemeral() {
			ephemeral = true
		}

		var lastSeen time.Time
		var lastSeenTime string
		if node.GetLastSeen() != nil {
			lastSeen = node.GetLastSeen().AsTime()
			lastSeenTime = lastSeen.Format(HeadscaleDateTimeFormat)
		}

		var expiry time.Time
		var expiryTime string
		if node.GetExpiry() != nil {
			expiry = node.GetExpiry().AsTime()
			expiryTime = expiry.Format(HeadscaleDateTimeFormat)
		} else {
			expiryTime = "N/A"
		}

		var machineKey key.MachinePublic
		err := machineKey.UnmarshalText(
			[]byte(node.GetMachineKey()),
		)
		if err != nil {
			machineKey = key.MachinePublic{}
		}

		var nodeKey key.NodePublic
		err = nodeKey.UnmarshalText(
			[]byte(node.GetNodeKey()),
		)
		if err != nil {
			return nil, err
		}

		var online string
		if node.GetOnline() {
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
		for _, tag := range node.GetForcedTags() {
			forcedTags += "," + tag
		}
		forcedTags = strings.TrimLeft(forcedTags, ",")
		var invalidTags string
		for _, tag := range node.GetInvalidTags() {
			if !slices.Contains(node.GetForcedTags(), tag) {
				invalidTags += "," + pterm.LightRed(tag)
			}
		}
		invalidTags = strings.TrimLeft(invalidTags, ",")
		var validTags string
		for _, tag := range node.GetValidTags() {
			if !slices.Contains(node.GetForcedTags(), tag) {
				validTags += "," + pterm.LightGreen(tag)
			}
		}
		validTags = strings.TrimLeft(validTags, ",")

		var user string
		if currentUser == "" || (currentUser == node.GetUser().GetName()) {
			user = pterm.LightMagenta(node.GetUser().GetName())
		} else {
			// Shared into this user
			user = pterm.LightYellow(node.GetUser().GetName())
		}

		var IPV4Address string
		var IPV6Address string
		for _, addr := range node.GetIpAddresses() {
			if netip.MustParseAddr(addr).Is4() {
				IPV4Address = addr
			} else {
				IPV6Address = addr
			}
		}

		nodeData := []string{
			strconv.FormatUint(node.GetId(), util.Base10),
			node.GetName(),
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

func nodeRoutesToPtables(
	nodes []*v1.Node,
) (pterm.TableData, error) {
	tableHeader := []string{
		"ID",
		"Hostname",
		"Approved",
		"Available",
		"Serving (Primary)",
	}
	tableData := pterm.TableData{tableHeader}

	for _, node := range nodes {
		nodeData := []string{
			strconv.FormatUint(node.GetId(), util.Base10),
			node.GetGivenName(),
			strings.Join(node.GetApprovedRoutes(), ", "),
			strings.Join(node.GetAvailableRoutes(), ", "),
			strings.Join(node.GetSubnetRoutes(), ", "),
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
		output := GetOutputFlag(cmd)

		// retrieve flags from CLI
		identifier, err := GetNodeIdentifier(cmd)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting node identifier: %s", err),
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

		err = WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
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
				return err
			}

			if resp != nil {
				SuccessOutput(
					resp.GetNode(),
					"Node updated",
					output,
				)
			}
			return nil
		})
		if err != nil {
			return
		}
	},
}

var approveRoutesCmd = &cobra.Command{
	Use:   "approve-routes",
	Short: "Manage the approved routes of a node",
	Run: func(cmd *cobra.Command, args []string) {
		output := GetOutputFlag(cmd)

		// retrieve flags from CLI
		identifier, err := GetNodeIdentifier(cmd)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error getting node identifier: %s", err),
				output,
			)
			return
		}
		routes, err := cmd.Flags().GetStringSlice("routes")
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf("Error retrieving list of routes to add to node, %v", err),
				output,
			)
			return
		}

		err = WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
			// Sending routes to node
			request := &v1.SetApprovedRoutesRequest{
				NodeId: identifier,
				Routes: routes,
			}
			resp, err := client.SetApprovedRoutes(ctx, request)
			if err != nil {
				ErrorOutput(
					err,
					fmt.Sprintf("Error while sending routes to headscale: %s", err),
					output,
				)
				return err
			}

			if resp != nil {
				SuccessOutput(
					resp.GetNode(),
					"Node updated",
					output,
				)
			}
			return nil
		})
		if err != nil {
			return
		}
	},
}
