package cli

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/pterm/pterm"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"
	"tailscale.com/types/key"
)

func init() {
	rootCmd.AddCommand(nodeCmd)
	listNodesCmd.Flags().StringP("user", "u", "", "Filter by user")
	nodeCmd.AddCommand(listNodesCmd)

	listNodeRoutesCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	nodeCmd.AddCommand(listNodeRoutesCmd)

	registerNodeCmd.Flags().StringP("user", "u", "", "User")
	registerNodeCmd.Flags().StringP("key", "k", "", "Key")
	mustMarkRequired(registerNodeCmd, "user", "key")
	nodeCmd.AddCommand(registerNodeCmd)

	expireNodeCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	expireNodeCmd.Flags().StringP("expiry", "e", "", "Set expire to (RFC3339 format, e.g. 2025-08-27T10:00:00Z), or leave empty to expire immediately.")
	mustMarkRequired(expireNodeCmd, "identifier")
	nodeCmd.AddCommand(expireNodeCmd)

	renameNodeCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	mustMarkRequired(renameNodeCmd, "identifier")
	nodeCmd.AddCommand(renameNodeCmd)

	deleteNodeCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	mustMarkRequired(deleteNodeCmd, "identifier")
	nodeCmd.AddCommand(deleteNodeCmd)

	tagCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	mustMarkRequired(tagCmd, "identifier")
	tagCmd.Flags().StringSliceP("tags", "t", []string{}, "List of tags to add to the node")
	nodeCmd.AddCommand(tagCmd)

	approveRoutesCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
	mustMarkRequired(approveRoutesCmd, "identifier")
	approveRoutesCmd.Flags().StringSliceP("routes", "r", []string{}, `List of routes that will be approved (comma-separated, e.g. "10.0.0.0/8,192.168.0.0/24" or empty string to remove all approved routes)`)
	nodeCmd.AddCommand(approveRoutesCmd)

	nodeCmd.AddCommand(backfillNodeIPsCmd)
}

var nodeCmd = &cobra.Command{
	Use:     "nodes",
	Short:   "Manage the nodes of Headscale",
	Aliases: []string{"node"},
}

var registerNodeCmd = &cobra.Command{
	Use:        "register",
	Short:      "Registers a node to your network",
	Deprecated: "use 'headscale auth register --auth-id <id> --user <user>' instead",
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		user, _ := cmd.Flags().GetString("user")
		registrationID, _ := cmd.Flags().GetString("key")

		request := &v1.RegisterNodeRequest{
			Key:  registrationID,
			User: user,
		}

		response, err := client.RegisterNode(ctx, request)
		if err != nil {
			return fmt.Errorf("registering node: %w", err)
		}

		return printOutput(
			cmd,
			response.GetNode(),
			fmt.Sprintf("Node %s registered", response.GetNode().GetGivenName()))
	}),
}

var listNodesCmd = &cobra.Command{
	Use:     "list",
	Short:   "List nodes",
	Aliases: []string{"ls", "show"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		user, _ := cmd.Flags().GetString("user")

		response, err := client.ListNodes(ctx, &v1.ListNodesRequest{User: user})
		if err != nil {
			return fmt.Errorf("listing nodes: %w", err)
		}

		return printListOutput(cmd, response.GetNodes(), func() error {
			tableData, err := nodesToPtables(user, response.GetNodes())
			if err != nil {
				return fmt.Errorf("converting to table: %w", err)
			}

			return pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
		})
	}),
}

var listNodeRoutesCmd = &cobra.Command{
	Use:     "list-routes",
	Short:   "List routes available on nodes",
	Aliases: []string{"lsr", "routes"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		identifier, _ := cmd.Flags().GetUint64("identifier")

		response, err := client.ListNodes(ctx, &v1.ListNodesRequest{})
		if err != nil {
			return fmt.Errorf("listing nodes: %w", err)
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

		return printListOutput(cmd, nodes, func() error {
			return pterm.DefaultTable.WithHasHeader().WithData(nodeRoutesToPtables(nodes)).Render()
		})
	}),
}

var expireNodeCmd = &cobra.Command{
	Use:     "expire",
	Short:   "Expire (log out) a node in your network",
	Long:    "Expiring a node will keep the node in the database and force it to reauthenticate.",
	Aliases: []string{"logout", "exp", "e"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		identifier, _ := cmd.Flags().GetUint64("identifier")
		expiry, _ := cmd.Flags().GetString("expiry")

		now := time.Now()

		expiryTime := now
		if expiry != "" {
			var err error
			expiryTime, err = time.Parse(time.RFC3339, expiry)
			if err != nil {
				return fmt.Errorf("parsing expiry time: %w", err)
			}
		}

		request := &v1.ExpireNodeRequest{
			NodeId: identifier,
			Expiry: timestamppb.New(expiryTime),
		}

		response, err := client.ExpireNode(ctx, request)
		if err != nil {
			return fmt.Errorf("expiring node: %w", err)
		}

		if now.Equal(expiryTime) || now.After(expiryTime) {
			return printOutput(cmd, response.GetNode(), "Node expired")
		}

		return printOutput(cmd, response.GetNode(), "Node expiration updated")
	}),
}

var renameNodeCmd = &cobra.Command{
	Use:   "rename NEW_NAME",
	Short: "Renames a node in your network",
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		identifier, _ := cmd.Flags().GetUint64("identifier")

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
			return fmt.Errorf("renaming node: %w", err)
		}

		return printOutput(cmd, response.GetNode(), "Node renamed")
	}),
}

var deleteNodeCmd = &cobra.Command{
	Use:     "delete",
	Short:   "Delete a node",
	Aliases: []string{"del"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		identifier, _ := cmd.Flags().GetUint64("identifier")

		getRequest := &v1.GetNodeRequest{
			NodeId: identifier,
		}

		getResponse, err := client.GetNode(ctx, getRequest)
		if err != nil {
			return fmt.Errorf("getting node: %w", err)
		}

		deleteRequest := &v1.DeleteNodeRequest{
			NodeId: identifier,
		}

		if !confirmAction(cmd, fmt.Sprintf(
			"Do you want to remove the node %s?",
			getResponse.GetNode().GetName(),
		)) {
			return printOutput(cmd, map[string]string{"Result": "Node not deleted"}, "Node not deleted")
		}

		_, err = client.DeleteNode(ctx, deleteRequest)
		if err != nil {
			return fmt.Errorf("deleting node: %w", err)
		}

		return printOutput(
			cmd,
			map[string]string{"Result": "Node deleted"},
			"Node deleted",
		)
	}),
}

var backfillNodeIPsCmd = &cobra.Command{
	Use:   "backfillips",
	Short: "Backfill IPs missing from nodes",
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
	RunE: func(cmd *cobra.Command, args []string) error {
		if !confirmAction(cmd, "Are you sure that you want to assign/remove IPs to/from nodes?") {
			return nil
		}

		ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig()
		if err != nil {
			return fmt.Errorf("connecting to headscale: %w", err)
		}
		defer cancel()
		defer conn.Close()

		changes, err := client.BackfillNodeIPs(ctx, &v1.BackfillNodeIPsRequest{Confirmed: true})
		if err != nil {
			return fmt.Errorf("backfilling IPs: %w", err)
		}

		return printOutput(cmd, changes, "Node IPs backfilled successfully")
	},
}

func nodesToPtables(
	currentUser string,
	nodes []*v1.Node,
) (pterm.TableData, error) {
	tableHeader := []string{
		"ID",
		"Hostname",
		"Name",
		"MachineKey",
		"NodeKey",
		"User",
		"Tags",
		"IP addresses",
		"Ephemeral",
		"Last seen",
		"Expiration",
		"Connected",
		"Expired",
	}
	tableData := pterm.TableData{tableHeader}

	for _, node := range nodes {
		var ephemeral bool
		if node.GetPreAuthKey() != nil && node.GetPreAuthKey().GetEphemeral() {
			ephemeral = true
		}

		var (
			lastSeen     time.Time
			lastSeenTime string
		)

		if node.GetLastSeen() != nil {
			lastSeen = node.GetLastSeen().AsTime()
			lastSeenTime = lastSeen.Format(HeadscaleDateTimeFormat)
		}

		var (
			expiry     time.Time
			expiryTime string
		)

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
		if node.GetExpiry() != nil && node.GetExpiry().AsTime().Before(time.Now()) {
			expired = pterm.LightRed("yes")
		} else {
			expired = pterm.LightGreen("no")
		}

		var tagsBuilder strings.Builder

		for _, tag := range node.GetTags() {
			tagsBuilder.WriteString("\n" + tag)
		}

		tags := strings.TrimLeft(tagsBuilder.String(), "\n")

		var user string
		if node.GetUser() != nil {
			user = node.GetUser().GetName()
		}

		var ipBuilder strings.Builder
		for _, addr := range node.GetIpAddresses() {
			ip, err := netip.ParseAddr(addr)
			if err == nil {
				if ipBuilder.Len() > 0 {
					ipBuilder.WriteString("\n")
				}

				ipBuilder.WriteString(ip.String())
			}
		}

		ipAddresses := ipBuilder.String()

		nodeData := []string{
			strconv.FormatUint(node.GetId(), util.Base10),
			node.GetName(),
			node.GetGivenName(),
			machineKey.ShortString(),
			nodeKey.ShortString(),
			user,
			tags,
			ipAddresses,
			strconv.FormatBool(ephemeral),
			lastSeenTime,
			expiryTime,
			online,
			expired,
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
) pterm.TableData {
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
			strings.Join(node.GetApprovedRoutes(), "\n"),
			strings.Join(node.GetAvailableRoutes(), "\n"),
			strings.Join(node.GetSubnetRoutes(), "\n"),
		}
		tableData = append(
			tableData,
			nodeData,
		)
	}

	return tableData
}

var tagCmd = &cobra.Command{
	Use:     "tag",
	Short:   "Manage the tags of a node",
	Aliases: []string{"tags", "t"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		identifier, _ := cmd.Flags().GetUint64("identifier")
		tagsToSet, _ := cmd.Flags().GetStringSlice("tags")

		// Sending tags to node
		request := &v1.SetTagsRequest{
			NodeId: identifier,
			Tags:   tagsToSet,
		}

		resp, err := client.SetTags(ctx, request)
		if err != nil {
			return fmt.Errorf("setting tags: %w", err)
		}

		return printOutput(cmd, resp.GetNode(), "Node updated")
	}),
}

var approveRoutesCmd = &cobra.Command{
	Use:   "approve-routes",
	Short: "Manage the approved routes of a node",
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		identifier, _ := cmd.Flags().GetUint64("identifier")
		routes, _ := cmd.Flags().GetStringSlice("routes")

		// Sending routes to node
		request := &v1.SetApprovedRoutesRequest{
			NodeId: identifier,
			Routes: routes,
		}

		resp, err := client.SetApprovedRoutes(ctx, request)
		if err != nil {
			return fmt.Errorf("setting approved routes: %w", err)
		}

		return printOutput(cmd, resp.GetNode(), "Node updated")
	}),
}
