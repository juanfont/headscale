package main

import (
	"context"
	"fmt"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

// Node command flags
var nodeArgs struct {
	ID         uint64 `flag:"id,i,Node ID"`
	Identifier uint64 `flag:"identifier,Node ID (backward compatibility alias for --id)"`
	Node       string `flag:"node,n,Node identifier (ID, hostname, or given name)"`
	User       string `flag:"user,u,User identifier (ID, username, email, or provider ID)"`
	ShowTags   bool   `flag:"show-tags,Show tags in output"`
	Tags       string `flag:"tags,t,Comma-separated tags"`
	Routes     string `flag:"routes,r,Comma-separated routes"`
	Key        string `flag:"key,k,Registration key"`
	NewName    string `flag:"new-name,New node name"`
}

// Helper function to get node ID from either --id or --identifier flags
// Prioritizes --id but falls back to --identifier for backward compatibility
func getIDFromNodeFlags() uint64 {
	if nodeArgs.ID != 0 {
		return nodeArgs.ID
	}
	return nodeArgs.Identifier
}

// Node command implementations

func registerNodeCommand(env *command.Env) error {
	if err := requireString(nodeArgs.User, "user"); err != nil {
		return err
	}
	if err := requireString(nodeArgs.Key, "key"); err != nil {
		return err
	}

	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		request := &v1.RegisterNodeRequest{
			Key:  nodeArgs.Key,
			User: nodeArgs.User,
		}

		response, err := client.RegisterNode(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot register node: %w", err)
		}

		return outputResult(
			response.GetNode(),
			fmt.Sprintf("Node %s registered", response.GetNode().GetGivenName()),
			globalArgs.Output,
		)
	})
}

func listNodesCommand(env *command.Env) error {
	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		request := &v1.ListNodesRequest{}

		// If user is specified, use it directly as string
		if nodeArgs.User != "" {
			request.User = nodeArgs.User
		}

		response, err := client.ListNodes(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot get nodes: %w", err)
		}

		if globalArgs.Output != "" {
			return outputResult(response.GetNodes(), "Nodes", globalArgs.Output)
		}

		tableData, err := nodesToPtables(nodeArgs.User, nodeArgs.ShowTags, response.GetNodes())
		if err != nil {
			return fmt.Errorf("error converting to table: %w", err)
		}

		return outputResult(tableData, "Nodes", "table")
	})
}

func expireNodeCommand(env *command.Env) error {
	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		// Get node ID from either --id or --identifier
		nodeID := getIDFromNodeFlags()
		if nodeID == 0 && nodeArgs.Node == "" {
			return fmt.Errorf("either --id/--identifier or --node flag is required")
		}

		finalNodeID, err := getNodeIDFromIdentifier(ctx, client, nodeID, nodeArgs.Node)
		if err != nil {
			return err
		}

		request := &v1.ExpireNodeRequest{NodeId: finalNodeID}

		response, err := client.ExpireNode(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot expire node: %w", err)
		}

		return outputResult(response.GetNode(), "Node expired", globalArgs.Output)
	})
}

func renameNodeCommand(env *command.Env) error {
	// Get new name from flag
	newName := nodeArgs.NewName
	if newName == "" {
		return fmt.Errorf("--new-name flag is required")
	}

	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		// Get node ID from either --id or --identifier
		nodeID := getIDFromNodeFlags()
		if nodeID == 0 && nodeArgs.Node == "" {
			return fmt.Errorf("either --id/--identifier or --node flag is required")
		}

		finalNodeID, err := getNodeIDFromIdentifier(ctx, client, nodeID, nodeArgs.Node)
		if err != nil {
			return err
		}

		request := &v1.RenameNodeRequest{
			NodeId:  finalNodeID,
			NewName: newName,
		}

		response, err := client.RenameNode(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot rename node: %w", err)
		}

		return outputResult(response.GetNode(), "Node renamed", globalArgs.Output)
	})
}

func deleteNodeCommand(env *command.Env) error {
	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		// Get node ID from either --id or --identifier
		nodeID := getIDFromNodeFlags()
		if nodeID == 0 && nodeArgs.Node == "" {
			return fmt.Errorf("either --id/--identifier or --node flag is required")
		}

		finalNodeID, err := getNodeIDFromIdentifier(ctx, client, nodeID, nodeArgs.Node)
		if err != nil {
			return err
		}

		// Get node first for confirmation
		getRequest := &v1.GetNodeRequest{NodeId: finalNodeID}

		getResponse, err := client.GetNode(ctx, getRequest)
		if err != nil {
			return fmt.Errorf("error getting node: %w", err)
		}

		// Confirm deletion using the helper
		shouldProceed, err := confirmDeletion("node", getResponse.GetNode().GetName(), globalArgs.Force)
		if err != nil {
			return err
		}
		if !shouldProceed {
			return nil
		}

		deleteRequest := &v1.DeleteNodeRequest{NodeId: finalNodeID}
		response, err := client.DeleteNode(ctx, deleteRequest)
		if err != nil {
			return fmt.Errorf("error deleting node: %w", err)
		}

		if globalArgs.Output != "" {
			return outputResult(response, "Node deleted", globalArgs.Output)
		}

		fmt.Printf("Node %s deleted successfully\n", getResponse.GetNode().GetName())
		return nil
	})
}

func moveNodeCommand(env *command.Env) error {
	if err := requireString(nodeArgs.User, "user"); err != nil {
		return err
	}

	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		// Get node ID from either --id or --identifier
		nodeID := getIDFromNodeFlags()
		if nodeID == 0 && nodeArgs.Node == "" {
			return fmt.Errorf("either --id/--identifier or --node flag is required")
		}

		finalNodeID, err := getNodeIDFromIdentifier(ctx, client, nodeID, nodeArgs.Node)
		if err != nil {
			return err
		}

		// Resolve user identifier to ID with fallback
		userID, err := resolveUserWithFallback(ctx, client, nodeArgs.User)
		if err != nil {
			return err
		}

		request := &v1.MoveNodeRequest{
			NodeId: finalNodeID,
			User:   userID,
		}

		response, err := client.MoveNode(ctx, request)
		if err != nil {
			return fmt.Errorf("error moving node: %w", err)
		}

		return outputResult(response.GetNode(), "Node moved to another user", globalArgs.Output)
	})
}

func setNodeTagsCommand(env *command.Env) error {
	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		// Get node ID from either --id or --identifier
		nodeID := getIDFromNodeFlags()
		if nodeID == 0 && nodeArgs.Node == "" {
			return fmt.Errorf("either --id/--identifier or --node flag is required")
		}

		finalNodeID, err := getNodeIDFromIdentifier(ctx, client, nodeID, nodeArgs.Node)
		if err != nil {
			return err
		}

		request := &v1.SetTagsRequest{
			NodeId: finalNodeID,
			Tags:   parseCommaSeparated(nodeArgs.Tags),
		}

		response, err := client.SetTags(ctx, request)
		if err != nil {
			return fmt.Errorf("error setting tags: %w", err)
		}

		return outputResult(response.GetNode(), "Node tags updated", globalArgs.Output)
	})
}

func listNodeRoutesCommand(env *command.Env) error {
	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		// Get node ID from either --id or --identifier
		nodeID := getIDFromNodeFlags()
		if nodeID == 0 && nodeArgs.Node == "" {
			return fmt.Errorf("either --id/--identifier or --node flag is required")
		}

		finalNodeID, err := getNodeIDFromIdentifier(ctx, client, nodeID, nodeArgs.Node)
		if err != nil {
			return err
		}

		// Get the node first to access its routes
		request := &v1.GetNodeRequest{NodeId: finalNodeID}
		response, err := client.GetNode(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot get node: %w", err)
		}

		node := response.GetNode()
		routes := map[string]interface{}{
			"approved_routes":  node.GetApprovedRoutes(),
			"available_routes": node.GetAvailableRoutes(),
			"subnet_routes":    node.GetSubnetRoutes(),
		}

		return outputResult(routes, "Node Routes", globalArgs.Output)
	})
}

func approveNodeRoutesCommand(env *command.Env) error {
	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		// Get node ID from either --id or --identifier
		nodeID := getIDFromNodeFlags()
		if nodeID == 0 && nodeArgs.Node == "" {
			return fmt.Errorf("either --id/--identifier or --node flag is required")
		}

		finalNodeID, err := getNodeIDFromIdentifier(ctx, client, nodeID, nodeArgs.Node)
		if err != nil {
			return err
		}

		request := &v1.SetApprovedRoutesRequest{
			NodeId: finalNodeID,
			Routes: parseCommaSeparated(nodeArgs.Routes),
		}

		response, err := client.SetApprovedRoutes(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot approve routes: %w", err)
		}

		return outputResult(response.GetNode(), "Routes approved", globalArgs.Output)
	})
}

func backfillNodeIPsCommand(env *command.Env) error {
	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		request := &v1.BackfillNodeIPsRequest{
			Confirmed: globalArgs.Force,
		}

		response, err := client.BackfillNodeIPs(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot backfill node IPs: %w", err)
		}

		return outputResult(response.GetChanges(), "Node IPs backfilled", globalArgs.Output)
	})
}

// Node command definitions

func nodeCommands() []*command.C {
	nodeCommand := &command.C{
		Name:     "nodes",
		Usage:    "<subcommand> [flags] [args...]",
		Help:     "Manage nodes in Headscale",
		SetFlags: command.Flags(flax.MustBind, &globalArgs, &nodeArgs),
		Commands: []*command.C{
			{
				Name:  "register",
				Usage: "--user <user> --key <key>",
				Help:  "Register a new node with the specified user and registration key",
				Run:   registerNodeCommand,
			},
			{
				Name:  "list",
				Usage: "[--user <user>] [--output json|yaml|table]",
				Help:  "List all nodes or nodes for a specific user",
				Run:   listNodesCommand,
			},
			createSubcommandAlias(listNodesCommand, "ls", "[--user <user>] [flags]", "List nodes (alias)"),
			{
				Name:  "expire",
				Usage: "--id <id> | --node <node>",
				Help:  "Expire a node immediately, forcing re-authentication",
				Run:   expireNodeCommand,
			},
			{
				Name:  "rename",
				Usage: "--id <id> | --node <node> --new-name <new-name>",
				Help:  "Rename a node to a new given name",
				Run:   renameNodeCommand,
			},
			{
				Name:  "delete",
				Usage: "--id <id> | --node <node> [--force]",
				Help:  "Delete a node permanently (prompts for confirmation unless --force is used)",
				Run:   deleteNodeCommand,
			},
			createSubcommandAlias(deleteNodeCommand, "destroy", "--id <id> | --node <node> [--force]", "Delete a node permanently (alias for delete)"),
			{
				Name:  "move",
				Usage: "--id <id> | --node <node> --user <user>",
				Help:  "Move a node to a different user (changes ownership)",
				Run:   moveNodeCommand,
			},
			{
				Name:  "tags",
				Usage: "--id <id> | --node <node> --tags <tag1,tag2,...>",
				Help:  "Set forced tags for a node (comma-separated, must start with 'tag:')",
				Run:   setNodeTagsCommand,
			},
			{
				Name:  "routes",
				Usage: "<subcommand> [flags]",
				Help:  "Manage node routes",
				Commands: []*command.C{
					{
						Name:  "list",
						Usage: "--id <id> | --node <node>",
						Help:  "List all routes advertised by a specific node",
						Run:   listNodeRoutesCommand,
					},
					{
						Name:  "approve",
						Usage: "--id <id> | --node <node> --routes <route1,route2,...>",
						Help:  "Approve specific routes for a node (comma-separated CIDR notation)",
						Run:   approveNodeRoutesCommand,
					},
				},
			},
			{
				Name:  "backfill-ips",
				Usage: "",
				Help:  "Backfill node IPs",
				Run:   backfillNodeIPsCommand,
			},
		},
	}

	return []*command.C{
		nodeCommand,
		// Node management alias
		createCommandAlias(nodeCommand, "node", "Manage nodes in Headscale (alias)"),
	}
}
