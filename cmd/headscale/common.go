package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

// Global flags available to all commands
var globalArgs struct {
	Config string `flag:"config,c,Config file path"`
	Output string `flag:"output,o,Output format (json, yaml, table)"`
	Force  bool   `flag:"force,Skip confirmation prompts"`
}

// userIdentifier represents a parsed user identifier
type userIdentifier struct {
	Type  string // "id", "username", "email", "provider"
	Value string
}

// nodeIdentifier represents a parsed node identifier
type nodeIdentifier struct {
	Type  string // "id", "name"
	Value string
}

// parseUserIdentifier parses a user identifier string and determines its type
func parseUserIdentifier(input string) userIdentifier {
	// Try to parse as numeric ID first
	if id, err := strconv.ParseUint(input, 10, 64); err == nil && id > 0 {
		return userIdentifier{Type: "id", Value: input}
	}

	// Check if it looks like an email
	if strings.Contains(input, "@") && strings.Contains(input, ".") {
		return userIdentifier{Type: "email", Value: input}
	}

	// Check if it looks like a provider identifier (contains a colon)
	if strings.Contains(input, ":") {
		return userIdentifier{Type: "provider", Value: input}
	}

	// Default to username
	return userIdentifier{Type: "username", Value: input}
}

// parseNodeIdentifier parses a node identifier string and determines its type
func parseNodeIdentifier(input string) nodeIdentifier {
	// Try to parse as numeric ID first
	if id, err := strconv.ParseUint(input, 10, 64); err == nil && id > 0 {
		return nodeIdentifier{Type: "id", Value: input}
	}

	// Default to name (will search both hostname and givenname on server side)
	return nodeIdentifier{Type: "name", Value: input}
}

// ResolveUserToID resolves a user identifier to a user ID
// This function will make a gRPC call to find the user by different identifier types
func ResolveUserToID(ctx context.Context, client v1.HeadscaleServiceClient, identifier string) (uint64, error) {
	if identifier == "" {
		return 0, fmt.Errorf("user identifier cannot be empty")
	}

	parsed := parseUserIdentifier(identifier)

	var request *v1.ListUsersRequest

	switch parsed.Type {
	case "id":
		// Already an ID, just parse and return
		id, err := strconv.ParseUint(parsed.Value, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid user ID: %w", err)
		}
		return id, nil

	case "username":
		request = &v1.ListUsersRequest{Name: parsed.Value}

	case "email":
		request = &v1.ListUsersRequest{Email: parsed.Value}

	case "provider":
		request = &v1.ListUsersRequest{ProviderId: parsed.Value}

	default:
		return 0, fmt.Errorf("unknown user identifier type: %s", parsed.Type)
	}

	response, err := client.ListUsers(ctx, request)
	if err != nil {
		return 0, fmt.Errorf("failed to list users: %w", err)
	}

	users := response.GetUsers()
	if len(users) == 0 {
		return 0, fmt.Errorf("user with %s '%s' not found", parsed.Type, parsed.Value)
	}

	if len(users) > 1 {
		return 0, fmt.Errorf("multiple users found with %s '%s'", parsed.Type, parsed.Value)
	}

	return users[0].GetId(), nil
}

// withHeadscaleClient handles the common gRPC client setup and cleanup pattern
// It takes a function that accepts a context and client, and handles all the boilerplate
func withHeadscaleClient(fn func(context.Context, v1.HeadscaleServiceClient) error) error {
	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(globalArgs.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()
	return fn(ctx, client)
}

// resolveUserWithFallback resolves a user identifier to a user ID with backwards compatibility fallback
// It first tries to resolve via ResolveUserToID, then falls back to parsing as direct uint64
func resolveUserWithFallback(ctx context.Context, client v1.HeadscaleServiceClient, userIdentifier string) (uint64, error) {
	// Try to resolve user identifier to ID
	userID, err := ResolveUserToID(ctx, client, userIdentifier)
	if err != nil {
		// Fallback: try parsing as direct uint64 for backwards compatibility
		if parsedID, parseErr := strconv.ParseUint(userIdentifier, 10, 64); parseErr == nil {
			return parsedID, nil
		}
		return 0, fmt.Errorf("cannot resolve user identifier '%s': %w", userIdentifier, err)
	}
	return userID, nil
}

// ResolveNodeToID resolves a node identifier to a node ID
// This function will make a gRPC call to find the node by different identifier types
func ResolveNodeToID(ctx context.Context, client v1.HeadscaleServiceClient, identifier string) (uint64, error) {
	if identifier == "" {
		return 0, fmt.Errorf("node identifier cannot be empty")
	}

	parsed := parseNodeIdentifier(identifier)

	switch parsed.Type {
	case "id":
		// Already an ID, just parse and return
		id, err := strconv.ParseUint(parsed.Value, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid node ID: %w", err)
		}
		return id, nil

	case "name":
		// Find node by name using new gRPC filtering
		request := &v1.ListNodesRequest{Name: parsed.Value}
		response, err := client.ListNodes(ctx, request)
		if err != nil {
			return 0, fmt.Errorf("failed to list nodes: %w", err)
		}

		nodes := response.GetNodes()
		if len(nodes) == 0 {
			return 0, fmt.Errorf("node with name '%s' not found", parsed.Value)
		}

		if len(nodes) > 1 {
			return 0, fmt.Errorf("multiple nodes found with name '%s'", parsed.Value)
		}

		return nodes[0].GetId(), nil

	default:
		return 0, fmt.Errorf("unknown node identifier type: %s", parsed.Type)
	}
}

// resolveNodeWithFallback resolves a node identifier to a node ID with backwards compatibility fallback
// It first tries to resolve via ResolveNodeToID, then falls back to parsing as direct uint64
func resolveNodeWithFallback(ctx context.Context, client v1.HeadscaleServiceClient, nodeIdentifier string) (uint64, error) {
	// Try to resolve node identifier to ID
	nodeID, err := ResolveNodeToID(ctx, client, nodeIdentifier)
	if err != nil {
		// Fallback: try parsing as direct uint64 for backwards compatibility
		if parsedID, parseErr := strconv.ParseUint(nodeIdentifier, 10, 64); parseErr == nil {
			return parsedID, nil
		}
		return 0, fmt.Errorf("cannot resolve node identifier '%s': %w", nodeIdentifier, err)
	}
	return nodeID, nil
}

// Command alias helper functions

// createCommandAlias creates a command alias with Unlisted: true
// It copies the original command structure and updates the name and help text
func createCommandAlias(original *command.C, aliasName, aliasHelp string) *command.C {
	alias := &command.C{
		Name:     aliasName,
		Usage:    original.Usage,
		Help:     aliasHelp,
		Run:      original.Run,
		SetFlags: original.SetFlags,
		Commands: original.Commands,
		Unlisted: true,
	}
	return alias
}

// createSubcommandAlias creates an alias for a subcommand within a command group
func createSubcommandAlias(originalRun func(*command.Env) error, aliasName, usage, aliasHelp string) *command.C {
	return &command.C{
		Name:     aliasName,
		Usage:    usage,
		Help:     aliasHelp,
		SetFlags: command.Flags(flax.MustBind, &globalArgs),
		Run:      originalRun,
		Unlisted: true,
	}
}

// Validation helper functions

// requireString validates that a required string flag is provided
func requireString(value, name string) error {
	if value == "" {
		return fmt.Errorf("--%s flag is required", name)
	}
	return nil
}

// requireUint64 validates that a required uint64 flag is provided
func requireUint64(value uint64, name string) error {
	if value == 0 {
		return fmt.Errorf("--%s flag is required", name)
	}
	return nil
}

// requireEither validates that at least one of two string values is provided
func requireEither(value1, name1, value2, name2 string) error {
	if value1 == "" && value2 == "" {
		return fmt.Errorf("either --%s or --%s flag is required", name1, name2)
	}
	return nil
}

// validateUserIdentifier validates that either ID or name is provided for user commands
func validateUserIdentifier(id uint64, name string) error {
	if id == 0 && name == "" {
		return fmt.Errorf("either --id or --name flag is required")
	}
	return nil
}

// validateNodeIdentifier validates that either ID or node identifier is provided for node commands
func validateNodeIdentifier(id uint64, node string) error {
	if id == 0 && node == "" {
		return fmt.Errorf("either --id or --node flag is required")
	}
	return nil
}

// requireNodeIdentifier validates that either ID or node identifier is provided
func requireNodeIdentifier(id uint64, node string) error {
	return validateNodeIdentifier(id, node)
}

// parseCommaSeparated parses a comma-separated string into a slice of strings
func parseCommaSeparated(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// getUserIDFromIdentifier resolves a user identifier (ID or name) to a user ID
// This centralizes the common pattern of looking up users by ID or name
func getUserIDFromIdentifier(ctx context.Context, client v1.HeadscaleServiceClient, id uint64, name string) (uint64, error) {
	if id != 0 {
		return id, nil
	}

	if name == "" {
		return 0, fmt.Errorf("either ID or name must be provided")
	}

	// Find user by name
	listReq := &v1.ListUsersRequest{Name: name}
	listResp, err := client.ListUsers(ctx, listReq)
	if err != nil {
		return 0, fmt.Errorf("cannot find user: %w", err)
	}
	if len(listResp.GetUsers()) == 0 {
		return 0, fmt.Errorf("user with name '%s' not found", name)
	}

	return listResp.GetUsers()[0].GetId(), nil
}

// getNodeIDFromIdentifier resolves a node identifier (ID or node identifier) to a node ID
// This centralizes the common pattern of looking up nodes by ID or identifier
func getNodeIDFromIdentifier(ctx context.Context, client v1.HeadscaleServiceClient, id uint64, nodeIdentifier string) (uint64, error) {
	if id != 0 {
		return id, nil
	}

	if nodeIdentifier == "" {
		return 0, fmt.Errorf("either ID or node identifier must be provided")
	}

	// Resolve node identifier to ID with fallback
	return resolveNodeWithFallback(ctx, client, nodeIdentifier)
}

// confirmDeletion prompts for deletion confirmation unless force is specified
// Returns true if the operation should proceed, false if cancelled
func confirmDeletion(itemType, itemName string, force bool) (bool, error) {
	if force {
		return true, nil
	}

	var confirmed bool
	prompt := &survey.Confirm{
		Message: fmt.Sprintf("Are you sure you want to delete %s '%s'?", itemType, itemName),
		Default: false,
	}

	err := survey.AskOne(prompt, &confirmed)
	if err != nil {
		return false, fmt.Errorf("confirmation prompt failed: %w", err)
	}

	return confirmed, nil
}

// parseDurationWithDefault parses a duration string with a default fallback
// This centralizes the common pattern of parsing expiration durations
func parseDurationWithDefault(durationStr string, defaultDuration time.Duration) (time.Time, error) {
	if durationStr == "" {
		return time.Now().Add(defaultDuration), nil
	}

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid duration: %w", err)
	}

	return time.Now().Add(duration), nil
}

// validateEmailFormat validates email format
func validateEmailFormat(email string) error {
	if email != "" && !strings.Contains(email, "@") {
		return fmt.Errorf("invalid email format: %s", email)
	}
	return nil
}

// validateDuration validates duration format
func validateDuration(durationStr string) error {
	if durationStr == "" {
		return nil
	}
	_, err := time.ParseDuration(durationStr)
	return err
}

// validateRoutes validates route format (CIDR notation)
func validateRoutes(routesStr string) error {
	if routesStr == "" {
		return nil
	}
	routes := parseCommaSeparated(routesStr)
	for _, route := range routes {
		if _, _, err := net.ParseCIDR(route); err != nil {
			return fmt.Errorf("invalid route format '%s': %w", route, err)
		}
	}
	return nil
}

// formatGRPCError converts gRPC errors to user-friendly messages
func formatGRPCError(err error) error {
	if err == nil {
		return nil
	}

	// Convert gRPC errors to user-friendly messages
	errStr := err.Error()

	// Handle common gRPC error patterns
	switch {
	case strings.Contains(errStr, "not found") || strings.Contains(errStr, "NotFound"):
		return fmt.Errorf("resource not found - please check your identifier")
	case strings.Contains(errStr, "already exists") || strings.Contains(errStr, "AlreadyExists"):
		return fmt.Errorf("resource already exists - use a different name")
	case strings.Contains(errStr, "permission denied") || strings.Contains(errStr, "PermissionDenied"):
		return fmt.Errorf("permission denied - check your API key or access rights")
	case strings.Contains(errStr, "invalid argument") || strings.Contains(errStr, "InvalidArgument"):
		return fmt.Errorf("invalid argument provided - check your input values")
	case strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "Unavailable"):
		return fmt.Errorf("cannot connect to headscale server - check if it's running and accessible")
	default:
		return err
	}
}
