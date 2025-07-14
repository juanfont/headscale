package cli

import (
	"fmt"

	survey "github.com/AlecAivazis/survey/v2"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/spf13/cobra"
)

// Command execution patterns for common CLI operations

// ListCommandFunc represents a function that fetches list data from the server
type ListCommandFunc func(*ClientWrapper, *cobra.Command) ([]interface{}, error)

// TableSetupFunc represents a function that configures table columns for display
type TableSetupFunc func(*TableRenderer)

// CreateCommandFunc represents a function that creates a new resource
type CreateCommandFunc func(*ClientWrapper, *cobra.Command, []string) (interface{}, error)

// GetResourceFunc represents a function that retrieves a single resource
type GetResourceFunc func(*ClientWrapper, *cobra.Command) (interface{}, error)

// DeleteResourceFunc represents a function that deletes a resource
type DeleteResourceFunc func(*ClientWrapper, *cobra.Command) (interface{}, error)

// UpdateResourceFunc represents a function that updates a resource
type UpdateResourceFunc func(*ClientWrapper, *cobra.Command, []string) (interface{}, error)

// ExecuteListCommand handles standard list command pattern
func ExecuteListCommand(cmd *cobra.Command, args []string, listFunc ListCommandFunc, tableSetup TableSetupFunc) {
	ExecuteWithClient(cmd, func(client *ClientWrapper) error {
		data, err := listFunc(client, cmd)
		if err != nil {
			return err
		}

		ListOutput(cmd, data, tableSetup)
		return nil
	})
}

// ExecuteCreateCommand handles standard create command pattern
func ExecuteCreateCommand(cmd *cobra.Command, args []string, createFunc CreateCommandFunc, successMessage string) {
	ExecuteWithClient(cmd, func(client *ClientWrapper) error {
		result, err := createFunc(client, cmd, args)
		if err != nil {
			return err
		}

		DetailOutput(cmd, result, successMessage)
		return nil
	})
}

// ExecuteGetCommand handles standard get/show command pattern
func ExecuteGetCommand(cmd *cobra.Command, args []string, getFunc GetResourceFunc, resourceName string) {
	ExecuteWithClient(cmd, func(client *ClientWrapper) error {
		result, err := getFunc(client, cmd)
		if err != nil {
			return err
		}

		DetailOutput(cmd, result, fmt.Sprintf("%s details", resourceName))
		return nil
	})
}

// ExecuteUpdateCommand handles standard update command pattern
func ExecuteUpdateCommand(cmd *cobra.Command, args []string, updateFunc UpdateResourceFunc, successMessage string) {
	ExecuteWithClient(cmd, func(client *ClientWrapper) error {
		result, err := updateFunc(client, cmd, args)
		if err != nil {
			return err
		}

		DetailOutput(cmd, result, successMessage)
		return nil
	})
}

// ExecuteDeleteCommand handles standard delete command pattern with confirmation
func ExecuteDeleteCommand(cmd *cobra.Command, args []string, getFunc GetResourceFunc, deleteFunc DeleteResourceFunc, resourceName string) {
	ExecuteWithClient(cmd, func(client *ClientWrapper) error {
		// First get the resource to show what will be deleted
		resource, err := getFunc(client, cmd)
		if err != nil {
			return err
		}

		// Check if force flag is set
		force := GetForce(cmd)
		
		// Get resource name for confirmation
		var displayName string
		switch r := resource.(type) {
		case *v1.Node:
			displayName = fmt.Sprintf("node '%s'", r.GetName())
		case *v1.User:
			displayName = fmt.Sprintf("user '%s'", r.GetName())
		case *v1.ApiKey:
			displayName = fmt.Sprintf("API key '%s'", r.GetPrefix())
		case *v1.PreAuthKey:
			displayName = fmt.Sprintf("preauth key '%s'", r.GetKey())
		default:
			displayName = resourceName
		}

		// Ask for confirmation unless force is used
		if !force {
			confirmed, err := ConfirmAction(fmt.Sprintf("Delete %s?", displayName))
			if err != nil {
				return err
			}
			if !confirmed {
				ConfirmationOutput(cmd, map[string]string{"Result": "Deletion cancelled"}, "Deletion cancelled")
				return nil
			}
		}

		// Proceed with deletion
		result, err := deleteFunc(client, cmd)
		if err != nil {
			return err
		}

		ConfirmationOutput(cmd, result, fmt.Sprintf("%s deleted successfully", displayName))
		return nil
	})
}

// Confirmation utilities

// ConfirmAction prompts the user for confirmation unless force is true
func ConfirmAction(message string) (bool, error) {
	if HasMachineOutputFlag() {
		// In machine output mode, don't prompt - assume no unless force is used
		return false, nil
	}

	confirm := false
	prompt := &survey.Confirm{
		Message: message,
	}
	err := survey.AskOne(prompt, &confirm)
	return confirm, err
}

// ConfirmDeletion is a specialized confirmation for deletion operations
func ConfirmDeletion(resourceName string) (bool, error) {
	return ConfirmAction(fmt.Sprintf("Are you sure you want to delete %s? This action cannot be undone.", resourceName))
}

// Resource identification helpers

// ResolveUserByNameOrID resolves a user by name, email, or ID
func ResolveUserByNameOrID(client *ClientWrapper, cmd *cobra.Command, nameOrID string) (*v1.User, error) {
	response, err := client.ListUsers(cmd, &v1.ListUsersRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	// Try to find by ID first (if it's numeric)
	for _, user := range response.GetUsers() {
		if fmt.Sprintf("%d", user.GetId()) == nameOrID {
			return user, nil
		}
	}

	// Try to find by name
	for _, user := range response.GetUsers() {
		if user.GetName() == nameOrID {
			return user, nil
		}
	}

	// Try to find by email
	for _, user := range response.GetUsers() {
		if user.GetEmail() == nameOrID {
			return user, nil
		}
	}

	return nil, fmt.Errorf("no user found matching '%s'", nameOrID)
}

// ResolveNodeByIdentifier resolves a node by hostname, IP, name, or ID
func ResolveNodeByIdentifier(client *ClientWrapper, cmd *cobra.Command, identifier string) (*v1.Node, error) {
	response, err := client.ListNodes(cmd, &v1.ListNodesRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	var matches []*v1.Node

	// Try to find by ID first (if it's numeric)
	for _, node := range response.GetNodes() {
		if fmt.Sprintf("%d", node.GetId()) == identifier {
			matches = append(matches, node)
		}
	}

	// Try to find by hostname
	for _, node := range response.GetNodes() {
		if node.GetName() == identifier {
			matches = append(matches, node)
		}
	}

	// Try to find by given name
	for _, node := range response.GetNodes() {
		if node.GetGivenName() == identifier {
			matches = append(matches, node)
		}
	}

	// Try to find by IP address
	for _, node := range response.GetNodes() {
		for _, ip := range node.GetIpAddresses() {
			if ip == identifier {
				matches = append(matches, node)
				break
			}
		}
	}

	// Remove duplicates
	uniqueMatches := make([]*v1.Node, 0)
	seen := make(map[uint64]bool)
	for _, match := range matches {
		if !seen[match.GetId()] {
			uniqueMatches = append(uniqueMatches, match)
			seen[match.GetId()] = true
		}
	}

	if len(uniqueMatches) == 0 {
		return nil, fmt.Errorf("no node found matching '%s'", identifier)
	}
	if len(uniqueMatches) > 1 {
		var names []string
		for _, node := range uniqueMatches {
			names = append(names, fmt.Sprintf("%s (ID: %d)", node.GetName(), node.GetId()))
		}
		return nil, fmt.Errorf("ambiguous node identifier '%s', matches: %v", identifier, names)
	}

	return uniqueMatches[0], nil
}

// Bulk operations

// ProcessMultipleResources processes multiple resources with error handling
func ProcessMultipleResources[T any](
	items []T,
	processor func(T) error,
	continueOnError bool,
) []error {
	var errors []error

	for _, item := range items {
		if err := processor(item); err != nil {
			errors = append(errors, err)
			if !continueOnError {
				break
			}
		}
	}

	return errors
}

// Validation helpers for common operations

// ValidateRequiredArgs ensures the required number of arguments are provided
func ValidateRequiredArgs(cmd *cobra.Command, args []string, minArgs int, usage string) error {
	if len(args) < minArgs {
		return fmt.Errorf("insufficient arguments provided\n\nUsage: %s", usage)
	}
	return nil
}

// ValidateExactArgs ensures exactly the specified number of arguments are provided
func ValidateExactArgs(cmd *cobra.Command, args []string, exactArgs int, usage string) error {
	if len(args) != exactArgs {
		return fmt.Errorf("expected %d argument(s), got %d\n\nUsage: %s", exactArgs, len(args), usage)
	}
	return nil
}

// Common command patterns as helpers

// StandardListCommand creates a standard list command implementation
func StandardListCommand(listFunc ListCommandFunc, tableSetup TableSetupFunc) func(*cobra.Command, []string) {
	return func(cmd *cobra.Command, args []string) {
		ExecuteListCommand(cmd, args, listFunc, tableSetup)
	}
}

// StandardCreateCommand creates a standard create command implementation
func StandardCreateCommand(createFunc CreateCommandFunc, successMessage string) func(*cobra.Command, []string) {
	return func(cmd *cobra.Command, args []string) {
		ExecuteCreateCommand(cmd, args, createFunc, successMessage)
	}
}

// StandardDeleteCommand creates a standard delete command implementation
func StandardDeleteCommand(getFunc GetResourceFunc, deleteFunc DeleteResourceFunc, resourceName string) func(*cobra.Command, []string) {
	return func(cmd *cobra.Command, args []string) {
		ExecuteDeleteCommand(cmd, args, getFunc, deleteFunc, resourceName)
	}
}

// StandardUpdateCommand creates a standard update command implementation
func StandardUpdateCommand(updateFunc UpdateResourceFunc, successMessage string) func(*cobra.Command, []string) {
	return func(cmd *cobra.Command, args []string) {
		ExecuteUpdateCommand(cmd, args, updateFunc, successMessage)
	}
}

// Error handling helpers

// WrapCommandError wraps an error with command context for better error messages
func WrapCommandError(cmd *cobra.Command, err error, action string) error {
	return fmt.Errorf("failed to %s: %w", action, err)
}

// IsValidationError checks if an error is a validation error (user input problem)
func IsValidationError(err error) bool {
	// Check for common validation error patterns
	errorStr := err.Error()
	validationPatterns := []string{
		"insufficient arguments",
		"required flag",
		"invalid value",
		"must be",
		"cannot be empty",
		"not found matching",
		"ambiguous",
	}

	for _, pattern := range validationPatterns {
		if fmt.Sprintf("%s", errorStr) != errorStr {
			continue
		}
		if len(errorStr) > len(pattern) && errorStr[:len(pattern)] == pattern {
			return true
		}
	}
	return false
}