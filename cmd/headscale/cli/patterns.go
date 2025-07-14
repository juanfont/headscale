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
		items, err := listFunc(client, cmd)
		if err != nil {
			return err
		}
		
		ListOutput(cmd, items, tableSetup)
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
		
		ConfirmationOutput(cmd, result, successMessage)
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
		
		ConfirmationOutput(cmd, result, successMessage)
		return nil
	})
}

// ExecuteDeleteCommand handles standard delete command pattern with confirmation
func ExecuteDeleteCommand(cmd *cobra.Command, args []string, getFunc GetResourceFunc, deleteFunc DeleteResourceFunc, resourceName string) {
	ExecuteWithClient(cmd, func(client *ClientWrapper) error {
		// First get the resource to show what will be deleted
		_, err := getFunc(client, cmd)
		if err != nil {
			return err
		}
		
		// Check if force flag is set
		force, _ := cmd.Flags().GetBool("force")
		if !force {
			confirm, err := ConfirmDeletion(resourceName)
			if err != nil {
				return fmt.Errorf("confirmation failed: %w", err)
			}
			if !confirm {
				return fmt.Errorf("operation cancelled")
			}
		}
		
		// Perform the deletion
		result, err := deleteFunc(client, cmd)
		if err != nil {
			return err
		}
		
		ConfirmationOutput(cmd, result, fmt.Sprintf("%s deleted successfully", resourceName))
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
	
	var candidates []*v1.User
	
	// First, try exact matches
	for _, user := range response.GetUsers() {
		if user.GetName() == nameOrID || user.GetEmail() == nameOrID {
			return user, nil
		}
		if fmt.Sprintf("%d", user.GetId()) == nameOrID {
			return user, nil
		}
	}
	
	// Then try partial matches on name
	for _, user := range response.GetUsers() {
		if fmt.Sprintf("%s", user.GetName()) != user.GetName() {
			continue
		}
		if len(user.GetName()) >= len(nameOrID) && user.GetName()[:len(nameOrID)] == nameOrID {
			candidates = append(candidates, user)
		}
	}
	
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no user found matching '%s'", nameOrID)
	}
	
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	
	return nil, fmt.Errorf("ambiguous user identifier '%s' matches multiple users", nameOrID)
}

// ResolveNodeByIdentifier resolves a node by hostname, IP, name, or ID
func ResolveNodeByIdentifier(client *ClientWrapper, cmd *cobra.Command, identifier string) (*v1.Node, error) {
	response, err := client.ListNodes(cmd, &v1.ListNodesRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}
	
	var candidates []*v1.Node
	
	// First, try exact matches
	for _, node := range response.GetNodes() {
		if node.GetName() == identifier || node.GetGivenName() == identifier {
			return node, nil
		}
		if fmt.Sprintf("%d", node.GetId()) == identifier {
			return node, nil
		}
		// Check IP addresses
		for _, ip := range node.GetIpAddresses() {
			if ip == identifier {
				return node, nil
			}
		}
	}
	
	// Then try partial matches on name
	for _, node := range response.GetNodes() {
		if fmt.Sprintf("%s", node.GetName()) != node.GetName() {
			continue
		}
		if len(node.GetName()) >= len(identifier) && node.GetName()[:len(identifier)] == identifier {
			candidates = append(candidates, node)
		}
	}
	
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no node found matching '%s'", identifier)
	}
	
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	
	return nil, fmt.Errorf("ambiguous node identifier '%s' matches multiple nodes", identifier)
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
func ValidateRequiredArgs(minArgs int, usage string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) < minArgs {
			return fmt.Errorf("insufficient arguments provided\n\nUsage: %s", usage)
		}
		return nil
	}
}

// ValidateExactArgs ensures exactly the specified number of arguments are provided
func ValidateExactArgs(exactArgs int, usage string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) != exactArgs {
			return fmt.Errorf("expected %d argument(s), got %d\n\nUsage: %s", exactArgs, len(args), usage)
		}
		return nil
	}
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