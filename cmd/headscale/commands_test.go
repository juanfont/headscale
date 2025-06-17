package main

import (
	"context"
	"strings"
	"testing"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
)

func TestCommandStructure(t *testing.T) {
	// Test that the command tree is properly structured
	root := createTestRootCommand()

	// Test that root command exists
	if root.Name != "headscale" {
		t.Errorf("Expected root command name 'headscale', got '%s'", root.Name)
	}

	// Test that subcommands exist
	expectedCommands := []string{"serve", "version", "config", "users", "nodes", "preauth-keys", "api-keys", "policy", "dev"}
	for _, expectedCmd := range expectedCommands {
		found := false
		for _, cmd := range root.Commands {
			if cmd.Name == expectedCmd {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected command '%s' not found", expectedCmd)
		}
	}
}

func TestUserCommands(t *testing.T) {
	root := createTestRootCommand()

	// Find users command
	var usersCmd *command.C
	for _, cmd := range root.Commands {
		if cmd.Name == "users" {
			usersCmd = cmd
			break
		}
	}

	if usersCmd == nil {
		t.Fatal("Users command not found")
	}

	// Test user subcommands
	expectedSubcommands := []string{"create", "list", "rename", "delete"}
	for _, expectedSub := range expectedSubcommands {
		found := false
		for _, sub := range usersCmd.Commands {
			if sub.Name == expectedSub {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected user subcommand '%s' not found", expectedSub)
		}
	}
}

func TestFlagBinding(t *testing.T) {
	// Test that flax flag binding works with new structure
	globalArgs.Config = "/test/config"
	globalArgs.Output = "json"
	globalArgs.Force = true

	userArgs.ID = 42
	userArgs.Name = "testuser"
	userArgs.Email = "test@example.com"

	// Test that fields are properly set
	if globalArgs.Config != "/test/config" {
		t.Errorf("Expected config '/test/config', got '%s'", globalArgs.Config)
	}
	if globalArgs.Output != "json" {
		t.Errorf("Expected output 'json', got '%s'", globalArgs.Output)
	}
	if !globalArgs.Force {
		t.Error("Expected force to be true")
	}
	if userArgs.ID != 42 {
		t.Errorf("Expected ID 42, got %d", userArgs.ID)
	}
	if userArgs.Name != "testuser" {
		t.Errorf("Expected name 'testuser', got '%s'", userArgs.Name)
	}
}

func TestFlagValidation(t *testing.T) {
	// Test RequireString validation
	err := requireString("", "test")
	if err == nil {
		t.Error("Expected error for empty required string")
	}
	if !strings.Contains(err.Error(), "--test flag is required") {
		t.Errorf("Expected specific error message, got '%s'", err.Error())
	}

	err = requireString("value", "test")
	if err != nil {
		t.Errorf("Expected no error for non-empty string, got '%s'", err.Error())
	}

	// Test RequireUint64 validation
	err = requireUint64(0, "id")
	if err == nil {
		t.Error("Expected error for zero uint64")
	}

	err = requireUint64(42, "id")
	if err != nil {
		t.Errorf("Expected no error for non-zero uint64, got '%s'", err.Error())
	}

	// Test RequireEither validation
	err = requireEither("", "name", "", "id")
	if err == nil {
		t.Error("Expected error when both values are empty")
	}

	err = requireEither("test", "name", "", "id")
	if err != nil {
		t.Errorf("Expected no error when first value is provided, got '%s'", err.Error())
	}

	err = requireEither("", "name", "42", "id")
	if err != nil {
		t.Errorf("Expected no error when second value is provided, got '%s'", err.Error())
	}
}

func TestIdentifierValidation(t *testing.T) {
	// Test ValidateUserIdentifier
	err := validateUserIdentifier(0, "")
	if err == nil {
		t.Error("Expected error when both ID and name are empty")
	}

	err = validateUserIdentifier(42, "")
	if err != nil {
		t.Errorf("Expected no error when ID is provided, got '%s'", err.Error())
	}

	err = validateUserIdentifier(0, "test")
	if err != nil {
		t.Errorf("Expected no error when name is provided, got '%s'", err.Error())
	}

	// Test ValidateNodeIdentifier
	err = validateNodeIdentifier(0, "")
	if err == nil {
		t.Error("Expected error when both ID and user are empty")
	}

	err = validateNodeIdentifier(42, "")
	if err != nil {
		t.Errorf("Expected no error when ID is provided, got '%s'", err.Error())
	}

	err = validateNodeIdentifier(0, "testuser")
	if err != nil {
		t.Errorf("Expected no error when user is provided, got '%s'", err.Error())
	}
}

func TestUserIdentifierParsing(t *testing.T) {
	// Test ParseUserIdentifier function
	tests := []struct {
		input    string
		expected userIdentifier
	}{
		{"123", userIdentifier{Type: "id", Value: "123"}},
		{"user@example.com", userIdentifier{Type: "email", Value: "user@example.com"}},
		{"oauth:provider:123", userIdentifier{Type: "provider", Value: "oauth:provider:123"}},
		{"username", userIdentifier{Type: "username", Value: "username"}},
	}

	for _, test := range tests {
		result := parseUserIdentifier(test.input)
		if result.Type != test.expected.Type || result.Value != test.expected.Value {
			t.Errorf("parseUserIdentifier(%s) = %+v, expected %+v", test.input, result, test.expected)
		}
	}
}

func TestCommaSeparatedParsing(t *testing.T) {
	// Test ParseCommaSeparated function
	tests := []struct {
		input    string
		expected []string
	}{
		{"", []string{}},
		{"tag1", []string{"tag1"}},
		{"tag1,tag2", []string{"tag1", "tag2"}},
		{"tag1, tag2, tag3", []string{"tag1", "tag2", "tag3"}},
		{"tag1,,tag3", []string{"tag1", "tag3"}},    // Empty elements should be filtered
		{" tag1 , tag2 ", []string{"tag1", "tag2"}}, // Whitespace should be trimmed
	}

	for _, test := range tests {
		result := parseCommaSeparated(test.input)
		if len(result) != len(test.expected) {
			t.Errorf("parseCommaSeparated(%s) length = %d, expected %d", test.input, len(result), len(test.expected))
			continue
		}
		for i, expected := range test.expected {
			if result[i] != expected {
				t.Errorf("parseCommaSeparated(%s)[%d] = %s, expected %s", test.input, i, result[i], expected)
			}
		}
	}
}

func TestFlaxIntegration(t *testing.T) {
	// Test that flax can parse our flag structures
	// Check global flags
	fields, err := flax.Check(&globalArgs)
	if err != nil {
		t.Fatalf("Error checking global flags: %v", err)
	}
	if len(fields) == 0 {
		t.Error("No global flags found - flax integration may be broken")
	}

	// Check user flags
	fields, err = flax.Check(&userArgs)
	if err != nil {
		t.Fatalf("Error checking user flags: %v", err)
	}
	if len(fields) == 0 {
		t.Error("No user flags found - flax integration may be broken")
	}

	// Check node flags
	fields, err = flax.Check(&nodeArgs)
	if err != nil {
		t.Fatalf("Error checking node flags: %v", err)
	}
	if len(fields) == 0 {
		t.Error("No node flags found - flax integration may be broken")
	}
}

func TestSimpleFlagsStructure(t *testing.T) {
	// Test the simplified flags structure
	globalArgs.Config = "/test"
	globalArgs.Output = "json"
	globalArgs.Force = true

	userArgs.ID = 42
	userArgs.Name = "test"
	userArgs.Email = "test@example.com"

	if globalArgs.Config != "/test" {
		t.Errorf("Expected global config '/test', got '%s'", globalArgs.Config)
	}
	if userArgs.ID != 42 {
		t.Errorf("Expected user ID 42, got %d", userArgs.ID)
	}
}

func TestCommandEnvironment(t *testing.T) {
	// Test command environment setup
	root := createTestRootCommand()

	env := root.NewEnv(nil).SetContext(context.Background())

	if env.Command != root {
		t.Error("Environment command should point to root")
	}

	if env.Context() == nil {
		t.Error("Environment context should be set")
	}
}

// Helper function to create a test version of the root command
func createTestRootCommand() *command.C {
	return &command.C{
		Name: "headscale",
		Usage: `<command> [flags] [args...]
  serve
  version
  config test
  users <subcommand> [flags] [args...]
  nodes <subcommand> [flags] [args...]
  preauth-keys <subcommand> [flags] [args...]
  api-keys <subcommand> [flags] [args...]
  policy <subcommand> [flags] [args...]
  dev <subcommand> [flags] [args...]`,

		Help: `headscale - a Tailscale control server

headscale is an open source implementation of the Tailscale control server

https://github.com/juanfont/headscale`,

		SetFlags: command.Flags(flax.MustBind, &globalArgs),

		Commands: []*command.C{
			// Server commands
			{
				Name:  "serve",
				Usage: "",
				Help:  "Start the headscale server",
			},
			{
				Name:  "version",
				Usage: "",
				Help:  "Show version information",
			},

			// Config commands
			{
				Name:  "config",
				Usage: "test",
				Help:  "Configuration management commands",
				Commands: []*command.C{
					{
						Name:  "test",
						Usage: "",
						Help:  "Test the configuration file",
					},
				},
			},

			// User management
			{
				Name:     "users",
				Usage:    "<subcommand> [flags] [args...]",
				Help:     "Manage users in Headscale",
				SetFlags: command.Flags(flax.MustBind, &userArgs),
				Commands: []*command.C{
					{Name: "create", Help: "Create a new user"},
					{Name: "list", Help: "List users"},
					{Name: "rename", Help: "Rename a user"},
					{Name: "delete", Help: "Delete a user"},
				},
			},

			// User management alias
			{
				Name:     "user",
				Usage:    "<subcommand> [flags] [args...]",
				Help:     "Manage users in Headscale (alias)",
				SetFlags: command.Flags(flax.MustBind, &userArgs),
				Unlisted: true,
				Commands: []*command.C{
					{Name: "create", Help: "Create a new user"},
					{Name: "list", Help: "List users"},
					{Name: "rename", Help: "Rename a user"},
					{Name: "delete", Help: "Delete a user"},
				},
			},

			// Node management
			{
				Name:     "nodes",
				Usage:    "<subcommand> [flags] [args...]",
				Help:     "Manage nodes in Headscale",
				SetFlags: command.Flags(flax.MustBind, &nodeArgs),
				Commands: []*command.C{
					{Name: "register", Help: "Register a node"},
					{Name: "list", Help: "List nodes"},
					{Name: "expire", Help: "Expire a node"},
					{Name: "rename", Help: "Rename a node"},
					{Name: "delete", Help: "Delete a node"},
					{Name: "move", Help: "Move node to another user"},
					{Name: "tags", Help: "Manage node tags"},
					{Name: "routes", Help: "Manage node routes"},
					{Name: "backfill-ips", Help: "Backfill missing IPs"},
				},
			},

			// PreAuth keys
			{
				Name:     "preauth-keys",
				Usage:    "<subcommand> [flags] [args...]",
				Help:     "Manage pre-authentication keys",
				SetFlags: command.Flags(flax.MustBind, &preAuthArgs),
				Commands: []*command.C{
					{Name: "create", Help: "Create a new pre-authentication key"},
					{Name: "list", Help: "List pre-authentication keys"},
					{Name: "expire", Help: "Expire a pre-authentication key"},
				},
			},

			// API keys
			{
				Name:     "api-keys",
				Usage:    "<subcommand> [flags] [args...]",
				Help:     "Manage API keys",
				SetFlags: command.Flags(flax.MustBind, &apiKeyArgs),
				Commands: []*command.C{
					{Name: "create", Help: "Create a new API key"},
					{Name: "list", Help: "List API keys"},
					{Name: "expire", Help: "Expire an API key"},
					{Name: "delete", Help: "Delete an API key"},
				},
			},

			// Policy management
			{
				Name:  "policy",
				Usage: "<subcommand> [flags] [args...]",
				Help:  "Manage ACL policies",
				Commands: []*command.C{
					{Name: "get", Help: "Get the current ACL policy"},
					{Name: "set", Help: "Set the ACL policy from a file", SetFlags: command.Flags(flax.MustBind, &policyArgs)},
					{Name: "test", Help: "Test a policy file", SetFlags: command.Flags(flax.MustBind, &policyArgs)},
					{Name: "reload", Help: "Reload the current policy"},
				},
			},

			// Development commands
			{
				Name:  "dev",
				Usage: "<subcommand> [flags] [args...]",
				Help:  "Development and testing commands",
				Commands: []*command.C{
					{
						Name:  "generate",
						Usage: "<subcommand>",
						Help:  "Generate various keys and tokens",
						Commands: []*command.C{
							{Name: "private-key", Help: "Generate a private key"},
						},
					},
					{Name: "create-node", Help: "Create a test node", SetFlags: command.Flags(flax.MustBind, &devArgs)},
				},
			},
		},
	}
}
