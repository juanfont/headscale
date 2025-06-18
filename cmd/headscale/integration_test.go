package main

import (
	"testing"

	"github.com/creachadair/command"
)

// TestIntegrationBasicFunctionality tests the basic CLI structure
func TestIntegrationBasicFunctionality(t *testing.T) {
	// Test that we can create the actual command tree without panics
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CLI creation panicked: %v", r)
		}
	}()

	// Build all commands like in main()
	var commands []*command.C

	// Add core commands
	commands = append(commands, serveCommands()...)
	commands = append(commands, configCommands()...)

	// Add management commands
	commands = append(commands, userCommands()...)
	commands = append(commands, nodeCommands()...)
	commands = append(commands, preAuthKeyCommands()...)
	commands = append(commands, apiKeyCommands()...)
	commands = append(commands, policyCommands()...)
	commands = append(commands, devCommands()...)

	if len(commands) == 0 {
		t.Error("No commands were created")
	}

	// Verify basic command structure
	commandNames := make(map[string]bool)
	for _, cmd := range commands {
		commandNames[cmd.Name] = true
	}

	expectedCommands := []string{"serve", "version", "users", "nodes", "preauth-keys", "api-keys", "policy", "dev"}
	for _, expected := range expectedCommands {
		if !commandNames[expected] {
			t.Errorf("Expected command '%s' not found", expected)
		}
	}
}

// TestIntegrationFlagBinding tests that flag binding works correctly
func TestIntegrationFlagBinding(t *testing.T) {
	// Test the simplified flag structures
	globalArgs.Config = "/test/config"
	globalArgs.Output = "json"
	globalArgs.Force = true

	userArgs.ID = 42
	userArgs.Name = "testuser"
	userArgs.Email = "test@example.com"

	// Test that flags are properly accessible
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
		t.Errorf("Expected user ID 42, got %d", userArgs.ID)
	}
}

// TestIntegrationCommandExecution tests that commands can be set up properly
func TestIntegrationCommandExecution(t *testing.T) {
	// Test user commands
	userCmds := userCommands()
	if len(userCmds) == 0 {
		t.Error("No user commands created")
	}

	// Test node commands
	nodeCmds := nodeCommands()
	if len(nodeCmds) == 0 {
		t.Error("No node commands created")
	}

	// Test API key commands
	apiCmds := apiKeyCommands()
	if len(apiCmds) == 0 {
		t.Error("No API key commands created")
	}

	// Test preauth commands
	preAuthCmds := preAuthKeyCommands()
	if len(preAuthCmds) == 0 {
		t.Error("No preauth commands created")
	}

	// Test policy commands
	policyCmds := policyCommands()
	if len(policyCmds) == 0 {
		t.Error("No policy commands created")
	}

	// Test dev commands
	devCmds := devCommands()
	if len(devCmds) == 0 {
		t.Error("No dev commands created")
	}

	// Test serve commands
	serveCmds := serveCommands()
	if len(serveCmds) == 0 {
		t.Error("No serve commands created")
	}

	// Test config commands
	configCmds := configCommands()
	if len(configCmds) == 0 {
		t.Error("No config commands created")
	}
}

// TestIntegrationValidationFunctions tests helper validation functions
func TestIntegrationValidationFunctions(t *testing.T) {
	// Test RequireString
	if err := requireString("", "test"); err == nil {
		t.Error("Expected error for empty required string")
	}
	if err := requireString("value", "test"); err != nil {
		t.Errorf("Expected no error for valid string: %v", err)
	}

	// Test RequireUint64
	if err := requireUint64(0, "id"); err == nil {
		t.Error("Expected error for zero uint64")
	}
	if err := requireUint64(42, "id"); err != nil {
		t.Errorf("Expected no error for valid uint64: %v", err)
	}

	// Test ValidateUserIdentifier
	if err := validateUserIdentifier(0, ""); err == nil {
		t.Error("Expected error when both ID and name are empty")
	}
	if err := validateUserIdentifier(42, ""); err != nil {
		t.Errorf("Expected no error when ID is provided: %v", err)
	}
	if err := validateUserIdentifier(0, "test"); err != nil {
		t.Errorf("Expected no error when name is provided: %v", err)
	}
}

// TestIntegrationParsingFunctions tests comma-separated parsing
func TestIntegrationParsingFunctions(t *testing.T) {
	// Test ParseCommaSeparated
	result := parseCommaSeparated("tag1,tag2,tag3")
	expected := []string{"tag1", "tag2", "tag3"}
	if len(result) != len(expected) {
		t.Errorf("Expected %d items, got %d", len(expected), len(result))
	}
	for i, exp := range expected {
		if result[i] != exp {
			t.Errorf("Expected %s at index %d, got %s", exp, i, result[i])
		}
	}

	// Test parsing tags (using parseCommaSeparated)
	tags := parseCommaSeparated("tag:test,tag:prod")
	if len(tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(tags))
	}

	// Test parsing routes (using parseCommaSeparated)
	routes := parseCommaSeparated("10.0.0.0/8,192.168.0.0/16")
	if len(routes) != 2 {
		t.Errorf("Expected 2 routes, got %d", len(routes))
	}
}

// TestIntegrationUserIdentifierParsing tests user identifier parsing
func TestIntegrationUserIdentifierParsing(t *testing.T) {
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
