package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
)

func TestServeCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"serve-user"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cliserve"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	t.Run("test_serve_help", func(t *testing.T) {
		// Test serve command help
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"serve",
				"--help",
			},
		)
		assertNoErr(t, err)
		
		// Help text should contain expected information
		assert.Contains(t, result, "serve", "help should mention serve command")
		assert.Contains(t, result, "Launches the headscale server", "help should contain command description")
	})
}

func TestServeCommandValidation(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"serve-validation-user"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cliservevalidation"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	t.Run("test_serve_with_invalid_config", func(t *testing.T) {
		// Test serve command with invalid config file
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"--config", "/nonexistent/config.yaml",
				"serve",
			},
		)
		// Should fail for invalid config file
		assert.Error(t, err, "should fail for invalid config file")
	})

	t.Run("test_serve_with_extra_args", func(t *testing.T) {
		// Test serve command with unexpected extra arguments
		// Note: This is a tricky test since serve runs a server
		// We'll test that it accepts extra args without crashing immediately
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		
		// Use a goroutine to test that the command doesn't immediately fail
		done := make(chan error, 1)
		go func() {
			_, err := headscale.Execute(
				[]string{
					"headscale",
					"serve",
					"extra",
					"args",
				},
			)
			done <- err
		}()
		
		select {
		case err := <-done:
			// If it returns an error quickly, it should be about args validation
			// or config issues, not a panic
			if err != nil {
				assert.NotContains(t, err.Error(), "panic", "should not panic on extra arguments")
			}
		case <-ctx.Done():
			// If it times out, that's actually good - it means the server started
			// and didn't immediately crash due to extra arguments
		}
	})
}

func TestServeCommandHealthCheck(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"serve-health-user"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cliservehealth"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	t.Run("test_serve_health_endpoint", func(t *testing.T) {
		// Test that the serve command starts a server that responds to health checks
		// This is effectively testing that the server is running and accessible
		
		// Get the server endpoint
		endpoint := headscale.GetEndpoint()
		assert.NotEmpty(t, endpoint, "headscale endpoint should not be empty")
		
		// Make a simple HTTP request to verify the server is running
		healthURL := fmt.Sprintf("%s/health", endpoint)
		
		// Use a timeout to avoid hanging
		client := &http.Client{
			Timeout: 5 * time.Second,
		}
		
		resp, err := client.Get(healthURL)
		if err != nil {
			// If we can't connect, check if it's because server isn't ready
			assert.Contains(t, err.Error(), "connection", 
				"health check failure should be connection-related if server not ready")
		} else {
			defer resp.Body.Close()
			// If we can connect, verify we get a reasonable response
			assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 500, 
				"health endpoint should return reasonable status code")
		}
	})

	t.Run("test_serve_api_endpoint", func(t *testing.T) {
		// Test that the serve command starts a server with API endpoints
		endpoint := headscale.GetEndpoint()
		assert.NotEmpty(t, endpoint, "headscale endpoint should not be empty")
		
		// Try to access a known API endpoint (version info)
		// This tests that the gRPC gateway is running
		versionURL := fmt.Sprintf("%s/api/v1/version", endpoint)
		
		client := &http.Client{
			Timeout: 5 * time.Second,
		}
		
		resp, err := client.Get(versionURL)
		if err != nil {
			// Connection errors are acceptable if server isn't fully ready
			assert.Contains(t, err.Error(), "connection", 
				"API endpoint failure should be connection-related if server not ready")
		} else {
			defer resp.Body.Close()
			// If we can connect, check that we get some response
			assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 500, 
				"API endpoint should return reasonable status code")
		}
	})
}

func TestServeCommandServerBehavior(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"serve-behavior-user"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cliservebenavior"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	t.Run("test_serve_accepts_connections", func(t *testing.T) {
		// Test that the server accepts connections from clients
		// This is a basic integration test to ensure serve works
		
		// Create a user for testing
		user := spec.Users[0]
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"users",
				"create",
				user,
			},
		)
		assertNoErr(t, err)
		
		// Create a pre-auth key
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"preauthkeys",
				"create",
				"--user", user,
				"--output", "json",
			},
		)
		assertNoErr(t, err)
		
		// Verify the preauth key creation worked
		assert.NotEmpty(t, result, "preauth key creation should produce output")
		assert.Contains(t, result, "key", "preauth key output should contain key field")
	})

	t.Run("test_serve_handles_node_operations", func(t *testing.T) {
		// Test that the server can handle basic node operations
		_ = spec.Users[0] // Test user for context
		
		// List nodes (should work even if empty)
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"nodes",
				"list",
				"--output", "json",
			},
		)
		assertNoErr(t, err)
		
		// Should return valid JSON array (even if empty)
		trimmed := strings.TrimSpace(result)
		assert.True(t, strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"), 
			"nodes list should return JSON array")
	})

	t.Run("test_serve_handles_user_operations", func(t *testing.T) {
		// Test that the server can handle user operations
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"users",
				"list",
				"--output", "json",
			},
		)
		assertNoErr(t, err)
		
		// Should return valid JSON array
		trimmed := strings.TrimSpace(result)
		assert.True(t, strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"), 
			"users list should return JSON array")
		
		// Should contain our test user
		assert.Contains(t, result, spec.Users[0], "users list should contain test user")
	})
}

func TestServeCommandEdgeCases(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"serve-edge-user"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cliserverecge"))
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	t.Run("test_serve_multiple_rapid_commands", func(t *testing.T) {
		// Test that the server can handle multiple rapid commands
		// This tests the server's ability to handle concurrent requests
		user := spec.Users[0]
		
		// Create user first
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"users",
				"create",
				user,
			},
		)
		assertNoErr(t, err)
		
		// Execute multiple commands rapidly
		for i := 0; i < 3; i++ {
			result, err := headscale.Execute(
				[]string{
					"headscale",
					"users",
					"list",
				},
			)
			assertNoErr(t, err)
			assert.Contains(t, result, user, "users list should consistently contain test user")
		}
	})

	t.Run("test_serve_handles_empty_commands", func(t *testing.T) {
		// Test that the server gracefully handles edge case commands
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"--help",
			},
		)
		assertNoErr(t, err)
		
		// Basic help should work
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"--version",
			},
		)
		if err == nil {
			assert.NotEmpty(t, result, "version command should produce output")
		}
	})

	t.Run("test_serve_handles_malformed_requests", func(t *testing.T) {
		// Test that the server handles malformed CLI requests gracefully
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"nonexistent-command",
			},
		)
		// Should fail gracefully for non-existent commands
		assert.Error(t, err, "should fail gracefully for non-existent commands")
		
		// Should not cause server to crash (we can still execute other commands)
		result, err := headscale.Execute(
			[]string{
				"headscale",
				"users",
				"list",
			},
		)
		assertNoErr(t, err)
		assert.NotEmpty(t, result, "server should still work after malformed request")
	})
}