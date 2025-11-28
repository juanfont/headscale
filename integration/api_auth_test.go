package integration

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

// TestAPIAuthenticationBypass tests that the API authentication middleware
// properly blocks unauthorized requests and does not leak sensitive data.
// This test reproduces the security issue described in:
// - https://github.com/juanfont/headscale/issues/2809
// - https://github.com/juanfont/headscale/pull/2810
//
// The bug: When authentication fails, the middleware writes "Unauthorized"
// but doesn't return early, allowing the handler to execute and append
// sensitive data to the response.
func TestAPIAuthenticationBypass(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"user1", "user2", "user3"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("apiauthbypass"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	// Create an API key using the CLI
	var validAPIKey string
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		apiKeyOutput, err := headscale.Execute(
			[]string{
				"headscale",
				"apikeys",
				"create",
				"--expiration",
				"24h",
			},
		)
		assert.NoError(ct, err)
		assert.NotEmpty(ct, apiKeyOutput)
		validAPIKey = strings.TrimSpace(apiKeyOutput)
	}, 20*time.Second, 1*time.Second)

	// Get the API endpoint
	endpoint := headscale.GetEndpoint()
	apiURL := fmt.Sprintf("%s/api/v1/user", endpoint)

	// Create HTTP client
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}

	t.Run("HTTP_NoAuthHeader", func(t *testing.T) {
		// Test 1: Request without any Authorization header
		// Expected: Should return 401 with ONLY "Unauthorized" text, no user data
		req, err := http.NewRequest("GET", apiURL, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		// Should return 401 Unauthorized
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"Expected 401 status code for request without auth header")

		bodyStr := string(body)

		// Should contain "Unauthorized" message
		assert.Contains(t, bodyStr, "Unauthorized",
			"Response should contain 'Unauthorized' message")

		// Should NOT contain user data after "Unauthorized"
		// This is the security bypass - if users array is present, auth was bypassed
		var jsonCheck map[string]any
		jsonErr := json.Unmarshal(body, &jsonCheck)

		// If we can unmarshal JSON and it contains "users", that's the bypass
		if jsonErr == nil {
			assert.NotContains(t, jsonCheck, "users",
				"SECURITY ISSUE: Response should NOT contain 'users' data when unauthorized")
			assert.NotContains(t, jsonCheck, "user",
				"SECURITY ISSUE: Response should NOT contain 'user' data when unauthorized")
		}

		// Additional check: response should not contain "user1", "user2", "user3"
		assert.NotContains(t, bodyStr, "user1",
			"SECURITY ISSUE: Response should NOT leak user 'user1' data")
		assert.NotContains(t, bodyStr, "user2",
			"SECURITY ISSUE: Response should NOT leak user 'user2' data")
		assert.NotContains(t, bodyStr, "user3",
			"SECURITY ISSUE: Response should NOT leak user 'user3' data")

		// Response should be minimal, just "Unauthorized"
		// Allow some variation in response format but body should be small
		assert.Less(t, len(bodyStr), 100,
			"SECURITY ISSUE: Unauthorized response body should be minimal, got: %s", bodyStr)
	})

	t.Run("HTTP_InvalidAuthHeader", func(t *testing.T) {
		// Test 2: Request with invalid Authorization header (missing "Bearer " prefix)
		// Expected: Should return 401 with ONLY "Unauthorized" text, no user data
		req, err := http.NewRequest("GET", apiURL, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "InvalidToken")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"Expected 401 status code for invalid auth header format")

		bodyStr := string(body)
		assert.Contains(t, bodyStr, "Unauthorized")

		// Should not leak user data
		assert.NotContains(t, bodyStr, "user1",
			"SECURITY ISSUE: Response should NOT leak user data")
		assert.NotContains(t, bodyStr, "user2",
			"SECURITY ISSUE: Response should NOT leak user data")
		assert.NotContains(t, bodyStr, "user3",
			"SECURITY ISSUE: Response should NOT leak user data")

		assert.Less(t, len(bodyStr), 100,
			"SECURITY ISSUE: Unauthorized response should be minimal")
	})

	t.Run("HTTP_InvalidBearerToken", func(t *testing.T) {
		// Test 3: Request with Bearer prefix but invalid token
		// Expected: Should return 401 with ONLY "Unauthorized" text, no user data
		// Note: Both malformed and properly formatted invalid tokens should return 401
		req, err := http.NewRequest("GET", apiURL, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer invalid-token-12345")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"Expected 401 status code for invalid bearer token")

		bodyStr := string(body)
		assert.Contains(t, bodyStr, "Unauthorized")

		// Should not leak user data
		assert.NotContains(t, bodyStr, "user1",
			"SECURITY ISSUE: Response should NOT leak user data")
		assert.NotContains(t, bodyStr, "user2",
			"SECURITY ISSUE: Response should NOT leak user data")
		assert.NotContains(t, bodyStr, "user3",
			"SECURITY ISSUE: Response should NOT leak user data")

		assert.Less(t, len(bodyStr), 100,
			"SECURITY ISSUE: Unauthorized response should be minimal")
	})

	t.Run("HTTP_ValidAPIKey", func(t *testing.T) {
		// Test 4: Request with valid API key
		// Expected: Should return 200 with user data (this is the authorized case)
		req, err := http.NewRequest("GET", apiURL, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", validAPIKey))

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		// Should succeed with valid auth
		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"Expected 200 status code with valid API key")

		// Should be able to parse as protobuf JSON
		var response v1.ListUsersResponse
		err = protojson.Unmarshal(body, &response)
		assert.NoError(t, err, "Response should be valid protobuf JSON with valid API key")

		// Should contain our test users
		users := response.GetUsers()
		assert.Len(t, users, 3, "Should have 3 users")
		userNames := make([]string, len(users))
		for i, u := range users {
			userNames[i] = u.GetName()
		}
		assert.Contains(t, userNames, "user1")
		assert.Contains(t, userNames, "user2")
		assert.Contains(t, userNames, "user3")
	})
}

// TestAPIAuthenticationBypassCurl tests the same security issue using curl
// from inside a container, which is closer to how the issue was discovered.
func TestAPIAuthenticationBypassCurl(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"testuser1", "testuser2"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("apiauthcurl"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	// Create a valid API key
	apiKeyOutput, err := headscale.Execute(
		[]string{
			"headscale",
			"apikeys",
			"create",
			"--expiration",
			"24h",
		},
	)
	require.NoError(t, err)
	validAPIKey := strings.TrimSpace(apiKeyOutput)

	endpoint := headscale.GetEndpoint()
	apiURL := fmt.Sprintf("%s/api/v1/user", endpoint)

	t.Run("Curl_NoAuth", func(t *testing.T) {
		// Execute curl from inside the headscale container without auth
		curlOutput, err := headscale.Execute(
			[]string{
				"curl",
				"-s",
				"-w",
				"\nHTTP_CODE:%{http_code}",
				apiURL,
			},
		)
		require.NoError(t, err)

		// Parse the output
		lines := strings.Split(curlOutput, "\n")
		var httpCode string
		var responseBody string

		for _, line := range lines {
			if after, ok := strings.CutPrefix(line, "HTTP_CODE:"); ok {
				httpCode = after
			} else {
				responseBody += line
			}
		}

		// Should return 401
		assert.Equal(t, "401", httpCode,
			"Curl without auth should return 401")

		// Should contain Unauthorized
		assert.Contains(t, responseBody, "Unauthorized",
			"Response should contain 'Unauthorized'")

		// Should NOT leak user data
		assert.NotContains(t, responseBody, "testuser1",
			"SECURITY ISSUE: Should not leak user data")
		assert.NotContains(t, responseBody, "testuser2",
			"SECURITY ISSUE: Should not leak user data")

		// Response should be small (just "Unauthorized")
		assert.Less(t, len(responseBody), 100,
			"SECURITY ISSUE: Unauthorized response should be minimal, got: %s", responseBody)
	})

	t.Run("Curl_InvalidAuth", func(t *testing.T) {
		// Execute curl with invalid auth header
		curlOutput, err := headscale.Execute(
			[]string{
				"curl",
				"-s",
				"-H",
				"Authorization: InvalidToken",
				"-w",
				"\nHTTP_CODE:%{http_code}",
				apiURL,
			},
		)
		require.NoError(t, err)

		lines := strings.Split(curlOutput, "\n")
		var httpCode string
		var responseBody string

		for _, line := range lines {
			if after, ok := strings.CutPrefix(line, "HTTP_CODE:"); ok {
				httpCode = after
			} else {
				responseBody += line
			}
		}

		assert.Equal(t, "401", httpCode)
		assert.Contains(t, responseBody, "Unauthorized")
		assert.NotContains(t, responseBody, "testuser1",
			"SECURITY ISSUE: Should not leak user data")
		assert.NotContains(t, responseBody, "testuser2",
			"SECURITY ISSUE: Should not leak user data")
	})

	t.Run("Curl_ValidAuth", func(t *testing.T) {
		// Execute curl with valid API key
		curlOutput, err := headscale.Execute(
			[]string{
				"curl",
				"-s",
				"-H",
				fmt.Sprintf("Authorization: Bearer %s", validAPIKey),
				"-w",
				"\nHTTP_CODE:%{http_code}",
				apiURL,
			},
		)
		require.NoError(t, err)

		lines := strings.Split(curlOutput, "\n")
		var httpCode string
		var responseBody string

		for _, line := range lines {
			if after, ok := strings.CutPrefix(line, "HTTP_CODE:"); ok {
				httpCode = after
			} else {
				responseBody += line
			}
		}

		// Should succeed
		assert.Equal(t, "200", httpCode,
			"Curl with valid API key should return 200")

		// Should contain user data
		var response v1.ListUsersResponse
		err = protojson.Unmarshal([]byte(responseBody), &response)
		assert.NoError(t, err, "Response should be valid protobuf JSON")
		users := response.GetUsers()
		assert.Len(t, users, 2, "Should have 2 users")
	})
}

// TestGRPCAuthenticationBypass tests that the gRPC authentication interceptor
// properly blocks unauthorized requests.
// This test verifies that the gRPC API does not have the same bypass issue
// as the HTTP API middleware.
func TestGRPCAuthenticationBypass(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"grpcuser1", "grpcuser2"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	// We need TLS for remote gRPC connections
	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("grpcauthtest"),
		hsic.WithTLS(),
		hsic.WithConfigEnv(map[string]string{
			// Enable gRPC on the standard port
			"HEADSCALE_GRPC_LISTEN_ADDR": "0.0.0.0:50443",
		}),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	// Create a valid API key
	apiKeyOutput, err := headscale.Execute(
		[]string{
			"headscale",
			"apikeys",
			"create",
			"--expiration",
			"24h",
		},
	)
	require.NoError(t, err)
	validAPIKey := strings.TrimSpace(apiKeyOutput)

	// Get the gRPC endpoint
	// For gRPC, we need to use the hostname and port 50443
	grpcAddress := fmt.Sprintf("%s:50443", headscale.GetHostname())

	t.Run("gRPC_NoAPIKey", func(t *testing.T) {
		// Test 1: Try to use CLI without API key (should fail)
		// When HEADSCALE_CLI_ADDRESS is set but HEADSCALE_CLI_API_KEY is not set,
		// the CLI should fail immediately
		_, err := headscale.Execute(
			[]string{
				"sh", "-c",
				fmt.Sprintf("HEADSCALE_CLI_ADDRESS=%s HEADSCALE_CLI_INSECURE=true headscale users list --output json 2>&1", grpcAddress),
			},
		)

		// Should fail - CLI exits when API key is missing
		assert.Error(t, err,
			"gRPC connection without API key should fail")
	})

	t.Run("gRPC_InvalidAPIKey", func(t *testing.T) {
		// Test 2: Try to use CLI with invalid API key (should fail with auth error)
		output, err := headscale.Execute(
			[]string{
				"sh", "-c",
				fmt.Sprintf("HEADSCALE_CLI_ADDRESS=%s HEADSCALE_CLI_API_KEY=invalid-key-12345 HEADSCALE_CLI_INSECURE=true headscale users list --output json 2>&1", grpcAddress),
			},
		)

		// Should fail with authentication error
		assert.Error(t, err,
			"gRPC connection with invalid API key should fail")

		// Should contain authentication error message
		outputStr := strings.ToLower(output)
		assert.True(t,
			strings.Contains(outputStr, "unauthenticated") ||
				strings.Contains(outputStr, "invalid token") ||
				strings.Contains(outputStr, "failed to validate token") ||
				strings.Contains(outputStr, "authentication"),
			"Error should indicate authentication failure, got: %s", output)

		// Should NOT leak user data
		assert.NotContains(t, output, "grpcuser1",
			"SECURITY ISSUE: gRPC should not leak user data with invalid auth")
		assert.NotContains(t, output, "grpcuser2",
			"SECURITY ISSUE: gRPC should not leak user data with invalid auth")
	})

	t.Run("gRPC_ValidAPIKey", func(t *testing.T) {
		// Test 3: Use CLI with valid API key (should succeed)
		output, err := headscale.Execute(
			[]string{
				"sh", "-c",
				fmt.Sprintf("HEADSCALE_CLI_ADDRESS=%s HEADSCALE_CLI_API_KEY=%s HEADSCALE_CLI_INSECURE=true headscale users list --output json", grpcAddress, validAPIKey),
			},
		)

		// Should succeed
		assert.NoError(t, err,
			"gRPC connection with valid API key should succeed, output: %s", output)

		// CLI outputs the users array directly, not wrapped in ListUsersResponse
		// Parse as JSON array (CLI uses json.Marshal, not protojson)
		var users []*v1.User
		err = json.Unmarshal([]byte(output), &users)
		assert.NoError(t, err, "Response should be valid JSON array")
		assert.Len(t, users, 2, "Should have 2 users")

		userNames := make([]string, len(users))
		for i, u := range users {
			userNames[i] = u.GetName()
		}
		assert.Contains(t, userNames, "grpcuser1")
		assert.Contains(t, userNames, "grpcuser2")
	})
}

// TestCLIWithConfigAuthenticationBypass tests that the headscale CLI
// with --config flag does not have authentication bypass issues when
// connecting to a remote server.
// Note: When using --config with local unix socket, no auth is needed.
// This test focuses on remote gRPC connections which require API keys.
func TestCLIWithConfigAuthenticationBypass(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"cliuser1", "cliuser2"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("cliconfigauth"),
		hsic.WithTLS(),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_GRPC_LISTEN_ADDR": "0.0.0.0:50443",
		}),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	// Create a valid API key
	apiKeyOutput, err := headscale.Execute(
		[]string{
			"headscale",
			"apikeys",
			"create",
			"--expiration",
			"24h",
		},
	)
	require.NoError(t, err)
	validAPIKey := strings.TrimSpace(apiKeyOutput)

	grpcAddress := fmt.Sprintf("%s:50443", headscale.GetHostname())

	// Create a config file for testing
	configWithoutKey := fmt.Sprintf(`
cli:
  address: %s
  timeout: 5s
  insecure: true
`, grpcAddress)

	configWithInvalidKey := fmt.Sprintf(`
cli:
  address: %s
  api_key: invalid-key-12345
  timeout: 5s
  insecure: true
`, grpcAddress)

	configWithValidKey := fmt.Sprintf(`
cli:
  address: %s
  api_key: %s
  timeout: 5s
  insecure: true
`, grpcAddress, validAPIKey)

	t.Run("CLI_Config_NoAPIKey", func(t *testing.T) {
		// Create config file without API key
		err := headscale.WriteFile("/tmp/config_no_key.yaml", []byte(configWithoutKey))
		require.NoError(t, err)

		// Try to use CLI with config that has no API key
		_, err = headscale.Execute(
			[]string{
				"headscale",
				"--config", "/tmp/config_no_key.yaml",
				"users", "list",
				"--output", "json",
			},
		)

		// Should fail
		assert.Error(t, err,
			"CLI with config missing API key should fail")
	})

	t.Run("CLI_Config_InvalidAPIKey", func(t *testing.T) {
		// Create config file with invalid API key
		err := headscale.WriteFile("/tmp/config_invalid_key.yaml", []byte(configWithInvalidKey))
		require.NoError(t, err)

		// Try to use CLI with invalid API key
		output, err := headscale.Execute(
			[]string{
				"sh", "-c",
				"headscale --config /tmp/config_invalid_key.yaml users list --output json 2>&1",
			},
		)

		// Should fail
		assert.Error(t, err,
			"CLI with invalid API key should fail")

		// Should indicate authentication failure
		outputStr := strings.ToLower(output)
		assert.True(t,
			strings.Contains(outputStr, "unauthenticated") ||
				strings.Contains(outputStr, "invalid token") ||
				strings.Contains(outputStr, "failed to validate token") ||
				strings.Contains(outputStr, "authentication"),
			"Error should indicate authentication failure, got: %s", output)

		// Should NOT leak user data
		assert.NotContains(t, output, "cliuser1",
			"SECURITY ISSUE: CLI should not leak user data with invalid auth")
		assert.NotContains(t, output, "cliuser2",
			"SECURITY ISSUE: CLI should not leak user data with invalid auth")
	})

	t.Run("CLI_Config_ValidAPIKey", func(t *testing.T) {
		// Create config file with valid API key
		err := headscale.WriteFile("/tmp/config_valid_key.yaml", []byte(configWithValidKey))
		require.NoError(t, err)

		// Use CLI with valid API key
		output, err := headscale.Execute(
			[]string{
				"headscale",
				"--config", "/tmp/config_valid_key.yaml",
				"users", "list",
				"--output", "json",
			},
		)

		// Should succeed
		assert.NoError(t, err,
			"CLI with valid API key should succeed")

		// CLI outputs the users array directly, not wrapped in ListUsersResponse
		// Parse as JSON array (CLI uses json.Marshal, not protojson)
		var users []*v1.User
		err = json.Unmarshal([]byte(output), &users)
		assert.NoError(t, err, "Response should be valid JSON array")
		assert.Len(t, users, 2, "Should have 2 users")

		userNames := make([]string, len(users))
		for i, u := range users {
			userNames[i] = u.GetName()
		}
		assert.Contains(t, userNames, "cliuser1")
		assert.Contains(t, userNames, "cliuser2")
	})
}
