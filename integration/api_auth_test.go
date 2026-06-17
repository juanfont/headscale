package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	apiv1 "github.com/juanfont/headscale/gen/api/v1"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)

	// Get the API endpoint
	endpoint := headscale.GetEndpoint()
	apiURL := endpoint + "/api/v1/user"

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
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, apiURL, nil)
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
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, apiURL, nil)
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
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, apiURL, nil)
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
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, apiURL, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+validAPIKey)

		resp, err := client.Do(req)
		require.NoError(t, err)

		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		// Should succeed with valid auth
		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"Expected 200 status code with valid API key")

		// Should be able to parse as the ogen JSON list envelope
		var response apiv1.ListUsersOK

		err = json.Unmarshal(body, &response)
		require.NoError(t, err, "Response should be valid JSON with valid API key")

		// Should contain our test users
		users := response.GetUsers()
		assert.Len(t, users, 3, "Should have 3 users")

		userNames := make([]string, len(users))
		for i, u := range users {
			userNames[i] = u.GetName().Or("")
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
	apiURL := endpoint + "/api/v1/user"

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

		var (
			httpCode     string
			responseBody string
		)

		var responseBodySb280 strings.Builder

		for _, line := range lines {
			if after, ok := strings.CutPrefix(line, "HTTP_CODE:"); ok {
				httpCode = after
			} else {
				responseBodySb280.WriteString(line)
			}
		}

		responseBody += responseBodySb280.String()

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

		var (
			httpCode     string
			responseBody string
		)

		var responseBodySb326 strings.Builder

		for _, line := range lines {
			if after, ok := strings.CutPrefix(line, "HTTP_CODE:"); ok {
				httpCode = after
			} else {
				responseBodySb326.WriteString(line)
			}
		}

		responseBody += responseBodySb326.String()

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
				"Authorization: Bearer " + validAPIKey,
				"-w",
				"\nHTTP_CODE:%{http_code}",
				apiURL,
			},
		)
		require.NoError(t, err)

		lines := strings.Split(curlOutput, "\n")

		var (
			httpCode     string
			responseBody string
		)

		var responseBodySb361 strings.Builder

		for _, line := range lines {
			if after, ok := strings.CutPrefix(line, "HTTP_CODE:"); ok {
				httpCode = after
			} else {
				responseBodySb361.WriteString(line)
			}
		}

		responseBody += responseBodySb361.String()

		// Should succeed
		assert.Equal(t, "200", httpCode,
			"Curl with valid API key should return 200")

		// Should contain user data
		var response apiv1.ListUsersOK

		err = json.Unmarshal([]byte(responseBody), &response)
		require.NoError(t, err, "Response should be valid JSON")

		users := response.GetUsers()
		assert.Len(t, users, 2, "Should have 2 users")
	})
}
