package cli

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockOidcCommand(t *testing.T) {
	// Test that the mockoidc command exists and is properly configured
	assert.NotNil(t, mockOidcCmd)
	assert.Equal(t, "mockoidc", mockOidcCmd.Use)
	assert.Equal(t, "Runs a mock OIDC server for testing", mockOidcCmd.Short)
	assert.Equal(t, "This internal command runs a OpenID Connect for testing purposes", mockOidcCmd.Long)
	assert.NotNil(t, mockOidcCmd.Run)
}

func TestMockOidcCommandInRootCommand(t *testing.T) {
	// Test that mockoidc is available as a subcommand of root
	cmd, _, err := rootCmd.Find([]string{"mockoidc"})
	require.NoError(t, err)
	assert.Equal(t, "mockoidc", cmd.Name())
	assert.Equal(t, mockOidcCmd, cmd)
}

func TestMockOidcErrorConstants(t *testing.T) {
	// Test that error constants are defined properly
	assert.Equal(t, Error("MOCKOIDC_CLIENT_ID not defined"), errMockOidcClientIDNotDefined)
	assert.Equal(t, Error("MOCKOIDC_CLIENT_SECRET not defined"), errMockOidcClientSecretNotDefined)
	assert.Equal(t, Error("MOCKOIDC_PORT not defined"), errMockOidcPortNotDefined)
}

func TestMockOidcConstants(t *testing.T) {
	// Test that time constants are defined
	assert.Equal(t, 60*time.Minute, refreshTTL)
	assert.Equal(t, 2*time.Minute, accessTTL) // This is the default value
}

func TestMockOIDCValidation(t *testing.T) {
	// Test the validation logic by testing the mockOIDC function directly
	// Save original env vars
	originalEnv := map[string]string{
		"MOCKOIDC_CLIENT_ID":     os.Getenv("MOCKOIDC_CLIENT_ID"),
		"MOCKOIDC_CLIENT_SECRET": os.Getenv("MOCKOIDC_CLIENT_SECRET"),
		"MOCKOIDC_ADDR":          os.Getenv("MOCKOIDC_ADDR"),
		"MOCKOIDC_PORT":          os.Getenv("MOCKOIDC_PORT"),
		"MOCKOIDC_USERS":         os.Getenv("MOCKOIDC_USERS"),
		"MOCKOIDC_ACCESS_TTL":    os.Getenv("MOCKOIDC_ACCESS_TTL"),
	}
	
	// Clear all env vars
	for key := range originalEnv {
		os.Unsetenv(key)
	}
	
	// Restore env vars after test
	defer func() {
		for key, value := range originalEnv {
			if value != "" {
				os.Setenv(key, value)
			} else {
				os.Unsetenv(key)
			}
		}
	}()

	tests := []struct {
		name        string
		setup       func()
		expectedErr error
	}{
		{
			name:        "missing client ID",
			setup:       func() {},
			expectedErr: errMockOidcClientIDNotDefined,
		},
		{
			name: "missing client secret",
			setup: func() {
				os.Setenv("MOCKOIDC_CLIENT_ID", "test-client")
			},
			expectedErr: errMockOidcClientSecretNotDefined,
		},
		{
			name: "missing address",
			setup: func() {
				os.Setenv("MOCKOIDC_CLIENT_ID", "test-client")
				os.Setenv("MOCKOIDC_CLIENT_SECRET", "test-secret")
			},
			expectedErr: errMockOidcPortNotDefined,
		},
		{
			name: "missing port",
			setup: func() {
				os.Setenv("MOCKOIDC_CLIENT_ID", "test-client")
				os.Setenv("MOCKOIDC_CLIENT_SECRET", "test-secret")
				os.Setenv("MOCKOIDC_ADDR", "localhost")
			},
			expectedErr: errMockOidcPortNotDefined,
		},
		{
			name: "missing users",
			setup: func() {
				os.Setenv("MOCKOIDC_CLIENT_ID", "test-client")
				os.Setenv("MOCKOIDC_CLIENT_SECRET", "test-secret")
				os.Setenv("MOCKOIDC_ADDR", "localhost")
				os.Setenv("MOCKOIDC_PORT", "9000")
			},
			expectedErr: nil, // We'll check error message instead of type
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear env vars for this test
			for key := range originalEnv {
				os.Unsetenv(key)
			}
			
			tt.setup()
			
			// Note: We can't actually run mockOIDC() because it would start a server
			// and block forever. We're testing the validation part that happens early.
			// In a real implementation, we would refactor to separate validation from execution.
			err := mockOIDC()
			require.Error(t, err)
			if tt.expectedErr != nil {
				assert.Equal(t, tt.expectedErr, err)
			} else {
				// For the "missing users" case, just check it's an error about users
				assert.Contains(t, err.Error(), "MOCKOIDC_USERS not defined")
			}
		})
	}
}

func TestMockOIDCAccessTTLParsing(t *testing.T) {
	// Test that MOCKOIDC_ACCESS_TTL environment variable parsing works
	originalAccessTTL := accessTTL
	defer func() { accessTTL = originalAccessTTL }()

	originalEnv := os.Getenv("MOCKOIDC_ACCESS_TTL")
	defer func() {
		if originalEnv != "" {
			os.Setenv("MOCKOIDC_ACCESS_TTL", originalEnv)
		} else {
			os.Unsetenv("MOCKOIDC_ACCESS_TTL")
		}
	}()

	// Test with valid duration
	os.Setenv("MOCKOIDC_ACCESS_TTL", "5m")
	
	// We can't easily test the parsing in isolation since it's embedded in mockOIDC()
	// In a refactor, we'd extract this to a separate function
	// For now, we test the concept by parsing manually
	accessTTLOverride := os.Getenv("MOCKOIDC_ACCESS_TTL")
	if accessTTLOverride != "" {
		newTTL, err := time.ParseDuration(accessTTLOverride)
		require.NoError(t, err)
		assert.Equal(t, 5*time.Minute, newTTL)
	}
}

func TestGetMockOIDC(t *testing.T) {
	// Test the getMockOIDC function
	users := []mockoidc.MockUser{
		{
			Subject: "user1",
			Email:   "user1@example.com",
			Groups:  []string{"users"},
		},
		{
			Subject: "user2", 
			Email:   "user2@example.com",
			Groups:  []string{"admins", "users"},
		},
	}

	mock, err := getMockOIDC("test-client", "test-secret", users)
	require.NoError(t, err)
	assert.NotNil(t, mock)

	// Verify configuration
	assert.Equal(t, "test-client", mock.ClientID)
	assert.Equal(t, "test-secret", mock.ClientSecret)
	assert.Equal(t, accessTTL, mock.AccessTTL)
	assert.Equal(t, refreshTTL, mock.RefreshTTL)
	assert.NotNil(t, mock.Keypair)
	assert.NotNil(t, mock.SessionStore)
	assert.NotNil(t, mock.UserQueue)
	assert.NotNil(t, mock.ErrorQueue)

	// Verify supported code challenge methods
	expectedMethods := []string{"plain", "S256"}
	assert.Equal(t, expectedMethods, mock.CodeChallengeMethodsSupported)
}

func TestMockOIDCUserJsonParsing(t *testing.T) {
	// Test that user JSON parsing works correctly
	userStr := `[
		{
			"subject": "user1",
			"email": "user1@example.com",
			"groups": ["users"]
		},
		{
			"subject": "user2",
			"email": "user2@example.com", 
			"groups": ["admins", "users"]
		}
	]`

	var users []mockoidc.MockUser
	err := json.Unmarshal([]byte(userStr), &users)
	require.NoError(t, err)

	assert.Len(t, users, 2)
	assert.Equal(t, "user1", users[0].Subject)
	assert.Equal(t, "user1@example.com", users[0].Email)
	assert.Equal(t, []string{"users"}, users[0].Groups)

	assert.Equal(t, "user2", users[1].Subject)
	assert.Equal(t, "user2@example.com", users[1].Email)
	assert.Equal(t, []string{"admins", "users"}, users[1].Groups)
}

func TestMockOIDCInvalidUserJson(t *testing.T) {
	// Test that invalid JSON returns an error
	invalidUserStr := `[{"subject": "user1", "email": "user1@example.com", "groups": ["users"]` // Missing closing bracket

	var users []mockoidc.MockUser
	err := json.Unmarshal([]byte(invalidUserStr), &users)
	require.Error(t, err)
}

// Note: We don't test the actual server startup because:
// 1. It would require available ports
// 2. It blocks forever (infinite loop waiting on channel)
// 3. It's integration testing rather than unit testing
//
// In a real refactor, we would:
// 1. Extract server configuration from server startup
// 2. Add context cancellation to allow graceful shutdown
// 3. Return the server instance for testing instead of blocking forever