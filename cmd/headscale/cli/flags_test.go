package cli

import (
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddIdentifierFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	
	AddIdentifierFlag(cmd, "identifier", "Test identifier")
	
	flag := cmd.Flags().Lookup("identifier")
	require.NotNil(t, flag)
	assert.Equal(t, "i", flag.Shorthand)
	assert.Equal(t, "Test identifier", flag.Usage)
	assert.Equal(t, "0", flag.DefValue)
}

func TestAddRequiredIdentifierFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	
	AddRequiredIdentifierFlag(cmd, "identifier", "Test identifier")
	
	flag := cmd.Flags().Lookup("identifier")
	require.NotNil(t, flag)
	assert.Equal(t, "i", flag.Shorthand)
	
	// Test that it's marked as required (cobra doesn't expose this directly)
	// We test by checking if validation fails when not set
	err := cmd.ValidateRequiredFlags()
	assert.Error(t, err)
}

func TestAddUserFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	
	AddUserFlag(cmd)
	
	flag := cmd.Flags().Lookup("user")
	require.NotNil(t, flag)
	assert.Equal(t, "u", flag.Shorthand)
	assert.Equal(t, "User", flag.Usage)
}

func TestAddOutputFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	
	AddOutputFlag(cmd)
	
	flag := cmd.Flags().Lookup("output")
	require.NotNil(t, flag)
	assert.Equal(t, "o", flag.Shorthand)
	assert.Contains(t, flag.Usage, "Output format")
}

func TestAddForceFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	
	AddForceFlag(cmd)
	
	flag := cmd.Flags().Lookup("force")
	require.NotNil(t, flag)
	assert.Equal(t, "false", flag.DefValue)
}

func TestAddExpirationFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	
	AddExpirationFlag(cmd, "24h")
	
	flag := cmd.Flags().Lookup("expiration")
	require.NotNil(t, flag)
	assert.Equal(t, "e", flag.Shorthand)
	assert.Equal(t, "24h", flag.DefValue)
}

func TestAddDeprecatedNamespaceFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	
	AddDeprecatedNamespaceFlag(cmd)
	
	flag := cmd.Flags().Lookup("namespace")
	require.NotNil(t, flag)
	assert.Equal(t, "n", flag.Shorthand)
	assert.True(t, flag.Hidden)
	assert.Equal(t, deprecateNamespaceMessage, flag.Deprecated)
}

func TestGetIdentifier(t *testing.T) {
	tests := []struct {
		name        string
		flagValue   string
		expectedVal uint64
		expectError bool
	}{
		{
			name:        "valid identifier",
			flagValue:   "123",
			expectedVal: 123,
			expectError: false,
		},
		{
			name:        "zero identifier",
			flagValue:   "0",
			expectedVal: 0,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{Use: "test"}
			AddIdentifierFlag(cmd, "identifier", "Test")
			
			// Set flag value
			err := cmd.Flags().Set("identifier", tt.flagValue)
			require.NoError(t, err)
			
			// Test getter
			val, err := GetIdentifier(cmd, "identifier")
			
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedVal, val)
			}
		})
	}
}

func TestGetUser(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	AddUserFlag(cmd)
	
	// Test default value
	user, err := GetUser(cmd)
	assert.NoError(t, err)
	assert.Equal(t, "", user)
	
	// Test set value
	err = cmd.Flags().Set("user", "testuser")
	require.NoError(t, err)
	
	user, err = GetUser(cmd)
	assert.NoError(t, err)
	assert.Equal(t, "testuser", user)
}

func TestGetOutputFormat(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	AddOutputFlag(cmd)
	
	// Test default value
	output := GetOutputFormat(cmd)
	assert.Equal(t, "", output)
	
	// Test set value
	err := cmd.Flags().Set("output", "json")
	require.NoError(t, err)
	
	output = GetOutputFormat(cmd)
	assert.Equal(t, "json", output)
}

func TestGetForce(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	AddForceFlag(cmd)
	
	// Test default value
	force := GetForce(cmd)
	assert.False(t, force)
	
	// Test set value
	err := cmd.Flags().Set("force", "true")
	require.NoError(t, err)
	
	force = GetForce(cmd)
	assert.True(t, force)
}

func TestGetExpiration(t *testing.T) {
	tests := []struct {
		name        string
		flagValue   string
		expected    time.Duration
		expectError bool
	}{
		{
			name:        "valid duration",
			flagValue:   "24h",
			expected:    24 * time.Hour,
			expectError: false,
		},
		{
			name:        "empty duration",
			flagValue:   "",
			expected:    0,
			expectError: false,
		},
		{
			name:        "invalid duration",
			flagValue:   "invalid",
			expected:    0,
			expectError: true,
		},
		{
			name:        "multiple units",
			flagValue:   "1h30m",
			expected:    time.Hour + 30*time.Minute,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{Use: "test"}
			AddExpirationFlag(cmd, "")
			
			if tt.flagValue != "" {
				err := cmd.Flags().Set("expiration", tt.flagValue)
				require.NoError(t, err)
			}
			
			duration, err := GetExpiration(cmd)
			
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, duration)
			}
		})
	}
}

func TestValidateRequiredFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	AddUserFlag(cmd)
	AddIdentifierFlag(cmd, "identifier", "Test")
	
	// Test when no flags are set
	err := ValidateRequiredFlags(cmd, "user", "identifier")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required flag user not set")
	
	// Set one flag
	err = cmd.Flags().Set("user", "testuser")
	require.NoError(t, err)
	
	err = ValidateRequiredFlags(cmd, "user", "identifier")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required flag identifier not set")
	
	// Set both flags
	err = cmd.Flags().Set("identifier", "123")
	require.NoError(t, err)
	
	err = ValidateRequiredFlags(cmd, "user", "identifier")
	assert.NoError(t, err)
}

func TestValidateExclusiveFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().StringP("name", "n", "", "Name")
	AddIdentifierFlag(cmd, "identifier", "Test")
	
	// Test when no flags are set (should pass)
	err := ValidateExclusiveFlags(cmd, "name", "identifier")
	assert.NoError(t, err)
	
	// Test when one flag is set (should pass)
	err = cmd.Flags().Set("name", "testname")
	require.NoError(t, err)
	
	err = ValidateExclusiveFlags(cmd, "name", "identifier")
	assert.NoError(t, err)
	
	// Test when both flags are set (should fail)
	err = cmd.Flags().Set("identifier", "123")
	require.NoError(t, err)
	
	err = ValidateExclusiveFlags(cmd, "name", "identifier")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "only one of the following flags can be set")
}

func TestValidateIdentifierFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	AddIdentifierFlag(cmd, "identifier", "Test")
	
	// Test with zero identifier (should fail)
	err := cmd.Flags().Set("identifier", "0")
	require.NoError(t, err)
	
	err = ValidateIdentifierFlag(cmd, "identifier")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be greater than 0")
	
	// Test with valid identifier (should pass)
	err = cmd.Flags().Set("identifier", "123")
	require.NoError(t, err)
	
	err = ValidateIdentifierFlag(cmd, "identifier")
	assert.NoError(t, err)
}

func TestValidateNonEmptyStringFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	AddUserFlag(cmd)
	
	// Test with empty string (should fail)
	err := ValidateNonEmptyStringFlag(cmd, "user")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
	
	// Test with non-empty string (should pass)
	err = cmd.Flags().Set("user", "testuser")
	require.NoError(t, err)
	
	err = ValidateNonEmptyStringFlag(cmd, "user")
	assert.NoError(t, err)
}

func TestHandleDeprecatedNamespaceFlag(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	AddUserFlag(cmd)
	AddDeprecatedNamespaceFlag(cmd)
	
	// Set namespace flag
	err := cmd.Flags().Set("namespace", "testnamespace")
	require.NoError(t, err)
	
	HandleDeprecatedNamespaceFlag(cmd)
	
	// User flag should now have the namespace value
	user, err := GetUser(cmd)
	assert.NoError(t, err)
	assert.Equal(t, "testnamespace", user)
}

func TestGetUserWithDeprecatedNamespace(t *testing.T) {
	tests := []struct {
		name          string
		userValue     string
		namespaceValue string
		expected      string
	}{
		{
			name:          "user flag set",
			userValue:     "testuser",
			namespaceValue: "testnamespace",
			expected:      "testuser",
		},
		{
			name:          "only namespace flag set",
			userValue:     "",
			namespaceValue: "testnamespace",
			expected:      "testnamespace",
		},
		{
			name:          "no flags set",
			userValue:     "",
			namespaceValue: "",
			expected:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{Use: "test"}
			AddUserFlag(cmd)
			AddDeprecatedNamespaceFlag(cmd)
			
			if tt.userValue != "" {
				err := cmd.Flags().Set("user", tt.userValue)
				require.NoError(t, err)
			}
			
			if tt.namespaceValue != "" {
				err := cmd.Flags().Set("namespace", tt.namespaceValue)
				require.NoError(t, err)
			}
			
			result, err := GetUserWithDeprecatedNamespace(cmd)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMultipleFlagTypes(t *testing.T) {
	// Test that multiple different flag types can be used together
	cmd := &cobra.Command{Use: "test"}
	
	AddUserFlag(cmd)
	AddIdentifierFlag(cmd, "identifier", "Test")
	AddOutputFlag(cmd)
	AddForceFlag(cmd)
	AddTagsFlag(cmd)
	AddPrefixFlag(cmd)
	
	// Set various flags
	err := cmd.Flags().Set("user", "testuser")
	require.NoError(t, err)
	
	err = cmd.Flags().Set("identifier", "123")
	require.NoError(t, err)
	
	err = cmd.Flags().Set("output", "json")
	require.NoError(t, err)
	
	err = cmd.Flags().Set("force", "true")
	require.NoError(t, err)
	
	err = cmd.Flags().Set("tags", "true")
	require.NoError(t, err)
	
	err = cmd.Flags().Set("prefix", "testprefix")
	require.NoError(t, err)
	
	// Test all getters
	user, err := GetUser(cmd)
	assert.NoError(t, err)
	assert.Equal(t, "testuser", user)
	
	identifier, err := GetIdentifier(cmd, "identifier")
	assert.NoError(t, err)
	assert.Equal(t, uint64(123), identifier)
	
	output := GetOutputFormat(cmd)
	assert.Equal(t, "json", output)
	
	force := GetForce(cmd)
	assert.True(t, force)
	
	tags := GetTags(cmd)
	assert.True(t, tags)
	
	prefix, err := GetPrefix(cmd)
	assert.NoError(t, err)
	assert.Equal(t, "testprefix", prefix)
}

func TestFlagErrorHandling(t *testing.T) {
	// Test error handling when flags don't exist
	cmd := &cobra.Command{Use: "test"}
	
	// Test getting non-existent flag
	_, err := GetIdentifier(cmd, "nonexistent")
	assert.Error(t, err)
	
	// Test validation of non-existent flag
	err = ValidateRequiredFlags(cmd, "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "flag nonexistent not found")
}