package cli

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Test input validation utilities

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		expectError bool
	}{
		{
			name:        "valid email",
			email:       "test@example.com",
			expectError: false,
		},
		{
			name:        "valid email with subdomain",
			email:       "user@mail.company.com",
			expectError: false,
		},
		{
			name:        "valid email with plus",
			email:       "user+tag@example.com",
			expectError: false,
		},
		{
			name:        "empty email",
			email:       "",
			expectError: true,
		},
		{
			name:        "invalid email without @",
			email:       "invalid-email",
			expectError: true,
		},
		{
			name:        "invalid email without domain",
			email:       "user@",
			expectError: true,
		},
		{
			name:        "invalid email without user",
			email:       "@example.com",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.email)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		expectError bool
	}{
		{
			name:        "valid HTTP URL",
			url:         "http://example.com",
			expectError: false,
		},
		{
			name:        "valid HTTPS URL",
			url:         "https://example.com",
			expectError: false,
		},
		{
			name:        "valid URL with path",
			url:         "https://example.com/path/to/resource",
			expectError: false,
		},
		{
			name:        "valid URL with query",
			url:         "https://example.com?query=value",
			expectError: false,
		},
		{
			name:        "empty URL",
			url:         "",
			expectError: true,
		},
		{
			name:        "URL without scheme",
			url:         "example.com",
			expectError: true,
		},
		{
			name:        "URL without host",
			url:         "https://",
			expectError: true,
		},
		{
			name:        "invalid URL",
			url:         "not-a-url",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURL(tt.url)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateDuration(t *testing.T) {
	tests := []struct {
		name        string
		duration    string
		expected    time.Duration
		expectError bool
	}{
		{
			name:        "valid hours",
			duration:    "1h",
			expected:    time.Hour,
			expectError: false,
		},
		{
			name:        "valid minutes",
			duration:    "30m",
			expected:    30 * time.Minute,
			expectError: false,
		},
		{
			name:        "valid seconds",
			duration:    "45s",
			expected:    45 * time.Second,
			expectError: false,
		},
		{
			name:        "valid complex duration",
			duration:    "1h30m",
			expected:    time.Hour + 30*time.Minute,
			expectError: false,
		},
		{
			name:        "empty duration",
			duration:    "",
			expectError: true,
		},
		{
			name:        "invalid duration format",
			duration:    "invalid",
			expectError: true,
		},
		{
			name:        "negative duration",
			duration:    "-1h",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateDuration(tt.duration)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestValidateUserName(t *testing.T) {
	tests := []struct {
		name        string
		username    string
		expectError bool
	}{
		{
			name:        "valid simple username",
			username:    "testuser",
			expectError: false,
		},
		{
			name:        "valid username with numbers",
			username:    "user123",
			expectError: false,
		},
		{
			name:        "valid username with dots",
			username:    "test.user",
			expectError: false,
		},
		{
			name:        "valid username with hyphens",
			username:    "test-user",
			expectError: false,
		},
		{
			name:        "valid username with underscores",
			username:    "test_user",
			expectError: false,
		},
		{
			name:        "valid email-style username",
			username:    "user@domain.com",
			expectError: false,
		},
		{
			name:        "empty username",
			username:    "",
			expectError: true,
		},
		{
			name:        "username starting with dot",
			username:    ".testuser",
			expectError: true,
		},
		{
			name:        "username ending with dot",
			username:    "testuser.",
			expectError: true,
		},
		{
			name:        "username starting with hyphen",
			username:    "-testuser",
			expectError: true,
		},
		{
			name:        "username ending with hyphen",
			username:    "testuser-",
			expectError: true,
		},
		{
			name:        "username with spaces",
			username:    "test user",
			expectError: true,
		},
		{
			name:        "username with special characters",
			username:    "test$user",
			expectError: true,
		},
		{
			name:        "username too long",
			username:    "verylongusernamethatexceedsthemaximumlengthallowedforusernames123",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUserName(tt.username)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateNodeName(t *testing.T) {
	tests := []struct {
		name        string
		nodeName    string
		expectError bool
	}{
		{
			name:        "valid simple node name",
			nodeName:    "testnode",
			expectError: false,
		},
		{
			name:        "valid node name with numbers",
			nodeName:    "node123",
			expectError: false,
		},
		{
			name:        "valid node name with hyphens",
			nodeName:    "test-node",
			expectError: false,
		},
		{
			name:        "valid single character",
			nodeName:    "n",
			expectError: false,
		},
		{
			name:        "empty node name",
			nodeName:    "",
			expectError: true,
		},
		{
			name:        "node name starting with hyphen",
			nodeName:    "-testnode",
			expectError: true,
		},
		{
			name:        "node name ending with hyphen",
			nodeName:    "testnode-",
			expectError: true,
		},
		{
			name:        "node name with underscores",
			nodeName:    "test_node",
			expectError: true,
		},
		{
			name:        "node name with dots",
			nodeName:    "test.node",
			expectError: true,
		},
		{
			name:        "node name too long",
			nodeName:    "verylongnodenamethatexceedsthemaximumlengthallowedforhostnames123",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNodeName(tt.nodeName)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateIPAddress(t *testing.T) {
	tests := []struct {
		name        string
		ip          string
		expectError bool
	}{
		{
			name:        "valid IPv4",
			ip:          "192.168.1.1",
			expectError: false,
		},
		{
			name:        "valid IPv6",
			ip:          "2001:db8::1",
			expectError: false,
		},
		{
			name:        "valid IPv6 full",
			ip:          "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			expectError: false,
		},
		{
			name:        "empty IP",
			ip:          "",
			expectError: true,
		},
		{
			name:        "invalid IPv4",
			ip:          "256.256.256.256",
			expectError: true,
		},
		{
			name:        "invalid format",
			ip:          "not-an-ip",
			expectError: true,
		},
		{
			name:        "IPv4 with extra octet",
			ip:          "192.168.1.1.1",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIPAddress(tt.ip)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateCIDR(t *testing.T) {
	tests := []struct {
		name        string
		cidr        string
		expectError bool
	}{
		{
			name:        "valid IPv4 CIDR",
			cidr:        "192.168.1.0/24",
			expectError: false,
		},
		{
			name:        "valid IPv6 CIDR",
			cidr:        "2001:db8::/32",
			expectError: false,
		},
		{
			name:        "valid single host IPv4",
			cidr:        "192.168.1.1/32",
			expectError: false,
		},
		{
			name:        "valid single host IPv6",
			cidr:        "2001:db8::1/128",
			expectError: false,
		},
		{
			name:        "empty CIDR",
			cidr:        "",
			expectError: true,
		},
		{
			name:        "IP without mask",
			cidr:        "192.168.1.1",
			expectError: true,
		},
		{
			name:        "invalid CIDR mask",
			cidr:        "192.168.1.0/33",
			expectError: true,
		},
		{
			name:        "invalid IP in CIDR",
			cidr:        "256.256.256.0/24",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCIDR(tt.cidr)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateTagsFormat(t *testing.T) {
	tests := []struct {
		name        string
		tags        []string
		expectError bool
	}{
		{
			name:        "valid simple tags",
			tags:        []string{"tag1", "tag2"},
			expectError: false,
		},
		{
			name:        "valid tag with colon",
			tags:        []string{"environment:production"},
			expectError: false,
		},
		{
			name:        "empty tags list",
			tags:        []string{},
			expectError: false,
		},
		{
			name:        "nil tags list",
			tags:        nil,
			expectError: false,
		},
		{
			name:        "tag with space",
			tags:        []string{"invalid tag"},
			expectError: true,
		},
		{
			name:        "empty tag",
			tags:        []string{""},
			expectError: true,
		},
		{
			name:        "tag with invalid characters",
			tags:        []string{"tag$invalid"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTagsFormat(tt.tags)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateAPIKeyPrefix(t *testing.T) {
	tests := []struct {
		name        string
		prefix      string
		expectError bool
	}{
		{
			name:        "valid prefix",
			prefix:      "testkey",
			expectError: false,
		},
		{
			name:        "valid prefix with numbers",
			prefix:      "key123",
			expectError: false,
		},
		{
			name:        "minimum length prefix",
			prefix:      "test",
			expectError: false,
		},
		{
			name:        "maximum length prefix",
			prefix:      "1234567890123456",
			expectError: false,
		},
		{
			name:        "empty prefix",
			prefix:      "",
			expectError: true,
		},
		{
			name:        "prefix too short",
			prefix:      "abc",
			expectError: true,
		},
		{
			name:        "prefix too long",
			prefix:      "12345678901234567",
			expectError: true,
		},
		{
			name:        "prefix with special characters",
			prefix:      "test-key",
			expectError: true,
		},
		{
			name:        "prefix with underscore",
			prefix:      "test_key",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAPIKeyPrefix(tt.prefix)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePreAuthKeyOptions(t *testing.T) {
	tests := []struct {
		name        string
		reusable    bool
		ephemeral   bool
		expiration  time.Duration
		expectError bool
	}{
		{
			name:        "valid reusable key",
			reusable:    true,
			ephemeral:   false,
			expiration:  time.Hour,
			expectError: false,
		},
		{
			name:        "valid ephemeral key",
			reusable:    false,
			ephemeral:   true,
			expiration:  time.Hour,
			expectError: false,
		},
		{
			name:        "valid non-reusable, non-ephemeral",
			reusable:    false,
			ephemeral:   false,
			expiration:  time.Hour,
			expectError: false,
		},
		{
			name:        "valid no expiration",
			reusable:    true,
			ephemeral:   false,
			expiration:  0,
			expectError: false,
		},
		{
			name:        "invalid ephemeral and reusable",
			reusable:    true,
			ephemeral:   true,
			expiration:  time.Hour,
			expectError: true,
		},
		{
			name:        "invalid ephemeral without expiration",
			reusable:    false,
			ephemeral:   true,
			expiration:  0,
			expectError: true,
		},
		{
			name:        "invalid expiration too long",
			reusable:    false,
			ephemeral:   false,
			expiration:  366 * 24 * time.Hour,
			expectError: true,
		},
		{
			name:        "invalid expiration too short",
			reusable:    false,
			ephemeral:   false,
			expiration:  30 * time.Second,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePreAuthKeyOptions(tt.reusable, tt.ephemeral, tt.expiration)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePolicyJSON(t *testing.T) {
	tests := []struct {
		name        string
		policy      string
		expectError bool
	}{
		{
			name:        "valid basic JSON",
			policy:      `{"acls": []}`,
			expectError: false,
		},
		{
			name:        "valid JSON with whitespace",
			policy:      `  {"acls": []}  `,
			expectError: false,
		},
		{
			name:        "empty policy",
			policy:      "",
			expectError: true,
		},
		{
			name:        "invalid JSON structure",
			policy:      "not json",
			expectError: true,
		},
		{
			name:        "array instead of object",
			policy:      `["not", "an", "object"]`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePolicyJSON(tt.policy)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePositiveInteger(t *testing.T) {
	tests := []struct {
		name        string
		value       int64
		fieldName   string
		expectError bool
	}{
		{
			name:        "valid positive integer",
			value:       5,
			fieldName:   "test field",
			expectError: false,
		},
		{
			name:        "zero value",
			value:       0,
			fieldName:   "test field",
			expectError: true,
		},
		{
			name:        "negative value",
			value:       -1,
			fieldName:   "test field",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePositiveInteger(tt.value, tt.fieldName)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.fieldName)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateNonNegativeInteger(t *testing.T) {
	tests := []struct {
		name        string
		value       int64
		fieldName   string
		expectError bool
	}{
		{
			name:        "valid positive integer",
			value:       5,
			fieldName:   "test field",
			expectError: false,
		},
		{
			name:        "zero value",
			value:       0,
			fieldName:   "test field",
			expectError: false,
		},
		{
			name:        "negative value",
			value:       -1,
			fieldName:   "test field",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNonNegativeInteger(tt.value, tt.fieldName)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.fieldName)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateStringLength(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		fieldName   string
		minLength   int
		maxLength   int
		expectError bool
	}{
		{
			name:        "valid length",
			value:       "hello",
			fieldName:   "test field",
			minLength:   3,
			maxLength:   10,
			expectError: false,
		},
		{
			name:        "minimum length",
			value:       "hi",
			fieldName:   "test field",
			minLength:   2,
			maxLength:   10,
			expectError: false,
		},
		{
			name:        "maximum length",
			value:       "1234567890",
			fieldName:   "test field",
			minLength:   2,
			maxLength:   10,
			expectError: false,
		},
		{
			name:        "too short",
			value:       "a",
			fieldName:   "test field",
			minLength:   3,
			maxLength:   10,
			expectError: true,
		},
		{
			name:        "too long",
			value:       "12345678901",
			fieldName:   "test field",
			minLength:   3,
			maxLength:   10,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStringLength(tt.value, tt.fieldName, tt.minLength, tt.maxLength)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.fieldName)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateOneOf(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		fieldName     string
		allowedValues []string
		expectError   bool
	}{
		{
			name:          "valid value",
			value:         "option1",
			fieldName:     "test field",
			allowedValues: []string{"option1", "option2", "option3"},
			expectError:   false,
		},
		{
			name:          "invalid value",
			value:         "invalid",
			fieldName:     "test field",
			allowedValues: []string{"option1", "option2", "option3"},
			expectError:   true,
		},
		{
			name:          "empty allowed values",
			value:         "anything",
			fieldName:     "test field",
			allowedValues: []string{},
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOneOf(tt.value, tt.fieldName, tt.allowedValues)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.fieldName)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Test that validation functions use consistent error formatting
func TestValidationErrorFormatting(t *testing.T) {
	// Test that errors include the invalid value in the message
	err := ValidateEmail("invalid-email")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid-email")

	err = ValidateUserName("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")

	err = ValidateAPIKeyPrefix("ab")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least 4 characters")
}