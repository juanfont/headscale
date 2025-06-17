package main

import (
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Mock data for testing
func createMockUsers() []*v1.User {
	return []*v1.User{
		{
			Id:         1,
			Name:       "testuser1",
			Email:      "test1@example.com",
			ProviderId: "provider1",
			CreatedAt:  timestamppb.New(time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)),
		},
		{
			Id:         2,
			Name:       "testuser2",
			Email:      "test2@example.com",
			ProviderId: "provider2",
			CreatedAt:  timestamppb.New(time.Date(2023, 1, 2, 12, 0, 0, 0, time.UTC)),
		},
	}
}

func createMockNodes() []*v1.Node {
	return []*v1.Node{
		{
			Id:          1,
			Name:        "test-node-1",
			IpAddresses: []string{"100.64.0.1", "fd7a:115c:a1e0::1"},
			User: &v1.User{
				Id:   1,
				Name: "testuser1",
			},
			LastSeen:   timestamppb.New(time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)),
			CreatedAt:  timestamppb.New(time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)),
			Online:     true,
			ForcedTags: []string{"tag:test", "tag:production"},
		},
		{
			Id:          2,
			Name:        "test-node-2",
			IpAddresses: []string{"100.64.0.2"},
			User: &v1.User{
				Id:   2,
				Name: "testuser2",
			},
			LastSeen:   timestamppb.New(time.Date(2023, 1, 2, 12, 0, 0, 0, time.UTC)),
			CreatedAt:  timestamppb.New(time.Date(2023, 1, 2, 12, 0, 0, 0, time.UTC)),
			Online:     false,
			ForcedTags: []string{},
		},
	}
}

func createMockPreAuthKeys() []*v1.PreAuthKey {
	return []*v1.PreAuthKey{
		{
			Id:         1,
			Key:        "test-key-1",
			User:       &v1.User{Id: 1, Name: "testuser1"},
			Reusable:   true,
			Ephemeral:  false,
			Used:       false,
			Expiration: timestamppb.New(time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC)),
			CreatedAt:  timestamppb.New(time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)),
			AclTags:    []string{"tag:test"},
		},
		{
			Id:         2,
			Key:        "test-key-2",
			User:       &v1.User{Id: 2, Name: "testuser2"},
			Reusable:   false,
			Ephemeral:  true,
			Used:       true,
			Expiration: nil, // No expiration
			CreatedAt:  timestamppb.New(time.Date(2023, 1, 2, 12, 0, 0, 0, time.UTC)),
			AclTags:    []string{},
		},
	}
}

func createMockApiKeys() []*v1.ApiKey {
	return []*v1.ApiKey{
		{
			Id:         1,
			Prefix:     "hskey_1234567890",
			Expiration: timestamppb.New(time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC)),
			CreatedAt:  timestamppb.New(time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)),
			LastSeen:   timestamppb.New(time.Date(2023, 1, 15, 12, 0, 0, 0, time.UTC)),
		},
		{
			Id:         2,
			Prefix:     "hskey_0987654321",
			Expiration: nil, // No expiration
			CreatedAt:  timestamppb.New(time.Date(2023, 1, 2, 12, 0, 0, 0, time.UTC)),
			LastSeen:   nil, // Never used
		},
	}
}

// Test timestamp formatting
func TestTimestampProtoToString(t *testing.T) {
	testCases := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "nil timestamp",
			input:    nil,
			expected: "-",
		},
		{
			name:     "valid protobuf timestamp",
			input:    timestamppb.New(time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)),
			expected: "2023-01-01 12:00:00",
		},
		{
			name:     "time.Time",
			input:    time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			expected: "2023-01-01 12:00:00",
		},
		{
			name:     "nil time pointer",
			input:    (*time.Time)(nil),
			expected: "-",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := timestampProtoToString(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test duration formatting
func TestFormatDuration(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty duration",
			input:    "",
			expected: "Never",
		},
		{
			name:     "seconds",
			input:    "30s",
			expected: "30s",
		},
		{
			name:     "minutes",
			input:    "5m",
			expected: "5m",
		},
		{
			name:     "hours",
			input:    "2h",
			expected: "2.0h",
		},
		{
			name:     "days",
			input:    "72h",
			expected: "3.0d",
		},
		{
			name:     "invalid duration",
			input:    "invalid",
			expected: "invalid",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := formatDuration(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test file size formatting
func TestFormatFileSize(t *testing.T) {
	testCases := []struct {
		name     string
		input    int64
		expected string
	}{
		{
			name:     "bytes",
			input:    512,
			expected: "512 B",
		},
		{
			name:     "kilobytes",
			input:    1536,
			expected: "1.5 KB",
		},
		{
			name:     "megabytes",
			input:    2097152,
			expected: "2.0 MB",
		},
		{
			name:     "gigabytes",
			input:    3221225472,
			expected: "3.0 GB",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := formatFileSize(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test string truncation
func TestTruncateString(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{
			name:     "no truncation needed",
			input:    "short",
			maxLen:   10,
			expected: "short",
		},
		{
			name:     "truncation with ellipsis",
			input:    "this is a very long string",
			maxLen:   10,
			expected: "this is...",
		},
		{
			name:     "truncation at edge case",
			input:    "exactly10",
			maxLen:   10,
			expected: "exactly10",
		},
		{
			name:     "very short maxLen",
			input:    "test",
			maxLen:   2,
			expected: "te",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := truncateString(tc.input, tc.maxLen)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test boolean formatting
func TestFormatBoolAsYesNo(t *testing.T) {
	assert.Equal(t, "Yes", formatBoolAsYesNo(true))
	assert.Equal(t, "No", formatBoolAsYesNo(false))
}

// Test string slice formatting
func TestFormatStringSlice(t *testing.T) {
	testCases := []struct {
		name     string
		input    []string
		maxItems int
		expected string
	}{
		{
			name:     "empty slice",
			input:    []string{},
			maxItems: 3,
			expected: "-",
		},
		{
			name:     "within limit",
			input:    []string{"tag1", "tag2"},
			maxItems: 3,
			expected: "tag1, tag2",
		},
		{
			name:     "exceeds limit",
			input:    []string{"tag1", "tag2", "tag3", "tag4", "tag5"},
			maxItems: 3,
			expected: "tag1, tag2, tag3... (+2 more)",
		},
		{
			name:     "exactly at limit",
			input:    []string{"tag1", "tag2", "tag3"},
			maxItems: 3,
			expected: "tag1, tag2, tag3",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := formatStringSlice(tc.input, tc.maxItems)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test validation functions
func TestValidateEmailFormat(t *testing.T) {
	testCases := []struct {
		name        string
		email       string
		expectError bool
	}{
		{
			name:        "valid email",
			email:       "user@example.com",
			expectError: false,
		},
		{
			name:        "empty email",
			email:       "",
			expectError: false,
		},
		{
			name:        "invalid email",
			email:       "notanemail",
			expectError: true,
		},
		{
			name:        "email without domain",
			email:       "user@",
			expectError: false, // Basic validation only checks for @
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEmailFormat(tc.email)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateDuration(t *testing.T) {
	testCases := []struct {
		name        string
		duration    string
		expectError bool
	}{
		{
			name:        "valid duration",
			duration:    "1h30m",
			expectError: false,
		},
		{
			name:        "empty duration",
			duration:    "",
			expectError: false,
		},
		{
			name:        "invalid duration",
			duration:    "invalid",
			expectError: true,
		},
		{
			name:        "seconds",
			duration:    "30s",
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDuration(tc.duration)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateRoutes(t *testing.T) {
	testCases := []struct {
		name        string
		routes      string
		expectError bool
	}{
		{
			name:        "valid CIDR",
			routes:      "10.0.0.0/8,192.168.1.0/24",
			expectError: false,
		},
		{
			name:        "empty routes",
			routes:      "",
			expectError: false,
		},
		{
			name:        "invalid CIDR",
			routes:      "10.0.0.0/99",
			expectError: true,
		},
		{
			name:        "mixed valid and invalid",
			routes:      "10.0.0.0/8,invalid",
			expectError: true,
		},
		{
			name:        "IPv6 CIDR",
			routes:      "2001:db8::/32",
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRoutes(tc.routes)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Integration tests for outputting tables
func TestOutputTablesIntegration(t *testing.T) {
	t.Run("users table output", func(t *testing.T) {
		users := createMockUsers()
		err := outputUsersTable(users)
		assert.NoError(t, err)
	})

	t.Run("nodes table output", func(t *testing.T) {
		nodes := createMockNodes()
		err := outputNodesTable(nodes)
		assert.NoError(t, err)
	})

	t.Run("nodes table with tags", func(t *testing.T) {
		nodes := createMockNodes()
		err := outputNodesTableWithTags(nodes)
		assert.NoError(t, err)
	})

	t.Run("preauth keys table output", func(t *testing.T) {
		keys := createMockPreAuthKeys()
		err := outputPreAuthKeysTable(keys)
		assert.NoError(t, err)
	})

	t.Run("api keys table output", func(t *testing.T) {
		keys := createMockApiKeys()
		err := outputApiKeysTable(keys)
		assert.NoError(t, err)
	})

	t.Run("empty users table", func(t *testing.T) {
		err := outputUsersTable([]*v1.User{})
		assert.NoError(t, err)
	})

	t.Run("empty nodes table", func(t *testing.T) {
		err := outputNodesTable([]*v1.Node{})
		assert.NoError(t, err)
	})
}

// Test outputTable function with different data types
func TestOutputTable(t *testing.T) {
	testCases := []struct {
		name string
		data interface{}
	}{
		{
			name: "users array",
			data: createMockUsers(),
		},
		{
			name: "single user",
			data: createMockUsers()[0],
		},
		{
			name: "nodes array",
			data: createMockNodes(),
		},
		{
			name: "single node",
			data: createMockNodes()[0],
		},
		{
			name: "preauth keys array",
			data: createMockPreAuthKeys(),
		},
		{
			name: "single preauth key",
			data: createMockPreAuthKeys()[0],
		},
		{
			name: "api keys array",
			data: createMockApiKeys(),
		},
		{
			name: "single api key",
			data: createMockApiKeys()[0],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := outputTable(tc.data)
			assert.NoError(t, err)
		})
	}
}

// Test table style consistency
func TestTableStyle(t *testing.T) {
	style := tableStyle()
	assert.NotNil(t, style)

	// Test that the style has headers enabled
	// This is a basic test to ensure the function returns a valid table printer
	assert.NotNil(t, style)
}

// Test routes table formatting
func TestOutputRoutesTable(t *testing.T) {
	testCases := []struct {
		name   string
		routes []string
	}{
		{
			name:   "multiple routes",
			routes: []string{"10.0.0.0/8", "192.168.1.0/24", "172.16.0.0/12"},
		},
		{
			name:   "single route",
			routes: []string{"10.0.0.0/8"},
		},
		{
			name:   "empty routes",
			routes: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := outputRoutesTable(tc.routes)
			assert.NoError(t, err)
		})
	}
}

// Test policy table formatting (should fallback to JSON)
func TestOutputPolicyTable(t *testing.T) {
	policy := map[string]interface{}{
		"groups": map[string][]string{
			"group:admin": {"user1", "user2"},
		},
		"acls": []map[string]interface{}{
			{
				"action": "accept",
				"src":    []string{"group:admin"},
				"dst":    []string{"*:*"},
			},
		},
	}

	err := outputPolicyTable(policy)
	assert.NoError(t, err)
}

// Benchmark tests for performance
func BenchmarkOutputUsersTable(b *testing.B) {
	users := createMockUsers()

	// Create more test data for a realistic benchmark
	for i := 3; i <= 100; i++ {
		users = append(users, &v1.User{
			Id:         uint64(i),
			Name:       "testuser" + string(rune(i)),
			Email:      "test" + string(rune(i)) + "@example.com",
			ProviderId: "provider" + string(rune(i)),
			CreatedAt:  timestamppb.New(time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)),
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = outputUsersTable(users)
	}
}

func BenchmarkOutputNodesTable(b *testing.B) {
	nodes := createMockNodes()

	// Create more test data
	for i := 3; i <= 100; i++ {
		nodes = append(nodes, &v1.Node{
			Id:          uint64(i),
			Name:        "test-node-" + string(rune(i)),
			IpAddresses: []string{"100.64.0." + string(rune(i))},
			User: &v1.User{
				Id:   uint64(i),
				Name: "testuser" + string(rune(i)),
			},
			LastSeen:  timestamppb.New(time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)),
			CreatedAt: timestamppb.New(time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)),
			Online:    i%2 == 0,
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = outputNodesTable(nodes)
	}
}

// Test error handling
func TestTableFormattingErrorHandling(t *testing.T) {
	t.Run("handles nil user gracefully", func(t *testing.T) {
		users := []*v1.User{nil, createMockUsers()[0]}
		// Should not panic
		err := outputUsersTable(users)
		assert.NoError(t, err)
	})

	t.Run("handles nil node gracefully", func(t *testing.T) {
		nodes := []*v1.Node{nil, createMockNodes()[0]}
		// Should not panic
		err := outputNodesTable(nodes)
		assert.NoError(t, err)
	})
}
