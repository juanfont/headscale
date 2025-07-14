package cli

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Core validation function tests

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		email       string
		expectError bool
	}{
		{"test@example.com", false},
		{"user+tag@example.com", false},
		{"", true},
		{"invalid-email", true},
		{"user@", true},
		{"@example.com", true},
	}

	for _, tt := range tests {
		err := ValidateEmail(tt.email)
		if tt.expectError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestValidateUserName(t *testing.T) {
	tests := []struct {
		name        string
		expectError bool
	}{
		{"validuser", false},
		{"user123", false},
		{"user.name", false},
		{"", true},
		{".invalid", true},
		{"invalid.", true},
		{"-invalid", true},
		{"invalid-", true},
		{"user with spaces", true},
	}

	for _, tt := range tests {
		err := ValidateUserName(tt.name)
		if tt.expectError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestValidateNodeName(t *testing.T) {
	tests := []struct {
		name        string
		expectError bool
	}{
		{"validnode", false},
		{"node123", false},
		{"node-name", false},
		{"", true},
		{"-invalid", true},
		{"invalid-", true},
		{"node_name", true}, // underscores not allowed
	}

	for _, tt := range tests {
		err := ValidateNodeName(tt.name)
		if tt.expectError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestValidateDuration(t *testing.T) {
	tests := []struct {
		duration    string
		expectError bool
	}{
		{"1h", false},
		{"30m", false},
		{"24h", false},
		{"", true},
		{"invalid", true},
		{"-1h", true},
	}

	for _, tt := range tests {
		_, err := ValidateDuration(tt.duration)
		if tt.expectError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestValidateAPIKeyPrefix(t *testing.T) {
	tests := []struct {
		prefix      string
		expectError bool
	}{
		{"validprefix", false},
		{"prefix123", false},
		{"abc", false}, // minimum length
		{"", true},     // empty
		{"ab", true},   // too short
		{"prefix_with_underscore", true}, // invalid chars
	}

	for _, tt := range tests {
		err := ValidateAPIKeyPrefix(tt.prefix)
		if tt.expectError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestValidatePreAuthKeyOptions(t *testing.T) {
	oneHour := time.Hour
	tests := []struct {
		name        string
		reusable    bool
		ephemeral   bool
		expiration  *time.Duration
		expectError bool
	}{
		{"valid reusable", true, false, &oneHour, false},
		{"valid ephemeral", false, true, &oneHour, false},
		{"invalid: both reusable and ephemeral", true, true, &oneHour, true},
		{"invalid: ephemeral without expiration", false, true, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var exp time.Duration
			if tt.expiration != nil {
				exp = *tt.expiration
			}
			err := ValidatePreAuthKeyOptions(tt.reusable, tt.ephemeral, exp)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}