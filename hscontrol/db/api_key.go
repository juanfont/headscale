package db

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	apiKeyPrefix       = "hskey-api-" //nolint:gosec // This is a prefix, not a credential
	apiKeyPrefixLength = 12
	apiKeyHashLength   = 64

	// Legacy format constants.
	legacyAPIPrefixLength = 7
	legacyAPIKeyLength    = 32
)

var (
	ErrAPIKeyFailedToParse     = errors.New("failed to parse ApiKey")
	ErrAPIKeyGenerationFailed  = errors.New("failed to generate API key")
	ErrAPIKeyInvalidGeneration = errors.New("generated API key failed validation")
)

// CreateAPIKey creates a new ApiKey in a user, and returns it.
func (hsdb *HSDatabase) CreateAPIKey(
	expiration *time.Time,
) (string, *types.APIKey, error) {
	// Generate public prefix (12 chars)
	prefix, err := util.GenerateRandomStringURLSafe(apiKeyPrefixLength)
	if err != nil {
		return "", nil, err
	}

	// Validate prefix
	if len(prefix) != apiKeyPrefixLength {
		return "", nil, fmt.Errorf("%w: generated prefix has invalid length: expected %d, got %d", ErrAPIKeyInvalidGeneration, apiKeyPrefixLength, len(prefix))
	}

	if !isValidBase64URLSafe(prefix) {
		return "", nil, fmt.Errorf("%w: generated prefix contains invalid characters", ErrAPIKeyInvalidGeneration)
	}

	// Generate secret (64 chars)
	secret, err := util.GenerateRandomStringURLSafe(apiKeyHashLength)
	if err != nil {
		return "", nil, err
	}

	// Validate secret
	if len(secret) != apiKeyHashLength {
		return "", nil, fmt.Errorf("%w: generated secret has invalid length: expected %d, got %d", ErrAPIKeyInvalidGeneration, apiKeyHashLength, len(secret))
	}

	if !isValidBase64URLSafe(secret) {
		return "", nil, fmt.Errorf("%w: generated secret contains invalid characters", ErrAPIKeyInvalidGeneration)
	}

	// Full key string (shown ONCE to user)
	keyStr := apiKeyPrefix + prefix + "-" + secret

	// bcrypt hash of secret
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, err
	}

	key := types.APIKey{
		Prefix:     prefix,
		Hash:       hash,
		Expiration: expiration,
	}

	if err := hsdb.DB.Save(&key).Error; err != nil {
		return "", nil, fmt.Errorf("failed to save API key to database: %w", err)
	}

	return keyStr, &key, nil
}

// ListAPIKeys returns the list of ApiKeys for a user.
func (hsdb *HSDatabase) ListAPIKeys() ([]types.APIKey, error) {
	keys := []types.APIKey{}
	if err := hsdb.DB.Find(&keys).Error; err != nil {
		return nil, err
	}

	return keys, nil
}

// GetAPIKey returns a ApiKey for a given key.
func (hsdb *HSDatabase) GetAPIKey(prefix string) (*types.APIKey, error) {
	key := types.APIKey{}
	if result := hsdb.DB.First(&key, "prefix = ?", prefix); result.Error != nil {
		return nil, result.Error
	}

	return &key, nil
}

// GetAPIKeyByID returns a ApiKey for a given id.
func (hsdb *HSDatabase) GetAPIKeyByID(id uint64) (*types.APIKey, error) {
	key := types.APIKey{}
	if result := hsdb.DB.Find(&types.APIKey{ID: id}).First(&key); result.Error != nil {
		return nil, result.Error
	}

	return &key, nil
}

// DestroyAPIKey destroys a ApiKey. Returns error if the ApiKey
// does not exist.
func (hsdb *HSDatabase) DestroyAPIKey(key types.APIKey) error {
	if result := hsdb.DB.Unscoped().Delete(key); result.Error != nil {
		return result.Error
	}

	return nil
}

// ExpireAPIKey marks a ApiKey as expired.
func (hsdb *HSDatabase) ExpireAPIKey(key *types.APIKey) error {
	if err := hsdb.DB.Model(&key).Update("Expiration", time.Now()).Error; err != nil {
		return err
	}

	return nil
}

func (hsdb *HSDatabase) ValidateAPIKey(keyStr string) (bool, error) {
	key, err := validateAPIKey(hsdb.DB, keyStr)
	if err != nil {
		return false, err
	}

	if key.Expiration != nil && key.Expiration.Before(time.Now()) {
		return false, nil
	}

	return true, nil
}

// ParseAPIKeyPrefix extracts the database prefix from a display prefix.
// Handles formats: "hskey-api-{12chars}-***", "hskey-api-{12chars}", or just "{12chars}".
// Returns the 12-character prefix suitable for database lookup.
func ParseAPIKeyPrefix(displayPrefix string) (string, error) {
	// If it's already just the 12-character prefix, return it
	if len(displayPrefix) == apiKeyPrefixLength && isValidBase64URLSafe(displayPrefix) {
		return displayPrefix, nil
	}

	// If it starts with the API key prefix, parse it
	if strings.HasPrefix(displayPrefix, apiKeyPrefix) {
		// Remove the "hskey-api-" prefix
		_, remainder, found := strings.Cut(displayPrefix, apiKeyPrefix)
		if !found {
			return "", fmt.Errorf("%w: invalid display prefix format", ErrAPIKeyFailedToParse)
		}

		// Extract just the first 12 characters (the actual prefix)
		if len(remainder) < apiKeyPrefixLength {
			return "", fmt.Errorf("%w: prefix too short", ErrAPIKeyFailedToParse)
		}

		prefix := remainder[:apiKeyPrefixLength]

		// Validate it's base64 URL-safe
		if !isValidBase64URLSafe(prefix) {
			return "", fmt.Errorf("%w: prefix contains invalid characters", ErrAPIKeyFailedToParse)
		}

		return prefix, nil
	}

	// For legacy 7-character prefixes or other formats, return as-is
	return displayPrefix, nil
}

// validateAPIKey validates an API key and returns the key if valid.
// Handles both new (hskey-api-{prefix}-{secret}) and legacy (prefix.secret) formats.
func validateAPIKey(db *gorm.DB, keyStr string) (*types.APIKey, error) {
	// Validate input is not empty
	if keyStr == "" {
		return nil, ErrAPIKeyFailedToParse
	}

	// Check for new format: hskey-api-{prefix}-{secret}
	_, prefixAndSecret, found := strings.Cut(keyStr, apiKeyPrefix)

	if !found {
		// Legacy format: prefix.secret
		return validateLegacyAPIKey(db, keyStr)
	}

	// New format: parse and verify
	const expectedMinLength = apiKeyPrefixLength + 1 + apiKeyHashLength
	if len(prefixAndSecret) < expectedMinLength {
		return nil, fmt.Errorf(
			"%w: key too short, expected at least %d chars after prefix, got %d",
			ErrAPIKeyFailedToParse,
			expectedMinLength,
			len(prefixAndSecret),
		)
	}

	// Use fixed-length parsing
	prefix := prefixAndSecret[:apiKeyPrefixLength]

	// Validate separator at expected position
	if prefixAndSecret[apiKeyPrefixLength] != '-' {
		return nil, fmt.Errorf(
			"%w: expected separator '-' at position %d, got '%c'",
			ErrAPIKeyFailedToParse,
			apiKeyPrefixLength,
			prefixAndSecret[apiKeyPrefixLength],
		)
	}

	secret := prefixAndSecret[apiKeyPrefixLength+1:]

	// Validate secret length
	if len(secret) != apiKeyHashLength {
		return nil, fmt.Errorf(
			"%w: secret length mismatch, expected %d chars, got %d",
			ErrAPIKeyFailedToParse,
			apiKeyHashLength,
			len(secret),
		)
	}

	// Validate prefix contains only base64 URL-safe characters
	if !isValidBase64URLSafe(prefix) {
		return nil, fmt.Errorf(
			"%w: prefix contains invalid characters (expected base64 URL-safe: A-Za-z0-9_-)",
			ErrAPIKeyFailedToParse,
		)
	}

	// Validate secret contains only base64 URL-safe characters
	if !isValidBase64URLSafe(secret) {
		return nil, fmt.Errorf(
			"%w: secret contains invalid characters (expected base64 URL-safe: A-Za-z0-9_-)",
			ErrAPIKeyFailedToParse,
		)
	}

	// Look up by prefix (indexed)
	var key types.APIKey

	err := db.First(&key, "prefix = ?", prefix).Error
	if err != nil {
		return nil, fmt.Errorf("API key not found: %w", err)
	}

	// Verify bcrypt hash
	err = bcrypt.CompareHashAndPassword(key.Hash, []byte(secret))
	if err != nil {
		return nil, fmt.Errorf("invalid API key: %w", err)
	}

	return &key, nil
}

// validateLegacyAPIKey validates a legacy format API key (prefix.secret).
func validateLegacyAPIKey(db *gorm.DB, keyStr string) (*types.APIKey, error) {
	// Legacy format uses "." as separator
	prefix, secret, found := strings.Cut(keyStr, ".")
	if !found {
		return nil, ErrAPIKeyFailedToParse
	}

	// Legacy prefix is 7 chars
	if len(prefix) != legacyAPIPrefixLength {
		return nil, fmt.Errorf("%w: legacy prefix length mismatch", ErrAPIKeyFailedToParse)
	}

	var key types.APIKey

	err := db.First(&key, "prefix = ?", prefix).Error
	if err != nil {
		return nil, fmt.Errorf("API key not found: %w", err)
	}

	// Verify bcrypt (key.Hash stores bcrypt of full secret)
	err = bcrypt.CompareHashAndPassword(key.Hash, []byte(secret))
	if err != nil {
		return nil, fmt.Errorf("invalid API key: %w", err)
	}

	return &key, nil
}
