package db

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"tailscale.com/util/rands"
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
	ErrAPIKeyFailedToParse    = errors.New("failed to parse ApiKey")
	ErrAPIKeyGenerationFailed = errors.New("failed to generate API key")
)

// CreateAPIKey creates a new [types.APIKey] in a user, and returns it.
func (hsdb *HSDatabase) CreateAPIKey(
	expiration *time.Time,
) (string, *types.APIKey, error) {
	// Generate public prefix (12 chars)
	prefix := rands.HexString(apiKeyPrefixLength)

	// Generate secret (64 chars)
	secret := rands.HexString(apiKeyHashLength)

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

	if err := hsdb.DB.Save(&key).Error; err != nil { //nolint:noinlineerr
		return "", nil, fmt.Errorf("saving API key to database: %w", err)
	}

	return keyStr, &key, nil
}

// ListAPIKeys returns the list of [types.APIKey] values for a user.
func (hsdb *HSDatabase) ListAPIKeys() ([]types.APIKey, error) {
	keys := []types.APIKey{}

	err := hsdb.DB.Find(&keys).Error
	if err != nil {
		return nil, err
	}

	return keys, nil
}

// GetAPIKey returns a [types.APIKey] for a given key.
func (hsdb *HSDatabase) GetAPIKey(prefix string) (*types.APIKey, error) {
	key := types.APIKey{}
	if result := hsdb.DB.First(&key, "prefix = ?", prefix); result.Error != nil {
		return nil, result.Error
	}

	return &key, nil
}

// GetAPIKeyByID returns a [types.APIKey] for a given id.
func (hsdb *HSDatabase) GetAPIKeyByID(id uint64) (*types.APIKey, error) {
	key := types.APIKey{}
	// Query on an explicit primary-key clause: a struct condition would drop a
	// zero-valued ID, making the lookup unconditional and returning the first
	// row instead of not-found.
	if result := hsdb.DB.First(&key, "id = ?", id); result.Error != nil {
		return nil, result.Error
	}

	return &key, nil
}

// DestroyAPIKey destroys a [types.APIKey]. Returns error if the [types.APIKey]
// does not exist.
func (hsdb *HSDatabase) DestroyAPIKey(key types.APIKey) error {
	if result := hsdb.DB.Unscoped().Delete(key); result.Error != nil {
		return result.Error
	}

	return nil
}

// ExpireAPIKey marks a [types.APIKey] as expired.
func (hsdb *HSDatabase) ExpireAPIKey(key *types.APIKey) error {
	err := hsdb.DB.Model(&key).Update("Expiration", time.Now()).Error
	if err != nil {
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
	prefix, secret, err := parsePrefixedKey(
		prefixAndSecret,
		apiKeyPrefixLength,
		apiKeyHashLength,
		ErrAPIKeyFailedToParse,
	)
	if err != nil {
		return nil, err
	}

	// Look up by prefix (indexed)
	var key types.APIKey

	err = db.First(&key, "prefix = ?", prefix).Error
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
