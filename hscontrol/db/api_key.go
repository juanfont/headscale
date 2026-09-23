package db

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
)

const (
	apiKeyPrefix = "hskey-api-" //nolint:gosec // This is a prefix, not a credential

	// Legacy format constant: the prefix length of pre-hskey "prefix.secret" keys.
	// TODO(kradalby): remove in 0.32 with legacy key formats (announced).
	legacyAPIPrefixLength = 7
)

var (
	ErrAPIKeyFailedToParse    = errors.New("failed to parse ApiKey")
	ErrAPIKeyGenerationFailed = errors.New("failed to generate API key")
	ErrAPIKeyExpired          = errors.New("API key expired")
	ErrAPIKeyNotFound         = fmt.Errorf("API key not found: %w", gorm.ErrRecordNotFound)
)

// CreateAPIKey creates a new [types.APIKey] in a user, and returns it.
func (hsdb *HSDatabase) CreateAPIKey(
	expiration *time.Time,
) (string, *types.APIKey, error) {
	keyStr, identifier, hash := generateSecret(apiKeyPrefix)

	cred := types.Credential{
		Kind:       types.CredentialAPIKey,
		Identifier: identifier,
		Hash:       hash,
		Expiration: expiration,
	}

	if err := hsdb.DB.Save(&cred).Error; err != nil { //nolint:noinlineerr
		return "", nil, fmt.Errorf("saving API key to database: %w", err)
	}

	return keyStr, credentialToAPIKey(&cred), nil
}

// ListAPIKeys returns the list of [types.APIKey] values for a user.
func (hsdb *HSDatabase) ListAPIKeys() ([]types.APIKey, error) {
	var creds []types.Credential

	err := hsdb.DB.Where("kind = ?", types.CredentialAPIKey).Order("id").Find(&creds).Error
	if err != nil {
		return nil, err
	}

	keys := make([]types.APIKey, 0, len(creds))
	for i := range creds {
		keys = append(keys, *credentialToAPIKey(&creds[i]))
	}

	return keys, nil
}

// GetAPIKey returns a [types.APIKey] for a given key.
func (hsdb *HSDatabase) GetAPIKey(prefix string) (*types.APIKey, error) {
	var cred types.Credential
	if result := hsdb.DB.First(&cred, "kind = ? AND identifier = ?", types.CredentialAPIKey, prefix); result.Error != nil {
		return nil, result.Error
	}

	return credentialToAPIKey(&cred), nil
}

// GetAPIKeyByID returns a [types.APIKey] for a given id.
func (hsdb *HSDatabase) GetAPIKeyByID(id uint64) (*types.APIKey, error) {
	var cred types.Credential
	// Query on an explicit primary-key clause: a struct condition would drop a
	// zero-valued ID, making the lookup unconditional and returning the first
	// row instead of not-found.
	if result := hsdb.DB.First(&cred, "kind = ? AND id = ?", types.CredentialAPIKey, id); result.Error != nil {
		return nil, result.Error
	}

	return credentialToAPIKey(&cred), nil
}

// DestroyAPIKey destroys a [types.APIKey]. Returns [ErrAPIKeyNotFound] if the
// [types.APIKey] does not exist.
func (hsdb *HSDatabase) DestroyAPIKey(key types.APIKey) error {
	res := hsdb.DB.Unscoped().
		Delete(&types.Credential{}, "kind = ? AND id = ?", types.CredentialAPIKey, key.ID)

	return apiKeyAffected(res)
}

// ExpireAPIKey marks a [types.APIKey] as expired.
func (hsdb *HSDatabase) ExpireAPIKey(key *types.APIKey) error {
	res := hsdb.DB.Model(&types.Credential{}).
		Where("kind = ? AND id = ?", types.CredentialAPIKey, key.ID).
		Update("expiration", time.Now())

	return apiKeyAffected(res)
}

// apiKeyAffected maps a write that matched no API key row to [ErrAPIKeyNotFound].
func apiKeyAffected(res *gorm.DB) error {
	if res.Error != nil {
		return res.Error
	}

	if res.RowsAffected == 0 {
		return ErrAPIKeyNotFound
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

// AuthenticateAPIKey validates keyStr and returns the matching, unexpired
// [types.APIKey] (with its owning UserID populated). Unlike ValidateAPIKey it
// returns the key itself, so the v2 API can act as the key's owning user. A
// non-nil error means the key is missing, malformed, or expired.
func (hsdb *HSDatabase) AuthenticateAPIKey(keyStr string) (*types.APIKey, error) {
	key, err := validateAPIKey(hsdb.DB, keyStr)
	if err != nil {
		return nil, err
	}

	if key.Expiration != nil && key.Expiration.Before(time.Now()) {
		return nil, ErrAPIKeyExpired
	}

	return key, nil
}

// SetAPIKeyUser sets the owning user of an API key. Used when an admin mints a
// key on behalf of a user (headscale apikeys create --user).
func (hsdb *HSDatabase) SetAPIKeyUser(keyID uint64, userID types.UserID) error {
	res := hsdb.DB.Model(&types.Credential{}).
		Where("kind = ? AND id = ?", types.CredentialAPIKey, keyID).
		Update("user_id", uint(userID))

	return apiKeyAffected(res)
}

// ParseAPIKeyPrefix extracts the database prefix from a display prefix.
// Handles formats: "hskey-api-{12chars}-***", "hskey-api-{12chars}", or just "{12chars}".
// Returns the 12-character prefix suitable for database lookup.
func ParseAPIKeyPrefix(displayPrefix string) (string, error) {
	// If it's already just the 12-character prefix, return it
	if len(displayPrefix) == keyIdentifierLength && isValidBase64URLSafe(displayPrefix) {
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
		if len(remainder) < keyIdentifierLength {
			return "", fmt.Errorf("%w: prefix too short", ErrAPIKeyFailedToParse)
		}

		prefix := remainder[:keyIdentifierLength]

		// Validate it's base64 URL-safe
		if !isValidBase64URLSafe(prefix) {
			return "", fmt.Errorf("%w: prefix contains invalid characters", ErrAPIKeyFailedToParse)
		}

		return prefix, nil
	}

	// For legacy 7-character prefixes or other formats, return as-is
	// TODO(kradalby): remove in 0.32 with legacy key formats (announced).
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
		// TODO(kradalby): remove in 0.32 with legacy key formats (announced).
		return validateLegacyAPIKey(db, keyStr)
	}

	prefix, secret, err := parsePrefixedKey(prefixAndSecret, ErrAPIKeyFailedToParse)
	if err != nil {
		return nil, err
	}

	cred, err := authenticateCredential(db, types.CredentialAPIKey, prefix, secret, ErrAPIKeyNotFound)
	if err != nil {
		return nil, err
	}

	return credentialToAPIKey(cred), nil
}

// validateLegacyAPIKey validates a legacy format API key (prefix.secret).
//
// TODO(kradalby): remove in 0.32 with legacy key formats (announced).
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

	cred, err := authenticateCredential(db, types.CredentialAPIKey, prefix, secret, ErrAPIKeyNotFound)
	if err != nil {
		return nil, err
	}

	return credentialToAPIKey(cred), nil
}
