package db

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"tailscale.com/util/set"
)

var (
	ErrPreAuthKeyNotFound          = errors.New("auth-key not found")
	ErrPreAuthKeyExpired           = errors.New("auth-key expired")
	ErrSingleUseAuthKeyHasBeenUsed = errors.New("auth-key has already been used")
	ErrUserMismatch                = errors.New("user mismatch")
	ErrPreAuthKeyACLTagInvalid     = errors.New("auth-key tag is invalid")
)

func (hsdb *HSDatabase) CreatePreAuthKey(
	uid *types.UserID,
	reusable bool,
	ephemeral bool,
	expiration *time.Time,
	aclTags []string,
) (*types.PreAuthKeyNew, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.PreAuthKeyNew, error) {
		return CreatePreAuthKey(tx, uid, reusable, ephemeral, expiration, aclTags)
	})
}

const (
	authKeyPrefix       = "hskey-auth-"
	authKeyPrefixLength = 12
	authKeyLength       = 64
)

// CreatePreAuthKey creates a new PreAuthKey in a user, and returns it.
// The uid parameter can be nil for system-created tagged keys.
// For tagged keys, uid tracks "created by" (who created the key).
// For user-owned keys, uid tracks the node owner.
func CreatePreAuthKey(
	tx *gorm.DB,
	uid *types.UserID,
	reusable bool,
	ephemeral bool,
	expiration *time.Time,
	aclTags []string,
) (*types.PreAuthKeyNew, error) {
	// Validate: must be tagged OR user-owned, not neither
	if uid == nil && len(aclTags) == 0 {
		return nil, ErrPreAuthKeyNotTaggedOrOwned
	}

	var (
		user   *types.User
		userID *uint
	)

	if uid != nil {
		var err error

		user, err = GetUserByID(tx, *uid)
		if err != nil {
			return nil, err
		}

		userID = &user.ID
	}

	// Remove duplicates and sort for consistency
	aclTags = set.SetOf(aclTags).Slice()
	slices.Sort(aclTags)

	// TODO(kradalby): factor out and create a reusable tag validation,
	// check if there is one in Tailscale's lib.
	for _, tag := range aclTags {
		if !strings.HasPrefix(tag, "tag:") {
			return nil, fmt.Errorf(
				"%w: '%s' did not begin with 'tag:'",
				ErrPreAuthKeyACLTagInvalid,
				tag,
			)
		}
	}

	now := time.Now().UTC()

	prefix, err := util.GenerateRandomStringURLSafe(authKeyPrefixLength)
	if err != nil {
		return nil, err
	}

	// Validate generated prefix (should always be valid, but be defensive)
	if len(prefix) != authKeyPrefixLength {
		return nil, fmt.Errorf("%w: generated prefix has invalid length: expected %d, got %d", ErrPreAuthKeyFailedToParse, authKeyPrefixLength, len(prefix))
	}

	if !isValidBase64URLSafe(prefix) {
		return nil, fmt.Errorf("%w: generated prefix contains invalid characters", ErrPreAuthKeyFailedToParse)
	}

	toBeHashed, err := util.GenerateRandomStringURLSafe(authKeyLength)
	if err != nil {
		return nil, err
	}

	// Validate generated hash (should always be valid, but be defensive)
	if len(toBeHashed) != authKeyLength {
		return nil, fmt.Errorf("%w: generated hash has invalid length: expected %d, got %d", ErrPreAuthKeyFailedToParse, authKeyLength, len(toBeHashed))
	}

	if !isValidBase64URLSafe(toBeHashed) {
		return nil, fmt.Errorf("%w: generated hash contains invalid characters", ErrPreAuthKeyFailedToParse)
	}

	keyStr := authKeyPrefix + prefix + "-" + toBeHashed

	hash, err := bcrypt.GenerateFromPassword([]byte(toBeHashed), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	key := types.PreAuthKey{
		UserID:     userID, // nil for system-created keys, or "created by" for tagged keys
		User:       user,   // nil for system-created keys
		Reusable:   reusable,
		Ephemeral:  ephemeral,
		CreatedAt:  &now,
		Expiration: expiration,
		Tags:       aclTags, // empty for user-owned keys
		Prefix:     prefix,  // Store prefix
		Hash:       hash,    // Store hash
	}

	if err := tx.Save(&key).Error; err != nil {
		return nil, fmt.Errorf("failed to create key in the database: %w", err)
	}

	return &types.PreAuthKeyNew{
		ID:         key.ID,
		Key:        keyStr,
		Reusable:   key.Reusable,
		Ephemeral:  key.Ephemeral,
		Tags:       key.Tags,
		Expiration: key.Expiration,
		CreatedAt:  key.CreatedAt,
		User:       key.User,
	}, nil
}

func (hsdb *HSDatabase) ListPreAuthKeys() ([]types.PreAuthKey, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) ([]types.PreAuthKey, error) {
		return ListPreAuthKeys(rx)
	})
}

// ListPreAuthKeys returns all PreAuthKeys in the database.
func ListPreAuthKeys(tx *gorm.DB) ([]types.PreAuthKey, error) {
	var keys []types.PreAuthKey

	err := tx.Preload("User").Find(&keys).Error
	if err != nil {
		return nil, err
	}

	return keys, nil
}

var (
	ErrPreAuthKeyFailedToParse    = errors.New("failed to parse auth-key")
	ErrPreAuthKeyNotTaggedOrOwned = errors.New("auth-key must be either tagged or owned by user")
)

func findAuthKey(tx *gorm.DB, keyStr string) (*types.PreAuthKey, error) {
	var pak types.PreAuthKey

	// Validate input is not empty
	if keyStr == "" {
		return nil, ErrPreAuthKeyFailedToParse
	}

	_, prefixAndHash, found := strings.Cut(keyStr, authKeyPrefix)

	if !found {
		// Legacy format (plaintext) - backwards compatibility
		err := tx.Preload("User").First(&pak, "key = ?", keyStr).Error
		if err != nil {
			return nil, ErrPreAuthKeyNotFound
		}

		return &pak, nil
	}

	// New format: hskey-auth-{12-char-prefix}-{64-char-hash}
	// Expected minimum length: 12 (prefix) + 1 (separator) + 64 (hash) = 77
	const expectedMinLength = authKeyPrefixLength + 1 + authKeyLength
	if len(prefixAndHash) < expectedMinLength {
		return nil, fmt.Errorf(
			"%w: key too short, expected at least %d chars after prefix, got %d",
			ErrPreAuthKeyFailedToParse,
			expectedMinLength,
			len(prefixAndHash),
		)
	}

	// Use fixed-length parsing instead of separator-based to handle dashes in base64 URL-safe
	prefix := prefixAndHash[:authKeyPrefixLength]

	// Validate separator at expected position
	if prefixAndHash[authKeyPrefixLength] != '-' {
		return nil, fmt.Errorf(
			"%w: expected separator '-' at position %d, got '%c'",
			ErrPreAuthKeyFailedToParse,
			authKeyPrefixLength,
			prefixAndHash[authKeyPrefixLength],
		)
	}

	hash := prefixAndHash[authKeyPrefixLength+1:]

	// Validate hash length
	if len(hash) != authKeyLength {
		return nil, fmt.Errorf(
			"%w: hash length mismatch, expected %d chars, got %d",
			ErrPreAuthKeyFailedToParse,
			authKeyLength,
			len(hash),
		)
	}

	// Validate prefix contains only base64 URL-safe characters
	if !isValidBase64URLSafe(prefix) {
		return nil, fmt.Errorf(
			"%w: prefix contains invalid characters (expected base64 URL-safe: A-Za-z0-9_-)",
			ErrPreAuthKeyFailedToParse,
		)
	}

	// Validate hash contains only base64 URL-safe characters
	if !isValidBase64URLSafe(hash) {
		return nil, fmt.Errorf(
			"%w: hash contains invalid characters (expected base64 URL-safe: A-Za-z0-9_-)",
			ErrPreAuthKeyFailedToParse,
		)
	}

	// Look up key by prefix
	err := tx.Preload("User").First(&pak, "prefix = ?", prefix).Error
	if err != nil {
		return nil, ErrPreAuthKeyNotFound
	}

	// Verify hash matches
	err = bcrypt.CompareHashAndPassword(pak.Hash, []byte(hash))
	if err != nil {
		return nil, fmt.Errorf("invalid auth key: %w", err)
	}

	return &pak, nil
}

// isValidBase64URLSafe checks if a string contains only base64 URL-safe characters.
func isValidBase64URLSafe(s string) bool {
	for _, c := range s {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}

	return true
}

func (hsdb *HSDatabase) GetPreAuthKey(key string) (*types.PreAuthKey, error) {
	return GetPreAuthKey(hsdb.DB, key)
}

// GetPreAuthKey returns a PreAuthKey for a given key. The caller is responsible
// for checking if the key is usable (expired or used).
func GetPreAuthKey(tx *gorm.DB, key string) (*types.PreAuthKey, error) {
	return findAuthKey(tx, key)
}

// DestroyPreAuthKey destroys a preauthkey. Returns error if the PreAuthKey
// does not exist. This also clears the auth_key_id on any nodes that reference
// this key.
func DestroyPreAuthKey(tx *gorm.DB, id uint64) error {
	return tx.Transaction(func(db *gorm.DB) error {
		// First, clear the foreign key reference on any nodes using this key
		err := db.Model(&types.Node{}).
			Where("auth_key_id = ?", id).
			Update("auth_key_id", nil).Error
		if err != nil {
			return fmt.Errorf("failed to clear auth_key_id on nodes: %w", err)
		}

		// Then delete the pre-auth key
		err = tx.Unscoped().Delete(&types.PreAuthKey{}, id).Error
		if err != nil {
			return err
		}

		return nil
	})
}

func (hsdb *HSDatabase) ExpirePreAuthKey(id uint64) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return ExpirePreAuthKey(tx, id)
	})
}

func (hsdb *HSDatabase) DeletePreAuthKey(id uint64) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return DestroyPreAuthKey(tx, id)
	})
}

// UsePreAuthKey marks a PreAuthKey as used.
func UsePreAuthKey(tx *gorm.DB, k *types.PreAuthKey) error {
	err := tx.Model(k).Update("used", true).Error
	if err != nil {
		return fmt.Errorf("failed to update key used status in the database: %w", err)
	}

	k.Used = true
	return nil
}

// MarkExpirePreAuthKey marks a PreAuthKey as expired.
func ExpirePreAuthKey(tx *gorm.DB, id uint64) error {
	now := time.Now()
	return tx.Model(&types.PreAuthKey{}).Where("id = ?", id).Update("expiration", now).Error
}
