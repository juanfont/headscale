package db

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"tailscale.com/util/rands"
	"tailscale.com/util/set"
)

var (
	// ErrPreAuthKeyNotFound wraps gorm.ErrRecordNotFound so an unknown or
	// deleted key is treated as a missing record by callers, which the
	// registration handler maps to a 401 rather than a raw server error.
	ErrPreAuthKeyNotFound          = fmt.Errorf("auth-key not found: %w", gorm.ErrRecordNotFound)
	ErrPreAuthKeyExpired           = errors.New("auth-key expired")
	ErrSingleUseAuthKeyHasBeenUsed = errors.New("auth-key has already been used")
	ErrUserMismatch                = errors.New("user mismatch")
	ErrPreAuthKeyACLTagInvalid     = errors.New("auth-key tag is invalid")
)

// validateACLTags deduplicates, sorts, and checks that every tag carries the
// "tag:" prefix. Shared by the pre-auth-key and OAuth credential paths so both
// enforce the same tag shape.
func validateACLTags(tags []string) ([]string, error) {
	tags = set.SetOf(tags).Slice()
	slices.Sort(tags)

	for _, tag := range tags {
		if !strings.HasPrefix(tag, "tag:") {
			return nil, fmt.Errorf(
				"%w: '%s' did not begin with 'tag:'",
				ErrPreAuthKeyACLTagInvalid,
				tag,
			)
		}
	}

	return tags, nil
}

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

// CreatePreAuthKey creates a new [types.PreAuthKey] in a user, and returns it.
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

	aclTags, err := validateACLTags(aclTags)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	prefix := rands.HexString(authKeyPrefixLength)

	toBeHashed := rands.HexString(authKeyLength)

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

	if err := tx.Save(&key).Error; err != nil { //nolint:noinlineerr
		return nil, fmt.Errorf("creating key in database: %w", err)
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

// SetPreAuthKeyDescription sets the free-text description on a pre-auth key.
// The v2 keys API sets it after creation rather than threading it through the
// many-armed CreatePreAuthKey signature shared by every other caller.
func (hsdb *HSDatabase) SetPreAuthKeyDescription(id uint64, description string) error {
	return hsdb.DB.Model(&types.PreAuthKey{}).
		Where("id = ?", id).
		Update("description", description).Error
}

func (hsdb *HSDatabase) ListPreAuthKeys() ([]types.PreAuthKey, error) {
	return Read(hsdb.DB, ListPreAuthKeys)
}

// ListPreAuthKeys returns all [types.PreAuthKey] values in the database.
func ListPreAuthKeys(tx *gorm.DB) ([]types.PreAuthKey, error) {
	var keys []types.PreAuthKey

	err := tx.Preload("User").Find(&keys).Error
	if err != nil {
		return nil, err
	}

	return keys, nil
}

// ListPreAuthKeysByUser returns all [types.PreAuthKey] values belonging to a specific user.
func ListPreAuthKeysByUser(tx *gorm.DB, uid types.UserID) ([]types.PreAuthKey, error) {
	var keys []types.PreAuthKey

	err := tx.Preload("User").Where("user_id = ?", uint(uid)).Find(&keys).Error
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
	prefix, hash, err := parsePrefixedKey(
		prefixAndHash,
		authKeyPrefixLength,
		authKeyLength,
		ErrPreAuthKeyFailedToParse,
	)
	if err != nil {
		return nil, err
	}

	// Look up key by prefix
	err = tx.Preload("User").First(&pak, "prefix = ?", prefix).Error
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

// parsePrefixedKey splits the prefix-and-secret portion of a new-format key
// (the part after the "hskey-*-" prefix) into its fixed-length prefix and
// secret components, validating the length, separator position, and that both
// components are base64 URL-safe. Fixed-length parsing is used instead of
// separator-based to handle dashes in base64 URL-safe characters.
func parsePrefixedKey(
	prefixAndSecret string,
	//nolint:unparam // kept explicit though every credential kind uses a 12-char prefix and 64-char secret today
	prefixLen, secretLen int,
	parseErr error,
) (string, string, error) {
	expectedMinLength := prefixLen + 1 + secretLen
	if len(prefixAndSecret) < expectedMinLength {
		return "", "", fmt.Errorf(
			"%w: key too short, expected at least %d chars after prefix, got %d",
			parseErr,
			expectedMinLength,
			len(prefixAndSecret),
		)
	}

	prefix := prefixAndSecret[:prefixLen]

	// Validate separator at expected position
	if prefixAndSecret[prefixLen] != '-' {
		return "", "", fmt.Errorf(
			"%w: expected separator '-' at position %d, got '%c'",
			parseErr,
			prefixLen,
			prefixAndSecret[prefixLen],
		)
	}

	secret := prefixAndSecret[prefixLen+1:]

	// Validate secret length
	if len(secret) != secretLen {
		return "", "", fmt.Errorf(
			"%w: secret length mismatch, expected %d chars, got %d",
			parseErr,
			secretLen,
			len(secret),
		)
	}

	// Validate prefix contains only base64 URL-safe characters
	if !isValidBase64URLSafe(prefix) {
		return "", "", fmt.Errorf(
			"%w: prefix contains invalid characters (expected base64 URL-safe: A-Za-z0-9_-)",
			parseErr,
		)
	}

	// Validate secret contains only base64 URL-safe characters
	if !isValidBase64URLSafe(secret) {
		return "", "", fmt.Errorf(
			"%w: secret contains invalid characters (expected base64 URL-safe: A-Za-z0-9_-)",
			parseErr,
		)
	}

	return prefix, secret, nil
}

// isValidBase64URLSafe reports whether s contains only base64 URL-safe
// characters (A-Za-z0-9-_). Key material is now generated as hex, a subset of
// this alphabet, so this accepts both current hex keys and any legacy keys
// still stored in the database.
func isValidBase64URLSafe(s string) bool {
	return !strings.ContainsFunc(s, func(c rune) bool {
		return (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_'
	})
}

func (hsdb *HSDatabase) GetPreAuthKey(key string) (*types.PreAuthKey, error) {
	return GetPreAuthKey(hsdb.DB, key)
}

// GetPreAuthKey returns a [types.PreAuthKey] for a given key. The caller is responsible
// for checking if the key is usable (expired or used).
func GetPreAuthKey(tx *gorm.DB, key string) (*types.PreAuthKey, error) {
	return findAuthKey(tx, key)
}

// GetPreAuthKeyByID returns a [types.PreAuthKey] by its primary key, with the
// owning user preloaded.
func (hsdb *HSDatabase) GetPreAuthKeyByID(id uint64) (*types.PreAuthKey, error) {
	pak := types.PreAuthKey{}
	// Explicit primary-key clause: a struct condition would drop a zero-valued
	// ID, making the lookup unconditional and returning the first row instead
	// of not-found.
	if result := hsdb.DB.Preload("User").First(&pak, "id = ?", id); result.Error != nil {
		return nil, result.Error
	}

	return &pak, nil
}

// DestroyPreAuthKey destroys a preauthkey. Returns error if the [types.PreAuthKey]
// does not exist. This also clears the auth_key_id on any nodes that reference
// this key.
func DestroyPreAuthKey(tx *gorm.DB, id uint64) error {
	return tx.Transaction(func(db *gorm.DB) error {
		// First, clear the foreign key reference on any nodes using this key
		err := db.Model(&types.Node{}).
			Where("auth_key_id = ?", id).
			Update("auth_key_id", nil).Error
		if err != nil {
			return fmt.Errorf("clearing auth_key_id on nodes: %w", err)
		}

		// Then delete the pre-auth key
		res := tx.Unscoped().Delete(&types.PreAuthKey{}, id)
		if res.Error != nil {
			return res.Error
		}

		if res.RowsAffected == 0 {
			return ErrPreAuthKeyNotFound
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

func (hsdb *HSDatabase) RevokePreAuthKey(id uint64) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return RevokePreAuthKey(tx, id)
	})
}

// RevokePreAuthKey soft-revokes a key (the v2 API's DELETE): the row is kept and
// stays retrievable with its invalid flag set, but the key can no longer
// authorize nodes. The background collector hard-deletes it after the retention
// window. An already-revoked or unknown id returns [ErrPreAuthKeyNotFound], so a
// repeated DELETE is a clean 404.
func RevokePreAuthKey(tx *gorm.DB, id uint64) error {
	res := tx.Model(&types.PreAuthKey{}).
		Where("id = ? AND revoked IS NULL", id).
		Update("revoked", time.Now())
	if res.Error != nil {
		return res.Error
	}

	if res.RowsAffected == 0 {
		return ErrPreAuthKeyNotFound
	}

	return nil
}

// DestroyRevokedPreAuthKeysBefore hard-deletes every key revoked before cutoff,
// returning how many were removed. The background collector calls this to reap
// soft-revoked keys after the retention window.
func (hsdb *HSDatabase) DestroyRevokedPreAuthKeysBefore(cutoff time.Time) (int, error) {
	var count int

	err := hsdb.Write(func(tx *gorm.DB) error {
		var ids []uint64

		err := tx.Model(&types.PreAuthKey{}).
			Where("revoked IS NOT NULL AND revoked < ?", cutoff).
			Pluck("id", &ids).Error
		if err != nil {
			return err
		}

		for _, id := range ids {
			err := DestroyPreAuthKey(tx, id)
			if err != nil {
				return err
			}
		}

		count = len(ids)

		return nil
	})

	return count, err
}

// UsePreAuthKey atomically marks a [types.PreAuthKey] as used. The UPDATE is
// guarded by `used = false` so two concurrent registrations racing for
// the same single-use key cannot both succeed: the first commits and
// the second returns [types.PAKError]("authkey already used"). Without the
// guard the previous code (Update("used", true) with no WHERE) would
// silently let both transactions claim the key.
func UsePreAuthKey(tx *gorm.DB, k *types.PreAuthKey) error {
	res := tx.Model(&types.PreAuthKey{}).
		Where("id = ? AND used = ?", k.ID, false).
		Update("used", true)
	if res.Error != nil {
		return fmt.Errorf("updating key used status in database: %w", res.Error)
	}

	if res.RowsAffected == 0 {
		return types.PAKError("authkey already used")
	}

	k.Used = true

	return nil
}

// ExpirePreAuthKey marks a [types.PreAuthKey] as expired, returning
// [ErrPreAuthKeyNotFound] rather than succeeding silently when no such key exists.
func ExpirePreAuthKey(tx *gorm.DB, id uint64) error {
	now := time.Now()

	res := tx.Model(&types.PreAuthKey{}).Where("id = ?", id).Update("expiration", now)
	if res.Error != nil {
		return res.Error
	}

	if res.RowsAffected == 0 {
		return ErrPreAuthKeyNotFound
	}

	return nil
}
