package db

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	v2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	ErrPreAuthKeyNotFound          = errors.New("AuthKey not found")
	ErrPreAuthKeyExpired           = errors.New("AuthKey expired")
	ErrSingleUseAuthKeyHasBeenUsed = errors.New("AuthKey has already been used")
	ErrUserMismatch                = errors.New("user mismatch")
	ErrPreAuthKeyACLTagInvalid     = errors.New("AuthKey tag is invalid")
	ErrPreAuthKeyFailedToParse     = errors.New("failed to parse AuthKey")
)

const authKeyPrefix = "hskey-auth-"
const authKeyPrefixLength = 12
const authKeyLength = 64

func (hsdb *HSDatabase) CreatePreAuthKey(
	uid *types.UserID,
	reusable bool,
	ephemeral bool,
	expiration *time.Time,
	tags []string,
) (string, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (string, error) {
		return CreatePreAuthKey(tx, uid, reusable, ephemeral, expiration, tags)
	})
}

// CreatePreAuthKey creates a new PreAuthKey in a user, and returns it.
// A PreAuthKey can be tagged or owned by a user, but not both.
func CreatePreAuthKey(
	tx *gorm.DB,
	uid *types.UserID,
	reusable bool,
	ephemeral bool,
	expiration *time.Time,
	tags []string,
) (string, error) {
	var err error
	var user *types.User
	var userID *uint

	if uid == nil && len(tags) == 0 {
		return "", errors.New("preauthkey must be either tagged or owned by user")
	}

	if uid != nil && len(tags) > 0 {
		return "", errors.New("preauthkey cannot be both tagged and owned by user")
	}

	if uid != nil {
		user, err = GetUserByID(tx, *uid)
		if err != nil {
			return "", err
		}

		userID = &user.ID
	}

	if len(tags) > 0 {
		slices.Sort(tags)
		tags = slices.Compact(tags)

		for _, tag := range tags {
			t := v2.Tag(tag)
			if err := t.Validate(); err != nil {
				return "", fmt.Errorf("invalid tag: %w", tag, err)
			}
		}
	}

	now := time.Now().UTC()

	prefix, err := util.GenerateRandomStringURLSafe(apiPrefixLength)
	if err != nil {
		return "", err
	}

	toBeHashed, err := util.GenerateRandomStringURLSafe(apiKeyLength)
	if err != nil {
		return "", err
	}

	// Key to return to user, this will only be visible _once_
	keyStr := authKeyPrefix + "-" + prefix + "-" + toBeHashed

	hash, err := bcrypt.GenerateFromPassword([]byte(toBeHashed), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	key := types.PreAuthKey{
		Reusable:   reusable,
		Ephemeral:  ephemeral,
		CreatedAt:  &now,
		Expiration: expiration,
		UserID:     userID,
		User:       user,
		Tags:       tags,
		Prefix:     prefix,
		Hash:       hash,
	}

	if err := tx.Save(&key).Error; err != nil {
		return "", fmt.Errorf("failed to create key in the database: %w", err)
	}

	return keyStr, nil
}

func (hsdb *HSDatabase) ListPreAuthKeys(uid types.UserID) ([]types.PreAuthKey, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) ([]types.PreAuthKey, error) {
		return ListPreAuthKeysByUser(rx, uid)
	})
}

// ListPreAuthKeysByUser returns the list of PreAuthKeys for a user.
func ListPreAuthKeysByUser(tx *gorm.DB, uid types.UserID) ([]types.PreAuthKey, error) {
	user, err := GetUserByID(tx, uid)
	if err != nil {
		return nil, err
	}

	keys := []types.PreAuthKey{}
	if err := tx.Preload("User").Where(&types.PreAuthKey{UserID: &user.ID}).Find(&keys).Error; err != nil {
		return nil, err
	}

	return keys, nil
}

// GetPreAuthKey returns a PreAuthKey by its key string.
// It will return an error if the key is not found, or if it is expired, used or invalid.
func (hsdb *HSDatabase) GetPreAuthKey(keyStr string) (*types.PreAuthKey, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.PreAuthKey, error) {
		return GetPreAuthKey(tx, keyStr)
	})
}

// GetPreAuthKey returns a PreAuthKey by its key string.
// It will return an error if the key is not found, or if it is expired, used or invalid.
func GetPreAuthKey(tx *gorm.DB, keyStr string) (*types.PreAuthKey, error) {
	pak, err := findAuthKey(tx, keyStr)
	if err != nil {
		return nil, err
	}

	if pak.Expiration != nil && pak.Expiration.Before(time.Now()) {
		return nil, ErrPreAuthKeyExpired
	}

	if pak.Used {
		return nil, ErrSingleUseAuthKeyHasBeenUsed
	}

	return pak, nil
}

func findAuthKey(tx *gorm.DB, keyStr string) (*types.PreAuthKey, error) {
	var pak *types.PreAuthKey
	_, prefixAndHash, found := strings.Cut(keyStr, authKeyPrefix)

	if !found {
		if err := tx.Preload("User").First(pak, "key = ?", keyStr).Error; err != nil {
			return nil, ErrPreAuthKeyNotFound
		}
	} else {
		prefix, hash, found := strings.Cut(prefixAndHash, "-")
		if !found {
			return nil, ErrPreAuthKeyFailedToParse
		}

		if err := tx.Preload("User").First(pak, "prefix = ?", prefix).Error; err != nil {
			return nil, ErrPreAuthKeyNotFound
		}

		if err := bcrypt.CompareHashAndPassword(pak.Hash, []byte(hash)); err != nil {
			return nil, err
		}
	}

	if pak == nil {
		return nil, ErrPreAuthKeyNotFound
	}

	return pak, nil
}

// DestroyPreAuthKey destroys a preauthkey. Returns error if the PreAuthKey
// does not exist.
func DestroyPreAuthKey(tx *gorm.DB, pak types.PreAuthKey) error {
	return tx.Transaction(func(db *gorm.DB) error {
		if result := db.Unscoped().Delete(pak); result.Error != nil {
			return result.Error
		}

		return nil
	})
}

func (hsdb *HSDatabase) ExpirePreAuthKey(k *types.PreAuthKey) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return ExpirePreAuthKey(tx, k)
	})
}

// UsePreAuthKey marks a PreAuthKey as used.
func UsePreAuthKey(tx *gorm.DB, k *types.PreAuthKey) error {
	k.Used = true
	if err := tx.Save(k).Error; err != nil {
		return fmt.Errorf("failed to update key used status in the database: %w", err)
	}

	return nil
}

// MarkExpirePreAuthKey marks a PreAuthKey as expired.
func ExpirePreAuthKey(tx *gorm.DB, k *types.PreAuthKey) error {
	if err := tx.Model(&k).Update("Expiration", time.Now()).Error; err != nil {
		return err
	}

	return nil
}
