package db

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
)

var (
	ErrPreAuthKeyNotFound          = errors.New("AuthKey not found")
	ErrPreAuthKeyExpired           = errors.New("AuthKey expired")
	ErrSingleUseAuthKeyHasBeenUsed = errors.New("AuthKey has already been used")
	ErrUserMismatch                = errors.New("user mismatch")
	ErrPreAuthKeyACLTagInvalid     = errors.New("AuthKey tag is invalid")
)

// CreatePreAuthKey creates a new PreAuthKey in a user, and returns it.
func (hsdb *HSDatabase) CreatePreAuthKey(
	userName string,
	reusable bool,
	ephemeral bool,
	expiration *time.Time,
	aclTags []string,
) (*types.PreAuthKey, error) {
	// TODO(kradalby): figure out this lock
	// hsdb.mu.Lock()
	// defer hsdb.mu.Unlock()

	user, err := hsdb.GetUser(userName)
	if err != nil {
		return nil, err
	}

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
	kstr, err := hsdb.generateKey()
	if err != nil {
		return nil, err
	}

	key := types.PreAuthKey{
		Key:        kstr,
		UserID:     user.ID,
		User:       *user,
		Reusable:   reusable,
		Ephemeral:  ephemeral,
		CreatedAt:  &now,
		Expiration: expiration,
	}

	err = hsdb.db.Transaction(func(db *gorm.DB) error {
		if err := db.Save(&key).Error; err != nil {
			return fmt.Errorf("failed to create key in the database: %w", err)
		}

		if len(aclTags) > 0 {
			seenTags := map[string]bool{}

			for _, tag := range aclTags {
				if !seenTags[tag] {
					if err := db.Save(&types.PreAuthKeyACLTag{PreAuthKeyID: key.ID, Tag: tag}).Error; err != nil {
						return fmt.Errorf(
							"failed to ceate key tag in the database: %w",
							err,
						)
					}
					seenTags[tag] = true
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return &key, nil
}

// ListPreAuthKeys returns the list of PreAuthKeys for a user.
func (hsdb *HSDatabase) ListPreAuthKeys(userName string) ([]types.PreAuthKey, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	return hsdb.listPreAuthKeys(userName)
}

func (hsdb *HSDatabase) listPreAuthKeys(userName string) ([]types.PreAuthKey, error) {
	user, err := hsdb.getUser(userName)
	if err != nil {
		return nil, err
	}

	keys := []types.PreAuthKey{}
	if err := hsdb.db.Preload("User").Preload("ACLTags").Where(&types.PreAuthKey{UserID: user.ID}).Find(&keys).Error; err != nil {
		return nil, err
	}

	return keys, nil
}

// GetPreAuthKey returns a PreAuthKey for a given key.
func (hsdb *HSDatabase) GetPreAuthKey(user string, key string) (*types.PreAuthKey, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	pak, err := hsdb.ValidatePreAuthKey(key)
	if err != nil {
		return nil, err
	}

	if pak.User.Name != user {
		return nil, ErrUserMismatch
	}

	return pak, nil
}

// DestroyPreAuthKey destroys a preauthkey. Returns error if the PreAuthKey
// does not exist.
func (hsdb *HSDatabase) DestroyPreAuthKey(pak types.PreAuthKey) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	return hsdb.destroyPreAuthKey(pak)
}

func (hsdb *HSDatabase) destroyPreAuthKey(pak types.PreAuthKey) error {
	return hsdb.db.Transaction(func(db *gorm.DB) error {
		if result := db.Unscoped().Where(types.PreAuthKeyACLTag{PreAuthKeyID: pak.ID}).Delete(&types.PreAuthKeyACLTag{}); result.Error != nil {
			return result.Error
		}

		if result := db.Unscoped().Delete(pak); result.Error != nil {
			return result.Error
		}

		return nil
	})
}

// MarkExpirePreAuthKey marks a PreAuthKey as expired.
func (hsdb *HSDatabase) ExpirePreAuthKey(k *types.PreAuthKey) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	if err := hsdb.db.Model(&k).Update("Expiration", time.Now()).Error; err != nil {
		return err
	}

	return nil
}

// UsePreAuthKey marks a PreAuthKey as used.
func (hsdb *HSDatabase) UsePreAuthKey(k *types.PreAuthKey) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	k.Used = true
	if err := hsdb.db.Save(k).Error; err != nil {
		return fmt.Errorf("failed to update key used status in the database: %w", err)
	}

	return nil
}

// ValidatePreAuthKey does the heavy lifting for validation of the PreAuthKey coming from a node
// If returns no error and a PreAuthKey, it can be used.
func (hsdb *HSDatabase) ValidatePreAuthKey(k string) (*types.PreAuthKey, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	pak := types.PreAuthKey{}
	if result := hsdb.db.Preload("User").Preload("ACLTags").First(&pak, "key = ?", k); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return nil, ErrPreAuthKeyNotFound
	}

	if pak.Expiration != nil && pak.Expiration.Before(time.Now()) {
		return nil, ErrPreAuthKeyExpired
	}

	if pak.Reusable || pak.Ephemeral { // we don't need to check if has been used before
		return &pak, nil
	}

	nodes := types.Nodes{}
	pakID := uint(pak.ID)
	if err := hsdb.db.
		Preload("AuthKey").
		Where(&types.Node{AuthKeyID: &pakID}).
		Find(&nodes).Error; err != nil {
		return nil, err
	}

	if len(nodes) != 0 || pak.Used {
		return nil, ErrSingleUseAuthKeyHasBeenUsed
	}

	return &pak, nil
}

func (hsdb *HSDatabase) generateKey() (string, error) {
	size := 24
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}
