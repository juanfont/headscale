package headscale

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
)

const (
	ErrPreAuthKeyNotFound          = Error("AuthKey not found")
	ErrPreAuthKeyExpired           = Error("AuthKey expired")
	ErrSingleUseAuthKeyHasBeenUsed = Error("AuthKey has already been used")
	ErrUserMismatch                = Error("user mismatch")
	ErrPreAuthKeyACLTagInvalid     = Error("AuthKey tag is invalid")
)

// PreAuthKey describes a pre-authorization key usable in a particular user.
type PreAuthKey struct {
	ID        uint64 `gorm:"primary_key"`
	Key       string
	UserID    uint
	User      User
	Reusable  bool
	Ephemeral bool `gorm:"default:false"`
	Used      bool `gorm:"default:false"`
	ACLTags   []PreAuthKeyACLTag

	CreatedAt  *time.Time
	Expiration *time.Time
}

// PreAuthKeyACLTag describes an autmatic tag applied to a node when registered with the associated PreAuthKey.
type PreAuthKeyACLTag struct {
	ID           uint64 `gorm:"primary_key"`
	PreAuthKeyID uint64
	Tag          string
}

// CreatePreAuthKey creates a new PreAuthKey in a user, and returns it.
func (h *Headscale) CreatePreAuthKey(
	userName string,
	reusable bool,
	ephemeral bool,
	expiration *time.Time,
	aclTags []string,
) (*PreAuthKey, error) {
	user, err := h.GetUser(userName)
	if err != nil {
		return nil, err
	}

	for _, tag := range aclTags {
		if !strings.HasPrefix(tag, "tag:") {
			return nil, fmt.Errorf("%w: '%s' did not begin with 'tag:'", ErrPreAuthKeyACLTagInvalid, tag)
		}
	}

	now := time.Now().UTC()
	kstr, err := h.generateKey()
	if err != nil {
		return nil, err
	}

	key := PreAuthKey{
		Key:        kstr,
		UserID:     user.ID,
		User:       *user,
		Reusable:   reusable,
		Ephemeral:  ephemeral,
		CreatedAt:  &now,
		Expiration: expiration,
	}

	err = h.db.Transaction(func(db *gorm.DB) error {
		if err := db.Save(&key).Error; err != nil {
			return fmt.Errorf("failed to create key in the database: %w", err)
		}

		if len(aclTags) > 0 {
			seenTags := map[string]bool{}

			for _, tag := range aclTags {
				if !seenTags[tag] {
					if err := db.Save(&PreAuthKeyACLTag{PreAuthKeyID: key.ID, Tag: tag}).Error; err != nil {
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
func (h *Headscale) ListPreAuthKeys(userName string) ([]PreAuthKey, error) {
	user, err := h.GetUser(userName)
	if err != nil {
		return nil, err
	}

	keys := []PreAuthKey{}
	if err := h.db.Preload("User").Preload("ACLTags").Where(&PreAuthKey{UserID: user.ID}).Find(&keys).Error; err != nil {
		return nil, err
	}

	return keys, nil
}

// GetPreAuthKey returns a PreAuthKey for a given key.
func (h *Headscale) GetPreAuthKey(user string, key string) (*PreAuthKey, error) {
	pak, err := h.checkKeyValidity(key)
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
func (h *Headscale) DestroyPreAuthKey(pak PreAuthKey) error {
	return h.db.Transaction(func(db *gorm.DB) error {
		if result := db.Unscoped().Where(PreAuthKeyACLTag{PreAuthKeyID: pak.ID}).Delete(&PreAuthKeyACLTag{}); result.Error != nil {
			return result.Error
		}

		if result := db.Unscoped().Delete(pak); result.Error != nil {
			return result.Error
		}

		return nil
	})
}

// MarkExpirePreAuthKey marks a PreAuthKey as expired.
func (h *Headscale) ExpirePreAuthKey(k *PreAuthKey) error {
	if err := h.db.Model(&k).Update("Expiration", time.Now()).Error; err != nil {
		return err
	}

	return nil
}

// UsePreAuthKey marks a PreAuthKey as used.
func (h *Headscale) UsePreAuthKey(k *PreAuthKey) error {
	k.Used = true
	if err := h.db.Save(k).Error; err != nil {
		return fmt.Errorf("failed to update key used status in the database: %w", err)
	}

	return nil
}

// checkKeyValidity does the heavy lifting for validation of the PreAuthKey coming from a node
// If returns no error and a PreAuthKey, it can be used.
func (h *Headscale) checkKeyValidity(k string) (*PreAuthKey, error) {
	pak := PreAuthKey{}
	if result := h.db.Preload("User").Preload("ACLTags").First(&pak, "key = ?", k); errors.Is(
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

	machines := []Machine{}
	if err := h.db.Preload("AuthKey").Where(&Machine{AuthKeyID: uint(pak.ID)}).Find(&machines).Error; err != nil {
		return nil, err
	}

	if len(machines) != 0 || pak.Used {
		return nil, ErrSingleUseAuthKeyHasBeenUsed
	}

	return &pak, nil
}

func (h *Headscale) generateKey() (string, error) {
	size := 24
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

func (key *PreAuthKey) toProto() *v1.PreAuthKey {
	protoKey := v1.PreAuthKey{
		User:      key.User.Name,
		Id:        strconv.FormatUint(key.ID, Base10),
		Key:       key.Key,
		Ephemeral: key.Ephemeral,
		Reusable:  key.Reusable,
		Used:      key.Used,
		AclTags:   make([]string, len(key.ACLTags)),
	}

	if key.Expiration != nil {
		protoKey.Expiration = timestamppb.New(*key.Expiration)
	}

	if key.CreatedAt != nil {
		protoKey.CreatedAt = timestamppb.New(*key.CreatedAt)
	}

	for idx := range key.ACLTags {
		protoKey.AclTags[idx] = key.ACLTags[idx].Tag
	}

	return &protoKey
}
