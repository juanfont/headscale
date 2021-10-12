package headscale

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"gorm.io/gorm"
)

const errorAuthKeyNotFound = Error("AuthKey not found")
const errorAuthKeyExpired = Error("AuthKey expired")
const errorAuthKeyNotReusableAlreadyUsed = Error("AuthKey not reusable already used")

// PreAuthKey describes a pre-authorization key usable in a particular namespace
type PreAuthKey struct {
	ID          uint64 `gorm:"primary_key"`
	Key         string
	NamespaceID uint
	Namespace   Namespace
	Reusable    bool
	Ephemeral   bool `gorm:"default:false"`

	AlreadyUsed bool `gorm:"-"` // this field is not stored in the DB, has to be manually filled

	CreatedAt  *time.Time
	Expiration *time.Time
}

// CreatePreAuthKey creates a new PreAuthKey in a namespace, and returns it
func (h *Headscale) CreatePreAuthKey(namespaceName string, reusable bool, ephemeral bool, expiration *time.Time) (*PreAuthKey, error) {
	n, err := h.GetNamespace(namespaceName)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	kstr, err := h.generateKey()
	if err != nil {
		return nil, err
	}

	k := PreAuthKey{
		Key:         kstr,
		NamespaceID: n.ID,
		Namespace:   *n,
		Reusable:    reusable,
		Ephemeral:   ephemeral,
		CreatedAt:   &now,
		Expiration:  expiration,
	}
	h.db.Save(&k)

	return &k, nil
}

// GetPreAuthKeys returns the list of PreAuthKeys for a namespace
func (h *Headscale) GetPreAuthKeys(namespaceName string) (*[]PreAuthKey, error) {
	n, err := h.GetNamespace(namespaceName)
	if err != nil {
		return nil, err
	}

	keys := []PreAuthKey{}
	if err := h.db.Preload("Namespace").Where(&PreAuthKey{NamespaceID: n.ID}).Find(&keys).Error; err != nil {
		return nil, err
	}

	for i, k := range keys {
		machines := []Machine{}
		if err := h.db.Preload("AuthKey").Where(&Machine{AuthKeyID: uint(k.ID)}).Find(&machines).Error; err != nil {
			return nil, err
		}
		if len(machines) > 0 {
			keys[i].AlreadyUsed = true
		}
	}
	return &keys, nil
}

// GetPreAuthKey returns a PreAuthKey for a given key
func (h *Headscale) GetPreAuthKey(namespace string, key string) (*PreAuthKey, error) {
	pak, err := h.checkKeyValidity(key)
	if err != nil {
		return nil, err
	}

	if pak.Namespace.Name != namespace {
		return nil, errors.New("Namespace mismatch")
	}

	return pak, nil
}

// MarkExpirePreAuthKey marks a PreAuthKey as expired
func (h *Headscale) MarkExpirePreAuthKey(k *PreAuthKey) error {
	if err := h.db.Model(&k).Update("Expiration", time.Now()).Error; err != nil {
		return err
	}
	return nil
}

// checkKeyValidity does the heavy lifting for validation of the PreAuthKey coming from a node
// If returns no error and a PreAuthKey, it can be used
func (h *Headscale) checkKeyValidity(k string) (*PreAuthKey, error) {
	pak := PreAuthKey{}
	if result := h.db.Preload("Namespace").First(&pak, "key = ?", k); errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, errorAuthKeyNotFound
	}

	if pak.Expiration != nil && pak.Expiration.Before(time.Now()) {
		return nil, errorAuthKeyExpired
	}

	if pak.Reusable || pak.Ephemeral { // we don't need to check if has been used before
		return &pak, nil
	}

	machines := []Machine{}
	if err := h.db.Preload("AuthKey").Where(&Machine{AuthKeyID: uint(pak.ID)}).Find(&machines).Error; err != nil {
		return nil, err
	}

	if len(machines) != 0 {
		return nil, errorAuthKeyNotReusableAlreadyUsed
	}

	// missing here validation on current usage
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
