package headscale

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"time"
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

	CreatedAt  *time.Time
	Expiration *time.Time
}

// CreatePreAuthKey creates a new PreAuthKey in a namespace, and returns it
func (h *Headscale) CreatePreAuthKey(namespaceName string, reusable bool, ephemeral bool, expiration *time.Time) (*PreAuthKey, error) {
	n, err := h.GetNamespace(namespaceName)
	if err != nil {
		return nil, err
	}

	db, err := h.db()
	if err != nil {
		log.Printf("Cannot open DB: %s", err)
		return nil, err
	}
	defer db.Close()

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
	db.Save(&k)

	return &k, nil
}

// GetPreAuthKeys returns the list of PreAuthKeys for a namespace
func (h *Headscale) GetPreAuthKeys(namespaceName string) (*[]PreAuthKey, error) {
	n, err := h.GetNamespace(namespaceName)
	if err != nil {
		return nil, err
	}
	db, err := h.db()
	if err != nil {
		log.Printf("Cannot open DB: %s", err)
		return nil, err
	}
	defer db.Close()

	keys := []PreAuthKey{}
	if err := db.Preload("Namespace").Where(&PreAuthKey{NamespaceID: n.ID}).Find(&keys).Error; err != nil {
		return nil, err
	}
	return &keys, nil
}

// checkKeyValidity does the heavy lifting for validation of the PreAuthKey coming from a node
// If returns no error and a PreAuthKey, it can be used
func (h *Headscale) checkKeyValidity(k string) (*PreAuthKey, error) {
	db, err := h.db()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	pak := PreAuthKey{}
	if db.Preload("Namespace").First(&pak, "key = ?", k).RecordNotFound() {
		return nil, errorAuthKeyNotFound
	}

	if pak.Expiration != nil && pak.Expiration.Before(time.Now()) {
		return nil, errorAuthKeyExpired
	}

	if pak.Reusable || pak.Ephemeral { // we don't need to check if has been used before
		return &pak, nil
	}

	machines := []Machine{}
	if err := db.Preload("AuthKey").Where(&Machine{AuthKeyID: uint(pak.ID)}).Find(&machines).Error; err != nil {
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
