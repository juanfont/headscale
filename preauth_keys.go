package headscale

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"time"
)

// PreAuthKey describes a pre-authorization key usable in a particular namespace
type PreAuthKey struct {
	ID          uint64 `gorm:"primary_key"`
	Key         string
	NamespaceID uint
	Namespace   Namespace
	Reusable    bool

	CreatedAt  *time.Time
	Expiration *time.Time
}

// CreatePreAuthKey creates a new PreAuthKey in a namespace, and returns it
func (h *Headscale) CreatePreAuthKey(namespaceName string, reusable bool, expiration *time.Time) (*PreAuthKey, error) {
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

func (h *Headscale) generateKey() (string, error) {
	size := 24
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
