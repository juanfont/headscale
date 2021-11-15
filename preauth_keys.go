package headscale

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
)

const (
	errPreAuthKeyNotFound          = Error("AuthKey not found")
	errPreAuthKeyExpired           = Error("AuthKey expired")
	errSingleUseAuthKeyHasBeenUsed = Error("AuthKey has already been used")
	errNamespaceMismatch           = Error("namespace mismatch")
)

// PreAuthKey describes a pre-authorization key usable in a particular namespace.
type PreAuthKey struct {
	ID          uint64 `gorm:"primary_key"`
	Key         string
	NamespaceID uint
	Namespace   Namespace
	Reusable    bool
	Ephemeral   bool `gorm:"default:false"`
	Used        bool `gorm:"default:false"`

	CreatedAt  *time.Time
	Expiration *time.Time
}

// CreatePreAuthKey creates a new PreAuthKey in a namespace, and returns it.
func (h *Headscale) CreatePreAuthKey(
	namespaceName string,
	reusable bool,
	ephemeral bool,
	expiration *time.Time,
) (*PreAuthKey, error) {
	namespace, err := h.GetNamespace(namespaceName)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	kstr, err := h.generateKey()
	if err != nil {
		return nil, err
	}

	key := PreAuthKey{
		Key:         kstr,
		NamespaceID: namespace.ID,
		Namespace:   *namespace,
		Reusable:    reusable,
		Ephemeral:   ephemeral,
		CreatedAt:   &now,
		Expiration:  expiration,
	}
	h.db.Save(&key)

	return &key, nil
}

// ListPreAuthKeys returns the list of PreAuthKeys for a namespace.
func (h *Headscale) ListPreAuthKeys(namespaceName string) ([]PreAuthKey, error) {
	namespace, err := h.GetNamespace(namespaceName)
	if err != nil {
		return nil, err
	}

	keys := []PreAuthKey{}
	if err := h.db.Preload("Namespace").Where(&PreAuthKey{NamespaceID: namespace.ID}).Find(&keys).Error; err != nil {
		return nil, err
	}

	return keys, nil
}

// GetPreAuthKey returns a PreAuthKey for a given key.
func (h *Headscale) GetPreAuthKey(namespace string, key string) (*PreAuthKey, error) {
	pak, err := h.checkKeyValidity(key)
	if err != nil {
		return nil, err
	}

	if pak.Namespace.Name != namespace {
		return nil, errNamespaceMismatch
	}

	return pak, nil
}

// DestroyPreAuthKey destroys a preauthkey. Returns error if the PreAuthKey
// does not exist.
func (h *Headscale) DestroyPreAuthKey(pak PreAuthKey) error {
	if result := h.db.Unscoped().Delete(pak); result.Error != nil {
		return result.Error
	}

	return nil
}

// MarkExpirePreAuthKey marks a PreAuthKey as expired.
func (h *Headscale) ExpirePreAuthKey(k *PreAuthKey) error {
	if err := h.db.Model(&k).Update("Expiration", time.Now()).Error; err != nil {
		return err
	}

	return nil
}

// checkKeyValidity does the heavy lifting for validation of the PreAuthKey coming from a node
// If returns no error and a PreAuthKey, it can be used.
func (h *Headscale) checkKeyValidity(k string) (*PreAuthKey, error) {
	pak := PreAuthKey{}
	if result := h.db.Preload("Namespace").First(&pak, "key = ?", k); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return nil, errPreAuthKeyNotFound
	}

	if pak.Expiration != nil && pak.Expiration.Before(time.Now()) {
		return nil, errPreAuthKeyExpired
	}

	if pak.Reusable || pak.Ephemeral { // we don't need to check if has been used before
		return &pak, nil
	}

	machines := []Machine{}
	if err := h.db.Preload("AuthKey").Where(&Machine{AuthKeyID: uint(pak.ID)}).Find(&machines).Error; err != nil {
		return nil, err
	}

	if len(machines) != 0 || pak.Used {
		return nil, errSingleUseAuthKeyHasBeenUsed
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
		Namespace: key.Namespace.Name,
		Id:        strconv.FormatUint(key.ID, Base10),
		Key:       key.Key,
		Ephemeral: key.Ephemeral,
		Reusable:  key.Reusable,
		Used:      key.Used,
	}

	if key.Expiration != nil {
		protoKey.Expiration = timestamppb.New(*key.Expiration)
	}

	if key.CreatedAt != nil {
		protoKey.CreatedAt = timestamppb.New(*key.CreatedAt)
	}

	return &protoKey
}
