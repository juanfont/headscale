package headscale

import (
	"fmt"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	apiPrefixLength = 7
	apiKeyLength    = 32

	errAPIKeyFailedToParse = Error("Failed to parse ApiKey")
)

// APIKey describes the datamodel for API keys used to remotely authenticate with
// headscale.
type APIKey struct {
	ID     uint64 `gorm:"primary_key"`
	Prefix string `gorm:"uniqueIndex"`
	Hash   []byte

	CreatedAt  *time.Time
	Expiration *time.Time
	LastSeen   *time.Time
}

// CreateAPIKey creates a new ApiKey in a namespace, and returns it.
func (h *Headscale) CreateAPIKey(
	expiration *time.Time,
) (string, *APIKey, error) {
	prefix, err := GenerateRandomStringURLSafe(apiPrefixLength)
	if err != nil {
		return "", nil, err
	}

	toBeHashed, err := GenerateRandomStringURLSafe(apiKeyLength)
	if err != nil {
		return "", nil, err
	}

	// Key to return to user, this will only be visible _once_
	keyStr := prefix + "." + toBeHashed

	hash, err := bcrypt.GenerateFromPassword([]byte(toBeHashed), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, err
	}

	key := APIKey{
		Prefix:     prefix,
		Hash:       hash,
		Expiration: expiration,
	}

	if err := h.db.Save(&key).Error; err != nil {
		return "", nil, fmt.Errorf("failed to save API key to database: %w", err)
	}

	return keyStr, &key, nil
}

// ListAPIKeys returns the list of ApiKeys for a namespace.
func (h *Headscale) ListAPIKeys() ([]APIKey, error) {
	keys := []APIKey{}
	if err := h.db.Find(&keys).Error; err != nil {
		return nil, err
	}

	return keys, nil
}

// GetAPIKey returns a ApiKey for a given key.
func (h *Headscale) GetAPIKey(prefix string) (*APIKey, error) {
	key := APIKey{}
	if result := h.db.First(&key, "prefix = ?", prefix); result.Error != nil {
		return nil, result.Error
	}

	return &key, nil
}

// GetAPIKeyByID returns a ApiKey for a given id.
func (h *Headscale) GetAPIKeyByID(id uint64) (*APIKey, error) {
	key := APIKey{}
	if result := h.db.Find(&APIKey{ID: id}).First(&key); result.Error != nil {
		return nil, result.Error
	}

	return &key, nil
}

// DestroyAPIKey destroys a ApiKey. Returns error if the ApiKey
// does not exist.
func (h *Headscale) DestroyAPIKey(key APIKey) error {
	if result := h.db.Unscoped().Delete(key); result.Error != nil {
		return result.Error
	}

	return nil
}

// ExpireAPIKey marks a ApiKey as expired.
func (h *Headscale) ExpireAPIKey(key *APIKey) error {
	if err := h.db.Model(&key).Update("Expiration", time.Now()).Error; err != nil {
		return err
	}

	return nil
}

func (h *Headscale) ValidateAPIKey(keyStr string) (bool, error) {
	prefix, hash, found := strings.Cut(keyStr, ".")
	if !found {
		return false, errAPIKeyFailedToParse
	}

	key, err := h.GetAPIKey(prefix)
	if err != nil {
		return false, fmt.Errorf("failed to validate api key: %w", err)
	}

	if key.Expiration.Before(time.Now()) {
		return false, nil
	}

	if err := bcrypt.CompareHashAndPassword(key.Hash, []byte(hash)); err != nil {
		return false, err
	}

	return true, nil
}

func (key *APIKey) toProto() *v1.ApiKey {
	protoKey := v1.ApiKey{
		Id:     key.ID,
		Prefix: key.Prefix,
	}

	if key.Expiration != nil {
		protoKey.Expiration = timestamppb.New(*key.Expiration)
	}

	if key.CreatedAt != nil {
		protoKey.CreatedAt = timestamppb.New(*key.CreatedAt)
	}

	if key.LastSeen != nil {
		protoKey.LastSeen = timestamppb.New(*key.LastSeen)
	}

	return &protoKey
}
