package db

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"golang.org/x/crypto/bcrypt"
)

const (
	apiPrefixLength = 7
	apiKeyLength    = 32
)

var ErrAPIKeyFailedToParse = errors.New("failed to parse ApiKey")

// CreateAPIKey creates a new ApiKey in a user, and returns it.
func (hsdb *HSDatabase) CreateAPIKey(
	expiration *time.Time,
) (string, *types.APIKey, error) {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	prefix, err := util.GenerateRandomStringURLSafe(apiPrefixLength)
	if err != nil {
		return "", nil, err
	}

	toBeHashed, err := util.GenerateRandomStringURLSafe(apiKeyLength)
	if err != nil {
		return "", nil, err
	}

	// Key to return to user, this will only be visible _once_
	keyStr := prefix + "." + toBeHashed

	hash, err := bcrypt.GenerateFromPassword([]byte(toBeHashed), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, err
	}

	key := types.APIKey{
		Prefix:     prefix,
		Hash:       hash,
		Expiration: expiration,
	}

	if err := hsdb.db.Save(&key).Error; err != nil {
		return "", nil, fmt.Errorf("failed to save API key to database: %w", err)
	}

	return keyStr, &key, nil
}

// ListAPIKeys returns the list of ApiKeys for a user.
func (hsdb *HSDatabase) ListAPIKeys() ([]types.APIKey, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	keys := []types.APIKey{}
	if err := hsdb.db.Find(&keys).Error; err != nil {
		return nil, err
	}

	return keys, nil
}

// GetAPIKey returns a ApiKey for a given key.
func (hsdb *HSDatabase) GetAPIKey(prefix string) (*types.APIKey, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	key := types.APIKey{}
	if result := hsdb.db.First(&key, "prefix = ?", prefix); result.Error != nil {
		return nil, result.Error
	}

	return &key, nil
}

// GetAPIKeyByID returns a ApiKey for a given id.
func (hsdb *HSDatabase) GetAPIKeyByID(id uint64) (*types.APIKey, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	key := types.APIKey{}
	if result := hsdb.db.Find(&types.APIKey{ID: id}).First(&key); result.Error != nil {
		return nil, result.Error
	}

	return &key, nil
}

// DestroyAPIKey destroys a ApiKey. Returns error if the ApiKey
// does not exist.
func (hsdb *HSDatabase) DestroyAPIKey(key types.APIKey) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	if result := hsdb.db.Unscoped().Delete(key); result.Error != nil {
		return result.Error
	}

	return nil
}

// ExpireAPIKey marks a ApiKey as expired.
func (hsdb *HSDatabase) ExpireAPIKey(key *types.APIKey) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	if err := hsdb.db.Model(&key).Update("Expiration", time.Now()).Error; err != nil {
		return err
	}

	return nil
}

func (hsdb *HSDatabase) ValidateAPIKey(keyStr string) (bool, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	prefix, hash, found := strings.Cut(keyStr, ".")
	if !found {
		return false, ErrAPIKeyFailedToParse
	}

	key, err := hsdb.GetAPIKey(prefix)
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
