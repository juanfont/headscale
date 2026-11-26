package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const (
	apiKeyPrefix = "hskey-api-" //nolint:gosec // This is a prefix, not a credential

	// Legacy format constant: the prefix length of pre-hskey "prefix.secret" keys.
	// TODO(kradalby): remove in 0.32 with legacy key formats (announced).
	legacyAPIPrefixLength = 7
)

var (
	ErrAPIKeyFailedToParse    = errors.New("failed to parse ApiKey")
	ErrAPIKeyGenerationFailed = errors.New("failed to generate API key")
	ErrAPIKeyExpired          = errors.New("API key expired")
	ErrAPIKeyRevoked          = errors.New("API key revoked")
	ErrAPIKeyNotFound         = fmt.Errorf("API key not found: %w", gorm.ErrRecordNotFound)
)

// CreateAPIKey creates a new [types.APIKey] in a user, and returns it.
func (hsdb *HSDatabase) CreateAPIKey(
	expiration *time.Time,
) (string, *types.APIKey, error) {
	keyStr, identifier, hash := generateSecret(apiKeyPrefix)

	cred := types.Credential{
		Kind:       types.CredentialAPIKey,
		Identifier: identifier,
		Hash:       hash,
		Expiration: expiration,
	}

	if err := hsdb.DB.Save(&cred).Error; err != nil { //nolint:noinlineerr
		return "", nil, fmt.Errorf("saving API key to database: %w", err)
	}

	return keyStr, credentialToAPIKey(&cred), nil
}

// NewAPIKey is what an API key is made from.
type NewAPIKey struct {
	// Owner is the user recorded on the key; it does not limit the key.
	Owner      *types.UserID
	Expiration *time.Time
	// Created is when the key was made; zero leaves it to the database.
	Created time.Time
	// Maker is the credential that asks for the key; see [holdCredential].
	Maker uint64
}

// CreateAPIKeyFrom makes the API key k describes, and returns it as stored,
// with its owner, and once its secret. An owner no user has is
// [ErrUserNotFound].
func CreateAPIKeyFrom(tx *gorm.DB, k NewAPIKey) (*types.Credential, string, error) {
	err := holdCredential(tx, k.Maker)
	if err != nil {
		return nil, "", err
	}

	var owner *types.User

	if k.Owner != nil {
		owner, err = GetUserByID(tx, *k.Owner)
		if err != nil {
			return nil, "", err
		}
	}

	keyStr, identifier, hash := generateSecret(apiKeyPrefix)

	cred := types.Credential{
		Kind:       types.CredentialAPIKey,
		Identifier: identifier,
		Hash:       hash,
		Expiration: k.Expiration,
	}

	if owner != nil {
		cred.UserID = &owner.ID
	}

	if !k.Created.IsZero() {
		cred.CreatedAt = &k.Created
	}

	err = tx.Create(&cred).Error
	if err != nil {
		return nil, "", fmt.Errorf("saving API key to database: %w", err)
	}

	// Attached after the insert, so the insert does not write the user.
	cred.User = owner

	return &cred, keyStr, nil
}

// ListAPIKeysPage is up to limit API keys with an ID above after, in ID
// order, expired and revoked ones too; with owner set, only the keys it owns.
func (hsdb *HSDatabase) ListAPIKeysPage(ctx context.Context, after uint64, limit int, owner types.UserID) ([]types.Credential, error) {
	return hsdb.listCredentialsPage(ctx, types.CredentialAPIKey, after, limit, func(q *gorm.DB) *gorm.DB {
		if owner != 0 {
			return q.Where("user_id = ?", owner)
		}

		return q
	})
}

// GetAPIKeyCredential is the API key with id, revoked or not, with its owner.
func (hsdb *HSDatabase) GetAPIKeyCredential(id uint64) (*types.Credential, error) {
	return GetAPIKeyCredential(hsdb.DB, id)
}

// GetAPIKeyCredential is [HSDatabase.GetAPIKeyCredential] in rx, which may
// carry a request's context.
func GetAPIKeyCredential(rx *gorm.DB, id uint64) (*types.Credential, error) {
	return getCredential(rx, types.CredentialAPIKey, "id = ?", id, ErrAPIKeyNotFound)
}

// ListAPIKeys returns every API key that is not revoked, for /api/v1, whose
// answer cannot say that a key is revoked.
func (hsdb *HSDatabase) ListAPIKeys() ([]types.APIKey, error) {
	var creds []types.Credential

	err := hsdb.DB.Where("kind = ? AND revoked IS NULL", types.CredentialAPIKey).Order("id").Find(&creds).Error
	if err != nil {
		return nil, err
	}

	keys := make([]types.APIKey, 0, len(creds))
	for i := range creds {
		keys = append(keys, *credentialToAPIKey(&creds[i]))
	}

	return keys, nil
}

// GetAPIKey returns a [types.APIKey] for a given key.
func (hsdb *HSDatabase) GetAPIKey(prefix string) (*types.APIKey, error) {
	var cred types.Credential
	if result := hsdb.DB.First(&cred, "kind = ? AND identifier = ?", types.CredentialAPIKey, prefix); result.Error != nil {
		return nil, result.Error
	}

	return credentialToAPIKey(&cred), nil
}

// GetAPIKeyByID returns a [types.APIKey] for a given id.
func (hsdb *HSDatabase) GetAPIKeyByID(id uint64) (*types.APIKey, error) {
	var cred types.Credential
	// Query on an explicit primary-key clause: a struct condition would drop a
	// zero-valued ID, making the lookup unconditional and returning the first
	// row instead of not-found.
	if result := hsdb.DB.First(&cred, "kind = ? AND id = ?", types.CredentialAPIKey, id); result.Error != nil {
		return nil, result.Error
	}

	return credentialToAPIKey(&cred), nil
}

// DestroyAPIKey destroys a [types.APIKey]. Returns [ErrAPIKeyNotFound] if the
// [types.APIKey] does not exist.
func (hsdb *HSDatabase) DestroyAPIKey(key types.APIKey) error {
	res := hsdb.DB.Unscoped().
		Delete(&types.Credential{}, "kind = ? AND id = ?", types.CredentialAPIKey, key.ID)

	return apiKeyAffected(res)
}

// ExpireAPIKey marks a [types.APIKey] as expired.
func (hsdb *HSDatabase) ExpireAPIKey(key *types.APIKey) error {
	res := hsdb.DB.Model(&types.Credential{}).
		Where("kind = ? AND id = ?", types.CredentialAPIKey, key.ID).
		Update("expiration", time.Now())

	return apiKeyAffected(res)
}

// RevokeAPIKey ends an API key: it is refused from the next request on, and
// its record stays, revoked, until the removal. See [revokeCredential]; an
// unknown id returns [ErrAPIKeyNotFound].
func (hsdb *HSDatabase) RevokeAPIKey(id uint64) error {
	return revokeCredential(hsdb.DB, types.CredentialAPIKey, "id = ?", id, ErrAPIKeyNotFound)
}

// apiKeyAffected maps a write that matched no API key row to [ErrAPIKeyNotFound].
func apiKeyAffected(res *gorm.DB) error {
	if res.Error != nil {
		return res.Error
	}

	if res.RowsAffected == 0 {
		return ErrAPIKeyNotFound
	}

	return nil
}

func (hsdb *HSDatabase) ValidateAPIKey(keyStr string) (bool, error) {
	_, err := hsdb.AuthenticateAPIKey(keyStr)
	if errors.Is(err, ErrAPIKeyExpired) || errors.Is(err, ErrAPIKeyRevoked) {
		return false, nil
	}

	return err == nil, err
}

// AuthenticateAPIKey validates keyStr and returns the matching [types.APIKey]
// (with its owning UserID populated), for every API alike. Unlike
// ValidateAPIKey it returns the key itself, so the v2 API can act as the
// key's owning user. A non-nil error means the key is missing, malformed,
// expired ([ErrAPIKeyExpired]) or revoked ([ErrAPIKeyRevoked]).
func (hsdb *HSDatabase) AuthenticateAPIKey(keyStr string) (*types.APIKey, error) {
	return AuthenticateAPIKey(hsdb.DB, keyStr)
}

// AuthenticateAPIKey is [HSDatabase.AuthenticateAPIKey] in rx, which may
// carry a request's context.
func AuthenticateAPIKey(rx *gorm.DB, keyStr string) (*types.APIKey, error) {
	cred, err := validateAPIKey(rx, keyStr)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	switch {
	case cred.Revoked != nil:
		return nil, ErrAPIKeyRevoked
	case cred.Expiration != nil && types.ExpiredAt(*cred.Expiration, now):
		return nil, ErrAPIKeyExpired
	}

	err = recordAPIKeyUse(rx, cred, now)
	if err != nil {
		return nil, err
	}

	return credentialToAPIKey(cred), nil
}

// apiKeyLastSeenEvery is how old the stored last use of an API key may grow
// before a request writes it again. A write for each request would queue
// every request of a busy key on SQLite's one writer; this bounds the writes
// to one a minute for each key, and the time an admin reads to a minute.
const apiKeyLastSeenEvery = time.Minute

// recordAPIKeyUse stores now as the last use of cred when the stored one is
// older than [apiKeyLastSeenEvery]. It first holds the row while the key is
// not revoked, and then reads the last use, the revoke and the expiry in its
// transaction and compares them here as instants: SQLite compares stored
// times as text, with the offset each was written with. The last use read
// before the hold may be stale, so a use that is late, or one that another
// request recorded meanwhile, writes nothing. On PostgreSQL the hold waits
// for a revoke or an expiry that is open and then sees it, so a key whose end
// answered is refused here, not let through, and an ended key writes nothing.
// A write that fails is logged and the request goes on: the key is valid,
// only the time is late.
func recordAPIKeyUse(db *gorm.DB, cred *types.Credential, now time.Time) error {
	if cred.LastSeen != nil && now.Sub(*cred.LastSeen) < apiKeyLastSeenEvery {
		return nil
	}

	seen := now.UTC().Truncate(time.Microsecond)

	err := db.Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&types.Credential{}).Where("id = ? AND revoked IS NULL", cred.ID).
			Update("last_seen", gorm.Expr("last_seen"))
		if res.Error != nil {
			return res.Error
		}

		var c types.Credential

		err := tx.Select("last_seen", "revoked", "expiration").Take(&c, "id = ?", cred.ID).Error

		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			return ErrAPIKeyNotFound
		case err != nil:
			return err
		case c.Revoked != nil || res.RowsAffected == 0:
			return ErrAPIKeyRevoked
		case c.Expiration != nil && types.ExpiredAt(*c.Expiration, now):
			return ErrAPIKeyExpired
		case c.LastSeen != nil && seen.Sub(*c.LastSeen) < apiKeyLastSeenEvery:
			seen = *c.LastSeen

			return nil
		}

		return tx.Model(&types.Credential{}).Where("id = ?", cred.ID).Update("last_seen", seen).Error
	})
	if errors.Is(err, ErrAPIKeyNotFound) || errors.Is(err, ErrAPIKeyRevoked) || errors.Is(err, ErrAPIKeyExpired) {
		return err
	}

	if err != nil {
		log.Warn().Err(err).Uint64("credential", cred.ID).Msg("recording the use of an API key")

		return nil
	}

	cred.LastSeen = &seen

	return nil
}

// SetAPIKeyUser sets the owning user of an API key. Used when an admin mints a
// key on behalf of a user (headscale apikeys create --user).
func (hsdb *HSDatabase) SetAPIKeyUser(keyID uint64, userID types.UserID) error {
	res := hsdb.DB.Model(&types.Credential{}).
		Where("kind = ? AND id = ?", types.CredentialAPIKey, keyID).
		Update("user_id", uint(userID))

	return apiKeyAffected(res)
}

// ParseAPIKeyPrefix extracts the database prefix from a display prefix.
// Handles formats: "hskey-api-{12chars}-***", "hskey-api-{12chars}", or just "{12chars}".
// Returns the 12-character prefix suitable for database lookup.
func ParseAPIKeyPrefix(displayPrefix string) (string, error) {
	// If it's already just the 12-character prefix, return it
	if len(displayPrefix) == keyIdentifierLength && isValidBase64URLSafe(displayPrefix) {
		return displayPrefix, nil
	}

	// If it starts with the API key prefix, parse it
	if strings.HasPrefix(displayPrefix, apiKeyPrefix) {
		// Remove the "hskey-api-" prefix
		_, remainder, found := strings.Cut(displayPrefix, apiKeyPrefix)
		if !found {
			return "", fmt.Errorf("%w: invalid display prefix format", ErrAPIKeyFailedToParse)
		}

		// Extract just the first 12 characters (the actual prefix)
		if len(remainder) < keyIdentifierLength {
			return "", fmt.Errorf("%w: prefix too short", ErrAPIKeyFailedToParse)
		}

		prefix := remainder[:keyIdentifierLength]

		// Validate it's base64 URL-safe
		if !isValidBase64URLSafe(prefix) {
			return "", fmt.Errorf("%w: prefix contains invalid characters", ErrAPIKeyFailedToParse)
		}

		return prefix, nil
	}

	// For legacy 7-character prefixes or other formats, return as-is
	// TODO(kradalby): remove in 0.32 with legacy key formats (announced).
	return displayPrefix, nil
}

// validateAPIKey finds the API key whose secret keyStr holds, whatever its
// state. Handles both new (hskey-api-{prefix}-{secret}) and legacy
// (prefix.secret) formats.
func validateAPIKey(db *gorm.DB, keyStr string) (*types.Credential, error) {
	// Validate input is not empty
	if keyStr == "" {
		return nil, ErrAPIKeyFailedToParse
	}

	// Check for new format: hskey-api-{prefix}-{secret}
	prefixAndSecret, found := types.CutCredentialPrefix(keyStr, types.CredentialAPIKey)

	if !found {
		// Legacy format: prefix.secret
		// TODO(kradalby): remove in 0.32 with legacy key formats (announced).
		return validateLegacyAPIKey(db, keyStr)
	}

	prefix, secret, err := parsePrefixedKey(prefixAndSecret, ErrAPIKeyFailedToParse)
	if err != nil {
		return nil, err
	}

	return authenticateCredential(db, types.CredentialAPIKey, prefix, secret, ErrAPIKeyNotFound)
}

// validateLegacyAPIKey validates a legacy format API key (prefix.secret).
//
// TODO(kradalby): remove in 0.32 with legacy key formats (announced).
func validateLegacyAPIKey(db *gorm.DB, keyStr string) (*types.Credential, error) {
	// Legacy format uses "." as separator
	prefix, secret, found := strings.Cut(keyStr, ".")
	if !found {
		return nil, ErrAPIKeyFailedToParse
	}

	// Legacy prefix is 7 chars
	if len(prefix) != legacyAPIPrefixLength {
		return nil, fmt.Errorf("%w: legacy prefix length mismatch", ErrAPIKeyFailedToParse)
	}

	return authenticateCredential(db, types.CredentialAPIKey, prefix, secret, ErrAPIKeyNotFound)
}
