package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
	"tailscale.com/util/set"
)

var (
	// ErrPreAuthKeyNotFound wraps gorm.ErrRecordNotFound so an unknown or
	// deleted key is treated as a missing record by callers, which the
	// registration handler maps to a 401 rather than a raw server error.
	ErrPreAuthKeyNotFound          = fmt.Errorf("auth-key not found: %w", gorm.ErrRecordNotFound)
	ErrPreAuthKeyExpired           = errors.New("auth-key expired")
	ErrSingleUseAuthKeyHasBeenUsed = errors.New("auth-key has already been used")
	ErrUserMismatch                = errors.New("user mismatch")
	ErrPreAuthKeyACLTagInvalid     = errors.New("auth-key tag is invalid")
)

// validateACLTags deduplicates, sorts, and checks that every tag carries the
// "tag:" prefix. Shared by the pre-auth-key and OAuth credential paths so both
// enforce the same tag shape.
func validateACLTags(tags []string) ([]string, error) {
	tags = set.SetOf(tags).Slice()
	slices.Sort(tags)

	for _, tag := range tags {
		if !strings.HasPrefix(tag, "tag:") {
			return nil, fmt.Errorf(
				"%w: '%s' did not begin with 'tag:'",
				ErrPreAuthKeyACLTagInvalid,
				tag,
			)
		}
	}

	return tags, nil
}

func (hsdb *HSDatabase) CreatePreAuthKey(
	uid *types.UserID,
	reusable bool,
	ephemeral bool,
	expiration *time.Time,
	aclTags []string,
) (*types.PreAuthKeyNew, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.PreAuthKeyNew, error) {
		return CreatePreAuthKey(tx, uid, reusable, ephemeral, expiration, aclTags)
	})
}

const authKeyPrefix = "hskey-auth-"

// NewPreAuthKey is what a key is made from.
type NewPreAuthKey struct {
	// User is the owner of a user's key. The legacy APIs also set it on a
	// tagged key, for the user who made it.
	User        *types.UserID
	Tags        []string
	Reusable    bool
	Ephemeral   bool
	Expiration  *time.Time
	Description string
	// CreatedBy is the user who owns the credential that made the key.
	CreatedBy *types.UserID
	// ByToken marks a key an OAuth access token made.
	ByToken bool
	// Created is when the key was made; zero is now.
	Created time.Time
}

// CreatePreAuthKey creates a new [types.PreAuthKey] in a user, and returns it.
// The uid parameter can be nil for system-created tagged keys.
// For tagged keys, uid tracks "created by" (who created the key).
// For user-owned keys, uid tracks the node owner.
func CreatePreAuthKey(
	tx *gorm.DB,
	uid *types.UserID,
	reusable bool,
	ephemeral bool,
	expiration *time.Time,
	aclTags []string,
) (*types.PreAuthKeyNew, error) {
	_, made, err := CreatePreAuthKeyFrom(tx, NewPreAuthKey{
		User: uid, Tags: aclTags, Reusable: reusable, Ephemeral: ephemeral, Expiration: expiration,
	})

	return made, err
}

// CreatePreAuthKeyFrom creates the key k describes. It returns the key as
// stored, and once its secret.
func CreatePreAuthKeyFrom(tx *gorm.DB, k NewPreAuthKey) (*types.PreAuthKey, *types.PreAuthKeyNew, error) {
	// Validate: must be tagged OR user-owned, not neither
	if k.User == nil && len(k.Tags) == 0 {
		return nil, nil, ErrPreAuthKeyNotTaggedOrOwned
	}

	var (
		user   *types.User
		userID *uint
	)

	if k.User != nil {
		var err error

		user, err = GetUserByID(tx, *k.User)
		if err != nil {
			return nil, nil, err
		}

		userID = &user.ID
	}

	aclTags, err := validateACLTags(k.Tags)
	if err != nil {
		return nil, nil, err
	}

	var createdBy *uint
	if k.CreatedBy != nil {
		createdBy = new(uint(*k.CreatedBy))
	}

	now := k.Created
	if now.IsZero() {
		now = time.Now().UTC()
	}

	keyStr, identifier, hash := generateSecret(authKeyPrefix)

	// Set only UserID for the write so GORM does not upsert the User row; the
	// User is attached afterwards for the returned projection.
	cred := types.Credential{
		Kind:            types.CredentialPreAuthKey,
		Identifier:      identifier,
		Hash:            hash,
		UserID:          userID, // nil for system-created keys, or "created by" for tagged keys
		Description:     k.Description,
		Reusable:        k.Reusable,
		Ephemeral:       k.Ephemeral,
		CreatedByToken:  k.ByToken,
		CreatedByUserID: createdBy,
		CreatedAt:       &now,
		Expiration:      k.Expiration,
		Tags:            aclTags, // empty for user-owned keys
	}

	if err := tx.Save(&cred).Error; err != nil { //nolint:noinlineerr
		return nil, nil, fmt.Errorf("creating key in database: %w", err)
	}

	cred.User = user // nil for system-created keys

	return credentialToPreAuthKey(&cred), &types.PreAuthKeyNew{
		ID:         cred.ID,
		Key:        keyStr,
		Reusable:   cred.Reusable,
		Ephemeral:  cred.Ephemeral,
		Tags:       cred.Tags,
		Expiration: cred.Expiration,
		CreatedAt:  cred.CreatedAt,
		User:       user,
	}, nil
}

func (hsdb *HSDatabase) ListPreAuthKeys() ([]types.PreAuthKey, error) {
	return Read(hsdb.DB, ListPreAuthKeys)
}

// ListPreAuthKeys returns all [types.PreAuthKey] values in the database.
func ListPreAuthKeys(tx *gorm.DB) ([]types.PreAuthKey, error) {
	var creds []types.Credential

	err := tx.Preload("User").
		Where("kind = ?", types.CredentialPreAuthKey).
		Find(&creds).Error
	if err != nil {
		return nil, err
	}

	keys := make([]types.PreAuthKey, 0, len(creds))
	for i := range creds {
		keys = append(keys, *credentialToPreAuthKey(&creds[i]))
	}

	return keys, nil
}

// ListPreAuthKeysByUser returns all [types.PreAuthKey] values belonging to a specific user.
func ListPreAuthKeysByUser(tx *gorm.DB, uid types.UserID) ([]types.PreAuthKey, error) {
	var creds []types.Credential

	err := tx.Preload("User").
		Where("kind = ? AND user_id = ?", types.CredentialPreAuthKey, uint(uid)).
		Find(&creds).Error
	if err != nil {
		return nil, err
	}

	keys := make([]types.PreAuthKey, 0, len(creds))
	for i := range creds {
		keys = append(keys, *credentialToPreAuthKey(&creds[i]))
	}

	return keys, nil
}

// PreAuthKeyFilter narrows a page of keys; a zero field matches every key.
// When both are set, a key must match both.
type PreAuthKeyFilter struct {
	// User matches the keys the user owns; a tagged key never matches.
	User types.UserID
	Tag  string
}

// where is the filter in SQL. It may select more than [PreAuthKeyFilter.keeps]
// keeps, never less.
func (f PreAuthKeyFilter) where(rx *gorm.DB) *gorm.DB {
	if f.User != 0 {
		// A tagged key's JSON list holds a quoted string; a user's key has none.
		rx = rx.Where("user_id = ? AND (tags IS NULL OR tags NOT LIKE ?)", uint(f.User), `%"%`)
	}

	if f.Tag != "" {
		// The tag as the JSON serializer stores it; a case-sensitive substring
		// on both databases, which LIKE is not on SQLite.
		quoted, _ := json.Marshal(f.Tag) //nolint:errchkjson // a string always marshals

		contains := "instr(tags, ?) > 0"
		if rx.Name() == "postgres" {
			contains = "strpos(tags, ?) > 0"
		}

		rx = rx.Where(contains, string(quoted))
	}

	return rx
}

func (f PreAuthKeyFilter) keeps(k *types.PreAuthKey) bool {
	return (f.User == 0 || !k.IsTagged() && k.UserID != nil && types.UserID(*k.UserID) == f.User) &&
		(f.Tag == "" || slices.Contains(k.Tags, f.Tag))
}

// ListPreAuthKeysPage returns, in ID order, up to limit keys with an ID
// above after that f matches, revoked keys too, and the IDs of those a node
// refers to; both from one transaction, which ends with ctx.
func (hsdb *HSDatabase) ListPreAuthKeysPage(
	ctx context.Context,
	after uint64,
	limit int,
	f PreAuthKeyFilter,
) ([]types.PreAuthKey, set.Set[uint64], error) {
	type page struct {
		keys []types.PreAuthKey
		refs set.Set[uint64]
	}

	p, err := Read(hsdb.DB.WithContext(ctx), func(rx *gorm.DB) (page, error) {
		var keys []types.PreAuthKey

		creds, err := pageCredentials(rx, types.CredentialPreAuthKey, after, limit, f.where, func(c *types.Credential) bool {
			k := credentialToPreAuthKey(c)
			if f.keeps(k) {
				keys = append(keys, *k)

				return true
			}

			return false
		})
		if err != nil {
			return page{}, err
		}

		ids := make([]uint64, len(creds))
		for i := range creds {
			ids[i] = creds[i].ID
		}

		refs, err := preAuthKeysReferenced(rx, ids)

		return page{keys: keys, refs: refs}, err
	})

	return p.keys, p.refs, err
}

// maxCredentialBatch bounds the rows one query of a page reads.
const maxCredentialBatch = 1000

// pageCredentials is, in ID order, up to limit credentials of kind with an
// ID above after that where selects in SQL and keep keeps. where may select
// more than keep keeps; the batches double up to [maxCredentialBatch], so the
// queries of a page do not grow with how few rows keep keeps.
func pageCredentials(
	rx *gorm.DB,
	kind types.CredentialKind,
	after uint64,
	limit int,
	where func(*gorm.DB) *gorm.DB,
	keep func(*types.Credential) bool,
) ([]types.Credential, error) {
	var kept []types.Credential

	for batch := limit; len(kept) < limit; batch = max(limit, min(2*batch, maxCredentialBatch)) {
		var creds []types.Credential

		err := where(rx.Preload("User").Where("kind = ? AND id > ?", kind, after)).
			Order("id").Limit(batch).
			Find(&creds).Error
		if err != nil {
			return nil, err
		}

		for i := range creds {
			if len(kept) < limit && keep(&creds[i]) {
				kept = append(kept, creds[i])
			}
		}

		if len(creds) < batch {
			break
		}

		after = creds[len(creds)-1].ID
	}

	return kept, nil
}

// GetPreAuthKeyWithReference is the key with id, and whether a node refers
// to it, from one transaction.
func (hsdb *HSDatabase) GetPreAuthKeyWithReference(id uint64) (*types.PreAuthKey, bool, error) {
	type found struct {
		key        *types.PreAuthKey
		referenced bool
	}

	f, err := Read(hsdb.DB, func(rx *gorm.DB) (found, error) {
		var cred types.Credential

		err := rx.Preload("User").First(&cred, "kind = ? AND id = ?", types.CredentialPreAuthKey, id).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return found{}, ErrPreAuthKeyNotFound
		}

		if err != nil {
			return found{}, err
		}

		refs, err := preAuthKeysReferenced(rx, []uint64{id})

		return found{key: credentialToPreAuthKey(&cred), referenced: refs.Contains(id)}, err
	})

	return f.key, f.referenced, err
}

// preAuthKeysReferenced is the IDs of ids that a node's auth_key_id holds.
func preAuthKeysReferenced(rx *gorm.DB, ids []uint64) (set.Set[uint64], error) {
	refs := set.Set[uint64]{}
	if len(ids) == 0 {
		return refs, nil
	}

	var held []uint64

	err := rx.Model(&types.Node{}).
		Where("auth_key_id IN ?", ids).
		Distinct().Pluck("auth_key_id", &held).Error
	if err != nil {
		return nil, fmt.Errorf("reading the nodes of auth keys: %w", err)
	}

	refs.AddSlice(held)

	return refs, nil
}

var (
	ErrPreAuthKeyFailedToParse    = errors.New("failed to parse auth-key")
	ErrPreAuthKeyNotTaggedOrOwned = errors.New("auth-key must be either tagged or owned by user")
)

func findAuthKey(tx *gorm.DB, keyStr string) (*types.PreAuthKey, error) {
	// Validate input is not empty
	if keyStr == "" {
		return nil, ErrPreAuthKeyFailedToParse
	}

	// Unprefixed: a migrated pre-0.28 plaintext key.
	// TODO(kradalby): remove in 0.32 with legacy key formats (announced).
	identifier, secret := legacyAuthKeyIdentifier(keyStr), keyStr

	prefixAndSecret, found := strings.CutPrefix(keyStr, authKeyPrefix)
	if found {
		var err error

		identifier, secret, err = parsePrefixedKey(prefixAndSecret, ErrPreAuthKeyFailedToParse)
		if err != nil {
			return nil, err
		}
	}

	cred, err := authenticateCredential(
		tx, types.CredentialPreAuthKey, identifier, secret, ErrPreAuthKeyNotFound, "User",
	)
	if err != nil {
		return nil, err
	}

	return credentialToPreAuthKey(cred), nil
}

// legacyAuthKeyIdentifier derives the lookup identifier of a pre-0.28 plaintext
// pre-auth key, which has no embedded identifier. The migration stores these
// keys under it with the whole key hashed as the secret; the "legacy-" prefix
// keeps it disjoint from the hex identifiers of current keys.
//
// TODO(kradalby): remove in 0.32 with legacy key formats (announced).
func legacyAuthKeyIdentifier(key string) string {
	sum := sha256.Sum256([]byte(key))

	return "legacy-" + hex.EncodeToString(sum[:])[:keyIdentifierLength]
}

// parsePrefixedKey splits the prefix-and-secret portion of a new-format key
// (the part after the "hskey-*-" prefix) into its fixed-length prefix and
// secret components, validating the length, separator position, and that both
// components are base64 URL-safe. Fixed-length parsing is used instead of
// separator-based to handle dashes in base64 URL-safe characters.
func parsePrefixedKey(prefixAndSecret string, parseErr error) (string, string, error) {
	const (
		prefixLen = keyIdentifierLength
		secretLen = keySecretLength
	)

	expectedMinLength := prefixLen + 1 + secretLen
	if len(prefixAndSecret) < expectedMinLength {
		return "", "", fmt.Errorf(
			"%w: key too short, expected at least %d chars after prefix, got %d",
			parseErr,
			expectedMinLength,
			len(prefixAndSecret),
		)
	}

	prefix := prefixAndSecret[:prefixLen]

	// Validate separator at expected position
	if prefixAndSecret[prefixLen] != '-' {
		return "", "", fmt.Errorf(
			"%w: expected separator '-' at position %d, got '%c'",
			parseErr,
			prefixLen,
			prefixAndSecret[prefixLen],
		)
	}

	secret := prefixAndSecret[prefixLen+1:]

	// Validate secret length
	if len(secret) != secretLen {
		return "", "", fmt.Errorf(
			"%w: secret length mismatch, expected %d chars, got %d",
			parseErr,
			secretLen,
			len(secret),
		)
	}

	// Validate prefix contains only base64 URL-safe characters
	if !isValidBase64URLSafe(prefix) {
		return "", "", fmt.Errorf(
			"%w: prefix contains invalid characters (expected base64 URL-safe: A-Za-z0-9_-)",
			parseErr,
		)
	}

	// Validate secret contains only base64 URL-safe characters
	if !isValidBase64URLSafe(secret) {
		return "", "", fmt.Errorf(
			"%w: secret contains invalid characters (expected base64 URL-safe: A-Za-z0-9_-)",
			parseErr,
		)
	}

	return prefix, secret, nil
}

// isValidBase64URLSafe reports whether s contains only base64 URL-safe
// characters (A-Za-z0-9-_): current keys are hex, older ones used the wider
// base64url alphabet.
//
// TODO(kradalby): accept hex only in 0.32, with legacy key formats.
func isValidBase64URLSafe(s string) bool {
	return !strings.ContainsFunc(s, func(c rune) bool {
		return (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_'
	})
}

func (hsdb *HSDatabase) GetPreAuthKey(key string) (*types.PreAuthKey, error) {
	return GetPreAuthKey(hsdb.DB, key)
}

// GetPreAuthKey returns a [types.PreAuthKey] for a given key. The caller is responsible
// for checking if the key is usable (expired or used).
func GetPreAuthKey(tx *gorm.DB, key string) (*types.PreAuthKey, error) {
	return findAuthKey(tx, key)
}

// GetPreAuthKeyByID returns a [types.PreAuthKey] by its primary key, with the
// owning user preloaded.
func (hsdb *HSDatabase) GetPreAuthKeyByID(id uint64) (*types.PreAuthKey, error) {
	var cred types.Credential
	// Explicit primary-key clause: a struct condition would drop a zero-valued
	// ID, making the lookup unconditional and returning the first row instead
	// of not-found.
	if result := hsdb.DB.Preload("User").
		First(&cred, "kind = ? AND id = ?", types.CredentialPreAuthKey, id); result.Error != nil {
		return nil, result.Error
	}

	return credentialToPreAuthKey(&cred), nil
}

// DestroyPreAuthKey destroys a preauthkey. Returns error if the [types.PreAuthKey]
// does not exist. Referenced ephemeral keys are revoked instead, so their
// nodes keep the key they joined with. Other keys are removed along with their
// nodes' auth_key_id references.
func DestroyPreAuthKey(tx *gorm.DB, id uint64) error {
	return tx.Transaction(func(db *gorm.DB) error {
		res := db.Model(&types.Credential{}).
			Where("kind = ? AND id = ? AND ephemeral = ?", types.CredentialPreAuthKey, id, true).
			Where("id IN (SELECT auth_key_id FROM nodes WHERE auth_key_id IS NOT NULL)").
			Update("revoked", gorm.Expr("COALESCE(revoked, ?)", time.Now()))
		if res.Error != nil {
			return res.Error
		}

		if res.RowsAffected > 0 {
			return nil
		}

		// First, clear the foreign key reference on any nodes using this key
		err := db.Model(&types.Node{}).
			Where("auth_key_id = ?", id).
			Update("auth_key_id", nil).Error
		if err != nil {
			return fmt.Errorf("clearing auth_key_id on nodes: %w", err)
		}

		// Then delete the pre-auth key, on the same savepoint as the
		// node update so both roll back together.
		res = db.Unscoped().
			Delete(&types.Credential{}, "kind = ? AND id = ?", types.CredentialPreAuthKey, id)
		if res.Error != nil {
			return res.Error
		}

		if res.RowsAffected == 0 {
			return ErrPreAuthKeyNotFound
		}

		return nil
	})
}

func (hsdb *HSDatabase) ExpirePreAuthKey(id uint64) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return ExpirePreAuthKey(tx, id)
	})
}

func (hsdb *HSDatabase) DeletePreAuthKey(id uint64) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return DestroyPreAuthKey(tx, id)
	})
}

func (hsdb *HSDatabase) RevokePreAuthKey(id uint64) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return RevokePreAuthKey(tx, id)
	})
}

// RevokePreAuthKey soft-revokes a key (the v2 API's DELETE): the row is kept and
// stays retrievable with its invalid flag set, but the key can no longer
// authorize nodes. The background collector hard-deletes it after the retention
// window. Revoking a revoked key keeps its first revoke time and succeeds, as a
// repeated DELETE does on Tailscale; an unknown id returns [ErrPreAuthKeyNotFound].
func RevokePreAuthKey(tx *gorm.DB, id uint64) error {
	res := tx.Model(&types.Credential{}).
		Where("kind = ? AND id = ?", types.CredentialPreAuthKey, id).
		Update("revoked", gorm.Expr("COALESCE(revoked, ?)", time.Now()))
	if res.Error != nil {
		return res.Error
	}

	if res.RowsAffected == 0 {
		return ErrPreAuthKeyNotFound
	}

	return nil
}

// DestroyRevokedPreAuthKeysBefore hard-deletes every key revoked before cutoff,
// returning how many were removed. The background collector calls this to reap
// soft-revoked keys after the retention window. Keys still referenced by a node
// are kept, so revoking a key does not change nodes already registered with it.
func (hsdb *HSDatabase) DestroyRevokedPreAuthKeysBefore(cutoff time.Time) (int, error) {
	var count int

	err := hsdb.Write(func(tx *gorm.DB) error {
		var ids []uint64

		err := tx.Model(&types.Credential{}).
			Where("kind = ? AND revoked IS NOT NULL AND revoked < ?", types.CredentialPreAuthKey, cutoff).
			Where("id NOT IN (SELECT auth_key_id FROM nodes WHERE auth_key_id IS NOT NULL)").
			Pluck("id", &ids).Error
		if err != nil {
			return err
		}

		for _, id := range ids {
			err := DestroyPreAuthKey(tx, id)
			if err != nil {
				return err
			}
		}

		count = len(ids)

		return nil
	})

	return count, err
}

// UsePreAuthKey atomically marks a [types.PreAuthKey] as used. The UPDATE is
// guarded by `used = false` so two concurrent registrations racing for
// the same single-use key cannot both succeed: the first commits and
// the second returns [types.PAKError]("authkey already used"). Without the
// guard the previous code (Update("used", true) with no WHERE) would
// silently let both transactions claim the key.
func UsePreAuthKey(tx *gorm.DB, k *types.PreAuthKey) error {
	return ClaimPreAuthKey(tx, k, true)
}

// ClaimPreAuthKey is the last check of a registration with k, made in the
// registration's transaction: a revoked or expired key is refused, and with
// consume a single-use key another node took. The key was read and checked
// before; a revoke or expire that answered since then must still hold. The
// UPDATE locks the key's row, so one that committed is seen, and one that
// has not waits for this registration and answers after the node exists.
func ClaimPreAuthKey(tx *gorm.DB, k *types.PreAuthKey, consume bool) error {
	q := tx.Model(&types.Credential{}).
		Where("kind = ? AND id = ? AND revoked IS NULL", types.CredentialPreAuthKey, k.ID)

	// A reusable key's row is written as it is, for the lock and the count.
	var used any = gorm.Expr("used")
	if consume {
		q, used = q.Where("used = ?", false), true
	}

	res := q.Update("used", used)
	if res.Error != nil {
		return fmt.Errorf("updating key used status in database: %w", res.Error)
	}

	// Read after the UPDATE holds the row. The expiry is compared here, not
	// in SQL: SQLite compares stored times as text, in whatever zone wrote them.
	var cred types.Credential

	err := tx.Select("revoked", "expiration").First(&cred, "kind = ? AND id = ?", types.CredentialPreAuthKey, k.ID).Error

	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return ErrPreAuthKeyNotFound
	case err != nil:
		return fmt.Errorf("reading key: %w", err)
	case cred.Revoked != nil:
		return types.PAKError("authkey revoked")
	case cred.Expiration != nil && cred.Expiration.Before(time.Now()):
		return types.PAKError("authkey expired")
	case res.RowsAffected == 0:
		return types.PAKError("authkey already used")
	}

	if consume {
		k.Used = true
	}

	return nil
}

// ExpirePreAuthKey marks a [types.PreAuthKey] as expired, returning
// [ErrPreAuthKeyNotFound] rather than succeeding silently when no such key exists.
func ExpirePreAuthKey(tx *gorm.DB, id uint64) error {
	now := time.Now()

	res := tx.Model(&types.Credential{}).
		Where("kind = ? AND id = ?", types.CredentialPreAuthKey, id).
		Update("expiration", now)
	if res.Error != nil {
		return res.Error
	}

	if res.RowsAffected == 0 {
		return ErrPreAuthKeyNotFound
	}

	return nil
}
