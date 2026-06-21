package db

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"golang.org/x/crypto/argon2"
	"gorm.io/gorm"
	"tailscale.com/util/rands"
	"tailscale.com/util/set"
)

const (
	// OAuth client secret: hskey-client-<clientID(12)>-<secret(64)>. The clientID
	// is the public, indexed lookup key (the analogue of an API key's prefix) and
	// is embedded in the secret so the token endpoint can derive it. The prefix
	// itself lives in the types package ([types.OAuthClientPrefix]).
	oauthClientIDLength     = 12
	oauthClientSecretLength = 64

	// OAuth access token: hskey-oauthtok-<prefix(12)>-<secret(64)>. The distinct
	// prefix (vs hskey-api- admin keys, [types.AccessTokenPrefix]) lets the auth
	// middleware dispatch a scoped token from an all-access admin key alone.
	accessTokenPrefixLength = 12
	accessTokenSecretLength = 64
)

var (
	ErrOAuthClientNotFound      = fmt.Errorf("oauth client not found: %w", gorm.ErrRecordNotFound)
	ErrOAuthClientFailedToParse = errors.New("failed to parse oauth client secret")
	ErrOAuthClientRevoked       = errors.New("oauth client revoked")

	ErrAccessTokenNotFound      = fmt.Errorf("oauth access token not found: %w", gorm.ErrRecordNotFound)
	ErrAccessTokenFailedToParse = errors.New("failed to parse oauth access token")
	ErrAccessTokenExpired       = errors.New("oauth access token expired")
	ErrAccessTokenClientRevoked = errors.New("oauth access token issuing client revoked or deleted")

	errSecretHashMalformed = errors.New("malformed secret hash")
	errSecretMismatch      = errors.New("secret does not match hash")
)

// Argon2id parameters, OWASP's minimum recommendation (19 MiB, 2 iterations, 1
// lane). They are encoded into every stored hash, so raising them later still
// verifies credentials stored under the old cost.
const (
	argon2Time    = 2
	argon2Memory  = 19 * 1024
	argon2Threads = 1
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

// argon2Limiter bounds concurrent Argon2id computations. Each costs ~19 MiB and
// the unauthenticated OAuth token endpoint runs one per attempt, so an unbounded
// flood could exhaust memory. ponytail: a global semaphore sized to GOMAXPROCS;
// revisit only if credential hashing ever becomes a throughput bottleneck.
var argon2Limiter = make(chan struct{}, max(2, runtime.GOMAXPROCS(0)))

// hashSecret hashes a credential secret with Argon2id, encoded in PHC string
// form so the parameters travel with the hash. Argon2id is the current OWASP
// recommendation, replacing bcrypt for new credential storage.
func hashSecret(secret string) ([]byte, error) {
	salt := make([]byte, argon2SaltLen)

	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	hash := argon2.IDKey([]byte(secret), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return []byte(encoded), nil
}

// verifySecret reports whether secret matches a hashSecret-encoded hash. It
// reads the cost parameters from the stored hash and compares in constant time
// so a mismatch leaks no timing signal.
func verifySecret(encoded []byte, secret string) error {
	parts := strings.Split(string(encoded), "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errSecretHashMalformed
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version { //nolint:noinlineerr
		return errSecretHashMalformed
	}

	var (
		memory, time uint32
		threads      uint8
	)

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil { //nolint:noinlineerr
		return errSecretHashMalformed
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return errSecretHashMalformed
	}

	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return errSecretHashMalformed
	}

	argon2Limiter <- struct{}{}
	//nolint:gosec // want is a 32-byte hash read back from storage, no overflow
	got := argon2.IDKey([]byte(secret), salt, time, memory, threads, uint32(len(want)))

	<-argon2Limiter

	if subtle.ConstantTimeCompare(got, want) != 1 {
		return errSecretMismatch
	}

	return nil
}

// CreateOAuthClient creates a new [types.OAuthClient] and returns the plaintext
// secret (shown ONCE) alongside the stored client. creatorUserID is the user who
// created it (informational), or nil.
func (hsdb *HSDatabase) CreateOAuthClient(
	scopes, tags []string,
	description string,
	creatorUserID *uint,
) (string, *types.OAuthClient, error) {
	tags, err := validateACLTags(tags)
	if err != nil {
		return "", nil, err
	}

	scopes = set.SetOf(scopes).Slice()
	slices.Sort(scopes)

	clientID := rands.HexString(oauthClientIDLength)
	secret := rands.HexString(oauthClientSecretLength)
	secretStr := types.OAuthClientPrefix + clientID + "-" + secret

	hash, err := hashSecret(secret)
	if err != nil {
		return "", nil, err
	}

	now := time.Now().UTC()
	client := types.OAuthClient{
		ClientID:    clientID,
		SecretHash:  hash,
		Scopes:      scopes,
		Tags:        tags,
		Description: description,
		UserID:      creatorUserID,
		CreatedAt:   &now,
	}

	err = hsdb.Write(func(tx *gorm.DB) error {
		return tx.Save(&client).Error
	})
	if err != nil {
		return "", nil, fmt.Errorf("saving oauth client: %w", err)
	}

	return secretStr, &client, nil
}

// AuthenticateOAuthClient validates a presented client secret and returns the
// matching, unrevoked [types.OAuthClient]. The client id is derived from the
// secret (its middle segment), so any separately-supplied client_id is
// redundant, matching Tailscale, where get-authkey passes a dummy id and the
// server derives the real one from the secret.
func (hsdb *HSDatabase) AuthenticateOAuthClient(secretStr string) (*types.OAuthClient, error) {
	if secretStr == "" {
		return nil, ErrOAuthClientFailedToParse
	}

	// Tailscale allows the secret to carry optional ?key=value attributes when
	// used directly as an auth key; strip them before parsing.
	secretStr, _, _ = strings.Cut(secretStr, "?")

	_, rest, found := strings.Cut(secretStr, types.OAuthClientPrefix)
	if !found {
		return nil, ErrOAuthClientFailedToParse
	}

	clientID, secret, err := parsePrefixedKey(
		rest,
		oauthClientIDLength,
		oauthClientSecretLength,
		ErrOAuthClientFailedToParse,
	)
	if err != nil {
		return nil, err
	}

	var client types.OAuthClient
	if err := hsdb.DB.First(&client, "client_id = ?", clientID).Error; err != nil { //nolint:noinlineerr
		return nil, ErrOAuthClientNotFound
	}

	if err := verifySecret(client.SecretHash, secret); err != nil { //nolint:noinlineerr
		return nil, fmt.Errorf("invalid oauth client secret: %w", err)
	}

	if client.Revoked != nil {
		return nil, ErrOAuthClientRevoked
	}

	return &client, nil
}

// GetOAuthClientByClientID returns a [types.OAuthClient] by its public client id.
func (hsdb *HSDatabase) GetOAuthClientByClientID(clientID string) (*types.OAuthClient, error) {
	var client types.OAuthClient
	if result := hsdb.DB.First(&client, "client_id = ?", clientID); result.Error != nil {
		return nil, result.Error
	}

	return &client, nil
}

// ListOAuthClients returns every [types.OAuthClient].
func (hsdb *HSDatabase) ListOAuthClients() ([]types.OAuthClient, error) {
	clients := []types.OAuthClient{}

	err := hsdb.DB.Find(&clients).Error
	if err != nil {
		return nil, err
	}

	return clients, nil
}

// RevokeOAuthClient deletes a client and all access tokens it issued. An unknown
// client id returns [ErrOAuthClientNotFound], so a repeated DELETE is a clean
// 404. Unlike pre-auth keys (which soft-revoke for node-registration history), an
// OAuth client has no such history and is removed outright, matching Tailscale.
func (hsdb *HSDatabase) RevokeOAuthClient(clientID string) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		err := tx.Where("client_id = ?", clientID).
			Delete(&types.OAuthAccessToken{}).Error
		if err != nil {
			return fmt.Errorf("deleting oauth access tokens: %w", err)
		}

		res := tx.Where("client_id = ?", clientID).Delete(&types.OAuthClient{})
		if res.Error != nil {
			return res.Error
		}

		if res.RowsAffected == 0 {
			return ErrOAuthClientNotFound
		}

		return nil
	})
}

// MintAccessToken stores a new [types.OAuthAccessToken] for clientID with the
// given (already narrowed) scopes/tags and expiration, returning the plaintext
// token (shown ONCE).
func (hsdb *HSDatabase) MintAccessToken(
	clientID string,
	scopes, tags []string,
	expiration *time.Time,
) (string, *types.OAuthAccessToken, error) {
	prefix := rands.HexString(accessTokenPrefixLength)
	secret := rands.HexString(accessTokenSecretLength)
	tokenStr := types.AccessTokenPrefix + prefix + "-" + secret

	hash, err := hashSecret(secret)
	if err != nil {
		return "", nil, err
	}

	now := time.Now().UTC()
	token := types.OAuthAccessToken{
		Prefix:     prefix,
		Hash:       hash,
		ClientID:   clientID,
		Scopes:     scopes,
		Tags:       tags,
		Expiration: expiration,
		CreatedAt:  &now,
	}

	// Mint inside a transaction that re-checks the client still exists and is
	// not revoked, so a mint cannot complete against a client being deleted.
	err = hsdb.Write(func(tx *gorm.DB) error {
		var client types.OAuthClient

		err := tx.First(&client, "client_id = ?", clientID).Error
		if err != nil {
			return ErrOAuthClientNotFound
		}

		if client.Revoked != nil {
			return ErrOAuthClientRevoked
		}

		return tx.Save(&token).Error
	})
	if err != nil {
		return "", nil, fmt.Errorf("saving oauth access token: %w", err)
	}

	return tokenStr, &token, nil
}

// AuthenticateAccessToken validates a presented bearer token and returns the
// matching, unexpired [types.OAuthAccessToken] (carrying its granted scopes and
// tags). A non-nil error means the token is missing, malformed, or expired.
func (hsdb *HSDatabase) AuthenticateAccessToken(tokenStr string) (*types.OAuthAccessToken, error) {
	if tokenStr == "" {
		return nil, ErrAccessTokenFailedToParse
	}

	_, rest, found := strings.Cut(tokenStr, types.AccessTokenPrefix)
	if !found {
		return nil, ErrAccessTokenFailedToParse
	}

	prefix, secret, err := parsePrefixedKey(
		rest,
		accessTokenPrefixLength,
		accessTokenSecretLength,
		ErrAccessTokenFailedToParse,
	)
	if err != nil {
		return nil, err
	}

	var token types.OAuthAccessToken
	if err := hsdb.DB.First(&token, "prefix = ?", prefix).Error; err != nil { //nolint:noinlineerr
		return nil, ErrAccessTokenNotFound
	}

	if err := verifySecret(token.Hash, secret); err != nil { //nolint:noinlineerr
		return nil, fmt.Errorf("invalid oauth access token: %w", err)
	}

	if token.Expiration != nil && token.Expiration.Before(time.Now()) {
		return nil, ErrAccessTokenExpired
	}

	// Bind validity to the issuing client: a token whose client has been
	// revoked or deleted is rejected. This closes a mint/revoke race (where a
	// token could be inserted after the client's tokens were purged) and any
	// orphan left by manual deletion or a future soft-revoke path.
	var client types.OAuthClient
	if err := hsdb.DB.First(&client, "client_id = ?", token.ClientID).Error; err != nil { //nolint:noinlineerr
		return nil, ErrAccessTokenClientRevoked
	}

	if client.Revoked != nil {
		return nil, ErrAccessTokenClientRevoked
	}

	return &token, nil
}

// DeleteExpiredAccessTokens hard-deletes every access token that expired before
// cutoff, returning how many were removed. Auth-time checks already reject
// expired tokens; the hourly reaper (see app.go) calls this only to keep the
// table from growing unbounded.
func (hsdb *HSDatabase) DeleteExpiredAccessTokens(cutoff time.Time) (int64, error) {
	res := hsdb.DB.Where("expiration IS NOT NULL AND expiration < ?", cutoff).
		Delete(&types.OAuthAccessToken{})

	return res.RowsAffected, res.Error
}
