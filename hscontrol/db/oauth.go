package db

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
	"tailscale.com/util/multierr"
	"tailscale.com/util/set"
)

var (
	ErrOAuthClientNotFound      = fmt.Errorf("oauth client not found: %w", gorm.ErrRecordNotFound)
	ErrOAuthClientFailedToParse = errors.New("failed to parse oauth client secret")
	ErrOAuthClientRevoked       = errors.New("oauth client revoked")
	ErrOAuthClientScopeInvalid  = errors.New("oauth client scope invalid")

	ErrAccessTokenNotFound      = fmt.Errorf("oauth access token not found: %w", gorm.ErrRecordNotFound)
	ErrAccessTokenFailedToParse = errors.New("failed to parse oauth access token")
	ErrAccessTokenExpired       = errors.New("oauth access token expired")
	ErrAccessTokenClientRevoked = errors.New("oauth access token issuing client revoked or deleted")
)

// validateScopes rejects any value outside the vocabulary in [scope.Known]. An
// unknown scope satisfies no requirement, so storing one would silently mint a
// client with fewer permissions than asked for. Every offending scope is
// reported so the caller can correct them all in one pass.
func validateScopes(scopes []string) error {
	var errs []error

	for _, s := range scopes {
		if !scope.Scope(s).Valid() {
			errs = append(errs, fmt.Errorf("%w: %q", ErrOAuthClientScopeInvalid, s))
		}
	}

	return multierr.New(errs...)
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

	err = validateScopes(scopes)
	if err != nil {
		return "", nil, err
	}

	scopes = set.SetOf(scopes).Slice()
	slices.Sort(scopes)

	secretStr, clientID, hash := generateSecret(types.OAuthClientPrefix)

	now := time.Now().UTC()
	cred := types.Credential{
		Kind:        types.CredentialOAuthClient,
		Identifier:  clientID,
		Hash:        hash,
		Scopes:      scopes,
		Tags:        tags,
		Description: description,
		UserID:      creatorUserID,
		CreatedAt:   &now,
	}

	err = hsdb.Write(func(tx *gorm.DB) error {
		return tx.Save(&cred).Error
	})
	if err != nil {
		return "", nil, fmt.Errorf("saving oauth client: %w", err)
	}

	return secretStr, credentialToOAuthClient(&cred), nil
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

	// See [types.TailscaleOAuthClientPrefix] for why the alias is accepted.
	rest, found := strings.CutPrefix(secretStr, types.OAuthClientPrefix)
	if !found {
		rest, found = strings.CutPrefix(secretStr, types.TailscaleOAuthClientPrefix)
	}

	if !found {
		return nil, ErrOAuthClientFailedToParse
	}

	clientID, secret, err := parsePrefixedKey(rest, ErrOAuthClientFailedToParse)
	if err != nil {
		return nil, err
	}

	cred, err := authenticateCredential(
		hsdb.DB, types.CredentialOAuthClient, clientID, secret, ErrOAuthClientNotFound,
	)
	if err != nil {
		return nil, err
	}

	if cred.Revoked != nil {
		return nil, ErrOAuthClientRevoked
	}

	return credentialToOAuthClient(cred), nil
}

// GetOAuthClientByClientID returns a [types.OAuthClient] by its public client id.
func (hsdb *HSDatabase) GetOAuthClientByClientID(clientID string) (*types.OAuthClient, error) {
	var cred types.Credential
	if result := hsdb.DB.First(&cred, "kind = ? AND identifier = ?", types.CredentialOAuthClient, clientID); result.Error != nil {
		return nil, result.Error
	}

	return credentialToOAuthClient(&cred), nil
}

// ListOAuthClients returns every [types.OAuthClient].
func (hsdb *HSDatabase) ListOAuthClients() ([]types.OAuthClient, error) {
	var creds []types.Credential

	err := hsdb.DB.Where("kind = ?", types.CredentialOAuthClient).Find(&creds).Error
	if err != nil {
		return nil, err
	}

	clients := make([]types.OAuthClient, 0, len(creds))
	for i := range creds {
		clients = append(clients, *credentialToOAuthClient(&creds[i]))
	}

	return clients, nil
}

// RevokeOAuthClient deletes a client and all access tokens it issued. An unknown
// client id returns [ErrOAuthClientNotFound], so a repeated DELETE is a clean
// 404. Unlike pre-auth keys (which soft-revoke for node-registration history), an
// OAuth client has no such history and is removed outright, matching Tailscale.
func (hsdb *HSDatabase) RevokeOAuthClient(clientID string) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		err := tx.Where("kind = ? AND client_id = ?", types.CredentialOAuthToken, clientID).
			Delete(&types.Credential{}).Error
		if err != nil {
			return fmt.Errorf("deleting oauth access tokens: %w", err)
		}

		res := tx.Where("kind = ? AND identifier = ?", types.CredentialOAuthClient, clientID).
			Delete(&types.Credential{})
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
	tokenStr, prefix, hash := generateSecret(types.AccessTokenPrefix)

	now := time.Now().UTC()
	cred := types.Credential{
		Kind:       types.CredentialOAuthToken,
		Identifier: prefix,
		Hash:       hash,
		ClientID:   clientID,
		Scopes:     scopes,
		Tags:       tags,
		Expiration: expiration,
		CreatedAt:  &now,
	}

	// Mint inside a transaction that re-checks the client still exists and is
	// not revoked, so a mint cannot complete against a client being deleted.
	err := hsdb.Write(func(tx *gorm.DB) error {
		var client types.Credential

		err := tx.First(&client, "kind = ? AND identifier = ?", types.CredentialOAuthClient, clientID).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrOAuthClientNotFound
		}

		if err != nil {
			return err
		}

		if client.Revoked != nil {
			return ErrOAuthClientRevoked
		}

		return tx.Save(&cred).Error
	})
	if err != nil {
		return "", nil, fmt.Errorf("saving oauth access token: %w", err)
	}

	return tokenStr, credentialToOAuthAccessToken(&cred), nil
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

	prefix, secret, err := parsePrefixedKey(rest, ErrAccessTokenFailedToParse)
	if err != nil {
		return nil, err
	}

	token, err := authenticateCredential(
		hsdb.DB, types.CredentialOAuthToken, prefix, secret, ErrAccessTokenNotFound,
	)
	if err != nil {
		return nil, err
	}

	if token.Expiration != nil && token.Expiration.Before(time.Now()) {
		return nil, ErrAccessTokenExpired
	}

	// Bind validity to the issuing client: a token whose client has been
	// revoked or deleted is rejected. This closes a mint/revoke race (where a
	// token could be inserted after the client's tokens were purged) and any
	// orphan left by manual deletion or a future soft-revoke path.
	var client types.Credential

	err = hsdb.DB.First(&client, "kind = ? AND identifier = ?", types.CredentialOAuthClient, token.ClientID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) || (err == nil && client.Revoked != nil) {
		return nil, ErrAccessTokenClientRevoked
	}

	if err != nil {
		return nil, fmt.Errorf("looking up issuing oauth client: %w", err)
	}

	return credentialToOAuthAccessToken(token), nil
}

// DeleteExpiredAccessTokens hard-deletes every access token that expired before
// cutoff, returning how many were removed. Auth-time checks already reject
// expired tokens; the hourly reaper (see app.go) calls this only to keep the
// table from growing unbounded.
func (hsdb *HSDatabase) DeleteExpiredAccessTokens(cutoff time.Time) (int64, error) {
	res := hsdb.DB.Where("kind = ? AND expiration IS NOT NULL AND expiration < ?", types.CredentialOAuthToken, cutoff).
		Delete(&types.Credential{})

	return res.RowsAffected, res.Error
}
