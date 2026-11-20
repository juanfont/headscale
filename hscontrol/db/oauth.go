package db

import (
	"context"
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

// maxAccessTokensPerClient bounds the access tokens kept for one OAuth client.
// Minting needs only the client secret, whatever its scopes, so each mint ends
// the client's tokens beyond the newest this many.
const maxAccessTokensPerClient = 1000

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

// NewOAuthClient is what an OAuth client is made from.
type NewOAuthClient struct {
	Scopes, Tags []string
	Description  string
	// CreatedBy is the user who made the client (informational), or nil.
	CreatedBy *types.UserID
	// Created is when the client was made; zero is now.
	Created time.Time
	// Maker is the credential that asks for the client; see [holdCredential].
	Maker uint64
}

// CreateOAuthClient creates a new [types.OAuthClient] and returns the plaintext
// secret (shown ONCE) alongside the stored client. creatorUserID is the user who
// created it (informational), or nil.
func (hsdb *HSDatabase) CreateOAuthClient(
	scopes, tags []string,
	description string,
	creatorUserID *uint,
) (string, *types.OAuthClient, error) {
	c := NewOAuthClient{Scopes: scopes, Tags: tags, Description: description}
	if creatorUserID != nil {
		c.CreatedBy = new(types.UserID(*creatorUserID))
	}

	made, err := Write(hsdb.DB, func(tx *gorm.DB) (createdOAuthClient, error) {
		cred, secret, err := CreateOAuthClientFrom(tx, c)

		return createdOAuthClient{cred, secret}, err
	})
	if err != nil {
		return "", nil, err
	}

	return made.secret, OAuthClientFromCredential(made.cred), nil
}

type createdOAuthClient struct {
	cred   *types.Credential
	secret string
}

// CreateOAuthClientFrom makes the client c describes: its tags spelled as
// tags and its scopes known, each folded and sorted. It returns the client as
// stored, with its maker, and once its secret.
func CreateOAuthClientFrom(tx *gorm.DB, c NewOAuthClient) (*types.Credential, string, error) {
	tags, err := validateACLTags(c.Tags)
	if err != nil {
		return nil, "", err
	}

	err = validateScopes(c.Scopes)
	if err != nil {
		return nil, "", err
	}

	var maker *types.User

	// A maker deleted while the request ran leaves createdBy null, as its
	// delete does to every client it made. The user before the credential
	// that asks, as a delete of the user locks them.
	if c.CreatedBy != nil {
		maker, err = holdUser(tx, *c.CreatedBy)
		if errors.Is(err, ErrUserNotFound) {
			maker, err = nil, nil
		}

		if err != nil {
			return nil, "", err
		}
	}

	err = holdCredential(tx, c.Maker)
	if err != nil {
		return nil, "", err
	}

	scopes := set.SetOf(c.Scopes).Slice()
	slices.Sort(scopes)

	secretStr, clientID, hash := generateSecret(types.OAuthClientPrefix)

	now := c.Created
	if now.IsZero() {
		now = time.Now().UTC()
	}

	cred := types.Credential{
		Kind:        types.CredentialOAuthClient,
		Identifier:  clientID,
		Hash:        hash,
		Scopes:      scopes,
		Tags:        tags,
		Description: c.Description,
		CreatedAt:   &now,
	}

	if maker != nil {
		cred.UserID = &maker.ID
	}

	err = tx.Create(&cred).Error
	if err != nil {
		return nil, "", fmt.Errorf("saving oauth client: %w", err)
	}

	cred.User = maker

	return &cred, secretStr, nil
}

// ListOAuthClientsPage is up to limit OAuth clients made after the one with
// the row ID after, in the order they were made, revoked ones too.
func (hsdb *HSDatabase) ListOAuthClientsPage(ctx context.Context, after uint64, limit int) ([]types.Credential, error) {
	return hsdb.listCredentialsPage(ctx, types.CredentialOAuthClient, after, limit, func(q *gorm.DB) *gorm.DB { return q })
}

// GetOAuthClientCredential is the OAuth client with clientID, revoked or not,
// with its maker.
func (hsdb *HSDatabase) GetOAuthClientCredential(clientID string) (*types.Credential, error) {
	return hsdb.getCredential(types.CredentialOAuthClient, "identifier = ?", clientID, ErrOAuthClientNotFound)
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

	return OAuthClientFromCredential(cred), nil
}

// GetOAuthClientByClientID returns a [types.OAuthClient] by its public client id.
func (hsdb *HSDatabase) GetOAuthClientByClientID(clientID string) (*types.OAuthClient, error) {
	var cred types.Credential
	if result := hsdb.DB.First(&cred, "kind = ? AND identifier = ?", types.CredentialOAuthClient, clientID); result.Error != nil {
		return nil, result.Error
	}

	return OAuthClientFromCredential(&cred), nil
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
		clients = append(clients, *OAuthClientFromCredential(&creds[i]))
	}

	return clients, nil
}

// RevokeOAuthClient soft-revokes a client, as Tailscale's DELETE does: the row
// stays retrievable with its invalid flag set, and the access tokens it issued
// are deleted in the same transaction, so none of them authenticates after the
// revoke answers. See [revokeCredential]; an unknown client id returns
// [ErrOAuthClientNotFound].
func (hsdb *HSDatabase) RevokeOAuthClient(clientID string) error {
	return hsdb.Write(func(tx *gorm.DB) error { return revokeOAuthClient(tx, clientID) })
}

// revokeOAuthClient is [HSDatabase.RevokeOAuthClient] in tx. The client's row
// is locked first, then its tokens', the order of every write that holds a
// client and a token.
func revokeOAuthClient(tx *gorm.DB, clientID string) error {
	err := revokeCredential(tx, types.CredentialOAuthClient, "identifier = ?", clientID, ErrOAuthClientNotFound)
	if err != nil {
		return err
	}

	err = tx.Where("kind = ? AND client_id = ?", types.CredentialOAuthToken, clientID).
		Delete(&types.Credential{}).Error
	if err != nil {
		return fmt.Errorf("deleting oauth access tokens: %w", err)
	}

	return nil
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

	scopes = set.SetOf(scopes).Slice()
	slices.Sort(scopes)

	tags = set.SetOf(tags).Slice()
	slices.Sort(tags)

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

	// The mint locks the client's row while it is not revoked: a revoke that
	// is open holds the mint until it commits, and the mint then refuses, so
	// no token is minted after the revoke answered.
	err := hsdb.Write(func(tx *gorm.DB) error {
		err := holdRow(tx, "kind = ? AND identifier = ?", types.CredentialOAuthClient, clientID)
		if errors.Is(err, ErrCredentialEnded) {
			var n int64

			err = tx.Model(&types.Credential{}).
				Where("kind = ? AND identifier = ?", types.CredentialOAuthClient, clientID).Count(&n).Error
			if err != nil {
				return err
			}

			if n == 0 {
				return ErrOAuthClientNotFound
			}

			return ErrOAuthClientRevoked
		}

		if err != nil {
			return err
		}

		err = tx.Save(&cred).Error
		if err != nil {
			return err
		}

		// Under the limit the subquery is NULL and nothing is deleted.
		newestSurplus := tx.Model(&types.Credential{}).Select("id").
			Where("kind = ? AND client_id = ?", types.CredentialOAuthToken, clientID).
			Order("id DESC").Limit(1).Offset(maxAccessTokensPerClient)

		return tx.Where("kind = ? AND client_id = ? AND id <= (?)",
			types.CredentialOAuthToken, clientID, newestSurplus).
			Delete(&types.Credential{}).Error
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

	rest, found := strings.CutPrefix(tokenStr, types.AccessTokenPrefix)
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
		return nil, fmt.Errorf("looking up issuing oauth client: %w: %w", ErrCredentialStore, err)
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
