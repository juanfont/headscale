package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
)

// revokedNow is the time a revoke stores: in UTC, because SQLite compares
// stored times as text and the removal compares them with its cutoff; and
// to the microsecond, which PostgreSQL keeps, so every database answers the
// same time.
func revokedNow() time.Time {
	return time.Now().UTC().Truncate(time.Microsecond)
}

// revokeCredential ends the credential of kind that cond matches, every kind
// alike: it is refused from now on, and its record stays, revoked, until
// [HSDatabase.DestroyRevokedCredentialsBefore] removes it. A credential that is
// revoked already keeps its first time, so a repeated revoke changes nothing.
// No match is notFound.
func revokeCredential(tx *gorm.DB, kind types.CredentialKind, cond string, arg any, notFound error) error {
	res := tx.Model(&types.Credential{}).Where("kind = ?", kind).Where(cond, arg).
		Update("revoked", gorm.Expr("COALESCE(revoked, ?)", revokedNow()))
	if res.Error != nil {
		return res.Error
	}

	if res.RowsAffected == 0 {
		return notFound
	}

	return nil
}

// DestroyRevokedCredentialsBefore removes every credential revoked before
// cutoff, of every kind, and returns how many. An auth key that a node refers
// to is kept until that node is deleted, so the node's auth key stays valid.
func (hsdb *HSDatabase) DestroyRevokedCredentialsBefore(cutoff time.Time) (int64, error) {
	res := hsdb.DB.Where("revoked IS NOT NULL AND revoked < ?", cutoff.UTC()).
		Where("id NOT IN (SELECT auth_key_id FROM nodes WHERE auth_key_id IS NOT NULL)").
		Delete(&types.Credential{})

	return res.RowsAffected, res.Error
}

// credentialToAPIKey projects a unified credentials row onto the [types.APIKey]
// shape the API, state, and CLI layers consume.
func credentialToAPIKey(c *types.Credential) *types.APIKey {
	return &types.APIKey{
		ID:         c.ID,
		Prefix:     c.Identifier,
		Hash:       c.Hash,
		UserID:     c.UserID,
		CreatedAt:  c.CreatedAt,
		Expiration: c.Expiration,
		LastSeen:   c.LastSeen,
	}
}

// OAuthClientFromCredential projects a unified credentials row onto the
// [types.OAuthClient] shape. The client id is stored as the row's identifier.
func OAuthClientFromCredential(c *types.Credential) *types.OAuthClient {
	return &types.OAuthClient{
		ID:          c.ID,
		ClientID:    c.Identifier,
		SecretHash:  c.Hash,
		Scopes:      c.Scopes,
		Tags:        c.Tags,
		Description: c.Description,
		UserID:      c.UserID,
		CreatedAt:   c.CreatedAt,
		Revoked:     c.Revoked,
	}
}

// credentialToPreAuthKey projects a unified credentials row onto the
// [types.PreAuthKey] shape. The lookup prefix is stored as the row's identifier;
// the User association is carried through when preloaded.
func credentialToPreAuthKey(c *types.Credential) *types.PreAuthKey {
	return &types.PreAuthKey{
		ID:              c.ID,
		Prefix:          c.Identifier,
		Hash:            c.Hash,
		UserID:          c.UserID,
		User:            c.User,
		Description:     c.Description,
		Reusable:        c.Reusable,
		Ephemeral:       c.Ephemeral,
		Used:            c.Used,
		Tags:            c.Tags,
		CreatedByToken:  c.CreatedByToken,
		CreatedByUserID: c.CreatedByUserID,
		FirstUsed:       c.FirstUsed,
		CreatedAt:       c.CreatedAt,
		Expiration:      c.Expiration,
		Revoked:         c.Revoked,
	}
}

// credentialToOAuthAccessToken projects a unified credentials row onto the
// [types.OAuthAccessToken] shape. The token's lookup prefix is stored as the
// row's identifier; ClientID links back to the issuing client's identifier.
func credentialToOAuthAccessToken(c *types.Credential) *types.OAuthAccessToken {
	return &types.OAuthAccessToken{
		ID:         c.ID,
		Prefix:     c.Identifier,
		Hash:       c.Hash,
		ClientID:   c.ClientID,
		Scopes:     c.Scopes,
		Tags:       c.Tags,
		Expiration: c.Expiration,
		CreatedAt:  c.CreatedAt,
	}
}

// ErrCredentialEnded is a write refused because the credential that asked
// for it was revoked, or removed, after the request was authenticated.
var ErrCredentialEnded = errors.New("the credential of the request ended")

// holdCredential is the last check of a write that the credential with id
// asks for, made in the write's transaction; id 0 is no credential (the unix
// socket, or an API that does not say). A revoked API key, and an access
// token whose client is revoked or which its client's revoke deleted, refuse
// the write. Each UPDATE locks its row, so a revoke that committed is seen,
// and one that has not waits for this write and answers after it: no
// credential is made by a credential whose revoke answered before. A token's
// client is locked before the token, in the order of [revokeOAuthClient] and
// [HSDatabase.MintAccessToken], so they cannot wait on each other.
func holdCredential(tx *gorm.DB, id uint64) error {
	if id == 0 {
		return nil
	}

	var maker types.Credential

	err := tx.Select("kind", "client_id").Take(&maker, "id = ?", id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrCredentialEnded
	}

	if err != nil {
		return fmt.Errorf("holding credential %d: %w", id, err)
	}

	if maker.Kind == types.CredentialOAuthToken {
		err = holdRow(tx, "kind = ? AND identifier = ?", types.CredentialOAuthClient, maker.ClientID)
		if err != nil {
			return err
		}
	}

	return holdRow(tx, "id = ?", id)
}

// holdRow locks the credential that cond matches while it is not revoked, or
// returns [ErrCredentialEnded].
func holdRow(tx *gorm.DB, cond string, args ...any) error {
	res := tx.Model(&types.Credential{}).Where(cond, args...).Where("revoked IS NULL").
		Update("revoked", gorm.Expr("revoked"))
	if res.Error != nil {
		return fmt.Errorf("holding credential: %w", res.Error)
	}

	if res.RowsAffected == 0 {
		return ErrCredentialEnded
	}

	return nil
}

// listCredentialsPage is up to limit credentials of kind with an ID above
// after, in ID order, revoked ones too, with their user; where narrows them
// in SQL. The read ends with ctx.
func (hsdb *HSDatabase) listCredentialsPage(
	ctx context.Context,
	kind types.CredentialKind,
	after uint64,
	limit int,
	where func(*gorm.DB) *gorm.DB,
) ([]types.Credential, error) {
	return Read(hsdb.DB.WithContext(ctx), func(rx *gorm.DB) ([]types.Credential, error) {
		return pageCredentials(rx, kind, after, limit, where, func(*types.Credential) bool { return true })
	})
}

// getCredential is the credential of kind that cond matches, revoked or not,
// with its user; none is notFound.
func getCredential(rx *gorm.DB, kind types.CredentialKind, cond string, arg any, notFound error) (*types.Credential, error) {
	var c types.Credential

	err := rx.Preload("User").Where("kind = ?", kind).Where(cond, arg).First(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, notFound
	}

	if err != nil {
		return nil, err
	}

	return &c, nil
}
