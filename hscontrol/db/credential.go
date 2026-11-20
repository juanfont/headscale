package db

import (
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

// credentialToOAuthClient projects a unified credentials row onto the
// [types.OAuthClient] shape. The client id is stored as the row's identifier.
func credentialToOAuthClient(c *types.Credential) *types.OAuthClient {
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
