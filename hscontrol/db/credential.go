package db

import (
	"github.com/juanfont/headscale/hscontrol/types"
)

// credentialToAPIKey projects a unified credentials row onto the [types.APIKey]
// shape the API, state, and CLI layers still consume.
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
		ID:          c.ID,
		Prefix:      c.Identifier,
		Hash:        c.Hash,
		UserID:      c.UserID,
		User:        c.User,
		Description: c.Description,
		Reusable:    c.Reusable,
		Ephemeral:   c.Ephemeral,
		Used:        c.Used,
		Tags:        c.Tags,
		CreatedAt:   c.CreatedAt,
		Expiration:  c.Expiration,
		Revoked:     c.Revoked,
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
