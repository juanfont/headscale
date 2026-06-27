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
