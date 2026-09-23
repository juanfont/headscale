package types

import (
	"time"
)

// CredentialKind discriminates rows of the credentials table.
type CredentialKind string

const (
	CredentialAPIKey      CredentialKind = "api"
	CredentialPreAuthKey  CredentialKind = "authkey"
	CredentialOAuthClient CredentialKind = "oauth_client" //nolint:gosec // discriminator value, not a credential
	CredentialOAuthToken  CredentialKind = "oauth_token"  //nolint:gosec // discriminator value, not a credential
)

// Credential is the unified storage model for every authenticatable secret:
// API keys, pre-auth keys, OAuth clients, and OAuth access tokens. Each row is
// discriminated by [Credential.Kind]. Only a hash of the secret is stored:
// SHA-256, or a legacy bcrypt/Argon2id hash until the next authentication.
// Identifier is the public, indexed lookup value — the 12-char prefix for API
// keys, pre-auth keys and access tokens, and the client id for OAuth clients —
// and is unique within a kind.
//
// Per-kind fields are sparse by design: Reusable/Ephemeral/Used apply to
// pre-auth keys, LastSeen to API keys, Scopes to OAuth credentials, ClientID
// links an OAuth token to its issuing client, and Tags to pre-auth keys and
// OAuth credentials.
type Credential struct {
	ID         uint64         `gorm:"primary_key"`
	Kind       CredentialKind `gorm:"not null;index:idx_credentials_identifier,unique,priority:1"`
	Identifier string         `gorm:"index:idx_credentials_identifier,unique,priority:2"`
	Hash       []byte

	// UserID records the owning (user-owned pre-auth key, API key) or creating
	// (tagged pre-auth key, OAuth client) user. Deleting the user nulls it.
	UserID *uint
	User   *User `gorm:"constraint:OnDelete:SET NULL;"`

	Description string

	Scopes []string `gorm:"serializer:json"`
	Tags   []string `gorm:"serializer:json"`

	Reusable  bool
	Ephemeral bool `gorm:"default:false"`
	Used      bool `gorm:"default:false"`

	LastSeen *time.Time

	// ClientID links an OAuth access token (Kind == CredentialOAuthToken) back to
	// the Identifier of its issuing OAuth client.
	ClientID string

	CreatedAt  *time.Time
	Expiration *time.Time
	Revoked    *time.Time
}

// IsTagged reports whether this credential carries tags. For a pre-auth key
// credential, a node registered with it becomes a tagged node.
func (c *Credential) IsTagged() bool {
	return len(c.Tags) > 0
}

// AsCredential projects a pre-auth key back onto a [Credential] (kind
// authkey), used to set a node's AuthKey association during registration from a
// pre-auth key projection.
func (pak *PreAuthKey) AsCredential() *Credential {
	if pak == nil {
		return nil
	}

	return &Credential{
		ID:          pak.ID,
		Kind:        CredentialPreAuthKey,
		Identifier:  pak.Prefix,
		Hash:        pak.Hash,
		UserID:      pak.UserID,
		User:        pak.User,
		Description: pak.Description,
		Reusable:    pak.Reusable,
		Ephemeral:   pak.Ephemeral,
		Used:        pak.Used,
		Tags:        pak.Tags,
		CreatedAt:   pak.CreatedAt,
		Expiration:  pak.Expiration,
		Revoked:     pak.Revoked,
	}
}
