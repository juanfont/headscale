package types

import (
	"time"
)

// Credential kinds. Every authenticatable secret in headscale is stored in the
// single credentials table, discriminated by Kind.
const (
	CredentialAPIKey      = "api"
	CredentialPreAuthKey  = "authkey"
	CredentialOAuthClient = "oauth_client" //nolint:gosec // discriminator value, not a credential
	CredentialOAuthToken  = "oauth_token"  //nolint:gosec // discriminator value, not a credential
)

// Credential is the unified storage model for every authenticatable secret:
// API keys, pre-auth keys, OAuth clients, and OAuth access tokens. Each row is
// discriminated by [Credential.Kind]. The secret is stored only as an Argon2id
// hash (legacy rows may still hold a bcrypt hash until first re-authentication).
// Identifier is the public, indexed lookup value — the 12-char prefix for API
// keys, pre-auth keys and access tokens, and the client id for OAuth clients —
// and is unique within a kind.
//
// Per-kind fields are sparse by design: Reusable/Ephemeral/Used apply to
// pre-auth keys, LastSeen to API keys, Scopes to OAuth credentials, ClientID
// links an OAuth token to its issuing client, and Tags to pre-auth keys and
// OAuth credentials.
type Credential struct {
	ID         uint64 `gorm:"primary_key"`
	Kind       string `gorm:"index:idx_credentials_identifier,unique,priority:1"`
	Identifier string `gorm:"index:idx_credentials_identifier,unique,priority:2"`
	Hash       []byte

	// UserID records the owning or creating user. Kept as a plain column with no
	// foreign key for API/OAuth kinds; pre-auth keys keep the user association.
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

// TableName pins the table name so GORM's naming strategy does not pluralise it
// unexpectedly and so it matches the hand-written migration DDL and schema.sql.
func (*Credential) TableName() string { return "credentials" }
