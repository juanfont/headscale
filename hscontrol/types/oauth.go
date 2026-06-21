package types

import (
	"time"

	"github.com/rs/zerolog"
)

const (
	// OAuthClientPrefix prefixes an OAuth client secret:
	// hskey-client-<clientID>-<secret>.
	OAuthClientPrefix = "hskey-client-" //nolint:gosec // prefix, not a credential

	// AccessTokenPrefix prefixes an OAuth access token:
	// hskey-oauthtok-<prefix>-<secret>. The v2 auth middleware dispatches a
	// scope-limited token from an all-access admin key on this prefix alone, so
	// it is one canonical constant shared by the db and api layers.
	AccessTokenPrefix = "hskey-oauthtok-" //nolint:gosec // prefix, not a credential
)

// OAuthClient is a long-lived OAuth 2.0 client-credentials principal. It mints
// short-lived [OAuthAccessToken]s limited to its Scopes and Tags. The secret is
// stored only as an Argon2id hash. ClientID is public and embedded in the secret
// string (hskey-client-<ClientID>-<secret>) so the token endpoint can derive it
// from the secret alone, matching Tailscale, where the client id is a substring
// of the client secret.
//
// An OAuth client is always tag/tailnet-scoped, never user-owned: the access
// tokens it mints, and the auth keys those tokens create, produce tagged nodes.
// UserID only records who created the client (informational), mirroring
// [APIKey].
type OAuthClient struct {
	ID         uint64 `gorm:"primary_key"`
	ClientID   string `gorm:"uniqueIndex"`
	SecretHash []byte

	// Scopes the client may grant. Tags the client may assign to access tokens
	// (and, transitively, to the auth keys and nodes those tokens create).
	Scopes []string `gorm:"serializer:json"`
	Tags   []string `gorm:"serializer:json"`

	Description string

	// UserID records who created the client. Kept as a plain column with no
	// foreign key so an upgraded database matches a freshly-migrated one.
	UserID *uint

	CreatedAt *time.Time
	Revoked   *time.Time
}

// TableName pins the table name. GORM's naming strategy would otherwise render
// OAuthClient as "o_auth_clients" (it breaks the OAuth initialism), diverging
// from the hand-written migration DDL and schema.sql.
func (*OAuthClient) TableName() string { return "oauth_clients" }

// OAuthAccessToken is a short-lived bearer token minted by an [OAuthClient] via
// the client-credentials grant. It carries the scope/tag set granted at mint
// time (a subset of the issuing client's), is stored as an Argon2id hash of its
// secret, and authenticates v2 API requests as Authorization: Bearer.
type OAuthAccessToken struct {
	ID     uint64 `gorm:"primary_key"`
	Prefix string `gorm:"uniqueIndex"`
	Hash   []byte

	// ClientID links back to the issuing [OAuthClient].
	ClientID string

	Scopes []string `gorm:"serializer:json"`
	Tags   []string `gorm:"serializer:json"`

	Expiration *time.Time
	CreatedAt  *time.Time
}

// TableName pins the table name (see [OAuthClient.TableName]).
func (*OAuthAccessToken) TableName() string { return "oauth_access_tokens" }

// maskedClientID returns the client id in masked form for safe logging.
// SECURITY: never log the secret or its hash.
func (c *OAuthClient) maskedClientID() string {
	if c.ClientID != "" {
		return OAuthClientPrefix + c.ClientID + "-***"
	}

	return ""
}

// MarshalZerologObject implements [zerolog.LogObjectMarshaler] for safe logging.
// SECURITY: intentionally does NOT log the secret or hash.
func (c *OAuthClient) MarshalZerologObject(e *zerolog.Event) {
	if c == nil {
		return
	}

	e.Uint64("oauth_client_id", c.ID)

	if masked := c.maskedClientID(); masked != "" {
		e.Str("oauth_client", masked)
	}

	if len(c.Scopes) > 0 {
		e.Strs("oauth_client_scopes", c.Scopes)
	}

	if len(c.Tags) > 0 {
		e.Strs("oauth_client_tags", c.Tags)
	}

	if c.Revoked != nil {
		e.Time("oauth_client_revoked", *c.Revoked)
	}
}

// maskedPrefix returns the token prefix in masked form for safe logging.
// SECURITY: never log the secret or its hash.
func (t *OAuthAccessToken) maskedPrefix() string {
	if t.Prefix != "" {
		return AccessTokenPrefix + t.Prefix + "-***"
	}

	return ""
}

// MarshalZerologObject implements [zerolog.LogObjectMarshaler] for safe logging.
// SECURITY: intentionally does NOT log the secret or hash.
func (t *OAuthAccessToken) MarshalZerologObject(e *zerolog.Event) {
	if t == nil {
		return
	}

	e.Uint64("oauth_token_id", t.ID)

	if masked := t.maskedPrefix(); masked != "" {
		e.Str("oauth_token", masked)
	}

	if t.ClientID != "" {
		e.Str("oauth_token_client", t.ClientID)
	}

	if len(t.Scopes) > 0 {
		e.Strs("oauth_token_scopes", t.Scopes)
	}

	if len(t.Tags) > 0 {
		e.Strs("oauth_token_tags", t.Tags)
	}

	if t.Expiration != nil {
		e.Time("oauth_token_expiration", *t.Expiration)
	}
}
