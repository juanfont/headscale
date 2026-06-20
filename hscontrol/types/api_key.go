package types

import (
	"time"

	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog"
)

// NewAPIKeyPrefixLength is the length of the prefix for new API keys.
const NewAPIKeyPrefixLength = 12

// APIKey describes the datamodel for API keys used to remotely authenticate with
// headscale.
type APIKey struct {
	ID     uint64 `gorm:"primary_key"`
	Prefix string `gorm:"uniqueIndex"`
	Hash   []byte

	// Optional owning user id. When set, an auth key created through the v2 API
	// with no tags is owned by this user — mirroring Tailscale, where a key is
	// owned by the identity that created it. Nil for legacy/admin keys, which
	// can only create tagged keys. Kept as a plain column (no foreign key) so an
	// upgraded database matches a freshly-migrated one.
	UserID *uint

	CreatedAt  *time.Time
	Expiration *time.Time
	LastSeen   *time.Time
}

// maskedPrefix returns the API key prefix in masked format for safe logging.
// SECURITY: Never log the full key or hash, only the masked prefix.
func (k *APIKey) maskedPrefix() string {
	if len(k.Prefix) == NewAPIKeyPrefixLength {
		return "hskey-api-" + k.Prefix + "-***"
	}

	return k.Prefix + "***"
}

// MarshalZerologObject implements [zerolog.LogObjectMarshaler] for safe logging.
// SECURITY: This method intentionally does NOT log the full key or hash.
// Only the masked prefix is logged for identification purposes.
func (k *APIKey) MarshalZerologObject(e *zerolog.Event) {
	if k == nil {
		return
	}

	e.Uint64(zf.APIKeyID, k.ID)
	e.Str(zf.APIKeyPrefix, k.maskedPrefix())

	if k.Expiration != nil {
		e.Time(zf.APIKeyExpiration, *k.Expiration)
	}

	if k.LastSeen != nil {
		e.Time(zf.APIKeyLastSeen, *k.LastSeen)
	}
}
