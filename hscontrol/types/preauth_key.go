package types

import (
	"strconv"
	"time"

	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type PAKError string

func (e PAKError) Error() string { return string(e) }

// StringID returns the key's id as a decimal string, the form the HTTP APIs
// render it as.
func (pak *PreAuthKey) StringID() string {
	if pak == nil {
		return ""
	}

	return strconv.FormatUint(pak.ID, util.Base10)
}

// StringID returns the key's id as a decimal string, the form the HTTP APIs
// render it as.
func (pak *PreAuthKeyNew) StringID() string {
	if pak == nil {
		return ""
	}

	return strconv.FormatUint(pak.ID, util.Base10)
}

// PreAuthKey describes a pre-authorization key usable in a particular user.
type PreAuthKey struct {
	ID uint64 `gorm:"primary_key"`

	// Legacy plaintext key (for backwards compatibility)
	Key string

	// New bcrypt-based authentication
	Prefix string
	Hash   []byte // bcrypt

	// For tagged keys: [PreAuthKey.UserID] tracks who created the key (informational)
	// For user-owned keys: [PreAuthKey.UserID] tracks the node owner
	// Can be nil for system-created tagged keys
	UserID *uint
	User   *User `gorm:"constraint:OnDelete:SET NULL;"`

	// Free-text description, set via the v2 API. Empty for keys created through
	// the v1 API or CLI.
	Description string

	Reusable  bool
	Ephemeral bool `gorm:"default:false"`
	Used      bool `gorm:"default:false"`

	// Tags to assign to nodes registered with this key.
	// Tags are copied to the node during registration.
	// If non-empty, this creates tagged nodes (not user-owned).
	Tags []string `gorm:"serializer:json"`

	CreatedAt  *time.Time
	Expiration *time.Time

	// Revoked is set when the key is revoked through the v2 API (Tailscale's
	// DELETE). A revoked key is invalid but kept retrievable until the
	// background collector reaps it after the configured retention window.
	Revoked *time.Time
}

// PreAuthKeyNew is returned once when the key is created.
type PreAuthKeyNew struct {
	ID         uint64 `gorm:"primary_key"`
	Key        string
	Reusable   bool
	Ephemeral  bool
	Tags       []string
	Expiration *time.Time
	CreatedAt  *time.Time
	User       *User // Can be nil for system-created tagged keys
}

// Validate checks if a pre auth key can be used.
func (pak *PreAuthKey) Validate() error {
	if pak == nil {
		return PAKError("invalid authkey")
	}

	// Use [zerolog.Event.EmbedObject] for safe logging - never log full key
	log.Debug().
		Caller().
		EmbedObject(pak).
		Msg("PreAuthKey.Validate: checking key")

	if pak.Revoked != nil {
		return PAKError("authkey revoked")
	}

	if pak.Expiration != nil && pak.Expiration.Before(time.Now()) {
		return PAKError("authkey expired")
	}

	// we don't need to check if has been used before
	if pak.Reusable {
		return nil
	}

	if pak.Used {
		return PAKError("authkey already used")
	}

	return nil
}

// IsTagged returns true if this [PreAuthKey] creates tagged nodes.
// When a [PreAuthKey] has tags, nodes registered with it will be tagged nodes.
func (pak *PreAuthKey) IsTagged() bool {
	return len(pak.Tags) > 0
}

// maskedPrefix returns the key prefix in masked format for safe logging.
// SECURITY: Never log the full key or hash, only the masked prefix.
func (pak *PreAuthKey) maskedPrefix() string {
	if pak.Prefix != "" {
		return "hskey-auth-" + pak.Prefix + "-***"
	}

	return ""
}

// MarshalZerologObject implements [zerolog.LogObjectMarshaler] for safe logging.
// SECURITY: This method intentionally does NOT log the full key or hash.
// Only the masked prefix is logged for identification purposes.
func (pak *PreAuthKey) MarshalZerologObject(e *zerolog.Event) {
	if pak == nil {
		return
	}

	e.Uint64(zf.PAKID, pak.ID)
	e.Bool(zf.PAKReusable, pak.Reusable)
	e.Bool(zf.PAKEphemeral, pak.Ephemeral)
	e.Bool(zf.PAKUsed, pak.Used)
	e.Bool(zf.PAKIsTagged, pak.IsTagged())

	// SECURITY: Only log masked prefix, never full key or hash
	if masked := pak.maskedPrefix(); masked != "" {
		e.Str(zf.PAKPrefix, masked)
	}

	if len(pak.Tags) > 0 {
		e.Strs(zf.PAKTags, pak.Tags)
	}

	if pak.User != nil {
		e.Str(zf.UserName, pak.User.Username())
	}

	if pak.Expiration != nil {
		e.Time(zf.PAKExpiration, *pak.Expiration)
	}
}
