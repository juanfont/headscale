package types

import (
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type PAKError string

func (e PAKError) Error() string { return string(e) }

// PreAuthKey describes a pre-authorization key usable in a particular user.
type PreAuthKey struct {
	ID uint64 `gorm:"primary_key"`

	// Legacy plaintext key (for backwards compatibility)
	Key string

	// New bcrypt-based authentication
	Prefix string
	Hash   []byte // bcrypt

	// For tagged keys: UserID tracks who created the key (informational)
	// For user-owned keys: UserID tracks the node owner
	// Can be nil for system-created tagged keys
	UserID *uint
	User   *User `gorm:"constraint:OnDelete:SET NULL;"`

	Reusable  bool
	Ephemeral bool `gorm:"default:false"`
	Used      bool `gorm:"default:false"`

	// Tags to assign to nodes registered with this key.
	// Tags are copied to the node during registration.
	// If non-empty, this creates tagged nodes (not user-owned).
	Tags []string `gorm:"serializer:json"`

	CreatedAt  *time.Time
	Expiration *time.Time
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

func (key *PreAuthKeyNew) Proto() *v1.PreAuthKey {
	protoKey := v1.PreAuthKey{
		Id:        key.ID,
		Key:       key.Key,
		User:      nil, // Will be set below if not nil
		Reusable:  key.Reusable,
		Ephemeral: key.Ephemeral,
		AclTags:   key.Tags,
	}

	if key.User != nil {
		protoKey.User = key.User.Proto()
	}

	if key.Expiration != nil {
		protoKey.Expiration = timestamppb.New(*key.Expiration)
	}

	if key.CreatedAt != nil {
		protoKey.CreatedAt = timestamppb.New(*key.CreatedAt)
	}

	return &protoKey
}

func (key *PreAuthKey) Proto() *v1.PreAuthKey {
	protoKey := v1.PreAuthKey{
		User:      nil, // Will be set below if not nil
		Id:        key.ID,
		Ephemeral: key.Ephemeral,
		Reusable:  key.Reusable,
		Used:      key.Used,
		AclTags:   key.Tags,
	}

	if key.User != nil {
		protoKey.User = key.User.Proto()
	}

	// For new keys (with prefix/hash), show the prefix so users can identify the key
	// For legacy keys (with plaintext key), show the full key for backwards compatibility
	if key.Prefix != "" {
		protoKey.Key = "hskey-auth-" + key.Prefix + "-***"
	} else if key.Key != "" {
		// Legacy key - show full key for backwards compatibility
		// TODO: Consider hiding this in a future major version
		protoKey.Key = key.Key
	}

	if key.Expiration != nil {
		protoKey.Expiration = timestamppb.New(*key.Expiration)
	}

	if key.CreatedAt != nil {
		protoKey.CreatedAt = timestamppb.New(*key.CreatedAt)
	}

	return &protoKey
}

// Validate checks if a pre auth key can be used.
func (pak *PreAuthKey) Validate() error {
	if pak == nil {
		return PAKError("invalid authkey")
	}

	// Use EmbedObject for safe logging - never log full key
	log.Debug().
		Caller().
		EmbedObject(pak).
		Msg("PreAuthKey.Validate: checking key")

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

// IsTagged returns true if this PreAuthKey creates tagged nodes.
// When a PreAuthKey has tags, nodes registered with it will be tagged nodes.
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

// MarshalZerologObject implements zerolog.LogObjectMarshaler for safe logging.
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
