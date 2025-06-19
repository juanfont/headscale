package types

import (
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PreAuthKey describes a pre-authorization key usable in a particular user.
type PreAuthKey struct {
	ID uint64 `gorm:"primary_key"`

	// Old Key, for backwards compatibility
	Key string

	// Encrypted key
	Prefix string
	Hash   []byte

	Reusable  bool
	Ephemeral bool `gorm:"default:false"`
	Used      bool `gorm:"default:false"`

	// UserID if set, is the owner of the key.
	// If a node is authenticated with this key, the node
	// is assigned to this user.
	UserID *uint `sql:"DEFAULT:NULL"`
	User   *User

	// Tags are always applied to the node and is one of
	// the sources of tags a node might have. They are copied
	// from the PreAuthKey when the node logs in the first time,
	// and ignored after.
	Tags []string `gorm:"column:tags;serializer:json"`

	CreatedAt  *time.Time
	Expiration *time.Time
}

func (key *PreAuthKey) Proto() *v1.PreAuthKey {
	protoKey := v1.PreAuthKey{
		User:      key.User.Proto(),
		Id:        key.ID,
		Key:       key.Key,
		Ephemeral: key.Ephemeral,
		Reusable:  key.Reusable,
		Used:      key.Used,
		AclTags:   key.Tags,
	}

	if key.Expiration != nil {
		protoKey.Expiration = timestamppb.New(*key.Expiration)
	}

	if key.CreatedAt != nil {
		protoKey.CreatedAt = timestamppb.New(*key.CreatedAt)
	}

	return &protoKey
}

// IsTagged reports if a key is tagged.
func (key *PreAuthKey) IsTagged() bool {
	if key.Tags == nil {
		return false
	}

	if len(key.Tags) > 0 {
		return true
	}

	return false
}
