package types

import (
	"strconv"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PreAuthKey describes a pre-authorization key usable in a particular user.
type PreAuthKey struct {
	ID        uint64 `gorm:"primary_key"`
	Key       string
	UserID    uint
	User      User `gorm:"constraint:OnDelete:CASCADE;"`
	Reusable  bool
	Ephemeral bool     `gorm:"default:false"`
	Used      bool     `gorm:"default:false"`
	Tags      []string `gorm:"serializer:json"`

	CreatedAt  *time.Time
	Expiration *time.Time
}

func (key *PreAuthKey) Proto() *v1.PreAuthKey {
	protoKey := v1.PreAuthKey{
		User:      key.User.Username(),
		Id:        strconv.FormatUint(key.ID, util.Base10),
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
