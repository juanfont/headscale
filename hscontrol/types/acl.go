package types

import (
	"encoding/json"
	"errors"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"gorm.io/datatypes"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

var (
	ErrACLPolicyNotFound         = errors.New("acl policy not found")
	ErrInvalidACLPolicyFormat    = errors.New("invalid policy format")
	ErrACLPolicyUpdateIsDisabled = errors.New("update is disabled for modes other than 'db'")
)

// ACL describes the data model for ACLs used to restrict access to resources.
type ACL struct {
	ID     uint64 `gorm:"primary_key"`
	Policy datatypes.JSON

	CreatedAt  *time.Time
	Expiration *time.Time
	LastSeen   *time.Time
}

func (a *ACL) Proto() *v1.ACL {
	var p map[string]any

	if err := json.Unmarshal(a.Policy, &p); err != nil {
		return nil
	}

	polPb, err := structpb.NewStruct(p)
	if err != nil {
		return nil
	}

	return &v1.ACL{
		Policy: polPb,
	}
}
