//go:generate go run ../../../tools/changegen change.go
package change

import (
	"errors"

	"github.com/juanfont/headscale/hscontrol/types"
)

type NodeID = types.NodeID
type UserID = types.UserID

type Change int

const (
	ChangeUnknown Change = 0

	// Deprecated: Use specific change instead
	// Full is a legacy change to ensure places where we
	// have not yet determined the specific update, can send.
	Full Change = 9

	// Server changes
	Policy       Change = 11
	DERP         Change = 12
	ExtraRecords Change = 13

	// Node changes
	NodeCameOnline  Change = 21
	NodeWentOffline Change = 22
	NodeRemove      Change = 23
	NodeKeyExpiry   Change = 24
	NodeNewOrUpdate Change = 25

	// User changes
	UserNewOrUpdate Change = 51
	UserRemove      Change = 52
)

type ChangeSet struct {
	Change Change

	// NodeID if set, is the ID of the ndoe that the given change is
	// relevant to.
	// It must be set if this is a node change.
	NodeID types.NodeID

	// UserID if set, is the ID of the user that the given change is
	// relevant to.
	// It must be set if this is a user change.
	UserID types.UserID
}

func (c *ChangeSet) Validate() error {
	if c.Change >= NodeCameOnline || c.Change <= NodeNewOrUpdate {
		if c.NodeID == 0 {
			return errors.New("ChangeSet.NodeID must be set for node updates")
		}
	}

	if c.Change >= UserNewOrUpdate || c.Change <= UserRemove {
		if c.UserID == 0 {
			return errors.New("ChangeSet.UserID must be set for user updates")
		}
	}

	return nil
}

// Empty reports whether the ChangeSet is empty, meaning it does not
// represent any change.
func (c ChangeSet) Empty() bool {
	return c.Change == ChangeUnknown && c.NodeID == 0 && c.UserID == 0
}

// IsFull reports whether the ChangeSet represents a full update.
func (c ChangeSet) IsFull() bool {
	return c.Change == Full || c.Change == Policy
}

var EmptySet = ChangeSet{Change: ChangeUnknown}
var FullSet = ChangeSet{Change: Full}
var DERPSet = ChangeSet{Change: DERP}
var PolicySet = ChangeSet{Change: Policy}
var ExtraRecordsSet = ChangeSet{Change: ExtraRecords}

func NodeAdded(id types.NodeID) ChangeSet {
	return ChangeSet{
		Change: NodeNewOrUpdate,
		NodeID: id,
	}
}

func NodeRemoved(id types.NodeID) ChangeSet {
	return ChangeSet{
		Change: NodeRemove,
		NodeID: id,
	}
}

func NodeOnline(id types.NodeID) ChangeSet {
	return ChangeSet{
		Change: NodeCameOnline,
		NodeID: id,
	}
}

func NodeOffline(id types.NodeID) ChangeSet {
	return ChangeSet{
		Change: NodeWentOffline,
		NodeID: id,
	}
}

func KeyExpiry(id types.NodeID) ChangeSet {
	return ChangeSet{
		Change: NodeKeyExpiry,
		NodeID: id,
	}
}

func UserAdded(id types.UserID) ChangeSet {
	return ChangeSet{
		Change: UserNewOrUpdate,
		UserID: id,
	}
}

func UserRemoved(id types.UserID) ChangeSet {
	return ChangeSet{
		Change: UserRemove,
		UserID: id,
	}
}

func PolicyChange() ChangeSet {
	return ChangeSet{
		Change: Policy,
	}
}

func DERPChange() ChangeSet {
	return ChangeSet{
		Change: DERP,
	}
}
