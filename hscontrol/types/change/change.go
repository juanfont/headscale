//go:generate go tool stringer -type=Change
package change

import (
	"errors"

	"github.com/juanfont/headscale/hscontrol/types"
)

type (
	NodeID = types.NodeID
	UserID = types.UserID
)

type Change int

const (
	ChangeUnknown Change = 0

	// Deprecated: Use specific change instead
	// Full is a legacy change to ensure places where we
	// have not yet determined the specific update, can send.
	Full Change = 9

	// Server changes.
	Policy       Change = 11
	DERP         Change = 12
	ExtraRecords Change = 13

	// Node changes.
	NodeCameOnline  Change = 21
	NodeWentOffline Change = 22
	NodeRemove      Change = 23
	NodeKeyExpiry   Change = 24
	NodeNewOrUpdate Change = 25

	// User changes.
	UserNewOrUpdate Change = 51
	UserRemove      Change = 52
)

// AlsoSelf reports whether this change should also be sent to the node itself.
func (c Change) AlsoSelf() bool {
	switch c {
	case NodeRemove, NodeKeyExpiry, NodeNewOrUpdate:
		return true
	}
	return false
}

type ChangeSet struct {
	Change Change

	// SelfUpdateOnly indicates that this change should only be sent
	// to the node itself, and not to other nodes.
	// This is used for changes that are not relevant to other nodes.
	// NodeID must be set if this is true.
	SelfUpdateOnly bool

	// NodeID if set, is the ID of the node that is being changed.
	// It must be set if this is a node change.
	NodeID types.NodeID

	// UserID if set, is the ID of the user that is being changed.
	// It must be set if this is a user change.
	UserID types.UserID

	// IsSubnetRouter indicates whether the node is a subnet router.
	IsSubnetRouter bool
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

func (c ChangeSet) AlsoSelf() bool {
	// If NodeID is 0, it means this ChangeSet is not related to a specific node,
	// so we consider it as a change that should be sent to all nodes.
	if c.NodeID == 0 {
		return true
	}
	return c.Change.AlsoSelf() || c.SelfUpdateOnly
}

var (
	EmptySet        = ChangeSet{Change: ChangeUnknown}
	FullSet         = ChangeSet{Change: Full}
	DERPSet         = ChangeSet{Change: DERP}
	PolicySet       = ChangeSet{Change: Policy}
	ExtraRecordsSet = ChangeSet{Change: ExtraRecords}
)

func FullSelf(id types.NodeID) ChangeSet {
	return ChangeSet{
		Change:         Full,
		SelfUpdateOnly: true,
		NodeID:         id,
	}
}

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
