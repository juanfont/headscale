package types

type Change struct {
	NodeChange    NodeChange
	UserChange    UserChange
	DERPChanged   bool
	PolicyChanged bool

	// TODO(kradalby): We can probably do better than sending a full update here,
	// but for now this will ensure that all of the nodes get the new records.
	ExtraRecordsChanged bool
}

func (c *Change) FullUpdate() bool {
	if !c.NodeChange.FullUpdate() && !c.UserChange.FullUpdate() {
		return false
	}

	return true
}

// type NodeChangeWhat string

// const (
// 	NodeChangeOnline  NodeChangeWhat = "node-online"
// 	NodeChangeOffline NodeChangeWhat = "node-offline"
// 	NodeChangeAdded   NodeChangeWhat = "node-added"
// 	NodeChangeRemoved NodeChangeWhat = "node-removed"
// )

type NodeChange struct {
	ID NodeID
	// What NodeChangeWhat

	// TODO(kradalby): FullChange is a bit of a
	FullChange bool

	ExpiryChanged bool
	RoutesChanged bool

	Online  bool
	Offline bool

	// TODO: This could maybe be more granular
	HostinfoChanged bool

	// Registration and auth related changes
	NewNode     bool
	RemovedNode bool
	KeyChanged  bool
	TagsChanged bool
}

func (c *NodeChange) RegistrationChanged() bool {
	return c.NewNode || c.KeyChanged || c.TagsChanged
}

func (c *NodeChange) OnlyKeyChange() bool {
	return c.ID != 0 && !c.NewNode && !c.TagsChanged && c.KeyChanged
}

func (c *NodeChange) FullUpdate() bool {
	if c.ID != 0 {
		if c.RegistrationChanged() {
			return true
		}

		if c.FullChange {
			return true
		}

		return false
	}

	return false
}

type UserChange struct {
	ID UserID

	NewUser     bool
	RemovedUser bool
}

func (c *UserChange) FullUpdate() bool {
	if c.ID != 0 {
		return true
	}

	if c.NewUser || c.RemovedUser {
		return true
	}

	return false
}
