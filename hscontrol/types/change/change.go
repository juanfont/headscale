//go:generate go run ../../../tools/changegen change.go
package change

import "github.com/juanfont/headscale/hscontrol/types"

type NodeID = types.NodeID
type UserID = types.UserID

type Change struct {
	Full                bool
	Node                NodeChange
	User                UserChange
	DERPChanged         bool
	PolicyChanged       bool
	ExtraRecordsChanged bool
}

type NodeChange struct {
	ID              NodeID
	FullChange      bool
	ExpiryChanged   bool
	RoutesChanged   bool
	Online          bool
	Offline         bool
	HostinfoChanged bool
	NewNode         bool
	RemovedNode     bool
	KeyChanged      bool
	TagsChanged     bool
}

type UserChange struct {
	ID          UserID
	NewUser     bool
	RemovedUser bool
}

var None = Change{}
var Full = Change{Full: true}

func (c Change) NeedsFullUpdate() bool {
	if c.Full {
		return true
	}
	return c.Node.NeedsFullUpdate() || c.User.NeedsFullUpdate()
}

func (nc NodeChange) ImportantChange() bool {
	return nc.NewNode || nc.KeyChanged || nc.TagsChanged
}

func (nc NodeChange) OnlyKeyChange() bool {
	return nc.ID != 0 && !nc.NewNode && !nc.TagsChanged && nc.KeyChanged
}

func (nc NodeChange) NeedsFullUpdate() bool {
	if nc.ID != 0 {
		if nc.ImportantChange() || nc.FullChange {
			return true
		}
	}
	return false
}

func (uc UserChange) NeedsFullUpdate() bool {
	return uc.ID != 0 || uc.NewUser || uc.RemovedUser
}
