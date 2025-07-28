//go:generate go tool viewer --type=User,Node,PreAuthKey
package types

//go:generate go run tailscale.com/cmd/viewer --type=User,Node,PreAuthKey

import (
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/tailcfg"
)

const (
	SelfUpdateIdentifier = "self-update"
	DatabasePostgres     = "postgres"
	DatabaseSqlite       = "sqlite3"
)

var ErrCannotParsePrefix = errors.New("cannot parse prefix")

type StateUpdateType int

func (su StateUpdateType) String() string {
	switch su {
	case StateFullUpdate:
		return "StateFullUpdate"
	case StatePeerChanged:
		return "StatePeerChanged"
	case StatePeerChangedPatch:
		return "StatePeerChangedPatch"
	case StatePeerRemoved:
		return "StatePeerRemoved"
	case StateSelfUpdate:
		return "StateSelfUpdate"
	case StateDERPUpdated:
		return "StateDERPUpdated"
	}

	return "unknown state update type"
}

const (
	StateFullUpdate StateUpdateType = iota
	// StatePeerChanged is used for updates that needs
	// to be calculated with all peers and all policy rules.
	// This would typically be things that include tags, routes
	// and similar.
	StatePeerChanged
	StatePeerChangedPatch
	StatePeerRemoved
	// StateSelfUpdate is used to indicate that the node
	// has changed in control, and the client needs to be
	// informed.
	// The updated node is inside the ChangeNodes field
	// which should have a length of one.
	StateSelfUpdate
	StateDERPUpdated
)

// StateUpdate is an internal message containing information about
// a state change that has happened to the network.
// If type is StateFullUpdate, all fields are ignored.
type StateUpdate struct {
	// The type of update
	Type StateUpdateType

	// ChangeNodes must be set when Type is StatePeerAdded
	// and StatePeerChanged and contains the full node
	// object for added nodes.
	ChangeNodes []NodeID

	// ChangePatches must be set when Type is StatePeerChangedPatch
	// and contains a populated PeerChange object.
	ChangePatches []*tailcfg.PeerChange

	// Removed must be set when Type is StatePeerRemoved and
	// contain a list of the nodes that has been removed from
	// the network.
	Removed []NodeID

	// DERPMap must be set when Type is StateDERPUpdated and
	// contain the new DERP Map.
	DERPMap *tailcfg.DERPMap

	// Additional message for tracking origin or what being
	// updated, useful for ambiguous updates like StatePeerChanged.
	Message string
}

// Empty reports if there are any updates in the StateUpdate.
func (su *StateUpdate) Empty() bool {
	switch su.Type {
	case StatePeerChanged:
		return len(su.ChangeNodes) == 0
	case StatePeerChangedPatch:
		return len(su.ChangePatches) == 0
	case StatePeerRemoved:
		return len(su.Removed) == 0
	}

	return false
}

func UpdateFull() StateUpdate {
	return StateUpdate{
		Type: StateFullUpdate,
	}
}

func UpdateSelf(nodeID NodeID) StateUpdate {
	return StateUpdate{
		Type:        StateSelfUpdate,
		ChangeNodes: []NodeID{nodeID},
	}
}

func UpdatePeerChanged(nodeIDs ...NodeID) StateUpdate {
	return StateUpdate{
		Type:        StatePeerChanged,
		ChangeNodes: nodeIDs,
	}
}

func UpdatePeerPatch(changes ...*tailcfg.PeerChange) StateUpdate {
	return StateUpdate{
		Type:          StatePeerChangedPatch,
		ChangePatches: changes,
	}
}

func UpdatePeerRemoved(nodeIDs ...NodeID) StateUpdate {
	return StateUpdate{
		Type:    StatePeerRemoved,
		Removed: nodeIDs,
	}
}

func UpdateExpire(nodeID NodeID, expiry time.Time) StateUpdate {
	return StateUpdate{
		Type: StatePeerChangedPatch,
		ChangePatches: []*tailcfg.PeerChange{
			{
				NodeID:    nodeID.NodeID(),
				KeyExpiry: &expiry,
			},
		},
	}
}

const RegistrationIDLength = 24

type RegistrationID string

func NewRegistrationID() (RegistrationID, error) {
	rid, err := util.GenerateRandomStringURLSafe(RegistrationIDLength)
	if err != nil {
		return "", err
	}

	return RegistrationID(rid), nil
}

func MustRegistrationID() RegistrationID {
	rid, err := NewRegistrationID()
	if err != nil {
		panic(err)
	}

	return rid
}

func RegistrationIDFromString(str string) (RegistrationID, error) {
	if len(str) != RegistrationIDLength {
		return "", fmt.Errorf("registration ID must be %d characters long", RegistrationIDLength)
	}
	return RegistrationID(str), nil
}

func (r RegistrationID) String() string {
	return string(r)
}

type RegisterNode struct {
	Node       Node
	Registered chan *Node
}

// DefaultBatcherWorkers returns the default number of batcher workers.
// Default to 3/4 of CPU cores, minimum 1, no maximum.
func DefaultBatcherWorkers() int {
	return DefaultBatcherWorkersFor(runtime.NumCPU())
}

// DefaultBatcherWorkersFor returns the default number of batcher workers for a given CPU count.
// Default to 3/4 of CPU cores, minimum 1, no maximum.
func DefaultBatcherWorkersFor(cpuCount int) int {
	defaultWorkers := (cpuCount * 3) / 4
	if defaultWorkers < 1 {
		defaultWorkers = 1
	}

	return defaultWorkers
}
