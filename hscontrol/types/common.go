//go:generate go tool viewer --type=User,Node,PreAuthKey
package types

//go:generate go run tailscale.com/cmd/viewer --type=User,Node,PreAuthKey

import (
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/tailcfg"
)

const (
	SelfUpdateIdentifier = "self-update"
	DatabasePostgres     = "postgres"
	DatabaseSqlite       = "sqlite3"
)

// Common errors.
var (
	ErrCannotParsePrefix   = errors.New("cannot parse prefix")
	ErrInvalidAuthIDLength = errors.New("registration ID has invalid length")
)

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
	case StateFullUpdate, StateSelfUpdate, StateDERPUpdated:
		// These update types don't have associated data to check,
		// so they are never considered empty.
		return false
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

const AuthIDLength = 24

type AuthID string

func NewAuthID() (AuthID, error) {
	rid, err := util.GenerateRandomStringURLSafe(AuthIDLength)
	if err != nil {
		return "", err
	}

	return AuthID(rid), nil
}

func MustAuthID() AuthID {
	rid, err := NewAuthID()
	if err != nil {
		panic(err)
	}

	return rid
}

func AuthIDFromString(str string) (AuthID, error) {
	r := AuthID(str)

	err := r.Validate()
	if err != nil {
		return "", err
	}

	return r, nil
}

func (r AuthID) String() string {
	return string(r)
}

func (r AuthID) Validate() error {
	if len(r) != AuthIDLength {
		return fmt.Errorf("%w: expected %d, got %d", ErrInvalidAuthIDLength, AuthIDLength, len(r))
	}

	return nil
}

// AuthRequest represent a pending authentication request from a user or a node.
// If it is a registration request, the node field will be populate with the node that is trying to register.
// When the authentication process is finished, the node that has been authenticated will be sent through the Finished channel.
// The closed field is used to ensure that the Finished channel is only closed once, and that no more nodes are sent through it after it has been closed.
type AuthRequest struct {
	node     *Node
	finished chan AuthVerdict
	closed   *atomic.Bool
}

func NewRegisterAuthRequest(node Node) AuthRequest {
	return AuthRequest{
		node:     &node,
		finished: make(chan AuthVerdict),
		closed:   &atomic.Bool{},
	}
}

// Node returns the node that is trying to register.
// It will panic if the AuthRequest is not a registration request.
// Can _only_ be used in the registration path.
func (rn *AuthRequest) Node() NodeView {
	if rn.node == nil {
		panic("Node can only be used in registration requests")
	}

	return rn.node.View()
}

func (rn *AuthRequest) FinishAuth(verdict AuthVerdict) {
	if rn.closed.Swap(true) {
		return
	}

	select {
	case rn.finished <- verdict:
	default:
	}

	close(rn.finished)
}

func (rn *AuthRequest) WaitForAuth() <-chan AuthVerdict {
	return rn.finished
}

type AuthVerdict struct {
	// Err is the error that occurred during the authentication process, if any.
	// If Err is nil, the authentication process has succeeded.
	// If Err is not nil, the authentication process has failed and the node should not be authenticated.
	Err error

	// Node is the node that has been authenticated.
	// Node is only valid if the auth request was a registration request
	// and the authentication process has succeeded.
	Node NodeView
}

func (v AuthVerdict) Accept() bool {
	return v.Err == nil
}

// DefaultBatcherWorkers returns the default number of batcher workers.
// Default to 3/4 of CPU cores, minimum 1, no maximum.
func DefaultBatcherWorkers() int {
	return DefaultBatcherWorkersFor(runtime.NumCPU())
}

// DefaultBatcherWorkersFor returns the default number of batcher workers for a given CPU count.
// Default to 3/4 of CPU cores, minimum 1, no maximum.
func DefaultBatcherWorkersFor(cpuCount int) int {
	const (
		workerNumerator   = 3
		workerDenominator = 4
	)

	defaultWorkers := max((cpuCount*workerNumerator)/workerDenominator, 1)

	return defaultWorkers
}
