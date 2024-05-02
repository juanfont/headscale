package types

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/util/ctxkey"
)

const (
	SelfUpdateIdentifier = "self-update"
	DatabasePostgres     = "postgres"
	DatabaseSqlite       = "sqlite3"
)

var ErrCannotParsePrefix = errors.New("cannot parse prefix")

type IPPrefix netip.Prefix

func (i *IPPrefix) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case string:
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return err
		}
		*i = IPPrefix(prefix)

		return nil
	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrCannotParsePrefix, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (i IPPrefix) Value() (driver.Value, error) {
	prefixStr := netip.Prefix(i).String()

	return prefixStr, nil
}

type IPPrefixes []netip.Prefix

func (i *IPPrefixes) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case []byte:
		return json.Unmarshal(value, i)

	case string:
		return json.Unmarshal([]byte(value), i)

	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrNodeAddressesInvalid, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (i IPPrefixes) Value() (driver.Value, error) {
	bytes, err := json.Marshal(i)

	return string(bytes), err
}

type StringList []string

func (i *StringList) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case []byte:
		return json.Unmarshal(value, i)

	case string:
		return json.Unmarshal([]byte(value), i)

	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrNodeAddressesInvalid, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (i StringList) Value() (driver.Value, error) {
	bytes, err := json.Marshal(i)

	return string(bytes), err
}

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

func StateUpdateExpire(nodeID NodeID, expiry time.Time) StateUpdate {
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

var (
	NotifyOriginKey   = ctxkey.New("notify.origin", "")
	NotifyHostnameKey = ctxkey.New("notify.hostname", "")
)

func NotifyCtx(ctx context.Context, origin, hostname string) context.Context {
	ctx2, _ := context.WithTimeout(ctx, 3*time.Second)
	ctx2 = NotifyOriginKey.WithValue(ctx2, origin)
	ctx2 = NotifyHostnameKey.WithValue(ctx2, hostname)
	return ctx2
}
