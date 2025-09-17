package mapper

import (
	"errors"
	"fmt"
	"time"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

type batcherFunc func(cfg *types.Config, state *state.State) Batcher

// Batcher defines the common interface for all batcher implementations.
type Batcher interface {
	Start()
	Close()
	AddNode(id types.NodeID, c chan<- *tailcfg.MapResponse, version tailcfg.CapabilityVersion) error
	RemoveNode(id types.NodeID, c chan<- *tailcfg.MapResponse) bool
	IsConnected(id types.NodeID) bool
	ConnectedMap() *xsync.Map[types.NodeID, bool]
	AddWork(c ...change.ChangeSet)
	MapResponseFromChange(id types.NodeID, c change.ChangeSet) (*tailcfg.MapResponse, error)
	DebugMapResponses() (map[types.NodeID][]tailcfg.MapResponse, error)
}

func NewBatcher(batchTime time.Duration, workers int, mapper *mapper) *LockFreeBatcher {
	return &LockFreeBatcher{
		mapper:  mapper,
		workers: workers,
		tick:    time.NewTicker(batchTime),

		// The size of this channel is arbitrary chosen, the sizing should be revisited.
		workCh:         make(chan work, workers*200),
		nodes:          xsync.NewMap[types.NodeID, *multiChannelNodeConn](),
		connected:      xsync.NewMap[types.NodeID, *time.Time](),
		pendingChanges: xsync.NewMap[types.NodeID, []change.ChangeSet](),
	}
}

// NewBatcherAndMapper creates a Batcher implementation.
func NewBatcherAndMapper(cfg *types.Config, state *state.State) Batcher {
	m := newMapper(cfg, state)
	b := NewBatcher(cfg.Tuning.BatchChangeDelay, cfg.Tuning.BatcherWorkers, m)
	m.batcher = b

	return b
}

// nodeConnection interface for different connection implementations.
type nodeConnection interface {
	nodeID() types.NodeID
	version() tailcfg.CapabilityVersion
	send(data *tailcfg.MapResponse) error
}

// generateMapResponse generates a [tailcfg.MapResponse] for the given NodeID that is based on the provided [change.ChangeSet].
func generateMapResponse(nodeID types.NodeID, version tailcfg.CapabilityVersion, mapper *mapper, c change.ChangeSet) (*tailcfg.MapResponse, error) {
	if c.Empty() {
		return nil, nil
	}

	// Validate inputs before processing
	if nodeID == 0 {
		return nil, fmt.Errorf("invalid nodeID: %d", nodeID)
	}

	if mapper == nil {
		return nil, fmt.Errorf("mapper is nil for nodeID %d", nodeID)
	}

	var (
		mapResp *tailcfg.MapResponse
		err     error
	)

	switch c.Change {
	case change.DERP:
		mapResp, err = mapper.derpMapResponse(nodeID)

	case change.NodeCameOnline, change.NodeWentOffline:
		if c.IsSubnetRouter {
			// TODO(kradalby): This can potentially be a peer update of the old and new subnet router.
			mapResp, err = mapper.fullMapResponse(nodeID, version)
		} else {
			// Trust the change type for online/offline status to avoid race conditions
			// between NodeStore updates and change processing
			onlineStatus := c.Change == change.NodeCameOnline

			mapResp, err = mapper.peerChangedPatchResponse(nodeID, []*tailcfg.PeerChange{
				{
					NodeID: c.NodeID.NodeID(),
					Online: ptr.To(onlineStatus),
				},
			})
		}

	case change.NodeNewOrUpdate:
		// If the node is the one being updated, we send a self update that preserves peer information
		// to ensure the node sees changes to its own properties (e.g., hostname/DNS name changes)
		// without losing its view of peer status during rapid reconnection cycles
		if c.IsSelfUpdate(nodeID) {
			mapResp, err = mapper.selfMapResponse(nodeID, version)
		} else {
			mapResp, err = mapper.peerChangeResponse(nodeID, version, c.NodeID)
		}

	case change.NodeRemove:
		mapResp, err = mapper.peerRemovedResponse(nodeID, c.NodeID)

	case change.NodeKeyExpiry:
		// If the node is the one whose key is expiring, we send a "full" self update
		// as nodes will ignore patch updates about themselves (?).
		if c.IsSelfUpdate(nodeID) {
			mapResp, err = mapper.selfMapResponse(nodeID, version)
			// mapResp, err = mapper.fullMapResponse(nodeID, version)
		} else {
			mapResp, err = mapper.peerChangedPatchResponse(nodeID, []*tailcfg.PeerChange{
				{
					NodeID:    c.NodeID.NodeID(),
					KeyExpiry: c.NodeExpiry,
				},
			})
		}

	default:
		// The following will always hit this:
		// change.Full, change.Policy
		mapResp, err = mapper.fullMapResponse(nodeID, version)
	}

	if err != nil {
		return nil, fmt.Errorf("generating map response for nodeID %d: %w", nodeID, err)
	}

	// TODO(kradalby): Is this necessary?
	// Validate the generated map response - only check for nil response
	// Note: mapResp.Node can be nil for peer updates, which is valid
	if mapResp == nil && c.Change != change.DERP && c.Change != change.NodeRemove {
		return nil, fmt.Errorf("generated nil map response for nodeID %d change %s", nodeID, c.Change.String())
	}

	return mapResp, nil
}

// handleNodeChange generates and sends a [tailcfg.MapResponse] for a given node and [change.ChangeSet].
func handleNodeChange(nc nodeConnection, mapper *mapper, c change.ChangeSet) error {
	if nc == nil {
		return errors.New("nodeConnection is nil")
	}

	nodeID := nc.nodeID()

	log.Debug().Caller().Uint64("node.id", nodeID.Uint64()).Str("change.type", c.Change.String()).Msg("Node change processing started because change notification received")

	var data *tailcfg.MapResponse
	var err error
	data, err = generateMapResponse(nodeID, nc.version(), mapper, c)
	if err != nil {
		return fmt.Errorf("generating map response for node %d: %w", nodeID, err)
	}

	if data == nil {
		// No data to send is valid for some change types
		return nil
	}

	// Send the map response
	err = nc.send(data)
	if err != nil {
		return fmt.Errorf("sending map response to node %d: %w", nodeID, err)
	}

	return nil
}

// workResult represents the result of processing a change.
type workResult struct {
	mapResponse *tailcfg.MapResponse
	err         error
}

// work represents a unit of work to be processed by workers.
type work struct {
	c        change.ChangeSet
	nodeID   types.NodeID
	resultCh chan<- workResult // optional channel for synchronous operations
}
