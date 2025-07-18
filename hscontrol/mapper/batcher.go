package mapper

import (
	"fmt"
	"time"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/puzpuzpuz/xsync/v4"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

type batcherFunc func(cfg *types.Config, state *state.State) Batcher

// Batcher defines the common interface for all batcher implementations.
type Batcher interface {
	Start()
	Close()
	AddNode(id types.NodeID, c chan<- *tailcfg.MapResponse, isRouter bool, version tailcfg.CapabilityVersion) error
	RemoveNode(id types.NodeID, c chan<- *tailcfg.MapResponse, isRouter bool)
	IsConnected(id types.NodeID) bool
	ConnectedMap() *xsync.Map[types.NodeID, bool]
	AddWork(c change.ChangeSet)
	MapResponseFromChange(id types.NodeID, c change.ChangeSet) (*tailcfg.MapResponse, error)
}

func NewBatcher(batchTime time.Duration, workers int, mapper *mapper) *LockFreeBatcher {
	return &LockFreeBatcher{
		mapper:  mapper,
		workers: workers,
		tick:    time.NewTicker(batchTime),

		// The size of this channel is arbitrary chosen, the sizing should be revisited.
		workCh:         make(chan work, workers*200),
		nodes:          xsync.NewMap[types.NodeID, *nodeConn](),
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

	var mapResp *tailcfg.MapResponse
	var err error

	switch c.Change {
	case change.DERP:
		mapResp, err = mapper.derpMapResponse(nodeID)

	case change.NodeCameOnline, change.NodeWentOffline:
		if c.IsSubnetRouter {
			// TODO(kradalby): This can potentially be a peer update of the old and new subnet router.
			mapResp, err = mapper.fullMapResponse(nodeID, version)
		} else {
			mapResp, err = mapper.peerChangedPatchResponse(nodeID, []*tailcfg.PeerChange{
				{
					NodeID: c.NodeID.NodeID(),
					Online: ptr.To(c.Change == change.NodeCameOnline),
				},
			})
		}

	case change.NodeNewOrUpdate:
		mapResp, err = mapper.fullMapResponse(nodeID, version)

	case change.NodeRemove:
		mapResp, err = mapper.peerRemovedResponse(nodeID, c.NodeID)

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
		return fmt.Errorf("nodeConnection is nil")
	}

	nodeID := nc.nodeID()
	data, err := generateMapResponse(nodeID, nc.version(), mapper, c)
	if err != nil {
		return fmt.Errorf("generating map response for node %d: %w", nodeID, err)
	}

	if data == nil {
		// No data to send is valid for some change types
		return nil
	}

	// Send the map response
	if err := nc.send(data); err != nil {
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
