package mapper

import (
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
	AddNode(id types.NodeID, c chan<- *tailcfg.MapResponse, isRouter bool, compress string, version tailcfg.CapabilityVersion)
	RemoveNode(id types.NodeID, c chan<- *tailcfg.MapResponse, isRouter bool)
	IsConnected(id types.NodeID) bool
	ConnectedMap() *xsync.Map[types.NodeID, bool]
	AddWork(c change.ChangeSet)
}

func NewBatcher(batchTime time.Duration, workers int, mapper *mapper) *LockFreeBatcher {
	return &LockFreeBatcher{
		mapper:   mapper,
		workers:  workers,
		tick:     time.NewTicker(batchTime),
		cancelCh: make(chan struct{}),

		// The size of this channel is arbitrary chosen, the sizing should be revisited.
		workCh:    make(chan work, workers*200),
		nodes:     xsync.NewMap[types.NodeID, *nodeConn](),
		connected: xsync.NewMap[types.NodeID, *time.Time](),
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

// handleNodeChange implements the shared logic for processing node changes.
func handleNodeChange(nc nodeConnection, mapper *mapper, c change.ChangeSet) error {
	var data *tailcfg.MapResponse
	var err error
	version := nc.version()

	if c.Empty() {
		return nil
	}

	switch c.Change {
	case change.DERP:
		data, err = mapper.derpMapResponse(nc.nodeID())

	case change.NodeCameOnline, change.NodeWentOffline:
		if c.IsSubnetRouter {
			// TODO(kradalby): This can potentially be a peer update of the old and new subnet router.
			data, err = mapper.fullMapResponse(nc.nodeID(), version)
		} else {
			data, err = mapper.peerChangedPatchResponse(nc.nodeID(), []*tailcfg.PeerChange{
				{
					NodeID: c.NodeID.NodeID(),
					Online: ptr.To(c.Change == change.NodeCameOnline),
				},
			})
		}
	case change.NodeNewOrUpdate:
		data, err = mapper.peerChangeResponse(nc.nodeID(), version, c.NodeID)

	case change.NodeRemove:
		data, err = mapper.peerRemovedResponse(nc.nodeID(), c.NodeID)

		// TODO(kradalby): Any other change will result in a full update to be cautious.
		// In the future, the goal is to hit this less and less as we add specific handling.
	default:
		// The following will always hit this:
		// change.Full, change.Policy
		data, err = mapper.fullMapResponse(nc.nodeID(), version)
	}

	if err != nil {
		return err
	}

	return nc.send(data)
}

// work represents a unit of work to be processed by workers.
type work struct {
	c      change.ChangeSet
	nodeID types.NodeID
}
