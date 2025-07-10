package mapper

import (
	"fmt"
	"time"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/sasha-s/go-deadlock"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

var (
	debugDeadlock        = envknob.Bool("HEADSCALE_DEBUG_DEADLOCK")
	debugDeadlockTimeout = envknob.RegisterDuration("HEADSCALE_DEBUG_DEADLOCK_TIMEOUT")
)

func init() {
	deadlock.Opts.Disable = !debugDeadlock
	if debugDeadlock {
		deadlock.Opts.DeadlockTimeout = debugDeadlockTimeout()
		deadlock.Opts.PrintAllCurrentGoroutines = true
	}
}

// nodeConnection interface for different connection implementations
type nodeConnection interface {
	nodeID() types.NodeID
	compressAndVersion() (string, tailcfg.CapabilityVersion)
	send(data []byte) error
}

// handleNodeChange implements the shared logic for processing node changes
func handleNodeChange(nc nodeConnection, mapper *mapper, c change.ChangeSet) error {
	var data []byte
	var err error
	compress, version := nc.compressAndVersion()

	if c.Empty() {
		return nil
	}

	switch c.Change {
	case change.DERP:
		data, err = mapper.derpMapResponse(nc.nodeID(), compress)

	// TODO(kradalby): If the node is a router, we need to do a full update here
	// to ensure routes are updated.
	case change.NodeCameOnline:
		data, err = mapper.peerChangedPatchResponse(nc.nodeID(), compress, []*tailcfg.PeerChange{
			{
				NodeID: c.NodeID.NodeID(),
				Online: ptr.To(true),
			},
		})
	case change.NodeWentOffline:
		data, err = mapper.peerChangedPatchResponse(nc.nodeID(), compress, []*tailcfg.PeerChange{
			{
				NodeID: c.NodeID.NodeID(),
				Online: ptr.To(false),
			},
		})
	case change.NodeRemove:
		data, err = mapper.peerRemovedResponse(nc.nodeID(), compress, c.NodeID)

		// TODO(kradalby): Any other change will result in a full update to be cautious.
		// In the future, the goal is to hit this less and less as we add specific handling.
	default:
		// The following will always hit this:
		// change.Full, change.Policy
		data, err = mapper.fullMapResponse(nc.nodeID(), version, compress)

	}

	if err != nil {
		return err
	}

	return nc.send(data)
}

type BatcherLock struct {
	mu deadlock.RWMutex // Protected by mu

	tick    *time.Ticker
	mapper  *mapper
	workers int

	// connected is a map of NodeID to the time the closed a connection.
	// This is used to track which nodes are currently connected.
	// If value is nil, the node is connected
	// If value is not nil, the node is disconnected
	// Protected by mu
	connected map[types.NodeID]*time.Time

	// nodes is a map of NodeID to a pointer to nodeConn that is used to send generated
	// mapResp to a client. Using pointers allows in-place updates during reconnection.
	// Protected by mu
	nodes map[types.NodeID]*nodeConn

	// partialChanges
	// Protected by mu
	partialChanges    map[types.NodeID]change.ChangeSet
	hasPartialChanges bool

	cancelCh chan struct{}
	workCh   chan work
}

func NewBatcherLock(batchTime time.Duration, workers int, mapper *mapper) *BatcherLock {
	return &BatcherLock{
		mapper:   mapper,
		workers:  workers,
		tick:     time.NewTicker(batchTime),
		cancelCh: make(chan struct{}),
		// TODO: No limit for now, this needs to be changed
		workCh: make(chan work, (1<<16)-1),

		nodes:     make(map[types.NodeID]*nodeConn),
		connected: make(map[types.NodeID]*time.Time),
	}
}

type batcherFunc func(cfg *types.Config, state *state.State) Batcher

// NewBatcherLockAndMapper creates a BatcherLock implementation
func NewBatcherLockAndMapper(cfg *types.Config, state *state.State) Batcher {
	m := newMapper(cfg, state)
	b := NewBatcherLock(cfg.Tuning.BatchChangeDelay, cfg.Tuning.BatcherWorkers, m)
	m.batcher = b
	return b
}

func (b *BatcherLock) Close() {
	b.cancelCh <- struct{}{}
	close(b.workCh)
}

func (b *BatcherLock) Start() {
	go b.doWork()
}

func (b *BatcherLock) AddNode(id types.NodeID, c chan<- []byte, compress string, version tailcfg.CapabilityVersion) {
	var sendInitialMap bool
	var mapCompress string
	var mapVersion tailcfg.CapabilityVersion

	b.mu.Lock()
	// If a nodeConn exists, update it in place instead of creating a new one.
	// This allows workers to automatically get the updated connection.
	if curr, ok := b.nodes[id]; ok {
		curr.mu.Lock()
		curr.c = c
		curr.compress = compress
		curr.version = version
		curr.mu.Unlock()

		// Note: We don't close the old channel - it will be garbage collected when the
		// HTTP handler's mapSession goes out of scope. Closing from here can cause race conditions.
	} else {
		// Create new nodeConn for first connection
		b.nodes[id] = &nodeConn{
			id:       id,
			c:        c,
			compress: compress,
			version:  version,
			mapper:   b.mapper,
		}
		sendInitialMap = true
		mapCompress = compress
		mapVersion = version
	}
	b.connected[id] = nil // nil means connected

	// TODO(kradalby): Handle:
	// - Updating peers with online status
	// - Updating routes in routemanager and peers
	b.addWorkLocked(change.ChangeSet{NodeID: id, Change: change.NodeCameOnline})
	b.mu.Unlock()

	// Send initial full map response for new nodes (outside of mutex lock to avoid deadlock)
	if sendInitialMap {
		data, err := b.mapper.fullMapResponse(id, mapVersion, mapCompress)
		if err == nil && len(data) > 0 {
			// Get the nodeConn again and send the full map response
			b.mu.RLock()
			if nc, ok := b.nodes[id]; ok {
				nc.mu.RLock()
				currentChannel := nc.c
				nc.mu.RUnlock()

				// Send the full map response directly to the node's channel
				select {
				case currentChannel <- data:
				default:
					// If channel is full, don't block
				}
			}
			b.mu.RUnlock()
		}
	}
}

func (b *BatcherLock) RemoveNode(id types.NodeID, c chan<- []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Check if the node exists and the channel matches
	if curr, ok := b.nodes[id]; ok {
		curr.mu.RLock()
		matches := curr.c == c
		curr.mu.RUnlock()

		if !matches {
			return // Channel doesn't match current connection
		}
	} else {
		return // Node doesn't exist
	}

	delete(b.nodes, id)
	b.connected[id] = ptr.To(time.Now())

	// TODO(kradalby): Handle:
	// - Updating peers with lastseen status, and only if not replaced
	// - Updating routes in routemanager and peers
	b.addWorkLocked(change.ChangeSet{NodeID: id, Change: change.NodeWentOffline})
}

func (b *BatcherLock) AddWork(c change.ChangeSet) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.addWorkLocked(c)
}

func (b *BatcherLock) addWorkLocked(c change.ChangeSet) {
	for nodeID := range b.nodes {
		// If this is a node-specific change, don't send it to the same node
		if c.NodeID != 0 && c.NodeID == nodeID {
			continue
		}
		b.workCh <- work{c, nodeID}
	}
}

func (b *BatcherLock) IsConnected(id types.NodeID) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// If the value is nil, it means the node is connected
	if b.connected[id] == nil {
		return true
	}

	// If the value is not nil, it means the node is disconnected
	return false
}

func (b *BatcherLock) ConnectedMap() *xsync.Map[types.NodeID, bool] {
	b.mu.RLock()
	defer b.mu.RUnlock()

	ret := xsync.NewMap[types.NodeID, bool]()

	for id, ts := range b.connected {
		if ts == nil {
			ret.Store(id, true)
		} else {
			ret.Store(id, false)
		}
	}

	return ret
}

// TODO(kradlaby): This doesnt really do anything atm, removed for simplicity
// in the initial implementation. No batching other than distributing to workers.
func (b *BatcherLock) doWork() {
	for range b.workers {
		b.startWorker()
	}

	for {
		select {
		case <-b.cancelCh:
			return
		case <-b.tick.C:
			// b.flush(false)
		}
	}
}

type work struct {
	c      change.ChangeSet
	nodeID types.NodeID
}

func (b *BatcherLock) startWorker() {
	go func() {
		for {
			select {
			case w, ok := <-b.workCh:
				if !ok {
					return
				}

				// Look up the current nodeConn for this nodeID
				b.mu.RLock()
				nc, exists := b.nodes[w.nodeID]
				b.mu.RUnlock()

				// Only process if the node is still connected
				if exists {
					nc.change(w.c)
				}
			}
		}
	}()
}

type nodeConn struct {
	mu deadlock.RWMutex // Protects channel and metadata updates
	id types.NodeID
	// Protected by mu
	c        chan<- []byte
	compress string
	version  tailcfg.CapabilityVersion
	mapper   *mapper
}

type changeUpdate int

func (nc *nodeConn) nodeID() types.NodeID {
	return nc.id
}

func (nc *nodeConn) change(c change.ChangeSet) error {
	return handleNodeChange(nc, nc.mapper, c)
}

// compressAndVersion atomically reads the compression and version settings
func (nc *nodeConn) compressAndVersion() (compress string, version tailcfg.CapabilityVersion) {
	nc.mu.RLock()
	defer nc.mu.RUnlock()
	return nc.compress, nc.version
}

// send attempts to send data to the node's channel with proper synchronization.
// If the channel is closed by its creator (HTTP handler), the send will fail gracefully.
func (nc *nodeConn) send(data []byte) error {
	nc.mu.RLock()
	c := nc.c
	nc.mu.RUnlock()

	if c == nil {
		return fmt.Errorf("unable to send to node %d: no channel", nc.id)
	}

	select {
	case c <- data:
		return nil
	default:
		// Channel is full or closed, don't block
		return fmt.Errorf("unable to send to node %d: channel full or closed", nc.id)
	}
}

// updateConnectionUnsafe updates connection parameters without additional locking
func (nc *nodeConn) updateConnectionUnsafe(c chan<- []byte, compress string, version tailcfg.CapabilityVersion) {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	nc.c = c
	nc.compress = compress
	nc.version = version
}

// matchesChannelUnsafe checks if the given channel matches current connection
func (nc *nodeConn) matchesChannelUnsafe(c chan<- []byte) bool {
	nc.mu.RLock()
	defer nc.mu.RUnlock()
	return nc.c == c
}

// resp is the logic that used to reside in the poller, but is now moved
// to process before sending to the node. The idea is that we do not want to
// be blocked on the send channel to the individual node, but rather
// process all the work and then send the responses to the nodes.
// TODO(kradalby): This is a temporary solution, as we explore this
// approach, we will likely need to refactor this further.
// func (b *Batcher) resp(id types.NodeID, nc *nodeConn, work *ChangeWork) ([]byte, error) {
// 	var data []byte
// 	var err error

// 	// TODO(kradalby): This should not be necessary, mapper only
// 	// use compress and version, and this can either be moved out
// 	// or passed directly. The mapreq isnt needed.
// 	req := tailcfg.MapRequest{
// 		Compress: nc.compress,
// 		Version:  nc.version,
// 	}

// 	// TODO(kradalby): We dont want to use the db here. We should
// 	// just have the node available, or at least quickly accessible
// 	// from the new fancy mem state we want.
// 	node, err := b.mapper.db.GetNodeByID(id)
// 	if err != nil {
// 		return nil, err
// 	}

// 	switch work.Update.Type {
// 	case types.StateFullUpdate:
// 		data, err = b.mapper.fullMapResponse(req, node)
// 	case types.StatePeerChanged:
// 		changed := make(map[types.NodeID]bool, len(work.Update.ChangeNodes))

// 		for _, nodeID := range work.Update.ChangeNodes {
// 			changed[nodeID] = true
// 		}

// 		data, err = b.mapper.peerChangedResponse(req, node, changed, work.Update.ChangePatches)

// 	case types.StatePeerChangedPatch:
// 		data, err = b.mapper.peerChangedPatchResponse(req, node, work.Update.ChangePatches)
// 	case types.StatePeerRemoved:
// 		changed := make(map[types.NodeID]bool, len(work.Update.Removed))

// 		for _, nodeID := range work.Update.Removed {
// 			changed[nodeID] = false
// 		}
// 		data, err = b.mapper.peerChangedResponse(req, node, changed, work.Update.ChangePatches)
// 	case types.StateSelfUpdate:
// 		data, err = b.mapper.peerChangedResponse(req, node, make(map[types.NodeID]bool), work.Update.ChangePatches)
// 	case types.StateDERPUpdated:
// 		data, err = b.mapper.derpMapResponse(req, node, work.Update.DERPMap)
// 	}

// 	return data, err
// }
