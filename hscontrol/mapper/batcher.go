package mapper

import (
	"fmt"
	"time"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/rs/zerolog/log"
	"github.com/sasha-s/go-deadlock"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
	"tailscale.com/util/mak"
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

type BatcherLock struct {
	mu deadlock.RWMutex

	tick   *time.Ticker
	mapper *mapper

	// connected is a map of NodeID to the time the closed a connection.
	// This is used to track which nodes are currently connected.
	// If value is nil, the node is connected
	// If value is not nil, the node is disconnected
	connected map[types.NodeID]*time.Time

	// nodes is a map of NodeID to a pointer to nodeConn that is used to send generated
	// mapResp to a client. Using pointers allows in-place updates during reconnection.
	nodes map[types.NodeID]*nodeConn

	// partialChanges
	partialChanges    map[types.NodeID]change.Change
	hasPartialChanges bool

	// TODO: we will probably have more workers, but for now,
	// this should serve for the experiment.
	cancelCh chan struct{}

	workCh chan work
}

func NewBatcherLock(batchTime time.Duration, mapper *mapper) *BatcherLock {
	return &BatcherLock{
		mapper:   mapper,
		tick:     time.NewTicker(batchTime),
		cancelCh: make(chan struct{}),
		// TODO: No limit for now, this needs to be changed
		workCh: make(chan work, (1<<16)-1),

		nodes:     make(map[types.NodeID]*nodeConn),
		connected: make(map[types.NodeID]*time.Time),
	}
}

// Factory functions for different batcher implementations

// NewBatcherAndMapper creates the default (BatcherLock) implementation
func NewBatcherAndMapper(cfg *types.Config, state *state.State) Batcher {
	m := newMapper(cfg, state)
	b := NewBatcherLock(cfg.Tuning.BatchChangeDelay, m)
	m.batcher = b
	return b
}

// NewBatcherLockAndMapper creates a BatcherLock implementation
func NewBatcherLockAndMapper(cfg *types.Config, state *state.State) Batcher {
	m := newMapper(cfg, state)
	b := NewBatcherLock(cfg.Tuning.BatchChangeDelay, m)
	m.batcher = b
	return b
}

// NewLockFreeBatcherAndMapper creates a LockFreeBatcher implementation
func NewLockFreeBatcherAndMapper(cfg *types.Config, state *state.State) Batcher {
	m := newMapper(cfg, state)
	b := NewLockFreeBatcher(cfg.Tuning.BatchChangeDelay, m)
	m.batcher = b
	return b
}

// NewHybridBatcherAndMapper creates a HybridBatcher implementation
func NewHybridBatcherAndMapper(cfg *types.Config, state *state.State) Batcher {
	m := newMapper(cfg, state)
	b := NewHybridBatcher(cfg.Tuning.BatchChangeDelay, m)
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
	b.mu.Lock()
	defer b.mu.Unlock()

	// If a nodeConn exists, update it in place instead of creating a new one.
	// This allows workers to automatically get the updated connection.
	// We don't close the old channel - it will be garbage collected when the
	// HTTP handler's mapSession goes out of scope.
	if curr, ok := b.nodes[id]; ok {
		curr.mu.Lock()
		curr.c = c
		curr.compress = compress
		curr.version = version
		curr.mu.Unlock()
	} else {
		// Create new nodeConn for first connection
		b.nodes[id] = &nodeConn{
			id:       id,
			c:        c,
			compress: compress,
			version:  version,
			mapper:   b.mapper,
		}
	}
	b.connected[id] = nil // nil means connected

	// TODO(kradalby): Handle:
	// - Updating peers with online status
	// - Updating routes in routemanager and peers
	chg := change.NodeOnline(id)
	b.addWorkLocked(chg)
}

func (b *BatcherLock) RemoveNode(id types.NodeID, c chan<- []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if curr, ok := b.nodes[id]; ok {
		if curr.c != c {
			return
		}
	}

	delete(b.nodes, id)
	b.connected[id] = ptr.To(time.Now())

	// TODO(kradalby): Handle:
	// - Updating peers with lastseen status, and only if not replaced
	// - Updating routes in routemanager and peers
}

func (b *BatcherLock) AddWork(c change.Change) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.addWorkLocked(c)
}

func (b *BatcherLock) addWorkLocked(c change.Change) {
	switch determineChange(c) {
	case partialUpdate:
		b.addPartialLocked(c)
	case fullUpdate:
		b.flushLocked(true)
	default:
		log.Trace().Msgf("ignoring change: %v", c)
	}
}

func (b *BatcherLock) addPartialLocked(c change.Change) {
	if cc, ok := b.partialChanges[c.Node.ID]; ok {
		b.partialChanges[c.Node.ID] = cc.Merge(c)
		return
	}

	mak.Set(&b.partialChanges, c.Node.ID, c)
	b.hasPartialChanges = true
}

func (b *BatcherLock) flush(full bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.flushLocked(full)
}

func (b *BatcherLock) flushLocked(full bool) {
	if full {
		b.hasPartialChanges = false
		clear(b.partialChanges)

		for nodeID := range b.nodes {
			b.workCh <- work{change.Full, nodeID}
		}
	}

	if b.hasPartialChanges {
		for _, c := range b.partialChanges {
			for nodeID := range b.nodes {
				b.workCh <- work{c, nodeID}
			}
		}
		b.hasPartialChanges = false
		clear(b.partialChanges)
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

func (b *BatcherLock) IsLikelyConnected(id types.NodeID) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.isLikelyConnectedLocked(id)
}

func (b *BatcherLock) isLikelyConnectedLocked(id types.NodeID) bool {
	// If the value is nil, it means the node is connected
	if b.connected[id] == nil {
		return true
	}

	// TODO(kradalby): Currently some tests depend on getting this offline immediately
	// so might have to rethink / not do this.
	// If the value is not nil, it means the node is disconnected
	// but we check if it was disconnected recently (within 10 seconds)
	// if time.Since(*b.connected[id]) < 10*time.Second {
	// 	return true
	// }

	return false
}

func (b *BatcherLock) LikelyConnectedMap() *xsync.Map[types.NodeID, bool] {
	b.mu.RLock()
	defer b.mu.RUnlock()

	ret := xsync.NewMap[types.NodeID, bool]()

	for id := range b.connected {
		ret.Store(id, b.isLikelyConnectedLocked(id))
	}

	return ret
}

func (b *BatcherLock) doWork() {
	// TODO(kradalby): figure out if it will be this integrated
	// and make number configurable
	for range 4 {
		b.startWorker()
	}

	for {
		select {
		case <-b.cancelCh:
			return
		case <-b.tick.C:
			b.flush(false)
		}
	}
}

// processChange is the current bottleneck where all the updates get picked up
// one by one and processed. This will have to change, it needs to go as fast as
// possible and just pass it on to the nodes. Currently it wont block because the
// work channel is super large, but it might not be able to keep up.
// one alternative is to have a worker per node, but that would
// mean a lot of goroutines, hanging around.
// Another is just a worker pool that picks up work and processes it,
// and passes it on to the nodes. That might be complicated with order?
func (b *BatcherLock) processChange(c change.Change) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	log.Trace().Msgf("processing work: %v", c)

	for id, node := range b.nodes {
		err := node.change(c)
		log.Error().Err(err).Uint64("node.id", id.Uint64()).Msgf("processing work for node %d", id)
	}
}

type work struct {
	c      change.Change
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
	mu       deadlock.RWMutex // Protects channel and metadata updates
	id       types.NodeID
	c        chan<- []byte
	compress string
	version  tailcfg.CapabilityVersion
	mapper   *mapper
}

type changeUpdate int

const (
	_ changeUpdate = iota
	ignoreUpdate
	partialUpdate
	fullUpdate
)

func determineChange(c change.Change) changeUpdate {
	if c.DERPChanged {
		return partialUpdate
	}

	// TODO(kradalby): Make policy a partial update?
	if c.PolicyChanged {
		return fullUpdate
	}

	if c.Node.ID != 0 {
		if c.Node.OnlyKeyChange() {
			return partialUpdate
		}

		if c.Node.ImportantChange() {
			return fullUpdate
		}
	}

	if c.NeedsFullUpdate() {
		return fullUpdate
	}

	return fullUpdate
}

func (nc *nodeConn) change(c change.Change) error {
	switch determineChange(c) {
	case partialUpdate:
		return nc.partialUpdate(c)
	case fullUpdate:
		return nc.fullUpdate()
	default:
		log.Trace().Msgf("ignoring change: %v", c)
		return nil
	}
}

// compressAndVersion atomically reads the compression and version settings
func (nc *nodeConn) compressAndVersion() (compress string, version tailcfg.CapabilityVersion) {
	nc.mu.RLock()
	defer nc.mu.RUnlock()
	return nc.compress, nc.version
}

func (nc *nodeConn) partialUpdate(c change.Change) error {
	var data []byte
	var err error
	if c.DERPChanged {
		compress, _ := nc.compressAndVersion()
		data, err = nc.mapper.derpMapResponse(nc.id, compress)
	}

	// TODO(kradalby): key update change

	if err != nil {
		return err
	}

	return nc.send(data)
}

func (nc *nodeConn) fullUpdate() error {
	compress, version := nc.compressAndVersion()
	data, err := nc.mapper.fullMapResponse(nc.id, version, compress)
	if err != nil {
		return err
	}

	return nc.send(data)
}

// send attempts to send data to the node's channel with proper synchronization.
// If the channel is closed by its creator (HTTP handler), the send will fail gracefully.
func (nc *nodeConn) send(data []byte) error {
	nc.mu.RLock()
	defer nc.mu.RUnlock()

	select {
	case nc.c <- data:
		return nil
	default:
		// Channel is full, don't block
		return fmt.Errorf("unable to send to node %d: channel full", nc.id)
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
