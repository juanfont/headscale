package mapper

import (
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/routes"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/rs/zerolog/log"
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

type Batcher struct {
	mu deadlock.RWMutex

	mapper *mapper

	// connected is a map of NodeID to the time the closed a connection.
	// This is used to track which nodes are currently connected.
	// If value is nil, the node is connected
	// If value is not nil, the node is disconnected
	connected map[types.NodeID]*time.Time

	// nodes is a map of NodeID to a channel that is used to send generated
	// mapResp to a client.
	nodes map[types.NodeID]nodeConn

	// TODO: we will probably have more workers, but for now,
	// this should serve for the experiment.
	cancelCh chan struct{}

	workCh chan *types.Change
}

func NewBatcherAndMapper(
	db *db.HSDatabase,
	cfg *types.Config,
	derpMap *tailcfg.DERPMap,
	polMan policy.PolicyManager,
	primary *routes.PrimaryRoutes,
) *Batcher {
	mapper := newMapper(db, cfg, derpMap, polMan, primary)
	b := NewBatcher(mapper)
	mapper.batcher = b

	return b
}

func NewBatcher(mapper *mapper) *Batcher {
	return &Batcher{
		mapper:   mapper,
		cancelCh: make(chan struct{}),
		// TODO: No limit for now, this needs to be changed
		workCh: make(chan *types.Change, (1<<16)-1),

		nodes:     make(map[types.NodeID]nodeConn),
		connected: make(map[types.NodeID]*time.Time),
	}
}

func (b *Batcher) Close() {
	b.cancelCh <- struct{}{}
}

func (b *Batcher) Start() {
	go b.doWork()
}

func (b *Batcher) AddNode(id types.NodeID, c chan<- []byte, compress string, version tailcfg.CapabilityVersion) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// If a channel exists, it means the node has opened a new
	// connection. Close the old channel and replace it.
	if curr, ok := b.nodes[id]; ok {
		// Use the safeCloseChannel helper in a goroutine to avoid deadlocks
		// if/when someone is waiting to send on this channel
		go func(nc nodeConn) {
			close(nc.c)
		}(curr)
	}

	b.nodes[id] = nodeConn{
		id:       id,
		c:        c,
		compress: compress,
		version:  version,

		// TODO(kradalby): Not sure about this one yet.
		mapper: b.mapper,
	}
	b.connected[id] = nil // nil means connected

	// TODO(kradalby): Handle:
	// - Updating peers with online status
	// - Updating routes in routemanager and peers
	b.AddWork(&types.Change{NodeChange: types.NodeChange{
		ID:     id,
		Online: true,
	}})
}

func (b *Batcher) RemoveNode(id types.NodeID, c chan<- []byte) {
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

func (b *Batcher) AddWork(change *types.Change) {
	log.Trace().Msgf("adding work: %v", change)
	b.workCh <- change
}

func (b *Batcher) IsConnected(id types.NodeID) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// If the value is nil, it means the node is connected
	if b.connected[id] == nil {
		return true
	}

	// If the value is not nil, it means the node is disconnected
	return false
}

func (b *Batcher) IsLikelyConnected(id types.NodeID) bool {
	return b.isLikelyConnectedLocked(id)
}

func (b *Batcher) isLikelyConnectedLocked(id types.NodeID) bool {
	// If the value is nil, it means the node is connected
	if b.connected[id] == nil {
		return true
	}

	// If the value is not nil, it means the node is disconnected
	// but we check if it was disconnected recently (within 5 seconds)
	if time.Since(*b.connected[id]) < 10*time.Second {
		return true
	}

	return false
}

func (b *Batcher) LikelyConnectedMap() *xsync.MapOf[types.NodeID, bool] {
	b.mu.RLock()
	defer b.mu.RUnlock()

	ret := xsync.NewMapOf[types.NodeID, bool]()

	for id := range b.connected {
		ret.Store(id, b.isLikelyConnectedLocked(id))
	}

	return ret
}

func (b *Batcher) doWork() {
	for {
		select {
		case <-b.cancelCh:
			return
		case work := <-b.workCh:
			b.processChange(work)
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
func (b *Batcher) processChange(c *types.Change) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	log.Trace().Msgf("processing work: %v", c)

	for id, node := range b.nodes {
		err := node.change(c)
		log.Error().Err(err).Uint64("node.id", id.Uint64()).Msgf("processing work for node %d", id)
	}
}

type nodeConn struct {
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

func determineChange(c *types.Change) changeUpdate {
	if c == nil {
		return ignoreUpdate
	}

	if c.DERPChanged {
		return partialUpdate
	}

	// TODO(kradalby): Make policy a partial update?
	if c.PolicyChanged {
		return fullUpdate
	}

	if c.NodeChange.ID != 0 {
		if c.NodeChange.OnlyKeyChange() {
			return partialUpdate
		}

		if c.NodeChange.ImportantNodeChange() {
			return fullUpdate
		}
	}

	if c.FullUpdate() {
		return fullUpdate
	}

	return fullUpdate
}

func (nc *nodeConn) change(c *types.Change) error {
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

func (nc *nodeConn) partialUpdate(c *types.Change) error {
	var data []byte
	var err error
	if c.DERPChanged {
		data, err = nc.mapper.derpMapResponse(nc.id, nc.compress)
	}

	// TODO(kradalby): key update change

	if err != nil {
		return err
	}

	nc.c <- data
	return nil
}

func (nc *nodeConn) fullUpdate() error {
	data, err := nc.mapper.fullMapResponse(nc.id, nc.version, nc.compress)
	if err != nil {
		return err
	}

	nc.c <- data
	return nil
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
