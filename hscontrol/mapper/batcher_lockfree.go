package mapper

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

// LockFreeBatcher uses atomic operations and concurrent maps to eliminate mutex contention.
type LockFreeBatcher struct {
	tick    *time.Ticker
	mapper  *mapper
	workers int

	// Lock-free concurrent maps
	nodes     *xsync.Map[types.NodeID, *nodeConn]
	connected *xsync.Map[types.NodeID, *time.Time]

	// Single-writer channel for coordination
	cancelCh chan struct{}
	workCh   chan work

	// Metrics counters
	totalNodes   atomic.Int64
	totalUpdates atomic.Int64
}

// AddNode is now lock-free - uses atomic operations.
// TODO(kradalby): See if we can move the isRouter argument somewhere else.
func (b *LockFreeBatcher) AddNode(id types.NodeID, c chan<- *tailcfg.MapResponse, isRouter bool, compress string, version tailcfg.CapabilityVersion) {
	// Create or update node atomically
	newConn := newNodeConn(id, c, compress, version, b.mapper)

	// Atomic store - if exists, this will update in place
	if existing, loaded := b.nodes.LoadOrStore(id, newConn); loaded {
		// Update existing connection using lock-free methods
		existing.updateConnection(c, compress, version)

		// Note: We don't close the old channel - it will be garbage collected when the
		// HTTP handler's mapSession goes out of scope. Closing from here can cause race conditions.
	} else {
		b.totalNodes.Add(1)
	}

	// Send initial full map to the node
	b.addWorkLockFree(change.FullSelf(id))

	// Mark as connected atomically AFTER sending initial map
	b.connected.Store(id, nil) // nil = connected

	// Tell other nodes that this node came online
	b.addWorkLockFree(change.ChangeSet{NodeID: id, Change: change.NodeCameOnline, IsSubnetRouter: isRouter})
}

// RemoveNode is lock-free.
func (b *LockFreeBatcher) RemoveNode(id types.NodeID, c chan<- *tailcfg.MapResponse, isRouter bool) {
	// Check if this is the current connection and mark it as closed
	if existing, ok := b.nodes.Load(id); ok {
		if !existing.matchesChannel(c) {
			return // Not the current connection
		}

		// Mark the connection as closed to prevent further sends
		if connData := existing.connData.Load(); connData != nil {
			connData.closed.Store(true)
		}
	}

	// Remove node and mark disconnected atomically
	b.nodes.Delete(id)
	b.connected.Store(id, ptr.To(time.Now()))
	b.totalNodes.Add(-1)

	// Notify other nodes that this node went offline
	b.addWorkLockFree(change.ChangeSet{NodeID: id, Change: change.NodeWentOffline, IsSubnetRouter: isRouter})
}

// AddWork is completely lock-free.
func (b *LockFreeBatcher) AddWork(c change.ChangeSet) {
	b.addWorkLockFree(c)
}

func (b *LockFreeBatcher) Start() {
	go b.doWork()
}

func (b *LockFreeBatcher) Close() {
	close(b.cancelCh)
	close(b.workCh)
}

func (b *LockFreeBatcher) doWork() {
	for range b.workers {
		go b.worker()
	}

	for {
		select {
		case <-b.cancelCh:
			return
		case <-b.tick.C:
			// No batching in this simplified implementation
		}
	}
}

func (b *LockFreeBatcher) worker() {
	for {
		select {
		case w, ok := <-b.workCh:
			if !ok {
				return
			}
			if nc, exists := b.nodes.Load(w.nodeID); exists {
				err := nc.change(w.c)
				if err != nil {
					log.Error().Err(err).Uint64("node.id", w.c.NodeID.Uint64()).Str("change", w.c.Change.String()).Msg("failed to apply change")
				}
			}
		case <-b.cancelCh:
			return
		}
	}
}

func (b *LockFreeBatcher) addWorkLockFree(c change.ChangeSet) {
	// Fast path for self-update only
	if c.SelfUpdateOnly {
		b.workCh <- work{c, c.NodeID}
		return
	}
	b.nodes.Range(func(nodeID types.NodeID, _ *nodeConn) bool {
		// If this is a node-specific change, don't send it to the same node
		// except for NodeNewOrUpdate changes which need to be sent to the node itself
		if c.NodeID == nodeID && !c.AlsoSelf() {
			return true
		}

		// We need to ensure the update is put on the work channel.
		// This channel should be sizable enough to not block, if it does,
		// we might need to increase its size.
		b.workCh <- work{c, nodeID}
		return true
	})
}

// IsConnected is lock-free read.
func (b *LockFreeBatcher) IsConnected(id types.NodeID) bool {
	if val, ok := b.connected.Load(id); ok {
		// nil means connected
		return val == nil
	}
	return false
}

// ConnectedMap returns a lock-free map of all connected nodes.
func (b *LockFreeBatcher) ConnectedMap() *xsync.Map[types.NodeID, bool] {
	ret := xsync.NewMap[types.NodeID, bool]()

	b.connected.Range(func(id types.NodeID, val *time.Time) bool {
		// nil means connected
		ret.Store(id, val == nil)
		return true
	})

	return ret
}

// connectionData holds the channel and connection parameters.
type connectionData struct {
	c       chan<- *tailcfg.MapResponse
	version tailcfg.CapabilityVersion
	closed  atomic.Bool // Track if this connection has been closed
}

// nodeConn described the node connection and its associated data.
type nodeConn struct {
	id     types.NodeID
	mapper *mapper

	// Atomic pointer to connection data - allows lock-free updates
	connData atomic.Pointer[connectionData]

	updateCount atomic.Int64
}

func newNodeConn(id types.NodeID, c chan<- *tailcfg.MapResponse, compress string, version tailcfg.CapabilityVersion, mapper *mapper) *nodeConn {
	nc := &nodeConn{
		id:     id,
		mapper: mapper,
	}

	// Initialize connection data
	data := &connectionData{
		c:       c,
		version: version,
	}
	nc.connData.Store(data)

	return nc
}

// updateConnection atomically updates connection parameters.
func (nc *nodeConn) updateConnection(c chan<- *tailcfg.MapResponse, compress string, version tailcfg.CapabilityVersion) {
	newData := &connectionData{
		c:       c,
		version: version,
	}
	nc.connData.Store(newData)
}

// matchesChannel checks if the given channel matches current connection.
func (nc *nodeConn) matchesChannel(c chan<- *tailcfg.MapResponse) bool {
	data := nc.connData.Load()
	if data == nil {
		return false
	}
	// Compare channel pointers directly
	return data.c == c
}

// compressAndVersion atomically reads connection settings.
func (nc *nodeConn) version() tailcfg.CapabilityVersion {
	data := nc.connData.Load()
	if data == nil {
		return 0
	}

	return data.version
}

func (nc *nodeConn) nodeID() types.NodeID {
	return nc.id
}

func (nc *nodeConn) change(c change.ChangeSet) error {
	return handleNodeChange(nc, nc.mapper, c)
}

// send sends data to the node's channel.
// The node will pick it up and send it to the HTTP handler.
func (nc *nodeConn) send(data *tailcfg.MapResponse) error {
	connData := nc.connData.Load()
	if connData == nil {
		return fmt.Errorf("node %d: no connection data", nc.id)
	}

	// Check if connection has been closed
	if connData.closed.Load() {
		return fmt.Errorf("node %d: connection closed", nc.id)
	}

	// TODO(kradalby): We might need some sort of timeout here if the client is not reading
	// the channel. That might mean that we are sending to a node that has gone offline, but
	// the channel is still open.
	connData.c <- data
	nc.updateCount.Add(1)
	return nil
}
