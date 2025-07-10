package mapper

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/puzpuzpuz/xsync/v4"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

// LockFreeBatcher uses atomic operations and concurrent maps to eliminate mutex contention
type LockFreeBatcher struct {
	tick    *time.Ticker
	mapper  *mapper
	workers int

	// Lock-free concurrent maps
	nodes     *xsync.Map[types.NodeID, *nodeConnLockFree]
	connected *xsync.Map[types.NodeID, *time.Time]

	// Single-writer channel for coordination
	cancelCh chan struct{}
	workCh   chan work

	// Metrics counters
	totalNodes   atomic.Int64
	totalUpdates atomic.Int64
}

func NewLockFreeBatcher(batchTime time.Duration, workers int, mapper *mapper) *LockFreeBatcher {
	return &LockFreeBatcher{
		mapper:    mapper,
		workers:   workers,
		tick:      time.NewTicker(batchTime),
		cancelCh:  make(chan struct{}),
		workCh:    make(chan work, (1<<16)-1),
		nodes:     xsync.NewMap[types.NodeID, *nodeConnLockFree](),
		connected: xsync.NewMap[types.NodeID, *time.Time](),
	}
}

// NewLockFreeBatcherAndMapper creates a LockFreeBatcher implementation
func NewLockFreeBatcherAndMapper(cfg *types.Config, state *state.State) Batcher {
	m := newMapper(cfg, state)
	b := NewLockFreeBatcher(cfg.Tuning.BatchChangeDelay, cfg.Tuning.BatcherWorkers, m)
	m.batcher = b
	return b
}

// AddNode is now lock-free - uses atomic operations
func (b *LockFreeBatcher) AddNode(id types.NodeID, c chan<- []byte, compress string, version tailcfg.CapabilityVersion) {
	// Create or update node atomically
	newConn := newNodeConnLockFree(id, c, compress, version, b.mapper)

	// Atomic store - if exists, this will update in place
	if existing, loaded := b.nodes.LoadOrStore(id, newConn); loaded {
		// Update existing connection using lock-free methods
		existing.updateConnection(c, compress, version)

		// Note: We don't close the old channel - it will be garbage collected when the
		// HTTP handler's mapSession goes out of scope. Closing from here can cause race conditions.
	} else {
		// New node - increment counter
		b.totalNodes.Add(1)
	}

	// Mark as connected atomically
	b.connected.Store(id, nil) // nil = connected

	// Generate work without blocking
	b.addWorkLockFree(change.ChangeSet{NodeID: id, Change: change.NodeCameOnline})
}

// RemoveNode is lock-free
func (b *LockFreeBatcher) RemoveNode(id types.NodeID, c chan<- []byte) {
	// Check if this is the current connection
	if existing, ok := b.nodes.Load(id); ok {
		if !existing.matchesChannel(c) {
			return // Not the current connection
		}
	}

	// Remove node and mark disconnected atomically
	b.nodes.Delete(id)
	b.connected.Store(id, ptr.To(time.Now()))
	b.totalNodes.Add(-1)

	// Notify other nodes that this node went offline
	b.addWorkLockFree(change.ChangeSet{NodeID: id, Change: change.NodeWentOffline})
}

// AddWork is completely lock-free
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
				nc.change(w.c)
			}
		case <-b.cancelCh:
			return
		}
	}
}

func (b *LockFreeBatcher) addWorkLockFree(c change.ChangeSet) {
	b.nodes.Range(func(nodeID types.NodeID, _ *nodeConnLockFree) bool {
		// If this is a node-specific change, don't send it to the same node
		if c.NodeID != 0 && c.NodeID == nodeID {
			return true // continue
		}
		select {
		case b.workCh <- work{c, nodeID}:
		default:
			// Channel full - drop work item (could add metrics here)
		}
		return true
	})
}

// IsConnected is lock-free read
func (b *LockFreeBatcher) IsConnected(id types.NodeID) bool {
	if val, ok := b.connected.Load(id); ok {
		return val == nil // nil means connected
	}
	return false
}

// ConnectedMap returns a lock-free map of all connected nodes
func (b *LockFreeBatcher) ConnectedMap() *xsync.Map[types.NodeID, bool] {
	ret := xsync.NewMap[types.NodeID, bool]()

	b.connected.Range(func(id types.NodeID, val *time.Time) bool {
		ret.Store(id, val == nil) // nil means connected
		return true
	})

	return ret
}

// GetMetrics provides lock-free access to counters
func (b *LockFreeBatcher) GetMetrics() (nodes, updates int64) {
	return b.totalNodes.Load(), b.totalUpdates.Load()
}

// Connection data structure for atomic updates
type connectionData struct {
	c        chan<- []byte
	compress string
	version  tailcfg.CapabilityVersion
}

// Lock-free nodeConn using atomic pointers
type nodeConnLockFree struct {
	id     types.NodeID
	mapper *mapper

	// Atomic pointer to connection data - allows lock-free updates
	connData atomic.Pointer[connectionData]

	// Optional: statistics
	updateCount atomic.Int64
	errorCount  atomic.Int64
}

func newNodeConnLockFree(id types.NodeID, c chan<- []byte, compress string, version tailcfg.CapabilityVersion, mapper *mapper) *nodeConnLockFree {
	nc := &nodeConnLockFree{
		id:     id,
		mapper: mapper,
	}

	// Initialize connection data
	data := &connectionData{
		c:        c,
		compress: compress,
		version:  version,
	}
	nc.connData.Store(data)

	return nc
}

// updateConnection atomically updates connection parameters
func (nc *nodeConnLockFree) updateConnection(c chan<- []byte, compress string, version tailcfg.CapabilityVersion) {
	newData := &connectionData{
		c:        c,
		compress: compress,
		version:  version,
	}
	nc.connData.Store(newData)
}

// matchesChannel checks if the given channel matches current connection
func (nc *nodeConnLockFree) matchesChannel(c chan<- []byte) bool {
	data := nc.connData.Load()
	if data == nil {
		return false
	}
	// Compare channel pointers directly
	return data.c == c
}

// compressAndVersion atomically reads connection settings
func (nc *nodeConnLockFree) compressAndVersion() (string, tailcfg.CapabilityVersion) {
	data := nc.connData.Load()
	if data == nil {
		return "", 0
	}
	return data.compress, data.version
}

func (nc *nodeConnLockFree) nodeID() types.NodeID {
	return nc.id
}

func (nc *nodeConnLockFree) change(c change.ChangeSet) error {
	err := handleNodeChange(nc, nc.mapper, c)
	if err != nil {
		nc.errorCount.Add(1)
	}
	return err
}

// send attempts non-blocking send
func (nc *nodeConnLockFree) send(data []byte) error {
	connData := nc.connData.Load()
	if connData == nil {
		return fmt.Errorf("node %d: no connection data", nc.id)
	}

	select {
	case connData.c <- data:
		nc.updateCount.Add(1)
		return nil
	default:
		nc.errorCount.Add(1)
		return fmt.Errorf("node %d: channel full or closed", nc.id)
	}
}

// GetStats returns lock-free statistics
func (nc *nodeConnLockFree) GetStats() (updates, errors int64) {
	return nc.updateCount.Load(), nc.errorCount.Load()
}

// Add missing methods for compatibility
func (nc *nodeConnLockFree) updateConnectionUnsafe(c chan<- []byte, compress string, version tailcfg.CapabilityVersion) {
	nc.updateConnection(c, compress, version)
}

func (nc *nodeConnLockFree) matchesChannelUnsafe(c chan<- []byte) bool {
	return nc.matchesChannel(c)
}
