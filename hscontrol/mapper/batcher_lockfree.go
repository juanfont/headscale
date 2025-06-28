package mapper

import (
	"sync/atomic"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/puzpuzpuz/xsync/v4"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

// LockFreeBatcher uses atomic operations and concurrent maps to eliminate mutex contention
type LockFreeBatcher struct {
	tick   *time.Ticker
	mapper *mapper

	// Lock-free concurrent maps - no mutex needed
	nodes     *xsync.Map[types.NodeID, *nodeConnLockFree] // Lock-free nodeConn
	connected *xsync.Map[types.NodeID, *time.Time]        // Replaces map[types.NodeID]*time.Time

	// Atomic flags for partial changes - eliminates mutex on reads
	hasPartialChanges atomic.Bool
	partialChanges    *xsync.Map[types.NodeID, change.Change]

	// Single-writer channel for coordination
	cancelCh chan struct{}
	workCh   chan work

	// Atomic counters for metrics
	totalNodes    atomic.Int64
	totalUpdates  atomic.Int64
}

func NewLockFreeBatcher(batchTime time.Duration, mapper *mapper) *LockFreeBatcher {
	return &LockFreeBatcher{
		mapper:         mapper,
		tick:           time.NewTicker(batchTime),
		cancelCh:       make(chan struct{}),
		workCh:         make(chan work, (1<<16)-1),
		nodes:          xsync.NewMap[types.NodeID, *nodeConnLockFree](),
		connected:      xsync.NewMap[types.NodeID, *time.Time](),
		partialChanges: xsync.NewMap[types.NodeID, change.Change](),
	}
}

// AddNode is now lock-free - uses atomic operations
func (b *LockFreeBatcher) AddNode(id types.NodeID, c chan<- []byte, compress string, version tailcfg.CapabilityVersion) {
	// Create or update node atomically
	newConn := newNodeConnLockFree(id, c, compress, version, b.mapper)

	// Atomic store - if exists, this will update in place
	if existing, loaded := b.nodes.LoadOrStore(id, newConn); loaded {
		// Update existing connection using lock-free methods
		existing.updateConnection(c, compress, version)
	} else {
		// New node - increment counter
		b.totalNodes.Add(1)
	}

	// Mark as connected atomically
	b.connected.Store(id, nil) // nil = connected

	// Generate work without blocking
	chg := change.NodeOnline(id)
	b.addWorkLockFree(chg)
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
}

// AddWork is completely lock-free
func (b *LockFreeBatcher) AddWork(c change.Change) {
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
	// Start workers
	for i := 0; i < 4; i++ {
		go b.worker()
	}

	for {
		select {
		case <-b.cancelCh:
			return
		case <-b.tick.C:
			b.flushLockFree(false)
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

func (b *LockFreeBatcher) addWorkLockFree(c change.Change) {
	switch determineChange(c) {
	case partialUpdate:
		b.addPartialLockFree(c)
	case fullUpdate:
		b.flushLockFree(true)
	}
}

func (b *LockFreeBatcher) addPartialLockFree(c change.Change) {
	// Merge with existing change if present
	if existing, loaded := b.partialChanges.LoadOrStore(c.Node.ID, c); loaded {
		merged := existing.Merge(c)
		b.partialChanges.Store(c.Node.ID, merged)
	}
	
	// Set flag atomically
	b.hasPartialChanges.Store(true)
}

func (b *LockFreeBatcher) flushLockFree(full bool) {
	if full {
		// Clear partial changes
		b.hasPartialChanges.Store(false)
		b.partialChanges.Clear()

		// Send full updates to all nodes
		b.nodes.Range(func(nodeID types.NodeID, _ *nodeConnLockFree) bool {
			select {
			case b.workCh <- work{change.Full, nodeID}:
			default:
				// Channel full - drop work item (could add metrics here)
			}
			return true
		})
	}

	if b.hasPartialChanges.Load() {
		// Process partial changes
		b.partialChanges.Range(func(nodeID types.NodeID, c change.Change) bool {
			// Send to all nodes
			b.nodes.Range(func(targetID types.NodeID, _ *nodeConnLockFree) bool {
				select {
				case b.workCh <- work{c, targetID}:
				default:
					// Channel full - could add backpressure handling
				}
				return true
			})
			return true
		})

		// Clear partial changes
		b.hasPartialChanges.Store(false)
		b.partialChanges.Clear()
	}
}

// IsConnected is lock-free read
func (b *LockFreeBatcher) IsConnected(id types.NodeID) bool {
	if val, ok := b.connected.Load(id); ok {
		return val == nil // nil means connected
	}
	return false
}

// IsLikelyConnected is lock-free read with same logic as original batcher
func (b *LockFreeBatcher) IsLikelyConnected(id types.NodeID) bool {
	if val, ok := b.connected.Load(id); ok {
		return val == nil // nil means connected
	}
	return false
}

// LikelyConnectedMap returns a lock-free map of all connected nodes
func (b *LockFreeBatcher) LikelyConnectedMap() *xsync.Map[types.NodeID, bool] {
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