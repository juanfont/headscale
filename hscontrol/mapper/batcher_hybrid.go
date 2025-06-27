package mapper

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/puzpuzpuz/xsync/v4"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

// BatchOperation represents a batched set of operations to reduce lock contention
type BatchOperation struct {
	AddNodes    []AddNodeOp
	RemoveNodes []RemoveNodeOp
	WorkItems   []change.Change
	timestamp   time.Time
}

type AddNodeOp struct {
	ID       types.NodeID
	Channel  chan<- []byte
	Compress string
	Version  tailcfg.CapabilityVersion
}

type RemoveNodeOp struct {
	ID      types.NodeID
	Channel chan<- []byte
}

// HybridBatcher combines lock-free reads with batched writes
type HybridBatcher struct {
	tick   *time.Ticker
	mapper *mapper

	// Lock-free concurrent maps for fast reads
	nodes     *xsync.Map[types.NodeID, *nodeConn]
	connected *xsync.Map[types.NodeID, *time.Time]

	// Batching system to reduce write contention
	batchCh   chan BatchOperation
	workCh    chan work
	cancelCh  chan struct{}

	// Partial changes with minimal locking
	partialMu      sync.RWMutex // Only for partial changes
	partialChanges map[types.NodeID]change.Change
	hasPartialChanges atomic.Bool

	// Batch aggregation
	currentBatch   BatchOperation
	batchMu        sync.Mutex
	batchTimer     *time.Timer
	maxBatchSize   int
	maxBatchDelay  time.Duration

	// Worker pool
	workers sync.WaitGroup

	// Metrics
	batchCount    atomic.Int64
	operationCount atomic.Int64
}

func NewHybridBatcher(batchTime time.Duration, mapper *mapper) *HybridBatcher {
	return &HybridBatcher{
		mapper:         mapper,
		tick:           time.NewTicker(batchTime),
		batchCh:        make(chan BatchOperation, 100),
		workCh:         make(chan work, (1<<16)-1),
		cancelCh:       make(chan struct{}),
		nodes:          xsync.NewMap[types.NodeID, *nodeConn](),
		connected:      xsync.NewMap[types.NodeID, *time.Time](),
		partialChanges: make(map[types.NodeID]change.Change),
		maxBatchSize:   50,   // Max operations per batch
		maxBatchDelay:  5 * time.Millisecond, // Max time to wait for batch
	}
}

func (b *HybridBatcher) Start() {
	go b.batchProcessor()
	go b.tickHandler()
	
	// Start worker pool
	for i := 0; i < 4; i++ {
		b.workers.Add(1)
		go b.worker()
	}
}

func (b *HybridBatcher) Close() {
	close(b.cancelCh)
	b.workers.Wait()
}

// Fast path: lock-free reads
func (b *HybridBatcher) IsConnected(id types.NodeID) bool {
	if val, ok := b.connected.Load(id); ok {
		return val == nil
	}
	return false
}

// IsLikelyConnected provides lock-free read with same logic as original batcher
func (b *HybridBatcher) IsLikelyConnected(id types.NodeID) bool {
	if val, ok := b.connected.Load(id); ok {
		return val == nil
	}
	return false
}

func (b *HybridBatcher) GetNodeCount() int {
	count := 0
	b.nodes.Range(func(_ types.NodeID, _ *nodeConn) bool {
		count++
		return true
	})
	return count
}

// Batched operations for writes
func (b *HybridBatcher) AddNode(id types.NodeID, c chan<- []byte, compress string, version tailcfg.CapabilityVersion) {
	op := AddNodeOp{
		ID:       id,
		Channel:  c,
		Compress: compress,
		Version:  version,
	}
	
	b.addToBatch(func(batch *BatchOperation) {
		batch.AddNodes = append(batch.AddNodes, op)
	})
}

func (b *HybridBatcher) RemoveNode(id types.NodeID, c chan<- []byte) {
	op := RemoveNodeOp{
		ID:      id,
		Channel: c,
	}
	
	b.addToBatch(func(batch *BatchOperation) {
		batch.RemoveNodes = append(batch.RemoveNodes, op)
	})
}

func (b *HybridBatcher) AddWork(c change.Change) {
	b.addToBatch(func(batch *BatchOperation) {
		batch.WorkItems = append(batch.WorkItems, c)
	})
}

// Batch aggregation with automatic flushing
func (b *HybridBatcher) addToBatch(fn func(*BatchOperation)) {
	b.batchMu.Lock()
	defer b.batchMu.Unlock()

	// Initialize batch if empty
	if len(b.currentBatch.AddNodes) == 0 && len(b.currentBatch.RemoveNodes) == 0 && len(b.currentBatch.WorkItems) == 0 {
		b.currentBatch.timestamp = time.Now()
		// Set timer for maximum batch delay
		if b.batchTimer != nil {
			b.batchTimer.Stop()
		}
		b.batchTimer = time.AfterFunc(b.maxBatchDelay, b.flushCurrentBatch)
	}

	// Add operation to current batch
	fn(&b.currentBatch)

	// Flush if batch is full
	totalOps := len(b.currentBatch.AddNodes) + len(b.currentBatch.RemoveNodes) + len(b.currentBatch.WorkItems)
	if totalOps >= b.maxBatchSize {
		b.flushCurrentBatchLocked()
	}
}

func (b *HybridBatcher) flushCurrentBatch() {
	b.batchMu.Lock()
	defer b.batchMu.Unlock()
	b.flushCurrentBatchLocked()
}

func (b *HybridBatcher) flushCurrentBatchLocked() {
	if len(b.currentBatch.AddNodes) == 0 && len(b.currentBatch.RemoveNodes) == 0 && len(b.currentBatch.WorkItems) == 0 {
		return
	}

	// Send batch for processing
	select {
	case b.batchCh <- b.currentBatch:
		b.batchCount.Add(1)
		b.operationCount.Add(int64(len(b.currentBatch.AddNodes) + len(b.currentBatch.RemoveNodes) + len(b.currentBatch.WorkItems)))
	case <-b.cancelCh:
		return
	default:
		// Batch channel full - could add metrics for dropped batches
	}

	// Reset current batch
	b.currentBatch = BatchOperation{}
	if b.batchTimer != nil {
		b.batchTimer.Stop()
		b.batchTimer = nil
	}
}

// Batch processor handles all write operations
func (b *HybridBatcher) batchProcessor() {
	for {
		select {
		case batch := <-b.batchCh:
			b.processBatch(batch)
		case <-b.cancelCh:
			return
		}
	}
}

func (b *HybridBatcher) processBatch(batch BatchOperation) {
	// Process all add node operations
	for _, op := range batch.AddNodes {
		newConn := &nodeConn{
			id:       op.ID,
			c:        op.Channel,
			compress: op.Compress,
			version:  op.Version,
			mapper:   b.mapper,
		}

		if existing, loaded := b.nodes.LoadOrStore(op.ID, newConn); loaded {
			existing.updateConnectionUnsafe(op.Channel, op.Compress, op.Version)
		}

		b.connected.Store(op.ID, nil) // connected
		
		// Generate online event
		chg := change.NodeOnline(op.ID)
		b.processWorkItem(chg)
	}

	// Process remove node operations
	for _, op := range batch.RemoveNodes {
		if existing, ok := b.nodes.Load(op.ID); ok {
			if existing.matchesChannelUnsafe(op.Channel) {
				b.nodes.Delete(op.ID)
				b.connected.Store(op.ID, ptr.To(time.Now()))
			}
		}
	}

	// Process work items
	for _, workItem := range batch.WorkItems {
		b.processWorkItem(workItem)
	}
}

func (b *HybridBatcher) processWorkItem(c change.Change) {
	switch determineChange(c) {
	case partialUpdate:
		b.addPartialChange(c)
	case fullUpdate:
		b.flushPartialChanges(true)
	}
}

// Partial changes with minimal locking
func (b *HybridBatcher) addPartialChange(c change.Change) {
	b.partialMu.Lock()
	if existing, ok := b.partialChanges[c.Node.ID]; ok {
		b.partialChanges[c.Node.ID] = existing.Merge(c)
	} else {
		b.partialChanges[c.Node.ID] = c
	}
	b.partialMu.Unlock()
	
	b.hasPartialChanges.Store(true)
}

func (b *HybridBatcher) flushPartialChanges(full bool) {
	if full {
		b.hasPartialChanges.Store(false)
		b.partialMu.Lock()
		clear(b.partialChanges)
		b.partialMu.Unlock()

		// Send full updates to all nodes
		b.nodes.Range(func(nodeID types.NodeID, _ *nodeConn) bool {
			select {
			case b.workCh <- work{change.Full, nodeID}:
			default:
				// Channel full
			}
			return true
		})
	}

	if b.hasPartialChanges.Load() {
		b.partialMu.RLock()
		changes := make(map[types.NodeID]change.Change)
		for nodeID, c := range b.partialChanges {
			changes[nodeID] = c
		}
		b.partialMu.RUnlock()

		// Send partial updates
		for _, c := range changes {
			b.nodes.Range(func(nodeID types.NodeID, _ *nodeConn) bool {
				select {
				case b.workCh <- work{c, nodeID}:
				default:
					// Channel full
				}
				return true
			})
		}

		b.hasPartialChanges.Store(false)
		b.partialMu.Lock()
		clear(b.partialChanges)
		b.partialMu.Unlock()
	}
}

func (b *HybridBatcher) tickHandler() {
	for {
		select {
		case <-b.tick.C:
			b.flushPartialChanges(false)
		case <-b.cancelCh:
			return
		}
	}
}

func (b *HybridBatcher) worker() {
	defer b.workers.Done()
	
	for {
		select {
		case w, ok := <-b.workCh:
			if !ok {
				return
			}
			
			if nodeConn, exists := b.nodes.Load(w.nodeID); exists {
				nodeConn.change(w.c)
			}
			
		case <-b.cancelCh:
			return
		}
	}
}

// GetMetrics returns performance metrics
func (b *HybridBatcher) GetMetrics() (batches, operations int64, avgBatchSize float64) {
	batchCount := b.batchCount.Load()
	opCount := b.operationCount.Load()
	
	if batchCount > 0 {
		avgBatchSize = float64(opCount) / float64(batchCount)
	}
	
	return batchCount, opCount, avgBatchSize
}

// LikelyConnectedMap returns a map of all connected nodes using lock-free reads
func (b *HybridBatcher) LikelyConnectedMap() *xsync.Map[types.NodeID, bool] {
	ret := xsync.NewMap[types.NodeID, bool]()
	
	b.connected.Range(func(id types.NodeID, val *time.Time) bool {
		ret.Store(id, val == nil) // nil means connected
		return true
	})
	
	return ret
}