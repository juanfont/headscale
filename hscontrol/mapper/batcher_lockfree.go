package mapper

import (
	"context"
	"fmt"
	"sync"
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

	// Work queue channel
	workCh chan work
	ctx    context.Context
	cancel context.CancelFunc

	// Batching state
	pendingChanges *xsync.Map[types.NodeID, []change.ChangeSet]
	batchMutex     sync.RWMutex

	// Metrics
	totalNodes      atomic.Int64
	totalUpdates    atomic.Int64
	workQueuedCount atomic.Int64
	workProcessed   atomic.Int64
	workErrors      atomic.Int64
}

// AddNode registers a new node connection with the batcher and sends an initial map response.
// It creates or updates the node's connection data, validates the initial map generation,
// and notifies other nodes that this node has come online.
// TODO(kradalby): See if we can move the isRouter argument somewhere else.
func (b *LockFreeBatcher) AddNode(id types.NodeID, c chan<- *tailcfg.MapResponse, isRouter bool, version tailcfg.CapabilityVersion) error {
	// First validate that we can generate initial map before doing anything else
	fullSelfChange := change.FullSelf(id)

	// TODO(kradalby): This should not be generated here, but rather in MapResponseFromChange.
	// This currently means that the goroutine for the node connection will do the processing
	// which means that we might have uncontrolled concurrency.
	// When we use MapResponseFromChange, it will be processed by the same worker pool, causing
	// it to be processed in a more controlled manner.
	initialMap, err := generateMapResponse(id, version, b.mapper, fullSelfChange)
	if err != nil {
		return fmt.Errorf("failed to generate initial map for node %d: %w", id, err)
	}

	// Only after validation succeeds, create or update node connection
	newConn := newNodeConn(id, c, version, b.mapper)

	var conn *nodeConn
	if existing, loaded := b.nodes.LoadOrStore(id, newConn); loaded {
		// Update existing connection
		existing.updateConnection(c, version)
		conn = existing
	} else {
		b.totalNodes.Add(1)
		conn = newConn
	}

	// Mark as connected only after validation succeeds
	b.connected.Store(id, nil) // nil = connected

	log.Info().Uint64("node.id", id.Uint64()).Bool("isRouter", isRouter).Msg("Node connected to batcher")

	// Send the validated initial map
	if initialMap != nil {
		if err := conn.send(initialMap); err != nil {
			// Clean up the connection state on send failure
			b.nodes.Delete(id)
			b.connected.Delete(id)
			return fmt.Errorf("failed to send initial map to node %d: %w", id, err)
		}

		// Notify other nodes that this node came online
		b.addWork(change.ChangeSet{NodeID: id, Change: change.NodeCameOnline, IsSubnetRouter: isRouter})
	}

	return nil
}

// RemoveNode disconnects a node from the batcher, marking it as offline and cleaning up its state.
// It validates the connection channel matches the current one, closes the connection,
// and notifies other nodes that this node has gone offline.
func (b *LockFreeBatcher) RemoveNode(id types.NodeID, c chan<- *tailcfg.MapResponse, isRouter bool) {
	// Check if this is the current connection and mark it as closed
	if existing, ok := b.nodes.Load(id); ok {
		if !existing.matchesChannel(c) {
			log.Debug().Uint64("node.id", id.Uint64()).Msg("RemoveNode called for non-current connection, ignoring")
			return // Not the current connection, not an error
		}

		// Mark the connection as closed to prevent further sends
		if connData := existing.connData.Load(); connData != nil {
			connData.closed.Store(true)
		}
	}

	log.Info().Uint64("node.id", id.Uint64()).Bool("isRouter", isRouter).Msg("Node disconnected from batcher, marking as offline")

	// Remove node and mark disconnected atomically
	b.nodes.Delete(id)
	b.connected.Store(id, ptr.To(time.Now()))
	b.totalNodes.Add(-1)

	// Notify other nodes that this node went offline
	b.addWork(change.ChangeSet{NodeID: id, Change: change.NodeWentOffline, IsSubnetRouter: isRouter})
}

// AddWork queues a change to be processed by the batcher.
// Critical changes are processed immediately, while others are batched for efficiency.
func (b *LockFreeBatcher) AddWork(c change.ChangeSet) {
	b.addWork(c)
}

func (b *LockFreeBatcher) Start() {
	b.ctx, b.cancel = context.WithCancel(context.Background())
	go b.doWork()
}

func (b *LockFreeBatcher) Close() {
	if b.cancel != nil {
		b.cancel()
	}
	close(b.workCh)
}

func (b *LockFreeBatcher) doWork() {
	log.Debug().Msg("batcher doWork loop started")
	defer log.Debug().Msg("batcher doWork loop stopped")

	for i := range b.workers {
		go b.worker(i + 1)
	}

	for {
		select {
		case <-b.tick.C:
			// Process batched changes
			b.processBatchedChanges()
		case <-b.ctx.Done():
			return
		}
	}
}

func (b *LockFreeBatcher) worker(workerID int) {
	log.Debug().Int("workerID", workerID).Msg("batcher worker started")
	defer log.Debug().Int("workerID", workerID).Msg("batcher worker stopped")

	for {
		select {
		case w, ok := <-b.workCh:
			if !ok {
				return
			}

			startTime := time.Now()
			b.workProcessed.Add(1)

			// If the resultCh is set, it means that this is a work request
			// where there is a blocking function waiting for the map that
			// is being generated.
			// This is used for synchronous map generation.
			if w.resultCh != nil {
				var result workResult
				if nc, exists := b.nodes.Load(w.nodeID); exists {
					result.mapResponse, result.err = generateMapResponse(nc.nodeID(), nc.version(), b.mapper, w.c)
					if result.err != nil {
						b.workErrors.Add(1)
						log.Error().Err(result.err).
							Int("workerID", workerID).
							Uint64("node.id", w.nodeID.Uint64()).
							Str("change", w.c.Change.String()).
							Msg("failed to generate map response for synchronous work")
					}
				} else {
					result.err = fmt.Errorf("node %d not found", w.nodeID)
					b.workErrors.Add(1)
					log.Error().Err(result.err).
						Int("workerID", workerID).
						Uint64("node.id", w.nodeID.Uint64()).
						Msg("node not found for synchronous work")
				}

				// Send result
				select {
				case w.resultCh <- result:
				case <-b.ctx.Done():
					return
				}

				duration := time.Since(startTime)
				if duration > 100*time.Millisecond {
					log.Warn().
						Int("workerID", workerID).
						Uint64("node.id", w.nodeID.Uint64()).
						Str("change", w.c.Change.String()).
						Dur("duration", duration).
						Msg("slow synchronous work processing")
				}
				continue
			}

			// If resultCh is nil, this is an asynchronous work request
			// that should be processed and sent to the node instead of
			// returned to the caller.
			if nc, exists := b.nodes.Load(w.nodeID); exists {
				// Check if this connection is still active before processing
				if connData := nc.connData.Load(); connData != nil && connData.closed.Load() {
					log.Debug().
						Int("workerID", workerID).
						Uint64("node.id", w.nodeID.Uint64()).
						Str("change", w.c.Change.String()).
						Msg("skipping work for closed connection")
					continue
				}

				err := nc.change(w.c)
				if err != nil {
					b.workErrors.Add(1)
					log.Error().Err(err).
						Int("workerID", workerID).
						Uint64("node.id", w.c.NodeID.Uint64()).
						Str("change", w.c.Change.String()).
						Msg("failed to apply change")
				}
			} else {
				log.Debug().
					Int("workerID", workerID).
					Uint64("node.id", w.nodeID.Uint64()).
					Str("change", w.c.Change.String()).
					Msg("node not found for asynchronous work - node may have disconnected")
			}

			duration := time.Since(startTime)
			if duration > 100*time.Millisecond {
				log.Warn().
					Int("workerID", workerID).
					Uint64("node.id", w.nodeID.Uint64()).
					Str("change", w.c.Change.String()).
					Dur("duration", duration).
					Msg("slow asynchronous work processing")
			}

		case <-b.ctx.Done():
			return
		}
	}
}

func (b *LockFreeBatcher) addWork(c change.ChangeSet) {
	// For critical changes that need immediate processing, send directly
	if b.shouldProcessImmediately(c) {
		if c.SelfUpdateOnly {
			b.queueWork(work{c: c, nodeID: c.NodeID, resultCh: nil})
			return
		}
		b.nodes.Range(func(nodeID types.NodeID, _ *nodeConn) bool {
			if c.NodeID == nodeID && !c.AlsoSelf() {
				return true
			}
			b.queueWork(work{c: c, nodeID: nodeID, resultCh: nil})
			return true
		})
		return
	}

	// For non-critical changes, add to batch
	b.addToBatch(c)
}

// queueWork safely queues work
func (b *LockFreeBatcher) queueWork(w work) {
	b.workQueuedCount.Add(1)

	select {
	case b.workCh <- w:
		// Successfully queued
	case <-b.ctx.Done():
		// Batcher is shutting down
		return
	}
}

// shouldProcessImmediately determines if a change should bypass batching
func (b *LockFreeBatcher) shouldProcessImmediately(c change.ChangeSet) bool {
	// Process these changes immediately to avoid delaying critical functionality
	switch c.Change {
	case change.Full, change.NodeRemove, change.NodeCameOnline, change.NodeWentOffline, change.Policy:
		return true
	default:
		return false
	}
}

// addToBatch adds a change to the pending batch
func (b *LockFreeBatcher) addToBatch(c change.ChangeSet) {
	b.batchMutex.Lock()
	defer b.batchMutex.Unlock()

	if c.SelfUpdateOnly {
		changes, _ := b.pendingChanges.LoadOrStore(c.NodeID, []change.ChangeSet{})
		changes = append(changes, c)
		b.pendingChanges.Store(c.NodeID, changes)
		return
	}

	b.nodes.Range(func(nodeID types.NodeID, _ *nodeConn) bool {
		if c.NodeID == nodeID && !c.AlsoSelf() {
			return true
		}

		changes, _ := b.pendingChanges.LoadOrStore(nodeID, []change.ChangeSet{})
		changes = append(changes, c)
		b.pendingChanges.Store(nodeID, changes)
		return true
	})
}

// processBatchedChanges processes all pending batched changes
func (b *LockFreeBatcher) processBatchedChanges() {
	b.batchMutex.Lock()
	defer b.batchMutex.Unlock()

	if b.pendingChanges == nil {
		return
	}

	// Process all pending changes
	b.pendingChanges.Range(func(nodeID types.NodeID, changes []change.ChangeSet) bool {
		if len(changes) == 0 {
			return true
		}

		// Send all batched changes for this node
		for _, c := range changes {
			b.queueWork(work{c: c, nodeID: nodeID, resultCh: nil})
		}

		// Clear the pending changes for this node
		b.pendingChanges.Delete(nodeID)
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

// MapResponseFromChange queues work to generate a map response and waits for the result.
// This allows synchronous map generation using the same worker pool.
func (b *LockFreeBatcher) MapResponseFromChange(id types.NodeID, c change.ChangeSet) (*tailcfg.MapResponse, error) {
	resultCh := make(chan workResult, 1)

	// Queue the work with a result channel using the safe queueing method
	b.queueWork(work{c: c, nodeID: id, resultCh: resultCh})

	// Wait for the result
	select {
	case result := <-resultCh:
		return result.mapResponse, result.err
	case <-b.ctx.Done():
		return nil, fmt.Errorf("batcher shutting down while generating map response for node %d", id)
	}
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

func newNodeConn(id types.NodeID, c chan<- *tailcfg.MapResponse, version tailcfg.CapabilityVersion, mapper *mapper) *nodeConn {
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
func (nc *nodeConn) updateConnection(c chan<- *tailcfg.MapResponse, version tailcfg.CapabilityVersion) {
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
