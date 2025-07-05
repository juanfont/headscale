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

	nodes     *xsync.Map[types.NodeID, *multiChannelNodeConn]
	connected *xsync.Map[types.NodeID, *time.Time]

	// Work queue channel
	workCh chan work
	ctx    context.Context
	cancel context.CancelFunc

	// Batching state
	pendingChanges *xsync.Map[types.NodeID, []change.ChangeSet]

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
func (b *LockFreeBatcher) AddNode(id types.NodeID, c chan<- *tailcfg.MapResponse, version tailcfg.CapabilityVersion) error {
	addNodeStart := time.Now()

	// Generate connection ID
	connID := generateConnectionID()

	// Create new connection entry
	now := time.Now()
	newEntry := &connectionEntry{
		id:      connID,
		c:       c,
		version: version,
		created: now,
	}

	// Only after validation succeeds, create or update node connection
	newConn := newNodeConn(id, c, version, b.mapper)

	if !loaded {
		b.totalNodes.Add(1)
		conn = newConn
	}

	b.connected.Store(id, nil) // nil = connected

	if err != nil {
		log.Error().Uint64("node.id", id.Uint64()).Err(err).Msg("Initial map generation failed")
		nodeConn.removeConnectionByChannel(c)
		return fmt.Errorf("failed to generate initial map for node %d: %w", id, err)
	}

	// Use a blocking send with timeout for initial map since the channel should be ready
	// and we want to avoid the race condition where the receiver isn't ready yet
	select {
	case c <- initialMap:
		// Success
	case <-time.After(5 * time.Second):
		log.Error().Uint64("node.id", id.Uint64()).Err(fmt.Errorf("timeout")).Msg("Initial map send timeout")
		log.Debug().Caller().Uint64("node.id", id.Uint64()).Dur("timeout.duration", 5*time.Second).
			Msg("Initial map send timed out because channel was blocked or receiver not ready")
		nodeConn.removeConnectionByChannel(c)
		return fmt.Errorf("failed to send initial map to node %d: timeout", id)
	}

	return nil
}

// RemoveNode disconnects a node from the batcher, marking it as offline and cleaning up its state.
// It validates the connection channel matches one of the current connections, closes that specific connection,
// and keeps the node entry alive for rapid reconnections instead of aggressive deletion.
// Reports if the node still has active connections after removal.
func (b *LockFreeBatcher) RemoveNode(id types.NodeID, c chan<- *tailcfg.MapResponse) bool {
	nodeConn, exists := b.nodes.Load(id)
	if !exists {
		log.Debug().Caller().Uint64("node.id", id.Uint64()).Msg("RemoveNode called for non-existent node because node not found in batcher")
		return false
	}

		// Mark the connection as closed to prevent further sends
		if connData := existing.connData.Load(); connData != nil {
			connData.closed.Store(true)
		}
	}

	// Check if node has any remaining active connections
	if nodeConn.hasActiveConnections() {
		log.Debug().Caller().Uint64("node.id", id.Uint64()).
			Int("active.connections", nodeConn.getActiveConnectionCount()).
			Msg("Node connection removed but keeping online because other connections remain")
		return true // Node still has active connections
	}

	// Remove node and mark disconnected atomically
	b.nodes.Delete(id)
	b.connected.Store(id, ptr.To(time.Now()))
	b.totalNodes.Add(-1)

	return false
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

				continue
			}

			// If resultCh is nil, this is an asynchronous work request
			// that should be processed and sent to the node instead of
			// returned to the caller.
			if nc, exists := b.nodes.Load(w.nodeID); exists {
				// Apply change to node - this will handle offline nodes gracefully
				// and queue work for when they reconnect
				err := nc.change(w.c)
				if err != nil {
					b.workErrors.Add(1)
					log.Error().Err(err).
						Int("workerID", workerID).
						Uint64("node.id", w.c.NodeID.Uint64()).
						Str("change", w.c.Change.String()).
						Msg("failed to apply change")
				}
			}
		case <-b.ctx.Done():
			return
		}
	}
}

func (b *LockFreeBatcher) addWork(c ...change.ChangeSet) {
	b.addToBatch(c...)
}

// queueWork safely queues work.
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

// addToBatch adds a change to the pending batch.
func (b *LockFreeBatcher) addToBatch(c ...change.ChangeSet) {
	// Short circuit if any of the changes is a full update, which
	// means we can skip sending individual changes.
	if change.HasFull(c) {
		b.nodes.Range(func(nodeID types.NodeID, _ *multiChannelNodeConn) bool {
			b.pendingChanges.Store(nodeID, []change.ChangeSet{{Change: change.Full}})

			return true
		})
		return
	}
}


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

// processBatchedChanges processes all pending batched changes.
func (b *LockFreeBatcher) processBatchedChanges() {
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
	// First check if we have active connections for this node
	if nodeConn, exists := b.nodes.Load(id); exists {
		if nodeConn.hasActiveConnections() {
			return true
		}
	}

	// Check disconnected timestamp with grace period
	val, ok := b.connected.Load(id)
	if !ok {
		return false
	}

	// nil means connected
	if val == nil {
		return true
	}

	return false
}

// ConnectedMap returns a lock-free map of all connected nodes.
func (b *LockFreeBatcher) ConnectedMap() *xsync.Map[types.NodeID, bool] {
	ret := xsync.NewMap[types.NodeID, bool]()

	// First, add all nodes with active connections
	b.nodes.Range(func(id types.NodeID, nodeConn *multiChannelNodeConn) bool {
		if nodeConn.hasActiveConnections() {
			ret.Store(id, true)
		}
		return true
	})

	// Then add all entries from the connected map
	b.connected.Range(func(id types.NodeID, val *time.Time) bool {
		// Only add if not already added as connected above
		if _, exists := ret.Load(id); !exists {
			if val == nil {
				// nil means connected
				ret.Store(id, true)
			} else {
				// timestamp means disconnected
				ret.Store(id, false)
			}
		}
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

	// Add all entries from the connected map to capture both connected and disconnected nodes
	b.connected.Range(func(id types.NodeID, val *time.Time) bool {
		// Only add if not already processed above
		if _, exists := result[id]; !exists {
			// Use immediate connection status for debug (no grace period)
			connected := (val == nil) // nil means connected, timestamp means disconnected
			result[id] = DebugNodeInfo{
				Connected:         connected,
				ActiveConnections: 0,
			}
		}
		return true
	})

	return result
}

func (b *LockFreeBatcher) DebugMapResponses() (map[types.NodeID][]tailcfg.MapResponse, error) {
	return b.mapper.debugMapResponses()
}
