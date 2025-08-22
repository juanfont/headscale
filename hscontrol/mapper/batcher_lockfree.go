package mapper

import (
	"context"
	"crypto/rand"
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
	log.Trace().Uint64("node.id", id.Uint64()).Msgf("AddNode called chan(%p), version: %d", c, version)
	log.Info().Uint64("node.id", id.Uint64()).Msgf("AddNode entry: attempting to register node with batcher")

	// Generate connection ID
	connID := generateConnectionID()

	// Create new connection entry
	newEntry := &connectionEntry{
		id:      connID,
		c:       c,
		version: version,
		created: time.Now(),
	}

	// Get or create multiChannelNodeConn - this reuses existing offline nodes for rapid reconnection
	nodeConn, loaded := b.nodes.LoadOrStore(id, newMultiChannelNodeConn(id, b.mapper))
	if !loaded {
		b.totalNodes.Add(1)
		log.Info().Uint64("node.id", id.Uint64()).Str("conn.id", connID).
			Msg("Created new multiChannelNodeConn")
	} else {
		log.Info().Uint64("node.id", id.Uint64()).Str("conn.id", connID).
			Int("existing_connections", nodeConn.getActiveConnectionCount()).
			Bool("was_offline", !nodeConn.hasActiveConnections()).
			Msg("Reusing existing multiChannelNodeConn (may be offline node reconnecting)")
	}

	// Add connection to the list (lock-free)
	log.Debug().Uint64("node.id", id.Uint64()).Str("conn.id", connID).
		Int("connections_before", nodeConn.getActiveConnectionCount()).
		Msg("Adding connection to multiChannelNodeConn")
	nodeConn.addConnection(newEntry)
	log.Debug().Uint64("node.id", id.Uint64()).Str("conn.id", connID).
		Int("connections_after", nodeConn.getActiveConnectionCount()).
		Msg("Added connection to multiChannelNodeConn")

	// TODO(kradalby): This should not be generated here, but rather in MapResponseFromChange.
	// This currently means that the goroutine for the node connection will do the processing
	// which means that we might have uncontrolled concurrency.
	// When we use MapResponseFromChange, it will be processed by the same worker pool, causing
	// it to be processed in a more controlled manner.
	var initialMap *tailcfg.MapResponse
	var err error
	initialMap, err = generateMapResponse(id, version, b.mapper, change.FullSelf(id))
	if err != nil {
		log.Error().Uint64("node.id", id.Uint64()).Str("conn.id", connID).Err(err).
			Msg("Failed to generate initial map, removing connection")
		nodeConn.removeConnectionByChannel(c)
		return fmt.Errorf("failed to generate initial map for node %d: %w", id, err)
	}

	// Send initial map to the new connection
	if initialMap != nil {
		log.Debug().Uint64("node.id", id.Uint64()).Str("conn.id", connID).
			Msg("Attempting to send initial map to channel")
		// Use a blocking send with timeout for initial map since the channel should be ready
		// and we want to avoid the race condition where the receiver isn't ready yet
		select {
		case c <- initialMap:
			log.Debug().Uint64("node.id", id.Uint64()).Str("conn.id", connID).
				Msg("Successfully sent initial map to channel")
		case <-time.After(5 * time.Second):
			log.Error().Uint64("node.id", id.Uint64()).Str("conn.id", connID).
				Msgf("Initial map send timed out after 5 seconds, channel may be blocked or full, removing connection")
			nodeConn.removeConnectionByChannel(c)
			return fmt.Errorf("failed to send initial map to node %d: timeout", id)
		}
	} else {
		log.Debug().Uint64("node.id", id.Uint64()).Str("conn.id", connID).
			Msg("No initial map to send (nil)")
	}

	// Update connection status
	b.connected.Store(id, nil) // nil = connected

	// Node will automatically receive updates through the normal flow
	// The initial full map already contains all current state

	log.Info().Uint64("node.id", id.Uint64()).Str("conn.id", connID).
		Int("active_connections", nodeConn.getActiveConnectionCount()).
		Msg("Node connection added to batcher")

	return nil
}

// RemoveNode disconnects a node from the batcher, marking it as offline and cleaning up its state.
// It validates the connection channel matches one of the current connections, closes that specific connection,
// and keeps the node entry alive for rapid reconnections instead of aggressive deletion.
// Returns true if the connection was found and removed, false if the channel was not found.
func (b *LockFreeBatcher) RemoveNode(id types.NodeID, c chan<- *tailcfg.MapResponse) bool {
	nodeConn, exists := b.nodes.Load(id)
	if !exists {
		log.Debug().Uint64("node.id", id.Uint64()).Msg("RemoveNode called for non-existent node")
		return false
	}

	// Remove specific connection
	log.Debug().Uint64("node.id", id.Uint64()).
		Int("connections_before", nodeConn.getActiveConnectionCount()).
		Msg("Removing connection from multiChannelNodeConn")
	removed := nodeConn.removeConnectionByChannel(c)
	if !removed {
		log.Debug().Uint64("node.id", id.Uint64()).Msg("RemoveNode: channel not found in node connections")
		return false
	}

	log.Info().Uint64("node.id", id.Uint64()).
		Int("connections_after", nodeConn.getActiveConnectionCount()).
		Msg("Node connection removed from batcher")

	// Check if node has any remaining active connections
	if nodeConn.hasActiveConnections() {
		log.Debug().Uint64("node.id", id.Uint64()).
			Int("active_connections", nodeConn.getActiveConnectionCount()).
			Msg("Node still has active connections, keeping online")
		return true // Node still has active connections
	}

	// No active connections - keep the node entry alive for rapid reconnections
	// The node will get a fresh full map when it reconnects
	log.Info().Uint64("node.id", id.Uint64()).Msg("Node has no remaining connections, keeping entry for rapid reconnection")
	b.connected.Store(id, ptr.To(time.Now()))

	return true
}

// AddWork queues a change to be processed by the batcher.
// Critical changes are processed immediately, while others are batched for efficiency.
func (b *LockFreeBatcher) AddWork(c change.ChangeSet) {
	log.Trace().Uint64("change.node.id", c.NodeID.Uint64()).Str("change.type", c.Change.String()).
		Bool("self_update_only", c.SelfUpdateOnly).Bool("also_self", c.AlsoSelf()).
		Msg("AddWork called - incoming change")
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

	// Create a cleanup ticker for removing truly disconnected nodes
	cleanupTicker := time.NewTicker(5 * time.Minute)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-b.tick.C:
			// Process batched changes
			b.processBatchedChanges()
		case <-cleanupTicker.C:
			// Clean up nodes that have been offline for too long
			b.cleanupOfflineNodes()
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
					var err error
					result.mapResponse, err = generateMapResponse(nc.nodeID(), nc.version(), b.mapper, w.c)
					result.err = err
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
		log.Debug().Uint64("change.node.id", c.NodeID.Uint64()).Str("change.type", c.Change.String()).
			Bool("self_update_only", c.SelfUpdateOnly).Msg("Processing immediate change")

		if c.SelfUpdateOnly {
			log.Debug().Uint64("change.node.id", c.NodeID.Uint64()).Str("change.type", c.Change.String()).
				Msg("Queuing self-update-only change")
			b.queueWork(work{c: c, nodeID: c.NodeID, resultCh: nil})
			return
		}

		// Count nodes for distribution
		nodeCount := 0
		b.nodes.Range(func(nodeID types.NodeID, nodeConn *multiChannelNodeConn) bool {
			nodeCount++
			return true
		})

		log.Debug().Uint64("change.node.id", c.NodeID.Uint64()).Str("change.type", c.Change.String()).
			Int("total_nodes", nodeCount).Msg("Distributing immediate change to all nodes")

		distributedCount := 0
		skippedCount := 0
		b.nodes.Range(func(nodeID types.NodeID, nodeConn *multiChannelNodeConn) bool {
			if c.NodeID == nodeID && !c.AlsoSelf() {
				log.Debug().Uint64("target.node.id", nodeID.Uint64()).Uint64("change.node.id", c.NodeID.Uint64()).
					Str("change.type", c.Change.String()).Msg("Skipping change - same node and not AlsoSelf")
				skippedCount++
				return true
			}

			log.Debug().Uint64("target.node.id", nodeID.Uint64()).Uint64("change.node.id", c.NodeID.Uint64()).
				Str("change.type", c.Change.String()).Int("active_connections", nodeConn.getActiveConnectionCount()).
				Msg("Queuing change for node")
			b.queueWork(work{c: c, nodeID: nodeID, resultCh: nil})
			distributedCount++

			return true
		})

		log.Info().Uint64("change.node.id", c.NodeID.Uint64()).Str("change.type", c.Change.String()).
			Int("distributed_to", distributedCount).Int("skipped", skippedCount).Int("total_nodes", nodeCount).
			Msg("Completed immediate change distribution")

		return
	}

	// For non-critical changes, add to batch
	b.addToBatch(c)
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

// shouldProcessImmediately determines if a change should bypass batching.
func (b *LockFreeBatcher) shouldProcessImmediately(c change.ChangeSet) bool {
	// Process these changes immediately to avoid delaying critical functionality
	switch c.Change {
	case change.Full, change.NodeRemove, change.NodeCameOnline, change.NodeWentOffline, change.Policy:
		return true
	default:
		return false
	}
}

// addToBatch adds a change to the pending batch.
func (b *LockFreeBatcher) addToBatch(c change.ChangeSet) {
	if c.SelfUpdateOnly {
		changes, _ := b.pendingChanges.LoadOrStore(c.NodeID, []change.ChangeSet{})
		changes = append(changes, c)
		b.pendingChanges.Store(c.NodeID, changes)

		return
	}

	b.nodes.Range(func(nodeID types.NodeID, _ *multiChannelNodeConn) bool {
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

// cleanupOfflineNodes removes nodes that have been offline for too long to prevent memory leaks.
func (b *LockFreeBatcher) cleanupOfflineNodes() {
	cleanupThreshold := 15 * time.Minute
	now := time.Now()

	var nodesToCleanup []types.NodeID

	// Find nodes that have been offline for too long
	b.connected.Range(func(nodeID types.NodeID, disconnectTime *time.Time) bool {
		if disconnectTime != nil && now.Sub(*disconnectTime) > cleanupThreshold {
			// Double-check the node doesn't have active connections
			if nodeConn, exists := b.nodes.Load(nodeID); exists {
				if !nodeConn.hasActiveConnections() {
					nodesToCleanup = append(nodesToCleanup, nodeID)
				}
			}
		}
		return true
	})

	// Clean up the identified nodes
	for _, nodeID := range nodesToCleanup {
		log.Info().Uint64("node.id", nodeID.Uint64()).
			Dur("offline_duration", cleanupThreshold).
			Msg("Cleaning up node that has been offline for too long")

		b.nodes.Delete(nodeID)
		b.connected.Delete(nodeID)
		b.totalNodes.Add(-1)
	}

	if len(nodesToCleanup) > 0 {
		log.Info().Int("cleaned_nodes", len(nodesToCleanup)).
			Msg("Completed cleanup of long-offline nodes")
	}
}

// IsConnected is lock-free read that checks if a node has any active connections.
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

	// During grace period, always return true to allow DNS resolution
	// for logout HTTP requests to complete successfully
	gracePeriod := 45 * time.Second

	return time.Since(*val) < gracePeriod
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

// connectionEntry represents a single connection to a node.
type connectionEntry struct {
	id      string // unique connection ID
	c       chan<- *tailcfg.MapResponse
	version tailcfg.CapabilityVersion
	created time.Time
}

// multiChannelNodeConn manages multiple concurrent connections for a single node.
type multiChannelNodeConn struct {
	id     types.NodeID
	mapper *mapper

	mutex       sync.RWMutex
	connections []*connectionEntry

	updateCount atomic.Int64
}

// generateConnectionID generates a unique connection identifier.
func generateConnectionID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}

// newMultiChannelNodeConn creates a new multi-channel node connection.
func newMultiChannelNodeConn(id types.NodeID, mapper *mapper) *multiChannelNodeConn {
	return &multiChannelNodeConn{
		id:     id,
		mapper: mapper,
	}
}

// addConnection adds a new connection.
func (mc *multiChannelNodeConn) addConnection(entry *connectionEntry) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.connections = append(mc.connections, entry)
	log.Debug().Uint64("node.id", mc.id.Uint64()).Str("conn.id", entry.id).
		Int("total_connections", len(mc.connections)).
		Msg("Successfully added connection")
}

// removeConnectionByChannel removes a connection by matching channel pointer.
func (mc *multiChannelNodeConn) removeConnectionByChannel(c chan<- *tailcfg.MapResponse) bool {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	for i, entry := range mc.connections {
		if entry.c == c {
			// Remove this connection
			mc.connections = append(mc.connections[:i], mc.connections[i+1:]...)
			log.Debug().Uint64("node.id", mc.id.Uint64()).
				Int("remaining_connections", len(mc.connections)).
				Msg("Successfully removed connection")
			return true
		}
	}
	return false
}

// hasActiveConnections checks if the node has any active connections.
func (mc *multiChannelNodeConn) hasActiveConnections() bool {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	return len(mc.connections) > 0
}

// getActiveConnectionCount returns the number of active connections.
func (mc *multiChannelNodeConn) getActiveConnectionCount() int {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	return len(mc.connections)
}

// send broadcasts data to all active connections for the node.
func (mc *multiChannelNodeConn) send(data *tailcfg.MapResponse) error {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	if len(mc.connections) == 0 {
		// During rapid reconnection, nodes may temporarily have no active connections
		// This is not an error - the node will receive a full map when it reconnects
		log.Debug().Uint64("node.id", mc.id.Uint64()).
			Msg("send: skipping send to node with no active connections (likely rapid reconnection)")
		return nil  // Return success instead of error
	}

	log.Debug().Uint64("node.id", mc.id.Uint64()).
		Int("total_connections", len(mc.connections)).
		Msg("send: broadcasting to all connections")

	var lastErr error
	successCount := 0
	var failedConnections []int // Track failed connections for removal

	// Send to all connections
	for i, conn := range mc.connections {
		log.Debug().Uint64("node.id", mc.id.Uint64()).
			Str("conn.id", conn.id).Int("connection_index", i).
			Msg("send: attempting to send to connection")

		if err := conn.send(data); err != nil {
			lastErr = err
			failedConnections = append(failedConnections, i)
			log.Warn().Err(err).
				Uint64("node.id", mc.id.Uint64()).
				Str("conn.id", conn.id).Int("connection_index", i).
				Msg("send: connection send failed")
		} else {
			successCount++
			log.Debug().Uint64("node.id", mc.id.Uint64()).
				Str("conn.id", conn.id).Int("connection_index", i).
				Msg("send: successfully sent to connection")
		}
	}

	// Remove failed connections (in reverse order to maintain indices)
	for i := len(failedConnections) - 1; i >= 0; i-- {
		idx := failedConnections[i]
		log.Debug().Uint64("node.id", mc.id.Uint64()).
			Str("conn.id", mc.connections[idx].id).
			Msg("send: removing failed connection")
		mc.connections = append(mc.connections[:idx], mc.connections[idx+1:]...)
	}

	mc.updateCount.Add(1)

	log.Info().Uint64("node.id", mc.id.Uint64()).
		Int("successful_sends", successCount).
		Int("failed_connections", len(failedConnections)).
		Int("remaining_connections", len(mc.connections)).
		Msg("send: completed broadcast")

	// Success if at least one send succeeded
	if successCount > 0 {
		return nil
	}

	return fmt.Errorf("node %d: all connections failed, last error: %w", mc.id, lastErr)
}

// send sends data to a single connection entry.
func (entry *connectionEntry) send(data *tailcfg.MapResponse) error {
	// TODO(kradalby): We might need some sort of timeout here if the client is not reading
	// the channel. That might mean that we are sending to a node that has gone offline, but
	// the channel is still open.
	select {
	case entry.c <- data:
		return nil
	default:
		// Channel is full or closed
		return fmt.Errorf("connection %s: channel send failed", entry.id)
	}
}

// nodeID returns the node ID.
func (mc *multiChannelNodeConn) nodeID() types.NodeID {
	return mc.id
}

// version returns the capability version from the first active connection.
// All connections for a node should have the same version in practice.
func (mc *multiChannelNodeConn) version() tailcfg.CapabilityVersion {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	if len(mc.connections) == 0 {
		return 0
	}

	return mc.connections[0].version
}

// change applies a change to all active connections for the node.
func (mc *multiChannelNodeConn) change(c change.ChangeSet) error {
	return handleNodeChange(mc, mc.mapper, c)
}

// DebugNodeInfo contains debug information about a node's connections.
type DebugNodeInfo struct {
	Connected         bool `json:"connected"`
	ActiveConnections int  `json:"active_connections"`
}

// Debug returns a pre-baked map of node debug information for the debug interface.
func (b *LockFreeBatcher) Debug() map[types.NodeID]DebugNodeInfo {
	result := make(map[types.NodeID]DebugNodeInfo)

	// Get all nodes with their connection status
	b.nodes.Range(func(id types.NodeID, nodeConn *multiChannelNodeConn) bool {
		nodeConn.mutex.RLock()
		activeConnCount := len(nodeConn.connections)
		nodeConn.mutex.RUnlock()

		result[id] = DebugNodeInfo{
			Connected:         activeConnCount > 0,
			ActiveConnections: activeConnCount,
		}
		return true
	})

	// Add disconnected nodes from the connected map (for grace period handling)
	b.connected.Range(func(id types.NodeID, val *time.Time) bool {
		if val != nil {
			// Only add if not already added as connected
			if _, exists := result[id]; !exists {
				result[id] = DebugNodeInfo{
					Connected:         false,
					ActiveConnections: 0,
				}
			}
		}
		return true
	})

	return result
}
