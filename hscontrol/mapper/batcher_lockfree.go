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
	// Initialize last used timestamp
	newEntry.lastUsed.Store(now.Unix())

	// Get or create multiChannelNodeConn - this reuses existing offline nodes for rapid reconnection
	nodeConn, loaded := b.nodes.LoadOrStore(id, newMultiChannelNodeConn(id, b.mapper))

	if !loaded {
		b.totalNodes.Add(1)
	}

	// Add connection to the list (lock-free)
	nodeConn.addConnection(newEntry)

	// Use the worker pool for controlled concurrency instead of direct generation
	initialMap, err := b.MapResponseFromChange(id, change.FullSelf(id))

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

	// Update connection status
	b.connected.Store(id, nil) // nil = connected

	// Node will automatically receive updates through the normal flow
	// The initial full map already contains all current state

	log.Debug().Caller().Uint64("node.id", id.Uint64()).Dur("total.duration", time.Since(addNodeStart)).
		Int("active.connections", nodeConn.getActiveConnectionCount()).
		Msg("Node connection established in batcher because AddNode completed successfully")

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

	// Remove specific connection
	removed := nodeConn.removeConnectionByChannel(c)
	if !removed {
		log.Debug().Caller().Uint64("node.id", id.Uint64()).Msg("RemoveNode: channel not found because connection already removed or invalid")
		return false
	}

	// Check if node has any remaining active connections
	if nodeConn.hasActiveConnections() {
		log.Debug().Caller().Uint64("node.id", id.Uint64()).
			Int("active.connections", nodeConn.getActiveConnectionCount()).
			Msg("Node connection removed but keeping online because other connections remain")
		return true // Node still has active connections
	}

	// No active connections - keep the node entry alive for rapid reconnections
	// The node will get a fresh full map when it reconnects
	log.Debug().Caller().Uint64("node.id", id.Uint64()).Msg("Node disconnected from batcher because all connections removed, keeping entry for rapid reconnection")
	b.connected.Store(id, ptr.To(time.Now()))

	return false
}

// AddWork queues a change to be processed by the batcher.
func (b *LockFreeBatcher) AddWork(c ...change.ChangeSet) {
	b.addWork(c...)
}

func (b *LockFreeBatcher) Start() {
	b.ctx, b.cancel = context.WithCancel(context.Background())
	go b.doWork()
}

func (b *LockFreeBatcher) Close() {
	if b.cancel != nil {
		b.cancel()
		b.cancel = nil // Prevent multiple calls
	}

	// Only close workCh once
	select {
	case <-b.workCh:
		// Channel is already closed
	default:
		close(b.workCh)
	}
}

func (b *LockFreeBatcher) doWork() {

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

	for {
		select {
		case w, ok := <-b.workCh:
			if !ok {
				return
			}

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

	all, self := change.SplitAllAndSelf(c)

	for _, changeSet := range self {
		changes, _ := b.pendingChanges.LoadOrStore(changeSet.NodeID, []change.ChangeSet{})
		changes = append(changes, changeSet)
		b.pendingChanges.Store(changeSet.NodeID, changes)

		return
	}

	b.nodes.Range(func(nodeID types.NodeID, _ *multiChannelNodeConn) bool {
		rel := change.RemoveUpdatesForSelf(nodeID, all)

		changes, _ := b.pendingChanges.LoadOrStore(nodeID, []change.ChangeSet{})
		changes = append(changes, rel...)
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

// connectionEntry represents a single connection to a node.
type connectionEntry struct {
	id       string // unique connection ID
	c        chan<- *tailcfg.MapResponse
	version  tailcfg.CapabilityVersion
	created  time.Time
	lastUsed atomic.Int64 // Unix timestamp of last successful send
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
	mutexWaitStart := time.Now()
	log.Debug().Caller().Uint64("node.id", mc.id.Uint64()).Str("chan", fmt.Sprintf("%p", entry.c)).Str("conn.id", entry.id).
		Msg("addConnection: waiting for mutex - POTENTIAL CONTENTION POINT")

	mc.mutex.Lock()
	mutexWaitDur := time.Since(mutexWaitStart)
	defer mc.mutex.Unlock()

	mc.connections = append(mc.connections, entry)
	log.Debug().Caller().Uint64("node.id", mc.id.Uint64()).Str("chan", fmt.Sprintf("%p", entry.c)).Str("conn.id", entry.id).
		Int("total_connections", len(mc.connections)).
		Dur("mutex_wait_time", mutexWaitDur).
		Msg("Successfully added connection after mutex wait")
}

// removeConnectionByChannel removes a connection by matching channel pointer.
func (mc *multiChannelNodeConn) removeConnectionByChannel(c chan<- *tailcfg.MapResponse) bool {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	for i, entry := range mc.connections {
		if entry.c == c {
			// Remove this connection
			mc.connections = append(mc.connections[:i], mc.connections[i+1:]...)
			log.Debug().Caller().Uint64("node.id", mc.id.Uint64()).Str("chan", fmt.Sprintf("%p", c)).
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
		log.Debug().Caller().Uint64("node.id", mc.id.Uint64()).
			Msg("send: skipping send to node with no active connections (likely rapid reconnection)")
		return nil // Return success instead of error
	}

	log.Debug().Caller().Uint64("node.id", mc.id.Uint64()).
		Int("total_connections", len(mc.connections)).
		Msg("send: broadcasting to all connections")

	var lastErr error
	successCount := 0
	var failedConnections []int // Track failed connections for removal

	// Send to all connections
	for i, conn := range mc.connections {
		log.Debug().Caller().Uint64("node.id", mc.id.Uint64()).Str("chan", fmt.Sprintf("%p", conn.c)).
			Str("conn.id", conn.id).Int("connection_index", i).
			Msg("send: attempting to send to connection")

		if err := conn.send(data); err != nil {
			lastErr = err
			failedConnections = append(failedConnections, i)
			log.Warn().Err(err).
				Uint64("node.id", mc.id.Uint64()).Str("chan", fmt.Sprintf("%p", conn.c)).
				Str("conn.id", conn.id).Int("connection_index", i).
				Msg("send: connection send failed")
		} else {
			successCount++
			log.Debug().Caller().Uint64("node.id", mc.id.Uint64()).Str("chan", fmt.Sprintf("%p", conn.c)).
				Str("conn.id", conn.id).Int("connection_index", i).
				Msg("send: successfully sent to connection")
		}
	}

	// Remove failed connections (in reverse order to maintain indices)
	for i := len(failedConnections) - 1; i >= 0; i-- {
		idx := failedConnections[i]
		log.Debug().Caller().Uint64("node.id", mc.id.Uint64()).
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

// send sends data to a single connection entry with timeout-based stale connection detection.
func (entry *connectionEntry) send(data *tailcfg.MapResponse) error {
	// Use a short timeout to detect stale connections where the client isn't reading the channel.
	// This is critical for detecting Docker containers that are forcefully terminated
	// but still have channels that appear open.
	select {
	case entry.c <- data:
		// Update last used timestamp on successful send
		entry.lastUsed.Store(time.Now().Unix())
		return nil
	case <-time.After(50 * time.Millisecond):
		// Connection is likely stale - client isn't reading from channel
		// This catches the case where Docker containers are killed but channels remain open
		return fmt.Errorf("connection %s: timeout sending to channel (likely stale connection)", entry.id)
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

	// Get all nodes with their connection status using immediate connection logic
	// (no grace period) for debug purposes
	b.nodes.Range(func(id types.NodeID, nodeConn *multiChannelNodeConn) bool {
		nodeConn.mutex.RLock()
		activeConnCount := len(nodeConn.connections)
		nodeConn.mutex.RUnlock()

		// Use immediate connection status: if active connections exist, node is connected
		// If not, check the connected map for nil (connected) vs timestamp (disconnected)
		connected := false
		if activeConnCount > 0 {
			connected = true
		} else {
			// Check connected map for immediate status
			if val, ok := b.connected.Load(id); ok && val == nil {
				connected = true
			}
		}

		result[id] = DebugNodeInfo{
			Connected:         connected,
			ActiveConnections: activeConnCount,
		}
		return true
	})

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
