package mapper

import (
	"crypto/rand"
	"errors"
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

var errConnectionClosed = errors.New("connection channel already closed")

// LockFreeBatcher uses atomic operations and concurrent maps to eliminate mutex contention.
type LockFreeBatcher struct {
	tick    *time.Ticker
	mapper  *mapper
	workers int

	nodes     *xsync.Map[types.NodeID, *multiChannelNodeConn]
	connected *xsync.Map[types.NodeID, *time.Time]

	// Work queue channel
	workCh     chan work
	workChOnce sync.Once // Ensures workCh is only closed once
	done       chan struct{}
	doneOnce   sync.Once // Ensures done is only closed once

	// Batching state
	pendingChanges *xsync.Map[types.NodeID, []change.Change]

	// Metrics
	totalNodes      atomic.Int64
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
func (b *LockFreeBatcher) AddWork(r ...change.Change) {
	b.addWork(r...)
}

func (b *LockFreeBatcher) Start() {
	b.done = make(chan struct{})
	go b.doWork()
}

func (b *LockFreeBatcher) Close() {
	// Signal shutdown to all goroutines, only once
	b.doneOnce.Do(func() {
		if b.done != nil {
			close(b.done)
		}
	})

	// Only close workCh once using sync.Once to prevent races
	b.workChOnce.Do(func() {
		close(b.workCh)
	})

	// Close the underlying channels supplying the data to the clients.
	b.nodes.Range(func(nodeID types.NodeID, conn *multiChannelNodeConn) bool {
		conn.close()
		return true
	})
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
		case <-b.done:
			log.Info().Msg("batcher done channel closed, stopping to feed workers")
			return
		}
	}
}

func (b *LockFreeBatcher) worker(workerID int) {
	for {
		select {
		case w, ok := <-b.workCh:
			if !ok {
				log.Debug().Int("worker.id", workerID).Msgf("worker channel closing, shutting down worker %d", workerID)
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

					result.mapResponse, err = generateMapResponse(nc, b.mapper, w.c)
					result.err = err
					if result.err != nil {
						b.workErrors.Add(1)
						log.Error().Err(result.err).
							Int("worker.id", workerID).
							Uint64("node.id", w.nodeID.Uint64()).
							Str("reason", w.c.Reason).
							Msg("failed to generate map response for synchronous work")
					} else if result.mapResponse != nil {
						// Update peer tracking for synchronous responses too
						nc.updateSentPeers(result.mapResponse)
					}
				} else {
					result.err = fmt.Errorf("node %d not found", w.nodeID)

					b.workErrors.Add(1)
					log.Error().Err(result.err).
						Int("worker.id", workerID).
						Uint64("node.id", w.nodeID.Uint64()).
						Msg("node not found for synchronous work")
				}

				// Send result
				select {
				case w.resultCh <- result:
				case <-b.done:
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
						Int("worker.id", workerID).
						Uint64("node.id", w.nodeID.Uint64()).
						Str("reason", w.c.Reason).
						Msg("failed to apply change")
				}
			}
		case <-b.done:
			log.Debug().Int("worker.id", workerID).Msg("batcher shutting down, exiting worker")
			return
		}
	}
}

func (b *LockFreeBatcher) addWork(r ...change.Change) {
	b.addToBatch(r...)
}

// queueWork safely queues work.
func (b *LockFreeBatcher) queueWork(w work) {
	b.workQueuedCount.Add(1)

	select {
	case b.workCh <- w:
		// Successfully queued
	case <-b.done:
		// Batcher is shutting down
		return
	}
}

// addToBatch adds changes to the pending batch.
func (b *LockFreeBatcher) addToBatch(changes ...change.Change) {
	// Clean up any nodes being permanently removed from the system.
	//
	// This handles the case where a node is deleted from state but the batcher
	// still has it registered. By cleaning up here, we prevent "node not found"
	// errors when workers try to generate map responses for deleted nodes.
	//
	// Safety: change.Change.PeersRemoved is ONLY populated when nodes are actually
	// deleted from the system (via change.NodeRemoved in state.DeleteNode). Policy
	// changes that affect peer visibility do NOT use this field - they set
	// RequiresRuntimePeerComputation=true and compute removed peers at runtime,
	// putting them in tailcfg.MapResponse.PeersRemoved (a different struct).
	// Therefore, this cleanup only removes nodes that are truly being deleted,
	// not nodes that are still connected but have lost visibility of certain peers.
	//
	// See: https://github.com/juanfont/headscale/issues/2924
	for _, ch := range changes {
		for _, removedID := range ch.PeersRemoved {
			if _, existed := b.nodes.LoadAndDelete(removedID); existed {
				b.totalNodes.Add(-1)
				log.Debug().
					Uint64("node.id", removedID.Uint64()).
					Msg("Removed deleted node from batcher")
			}

			b.connected.Delete(removedID)
			b.pendingChanges.Delete(removedID)
		}
	}

	// Short circuit if any of the changes is a full update, which
	// means we can skip sending individual changes.
	if change.HasFull(changes) {
		b.nodes.Range(func(nodeID types.NodeID, _ *multiChannelNodeConn) bool {
			b.pendingChanges.Store(nodeID, []change.Change{change.FullUpdate()})

			return true
		})

		return
	}

	broadcast, targeted := change.SplitTargetedAndBroadcast(changes)

	// Handle targeted changes - send only to the specific node
	for _, ch := range targeted {
		pending, _ := b.pendingChanges.LoadOrStore(ch.TargetNode, []change.Change{})
		pending = append(pending, ch)
		b.pendingChanges.Store(ch.TargetNode, pending)
	}

	// Handle broadcast changes - send to all nodes, filtering as needed
	if len(broadcast) > 0 {
		b.nodes.Range(func(nodeID types.NodeID, _ *multiChannelNodeConn) bool {
			filtered := change.FilterForNode(nodeID, broadcast)

			if len(filtered) > 0 {
				pending, _ := b.pendingChanges.LoadOrStore(nodeID, []change.Change{})
				pending = append(pending, filtered...)
				b.pendingChanges.Store(nodeID, pending)
			}

			return true
		})
	}
}

// processBatchedChanges processes all pending batched changes.
func (b *LockFreeBatcher) processBatchedChanges() {
	if b.pendingChanges == nil {
		return
	}

	// Process all pending changes
	b.pendingChanges.Range(func(nodeID types.NodeID, pending []change.Change) bool {
		if len(pending) == 0 {
			return true
		}

		// Send all batched changes for this node
		for _, ch := range pending {
			b.queueWork(work{c: ch, nodeID: nodeID, resultCh: nil})
		}

		// Clear the pending changes for this node
		b.pendingChanges.Delete(nodeID)

		return true
	})
}

// cleanupOfflineNodes removes nodes that have been offline for too long to prevent memory leaks.
// TODO(kradalby): reevaluate if we want to keep this.
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
func (b *LockFreeBatcher) MapResponseFromChange(id types.NodeID, ch change.Change) (*tailcfg.MapResponse, error) {
	resultCh := make(chan workResult, 1)

	// Queue the work with a result channel using the safe queueing method
	b.queueWork(work{c: ch, nodeID: id, resultCh: resultCh})

	// Wait for the result
	select {
	case result := <-resultCh:
		return result.mapResponse, result.err
	case <-b.done:
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
	closed   atomic.Bool  // Indicates if this connection has been closed
}

// multiChannelNodeConn manages multiple concurrent connections for a single node.
type multiChannelNodeConn struct {
	id     types.NodeID
	mapper *mapper

	mutex       sync.RWMutex
	connections []*connectionEntry

	updateCount atomic.Int64

	// lastSentPeers tracks which peers were last sent to this node.
	// This enables computing diffs for policy changes instead of sending
	// full peer lists (which clients interpret as "no change" when empty).
	// Using xsync.Map for lock-free concurrent access.
	lastSentPeers *xsync.Map[tailcfg.NodeID, struct{}]
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
		id:            id,
		mapper:        mapper,
		lastSentPeers: xsync.NewMap[tailcfg.NodeID, struct{}](),
	}
}

func (mc *multiChannelNodeConn) close() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	for _, conn := range mc.connections {
		// Mark as closed before closing the channel to prevent
		// send on closed channel panics from concurrent workers
		conn.closed.Store(true)
		close(conn.c)
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
	if data == nil {
		return nil
	}

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

	log.Debug().Uint64("node.id", mc.id.Uint64()).
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
	if data == nil {
		return nil
	}

	// Check if the connection has been closed to prevent send on closed channel panic.
	// This can happen during shutdown when Close() is called while workers are still processing.
	if entry.closed.Load() {
		return fmt.Errorf("connection %s: %w", entry.id, errConnectionClosed)
	}

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

// updateSentPeers updates the tracked peer state based on a sent MapResponse.
// This must be called after successfully sending a response to keep track of
// what the client knows about, enabling accurate diffs for future updates.
func (mc *multiChannelNodeConn) updateSentPeers(resp *tailcfg.MapResponse) {
	if resp == nil {
		return
	}

	// Full peer list replaces tracked state entirely
	if resp.Peers != nil {
		mc.lastSentPeers.Clear()

		for _, peer := range resp.Peers {
			mc.lastSentPeers.Store(peer.ID, struct{}{})
		}
	}

	// Incremental additions
	for _, peer := range resp.PeersChanged {
		mc.lastSentPeers.Store(peer.ID, struct{}{})
	}

	// Incremental removals
	for _, id := range resp.PeersRemoved {
		mc.lastSentPeers.Delete(id)
	}
}

// computePeerDiff compares the current peer list against what was last sent
// and returns the peers that were removed (in lastSentPeers but not in current).
func (mc *multiChannelNodeConn) computePeerDiff(currentPeers []tailcfg.NodeID) []tailcfg.NodeID {
	currentSet := make(map[tailcfg.NodeID]struct{}, len(currentPeers))
	for _, id := range currentPeers {
		currentSet[id] = struct{}{}
	}

	var removed []tailcfg.NodeID

	// Find removed: in lastSentPeers but not in current
	mc.lastSentPeers.Range(func(id tailcfg.NodeID, _ struct{}) bool {
		if _, exists := currentSet[id]; !exists {
			removed = append(removed, id)
		}

		return true
	})

	return removed
}

// change applies a change to all active connections for the node.
func (mc *multiChannelNodeConn) change(r change.Change) error {
	return handleNodeChange(mc, mc.mapper, r)
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

// WorkErrors returns the count of work errors encountered.
// This is primarily useful for testing and debugging.
func (b *LockFreeBatcher) WorkErrors() int64 {
	return b.workErrors.Load()
}
