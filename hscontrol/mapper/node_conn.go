package mapper

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

// connectionEntry represents a single connection to a node.
type connectionEntry struct {
	id       string // unique connection ID
	c        chan<- *tailcfg.MapResponse
	version  tailcfg.CapabilityVersion
	created  time.Time
	stop     func()
	lastUsed atomic.Int64 // Unix timestamp of last successful send
	closed   atomic.Bool  // Indicates if this connection has been closed
}

// multiChannelNodeConn manages multiple concurrent connections for a single node.
type multiChannelNodeConn struct {
	id     types.NodeID
	mapper *mapper
	log    zerolog.Logger

	mutex       sync.RWMutex
	connections []*connectionEntry

	// pendingMu protects pending changes independently of the connection mutex.
	// This avoids contention between addToBatch (which appends changes) and
	// send() (which sends data to connections).
	pendingMu sync.Mutex
	pending   []change.Change

	// workMu serializes change processing for this node across batch ticks.
	// Without this, two workers could process consecutive ticks' bundles
	// concurrently, causing out-of-order MapResponse delivery and races
	// on lastSentPeers (Clear+Store in updateSentPeers vs Range in
	// computePeerDiff).
	workMu sync.Mutex

	closeOnce   sync.Once
	updateCount atomic.Int64

	// lastSentPeers tracks which peers were last sent to this node.
	// This enables computing diffs for policy changes instead of sending
	// full peer lists (which clients interpret as "no change" when empty).
	// Using xsync.Map for lock-free concurrent access.
	lastSentPeers *xsync.Map[tailcfg.NodeID, struct{}]
}

// connIDCounter is a monotonically increasing counter used to generate
// unique connection identifiers without the overhead of crypto/rand.
// Connection IDs are process-local and need not be cryptographically random.
var connIDCounter atomic.Uint64

// generateConnectionID generates a unique connection identifier.
func generateConnectionID() string {
	return strconv.FormatUint(connIDCounter.Add(1), 10)
}

// newMultiChannelNodeConn creates a new multi-channel node connection.
func newMultiChannelNodeConn(id types.NodeID, mapper *mapper) *multiChannelNodeConn {
	return &multiChannelNodeConn{
		id:            id,
		mapper:        mapper,
		lastSentPeers: xsync.NewMap[tailcfg.NodeID, struct{}](),
		log:           log.With().Uint64(zf.NodeID, id.Uint64()).Logger(),
	}
}

func (mc *multiChannelNodeConn) close() {
	mc.closeOnce.Do(func() {
		mc.mutex.Lock()
		defer mc.mutex.Unlock()

		for _, conn := range mc.connections {
			mc.stopConnection(conn)
		}
	})
}

// stopConnection marks a connection as closed and tears down the owning session
// at most once, even if multiple cleanup paths race to remove it.
func (mc *multiChannelNodeConn) stopConnection(conn *connectionEntry) {
	if conn.closed.CompareAndSwap(false, true) {
		if conn.stop != nil {
			conn.stop()
		}
	}
}

// removeConnectionAtIndexLocked removes the active connection at index.
// If stopConnection is true, it also stops that session.
// Caller must hold mc.mutex.
func (mc *multiChannelNodeConn) removeConnectionAtIndexLocked(i int, stopConnection bool) *connectionEntry {
	conn := mc.connections[i]
	copy(mc.connections[i:], mc.connections[i+1:])
	mc.connections[len(mc.connections)-1] = nil // release pointer for GC
	mc.connections = mc.connections[:len(mc.connections)-1]

	if stopConnection {
		mc.stopConnection(conn)
	}

	return conn
}

// addConnection adds a new connection.
func (mc *multiChannelNodeConn) addConnection(entry *connectionEntry) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.connections = append(mc.connections, entry)
	mc.log.Debug().Str(zf.ConnID, entry.id).
		Int("total_connections", len(mc.connections)).
		Msg("connection added")
}

// removeConnectionByChannel removes a connection by matching channel pointer.
func (mc *multiChannelNodeConn) removeConnectionByChannel(c chan<- *tailcfg.MapResponse) bool {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	for i, entry := range mc.connections {
		if entry.c == c {
			mc.removeConnectionAtIndexLocked(i, false)
			mc.log.Debug().Str(zf.ConnID, entry.id).
				Int("remaining_connections", len(mc.connections)).
				Msg("connection removed")

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

// appendPending appends changes to this node's pending change list.
// Thread-safe via pendingMu; does not contend with the connection mutex.
func (mc *multiChannelNodeConn) appendPending(changes ...change.Change) {
	mc.pendingMu.Lock()
	mc.pending = append(mc.pending, changes...)
	mc.pendingMu.Unlock()
}

// drainPending atomically removes and returns all pending changes.
// Returns nil if there are no pending changes.
func (mc *multiChannelNodeConn) drainPending() []change.Change {
	mc.pendingMu.Lock()
	p := mc.pending
	mc.pending = nil
	mc.pendingMu.Unlock()

	return p
}

// send broadcasts data to all active connections for the node.
//
// To avoid holding the write lock during potentially slow sends (each stale
// connection can block for up to 50ms), the method snapshots connections under
// a read lock, sends without any lock held, then write-locks only to remove
// failures. New connections added between the snapshot and cleanup are safe:
// they receive a full initial map via AddNode, so missing this update causes
// no data loss.
func (mc *multiChannelNodeConn) send(data *tailcfg.MapResponse) error {
	if data == nil {
		return nil
	}

	// Snapshot connections under read lock.
	mc.mutex.RLock()

	if len(mc.connections) == 0 {
		mc.mutex.RUnlock()
		mc.log.Trace().
			Msg("send: no active connections, skipping")

		return nil
	}

	// Copy the slice so we can release the read lock before sending.
	snapshot := make([]*connectionEntry, len(mc.connections))
	copy(snapshot, mc.connections)
	mc.mutex.RUnlock()

	mc.log.Trace().
		Int("total_connections", len(snapshot)).
		Msg("send: broadcasting")

	// Send to all connections without holding any lock.
	// Stale connection timeouts (50ms each) happen here without blocking
	// other goroutines that need the mutex.
	var (
		lastErr      error
		successCount int
		failed       []*connectionEntry
	)

	for _, conn := range snapshot {
		err := conn.send(data)
		if err != nil {
			lastErr = err

			failed = append(failed, conn)

			mc.log.Warn().Err(err).
				Str(zf.ConnID, conn.id).
				Msg("send: connection failed")
		} else {
			successCount++
		}
	}

	// Write-lock only to remove failed connections.
	if len(failed) > 0 {
		mc.mutex.Lock()
		// Remove by pointer identity: only remove entries that still exist
		// in the current connections slice and match a failed pointer.
		// New connections added since the snapshot are not affected.
		failedSet := make(map[*connectionEntry]struct{}, len(failed))
		for _, f := range failed {
			failedSet[f] = struct{}{}
		}

		clean := mc.connections[:0]
		for _, conn := range mc.connections {
			if _, isFailed := failedSet[conn]; !isFailed {
				clean = append(clean, conn)
			} else {
				mc.log.Debug().
					Str(zf.ConnID, conn.id).
					Msg("send: removing failed connection")
				// Tear down the owning session so the old serveLongPoll
				// goroutine exits instead of lingering as a stale session.
				mc.stopConnection(conn)
			}
		}

		// Nil out trailing slots so removed *connectionEntry values
		// are not retained by the backing array.
		for i := len(clean); i < len(mc.connections); i++ {
			mc.connections[i] = nil
		}

		mc.connections = clean
		mc.mutex.Unlock()
	}

	mc.updateCount.Add(1)

	mc.log.Trace().
		Int("successful_sends", successCount).
		Int("failed_connections", len(failed)).
		Msg("send: broadcast complete")

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
	//
	// We use time.NewTimer + Stop instead of time.After to avoid leaking timers.
	// time.After creates a timer that lives in the runtime's timer heap until it fires,
	// even when the send succeeds immediately. On the hot path (1000+ nodes per tick),
	// this leaks thousands of timers per second.
	timer := time.NewTimer(50 * time.Millisecond) //nolint:mnd
	defer timer.Stop()

	select {
	case entry.c <- data:
		// Update last used timestamp on successful send
		entry.lastUsed.Store(time.Now().Unix())
		return nil
	case <-timer.C:
		// Connection is likely stale - client isn't reading from channel
		// This catches the case where Docker containers are killed but channels remain open
		return fmt.Errorf("connection %s: %w", entry.id, ErrConnectionSendTimeout)
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
