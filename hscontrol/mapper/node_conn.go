package mapper

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
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

// minPendingFold is the pending size below which appendPending leaves the
// folding to the drain.
const minPendingFold = 64

const maxConcurrentMapSessionsPerNode = 4

// errNoActiveConnections is returned by [multiChannelNodeConn.send] when a node
// has no active connections (disconnected but kept in the batcher for rapid
// reconnection). Callers must not update peer tracking state (lastSentPeers)
// after this error because the data was never delivered to any client.
var errNoActiveConnections = errors.New("no active connections")

// errNoReadyConnections is returned by [multiChannelNodeConn.send], having
// sent nothing, when any of the node's connections is still waiting for its
// initial map ([Batcher.AddNode] has registered it but not yet delivered the
// first full response). Sending a delta to it now would make it the stream's
// first frame, which Tailscale clients reject ("initial MapResponse lacked
// Node") — tearing down the poll. Unlike [errNoActiveConnections], the change
// must be retried, and on every connection: the in-flight initial map may have
// been generated from a snapshot older than the change, so dropping it would
// lose the update.
var errNoReadyConnections = errors.New("no connections ready for updates")

// errConnectionBackpressure keeps unsent changes queued without declaring a busy client dead.
var errConnectionBackpressure = errors.New("connection queue full")

// Match the initial-map timeout while staying below reconnect grace and client keepalive.
const connectionStallTimeout = 5 * time.Second

// A full snapshot supersedes state backlog past this size; pings remain
// one-shot work.
const maxPendingSize = 256

// connectionEntry represents a single connection to a node.
type connectionEntry struct {
	id       string // unique connection ID
	c        chan<- *tailcfg.MapResponse
	version  tailcfg.CapabilityVersion
	created  time.Time
	stop     func()
	lastUsed atomic.Int64 // Unix timestamp of last successful send
	closed   atomic.Bool  // Indicates if this connection has been closed

	blockedSince atomic.Pointer[time.Time]
	done         chan struct{}
	batcherDone  <-chan struct{}

	// pendingInitial is set by [Batcher.AddNode] while this
	// connection's initial map is still in flight, and cleared once it
	// is delivered. Broadcast sends to the node wait for it, so a delta
	// can never become the stream's first frame ahead of the initial
	// map. The zero value means the connection is ready.
	pendingInitial atomic.Bool

	// lastSelf is the self node last delivered to this connection's
	// client, which keeps it until sent another. Every send to an
	// established connection must go through [multiChannelNodeConn.send]
	// to keep it current.
	lastSelf atomic.Pointer[tailcfg.Node]

	// lastSSHPolicy is the last non-nil policy delivered to this connection.
	lastSSHPolicy atomic.Pointer[tailcfg.SSHPolicy]
}

// withSelfDelta returns data without its Node when this client already
// holds an equal one: a Node forces a full client netmap rebuild.
func (entry *connectionEntry) withSelfDelta(data *tailcfg.MapResponse) *tailcfg.MapResponse {
	if data.Node == nil || !data.Node.Equal(entry.lastSelf.Load()) {
		return data
	}

	stripped := *data
	stripped.Node = nil

	return &stripped
}

// withSSHPolicyDelta returns data without its SSHPolicy when this client
// already holds an equal one: any non-nil SSHPolicy forces a full client
// netmap rebuild. Equal content arrives in fresh pointers after every
// policy reload, so compare deeply.
func (entry *connectionEntry) withSSHPolicyDelta(data *tailcfg.MapResponse) *tailcfg.MapResponse {
	if data.SSHPolicy == nil || !reflect.DeepEqual(entry.lastSSHPolicy.Load(), data.SSHPolicy) {
		return data
	}

	stripped := *data
	stripped.SSHPolicy = nil

	return &stripped
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

	// pendingSize is [changesSize] of pending. A fold keeps every peer and
	// patch it merges, so the change count alone hides the backlog.
	pendingSize int

	// pendingFoldAt is the pending size at which appendPending folds the
	// backlog again: twice what the last fold left, so appends stay
	// amortized O(1).
	pendingFoldAt int

	// workMu serializes change processing for this node across batch ticks.
	// Without this, two workers could process consecutive ticks' bundles
	// concurrently, causing out-of-order [tailcfg.MapResponse] delivery and races
	// on lastSentPeers (Clear+Store in [multiChannelNodeConn.updateSentPeers] vs
	// Range in [multiChannelNodeConn.computePeerDiff]).
	workMu sync.Mutex

	// inFlight is true while a batched work bundle for this node is queued or
	// being processed. processBatchedChanges refuses to queue a second bundle
	// while one is in flight (the new changes wait in pending), so a saturated
	// worker pool cannot deliver tick N+1 before tick N: a non-FIFO workMu
	// cannot reorder bundles that never coexist.
	inFlight atomic.Bool

	closeOnce   sync.Once
	updateCount atomic.Int64

	// disconnectedAt records when the last connection was removed.
	// nil means the node is considered connected (or newly created);
	// non-nil means the node disconnected at the stored timestamp.
	// Used by [Batcher.cleanupOfflineNodes] to evict stale entries.
	disconnectedAt atomic.Pointer[time.Time]

	// lastSentPeers tracks which peers were last sent to this node.
	// This enables computing diffs for policy changes instead of sending
	// full peer lists (which clients interpret as "no change" when empty).
	// Using xsync.Map for lock-free concurrent access.
	lastSentPeers *xsync.Map[tailcfg.NodeID, struct{}]

	// Partial additions remain removal candidates when retries render newer state.
	partialPeers *xsync.Map[tailcfg.NodeID, struct{}]
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
		partialPeers:  xsync.NewMap[tailcfg.NodeID, struct{}](),
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
		close(conn.done)

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
	mc.connections = slices.Delete(mc.connections, i, i+1)

	if stopConnection {
		mc.stopConnection(conn)
	}

	return conn
}

// addConnection adds a new connection.
func (mc *multiChannelNodeConn) addConnection(entry *connectionEntry) {
	mc.addConnectionWithLimit(entry, 0)
}

// addConnectionWithLimit atomically adds a connection while keeping at most
// limit overlapping sessions. The oldest session is stopped and replaced when
// the limit is full, allowing normal client poll churn to make progress. A zero
// limit keeps the unbounded behavior used by low-level tests and benchmarks.
func (mc *multiChannelNodeConn) addConnectionWithLimit(
	entry *connectionEntry,
	limit int,
) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	for limit > 0 && len(mc.connections) >= limit {
		replaced := mc.removeConnectionAtIndexLocked(0, true)
		mc.log.Debug().Str(zf.ConnID, replaced.id).
			Msg("oldest overlapping connection replaced")
	}

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

// detach removes the connection for the given channel and marks the node
// disconnected if no active connections remain. A connection already gone
// was evicted, and the newer stream that evicted it owns the node's state.
func (mc *multiChannelNodeConn) detach(c chan<- *tailcfg.MapResponse) {
	if mc.removeConnectionByChannel(c) && !mc.hasActiveConnections() {
		mc.markDisconnected()
	}
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

// markConnected clears the disconnect timestamp, indicating the node
// has an active connection.
func (mc *multiChannelNodeConn) markConnected() {
	mc.disconnectedAt.Store(nil)
}

// markDisconnected records the current time as the moment the node
// lost its last connection. Used by [Batcher.cleanupOfflineNodes] to
// determine how long the node has been offline.
func (mc *multiChannelNodeConn) markDisconnected() {
	now := time.Now()
	mc.disconnectedAt.Store(&now)
}

// isConnected returns true if the node has active connections or has
// not been marked as disconnected.
func (mc *multiChannelNodeConn) isConnected() bool {
	if mc.hasActiveConnections() {
		return true
	}

	return mc.disconnectedAt.Load() == nil
}

// offlineDuration returns how long the node has been disconnected.
// Returns 0 if the node is connected or has never been marked as disconnected.
func (mc *multiChannelNodeConn) offlineDuration() time.Duration {
	t := mc.disconnectedAt.Load()
	if t == nil {
		return 0
	}

	return time.Since(*t)
}

// appendPending appends changes to this node's pending change list.
// Thread-safe via pendingMu; does not contend with the connection mutex.
func (mc *multiChannelNodeConn) appendPending(changes ...change.Change) {
	mc.pendingMu.Lock()

	mc.pending = append(mc.pending, changes...)
	mc.pendingSize += changesSize(changes)
	fullAtHead := len(mc.pending) > 0 && mc.pending[0].IsFull()

	// Pending drains only once the bundle in flight is delivered, so behind
	// workers it grew by every change; it renders folded anyway, and
	// folding twice gives what folding once does. Folding first leaves the
	// cap's collapse to a full map for backlogs that do not fold.
	if !fullAtHead && mc.pendingSize >= max(mc.pendingFoldAt, minPendingFold) {
		mc.setPendingLocked(change.CoalescePeerDeltas(mc.id, change.DedupePolicyChanges(mc.pending)))
		mc.pendingFoldAt = 2 * mc.pendingSize
	}

	if fullAtHead || mc.pendingSize > maxPendingSize {
		mc.setPendingLocked(change.CollapseToFull(mc.id, mc.pending))
	}
	mc.pendingMu.Unlock()
}

// prependPending puts changes at the head of the pending list, ahead of
// anything queued since. Used to retry changes that could not be
// delivered yet (initial map in flight): they were emitted before the
// currently pending ones, and order matters for stateful patches like
// online/offline.
func (mc *multiChannelNodeConn) prependPending(changes ...change.Change) {
	mc.pendingMu.Lock()
	full := (len(mc.pending) > 0 && mc.pending[0].IsFull()) ||
		(len(changes) > 0 && changes[0].IsFull())

	mc.pending = append(changes, mc.pending...)
	mc.pendingSize += changesSize(changes)

	if full || mc.pendingSize > maxPendingSize {
		mc.setPendingLocked(change.CollapseToFull(mc.id, mc.pending))
	}
	mc.pendingMu.Unlock()
}

// collapsePendingToFull replaces pending, together with incoming, by a
// single full update and the pings it cannot carry ([change.CollapseToFull]).
func (mc *multiChannelNodeConn) collapsePendingToFull(incoming []change.Change) {
	mc.pendingMu.Lock()
	mc.setPendingLocked(change.CollapseToFull(mc.id, slices.Concat(mc.pending, incoming)))
	mc.pendingMu.Unlock()
}

// drainPending atomically removes and returns all pending changes.
// Returns nil if there are no pending changes.
func (mc *multiChannelNodeConn) drainPending() []change.Change {
	mc.pendingMu.Lock()
	p := mc.pending
	mc.setPendingLocked(nil)
	mc.pendingMu.Unlock()

	return p
}

// setPendingLocked replaces pending. Caller must hold pendingMu.
func (mc *multiChannelNodeConn) setPendingLocked(p []change.Change) {
	mc.pending = p
	mc.pendingSize = changesSize(p)
}

// changesSize is how much pending holds for changes: each change, and the
// peers and patches it carries.
func changesSize(changes []change.Change) int {
	n := len(changes)
	for _, c := range changes {
		n += len(c.PeersChanged) + len(c.PeersRemoved) + len(c.PeerPatches)
	}

	return n
}

// takePending drains the pending changes for rendering. A node without a
// connection gets none and its changes are dropped: send would discard what
// they render, and its next connection opens with a full map rendered after
// it registered. The read lock keeps that registration out of the gap between
// the check and the drain.
func (mc *multiChannelNodeConn) takePending() []change.Change {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	p := mc.drainPending()
	if len(mc.connections) == 0 {
		mapperChangesDropped.WithLabelValues("no_connection").Add(float64(len(p)))

		return nil
	}

	return p
}

// send broadcasts data to all active connections for the node.
//
// To avoid holding the write lock during bounded channel waits, the method
// snapshots connections under a read lock, sends without any lock held, then
// write-locks only to remove failures. New connections added between the
// snapshot and cleanup are safe: [Batcher.AddNode] generates their initial
// map under workMu, after this bundle, so missing this update causes no data
// loss.
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

		return errNoActiveConnections
	}

	// A connection still awaiting its initial map must not get this
	// update first, and the map may predate it: send to none until the
	// map is out, see [errNoReadyConnections].
	if slices.ContainsFunc(mc.connections, func(conn *connectionEntry) bool {
		return conn.pendingInitial.Load()
	}) {
		mc.mutex.RUnlock()
		mc.log.Trace().
			Msg("send: a connection awaits its initial map, requeue")

		return errNoReadyConnections
	}

	snapshot := slices.Clone(mc.connections)

	mc.mutex.RUnlock()

	mc.log.Trace().
		Int("total_connections", len(snapshot)).
		Msg("send: broadcasting")

	// Send to all connections without holding any lock.
	// Bounded channel waits do not block other goroutines that need the mutex.
	var (
		lastErr        error
		successCount   int
		failed         []*connectionEntry
		blocked        []*connectionEntry
		newestAccepted bool
	)

	for _, conn := range snapshot {
		err := conn.send(conn.withSSHPolicyDelta(conn.withSelfDelta(data)))
		if errors.Is(err, errConnectionBackpressure) {
			blocked = append(blocked, conn)
			continue
		}

		if err != nil {
			lastErr = err

			failed = append(failed, conn)

			mc.log.Warn().Err(err).
				Str(zf.ConnID, conn.id).
				Msg("send: connection failed")
		} else {
			successCount++
			newestAccepted = conn == snapshot[len(snapshot)-1]

			if data.Node != nil {
				conn.lastSelf.Store(data.Node)
			}

			if data.SSHPolicy != nil {
				conn.lastSSHPolicy.Store(data.SSHPolicy)
			}
		}
	}

	// The newest ready stream supersedes blocked siblings left by reconnect overlap.
	if newestAccepted {
		failed = append(failed, blocked...)
		blocked = nil
	}

	// Write-lock only to remove failed connections.
	if len(failed) > 0 {
		mc.mutex.Lock()
		// Remove by pointer identity: only remove entries that still exist
		// in the current connections slice and match a failed pointer.
		// New connections added since the snapshot are not affected.
		// DeleteFunc preserves order and zeroes trailing slots so removed
		// *connectionEntry values are not retained by the backing array.
		mc.connections = slices.DeleteFunc(mc.connections, func(conn *connectionEntry) bool {
			if !slices.Contains(failed, conn) {
				return false
			}

			mc.log.Debug().
				Str(zf.ConnID, conn.id).
				Msg("send: removing failed connection")
			// Tear down the owning session so the old serveLongPoll
			// goroutine exits instead of lingering as a stale session.
			mc.stopConnection(conn)

			return true
		})
		mc.mutex.Unlock()
	}

	mc.updateCount.Add(1)

	mc.log.Trace().
		Int("successful_sends", successCount).
		Int("failed_connections", len(failed)).
		Msg("send: broadcast complete")

	if len(blocked) > 0 {
		if successCount > 0 {
			// Partial additions still need removal if a retry renders newer state without them.
			for _, peer := range slices.Concat(data.Peers, data.PeersChanged) {
				mc.partialPeers.Store(peer.ID, struct{}{})
			}
		}

		return errConnectionBackpressure
	}

	// Success if at least one send succeeded
	if successCount > 0 {
		return nil
	}

	return fmt.Errorf("node %d: all connections failed, last error: %w", mc.id, lastErr)
}

// send distinguishes temporary backpressure from a connection that has stopped making progress.
func (entry *connectionEntry) send(data *tailcfg.MapResponse) error {
	if data == nil {
		return nil
	}

	// Check if the connection has been closed to prevent send on closed channel panic.
	// This can happen during shutdown when Close() is called while workers are still processing.
	if entry.closed.Load() {
		return fmt.Errorf("connection %s: %w", entry.id, errConnectionClosed)
	}

	// Let a draining client free a slot before yielding this worker to other nodes.
	//
	// Use a timer rather than time.After so the timeout is explicitly released
	// on the fast path; both are GC-recoverable since Go 1.23.
	timer := time.NewTimer(50 * time.Millisecond) //nolint:mnd
	defer timer.Stop()

	select {
	case entry.c <- data:
		// Update last used timestamp on successful send
		entry.lastUsed.Store(time.Now().Unix())
		entry.blockedSince.Store(nil)

		return nil
	case <-entry.done:
		return fmt.Errorf("connection %s: %w", entry.id, errConnectionClosed)
	case <-entry.batcherDone:
		return ErrBatcherShuttingDown
	case <-timer.C:
	}

	// A short stall can be a busy reader; only evict after progress stops for the stall budget.
	since := entry.blockedSince.Load()
	if since == nil {
		now := time.Now()
		entry.blockedSince.CompareAndSwap(nil, &now)
	} else if time.Since(*since) >= connectionStallTimeout {
		// Connection is likely stale - client isn't reading from channel
		// This catches the case where Docker containers are killed but channels remain open
		return fmt.Errorf("connection %s: %w", entry.id, ErrConnectionSendTimeout)
	}

	return errConnectionBackpressure
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

// updateSentPeers updates the tracked peer state based on a sent [tailcfg.MapResponse].
// This must be called after successfully sending a response to keep track of
// what the client knows about, enabling accurate diffs for future updates.
func (mc *multiChannelNodeConn) updateSentPeers(resp *tailcfg.MapResponse) {
	if resp == nil {
		return
	}

	// Full peer list replaces tracked state entirely
	if resp.Peers != nil {
		mc.partialPeers.Clear()
		mc.lastSentPeers.Clear()

		for _, peer := range resp.Peers {
			mc.lastSentPeers.Store(peer.ID, struct{}{})
		}
	}

	// Incremental additions
	for _, peer := range resp.PeersChanged {
		mc.partialPeers.Delete(peer.ID)
		mc.lastSentPeers.Store(peer.ID, struct{}{})
	}

	// Incremental removals
	for _, id := range resp.PeersRemoved {
		mc.partialPeers.Delete(id)
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
	for _, sent := range []*xsync.Map[tailcfg.NodeID, struct{}]{mc.lastSentPeers, mc.partialPeers} {
		sent.Range(func(id tailcfg.NodeID, _ struct{}) bool {
			if _, exists := currentSet[id]; !exists {
				removed = append(removed, id)
				currentSet[id] = struct{}{}
			}

			return true
		})
	}

	return removed
}

// change applies a change to all active connections for the node.
func (mc *multiChannelNodeConn) change(r change.Change) error {
	return handleNodeChange(mc, mc.mapper, r)
}
