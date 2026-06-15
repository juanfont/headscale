package state

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
	"tailscale.com/util/dnsname"
)

// fallbackGivenName is the DNS label used when a node is written with
// an empty [types.Node.GivenName]. Matches Tailscale SaaS behaviour
// for empty sanitised labels.
const fallbackGivenName = "node"

// Errors returned by [NodeStore.SetGivenName]. [ErrNodeNotFound] is defined
// in state.go and reused here.
var (
	ErrGivenNameTaken   = errors.New("given name already in use by another node")
	ErrGivenNameInvalid = errors.New("given name is not a valid DNS label")
)

const (
	put             = 1
	del             = 2
	rebuildPeerMaps = 4
	setName         = 5
	updateMulti     = 6
)

const prometheusNamespace = "headscale"

var (
	nodeStoreOperations = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "nodestore_operations_total",
		Help:      "Total number of NodeStore operations",
	}, []string{"operation"})
	nodeStoreOperationDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: prometheusNamespace,
		Name:      "nodestore_operation_duration_seconds",
		Help:      "Duration of NodeStore operations",
		Buckets:   prometheus.DefBuckets,
	}, []string{"operation"})
	nodeStoreBatchSize = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: prometheusNamespace,
		Name:      "nodestore_batch_size",
		Help:      "Size of NodeStore write batches",
		Buckets:   []float64{1, 2, 5, 10, 20, 50, 100},
	})
	nodeStoreBatchDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: prometheusNamespace,
		Name:      "nodestore_batch_duration_seconds",
		Help:      "Duration of NodeStore batch processing",
		Buckets:   prometheus.DefBuckets,
	})
	nodeStoreSnapshotBuildDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: prometheusNamespace,
		Name:      "nodestore_snapshot_build_duration_seconds",
		Help:      "Duration of NodeStore snapshot building from nodes",
		Buckets:   prometheus.DefBuckets,
	})
	nodeStoreNodesCount = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: prometheusNamespace,
		Name:      "nodestore_nodes",
		Help:      "Number of nodes in the NodeStore",
	})
	nodeStorePeersCalculationDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: prometheusNamespace,
		Name:      "nodestore_peers_calculation_duration_seconds",
		Help:      "Duration of peers calculation in NodeStore",
		Buckets:   prometheus.DefBuckets,
	})
	nodeStoreQueueDepth = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: prometheusNamespace,
		Name:      "nodestore_queue_depth",
		Help:      "Current depth of NodeStore write queue",
	})
)

// NodeStore is a thread-safe store for nodes.
// It is a copy-on-write structure, replacing the "snapshot"
// when a change to the structure occurs. It is optimised for reads,
// and while batches are not fast, they are grouped together
// to do less of the expensive peer calculation if there are many
// changes rapidly.
//
// Writes will block until committed, while reads are never
// blocked. This means that the caller of a write operation
// is responsible for ensuring an update depending on a write
// is not issued before the write is complete.
type NodeStore struct {
	data atomic.Pointer[Snapshot]

	peersFunc  PeersFunc
	writeQueue chan work

	// stopped is closed once by Stop to signal the writer goroutine to exit
	// and to let in-flight writes return cleanly instead of panicking with
	// "send on closed channel" during shutdown.
	stopped  chan struct{}
	stopOnce sync.Once

	batchSize    int
	batchTimeout time.Duration
}

func NewNodeStore(allNodes types.Nodes, peersFunc PeersFunc, batchSize int, batchTimeout time.Duration) *NodeStore {
	nodes := make(map[types.NodeID]types.Node, len(allNodes))
	for _, n := range allNodes {
		nodes[n.ID] = *n
	}

	snap := snapshotFromNodes(nodes, peersFunc, nil)

	store := &NodeStore{
		peersFunc:    peersFunc,
		batchSize:    batchSize,
		batchTimeout: batchTimeout,
		stopped:      make(chan struct{}),
	}
	store.data.Store(&snap)

	// Initialize node count gauge
	nodeStoreNodesCount.Set(float64(len(nodes)))

	return store
}

// Snapshot is the representation of the current state of the [NodeStore].
// It contains all nodes and their relationships.
// It is a copy-on-write structure, meaning that when a write occurs,
// a new [Snapshot] is created with the updated state,
// and replaces the old one atomically.
type Snapshot struct {
	// nodesByID is the main source of truth for nodes.
	nodesByID map[types.NodeID]types.Node

	// calculated from nodesByID
	nodesByNodeKey    map[key.NodePublic]types.NodeView
	nodesByMachineKey map[key.MachinePublic]map[types.UserID]types.NodeView
	peersByNode       map[types.NodeID][]types.NodeView
	nodesByUser       map[types.UserID][]types.NodeView
	allNodes          []types.NodeView

	// routes maps each prefix to its current primary advertiser. The
	// previous assignment is carried over when still valid so the
	// primary does not flap on every unrelated batch.
	routes         map[netip.Prefix]types.NodeID
	isPrimaryRoute map[types.NodeID]bool
}

// PeersFunc is a function that takes a list of nodes and returns a map
// with the relationships between nodes and their peers.
// This will typically be used to calculate which nodes can see each other
// based on the current policy.
type PeersFunc func(nodes []types.NodeView) map[types.NodeID][]types.NodeView

// work represents a single operation to be performed on the [NodeStore].
type work struct {
	op         int
	nodeID     types.NodeID
	node       types.Node
	result     chan struct{}
	nodeResult chan types.NodeView
	// For rebuildPeerMaps operation
	rebuildResult chan struct{}
	// For setName operation (admin rename, reject-on-collision path).
	name      string
	errResult chan error
	// For updateMulti: per-node update functions applied as a single
	// batch entry so callers that need an atomic election (e.g. the HA
	// prober applying multiple probe results at once) cannot have a
	// partial snapshot published between the updates.
	multiUpdates map[types.NodeID]UpdateNodeFunc
}

// PutNode adds or updates a node in the store.
// If the node already exists, it will be replaced.
// If the node does not exist, it will be added.
// This is a blocking operation that waits for the write to complete.
// Returns the resulting node after all modifications in the batch have been applied.
func (s *NodeStore) PutNode(n types.Node) types.NodeView {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("put"))
	defer timer.ObserveDuration()

	work := work{
		op:         put,
		nodeID:     n.ID,
		node:       n,
		result:     make(chan struct{}),
		nodeResult: make(chan types.NodeView, 1),
	}

	nodeStoreQueueDepth.Inc()

	select {
	case s.writeQueue <- work:
	case <-s.stopped:
		nodeStoreQueueDepth.Dec()

		return types.NodeView{}
	}

	<-work.result
	nodeStoreQueueDepth.Dec()

	resultNode := <-work.nodeResult

	nodeStoreOperations.WithLabelValues("put").Inc()

	return resultNode
}

// UpdateNodeFunc is a function type that takes a pointer to a [types.Node] and modifies it.
type UpdateNodeFunc func(n *types.Node)

// UpdateNode applies a function to modify a specific node in the
// store. Single-node convenience wrapper around [NodeStore.UpdateNodes]
// — the writer goroutine signals completion only after the post-batch
// snapshot has been stored, so the follow-up [NodeStore.GetNode] read
// sees the applied update. Returns the resulting node and whether it
// exists.
//
// Callers that need to change several nodes atomically should call
// [NodeStore.UpdateNodes] directly; collecting changes into one batch
// keeps the election from running on a half-applied snapshot.
func (s *NodeStore) UpdateNode(nodeID types.NodeID, updateFn UpdateNodeFunc) (types.NodeView, bool) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("update"))
	defer timer.ObserveDuration()

	s.UpdateNodes(map[types.NodeID]UpdateNodeFunc{nodeID: updateFn})

	nodeStoreOperations.WithLabelValues("update").Inc()

	return s.GetNode(nodeID)
}

// UpdateNodes applies per-node update functions in a single atomic
// batch. The election that recomputes primary routes runs once, after
// every update has landed, so callers cannot observe an intermediate
// snapshot where only some of the updates are visible. Use this when
// the order in which two writers' updates are individually published
// would change the election outcome — e.g. the HA prober applying
// concurrent probe-timeout results.
func (s *NodeStore) UpdateNodes(updates map[types.NodeID]UpdateNodeFunc) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("update_multi"))
	defer timer.ObserveDuration()

	if len(updates) == 0 {
		return
	}

	w := work{
		op:           updateMulti,
		multiUpdates: updates,
		result:       make(chan struct{}),
	}

	nodeStoreQueueDepth.Inc()

	select {
	case s.writeQueue <- w:
	case <-s.stopped:
		nodeStoreQueueDepth.Dec()

		return
	}

	<-w.result
	nodeStoreQueueDepth.Dec()

	nodeStoreOperations.WithLabelValues("update_multi").Inc()
}

// DeleteNode removes a node from the store by its ID.
// This is a blocking operation that waits for the write to complete.
func (s *NodeStore) DeleteNode(id types.NodeID) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("delete"))
	defer timer.ObserveDuration()

	work := work{
		op:     del,
		nodeID: id,
		result: make(chan struct{}),
	}

	nodeStoreQueueDepth.Inc()

	select {
	case s.writeQueue <- work:
	case <-s.stopped:
		nodeStoreQueueDepth.Dec()

		return
	}

	<-work.result
	nodeStoreQueueDepth.Dec()

	nodeStoreOperations.WithLabelValues("delete").Inc()
}

// SetGivenName sets [types.Node.GivenName] on the node identified by id,
// rejecting the write if the name is already held by another node.
// Intended for the admin rename path, where auto-bumping a
// user-supplied name would be surprising.
//
// Returns:
//   - the stored [types.NodeView] and nil on success
//   - [ErrGivenNameInvalid]   if name is not a valid DNS label
//   - [ErrGivenNameTaken]     if another node already holds name
//   - [ErrNodeNotFound]       if no node with id exists
//
// Runs as a single writer-goroutine op, so the uniqueness check and the
// write are atomic with respect to concurrent
// [NodeStore.PutNode]/[NodeStore.UpdateNode].
func (s *NodeStore) SetGivenName(id types.NodeID, name string) (types.NodeView, error) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("set_name"))
	defer timer.ObserveDuration()

	w := work{
		op:         setName,
		nodeID:     id,
		name:       name,
		result:     make(chan struct{}),
		nodeResult: make(chan types.NodeView, 1),
		errResult:  make(chan error, 1),
	}

	nodeStoreQueueDepth.Inc()

	select {
	case s.writeQueue <- w:
	case <-s.stopped:
		nodeStoreQueueDepth.Dec()

		return types.NodeView{}, nil
	}

	<-w.result
	nodeStoreQueueDepth.Dec()

	nodeStoreOperations.WithLabelValues("set_name").Inc()

	err := <-w.errResult
	if err != nil {
		return types.NodeView{}, err
	}

	return <-w.nodeResult, nil
}

// Start initializes the [NodeStore] and starts processing the write queue.
func (s *NodeStore) Start() {
	s.writeQueue = make(chan work)
	go s.processWrite()
}

// Stop stops the [NodeStore]. It signals the writer goroutine via stopped
// rather than closing writeQueue, so writes racing shutdown drop cleanly
// instead of panicking on a closed channel.
func (s *NodeStore) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopped)
	})
}

// processWrite processes the write queue in batches.
func (s *NodeStore) processWrite() {
	c := time.NewTicker(s.batchTimeout)
	defer c.Stop()

	batch := make([]work, 0, s.batchSize)

	for {
		select {
		case w := <-s.writeQueue:
			batch = append(batch, w)
			if len(batch) >= s.batchSize {
				s.applyBatch(batch)
				batch = batch[:0]

				c.Reset(s.batchTimeout)
			}
		case <-c.C:
			if len(batch) != 0 {
				s.applyBatch(batch)
				batch = batch[:0]
			}

			c.Reset(s.batchTimeout)
		case <-s.stopped:
			// Apply any remaining batch so in-flight writers receive their
			// results, then exit.
			if len(batch) != 0 {
				s.applyBatch(batch)
			}

			return
		}
	}
}

// applyBatch applies a batch of work to the node store.
// This means that it takes a copy of the current nodes,
// then applies the batch of operations to that copy,
// runs any precomputation needed (like calculating peers),
// and finally replaces the snapshot in the store with the new one.
// The replacement of the snapshot is atomic, ensuring that reads
// are never blocked by writes.
// Each write item is blocked until the batch is applied to ensure
// the caller knows the operation is complete and do not send any
// updates that are dependent on a read that is yet to be written.
func (s *NodeStore) applyBatch(batch []work) {
	timer := prometheus.NewTimer(nodeStoreBatchDuration)
	defer timer.ObserveDuration()

	nodeStoreBatchSize.Observe(float64(len(batch)))

	nodes := make(map[types.NodeID]types.Node)
	maps.Copy(nodes, s.data.Load().nodesByID)

	// Track which work items need node results
	nodeResultRequests := make(map[types.NodeID][]*work)

	// Track rebuildPeerMaps operations
	var rebuildOps []*work

	// setErrResults collects per-work errors from the setName path so
	// they can be delivered after the snapshot swap, together with the
	// NodeView for that work.
	setErrResults := make(map[*work]error)

	for i := range batch {
		w := &batch[i]
		switch w.op {
		case put:
			n := w.node
			n.GivenName = resolveGivenName(nodes, n.ID, n.GivenName)

			nodes[w.nodeID] = n
			if w.nodeResult != nil {
				nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)
			}
		case updateMulti:
			for id, fn := range w.multiUpdates {
				n, exists := nodes[id]
				if !exists {
					continue
				}

				oldGivenName := n.GivenName
				fn(&n)

				if n.GivenName != oldGivenName {
					n.GivenName = resolveGivenName(nodes, n.ID, n.GivenName)
				}

				nodes[id] = n
			}
		case del:
			delete(nodes, w.nodeID)
			// For delete operations, send an invalid NodeView if requested
			if w.nodeResult != nil {
				nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)
			}
		case setName:
			n, exists := nodes[w.nodeID]
			if !exists {
				setErrResults[w] = ErrNodeNotFound
				nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)

				continue
			}

			if dnsname.ValidLabel(w.name) != nil {
				setErrResults[w] = ErrGivenNameInvalid
				nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)

				continue
			}

			taken := false

			for id, other := range nodes {
				if id != w.nodeID && other.GivenName == w.name {
					taken = true
					break
				}
			}

			if taken {
				setErrResults[w] = ErrGivenNameTaken
				nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)

				continue
			}

			n.GivenName = w.name
			nodes[w.nodeID] = n
			nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)
		case rebuildPeerMaps:
			// rebuildPeerMaps doesn't modify nodes, it just forces the snapshot rebuild
			// below to recalculate peer relationships using the current peersFunc
			rebuildOps = append(rebuildOps, w)
		}
	}

	prev := s.data.Load()
	newSnap := snapshotFromNodes(nodes, s.peersFunc, prev.routes)
	s.data.Store(&newSnap)

	// Update node count gauge
	nodeStoreNodesCount.Set(float64(len(nodes)))

	// Send the resulting nodes to all work items that requested them
	for nodeID, workItems := range nodeResultRequests {
		if node, exists := nodes[nodeID]; exists {
			nodeView := node.View()
			for _, w := range workItems {
				w.nodeResult <- nodeView

				close(w.nodeResult)

				if w.errResult != nil {
					w.errResult <- setErrResults[w]

					close(w.errResult)
				}
			}
		} else {
			// Node was deleted or doesn't exist
			for _, w := range workItems {
				w.nodeResult <- types.NodeView{} // Send invalid view

				close(w.nodeResult)

				if w.errResult != nil {
					w.errResult <- setErrResults[w]

					close(w.errResult)
				}
			}
		}
	}

	// Signal completion for rebuildPeerMaps operations
	for _, w := range rebuildOps {
		close(w.rebuildResult)
	}

	// Signal completion for all other work items
	for _, w := range batch {
		if w.op != rebuildPeerMaps {
			close(w.result)
		}
	}
}

// resolveGivenName returns a unique DNS label for the node identified
// by self, based on the caller-supplied base label. If base is empty
// it falls back to [fallbackGivenName] ("node"). The label's own holder
// (self) is excluded from the collision scan so an idempotent write
// keeps the current label.
//
// On collision the label is bumped as base, base-1, base-2, …, first
// unused wins. Must be called from the [NodeStore] writer goroutine
// (inside [NodeStore.applyBatch]) so the nodes map reflects all earlier
// ops in the batch and no other writer can interleave.
func resolveGivenName(nodes map[types.NodeID]types.Node, self types.NodeID, base string) string {
	if base == "" {
		base = fallbackGivenName
	}

	taken := make(map[string]struct{}, len(nodes))
	for id, n := range nodes {
		if id == self {
			continue
		}

		taken[n.GivenName] = struct{}{}
	}

	candidate := base
	for i := 1; ; i++ {
		if _, busy := taken[candidate]; !busy {
			return candidate
		}

		candidate = base + "-" + strconv.Itoa(i)
	}
}

// snapshotFromNodes builds the index maps and primary-route table for
// a new [Snapshot]. prevRoutes carries forward the previous primary
// assignment so a still-valid choice survives unrelated batches.
func snapshotFromNodes(
	nodes map[types.NodeID]types.Node,
	peersFunc PeersFunc,
	prevRoutes map[netip.Prefix]types.NodeID,
) Snapshot {
	timer := prometheus.NewTimer(nodeStoreSnapshotBuildDuration)
	defer timer.ObserveDuration()

	allNodes := make([]types.NodeView, 0, len(nodes))
	for _, n := range nodes {
		allNodes = append(allNodes, n.View())
	}

	routes, isPrimaryRoute := electPrimaryRoutes(nodes, prevRoutes)

	newSnap := Snapshot{
		nodesByID:         nodes,
		allNodes:          allNodes,
		nodesByNodeKey:    make(map[key.NodePublic]types.NodeView),
		nodesByMachineKey: make(map[key.MachinePublic]map[types.UserID]types.NodeView),

		// peersByNode is most likely the most expensive operation,
		// it will use the list of all nodes, combined with the
		// current policy to precalculate which nodes are peers and
		// can see each other.
		peersByNode: func() map[types.NodeID][]types.NodeView {
			peersTimer := prometheus.NewTimer(nodeStorePeersCalculationDuration)
			defer peersTimer.ObserveDuration()

			return peersFunc(allNodes)
		}(),
		nodesByUser: make(map[types.UserID][]types.NodeView),

		routes:         routes,
		isPrimaryRoute: isPrimaryRoute,
	}

	// Build nodesByUser, nodesByNodeKey, and nodesByMachineKey maps
	for _, n := range nodes {
		nodeView := n.View()
		userID := n.TypedUserID()

		// Tagged nodes are owned by their tags, not a user,
		// so they are not indexed by user.
		if !n.IsTagged() {
			newSnap.nodesByUser[userID] = append(newSnap.nodesByUser[userID], nodeView)
		}

		newSnap.nodesByNodeKey[n.NodeKey] = nodeView

		// Build machine key index
		if newSnap.nodesByMachineKey[n.MachineKey] == nil {
			newSnap.nodesByMachineKey[n.MachineKey] = make(map[types.UserID]types.NodeView)
		}

		newSnap.nodesByMachineKey[n.MachineKey][userID] = nodeView
	}

	return newSnap
}

// electPrimaryRoutes picks the primary advertiser for each non-exit
// prefix. Inputs are restricted to online nodes that advertise the
// prefix. The previous primary is preserved when it is still online
// and healthy (anti-flap); otherwise the lowest-NodeID healthy
// advertiser wins. When every advertiser is unhealthy the previous
// primary is preserved only if still a candidate — falling back to
// any other candidate would point peers at a node the prober has
// already declared unreachable, so leaving the prefix unmapped is
// preferred until a probe cycle finds one that responds.
func electPrimaryRoutes(
	nodes map[types.NodeID]types.Node,
	prev map[netip.Prefix]types.NodeID,
) (map[netip.Prefix]types.NodeID, map[types.NodeID]bool) {
	ids := make([]types.NodeID, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}

	slices.Sort(ids)

	advertisers := make(map[netip.Prefix][]types.NodeID)

	for _, id := range ids {
		n := nodes[id]
		if n.IsOnline == nil || !*n.IsOnline {
			continue
		}

		for _, p := range n.AllApprovedRoutes() {
			if tsaddr.IsExitRoute(p) {
				continue
			}

			advertisers[p] = append(advertisers[p], id)
		}
	}

	routes := make(map[netip.Prefix]types.NodeID, len(advertisers))
	for prefix, candidates := range advertisers {
		if cur, ok := prev[prefix]; ok &&
			slices.Contains(candidates, cur) &&
			!nodes[cur].Unhealthy {
			routes[prefix] = cur
			continue
		}

		var (
			selected types.NodeID
			found    bool
		)

		for _, c := range candidates {
			if !nodes[c].Unhealthy {
				selected = c
				found = true

				break
			}
		}

		// All-unhealthy fallback: preserve the previous primary only
		// when it is still a candidate. Falling back to any candidate
		// would point peers at a node the prober has already declared
		// unreachable; leaving the prefix unmapped is honest until a
		// probe cycle picks one that responds.
		if !found && len(candidates) >= 1 {
			if cur, ok := prev[prefix]; ok && slices.Contains(candidates, cur) {
				selected = cur
				found = true
			}
		}

		if found {
			routes[prefix] = selected
		}
	}

	isPrimaryRoute := make(map[types.NodeID]bool, len(routes))
	for _, id := range routes {
		isPrimaryRoute[id] = true
	}

	return routes, isPrimaryRoute
}

// GetNode retrieves a node by its ID.
// The bool indicates if the node exists or is available (like "err not found").
// The [types.NodeView] might be invalid, so it must be checked with .Valid(), which must
// be used to ensure it isn't an invalid node (this is more of a node error or node is broken).
func (s *NodeStore) GetNode(id types.NodeID) (types.NodeView, bool) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("get"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("get").Inc()

	n, exists := s.data.Load().nodesByID[id]
	if !exists {
		return types.NodeView{}, false
	}

	return n.View(), true
}

// GetNodeByNodeKey retrieves a node by its [key.NodePublic].
// The bool indicates if the node exists or is available (like "err not found").
// The [types.NodeView] might be invalid, so it must be checked with .Valid(), which must
// be used to ensure it isn't an invalid node (this is more of a node error or node is broken).
func (s *NodeStore) GetNodeByNodeKey(nodeKey key.NodePublic) (types.NodeView, bool) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("get_by_key"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("get_by_key").Inc()

	nodeView, exists := s.data.Load().nodesByNodeKey[nodeKey]

	return nodeView, exists
}

// GetNodesByMachineKeyAllUsers returns every node sharing machineKey, keyed by
// owning UserID. Tagged nodes are indexed under UserID(0) (the tagged sentinel);
// user-owned nodes under their owning UserID. Returns an empty map if none.
//
// One machine key can map to several nodes (the same device registered by
// different users via the "create new, do not transfer" path). Exposing the
// whole set lets callers decide with full context — index [userID] for an exact
// match, [0] for a tagged node, or reject when the set is ambiguous — rather
// than guessing from a single arbitrary pick.
func (s *NodeStore) GetNodesByMachineKeyAllUsers(machineKey key.MachinePublic) map[types.UserID]types.NodeView {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("get_nodes_by_machine_key_all_users"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("get_nodes_by_machine_key_all_users").Inc()

	userMap := s.data.Load().nodesByMachineKey[machineKey]

	out := make(map[types.UserID]types.NodeView, len(userMap))
	maps.Copy(out, userMap)

	return out
}

// DebugString returns debug information about the [NodeStore].
func (s *NodeStore) DebugString() string {
	snapshot := s.data.Load()

	var sb strings.Builder

	sb.WriteString("=== NodeStore Debug Information ===\n\n")

	// Basic counts
	fmt.Fprintf(&sb, "Total Nodes: %d\n", len(snapshot.nodesByID))
	fmt.Fprintf(&sb, "Users with Nodes: %d\n", len(snapshot.nodesByUser))
	sb.WriteString("\n")

	// User distribution (shows internal UserID tracking, not display owner)
	sb.WriteString("Nodes by Internal User ID:\n")

	for userID, nodes := range snapshot.nodesByUser {
		if len(nodes) > 0 {
			userName := "unknown"

			if nodes[0].Valid() && nodes[0].User().Valid() {
				userName = nodes[0].User().Name()
			}

			fmt.Fprintf(&sb, "  - User %d (%s): %d nodes\n", userID, userName, len(nodes))
		}
	}

	sb.WriteString("\n")

	// Peer relationships summary
	sb.WriteString("Peer Relationships:\n")

	totalPeers := 0

	for nodeID, peers := range snapshot.peersByNode {
		peerCount := len(peers)

		totalPeers += peerCount
		if node, exists := snapshot.nodesByID[nodeID]; exists {
			fmt.Fprintf(&sb, "  - Node %d (%s): %d peers\n",
				nodeID, node.Hostname, peerCount)
		}
	}

	if len(snapshot.peersByNode) > 0 {
		avgPeers := float64(totalPeers) / float64(len(snapshot.peersByNode))
		fmt.Fprintf(&sb, "  - Average peers per node: %.1f\n", avgPeers)
	}

	sb.WriteString("\n")

	// Node key index
	fmt.Fprintf(&sb, "NodeKey Index: %d entries\n", len(snapshot.nodesByNodeKey))
	sb.WriteString("\n")

	return sb.String()
}

// ListNodes returns a slice of all nodes in the store.
func (s *NodeStore) ListNodes() views.Slice[types.NodeView] {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("list"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("list").Inc()

	return views.SliceOf(s.data.Load().allNodes)
}

// ListPeers returns a slice of all peers for a given node ID.
func (s *NodeStore) ListPeers(id types.NodeID) views.Slice[types.NodeView] {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("list_peers"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("list_peers").Inc()

	return views.SliceOf(s.data.Load().peersByNode[id])
}

// PrimaryRouteFor returns the current primary advertiser for prefix.
func (s *NodeStore) PrimaryRouteFor(prefix netip.Prefix) (types.NodeID, bool) {
	id, ok := s.data.Load().routes[prefix]
	return id, ok
}

// PrimaryRoutesForNode returns the prefixes for which id is the current
// primary advertiser.
func (s *NodeStore) PrimaryRoutesForNode(id types.NodeID) []netip.Prefix {
	snap := s.data.Load()
	if !snap.isPrimaryRoute[id] {
		return nil
	}

	out := make([]netip.Prefix, 0)

	for prefix, nodeID := range snap.routes {
		if nodeID == id {
			out = append(out, prefix)
		}
	}

	return out
}

// HANodes returns the prefixes with two or more online advertisers, the
// candidate set the HA prober needs to monitor.
func (s *NodeStore) HANodes() map[netip.Prefix][]types.NodeID {
	snap := s.data.Load()

	advertisers := make(map[netip.Prefix][]types.NodeID)

	for id, n := range snap.nodesByID {
		if n.IsOnline == nil || !*n.IsOnline {
			continue
		}

		for _, p := range n.AllApprovedRoutes() {
			if tsaddr.IsExitRoute(p) {
				continue
			}

			advertisers[p] = append(advertisers[p], id)
		}
	}

	out := make(map[netip.Prefix][]types.NodeID)

	for p, ids := range advertisers {
		if len(ids) < 2 {
			continue
		}

		slices.Sort(ids)
		out[p] = ids
	}

	return out
}

// IsNodeHealthy reports whether the HA prober considers id healthy.
// Unknown nodes report healthy so absence does not exclude them from
// election.
func (s *NodeStore) IsNodeHealthy(id types.NodeID) bool {
	n, ok := s.data.Load().nodesByID[id]
	if !ok {
		return true
	}

	return !n.Unhealthy
}

// PrimaryRoutes returns the snapshot's prefix→primary map. The map is
// owned by the snapshot and must not be mutated; it is safe to read
// concurrently because snapshots are immutable once published.
func (s *NodeStore) PrimaryRoutes() map[netip.Prefix]types.NodeID {
	return s.data.Load().routes
}

// PrimaryRoutesString renders the snapshot's prefix→primary map for
// debug output and test diagnostics.
func (s *NodeStore) PrimaryRoutesString() string {
	snap := s.data.Load()
	if len(snap.routes) == 0 {
		return ""
	}

	prefixes := make([]netip.Prefix, 0, len(snap.routes))
	for p := range snap.routes {
		prefixes = append(prefixes, p)
	}

	slices.SortFunc(prefixes, netip.Prefix.Compare)

	var b strings.Builder
	for _, p := range prefixes {
		fmt.Fprintf(&b, "%s: %d\n", p, snap.routes[p])
	}

	return b.String()
}

// RebuildPeerMaps rebuilds the peer relationship map using the current [PeersFunc].
// This must be called after policy changes because [PeersFunc] uses [policy.PolicyManager]'s
// filters to determine which nodes can see each other. Without rebuilding, the
// peer map would use stale filter data until the next node add/delete.
func (s *NodeStore) RebuildPeerMaps() {
	result := make(chan struct{})

	w := work{
		op:            rebuildPeerMaps,
		rebuildResult: result,
	}

	s.writeQueue <- w

	<-result
}

// ListNodesByUser returns a slice of all nodes for a given user ID.
func (s *NodeStore) ListNodesByUser(uid types.UserID) views.Slice[types.NodeView] {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("list_by_user"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("list_by_user").Inc()

	return views.SliceOf(s.data.Load().nodesByUser[uid])
}
