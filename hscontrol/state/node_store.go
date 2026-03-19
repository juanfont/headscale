package state

import (
	"fmt"
	"maps"
	"strings"
	"sync/atomic"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

const (
	put             = 1
	del             = 2
	update          = 3
	rebuildPeerMaps = 4
	refreshPeers    = 5
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

	peersFunc            PeersFunc
	incrementalPeersFunc IncrementalPeersFunc
	writeQueue           chan work

	batchSize    int
	batchTimeout time.Duration
}

func NewNodeStore(allNodes types.Nodes, peersFunc PeersFunc, batchSize int, batchTimeout time.Duration) *NodeStore {
	nodes := make(map[types.NodeID]types.Node, len(allNodes))
	for _, n := range allNodes {
		nodes[n.ID] = *n
	}

	snap := snapshotFromNodes(nodes, peersFunc)

	store := &NodeStore{
		peersFunc:    peersFunc,
		batchSize:    batchSize,
		batchTimeout: batchTimeout,
	}
	store.data.Store(&snap)

	// Initialize node count gauge
	nodeStoreNodesCount.Set(float64(len(nodes)))

	return store
}

// Snapshot is the representation of the current state of the NodeStore.
// It contains all nodes and their relationships.
// It is a copy-on-write structure, meaning that when a write occurs,
// a new Snapshot is created with the updated state,
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
}

// PeersFunc is a function that takes a list of nodes and returns a map
// with the relationships between nodes and their peers.
// This will typically be used to calculate which nodes can see each other
// based on the current policy.
type PeersFunc func(nodes []types.NodeView) map[types.NodeID][]types.NodeView

// work represents a single operation to be performed on the NodeStore.
type work struct {
	op         int
	nodeID     types.NodeID
	node       types.Node
	updateFn   UpdateNodeFunc
	result     chan struct{}
	nodeResult chan types.NodeView // Channel to return the resulting node after batch application
	// For rebuildPeerMaps and refreshPeers operations
	rebuildResult chan struct{}
	// For refreshPeers: which node IDs to refresh
	refreshNodeIDs []types.NodeID
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

	s.writeQueue <- work

	<-work.result
	nodeStoreQueueDepth.Dec()

	resultNode := <-work.nodeResult

	nodeStoreOperations.WithLabelValues("put").Inc()

	return resultNode
}

// UpdateNodeFunc is a function type that takes a pointer to a Node and modifies it.
type UpdateNodeFunc func(n *types.Node)

// UpdateNode applies a function to modify a specific node in the store.
// This is a blocking operation that waits for the write to complete.
// This is analogous to a database "transaction", or, the caller should
// rather collect all data they want to change, and then call this function.
// Fewer calls are better.
// Returns the resulting node after all modifications in the batch have been applied.
//
// TODO(kradalby): Technically we could have a version of this that modifies the node
// in the current snapshot if _we know_ that the change will not affect the peer relationships.
// This is because the main nodesByID map contains the struct, and every other map is using a
// pointer to the underlying struct. The gotcha with this is that we will need to introduce
// a lock around the nodesByID map to ensure that no other writes are happening
// while we are modifying the node. Which mean we would need to implement read-write locks
// on all read operations.
func (s *NodeStore) UpdateNode(nodeID types.NodeID, updateFn func(n *types.Node)) (types.NodeView, bool) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("update"))
	defer timer.ObserveDuration()

	work := work{
		op:         update,
		nodeID:     nodeID,
		updateFn:   updateFn,
		result:     make(chan struct{}),
		nodeResult: make(chan types.NodeView, 1),
	}

	nodeStoreQueueDepth.Inc()

	s.writeQueue <- work

	<-work.result
	nodeStoreQueueDepth.Dec()

	resultNode := <-work.nodeResult

	nodeStoreOperations.WithLabelValues("update").Inc()

	// Return the node and whether it exists (is valid)
	return resultNode, resultNode.Valid()
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

	s.writeQueue <- work

	<-work.result
	nodeStoreQueueDepth.Dec()

	nodeStoreOperations.WithLabelValues("delete").Inc()
}

// Start initializes the NodeStore and starts processing the write queue.
func (s *NodeStore) Start() {
	s.writeQueue = make(chan work, s.batchSize)
	go s.processWrite()
}

// Stop stops the NodeStore.
func (s *NodeStore) Stop() {
	close(s.writeQueue)
}

// processWrite processes the write queue in batches.
// Uses a short micro-batch window: after receiving the first item, waits
// up to 1ms for more items to arrive before applying the batch. This
// eliminates the original 500ms batchTimeout wait during burst registration
// (where concurrent operations arrive within microseconds) while still
// batching concurrent operations correctly.
func (s *NodeStore) processWrite() {
	batch := make([]work, 0, s.batchSize)

	for {
		// Block until at least one item arrives (or channel closes).
		w, ok := <-s.writeQueue
		if !ok {
			if len(batch) != 0 {
				s.applyBatch(batch)
			}

			return
		}

		batch = append(batch, w)

		// Short micro-batch window: collect concurrent items arriving
		// within 1ms. This is long enough for goroutine scheduling but
		// 500x shorter than the original batchTimeout.
		timer := time.NewTimer(time.Millisecond)

	drain:
		for len(batch) < s.batchSize {
			select {
			case w2, ok2 := <-s.writeQueue:
				if !ok2 {
					break drain
				}

				batch = append(batch, w2)
			case <-timer.C:
				break drain
			}
		}

		timer.Stop()

		s.applyBatch(batch)
		batch = batch[:0]
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

	// Track whether any operation changes peer-visibility-relevant fields
	// (user, tags, IPs) vs only non-identity fields (endpoints, DERP, hostinfo).
	identityChanged := false

	for i := range batch {
		w := &batch[i]
		switch w.op {
		case put:
			nodes[w.nodeID] = w.node
			if w.nodeResult != nil {
				nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)
			}
		case update:
			// Update the specific node identified by nodeID
			if n, exists := nodes[w.nodeID]; exists {
				before := n.View()
				w.updateFn(&n)
				nodes[w.nodeID] = n
				if before.HasPolicyChange(n.View()) {
					identityChanged = true
				}
			}

			if w.nodeResult != nil {
				nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)
			}
		case del:
			delete(nodes, w.nodeID)
			identityChanged = true
			// For delete operations, send an invalid NodeView if requested
			if w.nodeResult != nil {
				nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)
			}
		case rebuildPeerMaps:
			// rebuildPeerMaps doesn't modify nodes, it just forces the snapshot rebuild
			// below to recalculate peer relationships using the current peersFunc
			identityChanged = true
			rebuildOps = append(rebuildOps, w)
		case refreshPeers:
			// refreshPeers recomputes peers for specific nodes only.
			// Handled after snapshot build below.
			rebuildOps = append(rebuildOps, w)
		}
	}

	// Classify the batch to decide rebuild strategy:
	// - Pure puts of new nodes (not replacing existing): use incremental snapshot
	// - Any deletes, identity-changing updates, or rebuildPeerMaps: full rebuild
	// - Updates that only change non-identity fields (endpoints, DERP, hostinfo):
	//   shallow snapshot reusing existing peersByNode
	oldSnap := s.data.Load()
	canIncremental := !identityChanged
	var newNodeIDs []types.NodeID

	if canIncremental {
		for i := range batch {
			w := &batch[i]
			switch w.op {
			case put:
				if _, existed := oldSnap.nodesByID[w.nodeID]; existed {
					canIncremental = false
				} else {
					newNodeIDs = append(newNodeIDs, w.nodeID)
				}
			case del:
				canIncremental = false
			// update ops that reach here have no identity change — safe for shallow
			}
			if !canIncremental {
				break
			}
		}
	}

	var newSnap Snapshot
	if canIncremental && len(newNodeIDs) > 0 && s.incrementalPeersFunc != nil {
		newSnap = incrementalSnapshot(oldSnap, nodes, newNodeIDs, s.incrementalPeersFunc)
	} else if canIncremental && len(newNodeIDs) == 0 {
		// Pure non-identity updates: reuse peer maps, just refresh node indexes
		newSnap = shallowSnapshot(oldSnap, nodes)
	} else {
		newSnap = snapshotFromNodes(nodes, s.peersFunc)
	}
	// Apply refreshPeers operations: recompute peers for specific nodes only.
	// This corrects stale peer data from PutNode that ran before policy update.
	if s.incrementalPeersFunc != nil {
		var refreshIDs []types.NodeID
		for i := range batch {
			if batch[i].op == refreshPeers {
				refreshIDs = append(refreshIDs, batch[i].refreshNodeIDs...)
			}
		}
		if len(refreshIDs) > 0 {
			newSnap = refreshNodePeers(&newSnap, nodes, refreshIDs, s.incrementalPeersFunc)
		}
	}

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
			}
		} else {
			// Node was deleted or doesn't exist
			for _, w := range workItems {
				w.nodeResult <- types.NodeView{} // Send invalid view

				close(w.nodeResult)
			}
		}
	}

	// Signal completion for rebuildPeerMaps and refreshPeers operations
	for _, w := range rebuildOps {
		close(w.rebuildResult)
	}

	// Signal completion for all other work items
	for _, w := range batch {
		if w.op != rebuildPeerMaps && w.op != refreshPeers {
			close(w.result)
		}
	}
}

// snapshotFromNodes creates a new Snapshot from the provided nodes.
// It builds a lot of "indexes" to make lookups fast for datasets we
// that is used frequently, like nodesByNodeKey, peersByNode, and nodesByUser.
// This is not a fast operation, it is the "slow" part of our copy-on-write
// structure, but it allows us to have fast reads and efficient lookups.
func snapshotFromNodes(nodes map[types.NodeID]types.Node, peersFunc PeersFunc) Snapshot {
	timer := prometheus.NewTimer(nodeStoreSnapshotBuildDuration)
	defer timer.ObserveDuration()

	allNodes := make([]types.NodeView, 0, len(nodes))
	for _, n := range nodes {
		allNodes = append(allNodes, n.View())
	}

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

// shallowSnapshot creates a new Snapshot reusing the old peersByNode map.
// This is used when updates only change non-identity fields (endpoints, DERP,
// hostinfo) that don't affect peer visibility, avoiding the expensive O(N²)
// BuildPeerMap call. It rebuilds all index maps with fresh NodeViews so
// readers see updated data, but peer relationships stay the same.
func shallowSnapshot(oldSnap *Snapshot, nodes map[types.NodeID]types.Node) Snapshot {
	timer := prometheus.NewTimer(nodeStoreSnapshotBuildDuration)
	defer timer.ObserveDuration()

	allNodes := make([]types.NodeView, 0, len(nodes))
	for _, n := range nodes {
		allNodes = append(allNodes, n.View())
	}

	// Rebuild peersByNode with fresh NodeViews pointing to the updated nodes.
	// The peer *relationships* (which IDs see which) are unchanged, but the
	// NodeView values must reflect the mutated node data.
	peersByNode := make(map[types.NodeID][]types.NodeView, len(oldSnap.peersByNode))
	for nodeID, oldPeers := range oldSnap.peersByNode {
		newPeers := make([]types.NodeView, 0, len(oldPeers))
		for _, p := range oldPeers {
			if n, ok := nodes[p.ID()]; ok {
				newPeers = append(newPeers, n.View())
			}
		}
		peersByNode[nodeID] = newPeers
	}

	newSnap := Snapshot{
		nodesByID:         nodes,
		allNodes:          allNodes,
		nodesByNodeKey:    make(map[key.NodePublic]types.NodeView, len(nodes)),
		nodesByMachineKey: make(map[key.MachinePublic]map[types.UserID]types.NodeView),
		peersByNode:       peersByNode,
		nodesByUser:       make(map[types.UserID][]types.NodeView),
	}

	for _, n := range nodes {
		nodeView := n.View()
		userID := n.TypedUserID()

		if !n.IsTagged() {
			newSnap.nodesByUser[userID] = append(newSnap.nodesByUser[userID], nodeView)
		}

		newSnap.nodesByNodeKey[n.NodeKey] = nodeView

		if newSnap.nodesByMachineKey[n.MachineKey] == nil {
			newSnap.nodesByMachineKey[n.MachineKey] = make(map[types.UserID]types.NodeView)
		}
		newSnap.nodesByMachineKey[n.MachineKey][userID] = nodeView
	}

	return newSnap
}

// IncrementalPeersFunc computes peers for a single node against all other nodes.
// Returns the list of peers visible to the given node.
type IncrementalPeersFunc func(node types.NodeView, allNodes []types.NodeView) []types.NodeView

// incrementalSnapshot builds a new snapshot by reusing the old snapshot's peer
// data and only computing peers for newly added nodes. This is O(K × N) where
// K is the number of new nodes, compared to O(N²) for a full rebuild.
func incrementalSnapshot(
	oldSnap *Snapshot,
	nodes map[types.NodeID]types.Node,
	newNodeIDs []types.NodeID,
	incrementalPeersFunc IncrementalPeersFunc,
) Snapshot {
	timer := prometheus.NewTimer(nodeStoreSnapshotBuildDuration)
	defer timer.ObserveDuration()

	// Build allNodes list and views
	allNodes := make([]types.NodeView, 0, len(nodes))
	for _, n := range nodes {
		allNodes = append(allNodes, n.View())
	}

	// Start with a copy of the old peer map
	peersByNode := make(map[types.NodeID][]types.NodeView, len(nodes))
	for id, peers := range oldSnap.peersByNode {
		// Copy slice to avoid mutating old snapshot
		peersCopy := make([]types.NodeView, len(peers))
		copy(peersCopy, peers)
		peersByNode[id] = peersCopy
	}

	// Build a set of new node IDs for fast lookup
	newIDSet := make(map[types.NodeID]struct{}, len(newNodeIDs))
	for _, id := range newNodeIDs {
		newIDSet[id] = struct{}{}
	}

	// For each new node, compute its peer relationships by checking against all nodes.
	// This is O(K × N) instead of O(N²).
	if incrementalPeersFunc != nil {
		for _, newID := range newNodeIDs {
			n := nodes[newID]
			newNode := n.View()
			peers := incrementalPeersFunc(newNode, allNodes)
			peersByNode[newID] = peers

			// Update existing nodes' peer lists to include the new node.
			// Skip peers that are also new nodes — their peer lists will be
			// computed directly by incrementalPeersFunc and already include us.
			for _, peer := range peers {
				peerID := peer.ID()
				if peerID != newID {
					if _, isNew := newIDSet[peerID]; !isNew {
						peersByNode[peerID] = append(peersByNode[peerID], newNode)
					}
				}
			}
		}
	}

	newSnap := Snapshot{
		nodesByID:         nodes,
		allNodes:          allNodes,
		nodesByNodeKey:    make(map[key.NodePublic]types.NodeView, len(nodes)),
		nodesByMachineKey: make(map[key.MachinePublic]map[types.UserID]types.NodeView, len(nodes)),
		peersByNode:       peersByNode,
		nodesByUser:       make(map[types.UserID][]types.NodeView),
	}

	// Build secondary indexes
	for _, n := range nodes {
		nodeView := n.View()
		userID := n.TypedUserID()

		if !n.IsTagged() {
			newSnap.nodesByUser[userID] = append(newSnap.nodesByUser[userID], nodeView)
		}

		newSnap.nodesByNodeKey[n.NodeKey] = nodeView

		if newSnap.nodesByMachineKey[n.MachineKey] == nil {
			newSnap.nodesByMachineKey[n.MachineKey] = make(map[types.UserID]types.NodeView)
		}
		newSnap.nodesByMachineKey[n.MachineKey][userID] = nodeView
	}

	return newSnap
}

// refreshNodePeers corrects the peer relationships for specific nodes in a snapshot.
// It recomputes peers for the specified node IDs using the current (correct) policy
// and updates both the forward and reverse peer entries. This is O(K×N) where K is
// the number of nodes to refresh.
func refreshNodePeers(
	snap *Snapshot,
	nodes map[types.NodeID]types.Node,
	refreshIDs []types.NodeID,
	incrementalPeersFunc IncrementalPeersFunc,
) Snapshot {
	allNodes := snap.allNodes

	// Copy the peer map (only the map structure + slice headers, not contents)
	peersByNode := make(map[types.NodeID][]types.NodeView, len(snap.peersByNode))
	for id, peers := range snap.peersByNode {
		peersByNode[id] = peers // Share slice reference
	}

	// Track which entries we've cloned (COW)
	cloned := make(map[types.NodeID]bool, len(refreshIDs)*2)

	refreshSet := make(map[types.NodeID]struct{}, len(refreshIDs))
	for _, id := range refreshIDs {
		refreshSet[id] = struct{}{}
	}

	for _, nodeID := range refreshIDs {
		n, exists := nodes[nodeID]
		if !exists {
			continue
		}
		nodeView := n.View()

		// Get old peers for this node (to remove reverse entries)
		oldPeers := peersByNode[nodeID]

		// Compute correct peers using current policy
		newPeers := incrementalPeersFunc(nodeView, allNodes)
		peersByNode[nodeID] = newPeers
		cloned[nodeID] = true

		// Build sets for diff
		oldPeerSet := make(map[types.NodeID]struct{}, len(oldPeers))
		for _, p := range oldPeers {
			oldPeerSet[p.ID()] = struct{}{}
		}
		newPeerSet := make(map[types.NodeID]struct{}, len(newPeers))
		for _, p := range newPeers {
			newPeerSet[p.ID()] = struct{}{}
		}

		// Remove reverse entries for peers that were removed
		for _, p := range oldPeers {
			pid := p.ID()
			if _, stillPeer := newPeerSet[pid]; !stillPeer {
				if _, isRefresh := refreshSet[pid]; !isRefresh {
					// COW: clone before first modification
					if !cloned[pid] {
						old := peersByNode[pid]
						c := make([]types.NodeView, len(old))
						copy(c, old)
						peersByNode[pid] = c
						cloned[pid] = true
					}
					// Remove nodeID from this peer's list
					peerList := peersByNode[pid]
					filtered := peerList[:0]
					for _, pp := range peerList {
						if pp.ID() != nodeID {
							filtered = append(filtered, pp)
						}
					}
					peersByNode[pid] = filtered
				}
			}
		}

		// Add reverse entries for peers that were added
		for _, p := range newPeers {
			pid := p.ID()
			if _, wasPeer := oldPeerSet[pid]; !wasPeer {
				if _, isRefresh := refreshSet[pid]; !isRefresh {
					// COW: clone before first modification
					if !cloned[pid] {
						old := peersByNode[pid]
						c := make([]types.NodeView, len(old), len(old)+1)
						copy(c, old)
						peersByNode[pid] = c
						cloned[pid] = true
					}
					peersByNode[pid] = append(peersByNode[pid], nodeView)
				}
			}
		}
	}

	// Build new snapshot reusing everything except peersByNode
	newSnap := Snapshot{
		nodesByID:         snap.nodesByID,
		allNodes:          snap.allNodes,
		nodesByNodeKey:    snap.nodesByNodeKey,
		nodesByMachineKey: snap.nodesByMachineKey,
		peersByNode:       peersByNode,
		nodesByUser:       snap.nodesByUser,
	}

	return newSnap
}

// GetNode retrieves a node by its ID.
// The bool indicates if the node exists or is available (like "err not found").
// The NodeView might be invalid, so it must be checked with .Valid(), which must be used to ensure
// it isn't an invalid node (this is more of a node error or node is broken).
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

// GetNodeByNodeKey retrieves a node by its NodeKey.
// The bool indicates if the node exists or is available (like "err not found").
// The NodeView might be invalid, so it must be checked with .Valid(), which must be used to ensure
// it isn't an invalid node (this is more of a node error or node is broken).
func (s *NodeStore) GetNodeByNodeKey(nodeKey key.NodePublic) (types.NodeView, bool) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("get_by_key"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("get_by_key").Inc()

	nodeView, exists := s.data.Load().nodesByNodeKey[nodeKey]

	return nodeView, exists
}

// GetNodeByMachineKey returns a node by its machine key and user ID. The bool indicates if the node exists.
func (s *NodeStore) GetNodeByMachineKey(machineKey key.MachinePublic, userID types.UserID) (types.NodeView, bool) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("get_by_machine_key"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("get_by_machine_key").Inc()

	snapshot := s.data.Load()
	if userMap, exists := snapshot.nodesByMachineKey[machineKey]; exists {
		if node, exists := userMap[userID]; exists {
			return node, true
		}
	}

	return types.NodeView{}, false
}

// GetNodeByMachineKeyAnyUser returns the first node with the given machine key,
// regardless of which user it belongs to. This is useful for scenarios like
// transferring a node to a different user when re-authenticating with a
// different user's auth key.
// If multiple nodes exist with the same machine key (different users), the
// first one found is returned (order is not guaranteed).
func (s *NodeStore) GetNodeByMachineKeyAnyUser(machineKey key.MachinePublic) (types.NodeView, bool) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("get_by_machine_key_any_user"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("get_by_machine_key_any_user").Inc()

	snapshot := s.data.Load()
	if userMap, exists := snapshot.nodesByMachineKey[machineKey]; exists {
		// Return the first node found (order not guaranteed due to map iteration)
		for _, node := range userMap {
			return node, true
		}
	}

	return types.NodeView{}, false
}

// DebugString returns debug information about the NodeStore.
func (s *NodeStore) DebugString() string {
	snapshot := s.data.Load()

	var sb strings.Builder

	sb.WriteString("=== NodeStore Debug Information ===\n\n")

	// Basic counts
	sb.WriteString(fmt.Sprintf("Total Nodes: %d\n", len(snapshot.nodesByID)))
	sb.WriteString(fmt.Sprintf("Users with Nodes: %d\n", len(snapshot.nodesByUser)))
	sb.WriteString("\n")

	// User distribution (shows internal UserID tracking, not display owner)
	sb.WriteString("Nodes by Internal User ID:\n")

	for userID, nodes := range snapshot.nodesByUser {
		if len(nodes) > 0 {
			userName := "unknown"

			if nodes[0].Valid() && nodes[0].User().Valid() {
				userName = nodes[0].User().Name()
			}

			sb.WriteString(fmt.Sprintf("  - User %d (%s): %d nodes\n", userID, userName, len(nodes)))
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
			sb.WriteString(fmt.Sprintf("  - Node %d (%s): %d peers\n",
				nodeID, node.Hostname, peerCount))
		}
	}

	if len(snapshot.peersByNode) > 0 {
		avgPeers := float64(totalPeers) / float64(len(snapshot.peersByNode))
		sb.WriteString(fmt.Sprintf("  - Average peers per node: %.1f\n", avgPeers))
	}

	sb.WriteString("\n")

	// Node key index
	sb.WriteString(fmt.Sprintf("NodeKey Index: %d entries\n", len(snapshot.nodesByNodeKey)))
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

// RebuildPeerMaps rebuilds the peer relationship map using the current peersFunc.
// This must be called after policy changes because peersFunc uses PolicyManager's
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

// RefreshPeersForNodes recomputes peer relationships for specific nodes only.
// This is used after policy updates to correct stale peer data that was computed
// before the policy was updated with the new node's IPs.
// This is a blocking operation that waits for the write to complete.
func (s *NodeStore) RefreshPeersForNodes(nodeIDs []types.NodeID) {
	if len(nodeIDs) == 0 {
		return
	}

	done := make(chan struct{})
	s.writeQueue <- work{
		op:             refreshPeers,
		refreshNodeIDs: nodeIDs,
		rebuildResult:  done,
	}
	<-done
}
