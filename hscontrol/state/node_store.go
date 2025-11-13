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
	batchSize    = 100
	batchTimeout = 500 * time.Millisecond
)

const (
	put             = 1
	del             = 2
	update          = 3
	rebuildPeerMaps = 4
	putWGPeer       = 5
	delWGPeer       = 6
	putConnection   = 7
	delConnection   = 8
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
		Name:      "nodestore_nodes_total",
		Help:      "Total number of nodes in the NodeStore",
	})
	nodeStoreWGPeersCount = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: prometheusNamespace,
		Name:      "nodestore_wgpeers_total",
		Help:      "Total number of WireGuard-only peers in the NodeStore",
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
}

func NewNodeStore(allNodes types.Nodes, allWGPeers types.WireGuardOnlyPeers, allConnections types.WireGuardConnections, peersFunc PeersFunc) *NodeStore {
	nodes := make(map[types.NodeID]types.Node, len(allNodes))
	for _, n := range allNodes {
		nodes[n.ID] = *n
	}

	wgPeers := make(map[types.NodeID]types.WireGuardOnlyPeer, len(allWGPeers))
	for _, p := range allWGPeers {
		wgPeers[types.NodeID(p.ID)] = *p
	}

	connections := make(map[types.NodeID]map[types.NodeID]types.WireGuardConnection)
	for _, conn := range allConnections {
		if connections[conn.NodeID] == nil {
			connections[conn.NodeID] = make(map[types.NodeID]types.WireGuardConnection)
		}
		connections[conn.NodeID][conn.WGPeerID] = *conn
	}

	snap := snapshotFromNodesWGPeersAndConnections(nodes, wgPeers, connections, peersFunc)

	store := &NodeStore{
		peersFunc: peersFunc,
	}
	store.data.Store(&snap)

	// Initialize metrics
	nodeStoreNodesCount.Set(float64(len(nodes)))
	nodeStoreWGPeersCount.Set(float64(len(wgPeers)))

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

	// for WireGuard-only peers
	wgPeersByID map[types.NodeID]types.WireGuardOnlyPeer
	allWGPeers  []*types.WireGuardOnlyPeer
	// for WireGuard connections (node-to-peer relationships with per-connection masq addresses)
	connectionsByNode map[types.NodeID]map[types.NodeID]types.WireGuardConnection
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
	// For rebuildPeerMaps operation
	rebuildResult chan struct{}

	// TODO(iridated): Ideally work would be an enum so we don't need to allocate
	// space for both node and wgPeer. At most one of them is used at a time.
	// for putWGPeer operations
	wgPeer types.WireGuardOnlyPeer

	// for connection operations
	connection types.WireGuardConnection
	wgPeerID   types.NodeID // used with nodeID for connection operations
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
	s.writeQueue = make(chan work)
	go s.processWrite()
}

// Stop stops the NodeStore.
func (s *NodeStore) Stop() {
	close(s.writeQueue)
}

// processWrite processes the write queue in batches.
func (s *NodeStore) processWrite() {
	c := time.NewTicker(batchTimeout)
	defer c.Stop()
	batch := make([]work, 0, batchSize)

	for {
		select {
		case w, ok := <-s.writeQueue:
			if !ok {
				// Channel closed, apply any remaining batch and exit
				if len(batch) != 0 {
					s.applyBatch(batch)
				}
				return
			}
			batch = append(batch, w)
			if len(batch) >= batchSize {
				s.applyBatch(batch)
				batch = batch[:0]
				c.Reset(batchTimeout)
			}
		case <-c.C:
			if len(batch) != 0 {
				s.applyBatch(batch)
				batch = batch[:0]
			}
			c.Reset(batchTimeout)
		}
	}
}

// applyBatch applies a batch of work to the node store.
// This means that it takes a copy of the current nodes, wg-only peers, and connections,
// then applies the batch of operations to those copies,
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

	prevSnapshot := s.data.Load()

	nodes := make(map[types.NodeID]types.Node)
	maps.Copy(nodes, prevSnapshot.nodesByID)

	wgPeers := make(map[types.NodeID]types.WireGuardOnlyPeer)
	maps.Copy(wgPeers, prevSnapshot.wgPeersByID)

	connections := make(map[types.NodeID]map[types.NodeID]types.WireGuardConnection)
	for nodeID, peerConns := range prevSnapshot.connectionsByNode {
		connections[nodeID] = make(map[types.NodeID]types.WireGuardConnection)
		maps.Copy(connections[nodeID], peerConns)
	}

	// Track which work items need node results
	nodeResultRequests := make(map[types.NodeID][]*work)

	// Track rebuildPeerMaps operations
	var rebuildOps []*work

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
				w.updateFn(&n)
				nodes[w.nodeID] = n
			}
			if w.nodeResult != nil {
				nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)
			}
		case del:
			delete(nodes, w.nodeID)
			// For delete operations, send an invalid NodeView if requested
			if w.nodeResult != nil {
				nodeResultRequests[w.nodeID] = append(nodeResultRequests[w.nodeID], w)
			}
		case rebuildPeerMaps:
			// rebuildPeerMaps doesn't modify nodes, it just forces the snapshot rebuild
			// below to recalculate peer relationships using the current peersFunc
			rebuildOps = append(rebuildOps, w)
		case putWGPeer:
			wgPeers[w.nodeID] = w.wgPeer
		case delWGPeer:
			delete(wgPeers, w.nodeID)
		case putConnection:
			if connections[w.nodeID] == nil {
				connections[w.nodeID] = make(map[types.NodeID]types.WireGuardConnection)
			}
			connections[w.nodeID][w.wgPeerID] = w.connection
		case delConnection:
			delete(connections[w.nodeID], w.wgPeerID)
			if len(connections[w.nodeID]) == 0 {
				delete(connections, w.nodeID)
			}
		}
	}

	newSnap := snapshotFromNodesWGPeersAndConnections(nodes, wgPeers, connections, s.peersFunc)
	s.data.Store(&newSnap)

	// Update metrics
	nodeStoreNodesCount.Set(float64(len(nodes)))
	nodeStoreWGPeersCount.Set(float64(len(wgPeers)))

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

// snapshotFromNodesWGPeersAndConnections creates a new Snapshot from the provided nodes, wg-only peers, and connections.
// It builds a lot of "indexes" to make lookups fast for datasets we
// that is used frequently, like nodesByNodeKey, peersByNode, nodesByUser, and connectionsByNode.
// This is not a fast operation, it is the "slow" part of our copy-on-write
// structure, but it allows us to have fast reads and efficient lookups.
func snapshotFromNodesWGPeersAndConnections(
	nodes map[types.NodeID]types.Node,
	wgPeers map[types.NodeID]types.WireGuardOnlyPeer,
	connections map[types.NodeID]map[types.NodeID]types.WireGuardConnection,
	peersFunc PeersFunc,
) Snapshot {
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

		wgPeersByID: wgPeers,
		allWGPeers:  make([]*types.WireGuardOnlyPeer, 0, len(wgPeers)),

		connectionsByNode: connections,
	}

	// Build nodesByUser, nodesByNodeKey, and nodesByMachineKey maps
	for _, n := range nodes {
		nodeView := n.View()
		userID := types.UserID(n.UserID)

		newSnap.nodesByUser[userID] = append(newSnap.nodesByUser[userID], nodeView)
		newSnap.nodesByNodeKey[n.NodeKey] = nodeView

		// Build machine key index
		if newSnap.nodesByMachineKey[n.MachineKey] == nil {
			newSnap.nodesByMachineKey[n.MachineKey] = make(map[types.UserID]types.NodeView)
		}
		newSnap.nodesByMachineKey[n.MachineKey][userID] = nodeView
	}

	// Build wg-only peer indexes
	for _, peer := range wgPeers {
		newSnap.allWGPeers = append(newSnap.allWGPeers, &peer)
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

	// User distribution
	sb.WriteString("Nodes by User:\n")
	for userID, nodes := range snapshot.nodesByUser {
		if len(nodes) > 0 {
			userName := "unknown"
			if len(nodes) > 0 && nodes[0].Valid() {
				userName = nodes[0].User().Name
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

	// WireGuard-Only Peers Summary
	sb.WriteString("WireGuard-Only Peers:\n")
	sb.WriteString(fmt.Sprintf("  Total WG Peers: %d\n", len(snapshot.wgPeersByID)))
	sb.WriteString("\n")

	// WG Peer Details
	if len(snapshot.allWGPeers) > 0 {
		sb.WriteString("WG Peer Details:\n")
		for _, peer := range snapshot.allWGPeers {
			sb.WriteString(fmt.Sprintf("  - ID: %d, Name: \"%s\", User: %d, Endpoints: %d\n",
				peer.ID, peer.Name, peer.UserID, len(peer.Endpoints)))
		}
		sb.WriteString("\n")
	}

	// WG Peer Connections (node-to-peer connections with masquerade details)
	if len(snapshot.connectionsByNode) > 0 {
		sb.WriteString("WG Peer Connections:\n")
		for nodeID, peerConnections := range snapshot.connectionsByNode {
			nodeName := fmt.Sprintf("Node %d", nodeID)
			if node, exists := snapshot.nodesByID[nodeID]; exists {
				nodeName = fmt.Sprintf("Node %d (%s)", nodeID, node.Hostname)
			}
			sb.WriteString(fmt.Sprintf("  %s -> %d WG peer(s):\n",
				nodeName, len(peerConnections)))

			for wgPeerID, conn := range peerConnections {
				peerName := fmt.Sprintf("WG Peer %d", wgPeerID)
				if peer, exists := snapshot.wgPeersByID[wgPeerID]; exists {
					peerName = fmt.Sprintf("WG Peer %d (%s)", wgPeerID, peer.Name)
				}

				masqAddrs := []string{}
				if conn.IPv4MasqAddr != nil {
					masqAddrs = append(masqAddrs, fmt.Sprintf("IPv4: %s", conn.IPv4MasqAddr.String()))
				}
				if conn.IPv6MasqAddr != nil {
					masqAddrs = append(masqAddrs, fmt.Sprintf("IPv6: %s", conn.IPv6MasqAddr.String()))
				}

				masqStr := "no masquerade"
				if len(masqAddrs) > 0 {
					masqStr = strings.Join(masqAddrs, ", ")
				}

				sb.WriteString(fmt.Sprintf("    - %s [%s]\n", peerName, masqStr))
			}
		}
		sb.WriteString("\n")
	}

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

// PutWGPeer adds or updates a WireGuard-only peer in the store.
// If the peer already exists, it will be replaced.
// If the peer does not exist, it will be added.
// This is a blocking operation that waits for the write to complete.
func (s *NodeStore) PutWGPeer(peer *types.WireGuardOnlyPeer) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("put_wgpeer"))
	defer timer.ObserveDuration()

	work := work{
		op:     putWGPeer,
		nodeID: types.NodeID(peer.ID),
		wgPeer: *peer,
		result: make(chan struct{}),
	}

	nodeStoreQueueDepth.Inc()
	s.writeQueue <- work
	<-work.result
	nodeStoreQueueDepth.Dec()

	nodeStoreOperations.WithLabelValues("put_wgpeer").Inc()
}

// GetWGPeer retrieves a WireGuard-only peer by its ID.
// The bool indicates if the peer exists.
func (s *NodeStore) GetWGPeer(id types.NodeID) (types.WireGuardOnlyPeer, bool) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("get_wgpeer"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("get_wgpeer").Inc()

	peer, exists := s.data.Load().wgPeersByID[id]
	return peer, exists
}

// DeleteWGPeer removes a WireGuard-only peer from the store by its ID.
// This is a blocking operation that waits for the write to complete.
func (s *NodeStore) DeleteWGPeer(id types.NodeID) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("delete_wgpeer"))
	defer timer.ObserveDuration()

	work := work{
		op:     delWGPeer,
		nodeID: id,
		result: make(chan struct{}),
	}

	nodeStoreQueueDepth.Inc()
	s.writeQueue <- work
	<-work.result
	nodeStoreQueueDepth.Dec()

	nodeStoreOperations.WithLabelValues("delete_wgpeer").Inc()
}

// ListWGPeersForNode returns WireGuard-only peers visible to a specific node.
// This uses the KnownNodeIDs field to determine visibility.
// This is called for every MapRequest (HOT PATH).
func (s *NodeStore) ListWGPeersForNode(nodeID types.NodeID) []*types.WireGuardOnlyPeer {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("list_wgpeers_for_node"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("list_wgpeers_for_node").Inc()

	snapshot := s.data.Load()
	wgPeersMap := snapshot.connectionsByNode[nodeID]
	wgPeers := make([]*types.WireGuardOnlyPeer, 0, len(wgPeersMap))
	for _, connection := range wgPeersMap {
		peer := snapshot.wgPeersByID[connection.WGPeerID]
		wgPeers = append(wgPeers, &peer)
	}
	return wgPeers
}

// ListWGPeers returns all WireGuard-only peers, optionally filtered by user ID.
// If userID is nil, returns all peers.
// If userID is not nil, filters by the specified user.
func (s *NodeStore) ListWGPeers(userID *uint) []*types.WireGuardOnlyPeer {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("list_wgpeers"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("list_wgpeers").Inc()

	allPeers := s.data.Load().allWGPeers

	// If no filter, return all
	if userID == nil {
		return allPeers
	}

	// Filter by userID (not hot path, so iteration is acceptable)
	var filtered []*types.WireGuardOnlyPeer
	for _, peer := range allPeers {
		if peer.UserID == types.UserID(*userID) {
			filtered = append(filtered, peer)
		}
	}
	return filtered
}

// PutConnection adds or updates a WireGuard connection in the store.
// This establishes a connection between a regular node and a WireGuard-only peer
// with per-connection masquerade addresses.
// This is a blocking operation that waits for the write to complete.
func (s *NodeStore) PutConnection(conn *types.WireGuardConnection) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("put_connection"))
	defer timer.ObserveDuration()

	work := work{
		op:         putConnection,
		nodeID:     conn.NodeID,
		wgPeerID:   conn.WGPeerID,
		connection: *conn,
		result:     make(chan struct{}),
	}

	nodeStoreQueueDepth.Inc()
	s.writeQueue <- work
	<-work.result
	nodeStoreQueueDepth.Dec()

	nodeStoreOperations.WithLabelValues("put_connection").Inc()
}

// DeleteConnection removes a WireGuard connection from the store.
// This is a blocking operation that waits for the write to complete.
func (s *NodeStore) DeleteConnection(nodeID, wgPeerID types.NodeID) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("delete_connection"))
	defer timer.ObserveDuration()

	work := work{
		op:       delConnection,
		nodeID:   nodeID,
		wgPeerID: wgPeerID,
		result:   make(chan struct{}),
	}

	nodeStoreQueueDepth.Inc()
	s.writeQueue <- work
	<-work.result
	nodeStoreQueueDepth.Dec()

	nodeStoreOperations.WithLabelValues("delete_connection").Inc()
}

// ListAllWireGuardConnections returns all connections in the store.
// This is for admin/debugging purposes, not for hot paths.
func (s *NodeStore) ListAllWireGuardConnections() []*types.WireGuardConnection {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("list_all_connections"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("list_all_connections").Inc()

	var result []*types.WireGuardConnection
	for _, peerConns := range s.data.Load().connectionsByNode {
		for _, conn := range peerConns {
			result = append(result, &conn)
		}
	}

	return result
}

// GetWireGuardConnectionWithPeer retrieves both a connection and its associated peer atomically.
// This method fetches from a single snapshot, eliminating TOCTOU race conditions where the
// connection and peer could be from different snapshots if fetched separately.
// This is called in hot paths (HOT PATH) for MapResponse generation.
func (s *NodeStore) GetWireGuardConnectionWithPeer(nodeID, wgPeerID types.NodeID) (*types.WireGuardConnectionWithPeer, bool) {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("get_connection_with_peer"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("get_connection_with_peer").Inc()

	snapshot := s.data.Load()

	connections := snapshot.connectionsByNode[nodeID]
	if connections == nil {
		return nil, false
	}

	conn, exists := connections[wgPeerID]
	if !exists {
		return nil, false
	}

	// peer must exist if connection has been added to node store
	peer := snapshot.wgPeersByID[wgPeerID]

	return &types.WireGuardConnectionWithPeer{
		Connection: &conn,
		Peer:       &peer,
	}, true
}

// GetWireGuardConnectionsWithPeersForNode returns all connections with their peers for a node.
// This method fetches from a single snapshot for atomic consistency, preventing TOCTOU races.
// This is called for every MapRequest (HOT PATH).
func (s *NodeStore) GetWireGuardConnectionsWithPeersForNode(nodeID types.NodeID) []*types.WireGuardConnectionWithPeer {
	timer := prometheus.NewTimer(nodeStoreOperationDuration.WithLabelValues("get_connections_with_peers_for_node"))
	defer timer.ObserveDuration()

	nodeStoreOperations.WithLabelValues("get_connections_with_peers_for_node").Inc()

	snapshot := s.data.Load()

	connections := snapshot.connectionsByNode[nodeID]
	if connections == nil {
		return nil
	}

	result := make([]*types.WireGuardConnectionWithPeer, 0, len(connections))
	for _, conn := range connections {
		peer := snapshot.wgPeersByID[conn.WGPeerID]
		result = append(result, &types.WireGuardConnectionWithPeer{
			Connection: &conn,
			Peer:       &peer,
		})
	}

	return result
}
