package state

import (
	"maps"
	"sync/atomic"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

const (
	batchSize    = 10
	batchTimeout = 500 * time.Millisecond
)

const (
	put    = 1
	del    = 2
	update = 3
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
	// TODO: metrics
}

func NewNodeStore(allNodes types.Nodes, peersFunc PeersFunc) *NodeStore {
	nodes := make(map[types.NodeID]types.Node, len(allNodes))
	for _, n := range allNodes {
		nodes[n.ID] = *n
	}
	snap := snapshotFromNodes(nodes, peersFunc)

	store := &NodeStore{
		peersFunc: peersFunc,
	}
	store.data.Store(&snap)

	return store
}

// Snapshot is the represenation of the current state of the NodeStore.
// It contains all nodes and their relationships.
// It is a copy-on-write structure, meaning that when a write occurs,
// a new Snapshot is created with the updated state,
// and replaces the old one atomically.
type Snapshot struct {
	// nodesByID is the main source of truth for nodes.
	nodesByID map[types.NodeID]types.Node

	// calculated from nodesByID
	nodesByNodeKey map[key.NodePublic]types.NodeView
	peersByNode    map[types.NodeID][]types.NodeView
	nodesByUser    map[types.UserID][]types.NodeView
	allNodes       []types.NodeView
}

// PeersFunc is a function that takes a list of nodes and returns a map
// with the relationships between nodes and their peers.
// This will typically be used to calculate which nodes can see each other
// based on the current policy.
type PeersFunc func(nodes []types.NodeView) map[types.NodeID][]types.NodeView

// work represents a single operation to be performed on the NodeStore.
type work struct {
	op       int
	nodeID   types.NodeID
	node     types.Node
	updateFn UpdateNodeFunc
	result   chan struct{}
}

// PutNode adds or updates a node in the store.
// If the node already exists, it will be replaced.
// If the node does not exist, it will be added.
// This is a blocking operation that waits for the write to complete.
func (s *NodeStore) PutNode(n types.Node) {
	work := work{
		op:     put,
		nodeID: n.ID,
		node:   n,
		result: make(chan struct{}),
	}

	s.writeQueue <- work
	<-work.result
}

// UpdateNodeFunc is a function type that takes a pointer to a Node and modifies it.
type UpdateNodeFunc func(n *types.Node)

// UpdateNode applies a function to modify a specific node in the store.
// This is a blocking operation that waits for the write to complete.
// This is analogous to a database "transaction", or, the caller should
// rather collect all data they want to change, and then call this function.
// Fewer calls are better.
//
// TODO(kradalby): Technically we could have a version of this that modifies the node
// in the current snapshot if _we know_ that the change will not affect the peer relationships.
// This is because the main nodesByID map contains the struct, and every other map is using a
// pointer to the underlying struct. The gotcha with this is that we will need to introduce
// a lock around the nodesByID map to ensure that no other writes are happening
// while we are modifying the node. Which mean we would need to implement read-write locks
// on all read operations.
func (s *NodeStore) UpdateNode(nodeID types.NodeID, updateFn func(n *types.Node)) {
	work := work{
		op:       update,
		nodeID:   nodeID,
		updateFn: updateFn,
		result:   make(chan struct{}),
	}

	s.writeQueue <- work
	<-work.result
}

// DeleteNode removes a node from the store by its ID.
// This is a blocking operation that waits for the write to complete.
func (s *NodeStore) DeleteNode(id types.NodeID) {
	work := work{
		op:     del,
		nodeID: id,
		result: make(chan struct{}),
	}

	s.writeQueue <- work
	<-work.result
}

// Start initializes the NodeStore and starts processing the write queue.
func (s *NodeStore) Start() {
	s.writeQueue = make(chan work)
	go s.processWrite()
}

// Stop stops the NodeStore and closes the write queue.
func (s *NodeStore) Stop() {
	close(s.writeQueue)
}

// processWrite processes the write queue in batches.
// It collects writes into batches and applies them periodically.
func (s *NodeStore) processWrite() {
	c := time.NewTicker(batchTimeout)
	batch := make([]work, 0, batchSize)

	for {
		select {
		case w, ok := <-s.writeQueue:
			if !ok {
				c.Stop()
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
	nodes := make(map[types.NodeID]types.Node)
	maps.Copy(nodes, s.data.Load().nodesByID)

	for _, w := range batch {
		switch w.op {
		case put:
			nodes[w.nodeID] = w.node
		case update:
			// Update the specific node identified by nodeID
			if n, exists := nodes[w.nodeID]; exists {
				w.updateFn(&n)
				nodes[w.nodeID] = n
			}
		case del:
			delete(nodes, w.nodeID)
		}
	}

	newSnap := snapshotFromNodes(nodes, s.peersFunc)
	s.data.Store(&newSnap)

	for _, w := range batch {
		close(w.result)
	}
}

// snapshotFromNodes creates a new Snapshot from the provided nodes.
// It builds a lot of "indexes" to make lookups fast for datasets we
// that is used frequently, like nodesByNodeKey, peersByNode, and nodesByUser.
// This is not a fast operation, it is the "slow" part of our copy-on-write
// structure, but it allows us to have fast reads and efficient lookups.
func snapshotFromNodes(nodes map[types.NodeID]types.Node, peersFunc PeersFunc) Snapshot {
	// TODO(kradalby): Add prometheus histograms for this operation.
	allNodes := make([]types.NodeView, 0, len(nodes))
	for _, n := range nodes {
		allNodes = append(allNodes, n.View())
	}

	newSnap := Snapshot{
		nodesByID:      nodes,
		allNodes:       allNodes,
		nodesByNodeKey: make(map[key.NodePublic]types.NodeView),

		// peersByNode is most likely the most expensive operation,
		// it will use the list of all nodes, combined with the
		// current policy to precalculate which nodes are peers and
		// can see each other.
		peersByNode: peersFunc(allNodes),
		nodesByUser: make(map[types.UserID][]types.NodeView),
	}

	// Build nodesByUser and nodesByNodeKey maps
	for _, n := range nodes {
		nodeView := n.View()
		newSnap.nodesByUser[types.UserID(n.UserID)] = append(newSnap.nodesByUser[types.UserID(n.UserID)], nodeView)
		newSnap.nodesByNodeKey[n.NodeKey] = nodeView
	}

	return newSnap
}

// GetNode retrieves a node by its ID.
// The bool indicates if the node exists or is available (like "err not found").
// The NodeView might be invalid, so it must be checked with .Valid(), which must be used to ensure
// it isn't an invalid node (this is more of a node error or node is broken).
func (s *NodeStore) GetNode(id types.NodeID) (types.NodeView, bool) {
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
	nodeView, exists := s.data.Load().nodesByNodeKey[nodeKey]
	return nodeView, exists
}

// ListNodes returns a slice of all nodes in the store.
func (s *NodeStore) ListNodes() views.Slice[types.NodeView] {
	return views.SliceOf(s.data.Load().allNodes)
}

// ListPeers returns a slice of all peers for a given node ID.
func (s *NodeStore) ListPeers(id types.NodeID) views.Slice[types.NodeView] {
	return views.SliceOf(s.data.Load().peersByNode[id])
}

// ListNodesByUser returns a slice of all nodes for a given user ID.
func (s *NodeStore) ListNodesByUser(uid types.UserID) views.Slice[types.NodeView] {
	return views.SliceOf(s.data.Load().nodesByUser[uid])
}
