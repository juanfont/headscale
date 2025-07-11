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
// blocked.
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
		peersFunc:  peersFunc,
		writeQueue: make(chan work, batchSize),
	}
	store.data.Store(&snap)

	return store
}

type Snapshot struct {
	// nodesByID is the main source of truth for nodes.
	nodesByID map[types.NodeID]types.Node

	// calculated from nodesByID
	nodesByNodeKey map[key.NodePublic]types.NodeView
	peersByNode    map[types.NodeID][]types.NodeView
	nodesByUser    map[types.UserID][]types.NodeView
	allNodes       []types.NodeView
}

type PeersFunc func(nodes []types.NodeView) map[types.NodeID][]types.NodeView

type work struct {
	op        int
	nodeID    types.NodeID
	node      types.Node
	updateFn  UpdateNodeFunc
	result    chan struct{}
	immediate bool // For operations that need immediate processing
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

// UpdateNodeImmediate applies a function to modify a specific node in the store
// with immediate processing (bypassing normal batching delays).
// Use this for time-sensitive updates like online status changes.
func (s *NodeStore) UpdateNodeImmediate(nodeID types.NodeID, updateFn func(n *types.Node)) {
	work := work{
		op:        update,
		nodeID:    nodeID,
		updateFn:  updateFn,
		result:    make(chan struct{}),
		immediate: true,
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

func (s *NodeStore) Start() {
	go s.processWrite()
}

func (s *NodeStore) Stop() {
	close(s.writeQueue)
}

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

			// Handle immediate operations right away
			if w.immediate {
				s.applyBatch([]work{w})
				continue
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

func snapshotFromNodes(nodes map[types.NodeID]types.Node, peersFunc PeersFunc) Snapshot {
	allNodes := make([]types.NodeView, 0, len(nodes))
	for _, n := range nodes {
		allNodes = append(allNodes, n.View())
	}

	newSnap := Snapshot{
		nodesByID:      nodes,
		allNodes:       allNodes,
		nodesByNodeKey: make(map[key.NodePublic]types.NodeView),
		peersByNode:    peersFunc(allNodes),
		nodesByUser:    make(map[types.UserID][]types.NodeView),
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
func (s *NodeStore) GetNode(id types.NodeID) types.NodeView {
	n, exists := s.data.Load().nodesByID[id]
	if !exists {
		return types.NodeView{}
	}
	return n.View()
}

// GetNodeByNodeKey retrieves a node by its NodeKey.
func (s *NodeStore) GetNodeByNodeKey(nodeKey key.NodePublic) types.NodeView {
	return s.data.Load().nodesByNodeKey[nodeKey]
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
