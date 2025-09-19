package state

import (
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/key"
)

func TestSnapshotFromNodes(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func() (map[types.NodeID]types.Node, PeersFunc)
		validate  func(t *testing.T, nodes map[types.NodeID]types.Node, snapshot Snapshot)
	}{
		{
			name: "empty nodes",
			setupFunc: func() (map[types.NodeID]types.Node, PeersFunc) {
				nodes := make(map[types.NodeID]types.Node)
				peersFunc := func(nodes []types.NodeView) map[types.NodeID][]types.NodeView {
					return make(map[types.NodeID][]types.NodeView)
				}

				return nodes, peersFunc
			},
			validate: func(t *testing.T, nodes map[types.NodeID]types.Node, snapshot Snapshot) {
				assert.Empty(t, snapshot.nodesByID)
				assert.Empty(t, snapshot.allNodes)
				assert.Empty(t, snapshot.peersByNode)
				assert.Empty(t, snapshot.nodesByUser)
			},
		},
		{
			name: "single node",
			setupFunc: func() (map[types.NodeID]types.Node, PeersFunc) {
				nodes := map[types.NodeID]types.Node{
					1: createTestNode(1, 1, "user1", "node1"),
				}
				return nodes, allowAllPeersFunc
			},
			validate: func(t *testing.T, nodes map[types.NodeID]types.Node, snapshot Snapshot) {
				assert.Len(t, snapshot.nodesByID, 1)
				assert.Len(t, snapshot.allNodes, 1)
				assert.Len(t, snapshot.peersByNode, 1)
				assert.Len(t, snapshot.nodesByUser, 1)

				require.Contains(t, snapshot.nodesByID, types.NodeID(1))
				assert.Equal(t, nodes[1].ID, snapshot.nodesByID[1].ID)
				assert.Empty(t, snapshot.peersByNode[1]) // no other nodes, so no peers
				assert.Len(t, snapshot.nodesByUser[1], 1)
				assert.Equal(t, types.NodeID(1), snapshot.nodesByUser[1][0].ID())
			},
		},
		{
			name: "multiple nodes same user",
			setupFunc: func() (map[types.NodeID]types.Node, PeersFunc) {
				nodes := map[types.NodeID]types.Node{
					1: createTestNode(1, 1, "user1", "node1"),
					2: createTestNode(2, 1, "user1", "node2"),
				}

				return nodes, allowAllPeersFunc
			},
			validate: func(t *testing.T, nodes map[types.NodeID]types.Node, snapshot Snapshot) {
				assert.Len(t, snapshot.nodesByID, 2)
				assert.Len(t, snapshot.allNodes, 2)
				assert.Len(t, snapshot.peersByNode, 2)
				assert.Len(t, snapshot.nodesByUser, 1)

				// Each node sees the other as peer (but not itself)
				assert.Len(t, snapshot.peersByNode[1], 1)
				assert.Equal(t, types.NodeID(2), snapshot.peersByNode[1][0].ID())
				assert.Len(t, snapshot.peersByNode[2], 1)
				assert.Equal(t, types.NodeID(1), snapshot.peersByNode[2][0].ID())
				assert.Len(t, snapshot.nodesByUser[1], 2)
			},
		},
		{
			name: "multiple nodes different users",
			setupFunc: func() (map[types.NodeID]types.Node, PeersFunc) {
				nodes := map[types.NodeID]types.Node{
					1: createTestNode(1, 1, "user1", "node1"),
					2: createTestNode(2, 2, "user2", "node2"),
					3: createTestNode(3, 1, "user1", "node3"),
				}

				return nodes, allowAllPeersFunc
			},
			validate: func(t *testing.T, nodes map[types.NodeID]types.Node, snapshot Snapshot) {
				assert.Len(t, snapshot.nodesByID, 3)
				assert.Len(t, snapshot.allNodes, 3)
				assert.Len(t, snapshot.peersByNode, 3)
				assert.Len(t, snapshot.nodesByUser, 2)

				// Each node should have 2 peers (all others, but not itself)
				assert.Len(t, snapshot.peersByNode[1], 2)
				assert.Len(t, snapshot.peersByNode[2], 2)
				assert.Len(t, snapshot.peersByNode[3], 2)

				// User groupings
				assert.Len(t, snapshot.nodesByUser[1], 2) // user1 has nodes 1,3
				assert.Len(t, snapshot.nodesByUser[2], 1) // user2 has node 2
			},
		},
		{
			name: "odd-even peers filtering",
			setupFunc: func() (map[types.NodeID]types.Node, PeersFunc) {
				nodes := map[types.NodeID]types.Node{
					1: createTestNode(1, 1, "user1", "node1"),
					2: createTestNode(2, 2, "user2", "node2"),
					3: createTestNode(3, 3, "user3", "node3"),
					4: createTestNode(4, 4, "user4", "node4"),
				}
				peersFunc := oddEvenPeersFunc

				return nodes, peersFunc
			},
			validate: func(t *testing.T, nodes map[types.NodeID]types.Node, snapshot Snapshot) {
				assert.Len(t, snapshot.nodesByID, 4)
				assert.Len(t, snapshot.allNodes, 4)
				assert.Len(t, snapshot.peersByNode, 4)
				assert.Len(t, snapshot.nodesByUser, 4)

				// Odd nodes should only see other odd nodes as peers
				require.Len(t, snapshot.peersByNode[1], 1)
				assert.Equal(t, types.NodeID(3), snapshot.peersByNode[1][0].ID())

				require.Len(t, snapshot.peersByNode[3], 1)
				assert.Equal(t, types.NodeID(1), snapshot.peersByNode[3][0].ID())

				// Even nodes should only see other even nodes as peers
				require.Len(t, snapshot.peersByNode[2], 1)
				assert.Equal(t, types.NodeID(4), snapshot.peersByNode[2][0].ID())

				require.Len(t, snapshot.peersByNode[4], 1)
				assert.Equal(t, types.NodeID(2), snapshot.peersByNode[4][0].ID())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodes, peersFunc := tt.setupFunc()
			snapshot := snapshotFromNodes(nodes, peersFunc)
			tt.validate(t, nodes, snapshot)
		})
	}
}

// Helper functions

func createTestNode(nodeID types.NodeID, userID uint, username, hostname string) types.Node {
	now := time.Now()
	machineKey := key.NewMachine()
	nodeKey := key.NewNode()
	discoKey := key.NewDisco()

	ipv4 := netip.MustParseAddr("100.64.0.1")
	ipv6 := netip.MustParseAddr("fd7a:115c:a1e0::1")

	return types.Node{
		ID:         nodeID,
		MachineKey: machineKey.Public(),
		NodeKey:    nodeKey.Public(),
		DiscoKey:   discoKey.Public(),
		Hostname:   hostname,
		GivenName:  hostname,
		UserID:     userID,
		User: types.User{
			Name:        username,
			DisplayName: username,
		},
		RegisterMethod: "test",
		IPv4:           &ipv4,
		IPv6:           &ipv6,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

// Peer functions

func allowAllPeersFunc(nodes []types.NodeView) map[types.NodeID][]types.NodeView {
	ret := make(map[types.NodeID][]types.NodeView, len(nodes))
	for _, node := range nodes {
		var peers []types.NodeView
		for _, n := range nodes {
			if n.ID() != node.ID() {
				peers = append(peers, n)
			}
		}
		ret[node.ID()] = peers
	}

	return ret
}

func oddEvenPeersFunc(nodes []types.NodeView) map[types.NodeID][]types.NodeView {
	ret := make(map[types.NodeID][]types.NodeView, len(nodes))
	for _, node := range nodes {
		var peers []types.NodeView
		nodeIsOdd := node.ID()%2 == 1

		for _, n := range nodes {
			if n.ID() == node.ID() {
				continue
			}

			peerIsOdd := n.ID()%2 == 1

			// Only add peer if both are odd or both are even
			if nodeIsOdd == peerIsOdd {
				peers = append(peers, n)
			}
		}
		ret[node.ID()] = peers
	}

	return ret
}

func TestNodeStoreOperations(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(t *testing.T) *NodeStore
		steps     []testStep
	}{
		{
			name: "create empty store and add single node",
			setupFunc: func(t *testing.T) *NodeStore {
				return NewNodeStore(nil, allowAllPeersFunc)
			},
			steps: []testStep{
				{
					name: "verify empty store",
					action: func(store *NodeStore) {
						snapshot := store.data.Load()
						assert.Empty(t, snapshot.nodesByID)
						assert.Empty(t, snapshot.allNodes)
						assert.Empty(t, snapshot.peersByNode)
						assert.Empty(t, snapshot.nodesByUser)
					},
				},
				{
					name: "add first node",
					action: func(store *NodeStore) {
						node := createTestNode(1, 1, "user1", "node1")
						resultNode := store.PutNode(node)
						assert.True(t, resultNode.Valid(), "PutNode should return valid node")
						assert.Equal(t, node.ID, resultNode.ID())

						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 1)
						assert.Len(t, snapshot.allNodes, 1)
						assert.Len(t, snapshot.peersByNode, 1)
						assert.Len(t, snapshot.nodesByUser, 1)

						require.Contains(t, snapshot.nodesByID, types.NodeID(1))
						assert.Equal(t, node.ID, snapshot.nodesByID[1].ID)
						assert.Empty(t, snapshot.peersByNode[1]) // no peers yet
						assert.Len(t, snapshot.nodesByUser[1], 1)
					},
				},
			},
		},
		{
			name: "create store with initial node and add more",
			setupFunc: func(t *testing.T) *NodeStore {
				node1 := createTestNode(1, 1, "user1", "node1")
				initialNodes := types.Nodes{&node1}
				return NewNodeStore(initialNodes, allowAllPeersFunc)
			},
			steps: []testStep{
				{
					name: "verify initial state",
					action: func(store *NodeStore) {
						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 1)
						assert.Len(t, snapshot.allNodes, 1)
						assert.Len(t, snapshot.peersByNode, 1)
						assert.Len(t, snapshot.nodesByUser, 1)
						assert.Empty(t, snapshot.peersByNode[1])
					},
				},
				{
					name: "add second node same user",
					action: func(store *NodeStore) {
						node2 := createTestNode(2, 1, "user1", "node2")
						resultNode := store.PutNode(node2)
						assert.True(t, resultNode.Valid(), "PutNode should return valid node")
						assert.Equal(t, types.NodeID(2), resultNode.ID())

						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 2)
						assert.Len(t, snapshot.allNodes, 2)
						assert.Len(t, snapshot.peersByNode, 2)
						assert.Len(t, snapshot.nodesByUser, 1)

						// Now both nodes should see each other as peers
						assert.Len(t, snapshot.peersByNode[1], 1)
						assert.Equal(t, types.NodeID(2), snapshot.peersByNode[1][0].ID())
						assert.Len(t, snapshot.peersByNode[2], 1)
						assert.Equal(t, types.NodeID(1), snapshot.peersByNode[2][0].ID())
						assert.Len(t, snapshot.nodesByUser[1], 2)
					},
				},
				{
					name: "add third node different user",
					action: func(store *NodeStore) {
						node3 := createTestNode(3, 2, "user2", "node3")
						resultNode := store.PutNode(node3)
						assert.True(t, resultNode.Valid(), "PutNode should return valid node")
						assert.Equal(t, types.NodeID(3), resultNode.ID())

						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 3)
						assert.Len(t, snapshot.allNodes, 3)
						assert.Len(t, snapshot.peersByNode, 3)
						assert.Len(t, snapshot.nodesByUser, 2)

						// All nodes should see the other 2 as peers
						assert.Len(t, snapshot.peersByNode[1], 2)
						assert.Len(t, snapshot.peersByNode[2], 2)
						assert.Len(t, snapshot.peersByNode[3], 2)

						// User groupings
						assert.Len(t, snapshot.nodesByUser[1], 2) // user1 has nodes 1,2
						assert.Len(t, snapshot.nodesByUser[2], 1) // user2 has node 3
					},
				},
			},
		},
		{
			name: "test node deletion",
			setupFunc: func(t *testing.T) *NodeStore {
				node1 := createTestNode(1, 1, "user1", "node1")
				node2 := createTestNode(2, 1, "user1", "node2")
				node3 := createTestNode(3, 2, "user2", "node3")
				initialNodes := types.Nodes{&node1, &node2, &node3}

				return NewNodeStore(initialNodes, allowAllPeersFunc)
			},
			steps: []testStep{
				{
					name: "verify initial 3 nodes",
					action: func(store *NodeStore) {
						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 3)
						assert.Len(t, snapshot.allNodes, 3)
						assert.Len(t, snapshot.peersByNode, 3)
						assert.Len(t, snapshot.nodesByUser, 2)
					},
				},
				{
					name: "delete middle node",
					action: func(store *NodeStore) {
						store.DeleteNode(2)

						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 2)
						assert.Len(t, snapshot.allNodes, 2)
						assert.Len(t, snapshot.peersByNode, 2)
						assert.Len(t, snapshot.nodesByUser, 2)

						// Node 2 should be gone
						assert.NotContains(t, snapshot.nodesByID, types.NodeID(2))

						// Remaining nodes should see each other as peers
						assert.Len(t, snapshot.peersByNode[1], 1)
						assert.Equal(t, types.NodeID(3), snapshot.peersByNode[1][0].ID())
						assert.Len(t, snapshot.peersByNode[3], 1)
						assert.Equal(t, types.NodeID(1), snapshot.peersByNode[3][0].ID())

						// User groupings updated
						assert.Len(t, snapshot.nodesByUser[1], 1) // user1 now has only node 1
						assert.Len(t, snapshot.nodesByUser[2], 1) // user2 still has node 3
					},
				},
				{
					name: "delete all remaining nodes",
					action: func(store *NodeStore) {
						store.DeleteNode(1)
						store.DeleteNode(3)

						snapshot := store.data.Load()
						assert.Empty(t, snapshot.nodesByID)
						assert.Empty(t, snapshot.allNodes)
						assert.Empty(t, snapshot.peersByNode)
						assert.Empty(t, snapshot.nodesByUser)
					},
				},
			},
		},
		{
			name: "test node updates",
			setupFunc: func(t *testing.T) *NodeStore {
				node1 := createTestNode(1, 1, "user1", "node1")
				node2 := createTestNode(2, 1, "user1", "node2")
				initialNodes := types.Nodes{&node1, &node2}
				return NewNodeStore(initialNodes, allowAllPeersFunc)
			},
			steps: []testStep{
				{
					name: "verify initial hostnames",
					action: func(store *NodeStore) {
						snapshot := store.data.Load()
						assert.Equal(t, "node1", snapshot.nodesByID[1].Hostname)
						assert.Equal(t, "node2", snapshot.nodesByID[2].Hostname)
					},
				},
				{
					name: "update node hostname",
					action: func(store *NodeStore) {
						resultNode, ok := store.UpdateNode(1, func(n *types.Node) {
							n.Hostname = "updated-node1"
							n.GivenName = "updated-node1"
						})
						assert.True(t, ok, "UpdateNode should return true for existing node")
						assert.True(t, resultNode.Valid(), "Result node should be valid")
						assert.Equal(t, "updated-node1", resultNode.Hostname())
						assert.Equal(t, "updated-node1", resultNode.GivenName())

						snapshot := store.data.Load()
						assert.Equal(t, "updated-node1", snapshot.nodesByID[1].Hostname)
						assert.Equal(t, "updated-node1", snapshot.nodesByID[1].GivenName)
						assert.Equal(t, "node2", snapshot.nodesByID[2].Hostname) // unchanged

						// Peers should still work correctly
						assert.Len(t, snapshot.peersByNode[1], 1)
						assert.Len(t, snapshot.peersByNode[2], 1)
					},
				},
			},
		},
		{
			name: "test with odd-even peers filtering",
			setupFunc: func(t *testing.T) *NodeStore {
				return NewNodeStore(nil, oddEvenPeersFunc)
			},
			steps: []testStep{
				{
					name: "add nodes with odd-even filtering",
					action: func(store *NodeStore) {
						// Add nodes in sequence
						n1 := store.PutNode(createTestNode(1, 1, "user1", "node1"))
						assert.True(t, n1.Valid())
						n2 := store.PutNode(createTestNode(2, 2, "user2", "node2"))
						assert.True(t, n2.Valid())
						n3 := store.PutNode(createTestNode(3, 3, "user3", "node3"))
						assert.True(t, n3.Valid())
						n4 := store.PutNode(createTestNode(4, 4, "user4", "node4"))
						assert.True(t, n4.Valid())

						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 4)

						// Verify odd-even peer relationships
						require.Len(t, snapshot.peersByNode[1], 1)
						assert.Equal(t, types.NodeID(3), snapshot.peersByNode[1][0].ID())

						require.Len(t, snapshot.peersByNode[2], 1)
						assert.Equal(t, types.NodeID(4), snapshot.peersByNode[2][0].ID())

						require.Len(t, snapshot.peersByNode[3], 1)
						assert.Equal(t, types.NodeID(1), snapshot.peersByNode[3][0].ID())

						require.Len(t, snapshot.peersByNode[4], 1)
						assert.Equal(t, types.NodeID(2), snapshot.peersByNode[4][0].ID())
					},
				},
				{
					name: "delete odd node and verify even nodes unaffected",
					action: func(store *NodeStore) {
						store.DeleteNode(1)

						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 3)

						// Node 3 (odd) should now have no peers
						assert.Empty(t, snapshot.peersByNode[3])

						// Even nodes should still see each other
						require.Len(t, snapshot.peersByNode[2], 1)
						assert.Equal(t, types.NodeID(4), snapshot.peersByNode[2][0].ID())
						require.Len(t, snapshot.peersByNode[4], 1)
						assert.Equal(t, types.NodeID(2), snapshot.peersByNode[4][0].ID())
					},
				},
			},
		},
		{
			name: "test batch modifications return correct node state",
			setupFunc: func(t *testing.T) *NodeStore {
				node1 := createTestNode(1, 1, "user1", "node1")
				node2 := createTestNode(2, 1, "user1", "node2")
				initialNodes := types.Nodes{&node1, &node2}
				return NewNodeStore(initialNodes, allowAllPeersFunc)
			},
			steps: []testStep{
				{
					name: "verify initial state",
					action: func(store *NodeStore) {
						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 2)
						assert.Equal(t, "node1", snapshot.nodesByID[1].Hostname)
						assert.Equal(t, "node2", snapshot.nodesByID[2].Hostname)
					},
				},
				{
					name: "concurrent updates should reflect all batch changes",
					action: func(store *NodeStore) {
						// Start multiple updates that will be batched together
						done1 := make(chan struct{})
						done2 := make(chan struct{})
						done3 := make(chan struct{})

						var resultNode1, resultNode2 types.NodeView
						var newNode3 types.NodeView
						var ok1, ok2 bool

						// These should all be processed in the same batch
						go func() {
							resultNode1, ok1 = store.UpdateNode(1, func(n *types.Node) {
								n.Hostname = "batch-updated-node1"
								n.GivenName = "batch-given-1"
							})
							close(done1)
						}()

						go func() {
							resultNode2, ok2 = store.UpdateNode(2, func(n *types.Node) {
								n.Hostname = "batch-updated-node2"
								n.GivenName = "batch-given-2"
							})
							close(done2)
						}()

						go func() {
							node3 := createTestNode(3, 1, "user1", "node3")
							newNode3 = store.PutNode(node3)
							close(done3)
						}()

						// Wait for all operations to complete
						<-done1
						<-done2
						<-done3

						// Verify the returned nodes reflect the batch state
						assert.True(t, ok1, "UpdateNode should succeed for node 1")
						assert.True(t, ok2, "UpdateNode should succeed for node 2")
						assert.True(t, resultNode1.Valid())
						assert.True(t, resultNode2.Valid())
						assert.True(t, newNode3.Valid())

						// Check that returned nodes have the updated values
						assert.Equal(t, "batch-updated-node1", resultNode1.Hostname())
						assert.Equal(t, "batch-given-1", resultNode1.GivenName())
						assert.Equal(t, "batch-updated-node2", resultNode2.Hostname())
						assert.Equal(t, "batch-given-2", resultNode2.GivenName())
						assert.Equal(t, "node3", newNode3.Hostname())

						// Verify the snapshot also reflects all changes
						snapshot := store.data.Load()
						assert.Len(t, snapshot.nodesByID, 3)
						assert.Equal(t, "batch-updated-node1", snapshot.nodesByID[1].Hostname)
						assert.Equal(t, "batch-updated-node2", snapshot.nodesByID[2].Hostname)
						assert.Equal(t, "node3", snapshot.nodesByID[3].Hostname)

						// Verify peer relationships are updated correctly with new node
						assert.Len(t, snapshot.peersByNode[1], 2) // sees nodes 2 and 3
						assert.Len(t, snapshot.peersByNode[2], 2) // sees nodes 1 and 3
						assert.Len(t, snapshot.peersByNode[3], 2) // sees nodes 1 and 2
					},
				},
				{
					name: "update non-existent node returns invalid view",
					action: func(store *NodeStore) {
						resultNode, ok := store.UpdateNode(999, func(n *types.Node) {
							n.Hostname = "should-not-exist"
						})

						assert.False(t, ok, "UpdateNode should return false for non-existent node")
						assert.False(t, resultNode.Valid(), "Result should be invalid NodeView")
					},
				},
				{
					name: "multiple updates to same node in batch all see final state",
					action: func(store *NodeStore) {
						// This test verifies that when multiple updates to the same node
						// are batched together, each returned node reflects ALL changes
						// in the batch, not just the individual update's changes.

						done1 := make(chan struct{})
						done2 := make(chan struct{})
						done3 := make(chan struct{})

						var resultNode1, resultNode2, resultNode3 types.NodeView
						var ok1, ok2, ok3 bool

						// These updates all modify node 1 and should be batched together
						// The final state should have all three modifications applied
						go func() {
							resultNode1, ok1 = store.UpdateNode(1, func(n *types.Node) {
								n.Hostname = "multi-update-hostname"
							})
							close(done1)
						}()

						go func() {
							resultNode2, ok2 = store.UpdateNode(1, func(n *types.Node) {
								n.GivenName = "multi-update-givenname"
							})
							close(done2)
						}()

						go func() {
							resultNode3, ok3 = store.UpdateNode(1, func(n *types.Node) {
								n.ForcedTags = []string{"tag1", "tag2"}
							})
							close(done3)
						}()

						// Wait for all operations to complete
						<-done1
						<-done2
						<-done3

						// All updates should succeed
						assert.True(t, ok1, "First update should succeed")
						assert.True(t, ok2, "Second update should succeed")
						assert.True(t, ok3, "Third update should succeed")

						// CRITICAL: Each returned node should reflect ALL changes from the batch
						// not just the change from its specific update call

						// resultNode1 (from hostname update) should also have the givenname and tags changes
						assert.Equal(t, "multi-update-hostname", resultNode1.Hostname())
						assert.Equal(t, "multi-update-givenname", resultNode1.GivenName())
						assert.Equal(t, []string{"tag1", "tag2"}, resultNode1.ForcedTags().AsSlice())

						// resultNode2 (from givenname update) should also have the hostname and tags changes
						assert.Equal(t, "multi-update-hostname", resultNode2.Hostname())
						assert.Equal(t, "multi-update-givenname", resultNode2.GivenName())
						assert.Equal(t, []string{"tag1", "tag2"}, resultNode2.ForcedTags().AsSlice())

						// resultNode3 (from tags update) should also have the hostname and givenname changes
						assert.Equal(t, "multi-update-hostname", resultNode3.Hostname())
						assert.Equal(t, "multi-update-givenname", resultNode3.GivenName())
						assert.Equal(t, []string{"tag1", "tag2"}, resultNode3.ForcedTags().AsSlice())

						// Verify the snapshot also has all changes
						snapshot := store.data.Load()
						finalNode := snapshot.nodesByID[1]
						assert.Equal(t, "multi-update-hostname", finalNode.Hostname)
						assert.Equal(t, "multi-update-givenname", finalNode.GivenName)
						assert.Equal(t, []string{"tag1", "tag2"}, finalNode.ForcedTags)
					},
				},
			},
		},
		{
			name: "test UpdateNode result is immutable for database save",
			setupFunc: func(t *testing.T) *NodeStore {
				node1 := createTestNode(1, 1, "user1", "node1")
				node2 := createTestNode(2, 1, "user1", "node2")
				initialNodes := types.Nodes{&node1, &node2}
				return NewNodeStore(initialNodes, allowAllPeersFunc)
			},
			steps: []testStep{
				{
					name: "verify returned node is complete and consistent",
					action: func(store *NodeStore) {
						// Update a node and verify the returned view is complete
						resultNode, ok := store.UpdateNode(1, func(n *types.Node) {
							n.Hostname = "db-save-hostname"
							n.GivenName = "db-save-given"
							n.ForcedTags = []string{"db-tag1", "db-tag2"}
						})

						assert.True(t, ok, "UpdateNode should succeed")
						assert.True(t, resultNode.Valid(), "Result should be valid")

						// Verify the returned node has all expected values
						assert.Equal(t, "db-save-hostname", resultNode.Hostname())
						assert.Equal(t, "db-save-given", resultNode.GivenName())
						assert.Equal(t, []string{"db-tag1", "db-tag2"}, resultNode.ForcedTags().AsSlice())

						// Convert to struct as would be done for database save
						nodePtr := resultNode.AsStruct()
						assert.NotNil(t, nodePtr)
						assert.Equal(t, "db-save-hostname", nodePtr.Hostname)
						assert.Equal(t, "db-save-given", nodePtr.GivenName)
						assert.Equal(t, []string{"db-tag1", "db-tag2"}, nodePtr.ForcedTags)

						// Verify the snapshot also reflects the same state
						snapshot := store.data.Load()
						storedNode := snapshot.nodesByID[1]
						assert.Equal(t, "db-save-hostname", storedNode.Hostname)
						assert.Equal(t, "db-save-given", storedNode.GivenName)
						assert.Equal(t, []string{"db-tag1", "db-tag2"}, storedNode.ForcedTags)
					},
				},
				{
					name: "concurrent updates all return consistent final state for DB save",
					action: func(store *NodeStore) {
						// Multiple goroutines updating the same node
						// All should receive the final batch state suitable for DB save
						done1 := make(chan struct{})
						done2 := make(chan struct{})
						done3 := make(chan struct{})

						var result1, result2, result3 types.NodeView
						var ok1, ok2, ok3 bool

						// Start concurrent updates
						go func() {
							result1, ok1 = store.UpdateNode(1, func(n *types.Node) {
								n.Hostname = "concurrent-db-hostname"
							})
							close(done1)
						}()

						go func() {
							result2, ok2 = store.UpdateNode(1, func(n *types.Node) {
								n.GivenName = "concurrent-db-given"
							})
							close(done2)
						}()

						go func() {
							result3, ok3 = store.UpdateNode(1, func(n *types.Node) {
								n.ForcedTags = []string{"concurrent-tag"}
							})
							close(done3)
						}()

						// Wait for all to complete
						<-done1
						<-done2
						<-done3

						assert.True(t, ok1 && ok2 && ok3, "All updates should succeed")

						// All results should be valid and suitable for database save
						assert.True(t, result1.Valid())
						assert.True(t, result2.Valid())
						assert.True(t, result3.Valid())

						// Convert each to struct as would be done for DB save
						nodePtr1 := result1.AsStruct()
						nodePtr2 := result2.AsStruct()
						nodePtr3 := result3.AsStruct()

						// All should have the complete final state
						assert.Equal(t, "concurrent-db-hostname", nodePtr1.Hostname)
						assert.Equal(t, "concurrent-db-given", nodePtr1.GivenName)
						assert.Equal(t, []string{"concurrent-tag"}, nodePtr1.ForcedTags)

						assert.Equal(t, "concurrent-db-hostname", nodePtr2.Hostname)
						assert.Equal(t, "concurrent-db-given", nodePtr2.GivenName)
						assert.Equal(t, []string{"concurrent-tag"}, nodePtr2.ForcedTags)

						assert.Equal(t, "concurrent-db-hostname", nodePtr3.Hostname)
						assert.Equal(t, "concurrent-db-given", nodePtr3.GivenName)
						assert.Equal(t, []string{"concurrent-tag"}, nodePtr3.ForcedTags)

						// Verify consistency with stored state
						snapshot := store.data.Load()
						storedNode := snapshot.nodesByID[1]
						assert.Equal(t, nodePtr1.Hostname, storedNode.Hostname)
						assert.Equal(t, nodePtr1.GivenName, storedNode.GivenName)
						assert.Equal(t, nodePtr1.ForcedTags, storedNode.ForcedTags)
					},
				},
				{
					name: "verify returned node preserves all fields for DB save",
					action: func(store *NodeStore) {
						// Get initial state
						snapshot := store.data.Load()
						originalNode := snapshot.nodesByID[2]
						originalIPv4 := originalNode.IPv4
						originalIPv6 := originalNode.IPv6
						originalCreatedAt := originalNode.CreatedAt
						originalUser := originalNode.User

						// Update only hostname
						resultNode, ok := store.UpdateNode(2, func(n *types.Node) {
							n.Hostname = "preserve-test-hostname"
						})

						assert.True(t, ok, "Update should succeed")

						// Convert to struct for DB save
						nodeForDB := resultNode.AsStruct()

						// Verify all fields are preserved
						assert.Equal(t, "preserve-test-hostname", nodeForDB.Hostname)
						assert.Equal(t, originalIPv4, nodeForDB.IPv4)
						assert.Equal(t, originalIPv6, nodeForDB.IPv6)
						assert.Equal(t, originalCreatedAt, nodeForDB.CreatedAt)
						assert.Equal(t, originalUser.Name, nodeForDB.User.Name)
						assert.Equal(t, types.NodeID(2), nodeForDB.ID)

						// These fields should be suitable for direct database save
						assert.NotNil(t, nodeForDB.IPv4)
						assert.NotNil(t, nodeForDB.IPv6)
						assert.False(t, nodeForDB.CreatedAt.IsZero())
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := tt.setupFunc(t)
			store.Start()
			defer store.Stop()

			for _, step := range tt.steps {
				t.Run(step.name, func(t *testing.T) {
					step.action(store)
				})
			}
		})
	}
}

type testStep struct {
	name   string
	action func(store *NodeStore)
}
