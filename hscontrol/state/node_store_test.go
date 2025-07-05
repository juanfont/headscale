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
						store.PutNode(node)

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
						store.PutNode(node2)

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
						store.PutNode(node3)

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
						store.UpdateNode(1, func(n *types.Node) {
							n.Hostname = "updated-node1"
							n.GivenName = "updated-node1"
						})

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
						store.PutNode(createTestNode(1, 1, "user1", "node1"))
						store.PutNode(createTestNode(2, 2, "user2", "node2"))
						store.PutNode(createTestNode(3, 3, "user3", "node3"))
						store.PutNode(createTestNode(4, 4, "user4", "node4"))

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
