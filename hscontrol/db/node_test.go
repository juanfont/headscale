package db

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestGetNode(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test")

	_, err = db.getNode(types.UserID(user.ID), "testnode")
	require.Error(t, err)

	node := db.CreateNodeForTest(user, "testnode")

	_, err = db.getNode(types.UserID(user.ID), "testnode")
	require.NoError(t, err)
	assert.Equal(t, "testnode", node.Hostname)
}

func TestGetNodeByID(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test")

	_, err = db.GetNodeByID(0)
	require.Error(t, err)

	node := db.CreateNodeForTest(user, "testnode")

	retrievedNode, err := db.GetNodeByID(node.ID)
	require.NoError(t, err)
	assert.Equal(t, "testnode", retrievedNode.Hostname)
}

func TestHardDeleteNode(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test")
	node := db.CreateNodeForTest(user, "testnode3")

	err = db.DeleteNode(node)
	require.NoError(t, err)

	_, err = db.getNode(types.UserID(user.ID), "testnode3")
	require.Error(t, err)
}

func TestListPeersManyNodes(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test")

	_, err = db.GetNodeByID(0)
	require.Error(t, err)

	nodes := db.CreateNodesForTest(user, 11, "testnode")

	firstNode := nodes[0]
	peersOfFirstNode, err := db.ListPeers(firstNode.ID)
	require.NoError(t, err)

	assert.Len(t, peersOfFirstNode, 10)
	assert.Equal(t, "testnode-1", peersOfFirstNode[0].Hostname)
	assert.Equal(t, "testnode-6", peersOfFirstNode[5].Hostname)
	assert.Equal(t, "testnode-10", peersOfFirstNode[9].Hostname)
}

func TestExpireNode(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user, err := db.CreateUser(types.User{Name: "test"})
	require.NoError(t, err)

	pak, err := db.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	require.NoError(t, err)

	pakID := pak.ID

	_, err = db.getNode(types.UserID(user.ID), "testnode")
	require.Error(t, err)

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()

	node := &types.Node{
		ID:             0,
		MachineKey:     machineKey.Public(),
		NodeKey:        nodeKey.Public(),
		Hostname:       "testnode",
		UserID:         &user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
		Expiry:         &time.Time{},
	}
	db.DB.Save(node)

	nodeFromDB, err := db.getNode(types.UserID(user.ID), "testnode")
	require.NoError(t, err)
	require.NotNil(t, nodeFromDB)

	assert.False(t, nodeFromDB.IsExpired())

	now := time.Now()
	err = db.NodeSetExpiry(nodeFromDB.ID, &now)
	require.NoError(t, err)

	nodeFromDB, err = db.getNode(types.UserID(user.ID), "testnode")
	require.NoError(t, err)

	assert.True(t, nodeFromDB.IsExpired())
}

func TestDisableNodeExpiry(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user, err := db.CreateUser(types.User{Name: "test"})
	require.NoError(t, err)

	pak, err := db.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	require.NoError(t, err)

	pakID := pak.ID
	node := &types.Node{
		ID:             0,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "testnode",
		UserID:         &user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
		Expiry:         &time.Time{},
	}
	db.DB.Save(node)

	// Set an expiry first.
	past := time.Now().Add(-time.Hour)
	err = db.NodeSetExpiry(node.ID, &past)
	require.NoError(t, err)

	nodeFromDB, err := db.getNode(types.UserID(user.ID), "testnode")
	require.NoError(t, err)
	assert.True(t, nodeFromDB.IsExpired(), "node should be expired")

	// Disable expiry by setting nil.
	err = db.NodeSetExpiry(node.ID, nil)
	require.NoError(t, err)

	nodeFromDB, err = db.getNode(types.UserID(user.ID), "testnode")
	require.NoError(t, err)
	assert.False(t, nodeFromDB.IsExpired(), "node should not be expired after disabling expiry")
	assert.Nil(t, nodeFromDB.Expiry, "expiry should be nil after disabling")
}

func TestSetTags(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user, err := db.CreateUser(types.User{Name: "test"})
	require.NoError(t, err)

	pak, err := db.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	require.NoError(t, err)

	pakID := pak.ID

	_, err = db.getNode(types.UserID(user.ID), "testnode")
	require.Error(t, err)

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()

	node := &types.Node{
		ID:             0,
		MachineKey:     machineKey.Public(),
		NodeKey:        nodeKey.Public(),
		Hostname:       "testnode",
		UserID:         &user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
	}

	trx := db.DB.Save(node)
	require.NoError(t, trx.Error)

	// assign simple tags
	sTags := []string{"tag:test", "tag:foo"}
	err = db.SetTags(node.ID, sTags)
	require.NoError(t, err)
	node, err = db.getNode(types.UserID(user.ID), "testnode")
	require.NoError(t, err)
	assert.Equal(t, sTags, node.Tags)

	// assign duplicate tags, expect no errors but no doubles in DB
	eTags := []string{"tag:bar", "tag:test", "tag:unknown", "tag:test"}
	err = db.SetTags(node.ID, eTags)
	require.NoError(t, err)
	node, err = db.getNode(types.UserID(user.ID), "testnode")
	require.NoError(t, err)
	assert.Equal(t, []string{"tag:bar", "tag:test", "tag:unknown"}, node.Tags)
}


func TestAutoApproveRoutes(t *testing.T) {
	tests := []struct {
		name         string
		acl          string
		routes       []netip.Prefix
		want         []netip.Prefix
		want2        []netip.Prefix
		expectChange bool // whether to expect route changes
	}{
		{
			name: "no-auto-approvers-empty-policy",
			acl: `
{
	"groups": {
		"group:admins": ["test@"]
	},
	"acls": [
		{
			"action": "accept",
			"src": ["group:admins"],
			"dst": ["group:admins:*"]
		}
	]
}`,
			routes:       []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")},
			want:         []netip.Prefix{}, // Should be empty - no auto-approvers
			want2:        []netip.Prefix{}, // Should be empty - no auto-approvers
			expectChange: false,            // No changes expected
		},
		{
			name: "no-auto-approvers-explicit-empty",
			acl: `
{
	"groups": {
		"group:admins": ["test@"]
	},
	"acls": [
		{
			"action": "accept",
			"src": ["group:admins"],
			"dst": ["group:admins:*"]
		}
	],
	"autoApprovers": {
		"routes": {},
		"exitNode": []
	}
}`,
			routes:       []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")},
			want:         []netip.Prefix{}, // Should be empty - explicitly empty auto-approvers
			want2:        []netip.Prefix{}, // Should be empty - explicitly empty auto-approvers
			expectChange: false,            // No changes expected
		},
		{
			name: "2068-approve-issue-sub-kube",
			acl: `
{
	"groups": {
		"group:k8s": ["test@"]
	},

// 	"acls": [
// 		{"action": "accept", "users": ["*"], "ports": ["*:*"]},
// 	],

	"autoApprovers": {
		"routes": {
			"10.42.0.0/16": ["test@"],
		}
	}
}`,
			routes:       []netip.Prefix{netip.MustParsePrefix("10.42.7.0/24")},
			want:         []netip.Prefix{netip.MustParsePrefix("10.42.7.0/24")},
			expectChange: true, // Routes should be approved
		},
		{
			name: "2068-approve-issue-sub-exit-tag",
			acl: `
{
	"tagOwners": {
		"tag:exit": ["test@"],
	},

	"groups": {
		"group:test": ["test@"]
	},

// 	"acls": [
// 		{"action": "accept", "users": ["*"], "ports": ["*:*"]},
// 	],

	"autoApprovers": {
		"exitNode": ["tag:exit"],
		"routes": {
			"10.10.0.0/16": ["group:test"],
			"10.11.0.0/16": ["test@"],
			"8.11.0.0/24": ["test2@"], // No nodes
		}
	}
}`,
			routes: []netip.Prefix{
				tsaddr.AllIPv4(),
				tsaddr.AllIPv6(),
				netip.MustParsePrefix("10.10.0.0/16"),
				netip.MustParsePrefix("10.11.0.0/24"),

				// Not approved
				netip.MustParsePrefix("8.11.0.0/24"),
			},
			want: []netip.Prefix{
				netip.MustParsePrefix("10.10.0.0/16"),
				netip.MustParsePrefix("10.11.0.0/24"),
			},
			want2: []netip.Prefix{
				tsaddr.AllIPv4(),
				tsaddr.AllIPv6(),
			},
			expectChange: true, // Routes should be approved
		},
	}

	for _, tt := range tests {
		pmfs := policy.PolicyManagerFuncsForTest([]byte(tt.acl))
		for i, pmf := range pmfs {
			t.Run(fmt.Sprintf("%s-policy-index%d", tt.name, i), func(t *testing.T) {
				adb, err := newSQLiteTestDB()
				require.NoError(t, err)

				user, err := adb.CreateUser(types.User{Name: "test"})
				require.NoError(t, err)
				_, err = adb.CreateUser(types.User{Name: "test2"})
				require.NoError(t, err)
				taggedUser, err := adb.CreateUser(types.User{Name: "tagged"})
				require.NoError(t, err)

				node := types.Node{
					ID:             1,
					MachineKey:     key.NewMachine().Public(),
					NodeKey:        key.NewNode().Public(),
					Hostname:       "testnode",
					UserID:         &user.ID,
					RegisterMethod: util.RegisterMethodAuthKey,
					Hostinfo: &tailcfg.Hostinfo{
						RoutableIPs: tt.routes,
					},
					IPv4: new(netip.MustParseAddr("100.64.0.1")),
				}

				err = adb.DB.Save(&node).Error
				require.NoError(t, err)

				nodeTagged := types.Node{
					ID:             2,
					MachineKey:     key.NewMachine().Public(),
					NodeKey:        key.NewNode().Public(),
					Hostname:       "taggednode",
					UserID:         &taggedUser.ID,
					RegisterMethod: util.RegisterMethodAuthKey,
					Hostinfo: &tailcfg.Hostinfo{
						RoutableIPs: tt.routes,
					},
					Tags: []string{"tag:exit"},
					IPv4: new(netip.MustParseAddr("100.64.0.2")),
				}

				err = adb.DB.Save(&nodeTagged).Error
				require.NoError(t, err)

				users, err := adb.ListUsers()
				require.NoError(t, err)

				nodes, err := adb.ListNodes()
				require.NoError(t, err)

				pm, err := pmf(users, nodes.ViewSlice())
				require.NoError(t, err)
				require.NotNil(t, pm)

				newRoutes1, changed1 := policy.ApproveRoutesWithPolicy(pm, node.View(), node.ApprovedRoutes, tt.routes)
				assert.Equal(t, tt.expectChange, changed1)

				if changed1 {
					err = SetApprovedRoutes(adb.DB, node.ID, newRoutes1)
					require.NoError(t, err)
				}

				newRoutes2, changed2 := policy.ApproveRoutesWithPolicy(pm, nodeTagged.View(), nodeTagged.ApprovedRoutes, tt.routes)
				if changed2 {
					err = SetApprovedRoutes(adb.DB, nodeTagged.ID, newRoutes2)
					require.NoError(t, err)
				}

				node1ByID, err := adb.GetNodeByID(1)
				require.NoError(t, err)

				// For empty auto-approvers tests, handle nil vs empty slice comparison
				expectedRoutes1 := tt.want
				if len(expectedRoutes1) == 0 {
					expectedRoutes1 = nil
				}

				if diff := cmp.Diff(expectedRoutes1, node1ByID.AllApprovedRoutes(), util.Comparers...); diff != "" {
					t.Errorf("unexpected enabled routes (-want +got):\n%s", diff)
				}

				node2ByID, err := adb.GetNodeByID(2)
				require.NoError(t, err)

				expectedRoutes2 := tt.want2
				if len(expectedRoutes2) == 0 {
					expectedRoutes2 = nil
				}

				if diff := cmp.Diff(expectedRoutes2, node2ByID.AllApprovedRoutes(), util.Comparers...); diff != "" {
					t.Errorf("unexpected enabled routes (-want +got):\n%s", diff)
				}
			})
		}
	}
}

func TestEphemeralGarbageCollectorOrder(t *testing.T) {
	want := []types.NodeID{1, 3}
	got := []types.NodeID{}

	var mu sync.Mutex

	deletionCount := make(chan struct{}, 10)

	e := NewEphemeralGarbageCollector(func(ni types.NodeID) {
		mu.Lock()
		defer mu.Unlock()

		got = append(got, ni)

		deletionCount <- struct{}{}
	})
	go e.Start()

	// Use shorter timeouts for faster tests
	go e.Schedule(1, 50*time.Millisecond)
	go e.Schedule(2, 100*time.Millisecond)
	go e.Schedule(3, 150*time.Millisecond)
	go e.Schedule(4, 200*time.Millisecond)

	// Wait for first deletion (node 1 at 50ms)
	select {
	case <-deletionCount:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for first deletion")
	}

	// Cancel nodes 2 and 4
	go e.Cancel(2)
	go e.Cancel(4)

	// Wait for node 3 to be deleted (at 150ms)
	select {
	case <-deletionCount:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for second deletion")
	}

	// Give a bit more time for any unexpected deletions
	select {
	case <-deletionCount:
		// Unexpected - more deletions than expected
	case <-time.After(300 * time.Millisecond):
		// Expected - no more deletions
	}

	e.Close()

	mu.Lock()
	defer mu.Unlock()

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("wrong nodes deleted, unexpected result (-want +got):\n%s", diff)
	}
}

func TestEphemeralGarbageCollectorLoads(t *testing.T) {
	var (
		got []types.NodeID
		mu  sync.Mutex
	)

	want := 1000

	var deletedCount atomic.Int64

	e := NewEphemeralGarbageCollector(func(ni types.NodeID) {
		mu.Lock()
		defer mu.Unlock()

		// Yield to other goroutines to introduce variability
		runtime.Gosched()

		got = append(got, ni)

		deletedCount.Add(1)
	})
	go e.Start()

	// Use shorter expiry for faster tests
	for i := range want {
		go e.Schedule(types.NodeID(i), 100*time.Millisecond) //nolint:gosec // test code, no overflow risk
	}

	// Wait for all deletions to complete
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		count := deletedCount.Load()
		assert.Equal(c, int64(want), count, "all nodes should be deleted")
	}, 10*time.Second, 50*time.Millisecond, "waiting for all deletions")

	e.Close()

	mu.Lock()
	defer mu.Unlock()

	if len(got) != want {
		t.Errorf("expected %d, got %d", want, len(got))
	}
}

//nolint:unused
func generateRandomNumber(t *testing.T, maxVal int64) int64 {
	t.Helper()

	maxB := big.NewInt(maxVal)

	n, err := rand.Int(rand.Reader, maxB)
	if err != nil {
		t.Fatalf("getting random number: %s", err)
	}

	return n.Int64() + 1
}

func TestListEphemeralNodes(t *testing.T) {
	db, err := newSQLiteTestDB()
	if err != nil {
		t.Fatalf("creating db: %s", err)
	}

	user, err := db.CreateUser(types.User{Name: "test"})
	require.NoError(t, err)

	pak, err := db.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	require.NoError(t, err)

	pakEph, err := db.CreatePreAuthKey(user.TypedID(), false, true, nil, nil)
	require.NoError(t, err)

	pakID := pak.ID
	pakEphID := pakEph.ID

	node := types.Node{
		ID:             0,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "test",
		UserID:         &user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
	}

	nodeEph := types.Node{
		ID:             0,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "ephemeral",
		UserID:         &user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakEphID,
	}

	err = db.DB.Save(&node).Error
	require.NoError(t, err)

	err = db.DB.Save(&nodeEph).Error
	require.NoError(t, err)

	nodes, err := db.ListNodes()
	require.NoError(t, err)

	ephemeralNodes, err := db.ListEphemeralNodes()
	require.NoError(t, err)

	assert.Len(t, nodes, 2)
	assert.Len(t, ephemeralNodes, 1)

	assert.Equal(t, nodeEph.ID, ephemeralNodes[0].ID)
	assert.Equal(t, nodeEph.AuthKeyID, ephemeralNodes[0].AuthKeyID)
	assert.Equal(t, nodeEph.UserID, ephemeralNodes[0].UserID)
	assert.Equal(t, nodeEph.Hostname, ephemeralNodes[0].Hostname)
}


func TestListPeers(t *testing.T) {
	// Setup test database
	db, err := newSQLiteTestDB()
	if err != nil {
		t.Fatalf("creating db: %s", err)
	}

	user, err := db.CreateUser(types.User{Name: "test"})
	require.NoError(t, err)

	user2, err := db.CreateUser(types.User{Name: "user2"})
	require.NoError(t, err)

	node1 := types.Node{
		ID:             0,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "test1",
		UserID:         &user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		Hostinfo:       &tailcfg.Hostinfo{},
	}

	node2 := types.Node{
		ID:             0,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "test2",
		UserID:         &user2.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		Hostinfo:       &tailcfg.Hostinfo{},
	}

	err = db.DB.Save(&node1).Error
	require.NoError(t, err)

	err = db.DB.Save(&node2).Error
	require.NoError(t, err)

	err = db.DB.Transaction(func(tx *gorm.DB) error {
		_, err := RegisterNodeForTest(tx, node1, nil, nil)
		if err != nil {
			return err
		}

		_, err = RegisterNodeForTest(tx, node2, nil, nil)

		return err
	})
	require.NoError(t, err)

	nodes, err := db.ListNodes()
	require.NoError(t, err)

	assert.Len(t, nodes, 2)

	// No parameter means no filter, should return all peers
	nodes, err = db.ListPeers(1)
	require.NoError(t, err)
	assert.Len(t, nodes, 1)
	assert.Equal(t, "test2", nodes[0].Hostname)

	// Empty node list should return all peers
	nodes, err = db.ListPeers(1, types.NodeIDs{}...)
	require.NoError(t, err)
	assert.Len(t, nodes, 1)
	assert.Equal(t, "test2", nodes[0].Hostname)

	// No match in IDs should return empty list and no error
	nodes, err = db.ListPeers(1, types.NodeIDs{3, 4, 5}...)
	require.NoError(t, err)
	assert.Empty(t, nodes)

	// Partial match in IDs
	nodes, err = db.ListPeers(1, types.NodeIDs{2, 3}...)
	require.NoError(t, err)
	assert.Len(t, nodes, 1)
	assert.Equal(t, "test2", nodes[0].Hostname)

	// Several matched IDs, but node ID is still filtered out
	nodes, err = db.ListPeers(1, types.NodeIDs{1, 2, 3}...)
	require.NoError(t, err)
	assert.Len(t, nodes, 1)
	assert.Equal(t, "test2", nodes[0].Hostname)
}

func TestListNodes(t *testing.T) {
	// Setup test database
	db, err := newSQLiteTestDB()
	if err != nil {
		t.Fatalf("creating db: %s", err)
	}

	user, err := db.CreateUser(types.User{Name: "test"})
	require.NoError(t, err)

	user2, err := db.CreateUser(types.User{Name: "user2"})
	require.NoError(t, err)

	node1 := types.Node{
		ID:             0,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "test1",
		UserID:         &user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		Hostinfo:       &tailcfg.Hostinfo{},
	}

	node2 := types.Node{
		ID:             0,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "test2",
		UserID:         &user2.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		Hostinfo:       &tailcfg.Hostinfo{},
	}

	err = db.DB.Save(&node1).Error
	require.NoError(t, err)

	err = db.DB.Save(&node2).Error
	require.NoError(t, err)

	err = db.DB.Transaction(func(tx *gorm.DB) error {
		_, err := RegisterNodeForTest(tx, node1, nil, nil)
		if err != nil {
			return err
		}

		_, err = RegisterNodeForTest(tx, node2, nil, nil)

		return err
	})
	require.NoError(t, err)

	nodes, err := db.ListNodes()
	require.NoError(t, err)

	assert.Len(t, nodes, 2)

	// No parameter means no filter, should return all nodes
	nodes, err = db.ListNodes()
	require.NoError(t, err)
	assert.Len(t, nodes, 2)
	assert.Equal(t, "test1", nodes[0].Hostname)
	assert.Equal(t, "test2", nodes[1].Hostname)

	// Empty node list should return all nodes
	nodes, err = db.ListNodes(types.NodeIDs{}...)
	require.NoError(t, err)
	assert.Len(t, nodes, 2)
	assert.Equal(t, "test1", nodes[0].Hostname)
	assert.Equal(t, "test2", nodes[1].Hostname)

	// No match in IDs should return empty list and no error
	nodes, err = db.ListNodes(types.NodeIDs{3, 4, 5}...)
	require.NoError(t, err)
	assert.Empty(t, nodes)

	// Partial match in IDs
	nodes, err = db.ListNodes(types.NodeIDs{2, 3}...)
	require.NoError(t, err)
	assert.Len(t, nodes, 1)
	assert.Equal(t, "test2", nodes[0].Hostname)

	// Several matched IDs
	nodes, err = db.ListNodes(types.NodeIDs{1, 2, 3}...)
	require.NoError(t, err)
	assert.Len(t, nodes, 2)
	assert.Equal(t, "test1", nodes[0].Hostname)
	assert.Equal(t, "test2", nodes[1].Hostname)
}
