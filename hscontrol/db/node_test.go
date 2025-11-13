package db

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/netip"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/check.v1"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/ptr"
)

func (s *Suite) TestGetNode(c *check.C) {
	user := db.CreateUserForTest("test")

	_, err := db.getNode(types.UserID(user.ID), "testnode")
	c.Assert(err, check.NotNil)

	node := db.CreateNodeForTest(user, "testnode")

	_, err = db.getNode(types.UserID(user.ID), "testnode")
	c.Assert(err, check.IsNil)
	c.Assert(node.Hostname, check.Equals, "testnode")
}

func (s *Suite) TestGetNodeByID(c *check.C) {
	user := db.CreateUserForTest("test")

	_, err := db.GetNodeByID(0)
	c.Assert(err, check.NotNil)

	node := db.CreateNodeForTest(user, "testnode")

	retrievedNode, err := db.GetNodeByID(node.ID)
	c.Assert(err, check.IsNil)
	c.Assert(retrievedNode.Hostname, check.Equals, "testnode")
}

func (s *Suite) TestHardDeleteNode(c *check.C) {
	user := db.CreateUserForTest("test")
	node := db.CreateNodeForTest(user, "testnode3")

	err := db.DeleteNode(node)
	c.Assert(err, check.IsNil)

	_, err = db.getNode(types.UserID(user.ID), "testnode3")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestListPeers(c *check.C) {
	user := db.CreateUserForTest("test")

	_, err := db.GetNodeByID(0)
	c.Assert(err, check.NotNil)

	nodes := db.CreateNodesForTest(user, 11, "testnode")

	firstNode := nodes[0]
	peersOfFirstNode, err := db.ListPeers(firstNode.ID)
	c.Assert(err, check.IsNil)

	c.Assert(len(peersOfFirstNode), check.Equals, 10)
	c.Assert(peersOfFirstNode[0].Hostname, check.Equals, "testnode-1")
	c.Assert(peersOfFirstNode[5].Hostname, check.Equals, "testnode-6")
	c.Assert(peersOfFirstNode[9].Hostname, check.Equals, "testnode-10")
}

func (s *Suite) TestExpireNode(c *check.C) {
	user, err := db.CreateUser(types.User{Name: "test"})
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.getNode(types.UserID(user.ID), "testnode")
	c.Assert(err, check.NotNil)

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()

	node := &types.Node{
		ID:             0,
		MachineKey:     machineKey.Public(),
		NodeKey:        nodeKey.Public(),
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      ptr.To(pak.ID),
		Expiry:         &time.Time{},
	}
	db.DB.Save(node)

	nodeFromDB, err := db.getNode(types.UserID(user.ID), "testnode")
	c.Assert(err, check.IsNil)
	c.Assert(nodeFromDB, check.NotNil)

	c.Assert(nodeFromDB.IsExpired(), check.Equals, false)

	now := time.Now()
	err = db.NodeSetExpiry(nodeFromDB.ID, now)
	c.Assert(err, check.IsNil)

	nodeFromDB, err = db.getNode(types.UserID(user.ID), "testnode")
	c.Assert(err, check.IsNil)

	c.Assert(nodeFromDB.IsExpired(), check.Equals, true)
}

func (s *Suite) TestSetTags(c *check.C) {
	user, err := db.CreateUser(types.User{Name: "test"})
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.getNode(types.UserID(user.ID), "testnode")
	c.Assert(err, check.NotNil)

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()

	node := &types.Node{
		ID:             0,
		MachineKey:     machineKey.Public(),
		NodeKey:        nodeKey.Public(),
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      ptr.To(pak.ID),
	}

	trx := db.DB.Save(node)
	c.Assert(trx.Error, check.IsNil)

	// assign simple tags
	sTags := []string{"tag:test", "tag:foo"}
	err = db.SetTags(node.ID, sTags)
	c.Assert(err, check.IsNil)
	node, err = db.getNode(types.UserID(user.ID), "testnode")
	c.Assert(err, check.IsNil)
	c.Assert(node.ForcedTags, check.DeepEquals, sTags)

	// assign duplicate tags, expect no errors but no doubles in DB
	eTags := []string{"tag:bar", "tag:test", "tag:unknown", "tag:test"}
	err = db.SetTags(node.ID, eTags)
	c.Assert(err, check.IsNil)
	node, err = db.getNode(types.UserID(user.ID), "testnode")
	c.Assert(err, check.IsNil)
	c.Assert(
		node.ForcedTags,
		check.DeepEquals,
		[]string{"tag:bar", "tag:test", "tag:unknown"},
	)

	// test removing tags
	err = db.SetTags(node.ID, []string{})
	c.Assert(err, check.IsNil)
	node, err = db.getNode(types.UserID(user.ID), "testnode")
	c.Assert(err, check.IsNil)
	c.Assert(node.ForcedTags, check.DeepEquals, []string{})
}

func TestHeadscale_generateGivenName(t *testing.T) {
	type args struct {
		suppliedName string
		randomSuffix bool
	}
	tests := []struct {
		name    string
		args    args
		want    *regexp.Regexp
		wantErr bool
	}{
		{
			name: "simple node name generation",
			args: args{
				suppliedName: "testnode",
				randomSuffix: false,
			},
			want:    regexp.MustCompile("^testnode$"),
			wantErr: false,
		},
		{
			name: "UPPERCASE node name generation",
			args: args{
				suppliedName: "TestNode",
				randomSuffix: false,
			},
			want:    regexp.MustCompile("^testnode$"),
			wantErr: false,
		},
		{
			name: "node name with 53 chars",
			args: args{
				suppliedName: "testmaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaachine",
				randomSuffix: false,
			},
			want:    regexp.MustCompile("^testmaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaachine$"),
			wantErr: false,
		},
		{
			name: "node name with 63 chars",
			args: args{
				suppliedName: "nodeeeeeee12345678901234567890123456789012345678901234567890123",
				randomSuffix: false,
			},
			want:    regexp.MustCompile("^nodeeeeeee12345678901234567890123456789012345678901234567890123$"),
			wantErr: false,
		},
		{
			name: "node name with 64 chars",
			args: args{
				suppliedName: "nodeeeeeee123456789012345678901234567890123456789012345678901234",
				randomSuffix: false,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "node name with 73 chars",
			args: args{
				suppliedName: "nodeeeeeee123456789012345678901234567890123456789012345678901234567890123",
				randomSuffix: false,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "node name with random suffix",
			args: args{
				suppliedName: "test",
				randomSuffix: true,
			},
			want:    regexp.MustCompile(fmt.Sprintf("^test-[a-z0-9]{%d}$", NodeGivenNameHashLength)),
			wantErr: false,
		},
		{
			name: "node name with 63 chars with random suffix",
			args: args{
				suppliedName: "nodeeee12345678901234567890123456789012345678901234567890123",
				randomSuffix: true,
			},
			want:    regexp.MustCompile(fmt.Sprintf("^nodeeee1234567890123456789012345678901234567890123456-[a-z0-9]{%d}$", NodeGivenNameHashLength)),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generateGivenName(tt.args.suppliedName, tt.args.randomSuffix)
			if (err != nil) != tt.wantErr {
				t.Errorf(
					"Headscale.GenerateGivenName() error = %v, wantErr %v",
					err,
					tt.wantErr,
				)

				return
			}

			if tt.want != nil && !tt.want.MatchString(got) {
				t.Errorf(
					"Headscale.GenerateGivenName() = %v, does not match %v",
					tt.want,
					got,
				)
			}

			if len(got) > util.LabelHostnameLength {
				t.Errorf(
					"Headscale.GenerateGivenName() = %v is larger than allowed DNS segment %d",
					got,
					util.LabelHostnameLength,
				)
			}
		})
	}
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
					UserID:         user.ID,
					RegisterMethod: util.RegisterMethodAuthKey,
					Hostinfo: &tailcfg.Hostinfo{
						RoutableIPs: tt.routes,
					},
					IPv4: ptr.To(netip.MustParseAddr("100.64.0.1")),
				}

				err = adb.DB.Save(&node).Error
				require.NoError(t, err)

				nodeTagged := types.Node{
					ID:             2,
					MachineKey:     key.NewMachine().Public(),
					NodeKey:        key.NewNode().Public(),
					Hostname:       "taggednode",
					UserID:         taggedUser.ID,
					RegisterMethod: util.RegisterMethodAuthKey,
					Hostinfo: &tailcfg.Hostinfo{
						RoutableIPs: tt.routes,
					},
					ForcedTags: []string{"tag:exit"},
					IPv4:       ptr.To(netip.MustParseAddr("100.64.0.2")),
				}

				err = adb.DB.Save(&nodeTagged).Error
				require.NoError(t, err)

				users, err := adb.ListUsers()
				assert.NoError(t, err)

				nodes, err := adb.ListNodes()
				assert.NoError(t, err)

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

	e := NewEphemeralGarbageCollector(func(ni types.NodeID) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, ni)
	})
	go e.Start()

	go e.Schedule(1, 1*time.Second)
	go e.Schedule(2, 2*time.Second)
	go e.Schedule(3, 3*time.Second)
	go e.Schedule(4, 4*time.Second)

	time.Sleep(time.Second)
	go e.Cancel(2)
	go e.Cancel(4)

	time.Sleep(6 * time.Second)

	e.Close()

	mu.Lock()
	defer mu.Unlock()

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("wrong nodes deleted, unexpected result (-want +got):\n%s", diff)
	}
}

func TestEphemeralGarbageCollectorLoads(t *testing.T) {
	var got []types.NodeID
	var mu sync.Mutex

	want := 1000

	e := NewEphemeralGarbageCollector(func(ni types.NodeID) {
		mu.Lock()
		defer mu.Unlock()

		time.Sleep(time.Duration(generateRandomNumber(t, 3)) * time.Millisecond)
		got = append(got, ni)
	})
	go e.Start()

	for i := range want {
		go e.Schedule(types.NodeID(i), 1*time.Second)
	}

	time.Sleep(10 * time.Second)

	e.Close()

	mu.Lock()
	defer mu.Unlock()

	if len(got) != want {
		t.Errorf("expected %d, got %d", want, len(got))
	}
}

func generateRandomNumber(t *testing.T, max int64) int64 {
	t.Helper()
	maxB := big.NewInt(max)
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

	pak, err := db.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, nil)
	require.NoError(t, err)

	pakEph, err := db.CreatePreAuthKey(types.UserID(user.ID), false, true, nil, nil)
	require.NoError(t, err)

	node := types.Node{
		ID:             0,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "test",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      ptr.To(pak.ID),
	}

	nodeEph := types.Node{
		ID:             0,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "ephemeral",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      ptr.To(pakEph.ID),
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

func TestNodeNaming(t *testing.T) {
	db, err := newSQLiteTestDB()
	if err != nil {
		t.Fatalf("creating db: %s", err)
	}

	user, err := db.CreateUser(types.User{Name: "test"})
	require.NoError(t, err)

	user2, err := db.CreateUser(types.User{Name: "user2"})
	require.NoError(t, err)

	node := types.Node{
		ID:             0,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "test",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		Hostinfo:       &tailcfg.Hostinfo{},
	}

	node2 := types.Node{
		ID:             0,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "test",
		UserID:         user2.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		Hostinfo:       &tailcfg.Hostinfo{},
	}

	// Using non-ASCII characters in the hostname can
	// break your network, so they should be replaced when registering
	// a node.
	// https://github.com/juanfont/headscale/issues/2343
	nodeInvalidHostname := types.Node{
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "我的电脑",
		UserID:         user2.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
	}

	nodeShortHostname := types.Node{
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "a",
		UserID:         user2.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
	}

	err = db.DB.Save(&node).Error
	require.NoError(t, err)

	err = db.DB.Save(&node2).Error
	require.NoError(t, err)

	err = db.DB.Transaction(func(tx *gorm.DB) error {
		_, err := RegisterNodeForTest(tx, node, nil, nil)
		if err != nil {
			return err
		}
		_, err = RegisterNodeForTest(tx, node2, nil, nil)
		if err != nil {
			return err
		}
		_, err = RegisterNodeForTest(tx, nodeInvalidHostname, ptr.To(mpp("100.64.0.66/32").Addr()), nil)
		_, err = RegisterNodeForTest(tx, nodeShortHostname, ptr.To(mpp("100.64.0.67/32").Addr()), nil)
		return err
	})
	require.NoError(t, err)

	nodes, err := db.ListNodes()
	require.NoError(t, err)

	assert.Len(t, nodes, 4)

	t.Logf("node1 %s %s", nodes[0].Hostname, nodes[0].GivenName)
	t.Logf("node2 %s %s", nodes[1].Hostname, nodes[1].GivenName)
	t.Logf("node3 %s %s", nodes[2].Hostname, nodes[2].GivenName)
	t.Logf("node4 %s %s", nodes[3].Hostname, nodes[3].GivenName)

	assert.Equal(t, nodes[0].Hostname, nodes[0].GivenName)
	assert.NotEqual(t, nodes[1].Hostname, nodes[1].GivenName)
	assert.Equal(t, nodes[0].Hostname, nodes[1].Hostname)
	assert.NotEqual(t, nodes[0].Hostname, nodes[1].GivenName)
	assert.Contains(t, nodes[1].GivenName, nodes[0].Hostname)
	assert.Equal(t, nodes[0].GivenName, nodes[1].Hostname)
	assert.Len(t, nodes[0].Hostname, 4)
	assert.Len(t, nodes[1].Hostname, 4)
	assert.Len(t, nodes[0].GivenName, 4)
	assert.Len(t, nodes[1].GivenName, 13)
	assert.Contains(t, nodes[2].Hostname, "invalid-") // invalid chars
	assert.Contains(t, nodes[2].GivenName, "invalid-")
	assert.Contains(t, nodes[3].Hostname, "invalid-") // too short
	assert.Contains(t, nodes[3].GivenName, "invalid-")

	// Nodes can be renamed to a unique name
	err = db.Write(func(tx *gorm.DB) error {
		return RenameNode(tx, nodes[0].ID, "newname")
	})
	require.NoError(t, err)

	nodes, err = db.ListNodes()
	require.NoError(t, err)
	assert.Len(t, nodes, 4)
	assert.Equal(t, "test", nodes[0].Hostname)
	assert.Equal(t, "newname", nodes[0].GivenName)

	// Nodes can reuse name that is no longer used
	err = db.Write(func(tx *gorm.DB) error {
		return RenameNode(tx, nodes[1].ID, "test")
	})
	require.NoError(t, err)

	nodes, err = db.ListNodes()
	require.NoError(t, err)
	assert.Len(t, nodes, 4)
	assert.Equal(t, "test", nodes[0].Hostname)
	assert.Equal(t, "newname", nodes[0].GivenName)
	assert.Equal(t, "test", nodes[1].GivenName)

	// Nodes cannot be renamed to used names
	err = db.Write(func(tx *gorm.DB) error {
		return RenameNode(tx, nodes[0].ID, "test")
	})
	assert.ErrorContains(t, err, "name is not unique")

	// Rename invalid chars
	err = db.Write(func(tx *gorm.DB) error {
		return RenameNode(tx, nodes[2].ID, "我的电脑")
	})
	assert.ErrorContains(t, err, "invalid characters")

	// Rename too short
	err = db.Write(func(tx *gorm.DB) error {
		return RenameNode(tx, nodes[3].ID, "a")
	})
	assert.ErrorContains(t, err, "at least 2 characters")

	// Rename with emoji
	err = db.Write(func(tx *gorm.DB) error {
		return RenameNode(tx, nodes[0].ID, "hostname-with-💩")
	})
	assert.ErrorContains(t, err, "invalid characters")

	// Rename with only emoji
	err = db.Write(func(tx *gorm.DB) error {
		return RenameNode(tx, nodes[0].ID, "🚀")
	})
	assert.ErrorContains(t, err, "invalid characters")
}

func TestRenameNodeComprehensive(t *testing.T) {
	db, err := newSQLiteTestDB()
	if err != nil {
		t.Fatalf("creating db: %s", err)
	}

	user, err := db.CreateUser(types.User{Name: "test"})
	require.NoError(t, err)

	node := types.Node{
		ID:             0,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		Hostinfo:       &tailcfg.Hostinfo{},
	}

	err = db.DB.Save(&node).Error
	require.NoError(t, err)

	err = db.DB.Transaction(func(tx *gorm.DB) error {
		_, err := RegisterNodeForTest(tx, node, nil, nil)
		return err
	})
	require.NoError(t, err)

	nodes, err := db.ListNodes()
	require.NoError(t, err)
	assert.Len(t, nodes, 1)

	tests := []struct {
		name    string
		newName string
		wantErr string
	}{
		{
			name:    "uppercase_rejected",
			newName: "User2-Host",
			wantErr: "must be lowercase",
		},
		{
			name:    "underscore_rejected",
			newName: "test_node",
			wantErr: "invalid characters",
		},
		{
			name:    "at_sign_uppercase_rejected",
			newName: "Test@Host",
			wantErr: "must be lowercase",
		},
		{
			name:    "at_sign_rejected",
			newName: "test@host",
			wantErr: "invalid characters",
		},
		{
			name:    "chinese_chars_with_dash_rejected",
			newName: "server-北京-01",
			wantErr: "invalid characters",
		},
		{
			name:    "chinese_only_rejected",
			newName: "我的电脑",
			wantErr: "invalid characters",
		},
		{
			name:    "emoji_with_text_rejected",
			newName: "laptop-🚀",
			wantErr: "invalid characters",
		},
		{
			name:    "mixed_chinese_emoji_rejected",
			newName: "测试💻机器",
			wantErr: "invalid characters",
		},
		{
			name:    "only_emojis_rejected",
			newName: "🎉🎊",
			wantErr: "invalid characters",
		},
		{
			name:    "only_at_signs_rejected",
			newName: "@@@",
			wantErr: "invalid characters",
		},
		{
			name:    "starts_with_dash_rejected",
			newName: "-test",
			wantErr: "cannot start or end with a hyphen",
		},
		{
			name:    "ends_with_dash_rejected",
			newName: "test-",
			wantErr: "cannot start or end with a hyphen",
		},
		{
			name:    "too_long_hostname_rejected",
			newName: "this-is-a-very-long-hostname-that-exceeds-sixty-three-characters-limit",
			wantErr: "must not exceed 63 characters",
		},
		{
			name:    "too_short_hostname_rejected",
			newName: "a",
			wantErr: "at least 2 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := db.Write(func(tx *gorm.DB) error {
				return RenameNode(tx, nodes[0].ID, tt.newName)
			})
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
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
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		Hostinfo:       &tailcfg.Hostinfo{},
	}

	node2 := types.Node{
		ID:             0,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "test2",
		UserID:         user2.ID,
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
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		Hostinfo:       &tailcfg.Hostinfo{},
	}

	node2 := types.Node{
		ID:             0,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "test2",
		UserID:         user2.ID,
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
