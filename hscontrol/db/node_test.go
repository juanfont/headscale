package db

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/netip"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/puzpuzpuz/xsync/v3"
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

	_, err = db.getNode(types.UserID(user.ID), "testnode")
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetNodeByID(c *check.C) {
	user, err := db.CreateUser(types.User{Name: "test"})
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNodeByID(0)
	c.Assert(err, check.NotNil)

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()

	node := types.Node{
		ID:             0,
		MachineKey:     machineKey.Public(),
		NodeKey:        nodeKey.Public(),
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      ptr.To(pak.ID),
	}
	trx := db.DB.Save(&node)
	c.Assert(trx.Error, check.IsNil)

	_, err = db.GetNodeByID(0)
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetNodeByAnyNodeKey(c *check.C) {
	user, err := db.CreateUser(types.User{Name: "test"})
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNodeByID(0)
	c.Assert(err, check.NotNil)

	nodeKey := key.NewNode()
	oldNodeKey := key.NewNode()

	machineKey := key.NewMachine()

	node := types.Node{
		ID:             0,
		MachineKey:     machineKey.Public(),
		NodeKey:        nodeKey.Public(),
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      ptr.To(pak.ID),
	}
	trx := db.DB.Save(&node)
	c.Assert(trx.Error, check.IsNil)

	_, err = db.GetNodeByAnyKey(machineKey.Public(), nodeKey.Public(), oldNodeKey.Public())
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestHardDeleteNode(c *check.C) {
	user, err := db.CreateUser(types.User{Name: "test"})
	c.Assert(err, check.IsNil)

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()

	node := types.Node{
		ID:             0,
		MachineKey:     machineKey.Public(),
		NodeKey:        nodeKey.Public(),
		Hostname:       "testnode3",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
	}
	trx := db.DB.Save(&node)
	c.Assert(trx.Error, check.IsNil)

	_, err = db.DeleteNode(&node, xsync.NewMapOf[types.NodeID, bool]())
	c.Assert(err, check.IsNil)

	_, err = db.getNode(types.UserID(user.ID), "testnode3")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestListPeers(c *check.C) {
	user, err := db.CreateUser(types.User{Name: "test"})
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNodeByID(0)
	c.Assert(err, check.NotNil)

	for index := 0; index <= 10; index++ {
		nodeKey := key.NewNode()
		machineKey := key.NewMachine()

		node := types.Node{
			ID:             types.NodeID(index),
			MachineKey:     machineKey.Public(),
			NodeKey:        nodeKey.Public(),
			Hostname:       "testnode" + strconv.Itoa(index),
			UserID:         user.ID,
			RegisterMethod: util.RegisterMethodAuthKey,
			AuthKeyID:      ptr.To(pak.ID),
		}
		trx := db.DB.Save(&node)
		c.Assert(trx.Error, check.IsNil)
	}

	node0ByID, err := db.GetNodeByID(0)
	c.Assert(err, check.IsNil)

	peersOfNode0, err := db.ListPeers(node0ByID.ID)
	c.Assert(err, check.IsNil)

	c.Assert(len(peersOfNode0), check.Equals, 9)
	c.Assert(peersOfNode0[0].Hostname, check.Equals, "testnode2")
	c.Assert(peersOfNode0[5].Hostname, check.Equals, "testnode7")
	c.Assert(peersOfNode0[8].Hostname, check.Equals, "testnode10")
}

func (s *Suite) TestGetACLFilteredPeers(c *check.C) {
	type base struct {
		user *types.User
		key  *types.PreAuthKey
	}

	stor := make([]base, 0)

	for _, name := range []string{"test", "admin"} {
		user, err := db.CreateUser(types.User{Name: name})
		c.Assert(err, check.IsNil)
		pak, err := db.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, nil)
		c.Assert(err, check.IsNil)
		stor = append(stor, base{user, pak})
	}

	_, err := db.GetNodeByID(0)
	c.Assert(err, check.NotNil)

	for index := 0; index <= 10; index++ {
		nodeKey := key.NewNode()
		machineKey := key.NewMachine()

		v4 := netip.MustParseAddr(fmt.Sprintf("100.64.0.%d", index+1))
		node := types.Node{
			ID:             types.NodeID(index),
			MachineKey:     machineKey.Public(),
			NodeKey:        nodeKey.Public(),
			IPv4:           &v4,
			Hostname:       "testnode" + strconv.Itoa(index),
			UserID:         stor[index%2].user.ID,
			RegisterMethod: util.RegisterMethodAuthKey,
			AuthKeyID:      ptr.To(stor[index%2].key.ID),
		}
		trx := db.DB.Save(&node)
		c.Assert(trx.Error, check.IsNil)
	}

	aclPolicy := &policy.ACLPolicy{
		Groups: map[string][]string{
			"group:test": {"admin"},
		},
		Hosts:     map[string]netip.Prefix{},
		TagOwners: map[string][]string{},
		ACLs: []policy.ACL{
			{
				Action:       "accept",
				Sources:      []string{"admin"},
				Destinations: []string{"*:*"},
			},
			{
				Action:       "accept",
				Sources:      []string{"test"},
				Destinations: []string{"test:*"},
			},
		},
		Tests: []policy.ACLTest{},
	}

	adminNode, err := db.GetNodeByID(1)
	c.Logf("Node(%v), user: %v", adminNode.Hostname, adminNode.User)
	c.Assert(adminNode.IPv4, check.NotNil)
	c.Assert(adminNode.IPv6, check.IsNil)
	c.Assert(err, check.IsNil)

	testNode, err := db.GetNodeByID(2)
	c.Logf("Node(%v), user: %v", testNode.Hostname, testNode.User)
	c.Assert(err, check.IsNil)

	adminPeers, err := db.ListPeers(adminNode.ID)
	c.Assert(err, check.IsNil)
	c.Assert(len(adminPeers), check.Equals, 9)

	testPeers, err := db.ListPeers(testNode.ID)
	c.Assert(err, check.IsNil)
	c.Assert(len(testPeers), check.Equals, 9)

	adminRules, _, err := policy.GenerateFilterAndSSHRulesForTests(aclPolicy, adminNode, adminPeers, []types.User{*stor[0].user, *stor[1].user})
	c.Assert(err, check.IsNil)

	testRules, _, err := policy.GenerateFilterAndSSHRulesForTests(aclPolicy, testNode, testPeers, []types.User{*stor[0].user, *stor[1].user})
	c.Assert(err, check.IsNil)

	peersOfAdminNode := policy.FilterNodesByACL(adminNode, adminPeers, adminRules)
	peersOfTestNode := policy.FilterNodesByACL(testNode, testPeers, testRules)
	c.Log(peersOfAdminNode)
	c.Log(peersOfTestNode)

	c.Assert(len(peersOfTestNode), check.Equals, 9)
	c.Assert(peersOfTestNode[0].Hostname, check.Equals, "testnode1")
	c.Assert(peersOfTestNode[1].Hostname, check.Equals, "testnode3")
	c.Assert(peersOfTestNode[3].Hostname, check.Equals, "testnode5")

	c.Assert(len(peersOfAdminNode), check.Equals, 9)
	c.Assert(peersOfAdminNode[0].Hostname, check.Equals, "testnode2")
	c.Assert(peersOfAdminNode[2].Hostname, check.Equals, "testnode4")
	c.Assert(peersOfAdminNode[5].Hostname, check.Equals, "testnode7")
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
		name   string
		acl    string
		routes []netip.Prefix
		want   []netip.Prefix
	}{
		{
			name: "2068-approve-issue-sub",
			acl: `
{
	"groups": {
		"group:k8s": ["test"]
	},

	"acls": [
		{"action": "accept", "users": ["*"], "ports": ["*:*"]},
	],

	"autoApprovers": {
		"routes": {
			"10.42.0.0/16": ["test"],
		}
	}
}`,
			routes: []netip.Prefix{netip.MustParsePrefix("10.42.7.0/24")},
			want:   []netip.Prefix{netip.MustParsePrefix("10.42.7.0/24")},
		},
		{
			name: "2068-approve-issue-sub",
			acl: `
{
	"tagOwners": {
		"tag:exit": ["test"],
	},

	"groups": {
		"group:test": ["test"]
	},

	"acls": [
		{"action": "accept", "users": ["*"], "ports": ["*:*"]},
	],

	"autoApprovers": {
		"exitNode": ["tag:exit"],
		"routes": {
			"10.10.0.0/16": ["group:test"],
			"10.11.0.0/16": ["test"],
		}
	}
}`,
			routes: []netip.Prefix{
				tsaddr.AllIPv4(),
				tsaddr.AllIPv6(),
				netip.MustParsePrefix("10.10.0.0/16"),
				netip.MustParsePrefix("10.11.0.0/24"),
			},
			want: []netip.Prefix{
				tsaddr.AllIPv4(),
				netip.MustParsePrefix("10.10.0.0/16"),
				netip.MustParsePrefix("10.11.0.0/24"),
				tsaddr.AllIPv6(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adb, err := newSQLiteTestDB()
			require.NoError(t, err)
			pol, err := policy.LoadACLPolicyFromBytes([]byte(tt.acl))

			require.NoError(t, err)
			require.NotNil(t, pol)

			user, err := adb.CreateUser(types.User{Name: "test"})
			require.NoError(t, err)

			pak, err := adb.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, nil)
			require.NoError(t, err)

			nodeKey := key.NewNode()
			machineKey := key.NewMachine()

			v4 := netip.MustParseAddr("100.64.0.1")
			node := types.Node{
				ID:             0,
				MachineKey:     machineKey.Public(),
				NodeKey:        nodeKey.Public(),
				Hostname:       "test",
				UserID:         user.ID,
				RegisterMethod: util.RegisterMethodAuthKey,
				AuthKeyID:      ptr.To(pak.ID),
				Hostinfo: &tailcfg.Hostinfo{
					RequestTags: []string{"tag:exit"},
					RoutableIPs: tt.routes,
				},
				IPv4: &v4,
			}

			trx := adb.DB.Save(&node)
			require.NoError(t, trx.Error)

			sendUpdate, err := adb.SaveNodeRoutes(&node)
			require.NoError(t, err)
			assert.False(t, sendUpdate)

			node0ByID, err := adb.GetNodeByID(0)
			require.NoError(t, err)

			users, err := adb.ListUsers()
			assert.NoError(t, err)

			nodes, err := adb.ListNodes()
			assert.NoError(t, err)

			pm, err := policy.NewPolicyManager([]byte(tt.acl), users, nodes)
			assert.NoError(t, err)

			// TODO(kradalby): Check state update
			err = adb.EnableAutoApprovedRoutes(pm, node0ByID)
			require.NoError(t, err)

			enabledRoutes, err := adb.GetEnabledRoutes(node0ByID)
			require.NoError(t, err)
			assert.Len(t, enabledRoutes, len(tt.want))

			tsaddr.SortPrefixes(enabledRoutes)

			if diff := cmp.Diff(tt.want, enabledRoutes, util.Comparers...); diff != "" {
				t.Errorf("unexpected enabled routes (-want +got):\n%s", diff)
			}
		})
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

	for i := 0; i < want; i++ {
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

func TestRenameNode(t *testing.T) {
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
	}

	node2 := types.Node{
		ID:             0,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "test",
		UserID:         user2.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
	}

	err = db.DB.Save(&node).Error
	require.NoError(t, err)

	err = db.DB.Save(&node2).Error
	require.NoError(t, err)

	err = db.DB.Transaction(func(tx *gorm.DB) error {
		_, err := RegisterNode(tx, node, nil, nil)
		if err != nil {
			return err
		}
		_, err = RegisterNode(tx, node2, nil, nil)
		return err
	})
	require.NoError(t, err)

	nodes, err := db.ListNodes()
	require.NoError(t, err)

	assert.Len(t, nodes, 2)

	t.Logf("node1 %s %s", nodes[0].Hostname, nodes[0].GivenName)
	t.Logf("node2 %s %s", nodes[1].Hostname, nodes[1].GivenName)

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

	// Nodes can be renamed to a unique name
	err = db.Write(func(tx *gorm.DB) error {
		return RenameNode(tx, nodes[0].ID, "newname")
	})
	require.NoError(t, err)

	nodes, err = db.ListNodes()
	require.NoError(t, err)
	assert.Len(t, nodes, 2)
	assert.Equal(t, "test", nodes[0].Hostname)
	assert.Equal(t, "newname", nodes[0].GivenName)

	// Nodes can reuse name that is no longer used
	err = db.Write(func(tx *gorm.DB) error {
		return RenameNode(tx, nodes[1].ID, "test")
	})
	require.NoError(t, err)

	nodes, err = db.ListNodes()
	require.NoError(t, err)
	assert.Len(t, nodes, 2)
	assert.Equal(t, "test", nodes[0].Hostname)
	assert.Equal(t, "newname", nodes[0].GivenName)
	assert.Equal(t, "test", nodes[1].GivenName)

	// Nodes cannot be renamed to used names
	err = db.Write(func(tx *gorm.DB) error {
		return RenameNode(tx, nodes[0].ID, "test")
	})
	assert.ErrorContains(t, err, "name is not unique")
}
