package db

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/puzpuzpuz/xsync/v3"
	"gopkg.in/check.v1"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func (s *Suite) TestGetNode(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.getNode("test", "testnode")
	c.Assert(err, check.NotNil)

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()
	pakID := uint(pak.ID)

	node := &types.Node{
		ID:             0,
		MachineKey:     machineKey.Public(),
		NodeKey:        nodeKey.Public(),
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
	}
	trx := db.DB.Save(node)
	c.Assert(trx.Error, check.IsNil)

	_, err = db.getNode("test", "testnode")
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetNodeByID(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNodeByID(0)
	c.Assert(err, check.NotNil)

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()

	pakID := uint(pak.ID)
	node := types.Node{
		ID:             0,
		MachineKey:     machineKey.Public(),
		NodeKey:        nodeKey.Public(),
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
	}
	trx := db.DB.Save(&node)
	c.Assert(trx.Error, check.IsNil)

	_, err = db.GetNodeByID(0)
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetNodeByAnyNodeKey(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNodeByID(0)
	c.Assert(err, check.NotNil)

	nodeKey := key.NewNode()
	oldNodeKey := key.NewNode()

	machineKey := key.NewMachine()

	pakID := uint(pak.ID)
	node := types.Node{
		ID:             0,
		MachineKey:     machineKey.Public(),
		NodeKey:        nodeKey.Public(),
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
	}
	trx := db.DB.Save(&node)
	c.Assert(trx.Error, check.IsNil)

	_, err = db.GetNodeByAnyKey(machineKey.Public(), nodeKey.Public(), oldNodeKey.Public())
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestHardDeleteNode(c *check.C) {
	user, err := db.CreateUser("test")
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

	_, err = db.getNode(user.Name, "testnode3")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestListPeers(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNodeByID(0)
	c.Assert(err, check.NotNil)

	pakID := uint(pak.ID)
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
			AuthKeyID:      &pakID,
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
		user, err := db.CreateUser(name)
		c.Assert(err, check.IsNil)
		pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
		c.Assert(err, check.IsNil)
		stor = append(stor, base{user, pak})
	}

	_, err := db.GetNodeByID(0)
	c.Assert(err, check.NotNil)

	for index := 0; index <= 10; index++ {
		nodeKey := key.NewNode()
		machineKey := key.NewMachine()
		pakID := uint(stor[index%2].key.ID)

		v4 := netip.MustParseAddr(fmt.Sprintf("100.64.0.%v", strconv.Itoa(index+1)))
		node := types.Node{
			ID:             types.NodeID(index),
			MachineKey:     machineKey.Public(),
			NodeKey:        nodeKey.Public(),
			IPv4:           &v4,
			Hostname:       "testnode" + strconv.Itoa(index),
			UserID:         stor[index%2].user.ID,
			RegisterMethod: util.RegisterMethodAuthKey,
			AuthKeyID:      &pakID,
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
	c.Assert(err, check.IsNil)

	testNode, err := db.GetNodeByID(2)
	c.Logf("Node(%v), user: %v", testNode.Hostname, testNode.User)
	c.Assert(err, check.IsNil)

	adminPeers, err := db.ListPeers(adminNode.ID)
	c.Assert(err, check.IsNil)

	testPeers, err := db.ListPeers(testNode.ID)
	c.Assert(err, check.IsNil)

	adminRules, _, err := policy.GenerateFilterAndSSHRulesForTests(aclPolicy, adminNode, adminPeers)
	c.Assert(err, check.IsNil)

	testRules, _, err := policy.GenerateFilterAndSSHRulesForTests(aclPolicy, testNode, testPeers)
	c.Assert(err, check.IsNil)

	peersOfAdminNode := policy.FilterNodesByACL(adminNode, adminPeers, adminRules)
	peersOfTestNode := policy.FilterNodesByACL(testNode, testPeers, testRules)

	c.Log(peersOfTestNode)
	c.Assert(len(peersOfTestNode), check.Equals, 9)
	c.Assert(peersOfTestNode[0].Hostname, check.Equals, "testnode1")
	c.Assert(peersOfTestNode[1].Hostname, check.Equals, "testnode3")
	c.Assert(peersOfTestNode[3].Hostname, check.Equals, "testnode5")

	c.Log(peersOfAdminNode)
	c.Assert(len(peersOfAdminNode), check.Equals, 9)
	c.Assert(peersOfAdminNode[0].Hostname, check.Equals, "testnode2")
	c.Assert(peersOfAdminNode[2].Hostname, check.Equals, "testnode4")
	c.Assert(peersOfAdminNode[5].Hostname, check.Equals, "testnode7")
}

func (s *Suite) TestExpireNode(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.getNode("test", "testnode")
	c.Assert(err, check.NotNil)

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()
	pakID := uint(pak.ID)

	node := &types.Node{
		ID:             0,
		MachineKey:     machineKey.Public(),
		NodeKey:        nodeKey.Public(),
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
		Expiry:         &time.Time{},
	}
	db.DB.Save(node)

	nodeFromDB, err := db.getNode("test", "testnode")
	c.Assert(err, check.IsNil)
	c.Assert(nodeFromDB, check.NotNil)

	c.Assert(nodeFromDB.IsExpired(), check.Equals, false)

	now := time.Now()
	err = db.NodeSetExpiry(nodeFromDB.ID, now)
	c.Assert(err, check.IsNil)

	nodeFromDB, err = db.getNode("test", "testnode")
	c.Assert(err, check.IsNil)

	c.Assert(nodeFromDB.IsExpired(), check.Equals, true)
}

func (s *Suite) TestGenerateGivenName(c *check.C) {
	user1, err := db.CreateUser("user-1")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user1.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.getNode("user-1", "testnode")
	c.Assert(err, check.NotNil)

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()

	machineKey2 := key.NewMachine()

	pakID := uint(pak.ID)
	node := &types.Node{
		ID:             0,
		MachineKey:     machineKey.Public(),
		NodeKey:        nodeKey.Public(),
		Hostname:       "hostname-1",
		GivenName:      "hostname-1",
		UserID:         user1.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
	}

	trx := db.DB.Save(node)
	c.Assert(trx.Error, check.IsNil)

	givenName, err := db.GenerateGivenName(machineKey2.Public(), "hostname-2")
	comment := check.Commentf("Same user, unique nodes, unique hostnames, no conflict")
	c.Assert(err, check.IsNil, comment)
	c.Assert(givenName, check.Equals, "hostname-2", comment)

	givenName, err = db.GenerateGivenName(machineKey.Public(), "hostname-1")
	comment = check.Commentf("Same user, same node, same hostname, no conflict")
	c.Assert(err, check.IsNil, comment)
	c.Assert(givenName, check.Equals, "hostname-1", comment)

	givenName, err = db.GenerateGivenName(machineKey2.Public(), "hostname-1")
	comment = check.Commentf("Same user, unique nodes, same hostname, conflict")
	c.Assert(err, check.IsNil, comment)
	c.Assert(givenName, check.Matches, fmt.Sprintf("^hostname-1-[a-z0-9]{%d}$", NodeGivenNameHashLength), comment)
}

func (s *Suite) TestSetTags(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.getNode("test", "testnode")
	c.Assert(err, check.NotNil)

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()

	pakID := uint(pak.ID)
	node := &types.Node{
		ID:             0,
		MachineKey:     machineKey.Public(),
		NodeKey:        nodeKey.Public(),
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
	}

	trx := db.DB.Save(node)
	c.Assert(trx.Error, check.IsNil)

	// assign simple tags
	sTags := []string{"tag:test", "tag:foo"}
	err = db.SetTags(node.ID, sTags)
	c.Assert(err, check.IsNil)
	node, err = db.getNode("test", "testnode")
	c.Assert(err, check.IsNil)
	c.Assert(node.ForcedTags, check.DeepEquals, types.StringList(sTags))

	// assign duplicat tags, expect no errors but no doubles in DB
	eTags := []string{"tag:bar", "tag:test", "tag:unknown", "tag:test"}
	err = db.SetTags(node.ID, eTags)
	c.Assert(err, check.IsNil)
	node, err = db.getNode("test", "testnode")
	c.Assert(err, check.IsNil)
	c.Assert(
		node.ForcedTags,
		check.DeepEquals,
		types.StringList([]string{"tag:bar", "tag:test", "tag:unknown"}),
	)

	// test removing tags
	err = db.SetTags(node.ID, []string{})
	c.Assert(err, check.IsNil)
	node, err = db.getNode("test", "testnode")
	c.Assert(err, check.IsNil)
	c.Assert(node.ForcedTags, check.DeepEquals, types.StringList([]string{}))
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

func (s *Suite) TestAutoApproveRoutes(c *check.C) {
	acl := []byte(`
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
}
	`)

	pol, err := policy.LoadACLPolicyFromBytes(acl, "hujson")
	c.Assert(err, check.IsNil)
	c.Assert(pol, check.NotNil)

	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()

	defaultRouteV4 := netip.MustParsePrefix("0.0.0.0/0")
	defaultRouteV6 := netip.MustParsePrefix("::/0")
	route1 := netip.MustParsePrefix("10.10.0.0/16")
	// Check if a subprefix of an autoapproved route is approved
	route2 := netip.MustParsePrefix("10.11.0.0/24")

	v4 := netip.MustParseAddr("100.64.0.1")
	pakID := uint(pak.ID)
	node := types.Node{
		ID:             0,
		MachineKey:     machineKey.Public(),
		NodeKey:        nodeKey.Public(),
		Hostname:       "test",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
		Hostinfo: &tailcfg.Hostinfo{
			RequestTags: []string{"tag:exit"},
			RoutableIPs: []netip.Prefix{defaultRouteV4, defaultRouteV6, route1, route2},
		},
		IPv4: &v4,
	}

	trx := db.DB.Save(&node)
	c.Assert(trx.Error, check.IsNil)

	sendUpdate, err := db.SaveNodeRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(sendUpdate, check.Equals, false)

	node0ByID, err := db.GetNodeByID(0)
	c.Assert(err, check.IsNil)

	// TODO(kradalby): Check state update
	err = db.EnableAutoApprovedRoutes(pol, node0ByID)
	c.Assert(err, check.IsNil)

	enabledRoutes, err := db.GetEnabledRoutes(node0ByID)
	c.Assert(err, check.IsNil)
	c.Assert(enabledRoutes, check.HasLen, 4)
}
