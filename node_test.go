package headscale

import (
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"gopkg.in/check.v1"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func (s *Suite) TestGetNode(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetNode("test", "testnode")
	c.Assert(err, check.NotNil)

	node := &Node{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(node)

	_, err = app.GetNode("test", "testnode")
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetNodeByID(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetNodeByID(0)
	c.Assert(err, check.NotNil)

	node := Node{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&node)

	_, err = app.GetNodeByID(0)
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetNodeByNodeKey(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetNodeByID(0)
	c.Assert(err, check.NotNil)

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()

	node := Node{
		ID:             0,
		MachineKey:     MachinePublicKeyStripPrefix(machineKey.Public()),
		NodeKey:        NodePublicKeyStripPrefix(nodeKey.Public()),
		DiscoKey:       "faa",
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&node)

	_, err = app.GetNodeByNodeKey(nodeKey.Public())
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetNodeByAnyNodeKey(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetNodeByID(0)
	c.Assert(err, check.NotNil)

	nodeKey := key.NewNode()
	oldNodeKey := key.NewNode()

	machineKey := key.NewMachine()

	node := Node{
		ID:             0,
		MachineKey:     MachinePublicKeyStripPrefix(machineKey.Public()),
		NodeKey:        NodePublicKeyStripPrefix(nodeKey.Public()),
		DiscoKey:       "faa",
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&node)

	_, err = app.GetNodeByAnyKey(machineKey.Public(), nodeKey.Public(), oldNodeKey.Public())
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestDeleteNode(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)
	node := Node{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(1),
	}
	app.db.Save(&node)

	err = app.DeleteNode(&node)
	c.Assert(err, check.IsNil)

	_, err = app.GetNode(user.Name, "testnode")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestHardDeleteNode(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)
	node := Node{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testnode3",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(1),
	}
	app.db.Save(&node)

	err = app.HardDeleteNode(&node)
	c.Assert(err, check.IsNil)

	_, err = app.GetNode(user.Name, "testnode3")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestListPeers(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetNodeByID(0)
	c.Assert(err, check.NotNil)

	for index := 0; index <= 10; index++ {
		node := Node{
			ID:             uint64(index),
			MachineKey:     "foo" + strconv.Itoa(index),
			NodeKey:        "bar" + strconv.Itoa(index),
			DiscoKey:       "faa" + strconv.Itoa(index),
			Hostname:       "testnode" + strconv.Itoa(index),
			UserID:         user.ID,
			RegisterMethod: RegisterMethodAuthKey,
			AuthKeyID:      uint(pak.ID),
		}
		app.db.Save(&node)
	}

	node0ByID, err := app.GetNodeByID(0)
	c.Assert(err, check.IsNil)

	peersOfNode0, err := app.ListPeers(node0ByID)
	c.Assert(err, check.IsNil)

	c.Assert(len(peersOfNode0), check.Equals, 9)
	c.Assert(peersOfNode0[0].Hostname, check.Equals, "testnode2")
	c.Assert(peersOfNode0[5].Hostname, check.Equals, "testnode7")
	c.Assert(peersOfNode0[8].Hostname, check.Equals, "testnode10")
}

func (s *Suite) TestGetACLFilteredPeers(c *check.C) {
	type base struct {
		user *User
		key  *PreAuthKey
	}

	stor := make([]base, 0)

	for _, name := range []string{"test", "admin"} {
		user, err := app.CreateUser(name)
		c.Assert(err, check.IsNil)
		pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
		c.Assert(err, check.IsNil)
		stor = append(stor, base{user, pak})
	}

	_, err := app.GetNodeByID(0)
	c.Assert(err, check.NotNil)

	for index := 0; index <= 10; index++ {
		node := Node{
			ID:         uint64(index),
			MachineKey: "foo" + strconv.Itoa(index),
			NodeKey:    "bar" + strconv.Itoa(index),
			DiscoKey:   "faa" + strconv.Itoa(index),
			IPAddresses: NodeAddresses{
				netip.MustParseAddr(fmt.Sprintf("100.64.0.%v", strconv.Itoa(index+1))),
			},
			Hostname:       "testnode" + strconv.Itoa(index),
			UserID:         stor[index%2].user.ID,
			RegisterMethod: RegisterMethodAuthKey,
			AuthKeyID:      uint(stor[index%2].key.ID),
		}
		app.db.Save(&node)
	}

	app.aclPolicy = &ACLPolicy{
		Groups: map[string][]string{
			"group:test": {"admin"},
		},
		Hosts:     map[string]netip.Prefix{},
		TagOwners: map[string][]string{},
		ACLs: []ACL{
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
		Tests: []ACLTest{},
	}

	err = app.UpdateACLRules()
	c.Assert(err, check.IsNil)

	adminNode, err := app.GetNodeByID(1)
	c.Logf("Node(%v), user: %v", adminNode.Hostname, adminNode.User)
	c.Assert(err, check.IsNil)

	testNode, err := app.GetNodeByID(2)
	c.Logf("Node(%v), user: %v", testNode.Hostname, testNode.User)
	c.Assert(err, check.IsNil)

	nodes, err := app.ListNodes()
	c.Assert(err, check.IsNil)

	peersOfTestNode := app.filterNodesByACL(testNode, nodes)
	peersOfAdminNode := app.filterNodesByACL(adminNode, nodes)

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
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetNode("test", "testnode")
	c.Assert(err, check.NotNil)

	node := &Node{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		Expiry:         &time.Time{},
	}
	app.db.Save(node)

	nodeFromDB, err := app.GetNode("test", "testnode")
	c.Assert(err, check.IsNil)
	c.Assert(nodeFromDB, check.NotNil)

	c.Assert(nodeFromDB.isExpired(), check.Equals, false)

	err = app.ExpireNode(nodeFromDB)
	c.Assert(err, check.IsNil)

	c.Assert(nodeFromDB.isExpired(), check.Equals, true)
}

func (s *Suite) TestSerdeAddressStrignSlice(c *check.C) {
	input := NodeAddresses([]netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	})
	serialized, err := input.Value()
	c.Assert(err, check.IsNil)
	if serial, ok := serialized.(string); ok {
		c.Assert(serial, check.Equals, "192.0.2.1,2001:db8::1")
	}

	var deserialized NodeAddresses
	err = deserialized.Scan(serialized)
	c.Assert(err, check.IsNil)

	c.Assert(len(deserialized), check.Equals, len(input))
	for i := range deserialized {
		c.Assert(deserialized[i], check.Equals, input[i])
	}
}

func (s *Suite) TestGenerateGivenName(c *check.C) {
	user1, err := app.CreateUser("user-1")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user1.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetNode("user-1", "testnode")
	c.Assert(err, check.NotNil)

	node := &Node{
		ID:             0,
		MachineKey:     "node-key-1",
		NodeKey:        "node-key-1",
		DiscoKey:       "disco-key-1",
		Hostname:       "hostname-1",
		GivenName:      "hostname-1",
		UserID:         user1.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(node)

	givenName, err := app.GenerateGivenName("node-key-2", "hostname-2")
	comment := check.Commentf("Same user, unique nodes, unique hostnames, no conflict")
	c.Assert(err, check.IsNil, comment)
	c.Assert(givenName, check.Equals, "hostname-2", comment)

	givenName, err = app.GenerateGivenName("node-key-1", "hostname-1")
	comment = check.Commentf("Same user, same node, same hostname, no conflict")
	c.Assert(err, check.IsNil, comment)
	c.Assert(givenName, check.Equals, "hostname-1", comment)

	givenName, err = app.GenerateGivenName("node-key-2", "hostname-1")
	comment = check.Commentf("Same user, unique nodes, same hostname, conflict")
	c.Assert(err, check.IsNil, comment)
	c.Assert(givenName, check.Matches, fmt.Sprintf("^hostname-1-[a-z0-9]{%d}$", NodeGivenNameHashLength), comment)

	givenName, err = app.GenerateGivenName("node-key-2", "hostname-1")
	comment = check.Commentf("Unique users, unique nodes, same hostname, conflict")
	c.Assert(err, check.IsNil, comment)
	c.Assert(givenName, check.Matches, fmt.Sprintf("^hostname-1-[a-z0-9]{%d}$", NodeGivenNameHashLength), comment)
}

func (s *Suite) TestSetTags(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetNode("test", "testnode")
	c.Assert(err, check.NotNil)

	node := &Node{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(node)

	// assign simple tags
	sTags := []string{"tag:test", "tag:foo"}
	err = app.SetTags(node, sTags)
	c.Assert(err, check.IsNil)
	node, err = app.GetNode("test", "testnode")
	c.Assert(err, check.IsNil)
	c.Assert(node.ForcedTags, check.DeepEquals, StringList(sTags))

	// assign duplicat tags, expect no errors but no doubles in DB
	eTags := []string{"tag:bar", "tag:test", "tag:unknown", "tag:test"}
	err = app.SetTags(node, eTags)
	c.Assert(err, check.IsNil)
	node, err = app.GetNode("test", "testnode")
	c.Assert(err, check.IsNil)
	c.Assert(
		node.ForcedTags,
		check.DeepEquals,
		StringList([]string{"tag:bar", "tag:test", "tag:unknown"}),
	)
}

func Test_getTags(t *testing.T) {
	type args struct {
		aclPolicy        *ACLPolicy
		node             Node
		stripEmailDomain bool
	}
	tests := []struct {
		name        string
		args        args
		wantInvalid []string
		wantValid   []string
	}{
		{
			name: "valid tag one node",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{
						"tag:valid": []string{"joe"},
					},
				},
				node: Node{
					User: User{
						Name: "joe",
					},
					HostInfo: HostInfo{
						RequestTags: []string{"tag:valid"},
					},
				},
				stripEmailDomain: false,
			},
			wantValid:   []string{"tag:valid"},
			wantInvalid: nil,
		},
		{
			name: "invalid tag and valid tag one node",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{
						"tag:valid": []string{"joe"},
					},
				},
				node: Node{
					User: User{
						Name: "joe",
					},
					HostInfo: HostInfo{
						RequestTags: []string{"tag:valid", "tag:invalid"},
					},
				},
				stripEmailDomain: false,
			},
			wantValid:   []string{"tag:valid"},
			wantInvalid: []string{"tag:invalid"},
		},
		{
			name: "multiple invalid and identical tags, should return only one invalid tag",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{
						"tag:valid": []string{"joe"},
					},
				},
				node: Node{
					User: User{
						Name: "joe",
					},
					HostInfo: HostInfo{
						RequestTags: []string{
							"tag:invalid",
							"tag:valid",
							"tag:invalid",
						},
					},
				},
				stripEmailDomain: false,
			},
			wantValid:   []string{"tag:valid"},
			wantInvalid: []string{"tag:invalid"},
		},
		{
			name: "only invalid tags",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{
						"tag:valid": []string{"joe"},
					},
				},
				node: Node{
					User: User{
						Name: "joe",
					},
					HostInfo: HostInfo{
						RequestTags: []string{"tag:invalid", "very-invalid"},
					},
				},
				stripEmailDomain: false,
			},
			wantValid:   nil,
			wantInvalid: []string{"tag:invalid", "very-invalid"},
		},
		{
			name: "empty ACLPolicy should return empty tags and should not panic",
			args: args{
				aclPolicy: nil,
				node: Node{
					User: User{
						Name: "joe",
					},
					HostInfo: HostInfo{
						RequestTags: []string{"tag:invalid", "very-invalid"},
					},
				},
				stripEmailDomain: false,
			},
			wantValid:   nil,
			wantInvalid: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotValid, gotInvalid := getTags(
				test.args.aclPolicy,
				test.args.node,
				test.args.stripEmailDomain,
			)
			for _, valid := range gotValid {
				if !contains(test.wantValid, valid) {
					t.Errorf(
						"valids: getTags() = %v, want %v",
						gotValid,
						test.wantValid,
					)

					break
				}
			}
			for _, invalid := range gotInvalid {
				if !contains(test.wantInvalid, invalid) {
					t.Errorf(
						"invalids: getTags() = %v, want %v",
						gotInvalid,
						test.wantInvalid,
					)

					break
				}
			}
		})
	}
}

func Test_getFilteredByACLPeers(t *testing.T) {
	type args struct {
		nodes []Node
		rules []tailcfg.FilterRule
		node  *Node
	}
	tests := []struct {
		name string
		args args
		want Nodes
	}{
		{
			name: "all hosts can talk to each other",
			args: args{
				nodes: []Node{ // list of all nodes in the database
					{
						ID: 1,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						SrcIPs: []string{"100.64.0.1", "100.64.0.2", "100.64.0.3"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*"},
						},
					},
				},
				node: &Node{ // current node
					ID:          1,
					IPAddresses: NodeAddresses{netip.MustParseAddr("100.64.0.1")},
					User:        User{Name: "joe"},
				},
			},
			want: Nodes{
				{
					ID:          2,
					IPAddresses: NodeAddresses{netip.MustParseAddr("100.64.0.2")},
					User:        User{Name: "marc"},
				},
				{
					ID:          3,
					IPAddresses: NodeAddresses{netip.MustParseAddr("100.64.0.3")},
					User:        User{Name: "mickael"},
				},
			},
		},
		{
			name: "One host can talk to another, but not all hosts",
			args: args{
				nodes: []Node{ // list of all nodes in the database
					{
						ID: 1,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						SrcIPs: []string{"100.64.0.1", "100.64.0.2", "100.64.0.3"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.2"},
						},
					},
				},
				node: &Node{ // current node
					ID:          1,
					IPAddresses: NodeAddresses{netip.MustParseAddr("100.64.0.1")},
					User:        User{Name: "joe"},
				},
			},
			want: Nodes{
				{
					ID:          2,
					IPAddresses: NodeAddresses{netip.MustParseAddr("100.64.0.2")},
					User:        User{Name: "marc"},
				},
			},
		},
		{
			name: "host cannot directly talk to destination, but return path is authorized",
			args: args{
				nodes: []Node{ // list of all nodes in the database
					{
						ID: 1,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						SrcIPs: []string{"100.64.0.3"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.2"},
						},
					},
				},
				node: &Node{ // current node
					ID:          2,
					IPAddresses: NodeAddresses{netip.MustParseAddr("100.64.0.2")},
					User:        User{Name: "marc"},
				},
			},
			want: Nodes{
				{
					ID:          3,
					IPAddresses: NodeAddresses{netip.MustParseAddr("100.64.0.3")},
					User:        User{Name: "mickael"},
				},
			},
		},
		{
			name: "rules allows all hosts to reach one destination",
			args: args{
				nodes: []Node{ // list of all nodes in the database
					{
						ID: 1,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						SrcIPs: []string{"*"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.2"},
						},
					},
				},
				node: &Node{ // current node
					ID: 1,
					IPAddresses: NodeAddresses{
						netip.MustParseAddr("100.64.0.1"),
					},
					User: User{Name: "joe"},
				},
			},
			want: Nodes{
				{
					ID: 2,
					IPAddresses: NodeAddresses{
						netip.MustParseAddr("100.64.0.2"),
					},
					User: User{Name: "marc"},
				},
			},
		},
		{
			name: "rules allows all hosts to reach one destination, destination can reach all hosts",
			args: args{
				nodes: []Node{ // list of all nodes in the database
					{
						ID: 1,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						SrcIPs: []string{"*"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.2"},
						},
					},
				},
				node: &Node{ // current node
					ID: 2,
					IPAddresses: NodeAddresses{
						netip.MustParseAddr("100.64.0.2"),
					},
					User: User{Name: "marc"},
				},
			},
			want: Nodes{
				{
					ID: 1,
					IPAddresses: NodeAddresses{
						netip.MustParseAddr("100.64.0.1"),
					},
					User: User{Name: "joe"},
				},
				{
					ID: 3,
					IPAddresses: NodeAddresses{
						netip.MustParseAddr("100.64.0.3"),
					},
					User: User{Name: "mickael"},
				},
			},
		},
		{
			name: "rule allows all hosts to reach all destinations",
			args: args{
				nodes: []Node{ // list of all nodes in the database
					{
						ID: 1,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						SrcIPs: []string{"*"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*"},
						},
					},
				},
				node: &Node{ // current node
					ID:          2,
					IPAddresses: NodeAddresses{netip.MustParseAddr("100.64.0.2")},
					User:        User{Name: "marc"},
				},
			},
			want: Nodes{
				{
					ID: 1,
					IPAddresses: NodeAddresses{
						netip.MustParseAddr("100.64.0.1"),
					},
					User: User{Name: "joe"},
				},
				{
					ID:          3,
					IPAddresses: NodeAddresses{netip.MustParseAddr("100.64.0.3")},
					User:        User{Name: "mickael"},
				},
			},
		},
		{
			name: "without rule all communications are forbidden",
			args: args{
				nodes: []Node{ // list of all nodes in the database
					{
						ID: 1,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
				},
				node: &Node{ // current node
					ID:          2,
					IPAddresses: NodeAddresses{netip.MustParseAddr("100.64.0.2")},
					User:        User{Name: "marc"},
				},
			},
			want: Nodes{},
		},
		{
			// Investigating 699
			// Found some nodes: [ts-head-8w6paa ts-unstable-lys2ib ts-head-upcrmb ts-unstable-rlwpvr] node=ts-head-8w6paa
			// ACL rules generated ACL=[{"DstPorts":[{"Bits":null,"IP":"*","Ports":{"First":0,"Last":65535}}],"SrcIPs":["fd7a:115c:a1e0::3","100.64.0.3","fd7a:115c:a1e0::4","100.64.0.4"]}]
			// ACL Cache Map={"100.64.0.3":{"*":{}},"100.64.0.4":{"*":{}},"fd7a:115c:a1e0::3":{"*":{}},"fd7a:115c:a1e0::4":{"*":{}}}
			name: "issue-699-broken-star",
			args: args{
				nodes: Nodes{ //
					{
						ID:       1,
						Hostname: "ts-head-upcrmb",
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.3"),
							netip.MustParseAddr("fd7a:115c:a1e0::3"),
						},
						User: User{Name: "user1"},
					},
					{
						ID:       2,
						Hostname: "ts-unstable-rlwpvr",
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.4"),
							netip.MustParseAddr("fd7a:115c:a1e0::4"),
						},
						User: User{Name: "user1"},
					},
					{
						ID:       3,
						Hostname: "ts-head-8w6paa",
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.1"),
							netip.MustParseAddr("fd7a:115c:a1e0::1"),
						},
						User: User{Name: "user2"},
					},
					{
						ID:       4,
						Hostname: "ts-unstable-lys2ib",
						IPAddresses: NodeAddresses{
							netip.MustParseAddr("100.64.0.2"),
							netip.MustParseAddr("fd7a:115c:a1e0::2"),
						},
						User: User{Name: "user2"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						DstPorts: []tailcfg.NetPortRange{
							{
								IP:    "*",
								Ports: tailcfg.PortRange{First: 0, Last: 65535},
							},
						},
						SrcIPs: []string{
							"fd7a:115c:a1e0::3", "100.64.0.3",
							"fd7a:115c:a1e0::4", "100.64.0.4",
						},
					},
				},
				node: &Node{ // current node
					ID:       3,
					Hostname: "ts-head-8w6paa",
					IPAddresses: NodeAddresses{
						netip.MustParseAddr("100.64.0.1"),
						netip.MustParseAddr("fd7a:115c:a1e0::1"),
					},
					User: User{Name: "user2"},
				},
			},
			want: Nodes{
				{
					ID:       1,
					Hostname: "ts-head-upcrmb",
					IPAddresses: NodeAddresses{
						netip.MustParseAddr("100.64.0.3"),
						netip.MustParseAddr("fd7a:115c:a1e0::3"),
					},
					User: User{Name: "user1"},
				},
				{
					ID:       2,
					Hostname: "ts-unstable-rlwpvr",
					IPAddresses: NodeAddresses{
						netip.MustParseAddr("100.64.0.4"),
						netip.MustParseAddr("fd7a:115c:a1e0::4"),
					},
					User: User{Name: "user1"},
				},
			},
		},
	}
	var lock sync.RWMutex
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aclRulesMap := generateACLPeerCacheMap(tt.args.rules)

			got := filterNodesByACL(
				tt.args.node,
				tt.args.nodes,
				&lock,
				aclRulesMap,
			)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("filterNodesByACL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHeadscale_generateGivenName(t *testing.T) {
	type args struct {
		suppliedName string
		randomSuffix bool
	}
	tests := []struct {
		name    string
		h       *Headscale
		args    args
		want    *regexp.Regexp
		wantErr bool
	}{
		{
			name: "simple node name generation",
			h: &Headscale{
				cfg: &Config{
					OIDC: OIDCConfig{
						StripEmaildomain: true,
					},
				},
			},
			args: args{
				suppliedName: "testnode",
				randomSuffix: false,
			},
			want:    regexp.MustCompile("^testnode$"),
			wantErr: false,
		},
		{
			name: "node name with 53 chars",
			h: &Headscale{
				cfg: &Config{
					OIDC: OIDCConfig{
						StripEmaildomain: true,
					},
				},
			},
			args: args{
				suppliedName: "testmaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaachine",
				randomSuffix: false,
			},
			want:    regexp.MustCompile("^testmaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaachine$"),
			wantErr: false,
		},
		{
			name: "node name with 63 chars",
			h: &Headscale{
				cfg: &Config{
					OIDC: OIDCConfig{
						StripEmaildomain: true,
					},
				},
			},
			args: args{
				suppliedName: "nodeeee12345678901234567890123456789012345678901234567890123",
				randomSuffix: false,
			},
			want:    regexp.MustCompile("^nodeeee12345678901234567890123456789012345678901234567890123$"),
			wantErr: false,
		},
		{
			name: "node name with 64 chars",
			h: &Headscale{
				cfg: &Config{
					OIDC: OIDCConfig{
						StripEmaildomain: true,
					},
				},
			},
			args: args{
				suppliedName: "nodeeee123456789012345678901234567890123456789012345678901234",
				randomSuffix: false,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "node name with 73 chars",
			h: &Headscale{
				cfg: &Config{
					OIDC: OIDCConfig{
						StripEmaildomain: true,
					},
				},
			},
			args: args{
				suppliedName: "nodeeee123456789012345678901234567890123456789012345678901234567890123",
				randomSuffix: false,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "node name with random suffix",
			h: &Headscale{
				cfg: &Config{
					OIDC: OIDCConfig{
						StripEmaildomain: true,
					},
				},
			},
			args: args{
				suppliedName: "test",
				randomSuffix: true,
			},
			want:    regexp.MustCompile(fmt.Sprintf("^test-[a-z0-9]{%d}$", NodeGivenNameHashLength)),
			wantErr: false,
		},
		{
			name: "node name with 63 chars with random suffix",
			h: &Headscale{
				cfg: &Config{
					OIDC: OIDCConfig{
						StripEmaildomain: true,
					},
				},
			},
			args: args{
				suppliedName: "nodeeee12345678901234567890123456789012345678901234567890123",
				randomSuffix: true,
			},
			want:    regexp.MustCompile(fmt.Sprintf("^nodeeee1234567890123456789012345678901234567890123-[a-z0-9]{%d}$", NodeGivenNameHashLength)),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.generateGivenName(tt.args.suppliedName, tt.args.randomSuffix)
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

			if len(got) > labelHostnameLength {
				t.Errorf(
					"Headscale.GenerateGivenName() = %v is larger than allowed DNS segment %d",
					got,
					labelHostnameLength,
				)
			}
		})
	}
}

func (s *Suite) TestAutoApproveRoutes(c *check.C) {
	err := app.LoadACLPolicy("./tests/acls/acl_policy_autoapprovers.hujson")
	c.Assert(err, check.IsNil)

	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	nodeKey := key.NewNode()

	defaultRoute := netip.MustParsePrefix("0.0.0.0/0")
	route1 := netip.MustParsePrefix("10.10.0.0/16")
	// Check if a subprefix of an autoapproved route is approved
	route2 := netip.MustParsePrefix("10.11.0.0/24")

	node := Node{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        NodePublicKeyStripPrefix(nodeKey.Public()),
		DiscoKey:       "faa",
		Hostname:       "test",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo: HostInfo{
			RequestTags: []string{"tag:exit"},
			RoutableIPs: []netip.Prefix{defaultRoute, route1, route2},
		},
		IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
	}

	app.db.Save(&node)

	err = app.processNodeRoutes(&node)
	c.Assert(err, check.IsNil)

	node0ByID, err := app.GetNodeByID(0)
	c.Assert(err, check.IsNil)

	err = app.EnableAutoApprovedRoutes(node0ByID)
	c.Assert(err, check.IsNil)

	enabledRoutes, err := app.GetEnabledRoutes(node0ByID)
	c.Assert(err, check.IsNil)
	c.Assert(enabledRoutes, check.HasLen, 3)
}
