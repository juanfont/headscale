package headscale

import (
	"errors"

	"gopkg.in/check.v1"
	"gorm.io/datatypes"
	"inet.af/netaddr"
)

func (s *Suite) TestWrongPath(c *check.C) {
	err := app.LoadACLPolicy("asdfg")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestBrokenHuJson(c *check.C) {
	err := app.LoadACLPolicy("./tests/acls/broken.hujson")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestInvalidPolicyHuson(c *check.C) {
	err := app.LoadACLPolicy("./tests/acls/invalid.hujson")
	c.Assert(err, check.NotNil)
	c.Assert(err, check.Equals, errEmptyPolicy)
}

func (s *Suite) TestParseHosts(c *check.C) {
	var hosts Hosts
	err := hosts.UnmarshalJSON(
		[]byte(
			`{"example-host-1": "100.100.100.100","example-host-2": "100.100.101.100/24"}`,
		),
	)
	c.Assert(hosts, check.NotNil)
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestParseInvalidCIDR(c *check.C) {
	var hosts Hosts
	err := hosts.UnmarshalJSON([]byte(`{"example-host-1": "100.100.100.100/42"}`))
	c.Assert(hosts, check.IsNil)
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestRuleInvalidGeneration(c *check.C) {
	err := app.LoadACLPolicy("./tests/acls/acl_policy_invalid.hujson")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestBasicRule(c *check.C) {
	err := app.LoadACLPolicy("./tests/acls/acl_policy_basic_1.hujson")
	c.Assert(err, check.IsNil)

	rules, err := app.generateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)
}

func (s *Suite) TestInvalidAction(c *check.C) {
	app.aclPolicy = &ACLPolicy{
		ACLs: []ACL{
			{Action: "invalidAction", Users: []string{"*"}, Ports: []string{"*:*"}},
		},
	}
	err := app.UpdateACLRules()
	c.Assert(errors.Is(err, errInvalidAction), check.Equals, true)
}

func (s *Suite) TestInvalidGroupInGroup(c *check.C) {
	// this ACL is wrong because the group in users sections doesn't exist
	app.aclPolicy = &ACLPolicy{
		Groups: Groups{"group:test": []string{"foo"}, "group:error": []string{"foo", "group:test"}},
		ACLs: []ACL{
			{Action: "accept", Users: []string{"group:error"}, Ports: []string{"*:*"}},
		},
	}
	err := app.UpdateACLRules()
	c.Assert(errors.Is(err, errInvalidGroup), check.Equals, true)
}

func (s *Suite) TestInvalidTagOwners(c *check.C) {
	// this ACL is wrong because no tagOwners own the requested tag for the server
	app.aclPolicy = &ACLPolicy{
		ACLs: []ACL{
			{Action: "accept", Users: []string{"tag:foo"}, Ports: []string{"*:*"}},
		},
	}
	err := app.UpdateACLRules()
	c.Assert(errors.Is(err, errInvalidTag), check.Equals, true)
}

// this test should validate that we can expand a group in a TagOWner section and
// match properly the IP's of the related hosts. The owner is valid and the tag is also valid.
// the tag is matched in the Users section
func (s *Suite) TestValidExpandTagOwnersInUsers(c *check.C) {
	namespace, err := app.CreateNamespace("foo")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("foo", "testmachine")
	c.Assert(err, check.NotNil)
	b := []byte("{\"OS\":\"centos\",\"Hostname\":\"foo\",\"RequestTags\":[\"tag:test\"]}")
	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		IPAddresses:    MachineAddresses{netaddr.MustParseIP("100.64.0.1")},
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       datatypes.JSON(b),
	}
	app.db.Save(&machine)

	app.aclPolicy = &ACLPolicy{
		Groups:    Groups{"group:test": []string{"foo", "foobar"}},
		TagOwners: TagOwners{"tag:test": []string{"bar", "group:test"}},
		ACLs: []ACL{
			{Action: "accept", Users: []string{"tag:test"}, Ports: []string{"*:*"}},
		},
	}
	err = app.UpdateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(app.aclRules, check.HasLen, 1)
	c.Assert(app.aclRules[0].SrcIPs, check.HasLen, 1)
	c.Assert(app.aclRules[0].SrcIPs[0], check.Equals, "100.64.0.1")
}

// this test should validate that we can expand a group in a TagOWner section and
// match properly the IP's of the related hosts. The owner is valid and the tag is also valid.
// the tag is matched in the Ports section
func (s *Suite) TestValidExpandTagOwnersInPorts(c *check.C) {
	namespace, err := app.CreateNamespace("foo")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("foo", "testmachine")
	c.Assert(err, check.NotNil)
	b := []byte("{\"OS\":\"centos\",\"Hostname\":\"foo\",\"RequestTags\":[\"tag:test\"]}")
	machine := Machine{
		ID:             1,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		IPAddresses:    MachineAddresses{netaddr.MustParseIP("100.64.0.1")},
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       datatypes.JSON(b),
	}
	app.db.Save(&machine)

	app.aclPolicy = &ACLPolicy{
		Groups:    Groups{"group:test": []string{"foo", "foobar"}},
		TagOwners: TagOwners{"tag:test": []string{"bar", "group:test"}},
		ACLs: []ACL{
			{Action: "accept", Users: []string{"*"}, Ports: []string{"tag:test:*"}},
		},
	}
	err = app.UpdateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(app.aclRules, check.HasLen, 1)
	c.Assert(app.aclRules[0].DstPorts, check.HasLen, 1)
	c.Assert(app.aclRules[0].DstPorts[0].IP, check.Equals, "100.64.0.1")
}

// need a test with:
// tag on a host that isn't owned by a tag owners. So the namespace
// of the host should be valid
func (s *Suite) TestInvalidTagValidNamespace(c *check.C) {
	namespace, err := app.CreateNamespace("foo")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("foo", "testmachine")
	c.Assert(err, check.NotNil)
	b := []byte("{\"OS\":\"centos\",\"Hostname\":\"foo\",\"RequestTags\":[\"tag:foo\"]}")
	machine := Machine{
		ID:             1,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		IPAddresses:    MachineAddresses{netaddr.MustParseIP("100.64.0.1")},
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       datatypes.JSON(b),
	}
	app.db.Save(&machine)

	app.aclPolicy = &ACLPolicy{
		TagOwners: TagOwners{"tag:test": []string{"foo"}},
		ACLs: []ACL{
			{Action: "accept", Users: []string{"foo"}, Ports: []string{"*:*"}},
		},
	}
	err = app.UpdateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(app.aclRules, check.HasLen, 1)
	c.Assert(app.aclRules[0].SrcIPs, check.HasLen, 1)
	c.Assert(app.aclRules[0].SrcIPs[0], check.Equals, "100.64.0.1")
}

// tag on a host is owned by a tag owner, the tag is valid.
// an ACL rule is matching the tag to a namespace. It should not be valid since the
// host should be tied to the tag now.
func (s *Suite) TestValidTagInvalidNamespace(c *check.C) {
	namespace, err := app.CreateNamespace("foo")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("foo", "webserver")
	c.Assert(err, check.NotNil)
	b := []byte("{\"OS\":\"centos\",\"Hostname\":\"webserver\",\"RequestTags\":[\"tag:webapp\"]}")
	machine := Machine{
		ID:             1,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "webserver",
		IPAddresses:    MachineAddresses{netaddr.MustParseIP("100.64.0.1")},
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       datatypes.JSON(b),
	}
	app.db.Save(&machine)
	_, err = app.GetMachine("foo", "user")
	b = []byte("{\"OS\":\"debian\",\"Hostname\":\"user\"}")
	c.Assert(err, check.NotNil)
	machine = Machine{
		ID:             2,
		MachineKey:     "foo2",
		NodeKey:        "bar2",
		DiscoKey:       "faab",
		Name:           "user",
		IPAddresses:    MachineAddresses{netaddr.MustParseIP("100.64.0.2")},
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       datatypes.JSON(b),
	}
	app.db.Save(&machine)

	app.aclPolicy = &ACLPolicy{
		TagOwners: TagOwners{"tag:webapp": []string{"foo"}},
		ACLs: []ACL{
			{Action: "accept", Users: []string{"foo"}, Ports: []string{"tag:webapp:80,443"}},
		},
	}
	err = app.UpdateACLRules()
	c.Assert(err, check.IsNil)
	c.Logf("Rules: %v", app.aclRules)
	c.Assert(app.aclRules, check.HasLen, 1)
	c.Assert(app.aclRules[0].SrcIPs, check.HasLen, 0)
}

func (s *Suite) TestPortRange(c *check.C) {
	err := app.LoadACLPolicy("./tests/acls/acl_policy_basic_range.hujson")
	c.Assert(err, check.IsNil)

	rules, err := app.generateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

	c.Assert(rules, check.HasLen, 1)
	c.Assert(rules[0].DstPorts, check.HasLen, 1)
	c.Assert(rules[0].DstPorts[0].Ports.First, check.Equals, uint16(5400))
	c.Assert(rules[0].DstPorts[0].Ports.Last, check.Equals, uint16(5500))
}

func (s *Suite) TestPortWildcard(c *check.C) {
	err := app.LoadACLPolicy("./tests/acls/acl_policy_basic_wildcards.hujson")
	c.Assert(err, check.IsNil)

	rules, err := app.generateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

	c.Assert(rules, check.HasLen, 1)
	c.Assert(rules[0].DstPorts, check.HasLen, 1)
	c.Assert(rules[0].DstPorts[0].Ports.First, check.Equals, uint16(0))
	c.Assert(rules[0].DstPorts[0].Ports.Last, check.Equals, uint16(65535))
	c.Assert(rules[0].SrcIPs, check.HasLen, 1)
	c.Assert(rules[0].SrcIPs[0], check.Equals, "*")
}

func (s *Suite) TestPortNamespace(c *check.C) {
	namespace, err := app.CreateNamespace("testnamespace")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("testnamespace", "testmachine")
	c.Assert(err, check.NotNil)
	ips, _ := app.getAvailableIPs()
	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: RegisterMethodAuthKey,
		IPAddresses:    ips,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

	err = app.LoadACLPolicy(
		"./tests/acls/acl_policy_basic_namespace_as_user.hujson",
	)
	c.Assert(err, check.IsNil)

	rules, err := app.generateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

	c.Assert(rules, check.HasLen, 1)
	c.Assert(rules[0].DstPorts, check.HasLen, 1)
	c.Assert(rules[0].DstPorts[0].Ports.First, check.Equals, uint16(0))
	c.Assert(rules[0].DstPorts[0].Ports.Last, check.Equals, uint16(65535))
	c.Assert(rules[0].SrcIPs, check.HasLen, 1)
	c.Assert(rules[0].SrcIPs[0], check.Not(check.Equals), "not an ip")
	c.Assert(len(ips), check.Equals, 1)
	c.Assert(rules[0].SrcIPs[0], check.Equals, ips[0].String())
}

func (s *Suite) TestPortGroup(c *check.C) {
	namespace, err := app.CreateNamespace("testnamespace")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("testnamespace", "testmachine")
	c.Assert(err, check.NotNil)
	ips, _ := app.getAvailableIPs()
	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: RegisterMethodAuthKey,
		IPAddresses:    ips,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

	err = app.LoadACLPolicy("./tests/acls/acl_policy_basic_groups.hujson")
	c.Assert(err, check.IsNil)

	rules, err := app.generateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

	c.Assert(rules, check.HasLen, 1)
	c.Assert(rules[0].DstPorts, check.HasLen, 1)
	c.Assert(rules[0].DstPorts[0].Ports.First, check.Equals, uint16(0))
	c.Assert(rules[0].DstPorts[0].Ports.Last, check.Equals, uint16(65535))
	c.Assert(rules[0].SrcIPs, check.HasLen, 1)
	c.Assert(rules[0].SrcIPs[0], check.Not(check.Equals), "not an ip")
	c.Assert(len(ips), check.Equals, 1)
	c.Assert(rules[0].SrcIPs[0], check.Equals, ips[0].String())
}
