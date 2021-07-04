package headscale

import (
	"gopkg.in/check.v1"
)

func (s *Suite) TestWrongPath(c *check.C) {
	err := h.LoadACLPolicy("asdfg")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestBrokenHuJson(c *check.C) {
	err := h.LoadACLPolicy("./tests/acls/broken.hujson")
	c.Assert(err, check.NotNil)

}

func (s *Suite) TestInvalidPolicyHuson(c *check.C) {
	err := h.LoadACLPolicy("./tests/acls/invalid.hujson")
	c.Assert(err, check.NotNil)
	c.Assert(err, check.Equals, errorEmptyPolicy)
}

func (s *Suite) TestParseHosts(c *check.C) {
	var hs Hosts
	err := hs.UnmarshalJSON([]byte(`{"example-host-1": "100.100.100.100","example-host-2": "100.100.101.100/24"}`))
	c.Assert(hs, check.NotNil)
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestParseInvalidCIDR(c *check.C) {
	var hs Hosts
	err := hs.UnmarshalJSON([]byte(`{"example-host-1": "100.100.100.100/42"}`))
	c.Assert(hs, check.IsNil)
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestRuleInvalidGeneration(c *check.C) {
	err := h.LoadACLPolicy("./tests/acls/acl_policy_invalid.hujson")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestBasicRule(c *check.C) {
	err := h.LoadACLPolicy("./tests/acls/acl_policy_basic_1.hujson")
	c.Assert(err, check.IsNil)

	rules, err := h.generateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)
}

func (s *Suite) TestPortRange(c *check.C) {
	err := h.LoadACLPolicy("./tests/acls/acl_policy_basic_range.hujson")
	c.Assert(err, check.IsNil)

	rules, err := h.generateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

	c.Assert(*rules, check.HasLen, 1)
	c.Assert((*rules)[0].DstPorts, check.HasLen, 1)
	c.Assert((*rules)[0].DstPorts[0].Ports.First, check.Equals, uint16(5400))
	c.Assert((*rules)[0].DstPorts[0].Ports.Last, check.Equals, uint16(5500))
}

func (s *Suite) TestPortWildcard(c *check.C) {
	err := h.LoadACLPolicy("./tests/acls/acl_policy_basic_wildcards.hujson")
	c.Assert(err, check.IsNil)

	rules, err := h.generateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

	c.Assert(*rules, check.HasLen, 1)
	c.Assert((*rules)[0].DstPorts, check.HasLen, 1)
	c.Assert((*rules)[0].DstPorts[0].Ports.First, check.Equals, uint16(0))
	c.Assert((*rules)[0].DstPorts[0].Ports.Last, check.Equals, uint16(65535))
	c.Assert((*rules)[0].SrcIPs, check.HasLen, 1)
	c.Assert((*rules)[0].SrcIPs[0], check.Equals, "*")
}

func (s *Suite) TestPortNamespace(c *check.C) {
	n, err := h.CreateNamespace("testnamespace")
	c.Assert(err, check.IsNil)

	pak, err := h.CreatePreAuthKey(n.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = h.GetMachine("testnamespace", "testmachine")
	c.Assert(err, check.NotNil)
	ip, _ := h.getAvailableIP()
	m := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		NamespaceID:    n.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      ip.String(),
		AuthKeyID:      uint(pak.ID),
	}
	h.db.Save(&m)

	err = h.LoadACLPolicy("./tests/acls/acl_policy_basic_namespace_as_user.hujson")
	c.Assert(err, check.IsNil)

	rules, err := h.generateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

	c.Assert(*rules, check.HasLen, 1)
	c.Assert((*rules)[0].DstPorts, check.HasLen, 1)
	c.Assert((*rules)[0].DstPorts[0].Ports.First, check.Equals, uint16(0))
	c.Assert((*rules)[0].DstPorts[0].Ports.Last, check.Equals, uint16(65535))
	c.Assert((*rules)[0].SrcIPs, check.HasLen, 1)
	c.Assert((*rules)[0].SrcIPs[0], check.Not(check.Equals), "not an ip")
	c.Assert((*rules)[0].SrcIPs[0], check.Equals, ip.String())
}

func (s *Suite) TestPortGroup(c *check.C) {
	n, err := h.CreateNamespace("testnamespace")
	c.Assert(err, check.IsNil)

	pak, err := h.CreatePreAuthKey(n.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = h.GetMachine("testnamespace", "testmachine")
	c.Assert(err, check.NotNil)
	ip, _ := h.getAvailableIP()
	m := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		NamespaceID:    n.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      ip.String(),
		AuthKeyID:      uint(pak.ID),
	}
	h.db.Save(&m)

	err = h.LoadACLPolicy("./tests/acls/acl_policy_basic_groups.hujson")
	c.Assert(err, check.IsNil)

	rules, err := h.generateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

	c.Assert(*rules, check.HasLen, 1)
	c.Assert((*rules)[0].DstPorts, check.HasLen, 1)
	c.Assert((*rules)[0].DstPorts[0].Ports.First, check.Equals, uint16(0))
	c.Assert((*rules)[0].DstPorts[0].Ports.Last, check.Equals, uint16(65535))
	c.Assert((*rules)[0].SrcIPs, check.HasLen, 1)
	c.Assert((*rules)[0].SrcIPs[0], check.Not(check.Equals), "not an ip")
	c.Assert((*rules)[0].SrcIPs[0], check.Equals, ip.String())
}
