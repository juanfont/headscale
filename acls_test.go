package headscale

import (
	"gopkg.in/check.v1"
)

func (s *Suite) TestWrongPath(c *check.C) {
	err := h.LoadPolicy("asdfg")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestBrokenHuJson(c *check.C) {
	err := h.LoadPolicy("./tests/acls/broken.hujson")
	c.Assert(err, check.NotNil)

}

func (s *Suite) TestInvalidPolicyHuson(c *check.C) {
	err := h.LoadPolicy("./tests/acls/invalid.hujson")
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

func (s *Suite) TestCheckLoaded(c *check.C) {
	err := h.LoadPolicy("./tests/acls/acl_policy_1.hujson")
	c.Assert(err, check.IsNil)
	c.Assert(h.aclPolicy, check.NotNil)
}

func (s *Suite) TestValidCheckParsedHosts(c *check.C) {
	err := h.LoadPolicy("./tests/acls/acl_policy_1.hujson")
	c.Assert(err, check.IsNil)
	c.Assert(h.aclPolicy, check.NotNil)
	c.Assert(h.aclPolicy.IsZero(), check.Equals, false)
	c.Assert(h.aclPolicy.Hosts, check.HasLen, 2)
}

func (s *Suite) TestRuleInvalidGeneration(c *check.C) {
	err := h.LoadPolicy("./tests/acls/acl_policy_invalid.hujson")
	c.Assert(err, check.IsNil)

	rules, err := h.generateACLRules()
	c.Assert(err, check.NotNil)
	c.Assert(rules, check.IsNil)
}

func (s *Suite) TestRuleGeneration(c *check.C) {
	err := h.LoadPolicy("./tests/acls/acl_policy_1.hujson")
	c.Assert(err, check.IsNil)

	rules, err := h.generateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

}
