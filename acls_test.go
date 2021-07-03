package headscale

import (
	"gopkg.in/check.v1"
)

func (s *Suite) TestWrongPath(c *check.C) {
	_, err := h.ParsePolicy("asdfg")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestBrokenHuJson(c *check.C) {
	_, err := h.ParsePolicy("./tests/acls/broken.hujson")
	c.Assert(err, check.NotNil)

}

func (s *Suite) TestInvalidPolicyHuson(c *check.C) {
	_, err := h.ParsePolicy("./tests/acls/invalid.hujson")
	c.Assert(err, check.NotNil)
	c.Assert(err, check.Equals, errorInvalidPolicy)
}

func (s *Suite) TestValidCheckHosts(c *check.C) {
	p, err := h.ParsePolicy("./tests/acls/acl_policy_1.hujson")
	c.Assert(err, check.IsNil)
	c.Assert(p, check.NotNil)
	c.Assert(p.IsZero(), check.Equals, false)

	hosts, err := p.GetHosts()
	c.Assert(err, check.IsNil)
	c.Assert(*hosts, check.HasLen, 2)
}
