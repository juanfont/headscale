package db

import (
	"gopkg.in/check.v1"

	"github.com/juanfont/headscale/hscontrol/types"
)

func (*Suite) TestACLNotFound(c *check.C) {
	acl, err := db.GetACL()
	c.Assert(err, check.NotNil)
	c.Assert(acl, check.IsNil)
}

func (*Suite) TestSetACL(c *check.C) {
	acl := &types.ACL{
		Policy: []byte(`{"groups":{"test":["user1"]}}`),
	}

	result, err := db.SetACL(acl)
	c.Assert(err, check.IsNil)
	c.Assert(result, check.NotNil)

	// Check that the ACL was saved
	acl, err = db.GetACL()
	c.Assert(err, check.IsNil)
	c.Assert(acl, check.NotNil)
	c.Assert(acl.Policy, check.NotNil)
	c.Assert(string(acl.Policy), check.Equals, `{"groups":{"test":["user1"]}}`)
}
