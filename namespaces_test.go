package headscale

import (
	"gopkg.in/check.v1"
)

func (s *Suite) TestCreateAndDestroyNamespace(c *check.C) {
	n, err := h.CreateNamespace("test")
	c.Assert(err, check.IsNil)
	c.Assert(n.Name, check.Equals, "test")

	ns, err := h.ListNamespaces()
	c.Assert(err, check.IsNil)
	c.Assert(len(*ns), check.Equals, 1)

	err = h.DestroyNamespace("test")
	c.Assert(err, check.IsNil)

	_, err = h.GetNamespace("test")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestDestroyNamespaceErrors(c *check.C) {
	err := h.DestroyNamespace("test")
	c.Assert(err, check.Equals, errorNamespaceNotFound)

	n, err := h.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := h.CreatePreAuthKey(n.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	m := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		NamespaceID:    n.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		AuthKeyID:      uint(pak.ID),
	}
	h.db.Save(&m)

	err = h.DestroyNamespace("test")
	c.Assert(err, check.Equals, errorNamespaceNotEmpty)
}
