package headscale

import (
	//_ "github.com/jinzhu/gorm/dialects/sqlite" // sql driver

	"gopkg.in/check.v1"
)

var _ = check.Suite(&Suite{})

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

	pak, err := h.CreatePreAuthKey(n.Name, false, nil)
	c.Assert(err, check.IsNil)

	db, err := h.db()
	if err != nil {
		c.Fatal(err)
	}
	defer db.Close()
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
	db.Save(&m)

	err = h.DestroyNamespace("test")
	c.Assert(err, check.Equals, errorNamespaceNotEmpty)
}
