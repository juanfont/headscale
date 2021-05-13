package headscale

import (
	"gopkg.in/check.v1"
)

var _ = check.Suite(&Suite{})

func (s *Suite) TestGetMachine(c *check.C) {
	n, err := h.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := h.CreatePreAuthKey(n.Name, false, nil)
	c.Assert(err, check.IsNil)

	db, err := h.db()
	if err != nil {
		c.Fatal(err)
	}
	defer db.Close()

	_, err = h.GetMachine("test", "testmachine")
	c.Assert(err, check.NotNil)

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

	m1, err := h.GetMachine("test", "testmachine")
	c.Assert(err, check.IsNil)

	_, err = m1.GetHostInfo()
	c.Assert(err, check.IsNil)

}
