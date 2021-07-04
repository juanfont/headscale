package headscale

import (
	"gopkg.in/check.v1"
)

func (s *Suite) TestGetMachine(c *check.C) {
	n, err := h.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := h.CreatePreAuthKey(n.Name, false, false, nil)
	c.Assert(err, check.IsNil)

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
	h.db.Save(&m)

	m1, err := h.GetMachine("test", "testmachine")
	c.Assert(err, check.IsNil)

	_, err = m1.GetHostInfo()
	c.Assert(err, check.IsNil)

}
