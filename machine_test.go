package headscale

import (
	"encoding/json"
	"strconv"

	"gopkg.in/check.v1"
)

func (s *Suite) TestGetMachine(c *check.C) {
	n, err := h.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := h.CreatePreAuthKey(n.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = h.GetMachine("test", "testmachine")
	c.Assert(err, check.NotNil)

	m := &Machine{
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
	h.db.Save(m)

	m1, err := h.GetMachine("test", "testmachine")
	c.Assert(err, check.IsNil)

	_, err = m1.GetHostInfo()
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetMachineByID(c *check.C) {
	n, err := h.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := h.CreatePreAuthKey(n.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = h.GetMachineByID(0)
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

	m1, err := h.GetMachineByID(0)
	c.Assert(err, check.IsNil)

	_, err = m1.GetHostInfo()
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestDeleteMachine(c *check.C) {
	n, err := h.CreateNamespace("test")
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
		AuthKeyID:      uint(1),
	}
	h.db.Save(&m)
	err = h.DeleteMachine(&m)
	c.Assert(err, check.IsNil)
	v, err := h.getValue("namespaces_pending_updates")
	c.Assert(err, check.IsNil)
	names := []string{}
	err = json.Unmarshal([]byte(v), &names)
	c.Assert(err, check.IsNil)
	c.Assert(names, check.DeepEquals, []string{n.Name})
	h.checkForNamespacesPendingUpdates()
	v, _ = h.getValue("namespaces_pending_updates")
	c.Assert(v, check.Equals, "")
	_, err = h.GetMachine(n.Name, "testmachine")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestHardDeleteMachine(c *check.C) {
	n, err := h.CreateNamespace("test")
	c.Assert(err, check.IsNil)
	m := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine3",
		NamespaceID:    n.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		AuthKeyID:      uint(1),
	}
	h.db.Save(&m)
	err = h.HardDeleteMachine(&m)
	c.Assert(err, check.IsNil)
	_, err = h.GetMachine(n.Name, "testmachine3")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestGetDirectPeers(c *check.C) {
	n, err := h.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := h.CreatePreAuthKey(n.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = h.GetMachineByID(0)
	c.Assert(err, check.NotNil)

	for i := 0; i <= 10; i++ {
		m := Machine{
			ID:             uint64(i),
			MachineKey:     "foo" + strconv.Itoa(i),
			NodeKey:        "bar" + strconv.Itoa(i),
			DiscoKey:       "faa" + strconv.Itoa(i),
			Name:           "testmachine" + strconv.Itoa(i),
			NamespaceID:    n.ID,
			Registered:     true,
			RegisterMethod: "authKey",
			AuthKeyID:      uint(pak.ID),
		}
		h.db.Save(&m)
	}

	m1, err := h.GetMachineByID(0)
	c.Assert(err, check.IsNil)

	_, err = m1.GetHostInfo()
	c.Assert(err, check.IsNil)

	peers, err := h.getDirectPeers(m1)
	c.Assert(err, check.IsNil)

	c.Assert(len(peers), check.Equals, 9)
	c.Assert(peers[0].Name, check.Equals, "testmachine2")
	c.Assert(peers[5].Name, check.Equals, "testmachine7")
	c.Assert(peers[8].Name, check.Equals, "testmachine10")
}
