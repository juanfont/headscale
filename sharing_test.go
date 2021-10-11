package headscale

import (
	"gopkg.in/check.v1"
)

func (s *Suite) TestBasicSharedNodesInNamespace(c *check.C) {
	n1, err := h.CreateNamespace("shared1")
	c.Assert(err, check.IsNil)

	n2, err := h.CreateNamespace("shared2")
	c.Assert(err, check.IsNil)

	pak1, err := h.CreatePreAuthKey(n1.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	pak2, err := h.CreatePreAuthKey(n2.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = h.GetMachine(n1.Name, "test_get_shared_nodes_1")
	c.Assert(err, check.NotNil)

	m1 := &Machine{
		ID:             0,
		MachineKey:     "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		NodeKey:        "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		DiscoKey:       "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		Name:           "test_get_shared_nodes_1",
		NamespaceID:    n1.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.1",
		AuthKeyID:      uint(pak1.ID),
	}
	h.db.Save(m1)

	_, err = h.GetMachine(n1.Name, m1.Name)
	c.Assert(err, check.IsNil)

	m2 := &Machine{
		ID:             1,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_2",
		NamespaceID:    n2.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.2",
		AuthKeyID:      uint(pak2.ID),
	}
	h.db.Save(m2)

	_, err = h.GetMachine(n2.Name, m2.Name)
	c.Assert(err, check.IsNil)

	p1s, err := h.getPeers(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(p1s), check.Equals, 0)

	err = h.AddSharedMachineToNamespace(m2, n1)
	c.Assert(err, check.IsNil)

	p1sAfter, err := h.getPeers(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(p1sAfter), check.Equals, 1)
	c.Assert(p1sAfter[0].ID, check.Equals, m2.ID)
}

func (s *Suite) TestSameNamespace(c *check.C) {
	n1, err := h.CreateNamespace("shared1")
	c.Assert(err, check.IsNil)

	n2, err := h.CreateNamespace("shared2")
	c.Assert(err, check.IsNil)

	pak1, err := h.CreatePreAuthKey(n1.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	pak2, err := h.CreatePreAuthKey(n2.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = h.GetMachine(n1.Name, "test_get_shared_nodes_1")
	c.Assert(err, check.NotNil)

	m1 := &Machine{
		ID:             0,
		MachineKey:     "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		NodeKey:        "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		DiscoKey:       "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		Name:           "test_get_shared_nodes_1",
		NamespaceID:    n1.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.1",
		AuthKeyID:      uint(pak1.ID),
	}
	h.db.Save(m1)

	_, err = h.GetMachine(n1.Name, m1.Name)
	c.Assert(err, check.IsNil)

	m2 := &Machine{
		ID:             1,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_2",
		NamespaceID:    n2.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.2",
		AuthKeyID:      uint(pak2.ID),
	}
	h.db.Save(m2)

	_, err = h.GetMachine(n2.Name, m2.Name)
	c.Assert(err, check.IsNil)

	p1s, err := h.getPeers(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(p1s), check.Equals, 0)

	err = h.AddSharedMachineToNamespace(m1, n1)
	c.Assert(err, check.Equals, errorSameNamespace)
}

func (s *Suite) TestAlreadyShared(c *check.C) {
	n1, err := h.CreateNamespace("shared1")
	c.Assert(err, check.IsNil)

	n2, err := h.CreateNamespace("shared2")
	c.Assert(err, check.IsNil)

	pak1, err := h.CreatePreAuthKey(n1.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	pak2, err := h.CreatePreAuthKey(n2.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = h.GetMachine(n1.Name, "test_get_shared_nodes_1")
	c.Assert(err, check.NotNil)

	m1 := &Machine{
		ID:             0,
		MachineKey:     "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		NodeKey:        "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		DiscoKey:       "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		Name:           "test_get_shared_nodes_1",
		NamespaceID:    n1.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.1",
		AuthKeyID:      uint(pak1.ID),
	}
	h.db.Save(m1)

	_, err = h.GetMachine(n1.Name, m1.Name)
	c.Assert(err, check.IsNil)

	m2 := &Machine{
		ID:             1,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_2",
		NamespaceID:    n2.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.2",
		AuthKeyID:      uint(pak2.ID),
	}
	h.db.Save(m2)

	_, err = h.GetMachine(n2.Name, m2.Name)
	c.Assert(err, check.IsNil)

	p1s, err := h.getPeers(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(p1s), check.Equals, 0)

	err = h.AddSharedMachineToNamespace(m2, n1)
	c.Assert(err, check.IsNil)
	err = h.AddSharedMachineToNamespace(m2, n1)
	c.Assert(err, check.Equals, errorMachineAlreadyShared)
}

func (s *Suite) TestDoNotIncludeRoutesOnShared(c *check.C) {
	n1, err := h.CreateNamespace("shared1")
	c.Assert(err, check.IsNil)

	n2, err := h.CreateNamespace("shared2")
	c.Assert(err, check.IsNil)

	pak1, err := h.CreatePreAuthKey(n1.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	pak2, err := h.CreatePreAuthKey(n2.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = h.GetMachine(n1.Name, "test_get_shared_nodes_1")
	c.Assert(err, check.NotNil)

	m1 := &Machine{
		ID:             0,
		MachineKey:     "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		NodeKey:        "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		DiscoKey:       "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		Name:           "test_get_shared_nodes_1",
		NamespaceID:    n1.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.1",
		AuthKeyID:      uint(pak1.ID),
	}
	h.db.Save(m1)

	_, err = h.GetMachine(n1.Name, m1.Name)
	c.Assert(err, check.IsNil)

	m2 := &Machine{
		ID:             1,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_2",
		NamespaceID:    n2.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.2",
		AuthKeyID:      uint(pak2.ID),
	}
	h.db.Save(m2)

	_, err = h.GetMachine(n2.Name, m2.Name)
	c.Assert(err, check.IsNil)

	p1s, err := h.getPeers(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(p1s), check.Equals, 0)

	err = h.AddSharedMachineToNamespace(m2, n1)
	c.Assert(err, check.IsNil)

	p1sAfter, err := h.getPeers(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(p1sAfter), check.Equals, 1)
	c.Assert(p1sAfter[0].Name, check.Equals, "test_get_shared_nodes_2")
}

func (s *Suite) TestComplexSharingAcrossNamespaces(c *check.C) {
	n1, err := h.CreateNamespace("shared1")
	c.Assert(err, check.IsNil)

	n2, err := h.CreateNamespace("shared2")
	c.Assert(err, check.IsNil)

	n3, err := h.CreateNamespace("shared3")
	c.Assert(err, check.IsNil)

	pak1, err := h.CreatePreAuthKey(n1.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	pak2, err := h.CreatePreAuthKey(n2.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	pak3, err := h.CreatePreAuthKey(n3.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	pak4, err := h.CreatePreAuthKey(n1.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = h.GetMachine(n1.Name, "test_get_shared_nodes_1")
	c.Assert(err, check.NotNil)

	m1 := &Machine{
		ID:             0,
		MachineKey:     "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		NodeKey:        "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		DiscoKey:       "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		Name:           "test_get_shared_nodes_1",
		NamespaceID:    n1.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.1",
		AuthKeyID:      uint(pak1.ID),
	}
	h.db.Save(m1)

	_, err = h.GetMachine(n1.Name, m1.Name)
	c.Assert(err, check.IsNil)

	m2 := &Machine{
		ID:             1,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_2",
		NamespaceID:    n2.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.2",
		AuthKeyID:      uint(pak2.ID),
	}
	h.db.Save(m2)

	_, err = h.GetMachine(n2.Name, m2.Name)
	c.Assert(err, check.IsNil)

	m3 := &Machine{
		ID:             2,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_3",
		NamespaceID:    n3.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.3",
		AuthKeyID:      uint(pak3.ID),
	}
	h.db.Save(m3)

	_, err = h.GetMachine(n3.Name, m3.Name)
	c.Assert(err, check.IsNil)

	m4 := &Machine{
		ID:             3,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_4",
		NamespaceID:    n1.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.4",
		AuthKeyID:      uint(pak4.ID),
	}
	h.db.Save(m4)

	_, err = h.GetMachine(n1.Name, m4.Name)
	c.Assert(err, check.IsNil)

	p1s, err := h.getPeers(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(p1s), check.Equals, 1) // nodes 1 and 4
	c.Assert(p1s[0].Name, check.Equals, "test_get_shared_nodes_4")

	err = h.AddSharedMachineToNamespace(m2, n1)
	c.Assert(err, check.IsNil)

	p1sAfter, err := h.getPeers(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(p1sAfter), check.Equals, 2) // nodes 1, 2, 4
	c.Assert(p1sAfter[0].Name, check.Equals, "test_get_shared_nodes_2")
	c.Assert(p1sAfter[1].Name, check.Equals, "test_get_shared_nodes_4")

	node1shared, err := h.getShared(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(node1shared), check.Equals, 1) // nodes 1, 2, 4
	c.Assert(node1shared[0].Name, check.Equals, "test_get_shared_nodes_2")

	pAlone, err := h.getPeers(m3)
	c.Assert(err, check.IsNil)
	c.Assert(len(pAlone), check.Equals, 0) // node 3 is alone
}

func (s *Suite) TestDeleteSharedMachine(c *check.C) {
	n1, err := h.CreateNamespace("shared1")
	c.Assert(err, check.IsNil)

	n2, err := h.CreateNamespace("shared2")
	c.Assert(err, check.IsNil)

	n3, err := h.CreateNamespace("shared3")
	c.Assert(err, check.IsNil)

	pak1n1, err := h.CreatePreAuthKey(n1.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	pak2n2, err := h.CreatePreAuthKey(n2.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	pak3n3, err := h.CreatePreAuthKey(n3.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	pak4n1, err := h.CreatePreAuthKey(n1.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = h.GetMachine(n1.Name, "test_get_shared_nodes_1")
	c.Assert(err, check.NotNil)

	m1 := &Machine{
		ID:             0,
		MachineKey:     "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		NodeKey:        "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		DiscoKey:       "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		Name:           "test_get_shared_nodes_1",
		NamespaceID:    n1.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.1",
		AuthKeyID:      uint(pak1n1.ID),
	}
	h.db.Save(m1)

	_, err = h.GetMachine(n1.Name, m1.Name)
	c.Assert(err, check.IsNil)

	m2 := &Machine{
		ID:             1,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_2",
		NamespaceID:    n2.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.2",
		AuthKeyID:      uint(pak2n2.ID),
	}
	h.db.Save(m2)

	_, err = h.GetMachine(n2.Name, m2.Name)
	c.Assert(err, check.IsNil)

	m3 := &Machine{
		ID:             2,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_3",
		NamespaceID:    n3.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.3",
		AuthKeyID:      uint(pak3n3.ID),
	}
	h.db.Save(m3)

	_, err = h.GetMachine(n3.Name, m3.Name)
	c.Assert(err, check.IsNil)

	m4 := &Machine{
		ID:             3,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_4",
		NamespaceID:    n1.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.4",
		AuthKeyID:      uint(pak4n1.ID),
	}
	h.db.Save(m4)

	_, err = h.GetMachine(n1.Name, m4.Name)
	c.Assert(err, check.IsNil)

	p1s, err := h.getPeers(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(p1s), check.Equals, 1) // nodes 1 and 4
	c.Assert(p1s[0].Name, check.Equals, "test_get_shared_nodes_4")

	err = h.AddSharedMachineToNamespace(m2, n1)
	c.Assert(err, check.IsNil)

	p1sAfter, err := h.getPeers(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(p1sAfter), check.Equals, 2) // nodes 1, 2, 4
	c.Assert(p1sAfter[0].Name, check.Equals, "test_get_shared_nodes_2")
	c.Assert(p1sAfter[1].Name, check.Equals, "test_get_shared_nodes_4")

	node1shared, err := h.getShared(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(node1shared), check.Equals, 1) // nodes 1, 2, 4
	c.Assert(node1shared[0].Name, check.Equals, "test_get_shared_nodes_2")

	pAlone, err := h.getPeers(m3)
	c.Assert(err, check.IsNil)
	c.Assert(len(pAlone), check.Equals, 0) // node 3 is alone

	sharedMachines, err := h.ListSharedMachinesInNamespace(n1.Name)
	c.Assert(err, check.IsNil)
	c.Assert(len(*sharedMachines), check.Equals, 1)

	err = h.DeleteMachine(m2)
	c.Assert(err, check.IsNil)

	sharedMachines, err = h.ListSharedMachinesInNamespace(n1.Name)
	c.Assert(err, check.IsNil)
	c.Assert(len(*sharedMachines), check.Equals, 0)
}
