package headscale

import (
	"gopkg.in/check.v1"
)

func CreateNodeNamespace(
	c *check.C,
	namespace, node, key, ip string,
) (*Namespace, *Machine) {
	n1, err := h.CreateNamespace(namespace)
	c.Assert(err, check.IsNil)

	pak1, err := h.CreatePreAuthKey(n1.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = h.GetMachine(n1.Name, node)
	c.Assert(err, check.NotNil)

	m1 := &Machine{
		ID:             0,
		MachineKey:     key,
		NodeKey:        key,
		DiscoKey:       key,
		Name:           node,
		NamespaceID:    n1.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      ip,
		AuthKeyID:      uint(pak1.ID),
	}
	h.db.Save(m1)

	_, err = h.GetMachine(n1.Name, m1.Name)
	c.Assert(err, check.IsNil)

	return n1, m1
}

func (s *Suite) TestBasicSharedNodesInNamespace(c *check.C) {
	n1, m1 := CreateNodeNamespace(
		c,
		"shared1",
		"test_get_shared_nodes_1",
		"686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		"100.64.0.1",
	)
	_, m2 := CreateNodeNamespace(
		c,
		"shared2",
		"test_get_shared_nodes_2",
		"dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		"100.64.0.2",
	)

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
	n1, m1 := CreateNodeNamespace(
		c,
		"shared1",
		"test_get_shared_nodes_1",
		"686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		"100.64.0.1",
	)

	p1s, err := h.getPeers(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(p1s), check.Equals, 0)

	err = h.AddSharedMachineToNamespace(m1, n1)
	c.Assert(err, check.Equals, errorSameNamespace)
}

func (s *Suite) TestUnshare(c *check.C) {
	n1, m1 := CreateNodeNamespace(
		c,
		"shared1",
		"test_unshare_1",
		"686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		"100.64.0.1",
	)
	_, m2 := CreateNodeNamespace(
		c,
		"shared2",
		"test_unshare_2",
		"dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		"100.64.0.2",
	)

	p1s, err := h.getPeers(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(p1s), check.Equals, 0)

	err = h.AddSharedMachineToNamespace(m2, n1)
	c.Assert(err, check.IsNil)

	p1s, err = h.getShared(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(p1s), check.Equals, 1)

	err = h.RemoveSharedMachineFromNamespace(m2, n1)
	c.Assert(err, check.IsNil)

	p1s, err = h.getShared(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(p1s), check.Equals, 0)

	err = h.RemoveSharedMachineFromNamespace(m2, n1)
	c.Assert(err, check.Equals, errorMachineNotShared)

	err = h.RemoveSharedMachineFromNamespace(m1, n1)
	c.Assert(err, check.Equals, errorMachineNotShared)
}

func (s *Suite) TestAlreadyShared(c *check.C) {
	n1, m1 := CreateNodeNamespace(
		c,
		"shared1",
		"test_get_shared_nodes_1",
		"686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		"100.64.0.1",
	)
	_, m2 := CreateNodeNamespace(
		c,
		"shared2",
		"test_get_shared_nodes_2",
		"dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		"100.64.0.2",
	)

	p1s, err := h.getPeers(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(p1s), check.Equals, 0)

	err = h.AddSharedMachineToNamespace(m2, n1)
	c.Assert(err, check.IsNil)
	err = h.AddSharedMachineToNamespace(m2, n1)
	c.Assert(err, check.Equals, errorMachineAlreadyShared)
}

func (s *Suite) TestDoNotIncludeRoutesOnShared(c *check.C) {
	n1, m1 := CreateNodeNamespace(
		c,
		"shared1",
		"test_get_shared_nodes_1",
		"686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		"100.64.0.1",
	)
	_, m2 := CreateNodeNamespace(
		c,
		"shared2",
		"test_get_shared_nodes_2",
		"dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		"100.64.0.2",
	)

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
	n1, m1 := CreateNodeNamespace(
		c,
		"shared1",
		"test_get_shared_nodes_1",
		"686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		"100.64.0.1",
	)
	_, m2 := CreateNodeNamespace(
		c,
		"shared2",
		"test_get_shared_nodes_2",
		"dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		"100.64.0.2",
	)
	_, m3 := CreateNodeNamespace(
		c,
		"shared3",
		"test_get_shared_nodes_3",
		"6e704bee83eb93db6fc2c417d7882964cd3f8cc87082cbb645982e34020c76c8",
		"100.64.0.3",
	)

	pak4, err := h.CreatePreAuthKey(n1.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	m4 := &Machine{
		ID:             4,
		MachineKey:     "4c3e07c3ecd40e9c945bb6797557c451850691c0409740578325e17009dd298f",
		NodeKey:        "4c3e07c3ecd40e9c945bb6797557c451850691c0409740578325e17009dd298f",
		DiscoKey:       "4c3e07c3ecd40e9c945bb6797557c451850691c0409740578325e17009dd298f",
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
	c.Assert(len(p1s), check.Equals, 1) // node1 can see node4
	c.Assert(p1s[0].Name, check.Equals, m4.Name)

	err = h.AddSharedMachineToNamespace(m2, n1)
	c.Assert(err, check.IsNil)

	p1sAfter, err := h.getPeers(m1)
	c.Assert(err, check.IsNil)
	c.Assert(
		len(p1sAfter),
		check.Equals,
		2,
	) // node1 can see node2 (shared) and node4 (same namespace)
	c.Assert(p1sAfter[0].Name, check.Equals, m2.Name)
	c.Assert(p1sAfter[1].Name, check.Equals, m4.Name)

	node1shared, err := h.getShared(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(node1shared), check.Equals, 1) // node1 can see node2 as shared
	c.Assert(node1shared[0].Name, check.Equals, m2.Name)

	pAlone, err := h.getPeers(m3)
	c.Assert(err, check.IsNil)
	c.Assert(len(pAlone), check.Equals, 0) // node3 is alone

	pSharedTo, err := h.getPeers(m2)
	c.Assert(err, check.IsNil)
	c.Assert(
		len(pSharedTo),
		check.Equals,
		2,
	) // node2 should see node1 (sharedTo) and node4 (sharedTo), as is shared in namespace1
	c.Assert(pSharedTo[0].Name, check.Equals, m1.Name)
	c.Assert(pSharedTo[1].Name, check.Equals, m4.Name)
}

func (s *Suite) TestDeleteSharedMachine(c *check.C) {
	n1, m1 := CreateNodeNamespace(
		c,
		"shared1",
		"test_get_shared_nodes_1",
		"686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		"100.64.0.1",
	)
	_, m2 := CreateNodeNamespace(
		c,
		"shared2",
		"test_get_shared_nodes_2",
		"dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		"100.64.0.2",
	)
	_, m3 := CreateNodeNamespace(
		c,
		"shared3",
		"test_get_shared_nodes_3",
		"6e704bee83eb93db6fc2c417d7882964cd3f8cc87082cbb645982e34020c76c8",
		"100.64.0.3",
	)

	pak4n1, err := h.CreatePreAuthKey(n1.Name, false, false, nil)
	c.Assert(err, check.IsNil)
	m4 := &Machine{
		ID:             4,
		MachineKey:     "4c3e07c3ecd40e9c945bb6797557c451850691c0409740578325e17009dd298f",
		NodeKey:        "4c3e07c3ecd40e9c945bb6797557c451850691c0409740578325e17009dd298f",
		DiscoKey:       "4c3e07c3ecd40e9c945bb6797557c451850691c0409740578325e17009dd298f",
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
	c.Assert(p1s[0].Name, check.Equals, m4.Name)

	err = h.AddSharedMachineToNamespace(m2, n1)
	c.Assert(err, check.IsNil)

	p1sAfter, err := h.getPeers(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(p1sAfter), check.Equals, 2) // nodes 1, 2, 4
	c.Assert(p1sAfter[0].Name, check.Equals, m2.Name)
	c.Assert(p1sAfter[1].Name, check.Equals, m4.Name)

	node1shared, err := h.getShared(m1)
	c.Assert(err, check.IsNil)
	c.Assert(len(node1shared), check.Equals, 1) // nodes 1, 2, 4
	c.Assert(node1shared[0].Name, check.Equals, m2.Name)

	pAlone, err := h.getPeers(m3)
	c.Assert(err, check.IsNil)
	c.Assert(len(pAlone), check.Equals, 0) // node 3 is alone

	sharedMachines, err := h.ListSharedMachinesInNamespace(n1.Name)
	c.Assert(err, check.IsNil)
	c.Assert(len(sharedMachines), check.Equals, 1)

	err = h.DeleteMachine(m2)
	c.Assert(err, check.IsNil)

	sharedMachines, err = h.ListSharedMachinesInNamespace(n1.Name)
	c.Assert(err, check.IsNil)
	c.Assert(len(sharedMachines), check.Equals, 0)
}
