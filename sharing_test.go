package headscale

import (
	"gopkg.in/check.v1"
)

func CreateNodeNamespace(
	c *check.C,
	namespaceName, node, key, ip string,
) (*Namespace, *Machine) {
	namespace, err := app.CreateNamespace(namespaceName)
	c.Assert(err, check.IsNil)

	pak1, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine(namespace.Name, node)
	c.Assert(err, check.NotNil)

	machine := &Machine{
		ID:             0,
		MachineKey:     key,
		NodeKey:        key,
		DiscoKey:       key,
		Name:           node,
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      ip,
		AuthKeyID:      uint(pak1.ID),
	}
	app.db.Save(machine)

	_, err = app.GetMachine(namespace.Name, machine.Name)
	c.Assert(err, check.IsNil)

	return namespace, machine
}

func (s *Suite) TestBasicSharedNodesInNamespace(c *check.C) {
	namespace1, machine1 := CreateNodeNamespace(
		c,
		"shared1",
		"test_get_shared_nodes_1",
		"686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		"100.64.0.1",
	)
	_, machine2 := CreateNodeNamespace(
		c,
		"shared2",
		"test_get_shared_nodes_2",
		"dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		"100.64.0.2",
	)

	peersOfMachine1BeforeShared, err := app.getPeers(machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(peersOfMachine1BeforeShared), check.Equals, 0)

	err = app.AddSharedMachineToNamespace(machine2, namespace1)
	c.Assert(err, check.IsNil)

	peersOfMachine1AfterShared, err := app.getPeers(machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(peersOfMachine1AfterShared), check.Equals, 1)
	c.Assert(peersOfMachine1AfterShared[0].ID, check.Equals, machine2.ID)
}

func (s *Suite) TestSameNamespace(c *check.C) {
	namespace1, machine1 := CreateNodeNamespace(
		c,
		"shared1",
		"test_get_shared_nodes_1",
		"686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		"100.64.0.1",
	)

	peersOfMachine1BeforeShare, err := app.getPeers(machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(peersOfMachine1BeforeShare), check.Equals, 0)

	err = app.AddSharedMachineToNamespace(machine1, namespace1)
	c.Assert(err, check.Equals, errSameNamespace)
}

func (s *Suite) TestUnshare(c *check.C) {
	namespace1, machine1 := CreateNodeNamespace(
		c,
		"shared1",
		"test_unshare_1",
		"686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		"100.64.0.1",
	)
	_, machine2 := CreateNodeNamespace(
		c,
		"shared2",
		"test_unshare_2",
		"dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		"100.64.0.2",
	)

	peersOfMachine1BeforeShare, err := app.getPeers(machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(peersOfMachine1BeforeShare), check.Equals, 0)

	err = app.AddSharedMachineToNamespace(machine2, namespace1)
	c.Assert(err, check.IsNil)

	peersOfMachine1BeforeShare, err = app.getShared(machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(peersOfMachine1BeforeShare), check.Equals, 1)

	err = app.RemoveSharedMachineFromNamespace(machine2, namespace1)
	c.Assert(err, check.IsNil)

	peersOfMachine1BeforeShare, err = app.getShared(machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(peersOfMachine1BeforeShare), check.Equals, 0)

	err = app.RemoveSharedMachineFromNamespace(machine2, namespace1)
	c.Assert(err, check.Equals, errMachineNotShared)

	err = app.RemoveSharedMachineFromNamespace(machine1, namespace1)
	c.Assert(err, check.Equals, errMachineNotShared)
}

func (s *Suite) TestAlreadyShared(c *check.C) {
	namespace1, machine1 := CreateNodeNamespace(
		c,
		"shared1",
		"test_get_shared_nodes_1",
		"686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		"100.64.0.1",
	)
	_, machine2 := CreateNodeNamespace(
		c,
		"shared2",
		"test_get_shared_nodes_2",
		"dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		"100.64.0.2",
	)

	peersOfMachine1BeforeShare, err := app.getPeers(machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(peersOfMachine1BeforeShare), check.Equals, 0)

	err = app.AddSharedMachineToNamespace(machine2, namespace1)
	c.Assert(err, check.IsNil)
	err = app.AddSharedMachineToNamespace(machine2, namespace1)
	c.Assert(err, check.Equals, errMachineAlreadyShared)
}

func (s *Suite) TestDoNotIncludeRoutesOnShared(c *check.C) {
	namespace1, machine1 := CreateNodeNamespace(
		c,
		"shared1",
		"test_get_shared_nodes_1",
		"686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		"100.64.0.1",
	)
	_, machine2 := CreateNodeNamespace(
		c,
		"shared2",
		"test_get_shared_nodes_2",
		"dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		"100.64.0.2",
	)

	peersOfMachine1BeforeShare, err := app.getPeers(machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(peersOfMachine1BeforeShare), check.Equals, 0)

	err = app.AddSharedMachineToNamespace(machine2, namespace1)
	c.Assert(err, check.IsNil)

	peersOfMachine1AfterShare, err := app.getPeers(machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(peersOfMachine1AfterShare), check.Equals, 1)
	c.Assert(peersOfMachine1AfterShare[0].Name, check.Equals, "test_get_shared_nodes_2")
}

func (s *Suite) TestComplexSharingAcrossNamespaces(c *check.C) {
	namespace1, machine1 := CreateNodeNamespace(
		c,
		"shared1",
		"test_get_shared_nodes_1",
		"686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		"100.64.0.1",
	)
	_, machine2 := CreateNodeNamespace(
		c,
		"shared2",
		"test_get_shared_nodes_2",
		"dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		"100.64.0.2",
	)
	_, machine3 := CreateNodeNamespace(
		c,
		"shared3",
		"test_get_shared_nodes_3",
		"6e704bee83eb93db6fc2c417d7882964cd3f8cc87082cbb645982e34020c76c8",
		"100.64.0.3",
	)

	pak4, err := app.CreatePreAuthKey(namespace1.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	machine4 := &Machine{
		ID:             4,
		MachineKey:     "4c3e07c3ecd40e9c945bb6797557c451850691c0409740578325e17009dd298f",
		NodeKey:        "4c3e07c3ecd40e9c945bb6797557c451850691c0409740578325e17009dd298f",
		DiscoKey:       "4c3e07c3ecd40e9c945bb6797557c451850691c0409740578325e17009dd298f",
		Name:           "test_get_shared_nodes_4",
		NamespaceID:    namespace1.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.4",
		AuthKeyID:      uint(pak4.ID),
	}
	app.db.Save(machine4)

	_, err = app.GetMachine(namespace1.Name, machine4.Name)
	c.Assert(err, check.IsNil)

	peersOfMachine1BeforeShare, err := app.getPeers(machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(peersOfMachine1BeforeShare), check.Equals, 1) // node1 can see node4
	c.Assert(peersOfMachine1BeforeShare[0].Name, check.Equals, machine4.Name)

	err = app.AddSharedMachineToNamespace(machine2, namespace1)
	c.Assert(err, check.IsNil)

	peersOfMachine1AfterShare, err := app.getPeers(machine1)
	c.Assert(err, check.IsNil)
	c.Assert(
		len(peersOfMachine1AfterShare),
		check.Equals,
		2,
	) // node1 can see node2 (shared) and node4 (same namespace)
	c.Assert(peersOfMachine1AfterShare[0].Name, check.Equals, machine2.Name)
	c.Assert(peersOfMachine1AfterShare[1].Name, check.Equals, machine4.Name)

	sharedOfMachine1, err := app.getShared(machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(sharedOfMachine1), check.Equals, 1) // node1 can see node2 as shared
	c.Assert(sharedOfMachine1[0].Name, check.Equals, machine2.Name)

	peersOfMachine3, err := app.getPeers(machine3)
	c.Assert(err, check.IsNil)
	c.Assert(len(peersOfMachine3), check.Equals, 0) // node3 is alone

	peersOfMachine2, err := app.getPeers(machine2)
	c.Assert(err, check.IsNil)
	c.Assert(
		len(peersOfMachine2),
		check.Equals,
		2,
	) // node2 should see node1 (sharedTo) and node4 (sharedTo), as is shared in namespace1
	c.Assert(peersOfMachine2[0].Name, check.Equals, machine1.Name)
	c.Assert(peersOfMachine2[1].Name, check.Equals, machine4.Name)
}

func (s *Suite) TestDeleteSharedMachine(c *check.C) {
	namespace1, machine1 := CreateNodeNamespace(
		c,
		"shared1",
		"test_get_shared_nodes_1",
		"686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		"100.64.0.1",
	)
	_, machine2 := CreateNodeNamespace(
		c,
		"shared2",
		"test_get_shared_nodes_2",
		"dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		"100.64.0.2",
	)
	_, machine3 := CreateNodeNamespace(
		c,
		"shared3",
		"test_get_shared_nodes_3",
		"6e704bee83eb93db6fc2c417d7882964cd3f8cc87082cbb645982e34020c76c8",
		"100.64.0.3",
	)

	pak4n1, err := app.CreatePreAuthKey(namespace1.Name, false, false, nil)
	c.Assert(err, check.IsNil)
	machine4 := &Machine{
		ID:             4,
		MachineKey:     "4c3e07c3ecd40e9c945bb6797557c451850691c0409740578325e17009dd298f",
		NodeKey:        "4c3e07c3ecd40e9c945bb6797557c451850691c0409740578325e17009dd298f",
		DiscoKey:       "4c3e07c3ecd40e9c945bb6797557c451850691c0409740578325e17009dd298f",
		Name:           "test_get_shared_nodes_4",
		NamespaceID:    namespace1.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.4",
		AuthKeyID:      uint(pak4n1.ID),
	}
	app.db.Save(machine4)

	_, err = app.GetMachine(namespace1.Name, machine4.Name)
	c.Assert(err, check.IsNil)

	peersOfMachine1BeforeShare, err := app.getPeers(machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(peersOfMachine1BeforeShare), check.Equals, 1) // nodes 1 and 4
	c.Assert(peersOfMachine1BeforeShare[0].Name, check.Equals, machine4.Name)

	err = app.AddSharedMachineToNamespace(machine2, namespace1)
	c.Assert(err, check.IsNil)

	peersOfMachine1AfterShare, err := app.getPeers(machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(peersOfMachine1AfterShare), check.Equals, 2) // nodes 1, 2, 4
	c.Assert(peersOfMachine1AfterShare[0].Name, check.Equals, machine2.Name)
	c.Assert(peersOfMachine1AfterShare[1].Name, check.Equals, machine4.Name)

	sharedOfMachine1, err := app.getShared(machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(sharedOfMachine1), check.Equals, 1) // nodes 1, 2, 4
	c.Assert(sharedOfMachine1[0].Name, check.Equals, machine2.Name)

	peersOfMachine3, err := app.getPeers(machine3)
	c.Assert(err, check.IsNil)
	c.Assert(len(peersOfMachine3), check.Equals, 0) // node 3 is alone

	sharedMachinesInNamespace1, err := app.ListSharedMachinesInNamespace(
		namespace1.Name,
	)
	c.Assert(err, check.IsNil)
	c.Assert(len(sharedMachinesInNamespace1), check.Equals, 1)

	err = app.DeleteMachine(machine2)
	c.Assert(err, check.IsNil)

	sharedMachinesInNamespace1, err = app.ListSharedMachinesInNamespace(namespace1.Name)
	c.Assert(err, check.IsNil)
	c.Assert(len(sharedMachinesInNamespace1), check.Equals, 0)
}
