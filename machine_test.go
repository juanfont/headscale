package headscale

import (
	"encoding/json"
	"strconv"

	"gopkg.in/check.v1"
)

func (s *Suite) TestGetMachine(c *check.C) {
	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("test", "testmachine")
	c.Assert(err, check.NotNil)

	machine := &Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(machine)

	machineFromDB, err := app.GetMachine("test", "testmachine")
	c.Assert(err, check.IsNil)

	_, err = machineFromDB.GetHostInfo()
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetMachineByID(c *check.C) {
	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachineByID(0)
	c.Assert(err, check.NotNil)

	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

	machineByID, err := app.GetMachineByID(0)
	c.Assert(err, check.IsNil)

	_, err = machineByID.GetHostInfo()
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestDeleteMachine(c *check.C) {
	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)
	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		AuthKeyID:      uint(1),
	}
	app.db.Save(&machine)

	err = app.DeleteMachine(&machine)
	c.Assert(err, check.IsNil)

	namespacesPendingUpdates, err := app.getValue("namespaces_pending_updates")
	c.Assert(err, check.IsNil)

	names := []string{}
	err = json.Unmarshal([]byte(namespacesPendingUpdates), &names)
	c.Assert(err, check.IsNil)
	c.Assert(names, check.DeepEquals, []string{namespace.Name})

	app.checkForNamespacesPendingUpdates()

	namespacesPendingUpdates, _ = app.getValue("namespaces_pending_updates")
	c.Assert(namespacesPendingUpdates, check.Equals, "")
	_, err = app.GetMachine(namespace.Name, "testmachine")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestHardDeleteMachine(c *check.C) {
	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)
	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine3",
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		AuthKeyID:      uint(1),
	}
	app.db.Save(&machine)

	err = app.HardDeleteMachine(&machine)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine(namespace.Name, "testmachine3")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestGetDirectPeers(c *check.C) {
	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachineByID(0)
	c.Assert(err, check.NotNil)

	for index := 0; index <= 10; index++ {
		machine := Machine{
			ID:             uint64(index),
			MachineKey:     "foo" + strconv.Itoa(index),
			NodeKey:        "bar" + strconv.Itoa(index),
			DiscoKey:       "faa" + strconv.Itoa(index),
			Name:           "testmachine" + strconv.Itoa(index),
			NamespaceID:    namespace.ID,
			Registered:     true,
			RegisterMethod: "authKey",
			AuthKeyID:      uint(pak.ID),
		}
		app.db.Save(&machine)
	}

	machine0ByID, err := app.GetMachineByID(0)
	c.Assert(err, check.IsNil)

	_, err = machine0ByID.GetHostInfo()
	c.Assert(err, check.IsNil)

	peersOfMachine0, err := app.getDirectPeers(machine0ByID)
	c.Assert(err, check.IsNil)

	c.Assert(len(peersOfMachine0), check.Equals, 9)
	c.Assert(peersOfMachine0[0].Name, check.Equals, "testmachine2")
	c.Assert(peersOfMachine0[5].Name, check.Equals, "testmachine7")
	c.Assert(peersOfMachine0[8].Name, check.Equals, "testmachine10")
}
