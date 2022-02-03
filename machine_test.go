package headscale

import (
	"fmt"
	"strconv"
	"time"

	"gopkg.in/check.v1"
	"inet.af/netaddr"
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
		RegisterMethod: RegisterMethodAuthKey,
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
		RegisterMethod: RegisterMethodAuthKey,
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
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(1),
	}
	app.db.Save(&machine)

	err = app.DeleteMachine(&machine)
	c.Assert(err, check.IsNil)

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
		RegisterMethod: RegisterMethodAuthKey,
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
			RegisterMethod: RegisterMethodAuthKey,
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

func (s *Suite) TestGetACLFilteredPeers(c *check.C) {
	type base struct {
		namespace *Namespace
		key       *PreAuthKey
	}

	var stor []base

	for _, name := range []string{"test", "admin"} {
		namespace, err := app.CreateNamespace(name)
		c.Assert(err, check.IsNil)
		pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
		c.Assert(err, check.IsNil)
		stor = append(stor, base{namespace, pak})

	}

	_, err := app.GetMachineByID(0)
	c.Assert(err, check.NotNil)

	for index := 0; index <= 10; index++ {
		machine := Machine{
			ID:             uint64(index),
			MachineKey:     "foo" + strconv.Itoa(index),
			NodeKey:        "bar" + strconv.Itoa(index),
			DiscoKey:       "faa" + strconv.Itoa(index),
			IPAddress:      fmt.Sprintf("100.64.0.%v", strconv.Itoa(index+1)),
			Name:           "testmachine" + strconv.Itoa(index),
			NamespaceID:    stor[index%2].namespace.ID,
			Registered:     true,
			RegisterMethod: RegisterMethodAuthKey,
			AuthKeyID:      uint(stor[index%2].key.ID),
		}
		app.db.Save(&machine)
	}

	app.aclPolicy = &ACLPolicy{
		Groups: map[string][]string{
			"group:test": {"admin"},
		},
		Hosts:     map[string]netaddr.IPPrefix{},
		TagOwners: map[string][]string{},
		ACLs: []ACL{
			{Action: "accept", Users: []string{"admin"}, Ports: []string{"*:*"}},
			{Action: "accept", Users: []string{"test"}, Ports: []string{"test:*"}},
		},
		Tests: []ACLTest{},
	}

	err = app.UpdateACLRules()
	c.Assert(err, check.IsNil)

	adminMachine, err := app.GetMachineByID(1)
	c.Logf("Machine(%v), namespace: %v", adminMachine.Name, adminMachine.Namespace)
	c.Assert(err, check.IsNil)

	testMachine, err := app.GetMachineByID(2)
	c.Logf("Machine(%v), namespace: %v", testMachine.Name, testMachine.Namespace)
	c.Assert(err, check.IsNil)

	_, err = testMachine.GetHostInfo()
	c.Assert(err, check.IsNil)

	peersOfTestMachine, err := app.getFilteredByACLPeers(testMachine)
	c.Assert(err, check.IsNil)

	peersOfAdminMachine, err := app.getFilteredByACLPeers(adminMachine)
	c.Assert(err, check.IsNil)

	c.Log(peersOfTestMachine)
	c.Assert(len(peersOfTestMachine), check.Equals, 4)
	c.Assert(peersOfTestMachine[0].Name, check.Equals, "testmachine4")
	c.Assert(peersOfTestMachine[1].Name, check.Equals, "testmachine6")
	c.Assert(peersOfTestMachine[3].Name, check.Equals, "testmachine10")

	c.Log(peersOfAdminMachine)
	c.Assert(len(peersOfAdminMachine), check.Equals, 9)
	c.Assert(peersOfAdminMachine[0].Name, check.Equals, "testmachine2")
	c.Assert(peersOfAdminMachine[2].Name, check.Equals, "testmachine4")
	c.Assert(peersOfAdminMachine[5].Name, check.Equals, "testmachine7")
}

func (s *Suite) TestExpireMachine(c *check.C) {
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
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		Expiry:         &time.Time{},
	}
	app.db.Save(machine)

	machineFromDB, err := app.GetMachine("test", "testmachine")
	c.Assert(err, check.IsNil)

	c.Assert(machineFromDB.isExpired(), check.Equals, false)

	app.ExpireMachine(machineFromDB)

	c.Assert(machineFromDB.isExpired(), check.Equals, true)
}

func (s *Suite) TestSerdeAddressStrignSlice(c *check.C) {
	input := MachineAddresses([]netaddr.IP{
		netaddr.MustParseIP("192.0.2.1"),
		netaddr.MustParseIP("2001:db8::1"),
	})
	serialized, err := input.Value()
	c.Assert(err, check.IsNil)
	if serial, ok := serialized.(string); ok {
		c.Assert(serial, check.Equals, "192.0.2.1,2001:db8::1")
	}

	var deserialized MachineAddresses
	err = deserialized.Scan(serialized)
	c.Assert(err, check.IsNil)

	c.Assert(len(deserialized), check.Equals, len(input))
	for i := range deserialized {
		c.Assert(deserialized[i], check.Equals, input[i])
	}
}
