package headscale

import (
	"github.com/rs/zerolog/log"
	"gopkg.in/check.v1"
	"gorm.io/gorm"
)

func (s *Suite) TestCreateAndDestroyNamespace(c *check.C) {
	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)
	c.Assert(namespace.Name, check.Equals, "test")

	namespaces, err := app.ListNamespaces()
	c.Assert(err, check.IsNil)
	c.Assert(len(namespaces), check.Equals, 1)

	err = app.DestroyNamespace("test")
	c.Assert(err, check.IsNil)

	_, err = app.GetNamespace("test")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestDestroyNamespaceErrors(c *check.C) {
	err := app.DestroyNamespace("test")
	c.Assert(err, check.Equals, errNamespaceNotFound)

	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	err = app.DestroyNamespace("test")
	c.Assert(err, check.IsNil)

	result := app.db.Preload("Namespace").First(&pak, "key = ?", pak.Key)
	// destroying a namespace also deletes all associated preauthkeys
	c.Assert(result.Error, check.Equals, gorm.ErrRecordNotFound)

	namespace, err = app.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err = app.CreatePreAuthKey(namespace.Name, false, false, nil)
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
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

	err = app.DestroyNamespace("test")
	c.Assert(err, check.Equals, errNamespaceNotEmptyOfNodes)
}

func (s *Suite) TestRenameNamespace(c *check.C) {
	namespaceTest, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)
	c.Assert(namespaceTest.Name, check.Equals, "test")

	namespaces, err := app.ListNamespaces()
	c.Assert(err, check.IsNil)
	c.Assert(len(namespaces), check.Equals, 1)

	err = app.RenameNamespace("test", "test_renamed")
	c.Assert(err, check.IsNil)

	_, err = app.GetNamespace("test")
	c.Assert(err, check.Equals, errNamespaceNotFound)

	_, err = app.GetNamespace("test_renamed")
	c.Assert(err, check.IsNil)

	err = app.RenameNamespace("test_does_not_exit", "test")
	c.Assert(err, check.Equals, errNamespaceNotFound)

	namespaceTest2, err := app.CreateNamespace("test2")
	c.Assert(err, check.IsNil)
	c.Assert(namespaceTest2.Name, check.Equals, "test2")

	err = app.RenameNamespace("test2", "test_renamed")
	c.Assert(err, check.Equals, errNamespaceExists)
}

func (s *Suite) TestGetMapResponseUserProfiles(c *check.C) {
	namespaceShared1, err := app.CreateNamespace("shared1")
	c.Assert(err, check.IsNil)

	namespaceShared2, err := app.CreateNamespace("shared2")
	c.Assert(err, check.IsNil)

	namespaceShared3, err := app.CreateNamespace("shared3")
	c.Assert(err, check.IsNil)

	preAuthKeyShared1, err := app.CreatePreAuthKey(
		namespaceShared1.Name,
		false,
		false,
		nil,
	)
	c.Assert(err, check.IsNil)

	preAuthKeyShared2, err := app.CreatePreAuthKey(
		namespaceShared2.Name,
		false,
		false,
		nil,
	)
	c.Assert(err, check.IsNil)

	preAuthKeyShared3, err := app.CreatePreAuthKey(
		namespaceShared3.Name,
		false,
		false,
		nil,
	)
	c.Assert(err, check.IsNil)

	preAuthKey2Shared1, err := app.CreatePreAuthKey(
		namespaceShared1.Name,
		false,
		false,
		nil,
	)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine(namespaceShared1.Name, "test_get_shared_nodes_1")
	c.Assert(err, check.NotNil)

	machineInShared1 := &Machine{
		ID:             1,
		MachineKey:     "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		NodeKey:        "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		DiscoKey:       "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		Name:           "test_get_shared_nodes_1",
		NamespaceID:    namespaceShared1.ID,
		Namespace:      *namespaceShared1,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.1",
		AuthKeyID:      uint(preAuthKeyShared1.ID),
	}
	app.db.Save(machineInShared1)

	_, err = app.GetMachine(namespaceShared1.Name, machineInShared1.Name)
	c.Assert(err, check.IsNil)

	machineInShared2 := &Machine{
		ID:             2,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_2",
		NamespaceID:    namespaceShared2.ID,
		Namespace:      *namespaceShared2,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.2",
		AuthKeyID:      uint(preAuthKeyShared2.ID),
	}
	app.db.Save(machineInShared2)

	_, err = app.GetMachine(namespaceShared2.Name, machineInShared2.Name)
	c.Assert(err, check.IsNil)

	machineInShared3 := &Machine{
		ID:             3,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_3",
		NamespaceID:    namespaceShared3.ID,
		Namespace:      *namespaceShared3,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.3",
		AuthKeyID:      uint(preAuthKeyShared3.ID),
	}
	app.db.Save(machineInShared3)

	_, err = app.GetMachine(namespaceShared3.Name, machineInShared3.Name)
	c.Assert(err, check.IsNil)

	machine2InShared1 := &Machine{
		ID:             4,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_4",
		NamespaceID:    namespaceShared1.ID,
		Namespace:      *namespaceShared1,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.4",
		AuthKeyID:      uint(preAuthKey2Shared1.ID),
	}
	app.db.Save(machine2InShared1)

	err = app.AddSharedMachineToNamespace(machineInShared2, namespaceShared1)
	c.Assert(err, check.IsNil)
	peersOfMachine1InShared1, err := app.getPeers(machineInShared1)
	c.Assert(err, check.IsNil)

	userProfiles := getMapResponseUserProfiles(
		*machineInShared1,
		peersOfMachine1InShared1,
	)

	log.Trace().Msgf("userProfiles %#v", userProfiles)
	c.Assert(len(userProfiles), check.Equals, 2)

	found := false
	for _, userProfiles := range userProfiles {
		if userProfiles.DisplayName == namespaceShared1.Name {
			found = true

			break
		}
	}
	c.Assert(found, check.Equals, true)

	found = false
	for _, userProfile := range userProfiles {
		if userProfile.DisplayName == namespaceShared2.Name {
			found = true

			break
		}
	}
	c.Assert(found, check.Equals, true)
}
