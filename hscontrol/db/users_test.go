package db

import (
	"net/netip"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"gopkg.in/check.v1"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

func (s *Suite) TestCreateAndDestroyUser(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)
	c.Assert(user.Name, check.Equals, "test")

	users, err := db.ListUsers()
	c.Assert(err, check.IsNil)
	c.Assert(len(users), check.Equals, 1)

	err = db.DestroyUser("test")
	c.Assert(err, check.IsNil)

	_, err = db.GetUser("test")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestDestroyUserErrors(c *check.C) {
	err := db.DestroyUser("test")
	c.Assert(err, check.Equals, ErrUserNotFound)

	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	err = db.DestroyUser("test")
	c.Assert(err, check.IsNil)

	result := db.db.Preload("User").First(&pak, "key = ?", pak.Key)
	// destroying a user also deletes all associated preauthkeys
	c.Assert(result.Error, check.Equals, gorm.ErrRecordNotFound)

	user, err = db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err = db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	machine := types.Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	db.db.Save(&machine)

	err = db.DestroyUser("test")
	c.Assert(err, check.Equals, ErrUserStillHasNodes)
}

func (s *Suite) TestRenameUser(c *check.C) {
	userTest, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)
	c.Assert(userTest.Name, check.Equals, "test")

	users, err := db.ListUsers()
	c.Assert(err, check.IsNil)
	c.Assert(len(users), check.Equals, 1)

	err = db.RenameUser("test", "test-renamed")
	c.Assert(err, check.IsNil)

	_, err = db.GetUser("test")
	c.Assert(err, check.Equals, ErrUserNotFound)

	_, err = db.GetUser("test-renamed")
	c.Assert(err, check.IsNil)

	err = db.RenameUser("test-does-not-exit", "test")
	c.Assert(err, check.Equals, ErrUserNotFound)

	userTest2, err := db.CreateUser("test2")
	c.Assert(err, check.IsNil)
	c.Assert(userTest2.Name, check.Equals, "test2")

	err = db.RenameUser("test2", "test-renamed")
	c.Assert(err, check.Equals, ErrUserExists)
}

func (s *Suite) TestGetMapResponseUserProfiles(c *check.C) {
	userShared1, err := db.CreateUser("shared1")
	c.Assert(err, check.IsNil)

	userShared2, err := db.CreateUser("shared2")
	c.Assert(err, check.IsNil)

	userShared3, err := db.CreateUser("shared3")
	c.Assert(err, check.IsNil)

	preAuthKeyShared1, err := db.CreatePreAuthKey(
		userShared1.Name,
		false,
		false,
		nil,
		nil,
	)
	c.Assert(err, check.IsNil)

	preAuthKeyShared2, err := db.CreatePreAuthKey(
		userShared2.Name,
		false,
		false,
		nil,
		nil,
	)
	c.Assert(err, check.IsNil)

	preAuthKeyShared3, err := db.CreatePreAuthKey(
		userShared3.Name,
		false,
		false,
		nil,
		nil,
	)
	c.Assert(err, check.IsNil)

	preAuthKey2Shared1, err := db.CreatePreAuthKey(
		userShared1.Name,
		false,
		false,
		nil,
		nil,
	)
	c.Assert(err, check.IsNil)

	_, err = db.GetMachine(userShared1.Name, "test_get_shared_nodes_1")
	c.Assert(err, check.NotNil)

	machineInShared1 := &types.Machine{
		ID:             1,
		MachineKey:     "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		NodeKey:        "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		DiscoKey:       "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		Hostname:       "test_get_shared_nodes_1",
		UserID:         userShared1.ID,
		User:           *userShared1,
		RegisterMethod: util.RegisterMethodAuthKey,
		IPAddresses:    []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		AuthKeyID:      uint(preAuthKeyShared1.ID),
	}
	db.db.Save(machineInShared1)

	_, err = db.GetMachine(userShared1.Name, machineInShared1.Hostname)
	c.Assert(err, check.IsNil)

	machineInShared2 := &types.Machine{
		ID:             2,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Hostname:       "test_get_shared_nodes_2",
		UserID:         userShared2.ID,
		User:           *userShared2,
		RegisterMethod: util.RegisterMethodAuthKey,
		IPAddresses:    []netip.Addr{netip.MustParseAddr("100.64.0.2")},
		AuthKeyID:      uint(preAuthKeyShared2.ID),
	}
	db.db.Save(machineInShared2)

	_, err = db.GetMachine(userShared2.Name, machineInShared2.Hostname)
	c.Assert(err, check.IsNil)

	machineInShared3 := &types.Machine{
		ID:             3,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Hostname:       "test_get_shared_nodes_3",
		UserID:         userShared3.ID,
		User:           *userShared3,
		RegisterMethod: util.RegisterMethodAuthKey,
		IPAddresses:    []netip.Addr{netip.MustParseAddr("100.64.0.3")},
		AuthKeyID:      uint(preAuthKeyShared3.ID),
	}
	db.db.Save(machineInShared3)

	_, err = db.GetMachine(userShared3.Name, machineInShared3.Hostname)
	c.Assert(err, check.IsNil)

	machine2InShared1 := &types.Machine{
		ID:             4,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Hostname:       "test_get_shared_nodes_4",
		UserID:         userShared1.ID,
		User:           *userShared1,
		RegisterMethod: util.RegisterMethodAuthKey,
		IPAddresses:    []netip.Addr{netip.MustParseAddr("100.64.0.4")},
		AuthKeyID:      uint(preAuthKey2Shared1.ID),
	}
	db.db.Save(machine2InShared1)

	peersOfMachine1InShared1, err := db.getPeers([]tailcfg.FilterRule{}, machineInShared1)
	c.Assert(err, check.IsNil)

	userProfiles := db.GetMapResponseUserProfiles(
		*machineInShared1,
		peersOfMachine1InShared1,
	)

	c.Assert(len(userProfiles), check.Equals, 3)

	found := false
	for _, userProfiles := range userProfiles {
		if userProfiles.DisplayName == userShared1.Name {
			found = true

			break
		}
	}
	c.Assert(found, check.Equals, true)

	found = false
	for _, userProfile := range userProfiles {
		if userProfile.DisplayName == userShared2.Name {
			found = true

			break
		}
	}
	c.Assert(found, check.Equals, true)
}

func (s *Suite) TestSetMachineUser(c *check.C) {
	oldUser, err := db.CreateUser("old")
	c.Assert(err, check.IsNil)

	newUser, err := db.CreateUser("new")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(oldUser.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	machine := types.Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         oldUser.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	db.db.Save(&machine)
	c.Assert(machine.UserID, check.Equals, oldUser.ID)

	err = db.SetMachineUser(&machine, newUser.Name)
	c.Assert(err, check.IsNil)
	c.Assert(machine.UserID, check.Equals, newUser.ID)
	c.Assert(machine.User.Name, check.Equals, newUser.Name)

	err = db.SetMachineUser(&machine, "non-existing-user")
	c.Assert(err, check.Equals, ErrUserNotFound)

	err = db.SetMachineUser(&machine, newUser.Name)
	c.Assert(err, check.IsNil)
	c.Assert(machine.UserID, check.Equals, newUser.ID)
	c.Assert(machine.User.Name, check.Equals, newUser.Name)
}
