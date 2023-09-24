package db

import (
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"gopkg.in/check.v1"
	"gorm.io/gorm"
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

	node := types.Node{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	db.db.Save(&node)

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

func (s *Suite) TestSetMachineUser(c *check.C) {
	oldUser, err := db.CreateUser("old")
	c.Assert(err, check.IsNil)

	newUser, err := db.CreateUser("new")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(oldUser.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	node := types.Node{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testnode",
		UserID:         oldUser.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	db.db.Save(&node)
	c.Assert(node.UserID, check.Equals, oldUser.ID)

	err = db.AssignNodeToUser(&node, newUser.Name)
	c.Assert(err, check.IsNil)
	c.Assert(node.UserID, check.Equals, newUser.ID)
	c.Assert(node.User.Name, check.Equals, newUser.Name)

	err = db.AssignNodeToUser(&node, "non-existing-user")
	c.Assert(err, check.Equals, ErrUserNotFound)

	err = db.AssignNodeToUser(&node, newUser.Name)
	c.Assert(err, check.IsNil)
	c.Assert(node.UserID, check.Equals, newUser.ID)
	c.Assert(node.User.Name, check.Equals, newUser.Name)
}
