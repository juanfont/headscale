package db

import (
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"gopkg.in/check.v1"
)

func (*Suite) TestCreatePreAuthKey(c *check.C) {
	_, err := db.CreatePreAuthKey("bogus", true, false, nil, nil)

	c.Assert(err, check.NotNil)

	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	key, err := db.CreatePreAuthKey(user.Name, true, false, nil, nil)
	c.Assert(err, check.IsNil)

	// Did we get a valid key?
	c.Assert(key.Key, check.NotNil)
	c.Assert(len(key.Key), check.Equals, 48)

	// Make sure the User association is populated
	c.Assert(key.User.Name, check.Equals, user.Name)

	_, err = db.ListPreAuthKeys("bogus")
	c.Assert(err, check.NotNil)

	keys, err := db.ListPreAuthKeys(user.Name)
	c.Assert(err, check.IsNil)
	c.Assert(len(keys), check.Equals, 1)

	// Make sure the User association is populated
	c.Assert((keys)[0].User.Name, check.Equals, user.Name)
}

func (*Suite) TestExpiredPreAuthKey(c *check.C) {
	user, err := db.CreateUser("test2")
	c.Assert(err, check.IsNil)

	now := time.Now()
	pak, err := db.CreatePreAuthKey(user.Name, true, false, &now, nil)
	c.Assert(err, check.IsNil)

	key, err := db.ValidatePreAuthKey(pak.Key)
	c.Assert(err, check.Equals, ErrPreAuthKeyExpired)
	c.Assert(key, check.IsNil)
}

func (*Suite) TestPreAuthKeyDoesNotExist(c *check.C) {
	key, err := db.ValidatePreAuthKey("potatoKey")
	c.Assert(err, check.Equals, ErrPreAuthKeyNotFound)
	c.Assert(key, check.IsNil)
}

func (*Suite) TestValidateKeyOk(c *check.C) {
	user, err := db.CreateUser("test3")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, true, false, nil, nil)
	c.Assert(err, check.IsNil)

	key, err := db.ValidatePreAuthKey(pak.Key)
	c.Assert(err, check.IsNil)
	c.Assert(key.ID, check.Equals, pak.ID)
}

func (*Suite) TestAlreadyUsedKey(c *check.C) {
	user, err := db.CreateUser("test4")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	pakID := uint(pak.ID)
	node := types.Node{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testest",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
	}
	trx := db.db.Save(&node)
	c.Assert(trx.Error, check.IsNil)

	key, err := db.ValidatePreAuthKey(pak.Key)
	c.Assert(err, check.Equals, ErrSingleUseAuthKeyHasBeenUsed)
	c.Assert(key, check.IsNil)
}

func (*Suite) TestReusableBeingUsedKey(c *check.C) {
	user, err := db.CreateUser("test5")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, true, false, nil, nil)
	c.Assert(err, check.IsNil)

	pakID := uint(pak.ID)
	node := types.Node{
		ID:             1,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testest",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
	}
	trx := db.db.Save(&node)
	c.Assert(trx.Error, check.IsNil)

	key, err := db.ValidatePreAuthKey(pak.Key)
	c.Assert(err, check.IsNil)
	c.Assert(key.ID, check.Equals, pak.ID)
}

func (*Suite) TestNotReusableNotBeingUsedKey(c *check.C) {
	user, err := db.CreateUser("test6")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	key, err := db.ValidatePreAuthKey(pak.Key)
	c.Assert(err, check.IsNil)
	c.Assert(key.ID, check.Equals, pak.ID)
}

func (*Suite) TestEphemeralKey(c *check.C) {
	user, err := db.CreateUser("test7")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, true, nil, nil)
	c.Assert(err, check.IsNil)

	now := time.Now().Add(-time.Second * 30)
	pakID := uint(pak.ID)
	node := types.Node{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testest",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		LastSeen:       &now,
		AuthKeyID:      &pakID,
	}
	trx := db.db.Save(&node)
	c.Assert(trx.Error, check.IsNil)

	_, err = db.ValidatePreAuthKey(pak.Key)
	// Ephemeral keys are by definition reusable
	c.Assert(err, check.IsNil)

	_, err = db.GetNode("test7", "testest")
	c.Assert(err, check.IsNil)

	db.ExpireEphemeralNodes(time.Second * 20)

	// The machine record should have been deleted
	_, err = db.GetNode("test7", "testest")
	c.Assert(err, check.NotNil)
}

func (*Suite) TestExpirePreauthKey(c *check.C) {
	user, err := db.CreateUser("test3")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, true, false, nil, nil)
	c.Assert(err, check.IsNil)
	c.Assert(pak.Expiration, check.IsNil)

	err = db.ExpirePreAuthKey(pak)
	c.Assert(err, check.IsNil)
	c.Assert(pak.Expiration, check.NotNil)

	key, err := db.ValidatePreAuthKey(pak.Key)
	c.Assert(err, check.Equals, ErrPreAuthKeyExpired)
	c.Assert(key, check.IsNil)
}

func (*Suite) TestNotReusableMarkedAsUsed(c *check.C) {
	user, err := db.CreateUser("test6")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)
	pak.Used = true
	db.db.Save(&pak)

	_, err = db.ValidatePreAuthKey(pak.Key)
	c.Assert(err, check.Equals, ErrSingleUseAuthKeyHasBeenUsed)
}

func (*Suite) TestPreAuthKeyACLTags(c *check.C) {
	user, err := db.CreateUser("test8")
	c.Assert(err, check.IsNil)

	_, err = db.CreatePreAuthKey(user.Name, false, false, nil, []string{"badtag"})
	c.Assert(err, check.NotNil) // Confirm that malformed tags are rejected

	tags := []string{"tag:test1", "tag:test2"}
	tagsWithDuplicate := []string{"tag:test1", "tag:test2", "tag:test2"}
	_, err = db.CreatePreAuthKey(user.Name, false, false, nil, tagsWithDuplicate)
	c.Assert(err, check.IsNil)

	listedPaks, err := db.ListPreAuthKeys("test8")
	c.Assert(err, check.IsNil)
	c.Assert(listedPaks[0].Proto().AclTags, check.DeepEquals, tags)
}
