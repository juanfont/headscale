package db

import (
	"sort"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"gopkg.in/check.v1"
	"tailscale.com/types/ptr"
)

func (*Suite) TestCreatePreAuthKey(c *check.C) {
	// ID does not exist
	_, err := db.CreatePreAuthKey(12345, true, false, nil, nil)
	c.Assert(err, check.NotNil)

	user, err := db.CreateUser(types.User{Name: "test"})
	c.Assert(err, check.IsNil)

	key, err := db.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
	c.Assert(err, check.IsNil)

	// Did we get a valid key?
	c.Assert(key.Key, check.NotNil)
	c.Assert(len(key.Key), check.Equals, 48)

	// Make sure the User association is populated
	c.Assert(key.User.ID, check.Equals, user.ID)

	// ID does not exist
	_, err = db.ListPreAuthKeys(1000000)
	c.Assert(err, check.NotNil)

	keys, err := db.ListPreAuthKeys(types.UserID(user.ID))
	c.Assert(err, check.IsNil)
	c.Assert(len(keys), check.Equals, 1)

	// Make sure the User association is populated
	c.Assert((keys)[0].User.ID, check.Equals, user.ID)
}

func (*Suite) TestExpiredPreAuthKey(c *check.C) {
	user, err := db.CreateUser(types.User{Name: "test2"})
	c.Assert(err, check.IsNil)

	now := time.Now().Add(-5 * time.Second)
	pak, err := db.CreatePreAuthKey(types.UserID(user.ID), true, false, &now, nil)
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
	user, err := db.CreateUser(types.User{Name: "test3"})
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
	c.Assert(err, check.IsNil)

	key, err := db.ValidatePreAuthKey(pak.Key)
	c.Assert(err, check.IsNil)
	c.Assert(key.ID, check.Equals, pak.ID)
}

func (*Suite) TestAlreadyUsedKey(c *check.C) {
	user, err := db.CreateUser(types.User{Name: "test4"})
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, nil)
	c.Assert(err, check.IsNil)

	node := types.Node{
		ID:             0,
		Hostname:       "testest",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      ptr.To(pak.ID),
	}
	trx := db.DB.Save(&node)
	c.Assert(trx.Error, check.IsNil)

	key, err := db.ValidatePreAuthKey(pak.Key)
	c.Assert(err, check.Equals, ErrSingleUseAuthKeyHasBeenUsed)
	c.Assert(key, check.IsNil)
}

func (*Suite) TestReusableBeingUsedKey(c *check.C) {
	user, err := db.CreateUser(types.User{Name: "test5"})
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
	c.Assert(err, check.IsNil)

	node := types.Node{
		ID:             1,
		Hostname:       "testest",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      ptr.To(pak.ID),
	}
	trx := db.DB.Save(&node)
	c.Assert(trx.Error, check.IsNil)

	key, err := db.ValidatePreAuthKey(pak.Key)
	c.Assert(err, check.IsNil)
	c.Assert(key.ID, check.Equals, pak.ID)
}

func (*Suite) TestNotReusableNotBeingUsedKey(c *check.C) {
	user, err := db.CreateUser(types.User{Name: "test6"})
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, nil)
	c.Assert(err, check.IsNil)

	key, err := db.ValidatePreAuthKey(pak.Key)
	c.Assert(err, check.IsNil)
	c.Assert(key.ID, check.Equals, pak.ID)
}

func (*Suite) TestExpirePreauthKey(c *check.C) {
	user, err := db.CreateUser(types.User{Name: "test3"})
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
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
	user, err := db.CreateUser(types.User{Name: "test6"})
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, nil)
	c.Assert(err, check.IsNil)
	pak.Used = true
	db.DB.Save(&pak)

	_, err = db.ValidatePreAuthKey(pak.Key)
	c.Assert(err, check.Equals, ErrSingleUseAuthKeyHasBeenUsed)
}

func (*Suite) TestPreAuthKeyACLTags(c *check.C) {
	user, err := db.CreateUser(types.User{Name: "test8"})
	c.Assert(err, check.IsNil)

	_, err = db.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, []string{"badtag"})
	c.Assert(err, check.NotNil) // Confirm that malformed tags are rejected

	tags := []string{"tag:test1", "tag:test2"}
	tagsWithDuplicate := []string{"tag:test1", "tag:test2", "tag:test2"}
	_, err = db.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, tagsWithDuplicate)
	c.Assert(err, check.IsNil)

	listedPaks, err := db.ListPreAuthKeys(types.UserID(user.ID))
	c.Assert(err, check.IsNil)
	gotTags := listedPaks[0].Proto().GetAclTags()
	sort.Sort(sort.StringSlice(gotTags))
	c.Assert(gotTags, check.DeepEquals, tags)
}
