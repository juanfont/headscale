package headscale

import (
	"time"

	"gopkg.in/check.v1"
)

func (*Suite) TestCreatePreAuthKey(c *check.C) {
	_, err := app.CreatePreAuthKey("bogus", true, false, nil)

	c.Assert(err, check.NotNil)

	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	key, err := app.CreatePreAuthKey(namespace.Name, true, false, nil)
	c.Assert(err, check.IsNil)

	// Did we get a valid key?
	c.Assert(key.Key, check.NotNil)
	c.Assert(len(key.Key), check.Equals, 48)

	// Make sure the Namespace association is populated
	c.Assert(key.Namespace.Name, check.Equals, namespace.Name)

	_, err = app.ListPreAuthKeys("bogus")
	c.Assert(err, check.NotNil)

	keys, err := app.ListPreAuthKeys(namespace.Name)
	c.Assert(err, check.IsNil)
	c.Assert(len(keys), check.Equals, 1)

	// Make sure the Namespace association is populated
	c.Assert((keys)[0].Namespace.Name, check.Equals, namespace.Name)
}

func (*Suite) TestExpiredPreAuthKey(c *check.C) {
	namespace, err := app.CreateNamespace("test2")
	c.Assert(err, check.IsNil)

	now := time.Now()
	pak, err := app.CreatePreAuthKey(namespace.Name, true, false, &now)
	c.Assert(err, check.IsNil)

	key, err := app.checkKeyValidity(pak.Key)
	c.Assert(err, check.Equals, errPreAuthKeyExpired)
	c.Assert(key, check.IsNil)
}

func (*Suite) TestPreAuthKeyDoesNotExist(c *check.C) {
	key, err := app.checkKeyValidity("potatoKey")
	c.Assert(err, check.Equals, errPreAuthKeyNotFound)
	c.Assert(key, check.IsNil)
}

func (*Suite) TestValidateKeyOk(c *check.C) {
	namespace, err := app.CreateNamespace("test3")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, true, false, nil)
	c.Assert(err, check.IsNil)

	key, err := app.checkKeyValidity(pak.Key)
	c.Assert(err, check.IsNil)
	c.Assert(key.ID, check.Equals, pak.ID)
}

func (*Suite) TestAlreadyUsedKey(c *check.C) {
	namespace, err := app.CreateNamespace("test4")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testest",
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

	key, err := app.checkKeyValidity(pak.Key)
	c.Assert(err, check.Equals, errSingleUseAuthKeyHasBeenUsed)
	c.Assert(key, check.IsNil)
}

func (*Suite) TestReusableBeingUsedKey(c *check.C) {
	namespace, err := app.CreateNamespace("test5")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, true, false, nil)
	c.Assert(err, check.IsNil)

	machine := Machine{
		ID:             1,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testest",
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

	key, err := app.checkKeyValidity(pak.Key)
	c.Assert(err, check.IsNil)
	c.Assert(key.ID, check.Equals, pak.ID)
}

func (*Suite) TestNotReusableNotBeingUsedKey(c *check.C) {
	namespace, err := app.CreateNamespace("test6")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	key, err := app.checkKeyValidity(pak.Key)
	c.Assert(err, check.IsNil)
	c.Assert(key.ID, check.Equals, pak.ID)
}

func (*Suite) TestEphemeralKey(c *check.C) {
	namespace, err := app.CreateNamespace("test7")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, true, nil)
	c.Assert(err, check.IsNil)

	now := time.Now()
	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testest",
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		LastSeen:       &now,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

	_, err = app.checkKeyValidity(pak.Key)
	// Ephemeral keys are by definition reusable
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("test7", "testest")
	c.Assert(err, check.IsNil)

	app.expireEphemeralNodesWorker()

	// The machine record should have been deleted
	_, err = app.GetMachine("test7", "testest")
	c.Assert(err, check.NotNil)
}

func (*Suite) TestExpirePreauthKey(c *check.C) {
	namespace, err := app.CreateNamespace("test3")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, true, false, nil)
	c.Assert(err, check.IsNil)
	c.Assert(pak.Expiration, check.IsNil)

	err = app.ExpirePreAuthKey(pak)
	c.Assert(err, check.IsNil)
	c.Assert(pak.Expiration, check.NotNil)

	key, err := app.checkKeyValidity(pak.Key)
	c.Assert(err, check.Equals, errPreAuthKeyExpired)
	c.Assert(key, check.IsNil)
}

func (*Suite) TestNotReusableMarkedAsUsed(c *check.C) {
	namespace, err := app.CreateNamespace("test6")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)
	pak.Used = true
	app.db.Save(&pak)

	_, err = app.checkKeyValidity(pak.Key)
	c.Assert(err, check.Equals, errSingleUseAuthKeyHasBeenUsed)
}
