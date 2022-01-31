package headscale

import (
	"gopkg.in/check.v1"
	"inet.af/netaddr"
)

func (s *Suite) TestGetAvailableIp(c *check.C) {
	ips, err := app.getAvailableIPs()

	c.Assert(err, check.IsNil)

	expected := netaddr.MustParseIP("10.27.0.1")

	c.Assert(len(ips), check.Equals, 1)
	c.Assert(ips[0].String(), check.Equals, expected.String())
}

func (s *Suite) TestGetUsedIps(c *check.C) {
	ips, err := app.getAvailableIPs()
	c.Assert(err, check.IsNil)

	namespace, err := app.CreateNamespace("test_ip")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("test", "testmachine")
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
		IPAddresses:    ips,
	}
	app.db.Save(&machine)

	usedIps, err := app.getUsedIPs()

	c.Assert(err, check.IsNil)

	expected := netaddr.MustParseIP("10.27.0.1")

	c.Assert(len(usedIps), check.Equals, 1)
	c.Assert(usedIps[0], check.Equals, expected)

	machine1, err := app.GetMachineByID(0)
	c.Assert(err, check.IsNil)

	c.Assert(len(machine1.IPAddresses), check.Equals, 1)
	c.Assert(machine1.IPAddresses[0], check.Equals, expected)
}

func (s *Suite) TestGetMultiIp(c *check.C) {
	namespace, err := app.CreateNamespace("test-ip-multi")
	c.Assert(err, check.IsNil)

	for index := 1; index <= 350; index++ {
		ips, err := app.getAvailableIPs()
		c.Assert(err, check.IsNil)

		pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
		c.Assert(err, check.IsNil)

		_, err = app.GetMachine("test", "testmachine")
		c.Assert(err, check.NotNil)

		machine := Machine{
			ID:             uint64(index),
			MachineKey:     "foo",
			NodeKey:        "bar",
			DiscoKey:       "faa",
			Name:           "testmachine",
			NamespaceID:    namespace.ID,
			Registered:     true,
			RegisterMethod: RegisterMethodAuthKey,
			AuthKeyID:      uint(pak.ID),
			IPAddresses:    ips,
		}
		app.db.Save(&machine)
	}

	usedIps, err := app.getUsedIPs()

	c.Assert(err, check.IsNil)

	c.Assert(len(usedIps), check.Equals, 350)

	c.Assert(usedIps[0], check.Equals, netaddr.MustParseIP("10.27.0.1"))
	c.Assert(usedIps[9], check.Equals, netaddr.MustParseIP("10.27.0.10"))
	c.Assert(usedIps[300], check.Equals, netaddr.MustParseIP("10.27.1.45"))

	// Check that we can read back the IPs
	machine1, err := app.GetMachineByID(1)
	c.Assert(err, check.IsNil)
	c.Assert(len(machine1.IPAddresses), check.Equals, 1)
	c.Assert(
		machine1.IPAddresses[0],
		check.Equals,
		netaddr.MustParseIP("10.27.0.1"),
	)

	machine50, err := app.GetMachineByID(50)
	c.Assert(err, check.IsNil)
	c.Assert(len(machine50.IPAddresses), check.Equals, 1)
	c.Assert(
		machine50.IPAddresses[0],
		check.Equals,
		netaddr.MustParseIP("10.27.0.50"),
	)

	expectedNextIP := netaddr.MustParseIP("10.27.1.95")
	nextIP, err := app.getAvailableIPs()
	c.Assert(err, check.IsNil)

	c.Assert(len(nextIP), check.Equals, 1)
	c.Assert(nextIP[0].String(), check.Equals, expectedNextIP.String())

	// If we call get Available again, we should receive
	// the same IP, as it has not been reserved.
	nextIP2, err := app.getAvailableIPs()
	c.Assert(err, check.IsNil)

	c.Assert(len(nextIP2), check.Equals, 1)
	c.Assert(nextIP2[0].String(), check.Equals, expectedNextIP.String())
}

func (s *Suite) TestGetAvailableIpMachineWithoutIP(c *check.C) {
	ips, err := app.getAvailableIPs()
	c.Assert(err, check.IsNil)

	expected := netaddr.MustParseIP("10.27.0.1")

	c.Assert(len(ips), check.Equals, 1)
	c.Assert(ips[0].String(), check.Equals, expected.String())

	namespace, err := app.CreateNamespace("test_ip")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("test", "testmachine")
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

	ips2, err := app.getAvailableIPs()
	c.Assert(err, check.IsNil)

	c.Assert(len(ips2), check.Equals, 1)
	c.Assert(ips2[0].String(), check.Equals, expected.String())
}
