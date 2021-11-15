package headscale

import (
	"gopkg.in/check.v1"
	"inet.af/netaddr"
)

func (s *Suite) TestGetAvailableIp(c *check.C) {
	ip, err := app.getAvailableIP()

	c.Assert(err, check.IsNil)

	expected := netaddr.MustParseIP("10.27.0.1")

	c.Assert(ip.String(), check.Equals, expected.String())
}

func (s *Suite) TestGetUsedIps(c *check.C) {
	ip, err := app.getAvailableIP()
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
		RegisterMethod: "authKey",
		AuthKeyID:      uint(pak.ID),
		IPAddress:      ip.String(),
	}
	app.db.Save(&machine)

	ips, err := app.getUsedIPs()

	c.Assert(err, check.IsNil)

	expected := netaddr.MustParseIP("10.27.0.1")

	c.Assert(ips[0], check.Equals, expected)

	machine1, err := app.GetMachineByID(0)
	c.Assert(err, check.IsNil)

	c.Assert(machine1.IPAddress, check.Equals, expected.String())
}

func (s *Suite) TestGetMultiIp(c *check.C) {
	namespace, err := app.CreateNamespace("test-ip-multi")
	c.Assert(err, check.IsNil)

	for index := 1; index <= 350; index++ {
		ip, err := app.getAvailableIP()
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
			RegisterMethod: "authKey",
			AuthKeyID:      uint(pak.ID),
			IPAddress:      ip.String(),
		}
		app.db.Save(&machine)
	}

	ips, err := app.getUsedIPs()

	c.Assert(err, check.IsNil)

	c.Assert(len(ips), check.Equals, 350)

	c.Assert(ips[0], check.Equals, netaddr.MustParseIP("10.27.0.1"))
	c.Assert(ips[9], check.Equals, netaddr.MustParseIP("10.27.0.10"))
	c.Assert(ips[300], check.Equals, netaddr.MustParseIP("10.27.1.47"))

	// Check that we can read back the IPs
	machine1, err := app.GetMachineByID(1)
	c.Assert(err, check.IsNil)
	c.Assert(
		machine1.IPAddress,
		check.Equals,
		netaddr.MustParseIP("10.27.0.1").String(),
	)

	machine50, err := app.GetMachineByID(50)
	c.Assert(err, check.IsNil)
	c.Assert(
		machine50.IPAddress,
		check.Equals,
		netaddr.MustParseIP("10.27.0.50").String(),
	)

	expectedNextIP := netaddr.MustParseIP("10.27.1.97")
	nextIP, err := app.getAvailableIP()
	c.Assert(err, check.IsNil)

	c.Assert(nextIP.String(), check.Equals, expectedNextIP.String())

	// If we call get Available again, we should receive
	// the same IP, as it has not been reserved.
	nextIP2, err := app.getAvailableIP()
	c.Assert(err, check.IsNil)

	c.Assert(nextIP2.String(), check.Equals, expectedNextIP.String())
}

func (s *Suite) TestGetAvailableIpMachineWithoutIP(c *check.C) {
	ip, err := app.getAvailableIP()
	c.Assert(err, check.IsNil)

	expected := netaddr.MustParseIP("10.27.0.1")

	c.Assert(ip.String(), check.Equals, expected.String())

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
		RegisterMethod: "authKey",
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

	ip2, err := app.getAvailableIP()
	c.Assert(err, check.IsNil)

	c.Assert(ip2.String(), check.Equals, expected.String())
}
