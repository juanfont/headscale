package headscale

import (
	"gopkg.in/check.v1"
	"inet.af/netaddr"
)

func (s *Suite) TestGetAvailableIp(c *check.C) {
	ip, err := h.getAvailableIP()

	c.Assert(err, check.IsNil)

	expected := netaddr.MustParseIP("10.27.0.0")

	c.Assert(ip.String(), check.Equals, expected.String())
}

func (s *Suite) TestGetUsedIps(c *check.C) {
	ip, err := h.getAvailableIP()
	c.Assert(err, check.IsNil)

	n, err := h.CreateNamespace("test_ip")
	c.Assert(err, check.IsNil)

	pak, err := h.CreatePreAuthKey(n.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = h.GetMachine("test", "testmachine")
	c.Assert(err, check.NotNil)

	m := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		NamespaceID:    n.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		AuthKeyID:      uint(pak.ID),
		IPAddress:      ip.String(),
	}
	h.db.Save(&m)

	ips, err := h.getUsedIPs()

	c.Assert(err, check.IsNil)

	expected := netaddr.MustParseIP("10.27.0.0")

	c.Assert(ips[0], check.Equals, expected)

	m1, err := h.GetMachineByID(0)
	c.Assert(err, check.IsNil)

	c.Assert(m1.IPAddress, check.Equals, expected.String())
}

func (s *Suite) TestGetMultiIp(c *check.C) {
	n, err := h.CreateNamespace("test-ip-multi")
	c.Assert(err, check.IsNil)

	for i := 1; i <= 350; i++ {
		ip, err := h.getAvailableIP()
		c.Assert(err, check.IsNil)

		pak, err := h.CreatePreAuthKey(n.Name, false, false, nil)
		c.Assert(err, check.IsNil)

		_, err = h.GetMachine("test", "testmachine")
		c.Assert(err, check.NotNil)

		m := Machine{
			ID:             uint64(i),
			MachineKey:     "foo",
			NodeKey:        "bar",
			DiscoKey:       "faa",
			Name:           "testmachine",
			NamespaceID:    n.ID,
			Registered:     true,
			RegisterMethod: "authKey",
			AuthKeyID:      uint(pak.ID),
			IPAddress:      ip.String(),
		}
		h.db.Save(&m)
	}

	ips, err := h.getUsedIPs()

	c.Assert(err, check.IsNil)

	c.Assert(len(ips), check.Equals, 350)

	c.Assert(ips[0], check.Equals, netaddr.MustParseIP("10.27.0.0"))
	c.Assert(ips[9], check.Equals, netaddr.MustParseIP("10.27.0.9"))
	c.Assert(ips[300], check.Equals, netaddr.MustParseIP("10.27.1.44"))

	// Check that we can read back the IPs
	m1, err := h.GetMachineByID(1)
	c.Assert(err, check.IsNil)
	c.Assert(m1.IPAddress, check.Equals, netaddr.MustParseIP("10.27.0.0").String())

	m50, err := h.GetMachineByID(50)
	c.Assert(err, check.IsNil)
	c.Assert(m50.IPAddress, check.Equals, netaddr.MustParseIP("10.27.0.49").String())

	expectedNextIP := netaddr.MustParseIP("10.27.1.94")
	nextIP, err := h.getAvailableIP()
	c.Assert(err, check.IsNil)

	c.Assert(nextIP.String(), check.Equals, expectedNextIP.String())

	// If we call get Available again, we should receive
	// the same IP, as it has not been reserved.
	nextIP2, err := h.getAvailableIP()
	c.Assert(err, check.IsNil)

	c.Assert(nextIP2.String(), check.Equals, expectedNextIP.String())
}
