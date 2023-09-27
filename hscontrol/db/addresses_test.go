package db

import (
	"net/netip"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/netipx"
	"gopkg.in/check.v1"
)

func (s *Suite) TestGetAvailableIp(c *check.C) {
	ips, err := db.getAvailableIPs()

	c.Assert(err, check.IsNil)

	expected := netip.MustParseAddr("10.27.0.1")

	c.Assert(len(ips), check.Equals, 1)
	c.Assert(ips[0].String(), check.Equals, expected.String())
}

func (s *Suite) TestGetUsedIps(c *check.C) {
	ips, err := db.getAvailableIPs()
	c.Assert(err, check.IsNil)

	user, err := db.CreateUser("test-ip")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNode("test", "testnode")
	c.Assert(err, check.NotNil)

	pakID := uint(pak.ID)
	node := types.Node{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
		IPAddresses:    ips,
	}
	db.db.Save(&node)

	usedIps, err := db.getUsedIPs()

	c.Assert(err, check.IsNil)

	expected := netip.MustParseAddr("10.27.0.1")
	expectedIPSetBuilder := netipx.IPSetBuilder{}
	expectedIPSetBuilder.Add(expected)
	expectedIPSet, _ := expectedIPSetBuilder.IPSet()

	c.Assert(usedIps.Equal(expectedIPSet), check.Equals, true)
	c.Assert(usedIps.Contains(expected), check.Equals, true)

	node1, err := db.GetNodeByID(0)
	c.Assert(err, check.IsNil)

	c.Assert(len(node1.IPAddresses), check.Equals, 1)
	c.Assert(node1.IPAddresses[0], check.Equals, expected)
}

func (s *Suite) TestGetMultiIp(c *check.C) {
	user, err := db.CreateUser("test-ip-multi")
	c.Assert(err, check.IsNil)

	for index := 1; index <= 350; index++ {
		db.ipAllocationMutex.Lock()

		ips, err := db.getAvailableIPs()
		c.Assert(err, check.IsNil)

		pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
		c.Assert(err, check.IsNil)

		_, err = db.GetNode("test", "testnode")
		c.Assert(err, check.NotNil)

		pakID := uint(pak.ID)
		node := types.Node{
			ID:             uint64(index),
			MachineKey:     "foo",
			NodeKey:        "bar",
			DiscoKey:       "faa",
			Hostname:       "testnode",
			UserID:         user.ID,
			RegisterMethod: util.RegisterMethodAuthKey,
			AuthKeyID:      &pakID,
			IPAddresses:    ips,
		}
		db.db.Save(&node)

		db.ipAllocationMutex.Unlock()
	}

	usedIps, err := db.getUsedIPs()
	c.Assert(err, check.IsNil)

	expected0 := netip.MustParseAddr("10.27.0.1")
	expected9 := netip.MustParseAddr("10.27.0.10")
	expected300 := netip.MustParseAddr("10.27.0.45")

	notExpectedIPSetBuilder := netipx.IPSetBuilder{}
	notExpectedIPSetBuilder.Add(expected0)
	notExpectedIPSetBuilder.Add(expected9)
	notExpectedIPSetBuilder.Add(expected300)
	notExpectedIPSet, err := notExpectedIPSetBuilder.IPSet()
	c.Assert(err, check.IsNil)

	// We actually expect it to be a lot larger
	c.Assert(usedIps.Equal(notExpectedIPSet), check.Equals, false)

	c.Assert(usedIps.Contains(expected0), check.Equals, true)
	c.Assert(usedIps.Contains(expected9), check.Equals, true)
	c.Assert(usedIps.Contains(expected300), check.Equals, true)

	// Check that we can read back the IPs
	node1, err := db.GetNodeByID(1)
	c.Assert(err, check.IsNil)
	c.Assert(len(node1.IPAddresses), check.Equals, 1)
	c.Assert(
		node1.IPAddresses[0],
		check.Equals,
		netip.MustParseAddr("10.27.0.1"),
	)

	node50, err := db.GetNodeByID(50)
	c.Assert(err, check.IsNil)
	c.Assert(len(node50.IPAddresses), check.Equals, 1)
	c.Assert(
		node50.IPAddresses[0],
		check.Equals,
		netip.MustParseAddr("10.27.0.50"),
	)

	expectedNextIP := netip.MustParseAddr("10.27.1.95")
	nextIP, err := db.getAvailableIPs()
	c.Assert(err, check.IsNil)

	c.Assert(len(nextIP), check.Equals, 1)
	c.Assert(nextIP[0].String(), check.Equals, expectedNextIP.String())

	// If we call get Available again, we should receive
	// the same IP, as it has not been reserved.
	nextIP2, err := db.getAvailableIPs()
	c.Assert(err, check.IsNil)

	c.Assert(len(nextIP2), check.Equals, 1)
	c.Assert(nextIP2[0].String(), check.Equals, expectedNextIP.String())
}

func (s *Suite) TestGetAvailableIpNodeWithoutIP(c *check.C) {
	ips, err := db.getAvailableIPs()
	c.Assert(err, check.IsNil)

	expected := netip.MustParseAddr("10.27.0.1")

	c.Assert(len(ips), check.Equals, 1)
	c.Assert(ips[0].String(), check.Equals, expected.String())

	user, err := db.CreateUser("test-ip")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNode("test", "testnode")
	c.Assert(err, check.NotNil)

	pakID := uint(pak.ID)
	node := types.Node{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
	}
	db.db.Save(&node)

	ips2, err := db.getAvailableIPs()
	c.Assert(err, check.IsNil)

	c.Assert(len(ips2), check.Equals, 1)
	c.Assert(ips2[0].String(), check.Equals, expected.String())
}
