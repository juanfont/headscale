package db

import (
	"net/netip"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/netipx"
	"gopkg.in/check.v1"
	"gorm.io/gorm"
)

func (s *Suite) TestGetAvailableIp(c *check.C) {
	tx := db.DB.Begin()
	defer tx.Rollback()

	ips, err := getAvailableIPs(tx, []netip.Prefix{
		netip.MustParsePrefix("10.27.0.0/23"),
	})

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

	_, err = db.getNode("test", "testnode")
	c.Assert(err, check.NotNil)

	node := types.Node{
		ID:             0,
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		IPAddresses:    ips,
	}
	db.Write(func(rx *gorm.DB) error {
		return rx.Save(&node).Error
	})

	usedIps, err := Read(db.DB, func(rx *gorm.DB) (*netipx.IPSet, error) {
		return getUsedIPs(rx)
	})
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
	user, err := db.CreateUser("test-ip")
	c.Assert(err, check.IsNil)

	ipPrefixes := []netip.Prefix{
		netip.MustParsePrefix("10.27.0.0/23"),
	}

	for index := 1; index <= 350; index++ {
		tx := db.DB.Begin()

		ips, err := getAvailableIPs(tx, ipPrefixes)
		c.Assert(err, check.IsNil)

		pak, err := CreatePreAuthKey(tx, user.Name, false, false, nil, nil)
		c.Assert(err, check.IsNil)

		_, err = getNode(tx, "test", "testnode")
		c.Assert(err, check.NotNil)

		node := types.Node{
			ID:             uint64(index),
			Hostname:       "testnode",
			UserID:         user.ID,
			RegisterMethod: util.RegisterMethodAuthKey,
			AuthKeyID:      uint(pak.ID),
			IPAddresses:    ips,
		}
		tx.Save(&node)
		c.Assert(tx.Commit().Error, check.IsNil)
	}

	usedIps, err := Read(db.DB, func(rx *gorm.DB) (*netipx.IPSet, error) {
		return getUsedIPs(rx)
	})
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

	_, err = db.getNode("test", "testnode")
	c.Assert(err, check.NotNil)

	node := types.Node{
		ID:             0,
		Hostname:       "testnode",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	db.DB.Save(&node)

	ips2, err := db.getAvailableIPs()
	c.Assert(err, check.IsNil)

	c.Assert(len(ips2), check.Equals, 1)
	c.Assert(ips2[0].String(), check.Equals, expected.String())
}
