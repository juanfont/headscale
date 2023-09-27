package db

import (
	"net/netip"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"gopkg.in/check.v1"
	"tailscale.com/tailcfg"
)

func (s *Suite) TestGetRoutes(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNode("test", "test_get_route_node")
	c.Assert(err, check.NotNil)

	route, err := netip.ParsePrefix("10.0.0.0/24")
	c.Assert(err, check.IsNil)

	hostInfo := tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{route},
	}

	pakID := uint(pak.ID)
	node := types.Node{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_get_route_node",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
		HostInfo:       types.HostInfo(hostInfo),
	}
	trx := db.db.Save(&node)
	c.Assert(trx.Error, check.IsNil)

	err = db.SaveNodeRoutes(&node)
	c.Assert(err, check.IsNil)

	advertisedRoutes, err := db.GetAdvertisedRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(len(advertisedRoutes), check.Equals, 1)

	err = db.enableRoutes(&node, "192.168.0.0/24")
	c.Assert(err, check.NotNil)

	err = db.enableRoutes(&node, "10.0.0.0/24")
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetEnableRoutes(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNode("test", "test_enable_route_node")
	c.Assert(err, check.NotNil)

	route, err := netip.ParsePrefix(
		"10.0.0.0/24",
	)
	c.Assert(err, check.IsNil)

	route2, err := netip.ParsePrefix(
		"150.0.10.0/25",
	)
	c.Assert(err, check.IsNil)

	hostInfo := tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{route, route2},
	}

	pakID := uint(pak.ID)
	node := types.Node{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_enable_route_node",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
		HostInfo:       types.HostInfo(hostInfo),
	}
	trx := db.db.Save(&node)
	c.Assert(trx.Error, check.IsNil)

	err = db.SaveNodeRoutes(&node)
	c.Assert(err, check.IsNil)

	availableRoutes, err := db.GetAdvertisedRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(err, check.IsNil)
	c.Assert(len(availableRoutes), check.Equals, 2)

	noEnabledRoutes, err := db.GetEnabledRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(len(noEnabledRoutes), check.Equals, 0)

	err = db.enableRoutes(&node, "192.168.0.0/24")
	c.Assert(err, check.NotNil)

	err = db.enableRoutes(&node, "10.0.0.0/24")
	c.Assert(err, check.IsNil)

	enabledRoutes, err := db.GetEnabledRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes), check.Equals, 1)

	// Adding it twice will just let it pass through
	err = db.enableRoutes(&node, "10.0.0.0/24")
	c.Assert(err, check.IsNil)

	enableRoutesAfterDoubleApply, err := db.GetEnabledRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(len(enableRoutesAfterDoubleApply), check.Equals, 1)

	err = db.enableRoutes(&node, "150.0.10.0/25")
	c.Assert(err, check.IsNil)

	enabledRoutesWithAdditionalRoute, err := db.GetEnabledRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutesWithAdditionalRoute), check.Equals, 2)
}

func (s *Suite) TestIsUniquePrefix(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNode("test", "test_enable_route_node")
	c.Assert(err, check.NotNil)

	route, err := netip.ParsePrefix(
		"10.0.0.0/24",
	)
	c.Assert(err, check.IsNil)

	route2, err := netip.ParsePrefix(
		"150.0.10.0/25",
	)
	c.Assert(err, check.IsNil)

	hostInfo1 := tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{route, route2},
	}
	pakID := uint(pak.ID)
	node1 := types.Node{
		ID:             1,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_enable_route_node",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
		HostInfo:       types.HostInfo(hostInfo1),
	}
	trx := db.db.Save(&node1)
	c.Assert(trx.Error, check.IsNil)

	err = db.SaveNodeRoutes(&node1)
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&node1, route.String())
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&node1, route2.String())
	c.Assert(err, check.IsNil)

	hostInfo2 := tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{route2},
	}
	node2 := types.Node{
		ID:             2,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_enable_route_node",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
		HostInfo:       types.HostInfo(hostInfo2),
	}
	trx = db.db.Save(&node2)
	c.Assert(trx.Error, check.IsNil)

	err = db.SaveNodeRoutes(&node2)
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&node2, route2.String())
	c.Assert(err, check.IsNil)

	enabledRoutes1, err := db.GetEnabledRoutes(&node1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 2)

	enabledRoutes2, err := db.GetEnabledRoutes(&node2)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes2), check.Equals, 1)

	routes, err := db.GetNodePrimaryRoutes(&node1)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 2)

	routes, err = db.GetNodePrimaryRoutes(&node2)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 0)
}

func (s *Suite) TestSubnetFailover(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNode("test", "test_enable_route_node")
	c.Assert(err, check.NotNil)

	prefix, err := netip.ParsePrefix(
		"10.0.0.0/24",
	)
	c.Assert(err, check.IsNil)

	prefix2, err := netip.ParsePrefix(
		"150.0.10.0/25",
	)
	c.Assert(err, check.IsNil)

	hostInfo1 := tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{prefix, prefix2},
	}

	now := time.Now()
	pakID := uint(pak.ID)
	node1 := types.Node{
		ID:             1,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_enable_route_node",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
		HostInfo:       types.HostInfo(hostInfo1),
		LastSeen:       &now,
	}
	trx := db.db.Save(&node1)
	c.Assert(trx.Error, check.IsNil)

	err = db.SaveNodeRoutes(&node1)
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&node1, prefix.String())
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&node1, prefix2.String())
	c.Assert(err, check.IsNil)

	err = db.HandlePrimarySubnetFailover()
	c.Assert(err, check.IsNil)

	enabledRoutes1, err := db.GetEnabledRoutes(&node1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 2)

	route, err := db.getPrimaryRoute(prefix)
	c.Assert(err, check.IsNil)
	c.Assert(route.NodeID, check.Equals, node1.ID)

	hostInfo2 := tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{prefix2},
	}
	node2 := types.Node{
		ID:             2,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_enable_route_node",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
		HostInfo:       types.HostInfo(hostInfo2),
		LastSeen:       &now,
	}
	trx = db.db.Save(&node2)
	c.Assert(trx.Error, check.IsNil)

	err = db.saveNodeRoutes(&node2)
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&node2, prefix2.String())
	c.Assert(err, check.IsNil)

	err = db.HandlePrimarySubnetFailover()
	c.Assert(err, check.IsNil)

	enabledRoutes1, err = db.GetEnabledRoutes(&node1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 2)

	enabledRoutes2, err := db.GetEnabledRoutes(&node2)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes2), check.Equals, 1)

	routes, err := db.GetNodePrimaryRoutes(&node1)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 2)

	routes, err = db.GetNodePrimaryRoutes(&node2)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 0)

	// lets make node1 lastseen 10 mins ago
	before := now.Add(-10 * time.Minute)
	node1.LastSeen = &before
	err = db.db.Save(&node1).Error
	c.Assert(err, check.IsNil)

	err = db.HandlePrimarySubnetFailover()
	c.Assert(err, check.IsNil)

	routes, err = db.GetNodePrimaryRoutes(&node1)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 1)

	routes, err = db.GetNodePrimaryRoutes(&node2)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 1)

	node2.HostInfo = types.HostInfo(tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{prefix, prefix2},
	})
	err = db.db.Save(&node2).Error
	c.Assert(err, check.IsNil)

	err = db.SaveNodeRoutes(&node2)
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&node2, prefix.String())
	c.Assert(err, check.IsNil)

	err = db.HandlePrimarySubnetFailover()
	c.Assert(err, check.IsNil)

	routes, err = db.GetNodePrimaryRoutes(&node1)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 0)

	routes, err = db.GetNodePrimaryRoutes(&node2)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 2)
}

func (s *Suite) TestDeleteRoutes(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNode("test", "test_enable_route_node")
	c.Assert(err, check.NotNil)

	prefix, err := netip.ParsePrefix(
		"10.0.0.0/24",
	)
	c.Assert(err, check.IsNil)

	prefix2, err := netip.ParsePrefix(
		"150.0.10.0/25",
	)
	c.Assert(err, check.IsNil)

	hostInfo1 := tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{prefix, prefix2},
	}

	now := time.Now()
	pakID := uint(pak.ID)
	node1 := types.Node{
		ID:             1,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_enable_route_node",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
		HostInfo:       types.HostInfo(hostInfo1),
		LastSeen:       &now,
	}
	trx := db.db.Save(&node1)
	c.Assert(trx.Error, check.IsNil)

	err = db.SaveNodeRoutes(&node1)
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&node1, prefix.String())
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&node1, prefix2.String())
	c.Assert(err, check.IsNil)

	routes, err := db.GetNodeRoutes(&node1)
	c.Assert(err, check.IsNil)

	err = db.DeleteRoute(uint64(routes[0].ID))
	c.Assert(err, check.IsNil)

	enabledRoutes1, err := db.GetEnabledRoutes(&node1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 1)
}
