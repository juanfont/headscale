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

	_, err = db.GetNode("test", "test_get_route_machine")
	c.Assert(err, check.NotNil)

	route, err := netip.ParsePrefix("10.0.0.0/24")
	c.Assert(err, check.IsNil)

	hostInfo := tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{route},
	}

	machine := types.Node{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_get_route_machine",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       types.HostInfo(hostInfo),
	}
	db.db.Save(&machine)

	err = db.SaveNodeRoutes(&machine)
	c.Assert(err, check.IsNil)

	advertisedRoutes, err := db.GetAdvertisedRoutes(&machine)
	c.Assert(err, check.IsNil)
	c.Assert(len(advertisedRoutes), check.Equals, 1)

	err = db.enableRoutes(&machine, "192.168.0.0/24")
	c.Assert(err, check.NotNil)

	err = db.enableRoutes(&machine, "10.0.0.0/24")
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetEnableRoutes(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNode("test", "test_enable_route_machine")
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

	machine := types.Node{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_enable_route_machine",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       types.HostInfo(hostInfo),
	}
	db.db.Save(&machine)

	err = db.SaveNodeRoutes(&machine)
	c.Assert(err, check.IsNil)

	availableRoutes, err := db.GetAdvertisedRoutes(&machine)
	c.Assert(err, check.IsNil)
	c.Assert(err, check.IsNil)
	c.Assert(len(availableRoutes), check.Equals, 2)

	noEnabledRoutes, err := db.GetEnabledRoutes(&machine)
	c.Assert(err, check.IsNil)
	c.Assert(len(noEnabledRoutes), check.Equals, 0)

	err = db.enableRoutes(&machine, "192.168.0.0/24")
	c.Assert(err, check.NotNil)

	err = db.enableRoutes(&machine, "10.0.0.0/24")
	c.Assert(err, check.IsNil)

	enabledRoutes, err := db.GetEnabledRoutes(&machine)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes), check.Equals, 1)

	// Adding it twice will just let it pass through
	err = db.enableRoutes(&machine, "10.0.0.0/24")
	c.Assert(err, check.IsNil)

	enableRoutesAfterDoubleApply, err := db.GetEnabledRoutes(&machine)
	c.Assert(err, check.IsNil)
	c.Assert(len(enableRoutesAfterDoubleApply), check.Equals, 1)

	err = db.enableRoutes(&machine, "150.0.10.0/25")
	c.Assert(err, check.IsNil)

	enabledRoutesWithAdditionalRoute, err := db.GetEnabledRoutes(&machine)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutesWithAdditionalRoute), check.Equals, 2)
}

func (s *Suite) TestIsUniquePrefix(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNode("test", "test_enable_route_machine")
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
	machine1 := types.Node{
		ID:             1,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_enable_route_machine",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       types.HostInfo(hostInfo1),
	}
	db.db.Save(&machine1)

	err = db.SaveNodeRoutes(&machine1)
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&machine1, route.String())
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&machine1, route2.String())
	c.Assert(err, check.IsNil)

	hostInfo2 := tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{route2},
	}
	machine2 := types.Node{
		ID:             2,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_enable_route_machine",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       types.HostInfo(hostInfo2),
	}
	db.db.Save(&machine2)

	err = db.SaveNodeRoutes(&machine2)
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&machine2, route2.String())
	c.Assert(err, check.IsNil)

	enabledRoutes1, err := db.GetEnabledRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 2)

	enabledRoutes2, err := db.GetEnabledRoutes(&machine2)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes2), check.Equals, 1)

	routes, err := db.GetNodePrimaryRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 2)

	routes, err = db.GetNodePrimaryRoutes(&machine2)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 0)
}

func (s *Suite) TestSubnetFailover(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNode("test", "test_enable_route_machine")
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
	machine1 := types.Node{
		ID:             1,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_enable_route_machine",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       types.HostInfo(hostInfo1),
		LastSeen:       &now,
	}
	db.db.Save(&machine1)

	err = db.SaveNodeRoutes(&machine1)
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&machine1, prefix.String())
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&machine1, prefix2.String())
	c.Assert(err, check.IsNil)

	err = db.HandlePrimarySubnetFailover()
	c.Assert(err, check.IsNil)

	enabledRoutes1, err := db.GetEnabledRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 2)

	route, err := db.getPrimaryRoute(prefix)
	c.Assert(err, check.IsNil)
	c.Assert(route.NodeID, check.Equals, machine1.ID)

	hostInfo2 := tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{prefix2},
	}
	machine2 := types.Node{
		ID:             2,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_enable_route_machine",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       types.HostInfo(hostInfo2),
		LastSeen:       &now,
	}
	db.db.Save(&machine2)

	err = db.saveNodeRoutes(&machine2)
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&machine2, prefix2.String())
	c.Assert(err, check.IsNil)

	err = db.HandlePrimarySubnetFailover()
	c.Assert(err, check.IsNil)

	enabledRoutes1, err = db.GetEnabledRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 2)

	enabledRoutes2, err := db.GetEnabledRoutes(&machine2)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes2), check.Equals, 1)

	routes, err := db.GetNodePrimaryRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 2)

	routes, err = db.GetNodePrimaryRoutes(&machine2)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 0)

	// lets make machine1 lastseen 10 mins ago
	before := now.Add(-10 * time.Minute)
	machine1.LastSeen = &before
	err = db.db.Save(&machine1).Error
	c.Assert(err, check.IsNil)

	err = db.HandlePrimarySubnetFailover()
	c.Assert(err, check.IsNil)

	routes, err = db.GetNodePrimaryRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 1)

	routes, err = db.GetNodePrimaryRoutes(&machine2)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 1)

	machine2.HostInfo = types.HostInfo(tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{prefix, prefix2},
	})
	err = db.db.Save(&machine2).Error
	c.Assert(err, check.IsNil)

	err = db.SaveNodeRoutes(&machine2)
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&machine2, prefix.String())
	c.Assert(err, check.IsNil)

	err = db.HandlePrimarySubnetFailover()
	c.Assert(err, check.IsNil)

	routes, err = db.GetNodePrimaryRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 0)

	routes, err = db.GetNodePrimaryRoutes(&machine2)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 2)
}

func (s *Suite) TestDeleteRoutes(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNode("test", "test_enable_route_machine")
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
	machine1 := types.Node{
		ID:             1,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_enable_route_machine",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       types.HostInfo(hostInfo1),
		LastSeen:       &now,
	}
	db.db.Save(&machine1)

	err = db.SaveNodeRoutes(&machine1)
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&machine1, prefix.String())
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&machine1, prefix2.String())
	c.Assert(err, check.IsNil)

	routes, err := db.GetNodeRoutes(&machine1)
	c.Assert(err, check.IsNil)

	err = db.DeleteRoute(uint64(routes[0].ID))
	c.Assert(err, check.IsNil)

	enabledRoutes1, err := db.GetEnabledRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 1)
}
