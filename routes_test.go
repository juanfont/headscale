package headscale

import (
	"net/netip"
	"time"

	"gopkg.in/check.v1"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func (s *Suite) TestGetRoutes(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("test", "test_get_route_machine")
	c.Assert(err, check.NotNil)

	route, err := netip.ParsePrefix("10.0.0.0/24")
	c.Assert(err, check.IsNil)

	hostInfo := tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{route},
	}

	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_get_route_machine",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       HostInfo(hostInfo),
	}
	app.db.Save(&machine)

	err = app.processMachineRoutes(&machine)
	c.Assert(err, check.IsNil)

	advertisedRoutes, err := app.GetAdvertisedRoutes(&machine)
	c.Assert(err, check.IsNil)
	c.Assert(len(advertisedRoutes), check.Equals, 1)

	err = app.EnableRoutes(&machine, "192.168.0.0/24")
	c.Assert(err, check.NotNil)

	err = app.EnableRoutes(&machine, "10.0.0.0/24")
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetEnableRoutes(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("test", "test_enable_route_machine")
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

	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_enable_route_machine",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       HostInfo(hostInfo),
	}
	app.db.Save(&machine)

	err = app.processMachineRoutes(&machine)
	c.Assert(err, check.IsNil)

	availableRoutes, err := app.GetAdvertisedRoutes(&machine)
	c.Assert(err, check.IsNil)
	c.Assert(err, check.IsNil)
	c.Assert(len(availableRoutes), check.Equals, 2)

	noEnabledRoutes, err := app.GetEnabledRoutes(&machine)
	c.Assert(err, check.IsNil)
	c.Assert(len(noEnabledRoutes), check.Equals, 0)

	err = app.EnableRoutes(&machine, "192.168.0.0/24")
	c.Assert(err, check.NotNil)

	err = app.EnableRoutes(&machine, "10.0.0.0/24")
	c.Assert(err, check.IsNil)

	enabledRoutes, err := app.GetEnabledRoutes(&machine)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes), check.Equals, 1)

	// Adding it twice will just let it pass through
	err = app.EnableRoutes(&machine, "10.0.0.0/24")
	c.Assert(err, check.IsNil)

	enableRoutesAfterDoubleApply, err := app.GetEnabledRoutes(&machine)
	c.Assert(err, check.IsNil)
	c.Assert(len(enableRoutesAfterDoubleApply), check.Equals, 1)

	err = app.EnableRoutes(&machine, "150.0.10.0/25")
	c.Assert(err, check.IsNil)

	enabledRoutesWithAdditionalRoute, err := app.GetEnabledRoutes(&machine)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutesWithAdditionalRoute), check.Equals, 2)
}

func (s *Suite) TestIsUniquePrefix(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("test", "test_enable_route_machine")
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
	machine1 := Machine{
		ID:             1,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_enable_route_machine",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       HostInfo(hostInfo1),
	}
	app.db.Save(&machine1)

	err = app.processMachineRoutes(&machine1)
	c.Assert(err, check.IsNil)

	err = app.EnableRoutes(&machine1, route.String())
	c.Assert(err, check.IsNil)

	err = app.EnableRoutes(&machine1, route2.String())
	c.Assert(err, check.IsNil)

	hostInfo2 := tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{route2},
	}
	machine2 := Machine{
		ID:             2,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_enable_route_machine",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       HostInfo(hostInfo2),
	}
	app.db.Save(&machine2)

	err = app.processMachineRoutes(&machine2)
	c.Assert(err, check.IsNil)

	err = app.EnableRoutes(&machine2, route2.String())
	c.Assert(err, check.IsNil)

	enabledRoutes1, err := app.GetEnabledRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 2)

	enabledRoutes2, err := app.GetEnabledRoutes(&machine2)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes2), check.Equals, 1)

	routes, err := app.getMachinePrimaryRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 2)

	routes, err = app.getMachinePrimaryRoutes(&machine2)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 0)
}

func (s *Suite) TestSubnetFailover(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("test", "test_enable_route_machine")
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
	machine1 := Machine{
		ID:             1,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_enable_route_machine",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       HostInfo(hostInfo1),
		LastSeen:       &now,
	}
	app.db.Save(&machine1)

	err = app.processMachineRoutes(&machine1)
	c.Assert(err, check.IsNil)

	err = app.EnableRoutes(&machine1, prefix.String())
	c.Assert(err, check.IsNil)

	err = app.EnableRoutes(&machine1, prefix2.String())
	c.Assert(err, check.IsNil)

	err = app.handlePrimarySubnetFailover()
	c.Assert(err, check.IsNil)

	enabledRoutes1, err := app.GetEnabledRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 2)

	route, err := app.getPrimaryRoute(prefix)
	c.Assert(err, check.IsNil)
	c.Assert(route.MachineID, check.Equals, machine1.ID)

	hostInfo2 := tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{prefix2},
	}
	machine2 := Machine{
		ID:             2,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_enable_route_machine",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       HostInfo(hostInfo2),
		LastSeen:       &now,
	}
	app.db.Save(&machine2)

	err = app.processMachineRoutes(&machine2)
	c.Assert(err, check.IsNil)

	err = app.EnableRoutes(&machine2, prefix2.String())
	c.Assert(err, check.IsNil)

	err = app.handlePrimarySubnetFailover()
	c.Assert(err, check.IsNil)

	enabledRoutes1, err = app.GetEnabledRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 2)

	enabledRoutes2, err := app.GetEnabledRoutes(&machine2)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes2), check.Equals, 1)

	routes, err := app.getMachinePrimaryRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 2)

	routes, err = app.getMachinePrimaryRoutes(&machine2)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 0)

	// lets make machine1 lastseen 10 mins ago
	before := now.Add(-10 * time.Minute)
	machine1.LastSeen = &before
	err = app.db.Save(&machine1).Error
	c.Assert(err, check.IsNil)

	err = app.handlePrimarySubnetFailover()
	c.Assert(err, check.IsNil)

	routes, err = app.getMachinePrimaryRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 1)

	routes, err = app.getMachinePrimaryRoutes(&machine2)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 1)

	machine2.HostInfo = HostInfo(tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{prefix, prefix2},
	})
	err = app.db.Save(&machine2).Error
	c.Assert(err, check.IsNil)

	err = app.processMachineRoutes(&machine2)
	c.Assert(err, check.IsNil)

	err = app.EnableRoutes(&machine2, prefix.String())
	c.Assert(err, check.IsNil)

	err = app.handlePrimarySubnetFailover()
	c.Assert(err, check.IsNil)

	routes, err = app.getMachinePrimaryRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 0)

	routes, err = app.getMachinePrimaryRoutes(&machine2)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 2)
}

// TestAllowedIPRoutes tests that the AllowedIPs are correctly set for a node,
// including both the primary routes the node is responsible for, and the
// exit node routes if enabled.
func (s *Suite) TestAllowedIPRoutes(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("test", "test_enable_route_machine")
	c.Assert(err, check.NotNil)

	prefix, err := netip.ParsePrefix(
		"10.0.0.0/24",
	)
	c.Assert(err, check.IsNil)

	prefix2, err := netip.ParsePrefix(
		"150.0.10.0/25",
	)
	c.Assert(err, check.IsNil)

	prefixExitNodeV4, err := netip.ParsePrefix(
		"0.0.0.0/0",
	)
	c.Assert(err, check.IsNil)

	prefixExitNodeV6, err := netip.ParsePrefix(
		"::/0",
	)
	c.Assert(err, check.IsNil)

	hostInfo1 := tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{prefix, prefix2, prefixExitNodeV4, prefixExitNodeV6},
	}

	nodeKey := key.NewNode()
	discoKey := key.NewDisco()
	machineKey := key.NewMachine()

	now := time.Now()
	machine1 := Machine{
		ID:             1,
		MachineKey:     MachinePublicKeyStripPrefix(machineKey.Public()),
		NodeKey:        NodePublicKeyStripPrefix(nodeKey.Public()),
		DiscoKey:       DiscoPublicKeyStripPrefix(discoKey.Public()),
		Hostname:       "test_enable_route_machine",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       HostInfo(hostInfo1),
		LastSeen:       &now,
	}
	app.db.Save(&machine1)

	err = app.processMachineRoutes(&machine1)
	c.Assert(err, check.IsNil)

	err = app.EnableRoutes(&machine1, prefix.String())
	c.Assert(err, check.IsNil)

	// We do not enable this one on purpose to test that it is not enabled
	// err = app.EnableRoutes(&machine1, prefix2.String())
	// c.Assert(err, check.IsNil)

	err = app.EnableRoutes(&machine1, prefixExitNodeV4.String())
	c.Assert(err, check.IsNil)

	err = app.EnableRoutes(&machine1, prefixExitNodeV6.String())
	c.Assert(err, check.IsNil)

	err = app.handlePrimarySubnetFailover()
	c.Assert(err, check.IsNil)

	enabledRoutes1, err := app.GetEnabledRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 3)

	peer, err := app.toNode(machine1, "headscale.net", nil)
	c.Assert(err, check.IsNil)

	c.Assert(len(peer.AllowedIPs), check.Equals, 3)

	foundExitNodeV4 := false
	foundExitNodeV6 := false
	for _, allowedIP := range peer.AllowedIPs {
		if allowedIP == prefixExitNodeV4 {
			foundExitNodeV4 = true
		}
		if allowedIP == prefixExitNodeV6 {
			foundExitNodeV6 = true
		}
	}

	c.Assert(foundExitNodeV4, check.Equals, true)
	c.Assert(foundExitNodeV6, check.Equals, true)
}
