package hscontrol

import (
	"net/netip"
	"time"

	"github.com/juanfont/headscale/hscontrol/util"
	"gopkg.in/check.v1"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func (s *Suite) TestGetRoutes(c *check.C) {
	user, err := app.db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.db.GetMachine("test", "test_get_route_machine")
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
	app.db.db.Save(&machine)

	err = app.db.processMachineRoutes(&machine)
	c.Assert(err, check.IsNil)

	advertisedRoutes, err := app.db.GetAdvertisedRoutes(&machine)
	c.Assert(err, check.IsNil)
	c.Assert(len(advertisedRoutes), check.Equals, 1)

	err = app.db.enableRoutes(&machine, "192.168.0.0/24")
	c.Assert(err, check.NotNil)

	err = app.db.enableRoutes(&machine, "10.0.0.0/24")
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetEnableRoutes(c *check.C) {
	user, err := app.db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.db.GetMachine("test", "test_enable_route_machine")
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
	app.db.db.Save(&machine)

	err = app.db.processMachineRoutes(&machine)
	c.Assert(err, check.IsNil)

	availableRoutes, err := app.db.GetAdvertisedRoutes(&machine)
	c.Assert(err, check.IsNil)
	c.Assert(err, check.IsNil)
	c.Assert(len(availableRoutes), check.Equals, 2)

	noEnabledRoutes, err := app.db.GetEnabledRoutes(&machine)
	c.Assert(err, check.IsNil)
	c.Assert(len(noEnabledRoutes), check.Equals, 0)

	err = app.db.enableRoutes(&machine, "192.168.0.0/24")
	c.Assert(err, check.NotNil)

	err = app.db.enableRoutes(&machine, "10.0.0.0/24")
	c.Assert(err, check.IsNil)

	enabledRoutes, err := app.db.GetEnabledRoutes(&machine)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes), check.Equals, 1)

	// Adding it twice will just let it pass through
	err = app.db.enableRoutes(&machine, "10.0.0.0/24")
	c.Assert(err, check.IsNil)

	enableRoutesAfterDoubleApply, err := app.db.GetEnabledRoutes(&machine)
	c.Assert(err, check.IsNil)
	c.Assert(len(enableRoutesAfterDoubleApply), check.Equals, 1)

	err = app.db.enableRoutes(&machine, "150.0.10.0/25")
	c.Assert(err, check.IsNil)

	enabledRoutesWithAdditionalRoute, err := app.db.GetEnabledRoutes(&machine)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutesWithAdditionalRoute), check.Equals, 2)
}

func (s *Suite) TestIsUniquePrefix(c *check.C) {
	user, err := app.db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.db.GetMachine("test", "test_enable_route_machine")
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
	app.db.db.Save(&machine1)

	err = app.db.processMachineRoutes(&machine1)
	c.Assert(err, check.IsNil)

	err = app.db.enableRoutes(&machine1, route.String())
	c.Assert(err, check.IsNil)

	err = app.db.enableRoutes(&machine1, route2.String())
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
	app.db.db.Save(&machine2)

	err = app.db.processMachineRoutes(&machine2)
	c.Assert(err, check.IsNil)

	err = app.db.enableRoutes(&machine2, route2.String())
	c.Assert(err, check.IsNil)

	enabledRoutes1, err := app.db.GetEnabledRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 2)

	enabledRoutes2, err := app.db.GetEnabledRoutes(&machine2)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes2), check.Equals, 1)

	routes, err := app.db.getMachinePrimaryRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 2)

	routes, err = app.db.getMachinePrimaryRoutes(&machine2)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 0)
}

func (s *Suite) TestSubnetFailover(c *check.C) {
	user, err := app.db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.db.GetMachine("test", "test_enable_route_machine")
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
	app.db.db.Save(&machine1)

	err = app.db.processMachineRoutes(&machine1)
	c.Assert(err, check.IsNil)

	err = app.db.enableRoutes(&machine1, prefix.String())
	c.Assert(err, check.IsNil)

	err = app.db.enableRoutes(&machine1, prefix2.String())
	c.Assert(err, check.IsNil)

	err = app.db.handlePrimarySubnetFailover()
	c.Assert(err, check.IsNil)

	enabledRoutes1, err := app.db.GetEnabledRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 2)

	route, err := app.db.getPrimaryRoute(prefix)
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
	app.db.db.Save(&machine2)

	err = app.db.processMachineRoutes(&machine2)
	c.Assert(err, check.IsNil)

	err = app.db.enableRoutes(&machine2, prefix2.String())
	c.Assert(err, check.IsNil)

	err = app.db.handlePrimarySubnetFailover()
	c.Assert(err, check.IsNil)

	enabledRoutes1, err = app.db.GetEnabledRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 2)

	enabledRoutes2, err := app.db.GetEnabledRoutes(&machine2)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes2), check.Equals, 1)

	routes, err := app.db.getMachinePrimaryRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 2)

	routes, err = app.db.getMachinePrimaryRoutes(&machine2)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 0)

	// lets make machine1 lastseen 10 mins ago
	before := now.Add(-10 * time.Minute)
	machine1.LastSeen = &before
	err = app.db.db.Save(&machine1).Error
	c.Assert(err, check.IsNil)

	err = app.db.handlePrimarySubnetFailover()
	c.Assert(err, check.IsNil)

	routes, err = app.db.getMachinePrimaryRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 1)

	routes, err = app.db.getMachinePrimaryRoutes(&machine2)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 1)

	machine2.HostInfo = HostInfo(tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{prefix, prefix2},
	})
	err = app.db.db.Save(&machine2).Error
	c.Assert(err, check.IsNil)

	err = app.db.processMachineRoutes(&machine2)
	c.Assert(err, check.IsNil)

	err = app.db.enableRoutes(&machine2, prefix.String())
	c.Assert(err, check.IsNil)

	err = app.db.handlePrimarySubnetFailover()
	c.Assert(err, check.IsNil)

	routes, err = app.db.getMachinePrimaryRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 0)

	routes, err = app.db.getMachinePrimaryRoutes(&machine2)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 2)
}

// TestAllowedIPRoutes tests that the AllowedIPs are correctly set for a node,
// including both the primary routes the node is responsible for, and the
// exit node routes if enabled.
func (s *Suite) TestAllowedIPRoutes(c *check.C) {
	user, err := app.db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.db.GetMachine("test", "test_enable_route_machine")
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
		MachineKey:     util.MachinePublicKeyStripPrefix(machineKey.Public()),
		NodeKey:        util.NodePublicKeyStripPrefix(nodeKey.Public()),
		DiscoKey:       util.DiscoPublicKeyStripPrefix(discoKey.Public()),
		Hostname:       "test_enable_route_machine",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       HostInfo(hostInfo1),
		LastSeen:       &now,
	}
	app.db.db.Save(&machine1)

	err = app.db.processMachineRoutes(&machine1)
	c.Assert(err, check.IsNil)

	err = app.db.enableRoutes(&machine1, prefix.String())
	c.Assert(err, check.IsNil)

	// We do not enable this one on purpose to test that it is not enabled
	// err = app.db.enableRoutes(&machine1, prefix2.String())
	// c.Assert(err, check.IsNil)

	routes, err := app.db.GetMachineRoutes(&machine1)
	c.Assert(err, check.IsNil)
	for _, route := range routes {
		if route.isExitRoute() {
			err = app.db.EnableRoute(uint64(route.ID))
			c.Assert(err, check.IsNil)

			// We only enable one exit route, so we can test that both are enabled
			break
		}
	}

	err = app.db.handlePrimarySubnetFailover()
	c.Assert(err, check.IsNil)

	enabledRoutes1, err := app.db.GetEnabledRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 3)

	peer, err := app.db.toNode(machine1, app.aclPolicy, "headscale.net", nil)
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

	// Now we disable only one of the exit routes
	// and we see if both are disabled
	var exitRouteV4 Route
	for _, route := range routes {
		if route.isExitRoute() && netip.Prefix(route.Prefix) == prefixExitNodeV4 {
			exitRouteV4 = route

			break
		}
	}

	err = app.db.DisableRoute(uint64(exitRouteV4.ID))
	c.Assert(err, check.IsNil)

	enabledRoutes1, err = app.db.GetEnabledRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 1)

	// and now we delete only one of the exit routes
	// and we check if both are deleted
	routes, err = app.db.GetMachineRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 4)

	err = app.db.DeleteRoute(uint64(exitRouteV4.ID))
	c.Assert(err, check.IsNil)

	routes, err = app.db.GetMachineRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 2)
}

func (s *Suite) TestDeleteRoutes(c *check.C) {
	user, err := app.db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.db.GetMachine("test", "test_enable_route_machine")
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
	app.db.db.Save(&machine1)

	err = app.db.processMachineRoutes(&machine1)
	c.Assert(err, check.IsNil)

	err = app.db.enableRoutes(&machine1, prefix.String())
	c.Assert(err, check.IsNil)

	err = app.db.enableRoutes(&machine1, prefix2.String())
	c.Assert(err, check.IsNil)

	routes, err := app.db.GetMachineRoutes(&machine1)
	c.Assert(err, check.IsNil)

	err = app.db.DeleteRoute(uint64(routes[0].ID))
	c.Assert(err, check.IsNil)

	enabledRoutes1, err := app.db.GetEnabledRoutes(&machine1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 1)
}
