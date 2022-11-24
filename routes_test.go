package headscale

import (
	"net/netip"

	"gopkg.in/check.v1"
	"tailscale.com/tailcfg"
)

func (s *Suite) TestGetRoutes(c *check.C) {
	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil, nil)
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
		NamespaceID:    namespace.ID,
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
	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil, nil)
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
		NamespaceID:    namespace.ID,
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
	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil, nil)
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
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_enable_route_machine",
		NamespaceID:    namespace.ID,
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
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "test_enable_route_machine",
		NamespaceID:    namespace.ID,
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
