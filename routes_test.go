package headscale

import (
	"encoding/json"

	"gopkg.in/check.v1"
	"gorm.io/datatypes"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
)

func (s *Suite) TestGetRoutes(c *check.C) {
	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("test", "test_get_route_machine")
	c.Assert(err, check.NotNil)

	route, err := netaddr.ParseIPPrefix("10.0.0.0/24")
	c.Assert(err, check.IsNil)

	hostInfo := tailcfg.Hostinfo{
		RoutableIPs: []netaddr.IPPrefix{route},
	}
	hostinfo, err := json.Marshal(hostInfo)
	c.Assert(err, check.IsNil)

	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "test_get_route_machine",
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		AuthKeyID:      uint(pak.ID),
		HostInfo:       datatypes.JSON(hostinfo),
	}
	app.db.Save(&machine)

	advertisedRoutes, err := app.GetAdvertisedNodeRoutes(
		"test",
		"test_get_route_machine",
	)
	c.Assert(err, check.IsNil)
	c.Assert(len(*advertisedRoutes), check.Equals, 1)

	err = app.EnableNodeRoute("test", "test_get_route_machine", "192.168.0.0/24")
	c.Assert(err, check.NotNil)

	err = app.EnableNodeRoute("test", "test_get_route_machine", "10.0.0.0/24")
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetEnableRoutes(c *check.C) {
	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("test", "test_enable_route_machine")
	c.Assert(err, check.NotNil)

	route, err := netaddr.ParseIPPrefix(
		"10.0.0.0/24",
	)
	c.Assert(err, check.IsNil)

	route2, err := netaddr.ParseIPPrefix(
		"150.0.10.0/25",
	)
	c.Assert(err, check.IsNil)

	hostInfo := tailcfg.Hostinfo{
		RoutableIPs: []netaddr.IPPrefix{route, route2},
	}
	hostinfo, err := json.Marshal(hostInfo)
	c.Assert(err, check.IsNil)

	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "test_enable_route_machine",
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		AuthKeyID:      uint(pak.ID),
		HostInfo:       datatypes.JSON(hostinfo),
	}
	app.db.Save(&machine)

	availableRoutes, err := app.GetAdvertisedNodeRoutes(
		"test",
		"test_enable_route_machine",
	)
	c.Assert(err, check.IsNil)
	c.Assert(len(*availableRoutes), check.Equals, 2)

	noEnabledRoutes, err := app.GetEnabledNodeRoutes(
		"test",
		"test_enable_route_machine",
	)
	c.Assert(err, check.IsNil)
	c.Assert(len(noEnabledRoutes), check.Equals, 0)

	err = app.EnableNodeRoute("test", "test_enable_route_machine", "192.168.0.0/24")
	c.Assert(err, check.NotNil)

	err = app.EnableNodeRoute("test", "test_enable_route_machine", "10.0.0.0/24")
	c.Assert(err, check.IsNil)

	enabledRoutes, err := app.GetEnabledNodeRoutes("test", "test_enable_route_machine")
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes), check.Equals, 1)

	// Adding it twice will just let it pass through
	err = app.EnableNodeRoute("test", "test_enable_route_machine", "10.0.0.0/24")
	c.Assert(err, check.IsNil)

	enableRoutesAfterDoubleApply, err := app.GetEnabledNodeRoutes(
		"test",
		"test_enable_route_machine",
	)
	c.Assert(err, check.IsNil)
	c.Assert(len(enableRoutesAfterDoubleApply), check.Equals, 1)

	err = app.EnableNodeRoute("test", "test_enable_route_machine", "150.0.10.0/25")
	c.Assert(err, check.IsNil)

	enabledRoutesWithAdditionalRoute, err := app.GetEnabledNodeRoutes(
		"test",
		"test_enable_route_machine",
	)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutesWithAdditionalRoute), check.Equals, 2)
}
