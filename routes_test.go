package headscale

import (
	"encoding/json"

	"gopkg.in/check.v1"
	"gorm.io/datatypes"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
)

func (s *Suite) TestGetRoutes(c *check.C) {
	n, err := h.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := h.CreatePreAuthKey(n.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = h.GetMachine("test", "test_get_route_machine")
	c.Assert(err, check.NotNil)

	route, err := netaddr.ParseIPPrefix("10.0.0.0/24")
	c.Assert(err, check.IsNil)

	hi := tailcfg.Hostinfo{
		RoutableIPs: []netaddr.IPPrefix{route},
	}
	hostinfo, err := json.Marshal(hi)
	c.Assert(err, check.IsNil)

	m := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "test_get_route_machine",
		NamespaceID:    n.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		AuthKeyID:      uint(pak.ID),
		HostInfo:       datatypes.JSON(hostinfo),
	}
	h.db.Save(&m)

	r, err := h.GetAdvertisedNodeRoutes("test", "test_get_route_machine")
	c.Assert(err, check.IsNil)
	c.Assert(len(*r), check.Equals, 1)

	err = h.EnableNodeRoute("test", "test_get_route_machine", "192.168.0.0/24")
	c.Assert(err, check.NotNil)

	err = h.EnableNodeRoute("test", "test_get_route_machine", "10.0.0.0/24")
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetEnableRoutes(c *check.C) {
	n, err := h.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := h.CreatePreAuthKey(n.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = h.GetMachine("test", "test_enable_route_machine")
	c.Assert(err, check.NotNil)

	route, err := netaddr.ParseIPPrefix(
		"10.0.0.0/24",
	)
	c.Assert(err, check.IsNil)

	route2, err := netaddr.ParseIPPrefix(
		"150.0.10.0/25",
	)
	c.Assert(err, check.IsNil)

	hi := tailcfg.Hostinfo{
		RoutableIPs: []netaddr.IPPrefix{route, route2},
	}
	hostinfo, err := json.Marshal(hi)
	c.Assert(err, check.IsNil)

	m := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "test_enable_route_machine",
		NamespaceID:    n.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		AuthKeyID:      uint(pak.ID),
		HostInfo:       datatypes.JSON(hostinfo),
	}
	h.db.Save(&m)

	availableRoutes, err := h.GetAdvertisedNodeRoutes("test", "test_enable_route_machine")
	c.Assert(err, check.IsNil)
	c.Assert(len(*availableRoutes), check.Equals, 2)

	enabledRoutes, err := h.GetEnabledNodeRoutes("test", "test_enable_route_machine")
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes), check.Equals, 0)

	err = h.EnableNodeRoute("test", "test_enable_route_machine", "192.168.0.0/24")
	c.Assert(err, check.NotNil)

	err = h.EnableNodeRoute("test", "test_enable_route_machine", "10.0.0.0/24")
	c.Assert(err, check.IsNil)

	enabledRoutes1, err := h.GetEnabledNodeRoutes("test", "test_enable_route_machine")
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 1)

	// Adding it twice will just let it pass through
	err = h.EnableNodeRoute("test", "test_enable_route_machine", "10.0.0.0/24")
	c.Assert(err, check.IsNil)

	enabledRoutes2, err := h.GetEnabledNodeRoutes("test", "test_enable_route_machine")
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes2), check.Equals, 1)

	err = h.EnableNodeRoute("test", "test_enable_route_machine", "150.0.10.0/25")
	c.Assert(err, check.IsNil)

	enabledRoutes3, err := h.GetEnabledNodeRoutes("test", "test_enable_route_machine")
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes3), check.Equals, 2)
}
