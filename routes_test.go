package headscale

import (
	"encoding/json"

	"gopkg.in/check.v1"
	"gorm.io/datatypes"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
)

var _ = check.Suite(&Suite{})

func (s *Suite) TestGetRoutes(c *check.C) {
	n, err := h.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := h.CreatePreAuthKey(n.Name, false, nil)
	c.Assert(err, check.IsNil)

	db, err := h.db()
	if err != nil {
		c.Fatal(err)
	}
	defer db.Close()

	_, err = h.GetMachine("test", "testmachine")
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
		Name:           "testmachine",
		NamespaceID:    n.ID,
		Registered:     true,
		RegisterMethod: "authKey",
		AuthKeyID:      uint(pak.ID),
		HostInfo:       datatypes.JSON(hostinfo),
	}
	db.Save(&m)

	r, err := h.GetNodeRoutes("test", "testmachine")
	c.Assert(err, check.IsNil)
	c.Assert(len(*r), check.Equals, 1)

	_, err = h.EnableNodeRoute("test", "testmachine", "192.168.0.0/24")
	c.Assert(err, check.NotNil)

	_, err = h.EnableNodeRoute("test", "testmachine", "10.0.0.0/24")
	c.Assert(err, check.IsNil)

}
