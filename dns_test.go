package headscale

import (
	"fmt"

	"gopkg.in/check.v1"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

func (s *Suite) TestMagicDNSRootDomains100(c *check.C) {
	prefix := netaddr.MustParseIPPrefix("100.64.0.0/10")
	domains, err := generateMagicDNSRootDomains(prefix, "foobar.headscale.net")
	c.Assert(err, check.IsNil)

	found := false
	for _, domain := range domains {
		if domain == "64.100.in-addr.arpa." {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, true)

	found = false
	for _, domain := range domains {
		if domain == "100.100.in-addr.arpa." {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, true)

	found = false
	for _, domain := range domains {
		if domain == "127.100.in-addr.arpa." {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, true)
}

func (s *Suite) TestMagicDNSRootDomains172(c *check.C) {
	prefix := netaddr.MustParseIPPrefix("172.16.0.0/16")
	domains, err := generateMagicDNSRootDomains(prefix, "headscale.net")
	c.Assert(err, check.IsNil)

	found := false
	for _, domain := range domains {
		if domain == "0.16.172.in-addr.arpa." {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, true)

	found = false
	for _, domain := range domains {
		if domain == "255.16.172.in-addr.arpa." {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, true)
}

func (s *Suite) TestDNSConfigMapResponseWithMagicDNS(c *check.C) {
	n1, err := h.CreateNamespace("shared1")
	c.Assert(err, check.IsNil)

	n2, err := h.CreateNamespace("shared2")
	c.Assert(err, check.IsNil)

	n3, err := h.CreateNamespace("shared3")
	c.Assert(err, check.IsNil)

	pak1n1, err := h.CreatePreAuthKey(n1.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	pak2n2, err := h.CreatePreAuthKey(n2.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	pak3n3, err := h.CreatePreAuthKey(n3.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	pak4n1, err := h.CreatePreAuthKey(n1.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = h.GetMachine(n1.Name, "test_get_shared_nodes_1")
	c.Assert(err, check.NotNil)

	m1 := &Machine{
		ID:             1,
		MachineKey:     "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		NodeKey:        "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		DiscoKey:       "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		Name:           "test_get_shared_nodes_1",
		NamespaceID:    n1.ID,
		Namespace:      *n1,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.1",
		AuthKeyID:      uint(pak1n1.ID),
	}
	h.db.Save(m1)

	_, err = h.GetMachine(n1.Name, m1.Name)
	c.Assert(err, check.IsNil)

	m2 := &Machine{
		ID:             2,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_2",
		NamespaceID:    n2.ID,
		Namespace:      *n2,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.2",
		AuthKeyID:      uint(pak2n2.ID),
	}
	h.db.Save(m2)

	_, err = h.GetMachine(n2.Name, m2.Name)
	c.Assert(err, check.IsNil)

	m3 := &Machine{
		ID:             3,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_3",
		NamespaceID:    n3.ID,
		Namespace:      *n3,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.3",
		AuthKeyID:      uint(pak3n3.ID),
	}
	h.db.Save(m3)

	_, err = h.GetMachine(n3.Name, m3.Name)
	c.Assert(err, check.IsNil)

	m4 := &Machine{
		ID:             4,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_4",
		NamespaceID:    n1.ID,
		Namespace:      *n1,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.4",
		AuthKeyID:      uint(pak4n1.ID),
	}
	h.db.Save(m4)

	err = h.AddSharedMachineToNamespace(m2, n1)
	c.Assert(err, check.IsNil)

	baseDomain := "foobar.headscale.net"
	dnsConfigOrig := tailcfg.DNSConfig{
		Routes:  make(map[string][]dnstype.Resolver),
		Domains: []string{baseDomain},
		Proxied: true,
	}

	m1peers, err := h.getPeers(m1)
	c.Assert(err, check.IsNil)

	dnsConfig, err := getMapResponseDNSConfig(&dnsConfigOrig, baseDomain, *m1, m1peers)
	c.Assert(err, check.IsNil)
	c.Assert(dnsConfig, check.NotNil)
	c.Assert(len(dnsConfig.Routes), check.Equals, 2)

	routeN1 := fmt.Sprintf("%s.%s", n1.Name, baseDomain)
	_, ok := dnsConfig.Routes[routeN1]
	c.Assert(ok, check.Equals, true)

	routeN2 := fmt.Sprintf("%s.%s", n2.Name, baseDomain)
	_, ok = dnsConfig.Routes[routeN2]
	c.Assert(ok, check.Equals, true)

	routeN3 := fmt.Sprintf("%s.%s", n3.Name, baseDomain)
	_, ok = dnsConfig.Routes[routeN3]
	c.Assert(ok, check.Equals, false)
}

func (s *Suite) TestDNSConfigMapResponseWithoutMagicDNS(c *check.C) {
	n1, err := h.CreateNamespace("shared1")
	c.Assert(err, check.IsNil)

	n2, err := h.CreateNamespace("shared2")
	c.Assert(err, check.IsNil)

	n3, err := h.CreateNamespace("shared3")
	c.Assert(err, check.IsNil)

	pak1n1, err := h.CreatePreAuthKey(n1.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	pak2n2, err := h.CreatePreAuthKey(n2.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	pak3n3, err := h.CreatePreAuthKey(n3.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	pak4n1, err := h.CreatePreAuthKey(n1.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = h.GetMachine(n1.Name, "test_get_shared_nodes_1")
	c.Assert(err, check.NotNil)

	m1 := &Machine{
		ID:             1,
		MachineKey:     "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		NodeKey:        "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		DiscoKey:       "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		Name:           "test_get_shared_nodes_1",
		NamespaceID:    n1.ID,
		Namespace:      *n1,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.1",
		AuthKeyID:      uint(pak1n1.ID),
	}
	h.db.Save(m1)

	_, err = h.GetMachine(n1.Name, m1.Name)
	c.Assert(err, check.IsNil)

	m2 := &Machine{
		ID:             2,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_2",
		NamespaceID:    n2.ID,
		Namespace:      *n2,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.2",
		AuthKeyID:      uint(pak2n2.ID),
	}
	h.db.Save(m2)

	_, err = h.GetMachine(n2.Name, m2.Name)
	c.Assert(err, check.IsNil)

	m3 := &Machine{
		ID:             3,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_3",
		NamespaceID:    n3.ID,
		Namespace:      *n3,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.3",
		AuthKeyID:      uint(pak3n3.ID),
	}
	h.db.Save(m3)

	_, err = h.GetMachine(n3.Name, m3.Name)
	c.Assert(err, check.IsNil)

	m4 := &Machine{
		ID:             4,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_4",
		NamespaceID:    n1.ID,
		Namespace:      *n1,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.4",
		AuthKeyID:      uint(pak4n1.ID),
	}
	h.db.Save(m4)

	err = h.AddSharedMachineToNamespace(m2, n1)
	c.Assert(err, check.IsNil)

	baseDomain := "foobar.headscale.net"
	dnsConfigOrig := tailcfg.DNSConfig{
		Routes:  make(map[string][]dnstype.Resolver),
		Domains: []string{baseDomain},
		Proxied: false,
	}

	m1peers, err := h.getPeers(m1)
	c.Assert(err, check.IsNil)

	dnsConfig, err := getMapResponseDNSConfig(&dnsConfigOrig, baseDomain, *m1, m1peers)
	c.Assert(err, check.IsNil)
	c.Assert(dnsConfig, check.NotNil)
	c.Assert(len(dnsConfig.Routes), check.Equals, 0)
	c.Assert(len(dnsConfig.Domains), check.Equals, 1)
}
