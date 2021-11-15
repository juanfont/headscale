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
	domains := generateMagicDNSRootDomains(prefix)

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
	domains := generateMagicDNSRootDomains(prefix)

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
	namespaceShared1, err := app.CreateNamespace("shared1")
	c.Assert(err, check.IsNil)

	namespaceShared2, err := app.CreateNamespace("shared2")
	c.Assert(err, check.IsNil)

	namespaceShared3, err := app.CreateNamespace("shared3")
	c.Assert(err, check.IsNil)

	preAuthKeyInShared1, err := app.CreatePreAuthKey(
		namespaceShared1.Name,
		false,
		false,
		nil,
	)
	c.Assert(err, check.IsNil)

	preAuthKeyInShared2, err := app.CreatePreAuthKey(
		namespaceShared2.Name,
		false,
		false,
		nil,
	)
	c.Assert(err, check.IsNil)

	preAuthKeyInShared3, err := app.CreatePreAuthKey(
		namespaceShared3.Name,
		false,
		false,
		nil,
	)
	c.Assert(err, check.IsNil)

	PreAuthKey2InShared1, err := app.CreatePreAuthKey(
		namespaceShared1.Name,
		false,
		false,
		nil,
	)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine(namespaceShared1.Name, "test_get_shared_nodes_1")
	c.Assert(err, check.NotNil)

	machineInShared1 := &Machine{
		ID:             1,
		MachineKey:     "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		NodeKey:        "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		DiscoKey:       "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		Name:           "test_get_shared_nodes_1",
		NamespaceID:    namespaceShared1.ID,
		Namespace:      *namespaceShared1,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.1",
		AuthKeyID:      uint(preAuthKeyInShared1.ID),
	}
	app.db.Save(machineInShared1)

	_, err = app.GetMachine(namespaceShared1.Name, machineInShared1.Name)
	c.Assert(err, check.IsNil)

	machineInShared2 := &Machine{
		ID:             2,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_2",
		NamespaceID:    namespaceShared2.ID,
		Namespace:      *namespaceShared2,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.2",
		AuthKeyID:      uint(preAuthKeyInShared2.ID),
	}
	app.db.Save(machineInShared2)

	_, err = app.GetMachine(namespaceShared2.Name, machineInShared2.Name)
	c.Assert(err, check.IsNil)

	machineInShared3 := &Machine{
		ID:             3,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_3",
		NamespaceID:    namespaceShared3.ID,
		Namespace:      *namespaceShared3,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.3",
		AuthKeyID:      uint(preAuthKeyInShared3.ID),
	}
	app.db.Save(machineInShared3)

	_, err = app.GetMachine(namespaceShared3.Name, machineInShared3.Name)
	c.Assert(err, check.IsNil)

	machine2InShared1 := &Machine{
		ID:             4,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_4",
		NamespaceID:    namespaceShared1.ID,
		Namespace:      *namespaceShared1,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.4",
		AuthKeyID:      uint(PreAuthKey2InShared1.ID),
	}
	app.db.Save(machine2InShared1)

	err = app.AddSharedMachineToNamespace(machineInShared2, namespaceShared1)
	c.Assert(err, check.IsNil)

	baseDomain := "foobar.headscale.net"
	dnsConfigOrig := tailcfg.DNSConfig{
		Routes:  make(map[string][]dnstype.Resolver),
		Domains: []string{baseDomain},
		Proxied: true,
	}

	peersOfMachineInShared1, err := app.getPeers(machineInShared1)
	c.Assert(err, check.IsNil)

	dnsConfig := getMapResponseDNSConfig(
		&dnsConfigOrig,
		baseDomain,
		*machineInShared1,
		peersOfMachineInShared1,
	)
	c.Assert(dnsConfig, check.NotNil)
	c.Assert(len(dnsConfig.Routes), check.Equals, 2)

	domainRouteShared1 := fmt.Sprintf("%s.%s", namespaceShared1.Name, baseDomain)
	_, ok := dnsConfig.Routes[domainRouteShared1]
	c.Assert(ok, check.Equals, true)

	domainRouteShared2 := fmt.Sprintf("%s.%s", namespaceShared2.Name, baseDomain)
	_, ok = dnsConfig.Routes[domainRouteShared2]
	c.Assert(ok, check.Equals, true)

	domainRouteShared3 := fmt.Sprintf("%s.%s", namespaceShared3.Name, baseDomain)
	_, ok = dnsConfig.Routes[domainRouteShared3]
	c.Assert(ok, check.Equals, false)
}

func (s *Suite) TestDNSConfigMapResponseWithoutMagicDNS(c *check.C) {
	namespaceShared1, err := app.CreateNamespace("shared1")
	c.Assert(err, check.IsNil)

	namespaceShared2, err := app.CreateNamespace("shared2")
	c.Assert(err, check.IsNil)

	namespaceShared3, err := app.CreateNamespace("shared3")
	c.Assert(err, check.IsNil)

	preAuthKeyInShared1, err := app.CreatePreAuthKey(
		namespaceShared1.Name,
		false,
		false,
		nil,
	)
	c.Assert(err, check.IsNil)

	preAuthKeyInShared2, err := app.CreatePreAuthKey(
		namespaceShared2.Name,
		false,
		false,
		nil,
	)
	c.Assert(err, check.IsNil)

	preAuthKeyInShared3, err := app.CreatePreAuthKey(
		namespaceShared3.Name,
		false,
		false,
		nil,
	)
	c.Assert(err, check.IsNil)

	preAuthKey2InShared1, err := app.CreatePreAuthKey(
		namespaceShared1.Name,
		false,
		false,
		nil,
	)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine(namespaceShared1.Name, "test_get_shared_nodes_1")
	c.Assert(err, check.NotNil)

	machineInShared1 := &Machine{
		ID:             1,
		MachineKey:     "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		NodeKey:        "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		DiscoKey:       "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		Name:           "test_get_shared_nodes_1",
		NamespaceID:    namespaceShared1.ID,
		Namespace:      *namespaceShared1,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.1",
		AuthKeyID:      uint(preAuthKeyInShared1.ID),
	}
	app.db.Save(machineInShared1)

	_, err = app.GetMachine(namespaceShared1.Name, machineInShared1.Name)
	c.Assert(err, check.IsNil)

	machineInShared2 := &Machine{
		ID:             2,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_2",
		NamespaceID:    namespaceShared2.ID,
		Namespace:      *namespaceShared2,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.2",
		AuthKeyID:      uint(preAuthKeyInShared2.ID),
	}
	app.db.Save(machineInShared2)

	_, err = app.GetMachine(namespaceShared2.Name, machineInShared2.Name)
	c.Assert(err, check.IsNil)

	machineInShared3 := &Machine{
		ID:             3,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_3",
		NamespaceID:    namespaceShared3.ID,
		Namespace:      *namespaceShared3,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.3",
		AuthKeyID:      uint(preAuthKeyInShared3.ID),
	}
	app.db.Save(machineInShared3)

	_, err = app.GetMachine(namespaceShared3.Name, machineInShared3.Name)
	c.Assert(err, check.IsNil)

	machine2InShared1 := &Machine{
		ID:             4,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Name:           "test_get_shared_nodes_4",
		NamespaceID:    namespaceShared1.ID,
		Namespace:      *namespaceShared1,
		Registered:     true,
		RegisterMethod: "authKey",
		IPAddress:      "100.64.0.4",
		AuthKeyID:      uint(preAuthKey2InShared1.ID),
	}
	app.db.Save(machine2InShared1)

	err = app.AddSharedMachineToNamespace(machineInShared2, namespaceShared1)
	c.Assert(err, check.IsNil)

	baseDomain := "foobar.headscale.net"
	dnsConfigOrig := tailcfg.DNSConfig{
		Routes:  make(map[string][]dnstype.Resolver),
		Domains: []string{baseDomain},
		Proxied: false,
	}

	peersOfMachine1Shared1, err := app.getPeers(machineInShared1)
	c.Assert(err, check.IsNil)

	dnsConfig := getMapResponseDNSConfig(
		&dnsConfigOrig,
		baseDomain,
		*machineInShared1,
		peersOfMachine1Shared1,
	)
	c.Assert(dnsConfig, check.NotNil)
	c.Assert(len(dnsConfig.Routes), check.Equals, 0)
	c.Assert(len(dnsConfig.Domains), check.Equals, 1)
}
