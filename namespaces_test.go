package headscale

import (
	"github.com/rs/zerolog/log"
	"gopkg.in/check.v1"
)

func (s *Suite) TestCreateAndDestroyNamespace(c *check.C) {
	n, err := h.CreateNamespace("test")
	c.Assert(err, check.IsNil)
	c.Assert(n.Name, check.Equals, "test")

	ns, err := h.ListNamespaces()
	c.Assert(err, check.IsNil)
	c.Assert(len(*ns), check.Equals, 1)

	err = h.DestroyNamespace("test")
	c.Assert(err, check.IsNil)

	_, err = h.GetNamespace("test")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestDestroyNamespaceErrors(c *check.C) {
	err := h.DestroyNamespace("test")
	c.Assert(err, check.Equals, errorNamespaceNotFound)

	n, err := h.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := h.CreatePreAuthKey(n.Name, false, false, nil)
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
	}
	h.db.Save(&m)

	err = h.DestroyNamespace("test")
	c.Assert(err, check.Equals, errorNamespaceNotEmpty)
}

func (s *Suite) TestGetMapResponseUserProfiles(c *check.C) {
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
	m1peers, err := h.getPeers(m1)
	c.Assert(err, check.IsNil)

	userProfiles := getMapResponseUserProfiles(*m1, m1peers)

	log.Trace().Msgf("userProfiles %#v", userProfiles)
	c.Assert(len(userProfiles), check.Equals, 2)

	found := false
	for _, up := range userProfiles {
		if up.DisplayName == n1.Name {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, true)

	found = false
	for _, up := range userProfiles {
		if up.DisplayName == n2.Name {
			found = true
			break
		}
	}
	c.Assert(found, check.Equals, true)
}
