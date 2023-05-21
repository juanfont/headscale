package db

import (
	"net/netip"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"gopkg.in/check.v1"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
)

// TODO(kradalby):
// Convert these tests to being non-database dependent and table driven. They are
// very verbose, and dont really need the database.

func (s *Suite) TestSshRules(c *check.C) {
	envknob.Setenv("HEADSCALE_EXPERIMENTAL_FEATURE_SSH", "1")

	user, err := db.CreateUser("user1")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetMachine("user1", "testmachine")
	c.Assert(err, check.NotNil)
	hostInfo := tailcfg.Hostinfo{
		OS:          "centos",
		Hostname:    "testmachine",
		RequestTags: []string{"tag:test"},
	}

	machine := types.Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		IPAddresses:    types.MachineAddresses{netip.MustParseAddr("100.64.0.1")},
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       types.HostInfo(hostInfo),
	}
	err = db.MachineSave(&machine)
	c.Assert(err, check.IsNil)

	aclPolicy := &policy.ACLPolicy{
		Groups: policy.Groups{
			"group:test": []string{"user1"},
		},
		Hosts: policy.Hosts{
			"client": netip.PrefixFrom(netip.MustParseAddr("100.64.99.42"), 32),
		},
		ACLs: []policy.ACL{
			{
				Action:       "accept",
				Sources:      []string{"*"},
				Destinations: []string{"*:*"},
			},
		},
		SSHs: []policy.SSH{
			{
				Action:       "accept",
				Sources:      []string{"group:test"},
				Destinations: []string{"client"},
				Users:        []string{"autogroup:nonroot"},
			},
			{
				Action:       "accept",
				Sources:      []string{"*"},
				Destinations: []string{"client"},
				Users:        []string{"autogroup:nonroot"},
			},
		},
	}

	_, sshPolicy, err := policy.GenerateFilterRules(aclPolicy, types.Machines{}, false)

	c.Assert(err, check.IsNil)
	c.Assert(sshPolicy, check.NotNil)
	c.Assert(sshPolicy.Rules, check.HasLen, 2)
	c.Assert(sshPolicy.Rules[0].SSHUsers, check.HasLen, 1)
	c.Assert(sshPolicy.Rules[0].Principals, check.HasLen, 1)
	c.Assert(sshPolicy.Rules[0].Principals[0].UserLogin, check.Matches, "user1")

	c.Assert(sshPolicy.Rules[1].SSHUsers, check.HasLen, 1)
	c.Assert(sshPolicy.Rules[1].Principals, check.HasLen, 1)
	c.Assert(sshPolicy.Rules[1].Principals[0].NodeIP, check.Matches, "*")
}

// this test should validate that we can expand a group in a TagOWner section and
// match properly the IP's of the related hosts. The owner is valid and the tag is also valid.
// the tag is matched in the Sources section.
func (s *Suite) TestValidExpandTagOwnersInSources(c *check.C) {
	user, err := db.CreateUser("user1")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetMachine("user1", "testmachine")
	c.Assert(err, check.NotNil)
	hostInfo := tailcfg.Hostinfo{
		OS:          "centos",
		Hostname:    "testmachine",
		RequestTags: []string{"tag:test"},
	}

	machine := types.Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		IPAddresses:    types.MachineAddresses{netip.MustParseAddr("100.64.0.1")},
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       types.HostInfo(hostInfo),
	}
	err = db.MachineSave(&machine)
	c.Assert(err, check.IsNil)

	pol := &policy.ACLPolicy{
		Groups:    policy.Groups{"group:test": []string{"user1", "user2"}},
		TagOwners: policy.TagOwners{"tag:test": []string{"user3", "group:test"}},
		ACLs: []policy.ACL{
			{
				Action:       "accept",
				Sources:      []string{"tag:test"},
				Destinations: []string{"*:*"},
			},
		},
	}

	machines, err := db.ListMachines()
	c.Assert(err, check.IsNil)

	rules, _, err := policy.GenerateFilterRules(pol, machines, false)
	c.Assert(err, check.IsNil)

	c.Assert(rules, check.HasLen, 1)
	c.Assert(rules[0].SrcIPs, check.HasLen, 1)
	c.Assert(rules[0].SrcIPs[0], check.Equals, "100.64.0.1/32")
}

// this test should validate that we can expand a group in a TagOWner section and
// match properly the IP's of the related hosts. The owner is valid and the tag is also valid.
// the tag is matched in the Destinations section.
func (s *Suite) TestValidExpandTagOwnersInDestinations(c *check.C) {
	user, err := db.CreateUser("user1")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetMachine("user1", "testmachine")
	c.Assert(err, check.NotNil)
	hostInfo := tailcfg.Hostinfo{
		OS:          "centos",
		Hostname:    "testmachine",
		RequestTags: []string{"tag:test"},
	}

	machine := types.Machine{
		ID:             1,
		MachineKey:     "12345",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		IPAddresses:    types.MachineAddresses{netip.MustParseAddr("100.64.0.1")},
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       types.HostInfo(hostInfo),
	}
	err = db.MachineSave(&machine)
	c.Assert(err, check.IsNil)

	pol := &policy.ACLPolicy{
		Groups:    policy.Groups{"group:test": []string{"user1", "user2"}},
		TagOwners: policy.TagOwners{"tag:test": []string{"user3", "group:test"}},
		ACLs: []policy.ACL{
			{
				Action:       "accept",
				Sources:      []string{"*"},
				Destinations: []string{"tag:test:*"},
			},
		},
	}

	machines, err := db.ListMachines()
	c.Assert(err, check.IsNil)

	rules, _, err := policy.GenerateFilterRules(pol, machines, false)
	c.Assert(err, check.IsNil)

	c.Assert(rules, check.HasLen, 1)
	c.Assert(rules[0].DstPorts, check.HasLen, 1)
	c.Assert(rules[0].DstPorts[0].IP, check.Equals, "100.64.0.1/32")
}

// need a test with:
// tag on a host that isn't owned by a tag owners. So the user
// of the host should be valid.
func (s *Suite) TestInvalidTagValidUser(c *check.C) {
	user, err := db.CreateUser("user1")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetMachine("user1", "testmachine")
	c.Assert(err, check.NotNil)
	hostInfo := tailcfg.Hostinfo{
		OS:          "centos",
		Hostname:    "testmachine",
		RequestTags: []string{"tag:foo"},
	}

	machine := types.Machine{
		ID:             1,
		MachineKey:     "12345",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		IPAddresses:    types.MachineAddresses{netip.MustParseAddr("100.64.0.1")},
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       types.HostInfo(hostInfo),
	}
	err = db.MachineSave(&machine)
	c.Assert(err, check.IsNil)

	pol := &policy.ACLPolicy{
		TagOwners: policy.TagOwners{"tag:test": []string{"user1"}},
		ACLs: []policy.ACL{
			{
				Action:       "accept",
				Sources:      []string{"user1"},
				Destinations: []string{"*:*"},
			},
		},
	}

	machines, err := db.ListMachines()
	c.Assert(err, check.IsNil)

	rules, _, err := policy.GenerateFilterRules(pol, machines, false)
	c.Assert(err, check.IsNil)

	c.Assert(rules, check.HasLen, 1)
	c.Assert(rules[0].SrcIPs, check.HasLen, 1)
	c.Assert(rules[0].SrcIPs[0], check.Equals, "100.64.0.1/32")
}

// tag on a host is owned by a tag owner, the tag is valid.
// an ACL rule is matching the tag to a user. It should not be valid since the
// host should be tied to the tag now.
func (s *Suite) TestValidTagInvalidUser(c *check.C) {
	user, err := db.CreateUser("user1")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetMachine("user1", "webserver")
	c.Assert(err, check.NotNil)
	hostInfo := tailcfg.Hostinfo{
		OS:          "centos",
		Hostname:    "webserver",
		RequestTags: []string{"tag:webapp"},
	}

	machine := types.Machine{
		ID:             1,
		MachineKey:     "12345",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "webserver",
		IPAddresses:    types.MachineAddresses{netip.MustParseAddr("100.64.0.1")},
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       types.HostInfo(hostInfo),
	}
	err = db.MachineSave(&machine)
	c.Assert(err, check.IsNil)

	_, err = db.GetMachine("user1", "user")
	hostInfo2 := tailcfg.Hostinfo{
		OS:       "debian",
		Hostname: "Hostname",
	}
	c.Assert(err, check.NotNil)
	machine = types.Machine{
		ID:             2,
		MachineKey:     "56789",
		NodeKey:        "bar2",
		DiscoKey:       "faab",
		Hostname:       "user",
		IPAddresses:    types.MachineAddresses{netip.MustParseAddr("100.64.0.2")},
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       types.HostInfo(hostInfo2),
	}
	err = db.MachineSave(&machine)
	c.Assert(err, check.IsNil)

	pol := &policy.ACLPolicy{
		TagOwners: policy.TagOwners{"tag:webapp": []string{"user1"}},
		ACLs: []policy.ACL{
			{
				Action:       "accept",
				Sources:      []string{"user1"},
				Destinations: []string{"tag:webapp:80,443"},
			},
		},
	}

	machines, err := db.ListMachines()
	c.Assert(err, check.IsNil)

	rules, _, err := policy.GenerateFilterRules(pol, machines, false)
	c.Assert(err, check.IsNil)

	c.Assert(rules, check.HasLen, 1)
	c.Assert(rules[0].SrcIPs, check.HasLen, 1)
	c.Assert(rules[0].SrcIPs[0], check.Equals, "100.64.0.2/32")
	c.Assert(rules[0].DstPorts, check.HasLen, 2)
	c.Assert(rules[0].DstPorts[0].Ports.First, check.Equals, uint16(80))
	c.Assert(rules[0].DstPorts[0].Ports.Last, check.Equals, uint16(80))
	c.Assert(rules[0].DstPorts[0].IP, check.Equals, "100.64.0.1/32")
	c.Assert(rules[0].DstPorts[1].Ports.First, check.Equals, uint16(443))
	c.Assert(rules[0].DstPorts[1].Ports.Last, check.Equals, uint16(443))
	c.Assert(rules[0].DstPorts[1].IP, check.Equals, "100.64.0.1/32")
}

func (s *Suite) TestPortUser(c *check.C) {
	user, err := db.CreateUser("testuser")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetMachine("testuser", "testmachine")
	c.Assert(err, check.NotNil)
	ips, _ := db.getAvailableIPs()
	machine := types.Machine{
		ID:             0,
		MachineKey:     "12345",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		IPAddresses:    ips,
		AuthKeyID:      uint(pak.ID),
	}
	err = db.MachineSave(&machine)
	c.Assert(err, check.IsNil)

	acl := []byte(`
{
	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"action": "accept",
			"src": [
				"testuser",
			],
			"dst": [
				"host-1:*",
			],
		},
	],
}
	`)
	pol, err := policy.LoadACLPolicyFromBytes(acl, "hujson")
	c.Assert(err, check.IsNil)
	c.Assert(pol, check.NotNil)

	machines, err := db.ListMachines()
	c.Assert(err, check.IsNil)

	rules, _, err := policy.GenerateFilterRules(pol, machines, false)
	c.Assert(err, check.IsNil)

	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

	c.Assert(rules, check.HasLen, 1)
	c.Assert(rules[0].DstPorts, check.HasLen, 1)
	c.Assert(rules[0].DstPorts[0].Ports.First, check.Equals, uint16(0))
	c.Assert(rules[0].DstPorts[0].Ports.Last, check.Equals, uint16(65535))
	c.Assert(rules[0].SrcIPs, check.HasLen, 1)
	c.Assert(rules[0].SrcIPs[0], check.Not(check.Equals), "not an ip")
	c.Assert(len(ips), check.Equals, 1)
	c.Assert(rules[0].SrcIPs[0], check.Equals, ips[0].String()+"/32")
}

func (s *Suite) TestPortGroup(c *check.C) {
	user, err := db.CreateUser("testuser")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetMachine("testuser", "testmachine")
	c.Assert(err, check.NotNil)
	ips, _ := db.getAvailableIPs()
	machine := types.Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		IPAddresses:    ips,
		AuthKeyID:      uint(pak.ID),
	}
	err = db.MachineSave(&machine)
	c.Assert(err, check.IsNil)

	acl := []byte(`
{
	"groups": {
		"group:example": [
			"testuser",
		],
	},

	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"action": "accept",
			"src": [
				"group:example",
			],
			"dst": [
				"host-1:*",
			],
		},
	],
}
	`)
	pol, err := policy.LoadACLPolicyFromBytes(acl, "hujson")
	c.Assert(err, check.IsNil)

	machines, err := db.ListMachines()
	c.Assert(err, check.IsNil)

	rules, _, err := policy.GenerateFilterRules(pol, machines, false)
	c.Assert(err, check.IsNil)

	c.Assert(rules, check.NotNil)

	c.Assert(rules, check.HasLen, 1)
	c.Assert(rules[0].DstPorts, check.HasLen, 1)
	c.Assert(rules[0].DstPorts[0].Ports.First, check.Equals, uint16(0))
	c.Assert(rules[0].DstPorts[0].Ports.Last, check.Equals, uint16(65535))
	c.Assert(rules[0].SrcIPs, check.HasLen, 1)
	c.Assert(rules[0].SrcIPs[0], check.Not(check.Equals), "not an ip")
	c.Assert(len(ips), check.Equals, 1)
	c.Assert(rules[0].SrcIPs[0], check.Equals, ips[0].String()+"/32")
}
