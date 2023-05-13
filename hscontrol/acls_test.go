package hscontrol

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/rs/zerolog/log"
	"go4.org/netipx"
	"gopkg.in/check.v1"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
)

func (s *Suite) TestWrongPath(c *check.C) {
	err := app.LoadACLPolicyFromPath("asdfg")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestBrokenHuJson(c *check.C) {
	acl := []byte(`
{
	`)
	err := app.LoadACLPolicyFromBytes(acl, "hujson")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestInvalidPolicyHuson(c *check.C) {
	acl := []byte(`
{
    "valid_json": true,
    "but_a_policy_though": false
}
	`)
	err := app.LoadACLPolicyFromBytes(acl, "hujson")
	c.Assert(err, check.NotNil)
	c.Assert(err, check.Equals, errEmptyPolicy)
}

func (s *Suite) TestParseHosts(c *check.C) {
	var hosts Hosts
	err := hosts.UnmarshalJSON(
		[]byte(
			`{"example-host-1": "100.100.100.100","example-host-2": "100.100.101.100/24"}`,
		),
	)
	c.Assert(hosts, check.NotNil)
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestParseInvalidCIDR(c *check.C) {
	var hosts Hosts
	err := hosts.UnmarshalJSON([]byte(`{"example-host-1": "100.100.100.100/42"}`))
	c.Assert(hosts, check.IsNil)
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestRuleInvalidGeneration(c *check.C) {
	acl := []byte(`
{
    // Declare static groups of users beyond those in the identity service.
    "groups": {
        "group:example": [
            "user1@example.com",
            "user2@example.com",
        ],
    },
    // Declare hostname aliases to use in place of IP addresses or subnets.
    "hosts": {
        "example-host-1": "100.100.100.100",
        "example-host-2": "100.100.101.100/24",
    },
    // Define who is allowed to use which tags.
    "tagOwners": {
        // Everyone in the montreal-admins or global-admins group are
        // allowed to tag servers as montreal-webserver.
        "tag:montreal-webserver": [
            "group:montreal-admins",
            "group:global-admins",
        ],
        // Only a few admins are allowed to create API servers.
        "tag:api-server": [
            "group:global-admins",
            "example-host-1",
        ],
    },
    // Access control lists.
    "acls": [
        // Engineering users, plus the president, can access port 22 (ssh)
        // and port 3389 (remote desktop protocol) on all servers, and all
        // ports on git-server or ci-server.
        {
            "action": "accept",
            "src": [
                "group:engineering",
                "president@example.com"
            ],
            "dst": [
                "*:22,3389",
                "git-server:*",
                "ci-server:*"
            ],
        },
        // Allow engineer users to access any port on a device tagged with
        // tag:production.
        {
            "action": "accept",
            "src": [
                "group:engineers"
            ],
            "dst": [
                "tag:production:*"
            ],
        },
        // Allow servers in the my-subnet host and 192.168.1.0/24 to access hosts
        // on both networks.
        {
            "action": "accept",
            "src": [
                "my-subnet",
                "192.168.1.0/24"
            ],
            "dst": [
                "my-subnet:*",
                "192.168.1.0/24:*"
            ],
        },
        // Allow every user of your network to access anything on the network.
        // Comment out this section if you want to define specific ACL
        // restrictions above.
        {
            "action": "accept",
            "src": [
                "*"
            ],
            "dst": [
                "*:*"
            ],
        },
        // All users in Montreal are allowed to access the Montreal web
        // servers.
        {
            "action": "accept",
            "src": [
                "group:montreal-users"
            ],
            "dst": [
                "tag:montreal-webserver:80,443"
            ],
        },
        // Montreal web servers are allowed to make outgoing connections to
        // the API servers, but only on https port 443.
        // In contrast, this doesn't grant API servers the right to initiate
        // any connections.
        {
            "action": "accept",
            "src": [
                "tag:montreal-webserver"
            ],
            "dst": [
                "tag:api-server:443"
            ],
        },
    ],
    // Declare tests to check functionality of ACL rules
    "tests": [
        {
            "src": "user1@example.com",
            "accept": [
                "example-host-1:22",
                "example-host-2:80"
            ],
            "deny": [
                "exapmle-host-2:100"
            ],
        },
        {
            "src": "user2@example.com",
            "accept": [
                "100.60.3.4:22"
            ],
        },
    ],
}
	`)
	err := app.LoadACLPolicyFromBytes(acl, "hujson")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestBasicRule(c *check.C) {
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
                "subnet-1",
                "192.168.1.0/24"
            ],
            "dst": [
                "*:22,3389",
                "host-1:*",
            ],
        },
    ],
}
	`)
	err := app.LoadACLPolicyFromBytes(acl, "hujson")
	c.Assert(err, check.IsNil)

	rules, err := app.aclPolicy.generateFilterRules([]Machine{}, false)
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)
}

// TODO(kradalby): Make tests values safe, independent and descriptive.
func (s *Suite) TestInvalidAction(c *check.C) {
	app.aclPolicy = &ACLPolicy{
		ACLs: []ACL{
			{
				Action:       "invalidAction",
				Sources:      []string{"*"},
				Destinations: []string{"*:*"},
			},
		},
	}
	err := app.UpdateACLRules()
	c.Assert(errors.Is(err, errInvalidAction), check.Equals, true)
}

func (s *Suite) TestSshRules(c *check.C) {
	envknob.Setenv("HEADSCALE_EXPERIMENTAL_FEATURE_SSH", "1")

	user, err := app.CreateUser("user1")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("user1", "testmachine")
	c.Assert(err, check.NotNil)
	hostInfo := tailcfg.Hostinfo{
		OS:          "centos",
		Hostname:    "testmachine",
		RequestTags: []string{"tag:test"},
	}

	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		IPAddresses:    MachineAddresses{netip.MustParseAddr("100.64.0.1")},
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       HostInfo(hostInfo),
	}
	app.db.Save(&machine)

	app.aclPolicy = &ACLPolicy{
		Groups: Groups{
			"group:test": []string{"user1"},
		},
		Hosts: Hosts{
			"client": netip.PrefixFrom(netip.MustParseAddr("100.64.99.42"), 32),
		},
		ACLs: []ACL{
			{
				Action:       "accept",
				Sources:      []string{"*"},
				Destinations: []string{"*:*"},
			},
		},
		SSHs: []SSH{
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

	err = app.UpdateACLRules()

	c.Assert(err, check.IsNil)
	c.Assert(app.sshPolicy, check.NotNil)
	c.Assert(app.sshPolicy.Rules, check.HasLen, 2)
	c.Assert(app.sshPolicy.Rules[0].SSHUsers, check.HasLen, 1)
	c.Assert(app.sshPolicy.Rules[0].Principals, check.HasLen, 1)
	c.Assert(app.sshPolicy.Rules[0].Principals[0].UserLogin, check.Matches, "user1")

	c.Assert(app.sshPolicy.Rules[1].SSHUsers, check.HasLen, 1)
	c.Assert(app.sshPolicy.Rules[1].Principals, check.HasLen, 1)
	c.Assert(app.sshPolicy.Rules[1].Principals[0].NodeIP, check.Matches, "*")
}

func (s *Suite) TestInvalidGroupInGroup(c *check.C) {
	// this ACL is wrong because the group in Sources sections doesn't exist
	app.aclPolicy = &ACLPolicy{
		Groups: Groups{
			"group:test":  []string{"foo"},
			"group:error": []string{"foo", "group:test"},
		},
		ACLs: []ACL{
			{
				Action:       "accept",
				Sources:      []string{"group:error"},
				Destinations: []string{"*:*"},
			},
		},
	}
	err := app.UpdateACLRules()
	c.Assert(errors.Is(err, errInvalidGroup), check.Equals, true)
}

func (s *Suite) TestInvalidTagOwners(c *check.C) {
	// this ACL is wrong because no tagOwners own the requested tag for the server
	app.aclPolicy = &ACLPolicy{
		ACLs: []ACL{
			{
				Action:       "accept",
				Sources:      []string{"tag:foo"},
				Destinations: []string{"*:*"},
			},
		},
	}
	err := app.UpdateACLRules()
	c.Assert(errors.Is(err, errInvalidTag), check.Equals, true)
}

// this test should validate that we can expand a group in a TagOWner section and
// match properly the IP's of the related hosts. The owner is valid and the tag is also valid.
// the tag is matched in the Sources section.
func (s *Suite) TestValidExpandTagOwnersInSources(c *check.C) {
	user, err := app.CreateUser("user1")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("user1", "testmachine")
	c.Assert(err, check.NotNil)
	hostInfo := tailcfg.Hostinfo{
		OS:          "centos",
		Hostname:    "testmachine",
		RequestTags: []string{"tag:test"},
	}

	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		IPAddresses:    MachineAddresses{netip.MustParseAddr("100.64.0.1")},
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       HostInfo(hostInfo),
	}
	app.db.Save(&machine)

	app.aclPolicy = &ACLPolicy{
		Groups:    Groups{"group:test": []string{"user1", "user2"}},
		TagOwners: TagOwners{"tag:test": []string{"user3", "group:test"}},
		ACLs: []ACL{
			{
				Action:       "accept",
				Sources:      []string{"tag:test"},
				Destinations: []string{"*:*"},
			},
		},
	}
	err = app.UpdateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(app.aclRules, check.HasLen, 1)
	c.Assert(app.aclRules[0].SrcIPs, check.HasLen, 1)
	c.Assert(app.aclRules[0].SrcIPs[0], check.Equals, "100.64.0.1/32")
}

// this test should validate that we can expand a group in a TagOWner section and
// match properly the IP's of the related hosts. The owner is valid and the tag is also valid.
// the tag is matched in the Destinations section.
func (s *Suite) TestValidExpandTagOwnersInDestinations(c *check.C) {
	user, err := app.CreateUser("user1")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("user1", "testmachine")
	c.Assert(err, check.NotNil)
	hostInfo := tailcfg.Hostinfo{
		OS:          "centos",
		Hostname:    "testmachine",
		RequestTags: []string{"tag:test"},
	}

	machine := Machine{
		ID:             1,
		MachineKey:     "12345",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		IPAddresses:    MachineAddresses{netip.MustParseAddr("100.64.0.1")},
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       HostInfo(hostInfo),
	}
	app.db.Save(&machine)

	app.aclPolicy = &ACLPolicy{
		Groups:    Groups{"group:test": []string{"user1", "user2"}},
		TagOwners: TagOwners{"tag:test": []string{"user3", "group:test"}},
		ACLs: []ACL{
			{
				Action:       "accept",
				Sources:      []string{"*"},
				Destinations: []string{"tag:test:*"},
			},
		},
	}
	err = app.UpdateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(app.aclRules, check.HasLen, 1)
	c.Assert(app.aclRules[0].DstPorts, check.HasLen, 1)
	c.Assert(app.aclRules[0].DstPorts[0].IP, check.Equals, "100.64.0.1/32")
}

// need a test with:
// tag on a host that isn't owned by a tag owners. So the user
// of the host should be valid.
func (s *Suite) TestInvalidTagValidUser(c *check.C) {
	user, err := app.CreateUser("user1")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("user1", "testmachine")
	c.Assert(err, check.NotNil)
	hostInfo := tailcfg.Hostinfo{
		OS:          "centos",
		Hostname:    "testmachine",
		RequestTags: []string{"tag:foo"},
	}

	machine := Machine{
		ID:             1,
		MachineKey:     "12345",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		IPAddresses:    MachineAddresses{netip.MustParseAddr("100.64.0.1")},
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       HostInfo(hostInfo),
	}
	app.db.Save(&machine)

	app.aclPolicy = &ACLPolicy{
		TagOwners: TagOwners{"tag:test": []string{"user1"}},
		ACLs: []ACL{
			{
				Action:       "accept",
				Sources:      []string{"user1"},
				Destinations: []string{"*:*"},
			},
		},
	}
	err = app.UpdateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(app.aclRules, check.HasLen, 1)
	c.Assert(app.aclRules[0].SrcIPs, check.HasLen, 1)
	c.Assert(app.aclRules[0].SrcIPs[0], check.Equals, "100.64.0.1/32")
}

// tag on a host is owned by a tag owner, the tag is valid.
// an ACL rule is matching the tag to a user. It should not be valid since the
// host should be tied to the tag now.
func (s *Suite) TestValidTagInvalidUser(c *check.C) {
	user, err := app.CreateUser("user1")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("user1", "webserver")
	c.Assert(err, check.NotNil)
	hostInfo := tailcfg.Hostinfo{
		OS:          "centos",
		Hostname:    "webserver",
		RequestTags: []string{"tag:webapp"},
	}

	machine := Machine{
		ID:             1,
		MachineKey:     "12345",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "webserver",
		IPAddresses:    MachineAddresses{netip.MustParseAddr("100.64.0.1")},
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       HostInfo(hostInfo),
	}
	app.db.Save(&machine)
	_, err = app.GetMachine("user1", "user")
	hostInfo2 := tailcfg.Hostinfo{
		OS:       "debian",
		Hostname: "Hostname",
	}
	c.Assert(err, check.NotNil)
	machine = Machine{
		ID:             2,
		MachineKey:     "56789",
		NodeKey:        "bar2",
		DiscoKey:       "faab",
		Hostname:       "user",
		IPAddresses:    MachineAddresses{netip.MustParseAddr("100.64.0.2")},
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       HostInfo(hostInfo2),
	}
	app.db.Save(&machine)

	app.aclPolicy = &ACLPolicy{
		TagOwners: TagOwners{"tag:webapp": []string{"user1"}},
		ACLs: []ACL{
			{
				Action:       "accept",
				Sources:      []string{"user1"},
				Destinations: []string{"tag:webapp:80,443"},
			},
		},
	}
	err = app.UpdateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(app.aclRules, check.HasLen, 1)
	c.Assert(app.aclRules[0].SrcIPs, check.HasLen, 1)
	c.Assert(app.aclRules[0].SrcIPs[0], check.Equals, "100.64.0.2/32")
	c.Assert(app.aclRules[0].DstPorts, check.HasLen, 2)
	c.Assert(app.aclRules[0].DstPorts[0].Ports.First, check.Equals, uint16(80))
	c.Assert(app.aclRules[0].DstPorts[0].Ports.Last, check.Equals, uint16(80))
	c.Assert(app.aclRules[0].DstPorts[0].IP, check.Equals, "100.64.0.1/32")
	c.Assert(app.aclRules[0].DstPorts[1].Ports.First, check.Equals, uint16(443))
	c.Assert(app.aclRules[0].DstPorts[1].Ports.Last, check.Equals, uint16(443))
	c.Assert(app.aclRules[0].DstPorts[1].IP, check.Equals, "100.64.0.1/32")
}

func (s *Suite) TestPortRange(c *check.C) {
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
                "subnet-1",
            ],
            "dst": [
                "host-1:5400-5500",
            ],
        },
    ],
}
	`)
	err := app.LoadACLPolicyFromBytes(acl, "hujson")
	c.Assert(err, check.IsNil)

	rules, err := app.aclPolicy.generateFilterRules([]Machine{}, false)
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

	c.Assert(rules, check.HasLen, 1)
	c.Assert(rules[0].DstPorts, check.HasLen, 1)
	c.Assert(rules[0].DstPorts[0].Ports.First, check.Equals, uint16(5400))
	c.Assert(rules[0].DstPorts[0].Ports.Last, check.Equals, uint16(5500))
}

func (s *Suite) TestProtocolParsing(c *check.C) {
	acl := []byte(`
{
    "hosts": {
        "host-1": "100.100.100.100",
        "subnet-1": "100.100.101.100/24",
    },

    "acls": [
        {
            "Action": "accept",
            "src": [
                "*",
            ],
            "proto": "tcp",
            "dst": [
                "host-1:*",
            ],
        },
        {
            "Action": "accept",
            "src": [
                "*",
            ],
            "proto": "udp",
            "dst": [
                "host-1:53",
            ],
        },
        {
            "Action": "accept",
            "src": [
                "*",
            ],
            "proto": "icmp",
            "dst": [
                "host-1:*",
            ],
        },
    ],
}
	`)
	err := app.LoadACLPolicyFromBytes(acl, "hujson")
	c.Assert(err, check.IsNil)

	rules, err := app.aclPolicy.generateFilterRules([]Machine{}, false)
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

	c.Assert(rules, check.HasLen, 3)
	c.Assert(rules[0].IPProto[0], check.Equals, protocolTCP)
	c.Assert(rules[1].IPProto[0], check.Equals, protocolUDP)
	c.Assert(rules[2].IPProto[1], check.Equals, protocolIPv6ICMP)
}

func (s *Suite) TestPortWildcard(c *check.C) {
	acl := []byte(`
{
    "hosts": {
        "host-1": "100.100.100.100",
        "subnet-1": "100.100.101.100/24",
    },

    "acls": [
        {
            "Action": "accept",
            "src": [
                "*",
            ],
            "dst": [
                "host-1:*",
            ],
        },
    ],
}
	`)
	err := app.LoadACLPolicyFromBytes(acl, "hujson")
	c.Assert(err, check.IsNil)

	rules, err := app.aclPolicy.generateFilterRules([]Machine{}, false)
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

	c.Assert(rules, check.HasLen, 1)
	c.Assert(rules[0].DstPorts, check.HasLen, 1)
	c.Assert(rules[0].DstPorts[0].Ports.First, check.Equals, uint16(0))
	c.Assert(rules[0].DstPorts[0].Ports.Last, check.Equals, uint16(65535))
	c.Assert(rules[0].SrcIPs, check.HasLen, 2)
	c.Assert(rules[0].SrcIPs[0], check.Equals, "0.0.0.0/0")
}

func (s *Suite) TestPortWildcardYAML(c *check.C) {
	acl := []byte(`
---
hosts:
  host-1: 100.100.100.100/32
  subnet-1: 100.100.101.100/24
acls:
  - action: accept
    src:
      - "*"
    dst:
      - host-1:*
`)
	err := app.LoadACLPolicyFromBytes(acl, "yaml")
	c.Assert(err, check.IsNil)

	rules, err := app.aclPolicy.generateFilterRules([]Machine{}, false)
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

	c.Assert(rules, check.HasLen, 1)
	c.Assert(rules[0].DstPorts, check.HasLen, 1)
	c.Assert(rules[0].DstPorts[0].Ports.First, check.Equals, uint16(0))
	c.Assert(rules[0].DstPorts[0].Ports.Last, check.Equals, uint16(65535))
	c.Assert(rules[0].SrcIPs, check.HasLen, 2)
	c.Assert(rules[0].SrcIPs[0], check.Equals, "0.0.0.0/0")
}

func (s *Suite) TestPortUser(c *check.C) {
	user, err := app.CreateUser("testuser")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("testuser", "testmachine")
	c.Assert(err, check.NotNil)
	ips, _ := app.getAvailableIPs()
	machine := Machine{
		ID:             0,
		MachineKey:     "12345",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		IPAddresses:    ips,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

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
	err = app.LoadACLPolicyFromBytes(acl, "hujson")
	c.Assert(err, check.IsNil)

	machines, err := app.ListMachines()
	c.Assert(err, check.IsNil)

	rules, err := app.aclPolicy.generateFilterRules(machines, false)
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
	user, err := app.CreateUser("testuser")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("testuser", "testmachine")
	c.Assert(err, check.NotNil)
	ips, _ := app.getAvailableIPs()
	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		IPAddresses:    ips,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

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
	err = app.LoadACLPolicyFromBytes(acl, "hujson")
	c.Assert(err, check.IsNil)

	machines, err := app.ListMachines()
	c.Assert(err, check.IsNil)

	rules, err := app.aclPolicy.generateFilterRules(machines, false)
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

func Test_expandGroup(t *testing.T) {
	type field struct {
		pol ACLPolicy
	}
	type args struct {
		group            string
		stripEmailDomain bool
	}
	tests := []struct {
		name    string
		field   field
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "simple test",
			field: field{
				pol: ACLPolicy{
					Groups: Groups{
						"group:test": []string{"user1", "user2", "user3"},
						"group:foo":  []string{"user2", "user3"},
					},
				},
			},
			args: args{
				group:            "group:test",
				stripEmailDomain: true,
			},
			want:    []string{"user1", "user2", "user3"},
			wantErr: false,
		},
		{
			name: "InexistantGroup",
			field: field{
				pol: ACLPolicy{
					Groups: Groups{
						"group:test": []string{"user1", "user2", "user3"},
						"group:foo":  []string{"user2", "user3"},
					},
				},
			},
			args: args{
				group:            "group:undefined",
				stripEmailDomain: true,
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "Expand emails in group",
			field: field{
				pol: ACLPolicy{
					Groups: Groups{
						"group:admin": []string{
							"joe.bar@gmail.com",
							"john.doe@yahoo.fr",
						},
					},
				},
			},
			args: args{
				group:            "group:admin",
				stripEmailDomain: true,
			},
			want:    []string{"joe.bar", "john.doe"},
			wantErr: false,
		},
		{
			name: "Expand emails in group",
			field: field{
				pol: ACLPolicy{
					Groups: Groups{
						"group:admin": []string{
							"joe.bar@gmail.com",
							"john.doe@yahoo.fr",
						},
					},
				},
			},
			args: args{
				group:            "group:admin",
				stripEmailDomain: false,
			},
			want:    []string{"joe.bar.gmail.com", "john.doe.yahoo.fr"},
			wantErr: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.field.pol.getUsersInGroup(
				test.args.group,
				test.args.stripEmailDomain,
			)
			if (err != nil) != test.wantErr {
				t.Errorf("expandGroup() error = %v, wantErr %v", err, test.wantErr)

				return
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("expandGroup() = %v, want %v", got, test.want)
			}
		})
	}
}

func Test_expandTagOwners(t *testing.T) {
	type args struct {
		aclPolicy        *ACLPolicy
		tag              string
		stripEmailDomain bool
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "simple tag expansion",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{"tag:test": []string{"user1"}},
				},
				tag:              "tag:test",
				stripEmailDomain: true,
			},
			want:    []string{"user1"},
			wantErr: false,
		},
		{
			name: "expand with tag and group",
			args: args{
				aclPolicy: &ACLPolicy{
					Groups:    Groups{"group:foo": []string{"user1", "user2"}},
					TagOwners: TagOwners{"tag:test": []string{"group:foo"}},
				},
				tag:              "tag:test",
				stripEmailDomain: true,
			},
			want:    []string{"user1", "user2"},
			wantErr: false,
		},
		{
			name: "expand with user and group",
			args: args{
				aclPolicy: &ACLPolicy{
					Groups:    Groups{"group:foo": []string{"user1", "user2"}},
					TagOwners: TagOwners{"tag:test": []string{"group:foo", "user3"}},
				},
				tag:              "tag:test",
				stripEmailDomain: true,
			},
			want:    []string{"user1", "user2", "user3"},
			wantErr: false,
		},
		{
			name: "invalid tag",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{"tag:foo": []string{"group:foo", "user1"}},
				},
				tag:              "tag:test",
				stripEmailDomain: true,
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "invalid group",
			args: args{
				aclPolicy: &ACLPolicy{
					Groups:    Groups{"group:bar": []string{"user1", "user2"}},
					TagOwners: TagOwners{"tag:test": []string{"group:foo", "user2"}},
				},
				tag:              "tag:test",
				stripEmailDomain: true,
			},
			want:    []string{},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := getTagOwners(
				test.args.aclPolicy,
				test.args.tag,
				test.args.stripEmailDomain,
			)
			if (err != nil) != test.wantErr {
				t.Errorf("expandTagOwners() error = %v, wantErr %v", err, test.wantErr)

				return
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("expandTagOwners() = %v, want %v", got, test.want)
			}
		})
	}
}

func Test_expandPorts(t *testing.T) {
	type args struct {
		portsStr      string
		needsWildcard bool
	}
	tests := []struct {
		name    string
		args    args
		want    *[]tailcfg.PortRange
		wantErr bool
	}{
		{
			name: "wildcard",
			args: args{portsStr: "*", needsWildcard: true},
			want: &[]tailcfg.PortRange{
				{First: portRangeBegin, Last: portRangeEnd},
			},
			wantErr: false,
		},
		{
			name: "needs wildcard but does not require it",
			args: args{portsStr: "*", needsWildcard: false},
			want: &[]tailcfg.PortRange{
				{First: portRangeBegin, Last: portRangeEnd},
			},
			wantErr: false,
		},
		{
			name:    "needs wildcard but gets port",
			args:    args{portsStr: "80,443", needsWildcard: true},
			want:    nil,
			wantErr: true,
		},
		{
			name: "two Destinations",
			args: args{portsStr: "80,443", needsWildcard: false},
			want: &[]tailcfg.PortRange{
				{First: 80, Last: 80},
				{First: 443, Last: 443},
			},
			wantErr: false,
		},
		{
			name: "a range and a port",
			args: args{portsStr: "80-1024,443", needsWildcard: false},
			want: &[]tailcfg.PortRange{
				{First: 80, Last: 1024},
				{First: 443, Last: 443},
			},
			wantErr: false,
		},
		{
			name:    "out of bounds",
			args:    args{portsStr: "854038", needsWildcard: false},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong port",
			args:    args{portsStr: "85a38", needsWildcard: false},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong port in first",
			args:    args{portsStr: "a-80", needsWildcard: false},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong port in last",
			args:    args{portsStr: "80-85a38", needsWildcard: false},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong port format",
			args:    args{portsStr: "80-85a38-3", needsWildcard: false},
			want:    nil,
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := expandPorts(test.args.portsStr, test.args.needsWildcard)
			if (err != nil) != test.wantErr {
				t.Errorf("expandPorts() error = %v, wantErr %v", err, test.wantErr)

				return
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("expandPorts() = %v, want %v", got, test.want)
			}
		})
	}
}

func Test_listMachinesInUser(t *testing.T) {
	type args struct {
		machines []Machine
		user     string
	}
	tests := []struct {
		name string
		args args
		want []Machine
	}{
		{
			name: "1 machine in user",
			args: args{
				machines: []Machine{
					{User: User{Name: "joe"}},
				},
				user: "joe",
			},
			want: []Machine{
				{User: User{Name: "joe"}},
			},
		},
		{
			name: "3 machines, 2 in user",
			args: args{
				machines: []Machine{
					{ID: 1, User: User{Name: "joe"}},
					{ID: 2, User: User{Name: "marc"}},
					{ID: 3, User: User{Name: "marc"}},
				},
				user: "marc",
			},
			want: []Machine{
				{ID: 2, User: User{Name: "marc"}},
				{ID: 3, User: User{Name: "marc"}},
			},
		},
		{
			name: "5 machines, 0 in user",
			args: args{
				machines: []Machine{
					{ID: 1, User: User{Name: "joe"}},
					{ID: 2, User: User{Name: "marc"}},
					{ID: 3, User: User{Name: "marc"}},
					{ID: 4, User: User{Name: "marc"}},
					{ID: 5, User: User{Name: "marc"}},
				},
				user: "mickael",
			},
			want: []Machine{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := filterMachinesByUser(test.args.machines, test.args.user); !reflect.DeepEqual(
				got,
				test.want,
			) {
				t.Errorf("listMachinesInUser() = %v, want %v", got, test.want)
			}
		})
	}
}

func Test_expandAlias(t *testing.T) {
	set := func(ips []string, prefixes []string) *netipx.IPSet {
		var builder netipx.IPSetBuilder

		for _, ip := range ips {
			builder.Add(netip.MustParseAddr(ip))
		}

		for _, pre := range prefixes {
			builder.AddPrefix(netip.MustParsePrefix(pre))
		}

		s, _ := builder.IPSet()

		return s
	}

	type field struct {
		pol ACLPolicy
	}
	type args struct {
		machines         []Machine
		aclPolicy        ACLPolicy
		alias            string
		stripEmailDomain bool
	}
	tests := []struct {
		name    string
		field   field
		args    args
		want    *netipx.IPSet
		wantErr bool
	}{
		{
			name: "wildcard",
			field: field{
				pol: ACLPolicy{},
			},
			args: args{
				alias: "*",
				machines: []Machine{
					{IPAddresses: MachineAddresses{netip.MustParseAddr("100.64.0.1")}},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.78.84.227"),
						},
					},
				},
				stripEmailDomain: true,
			},
			want: set([]string{}, []string{
				"0.0.0.0/0",
				"::/0",
			}),
			wantErr: false,
		},
		{
			name: "simple group",
			field: field{
				pol: ACLPolicy{
					Groups: Groups{"group:accountant": []string{"joe", "marc"}},
				},
			},
			args: args{
				alias: "group:accountant",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "joe"},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "marc"},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
						User: User{Name: "mickael"},
					},
				},
				stripEmailDomain: true,
			},
			want: set([]string{
				"100.64.0.1", "100.64.0.2", "100.64.0.3",
			}, []string{}),
			wantErr: false,
		},
		{
			name: "wrong group",
			field: field{
				pol: ACLPolicy{
					Groups: Groups{"group:accountant": []string{"joe", "marc"}},
				},
			},
			args: args{
				alias: "group:hr",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "joe"},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "marc"},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
						User: User{Name: "mickael"},
					},
				},
				stripEmailDomain: true,
			},
			want:    set([]string{}, []string{}),
			wantErr: true,
		},
		{
			name: "simple ipaddress",
			field: field{
				pol: ACLPolicy{},
			},
			args: args{
				alias:            "10.0.0.3",
				machines:         []Machine{},
				stripEmailDomain: true,
			},
			want: set([]string{
				"10.0.0.3",
			}, []string{}),
			wantErr: false,
		},
		{
			name: "simple host by ip passed through",
			field: field{
				pol: ACLPolicy{},
			},
			args: args{
				alias:            "10.0.0.1",
				machines:         []Machine{},
				stripEmailDomain: true,
			},
			want: set([]string{
				"10.0.0.1",
			}, []string{}),
			wantErr: false,
		},
		{
			name: "simple host by ipv4 single ipv4",
			field: field{
				pol: ACLPolicy{},
			},
			args: args{
				alias: "10.0.0.1",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("10.0.0.1"),
						},
						User: User{Name: "mickael"},
					},
				},
				stripEmailDomain: true,
			},
			want: set([]string{
				"10.0.0.1",
			}, []string{}),
			wantErr: false,
		},
		{
			name: "simple host by ipv4 single dual stack",
			field: field{
				pol: ACLPolicy{},
			},
			args: args{
				alias: "10.0.0.1",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("10.0.0.1"),
							netip.MustParseAddr("fd7a:115c:a1e0:ab12:4843:2222:6273:2222"),
						},
						User: User{Name: "mickael"},
					},
				},
				stripEmailDomain: true,
			},
			want: set([]string{
				"10.0.0.1", "fd7a:115c:a1e0:ab12:4843:2222:6273:2222",
			}, []string{}),
			wantErr: false,
		},
		{
			name: "simple host by ipv6 single dual stack",
			field: field{
				pol: ACLPolicy{},
			},
			args: args{
				alias: "fd7a:115c:a1e0:ab12:4843:2222:6273:2222",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("10.0.0.1"),
							netip.MustParseAddr("fd7a:115c:a1e0:ab12:4843:2222:6273:2222"),
						},
						User: User{Name: "mickael"},
					},
				},
				stripEmailDomain: true,
			},
			want: set([]string{
				"fd7a:115c:a1e0:ab12:4843:2222:6273:2222", "10.0.0.1",
			}, []string{}),
			wantErr: false,
		},
		{
			name: "simple host by hostname alias",
			field: field{
				pol: ACLPolicy{
					Hosts: Hosts{
						"testy": netip.MustParsePrefix("10.0.0.132/32"),
					},
				},
			},
			args: args{
				alias:            "testy",
				machines:         []Machine{},
				stripEmailDomain: true,
			},
			want:    set([]string{}, []string{"10.0.0.132/32"}),
			wantErr: false,
		},
		{
			name: "private network",
			field: field{
				pol: ACLPolicy{
					Hosts: Hosts{
						"homeNetwork": netip.MustParsePrefix("192.168.1.0/24"),
					},
				},
			},
			args: args{
				alias:            "homeNetwork",
				machines:         []Machine{},
				stripEmailDomain: true,
			},
			want:    set([]string{}, []string{"192.168.1.0/24"}),
			wantErr: false,
		},
		{
			name: "simple CIDR",
			field: field{
				pol: ACLPolicy{},
			},
			args: args{
				alias:            "10.0.0.0/16",
				machines:         []Machine{},
				aclPolicy:        ACLPolicy{},
				stripEmailDomain: true,
			},
			want:    set([]string{}, []string{"10.0.0.0/16"}),
			wantErr: false,
		},
		{
			name: "simple tag",
			field: field{
				pol: ACLPolicy{
					TagOwners: TagOwners{"tag:hr-webserver": []string{"joe"}},
				},
			},
			args: args{
				alias: "tag:hr-webserver",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "marc"},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
						User: User{Name: "joe"},
					},
				},
				stripEmailDomain: true,
			},
			want: set([]string{
				"100.64.0.1", "100.64.0.2",
			}, []string{}),
			wantErr: false,
		},
		{
			name: "No tag defined",
			field: field{
				pol: ACLPolicy{
					Groups: Groups{"group:accountant": []string{"joe", "marc"}},
					TagOwners: TagOwners{
						"tag:accountant-webserver": []string{"group:accountant"},
					},
				},
			},
			args: args{
				alias: "tag:hr-webserver",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "joe"},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "marc"},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
						User: User{Name: "mickael"},
					},
				},
				stripEmailDomain: true,
			},
			want:    set([]string{}, []string{}),
			wantErr: true,
		},
		{
			name: "Forced tag defined",
			field: field{
				pol: ACLPolicy{},
			},
			args: args{
				alias: "tag:hr-webserver",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User:       User{Name: "joe"},
						ForcedTags: []string{"tag:hr-webserver"},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User:       User{Name: "joe"},
						ForcedTags: []string{"tag:hr-webserver"},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "marc"},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
						User: User{Name: "mickael"},
					},
				},
				stripEmailDomain: true,
			},
			want:    set([]string{"100.64.0.1", "100.64.0.2"}, []string{}),
			wantErr: false,
		},
		{
			name: "Forced tag with legitimate tagOwner",
			field: field{
				pol: ACLPolicy{
					TagOwners: TagOwners{
						"tag:hr-webserver": []string{"joe"},
					},
				},
			},
			args: args{
				alias: "tag:hr-webserver",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User:       User{Name: "joe"},
						ForcedTags: []string{"tag:hr-webserver"},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "marc"},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
						User: User{Name: "mickael"},
					},
				},
				stripEmailDomain: true,
			},
			want:    set([]string{"100.64.0.1", "100.64.0.2"}, []string{}),
			wantErr: false,
		},
		{
			name: "list host in user without correctly tagged servers",
			field: field{
				pol: ACLPolicy{
					TagOwners: TagOwners{"tag:accountant-webserver": []string{"joe"}},
				},
			},
			args: args{
				alias: "joe",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "marc"},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
						User: User{Name: "joe"},
					},
				},
				stripEmailDomain: true,
			},
			want:    set([]string{"100.64.0.4"}, []string{}),
			wantErr: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.field.pol.expandAlias(
				test.args.machines,
				test.args.alias,
				test.args.stripEmailDomain,
			)
			if (err != nil) != test.wantErr {
				t.Errorf("expandAlias() error = %v, wantErr %v", err, test.wantErr)

				return
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("expandAlias() = %v, want %v", got, test.want)
			}
		})
	}
}

func Test_excludeCorrectlyTaggedNodes(t *testing.T) {
	type args struct {
		aclPolicy        *ACLPolicy
		nodes            []Machine
		user             string
		stripEmailDomain bool
	}
	tests := []struct {
		name    string
		args    args
		want    []Machine
		wantErr bool
	}{
		{
			name: "exclude nodes with valid tags",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{"tag:accountant-webserver": []string{"joe"}},
				},
				nodes: []Machine{
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
						User: User{Name: "joe"},
					},
				},
				user:             "joe",
				stripEmailDomain: true,
			},
			want: []Machine{
				{
					IPAddresses: MachineAddresses{netip.MustParseAddr("100.64.0.4")},
					User:        User{Name: "joe"},
				},
			},
		},
		{
			name: "exclude nodes with valid tags, and owner is in a group",
			args: args{
				aclPolicy: &ACLPolicy{
					Groups: Groups{
						"group:accountant": []string{"joe", "bar"},
					},
					TagOwners: TagOwners{
						"tag:accountant-webserver": []string{"group:accountant"},
					},
				},
				nodes: []Machine{
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
						User: User{Name: "joe"},
					},
				},
				user:             "joe",
				stripEmailDomain: true,
			},
			want: []Machine{
				{
					IPAddresses: MachineAddresses{netip.MustParseAddr("100.64.0.4")},
					User:        User{Name: "joe"},
				},
			},
		},
		{
			name: "exclude nodes with valid tags and with forced tags",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{"tag:accountant-webserver": []string{"joe"}},
				},
				nodes: []Machine{
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User:       User{Name: "joe"},
						ForcedTags: []string{"tag:accountant-webserver"},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
						User: User{Name: "joe"},
					},
				},
				user:             "joe",
				stripEmailDomain: true,
			},
			want: []Machine{
				{
					IPAddresses: MachineAddresses{netip.MustParseAddr("100.64.0.4")},
					User:        User{Name: "joe"},
				},
			},
		},
		{
			name: "all nodes have invalid tags, don't exclude them",
			args: args{
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{"tag:accountant-webserver": []string{"joe"}},
				},
				nodes: []Machine{
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "hr-web1",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "hr-web2",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.4"),
						},
						User: User{Name: "joe"},
					},
				},
				user:             "joe",
				stripEmailDomain: true,
			},
			want: []Machine{
				{
					IPAddresses: MachineAddresses{
						netip.MustParseAddr("100.64.0.1"),
					},
					User: User{Name: "joe"},
					HostInfo: HostInfo{
						OS:          "centos",
						Hostname:    "hr-web1",
						RequestTags: []string{"tag:hr-webserver"},
					},
				},
				{
					IPAddresses: MachineAddresses{
						netip.MustParseAddr("100.64.0.2"),
					},
					User: User{Name: "joe"},
					HostInfo: HostInfo{
						OS:          "centos",
						Hostname:    "hr-web2",
						RequestTags: []string{"tag:hr-webserver"},
					},
				},
				{
					IPAddresses: MachineAddresses{
						netip.MustParseAddr("100.64.0.4"),
					},
					User: User{Name: "joe"},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := excludeCorrectlyTaggedNodes(
				test.args.aclPolicy,
				test.args.nodes,
				test.args.user,
				test.args.stripEmailDomain,
			)
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("excludeCorrectlyTaggedNodes() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestACLPolicy_generateFilterRules(t *testing.T) {
	type field struct {
		pol ACLPolicy
	}
	type args struct {
		machines         []Machine
		stripEmailDomain bool
	}
	tests := []struct {
		name    string
		field   field
		args    args
		want    []tailcfg.FilterRule
		wantErr bool
	}{
		{
			name:    "no-policy",
			field:   field{},
			args:    args{},
			want:    []tailcfg.FilterRule{},
			wantErr: false,
		},
		{
			name: "allow-all",
			field: field{
				pol: ACLPolicy{
					ACLs: []ACL{
						{
							Action:       "accept",
							Sources:      []string{"*"},
							Destinations: []string{"*:*"},
						},
					},
				},
			},
			args: args{
				machines:         []Machine{},
				stripEmailDomain: true,
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"0.0.0.0/0", "::/0"},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP: "0.0.0.0/0",
							Ports: tailcfg.PortRange{
								First: 0,
								Last:  65535,
							},
						},
						{
							IP: "::/0",
							Ports: tailcfg.PortRange{
								First: 0,
								Last:  65535,
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "host1-can-reach-host2",
			field: field{
				pol: ACLPolicy{
					ACLs: []ACL{
						{
							Action:       "accept",
							Sources:      []string{"100.64.0.1"},
							Destinations: []string{"100.64.0.2:*"},
						},
					},
				},
			},
			args: args{
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.1"),
							netip.MustParseAddr("fd7a:115c:a1e0:ab12:4843:2222:6273:2221"),
						},
						User: User{Name: "mickael"},
					},
					{
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
							netip.MustParseAddr("fd7a:115c:a1e0:ab12:4843:2222:6273:2222"),
						},
						User: User{Name: "mickael"},
					},
				},
				stripEmailDomain: true,
			},
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.1/32", "fd7a:115c:a1e0:ab12:4843:2222:6273:2221/128"},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP: "100.64.0.2/32",
							Ports: tailcfg.PortRange{
								First: 0,
								Last:  65535,
							},
						},
						{
							IP: "fd7a:115c:a1e0:ab12:4843:2222:6273:2222/128",
							Ports: tailcfg.PortRange{
								First: 0,
								Last:  65535,
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.field.pol.generateFilterRules(
				tt.args.machines,
				tt.args.stripEmailDomain,
			)
			if (err != nil) != tt.wantErr {
				t.Errorf("ACLPolicy.generateFilterRules() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				log.Trace().Interface("got", got).Msg("result")
				t.Errorf("ACLPolicy.generateFilterRules() = %v, want %v", got, tt.want)
			}
		})
	}
}
