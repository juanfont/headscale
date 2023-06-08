package db

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"tailscale.com/tailcfg"
)

// TODO(kradalby):
// Convert these tests to being non-database dependent and table driven. They are
// very verbose, and dont really need the database.

// this test should validate that we can expand a group in a TagOWner section and
// match properly the IP's of the related hosts. The owner is valid and the tag is also valid.
// the tag is matched in the Sources section.
func TestValidExpandTagOwnersInSources(t *testing.T) {
	hostInfo := tailcfg.Hostinfo{
		OS:          "centos",
		Hostname:    "testmachine",
		RequestTags: []string{"tag:test"},
	}

	machine := types.Machine{
		ID:          0,
		MachineKey:  "foo",
		NodeKey:     "bar",
		DiscoKey:    "faa",
		Hostname:    "testmachine",
		IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.1")},
		UserID:      0,
		User: types.User{
			Name: "user1",
		},
		RegisterMethod: util.RegisterMethodAuthKey,
		HostInfo:       types.HostInfo(hostInfo),
	}

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

	got, _, err := policy.GenerateFilterRules(pol, &machine, types.Machines{}, false)
	assert.NoError(t, err)

	want := []tailcfg.FilterRule{
		{
			SrcIPs: []string{"100.64.0.1/32"},
			DstPorts: []tailcfg.NetPortRange{
				{IP: "0.0.0.0/0", Ports: tailcfg.PortRange{Last: 65535}},
				{IP: "::/0", Ports: tailcfg.PortRange{Last: 65535}},
			},
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("TestValidExpandTagOwnersInSources() unexpected result (-want +got):\n%s", diff)
	}
}

// need a test with:
// tag on a host that isn't owned by a tag owners. So the user
// of the host should be valid.
func TestInvalidTagValidUser(t *testing.T) {
	hostInfo := tailcfg.Hostinfo{
		OS:          "centos",
		Hostname:    "testmachine",
		RequestTags: []string{"tag:foo"},
	}

	machine := types.Machine{
		ID:          1,
		MachineKey:  "12345",
		NodeKey:     "bar",
		DiscoKey:    "faa",
		Hostname:    "testmachine",
		IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.1")},
		UserID:      1,
		User: types.User{
			Name: "user1",
		},
		RegisterMethod: util.RegisterMethodAuthKey,
		HostInfo:       types.HostInfo(hostInfo),
	}

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

	got, _, err := policy.GenerateFilterRules(pol, &machine, types.Machines{}, false)
	assert.NoError(t, err)

	want := []tailcfg.FilterRule{
		{
			SrcIPs: []string{"100.64.0.1/32"},
			DstPorts: []tailcfg.NetPortRange{
				{IP: "0.0.0.0/0", Ports: tailcfg.PortRange{Last: 65535}},
				{IP: "::/0", Ports: tailcfg.PortRange{Last: 65535}},
			},
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("TestInvalidTagValidUser() unexpected result (-want +got):\n%s", diff)
	}
}

func TestPortGroup(t *testing.T) {
	machine := types.Machine{
		ID:         0,
		MachineKey: "foo",
		NodeKey:    "bar",
		DiscoKey:   "faa",
		Hostname:   "testmachine",
		UserID:     0,
		User: types.User{
			Name: "testuser",
		},
		RegisterMethod: util.RegisterMethodAuthKey,
		IPAddresses:    types.MachineAddresses{netip.MustParseAddr("100.64.0.5")},
	}

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
	assert.NoError(t, err)

	got, _, err := policy.GenerateFilterRules(pol, &machine, types.Machines{}, false)
	assert.NoError(t, err)

	want := []tailcfg.FilterRule{
		{
			SrcIPs: []string{"100.64.0.5/32"},
			DstPorts: []tailcfg.NetPortRange{
				{IP: "100.100.100.100/32", Ports: tailcfg.PortRange{Last: 65535}},
			},
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("TestPortGroup() unexpected result (-want +got):\n%s", diff)
	}
}

func TestPortUser(t *testing.T) {
	machine := types.Machine{
		ID:         0,
		MachineKey: "12345",
		NodeKey:    "bar",
		DiscoKey:   "faa",
		Hostname:   "testmachine",
		UserID:     0,
		User: types.User{
			Name: "testuser",
		},
		RegisterMethod: util.RegisterMethodAuthKey,
		IPAddresses:    types.MachineAddresses{netip.MustParseAddr("100.64.0.9")},
	}

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
	assert.NoError(t, err)

	got, _, err := policy.GenerateFilterRules(pol, &machine, types.Machines{}, false)
	assert.NoError(t, err)

	want := []tailcfg.FilterRule{
		{
			SrcIPs: []string{"100.64.0.9/32"},
			DstPorts: []tailcfg.NetPortRange{
				{IP: "100.100.100.100/32", Ports: tailcfg.PortRange{Last: 65535}},
			},
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("TestPortUser() unexpected result (-want +got):\n%s", diff)
	}
}

// this test should validate that we can expand a group in a TagOWner section and
// match properly the IP's of the related hosts. The owner is valid and the tag is also valid.
// the tag is matched in the Destinations section.
func TestValidExpandTagOwnersInDestinations(t *testing.T) {
	hostInfo := tailcfg.Hostinfo{
		OS:          "centos",
		Hostname:    "testmachine",
		RequestTags: []string{"tag:test"},
	}

	machine := types.Machine{
		ID:          1,
		MachineKey:  "12345",
		NodeKey:     "bar",
		DiscoKey:    "faa",
		Hostname:    "testmachine",
		IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.1")},
		UserID:      1,
		User: types.User{
			Name: "user1",
		},
		RegisterMethod: util.RegisterMethodAuthKey,
		HostInfo:       types.HostInfo(hostInfo),
	}

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

	// rules, _, err := policy.GenerateFilterRules(pol, &machine, peers, false)
	// c.Assert(err, check.IsNil)
	//
	// c.Assert(rules, check.HasLen, 1)
	// c.Assert(rules[0].DstPorts, check.HasLen, 1)
	// c.Assert(rules[0].DstPorts[0].IP, check.Equals, "100.64.0.1/32")

	got, _, err := policy.GenerateFilterRules(pol, &machine, types.Machines{}, false)
	assert.NoError(t, err)

	want := []tailcfg.FilterRule{
		{
			SrcIPs: []string{"0.0.0.0/0", "::/0"},
			DstPorts: []tailcfg.NetPortRange{
				{IP: "100.64.0.1/32", Ports: tailcfg.PortRange{Last: 65535}},
			},
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf(
			"TestValidExpandTagOwnersInDestinations() unexpected result (-want +got):\n%s",
			diff,
		)
	}
}

// tag on a host is owned by a tag owner, the tag is valid.
// an ACL rule is matching the tag to a user. It should not be valid since the
// host should be tied to the tag now.
func TestValidTagInvalidUser(t *testing.T) {
	hostInfo := tailcfg.Hostinfo{
		OS:          "centos",
		Hostname:    "webserver",
		RequestTags: []string{"tag:webapp"},
	}

	machine := types.Machine{
		ID:          1,
		MachineKey:  "12345",
		NodeKey:     "bar",
		DiscoKey:    "faa",
		Hostname:    "webserver",
		IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.1")},
		UserID:      1,
		User: types.User{
			Name: "user1",
		},
		RegisterMethod: util.RegisterMethodAuthKey,
		HostInfo:       types.HostInfo(hostInfo),
	}

	hostInfo2 := tailcfg.Hostinfo{
		OS:       "debian",
		Hostname: "Hostname",
	}

	machine2 := types.Machine{
		ID:          2,
		MachineKey:  "56789",
		NodeKey:     "bar2",
		DiscoKey:    "faab",
		Hostname:    "user",
		IPAddresses: types.MachineAddresses{netip.MustParseAddr("100.64.0.2")},
		UserID:      1,
		User: types.User{
			Name: "user1",
		},
		RegisterMethod: util.RegisterMethodAuthKey,
		HostInfo:       types.HostInfo(hostInfo2),
	}

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

	got, _, err := policy.GenerateFilterRules(pol, &machine, types.Machines{machine2}, false)
	assert.NoError(t, err)

	want := []tailcfg.FilterRule{
		{
			SrcIPs: []string{"100.64.0.2/32"},
			DstPorts: []tailcfg.NetPortRange{
				{IP: "100.64.0.1/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
				{IP: "100.64.0.1/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
			},
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("TestValidTagInvalidUser() unexpected result (-want +got):\n%s", diff)
	}
}
