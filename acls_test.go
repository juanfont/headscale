package headscale

import (
	"errors"
	"reflect"
	"testing"

	"gopkg.in/check.v1"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
)

func (s *Suite) TestWrongPath(c *check.C) {
	err := app.LoadACLPolicy("asdfg")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestBrokenHuJson(c *check.C) {
	err := app.LoadACLPolicy("./tests/acls/broken.hujson")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestInvalidPolicyHuson(c *check.C) {
	err := app.LoadACLPolicy("./tests/acls/invalid.hujson")
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
	err := app.LoadACLPolicy("./tests/acls/acl_policy_invalid.hujson")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestBasicRule(c *check.C) {
	err := app.LoadACLPolicy("./tests/acls/acl_policy_basic_1.hujson")
	c.Assert(err, check.IsNil)

	rules, err := app.generateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)
}

// TODO(kradalby): Make tests values safe, independent and descriptive.
func (s *Suite) TestInvalidAction(c *check.C) {
	app.aclPolicy = &ACLPolicy{
		ACLs: []ACL{
			{Action: "invalidAction", Sources: []string{"*"}, Destinations: []string{"*:*"}},
		},
	}
	err := app.UpdateACLRules()
	c.Assert(errors.Is(err, errInvalidAction), check.Equals, true)
}

func (s *Suite) TestInvalidGroupInGroup(c *check.C) {
	// this ACL is wrong because the group in Sources sections doesn't exist
	app.aclPolicy = &ACLPolicy{
		Groups: Groups{
			"group:test":  []string{"foo"},
			"group:error": []string{"foo", "group:test"},
		},
		ACLs: []ACL{
			{Action: "accept", Sources: []string{"group:error"}, Destinations: []string{"*:*"}},
		},
	}
	err := app.UpdateACLRules()
	c.Assert(errors.Is(err, errInvalidGroup), check.Equals, true)
}

func (s *Suite) TestInvalidTagOwners(c *check.C) {
	// this ACL is wrong because no tagOwners own the requested tag for the server
	app.aclPolicy = &ACLPolicy{
		ACLs: []ACL{
			{Action: "accept", Sources: []string{"tag:foo"}, Destinations: []string{"*:*"}},
		},
	}
	err := app.UpdateACLRules()
	c.Assert(errors.Is(err, errInvalidTag), check.Equals, true)
}

// this test should validate that we can expand a group in a TagOWner section and
// match properly the IP's of the related hosts. The owner is valid and the tag is also valid.
// the tag is matched in the Sources section.
func (s *Suite) TestValidExpandTagOwnersInSources(c *check.C) {
	namespace, err := app.CreateNamespace("user1")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
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
		IPAddresses:    MachineAddresses{netaddr.MustParseIP("100.64.0.1")},
		NamespaceID:    namespace.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       HostInfo(hostInfo),
	}
	app.db.Save(&machine)

	app.aclPolicy = &ACLPolicy{
		Groups:    Groups{"group:test": []string{"user1", "user2"}},
		TagOwners: TagOwners{"tag:test": []string{"user3", "group:test"}},
		ACLs: []ACL{
			{Action: "accept", Sources: []string{"tag:test"}, Destinations: []string{"*:*"}},
		},
	}
	err = app.UpdateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(app.aclRules, check.HasLen, 1)
	c.Assert(app.aclRules[0].SrcIPs, check.HasLen, 1)
	c.Assert(app.aclRules[0].SrcIPs[0], check.Equals, "100.64.0.1")
}

// this test should validate that we can expand a group in a TagOWner section and
// match properly the IP's of the related hosts. The owner is valid and the tag is also valid.
// the tag is matched in the Destinations section.
func (s *Suite) TestValidExpandTagOwnersInDestinations(c *check.C) {
	namespace, err := app.CreateNamespace("user1")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
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
		IPAddresses:    MachineAddresses{netaddr.MustParseIP("100.64.0.1")},
		NamespaceID:    namespace.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       HostInfo(hostInfo),
	}
	app.db.Save(&machine)

	app.aclPolicy = &ACLPolicy{
		Groups:    Groups{"group:test": []string{"user1", "user2"}},
		TagOwners: TagOwners{"tag:test": []string{"user3", "group:test"}},
		ACLs: []ACL{
			{Action: "accept", Sources: []string{"*"}, Destinations: []string{"tag:test:*"}},
		},
	}
	err = app.UpdateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(app.aclRules, check.HasLen, 1)
	c.Assert(app.aclRules[0].DstPorts, check.HasLen, 1)
	c.Assert(app.aclRules[0].DstPorts[0].IP, check.Equals, "100.64.0.1")
}

// need a test with:
// tag on a host that isn't owned by a tag owners. So the namespace
// of the host should be valid.
func (s *Suite) TestInvalidTagValidNamespace(c *check.C) {
	namespace, err := app.CreateNamespace("user1")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
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
		IPAddresses:    MachineAddresses{netaddr.MustParseIP("100.64.0.1")},
		NamespaceID:    namespace.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       HostInfo(hostInfo),
	}
	app.db.Save(&machine)

	app.aclPolicy = &ACLPolicy{
		TagOwners: TagOwners{"tag:test": []string{"user1"}},
		ACLs: []ACL{
			{Action: "accept", Sources: []string{"user1"}, Destinations: []string{"*:*"}},
		},
	}
	err = app.UpdateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(app.aclRules, check.HasLen, 1)
	c.Assert(app.aclRules[0].SrcIPs, check.HasLen, 1)
	c.Assert(app.aclRules[0].SrcIPs[0], check.Equals, "100.64.0.1")
}

// tag on a host is owned by a tag owner, the tag is valid.
// an ACL rule is matching the tag to a namespace. It should not be valid since the
// host should be tied to the tag now.
func (s *Suite) TestValidTagInvalidNamespace(c *check.C) {
	namespace, err := app.CreateNamespace("user1")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
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
		IPAddresses:    MachineAddresses{netaddr.MustParseIP("100.64.0.1")},
		NamespaceID:    namespace.ID,
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
		IPAddresses:    MachineAddresses{netaddr.MustParseIP("100.64.0.2")},
		NamespaceID:    namespace.ID,
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
	c.Assert(app.aclRules[0].SrcIPs[0], check.Equals, "100.64.0.2")
	c.Assert(app.aclRules[0].DstPorts, check.HasLen, 2)
	c.Assert(app.aclRules[0].DstPorts[0].Ports.First, check.Equals, uint16(80))
	c.Assert(app.aclRules[0].DstPorts[0].Ports.Last, check.Equals, uint16(80))
	c.Assert(app.aclRules[0].DstPorts[0].IP, check.Equals, "100.64.0.1")
	c.Assert(app.aclRules[0].DstPorts[1].Ports.First, check.Equals, uint16(443))
	c.Assert(app.aclRules[0].DstPorts[1].Ports.Last, check.Equals, uint16(443))
	c.Assert(app.aclRules[0].DstPorts[1].IP, check.Equals, "100.64.0.1")
}

func (s *Suite) TestPortRange(c *check.C) {
	err := app.LoadACLPolicy("./tests/acls/acl_policy_basic_range.hujson")
	c.Assert(err, check.IsNil)

	rules, err := app.generateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

	c.Assert(rules, check.HasLen, 1)
	c.Assert(rules[0].DstPorts, check.HasLen, 1)
	c.Assert(rules[0].DstPorts[0].Ports.First, check.Equals, uint16(5400))
	c.Assert(rules[0].DstPorts[0].Ports.Last, check.Equals, uint16(5500))
}

func (s *Suite) TestProtocolParsing(c *check.C) {
	err := app.LoadACLPolicy("./tests/acls/acl_policy_basic_protocols.hujson")
	c.Assert(err, check.IsNil)

	rules, err := app.generateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

	c.Assert(rules, check.HasLen, 3)
	c.Assert(rules[0].IPProto[0], check.Equals, protocolTCP)
	c.Assert(rules[1].IPProto[0], check.Equals, protocolUDP)
	c.Assert(rules[2].IPProto[1], check.Equals, protocolIPv6ICMP)
}

func (s *Suite) TestPortWildcard(c *check.C) {
	err := app.LoadACLPolicy("./tests/acls/acl_policy_basic_wildcards.hujson")
	c.Assert(err, check.IsNil)

	rules, err := app.generateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

	c.Assert(rules, check.HasLen, 1)
	c.Assert(rules[0].DstPorts, check.HasLen, 1)
	c.Assert(rules[0].DstPorts[0].Ports.First, check.Equals, uint16(0))
	c.Assert(rules[0].DstPorts[0].Ports.Last, check.Equals, uint16(65535))
	c.Assert(rules[0].SrcIPs, check.HasLen, 1)
	c.Assert(rules[0].SrcIPs[0], check.Equals, "*")
}

func (s *Suite) TestPortWildcardYAML(c *check.C) {
	err := app.LoadACLPolicy("./tests/acls/acl_policy_basic_wildcards.yaml")
	c.Assert(err, check.IsNil)

	rules, err := app.generateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

	c.Assert(rules, check.HasLen, 1)
	c.Assert(rules[0].DstPorts, check.HasLen, 1)
	c.Assert(rules[0].DstPorts[0].Ports.First, check.Equals, uint16(0))
	c.Assert(rules[0].DstPorts[0].Ports.Last, check.Equals, uint16(65535))
	c.Assert(rules[0].SrcIPs, check.HasLen, 1)
	c.Assert(rules[0].SrcIPs[0], check.Equals, "*")
}

func (s *Suite) TestPortNamespace(c *check.C) {
	namespace, err := app.CreateNamespace("testnamespace")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("testnamespace", "testmachine")
	c.Assert(err, check.NotNil)
	ips, _ := app.getAvailableIPs()
	machine := Machine{
		ID:             0,
		MachineKey:     "12345",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		NamespaceID:    namespace.ID,
		RegisterMethod: RegisterMethodAuthKey,
		IPAddresses:    ips,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

	err = app.LoadACLPolicy(
		"./tests/acls/acl_policy_basic_namespace_as_user.hujson",
	)
	c.Assert(err, check.IsNil)

	rules, err := app.generateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

	c.Assert(rules, check.HasLen, 1)
	c.Assert(rules[0].DstPorts, check.HasLen, 1)
	c.Assert(rules[0].DstPorts[0].Ports.First, check.Equals, uint16(0))
	c.Assert(rules[0].DstPorts[0].Ports.Last, check.Equals, uint16(65535))
	c.Assert(rules[0].SrcIPs, check.HasLen, 1)
	c.Assert(rules[0].SrcIPs[0], check.Not(check.Equals), "not an ip")
	c.Assert(len(ips), check.Equals, 1)
	c.Assert(rules[0].SrcIPs[0], check.Equals, ips[0].String())
}

func (s *Suite) TestPortGroup(c *check.C) {
	namespace, err := app.CreateNamespace("testnamespace")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("testnamespace", "testmachine")
	c.Assert(err, check.NotNil)
	ips, _ := app.getAvailableIPs()
	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		NamespaceID:    namespace.ID,
		RegisterMethod: RegisterMethodAuthKey,
		IPAddresses:    ips,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

	err = app.LoadACLPolicy("./tests/acls/acl_policy_basic_groups.hujson")
	c.Assert(err, check.IsNil)

	rules, err := app.generateACLRules()
	c.Assert(err, check.IsNil)
	c.Assert(rules, check.NotNil)

	c.Assert(rules, check.HasLen, 1)
	c.Assert(rules[0].DstPorts, check.HasLen, 1)
	c.Assert(rules[0].DstPorts[0].Ports.First, check.Equals, uint16(0))
	c.Assert(rules[0].DstPorts[0].Ports.Last, check.Equals, uint16(65535))
	c.Assert(rules[0].SrcIPs, check.HasLen, 1)
	c.Assert(rules[0].SrcIPs[0], check.Not(check.Equals), "not an ip")
	c.Assert(len(ips), check.Equals, 1)
	c.Assert(rules[0].SrcIPs[0], check.Equals, ips[0].String())
}

func Test_expandGroup(t *testing.T) {
	type args struct {
		aclPolicy        ACLPolicy
		group            string
		stripEmailDomain bool
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "simple test",
			args: args{
				aclPolicy: ACLPolicy{
					Groups: Groups{
						"group:test": []string{"user1", "user2", "user3"},
						"group:foo":  []string{"user2", "user3"},
					},
				},
				group:            "group:test",
				stripEmailDomain: true,
			},
			want:    []string{"user1", "user2", "user3"},
			wantErr: false,
		},
		{
			name: "InexistantGroup",
			args: args{
				aclPolicy: ACLPolicy{
					Groups: Groups{
						"group:test": []string{"user1", "user2", "user3"},
						"group:foo":  []string{"user2", "user3"},
					},
				},
				group:            "group:undefined",
				stripEmailDomain: true,
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "Expand emails in group",
			args: args{
				aclPolicy: ACLPolicy{
					Groups: Groups{
						"group:admin": []string{
							"joe.bar@gmail.com",
							"john.doe@yahoo.fr",
						},
					},
				},
				group:            "group:admin",
				stripEmailDomain: true,
			},
			want:    []string{"joe.bar", "john.doe"},
			wantErr: false,
		},
		{
			name: "Expand emails in group",
			args: args{
				aclPolicy: ACLPolicy{
					Groups: Groups{
						"group:admin": []string{
							"joe.bar@gmail.com",
							"john.doe@yahoo.fr",
						},
					},
				},
				group:            "group:admin",
				stripEmailDomain: false,
			},
			want:    []string{"joe.bar.gmail.com", "john.doe.yahoo.fr"},
			wantErr: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := expandGroup(
				test.args.aclPolicy,
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
		aclPolicy        ACLPolicy
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
				aclPolicy: ACLPolicy{
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
				aclPolicy: ACLPolicy{
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
			name: "expand with namespace and group",
			args: args{
				aclPolicy: ACLPolicy{
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
				aclPolicy: ACLPolicy{
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
				aclPolicy: ACLPolicy{
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
			got, err := expandTagOwners(
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

func Test_listMachinesInNamespace(t *testing.T) {
	type args struct {
		machines  []Machine
		namespace string
	}
	tests := []struct {
		name string
		args args
		want []Machine
	}{
		{
			name: "1 machine in namespace",
			args: args{
				machines: []Machine{
					{Namespace: Namespace{Name: "joe"}},
				},
				namespace: "joe",
			},
			want: []Machine{
				{Namespace: Namespace{Name: "joe"}},
			},
		},
		{
			name: "3 machines, 2 in namespace",
			args: args{
				machines: []Machine{
					{ID: 1, Namespace: Namespace{Name: "joe"}},
					{ID: 2, Namespace: Namespace{Name: "marc"}},
					{ID: 3, Namespace: Namespace{Name: "marc"}},
				},
				namespace: "marc",
			},
			want: []Machine{
				{ID: 2, Namespace: Namespace{Name: "marc"}},
				{ID: 3, Namespace: Namespace{Name: "marc"}},
			},
		},
		{
			name: "5 machines, 0 in namespace",
			args: args{
				machines: []Machine{
					{ID: 1, Namespace: Namespace{Name: "joe"}},
					{ID: 2, Namespace: Namespace{Name: "marc"}},
					{ID: 3, Namespace: Namespace{Name: "marc"}},
					{ID: 4, Namespace: Namespace{Name: "marc"}},
					{ID: 5, Namespace: Namespace{Name: "marc"}},
				},
				namespace: "mickael",
			},
			want: []Machine{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := filterMachinesByNamespace(test.args.machines, test.args.namespace); !reflect.DeepEqual(
				got,
				test.want,
			) {
				t.Errorf("listMachinesInNamespace() = %v, want %v", got, test.want)
			}
		})
	}
}

// nolint
func Test_expandAlias(t *testing.T) {
	type args struct {
		machines         []Machine
		aclPolicy        ACLPolicy
		alias            string
		stripEmailDomain bool
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "wildcard",
			args: args{
				alias: "*",
				machines: []Machine{
					{IPAddresses: MachineAddresses{netaddr.MustParseIP("100.64.0.1")}},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.78.84.227"),
						},
					},
				},
				aclPolicy:        ACLPolicy{},
				stripEmailDomain: true,
			},
			want:    []string{"*"},
			wantErr: false,
		},
		{
			name: "simple group",
			args: args{
				alias: "group:accountant",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "joe"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "joe"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.3"),
						},
						Namespace: Namespace{Name: "marc"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.4"),
						},
						Namespace: Namespace{Name: "mickael"},
					},
				},
				aclPolicy: ACLPolicy{
					Groups: Groups{"group:accountant": []string{"joe", "marc"}},
				},
				stripEmailDomain: true,
			},
			want:    []string{"100.64.0.1", "100.64.0.2", "100.64.0.3"},
			wantErr: false,
		},
		{
			name: "wrong group",
			args: args{
				alias: "group:hr",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "joe"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "joe"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.3"),
						},
						Namespace: Namespace{Name: "marc"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.4"),
						},
						Namespace: Namespace{Name: "mickael"},
					},
				},
				aclPolicy: ACLPolicy{
					Groups: Groups{"group:accountant": []string{"joe", "marc"}},
				},
				stripEmailDomain: true,
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "simple ipaddress",
			args: args{
				alias:            "10.0.0.3",
				machines:         []Machine{},
				aclPolicy:        ACLPolicy{},
				stripEmailDomain: true,
			},
			want:    []string{"10.0.0.3"},
			wantErr: false,
		},
		{
			name: "private network",
			args: args{
				alias:    "homeNetwork",
				machines: []Machine{},
				aclPolicy: ACLPolicy{
					Hosts: Hosts{
						"homeNetwork": netaddr.MustParseIPPrefix("192.168.1.0/24"),
					},
				},
				stripEmailDomain: true,
			},
			want:    []string{"192.168.1.0/24"},
			wantErr: false,
		},
		{
			name: "simple host",
			args: args{
				alias:            "10.0.0.1",
				machines:         []Machine{},
				aclPolicy:        ACLPolicy{},
				stripEmailDomain: true,
			},
			want:    []string{"10.0.0.1"},
			wantErr: false,
		},
		{
			name: "simple CIDR",
			args: args{
				alias:            "10.0.0.0/16",
				machines:         []Machine{},
				aclPolicy:        ACLPolicy{},
				stripEmailDomain: true,
			},
			want:    []string{"10.0.0.0/16"},
			wantErr: false,
		},
		{
			name: "simple tag",
			args: args{
				alias: "tag:hr-webserver",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.3"),
						},
						Namespace: Namespace{Name: "marc"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.4"),
						},
						Namespace: Namespace{Name: "joe"},
					},
				},
				aclPolicy: ACLPolicy{
					TagOwners: TagOwners{"tag:hr-webserver": []string{"joe"}},
				},
				stripEmailDomain: true,
			},
			want:    []string{"100.64.0.1", "100.64.0.2"},
			wantErr: false,
		},
		{
			name: "No tag defined",
			args: args{
				alias: "tag:hr-webserver",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "joe"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "joe"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.3"),
						},
						Namespace: Namespace{Name: "marc"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.4"),
						},
						Namespace: Namespace{Name: "mickael"},
					},
				},
				aclPolicy: ACLPolicy{
					Groups: Groups{"group:accountant": []string{"joe", "marc"}},
					TagOwners: TagOwners{
						"tag:accountant-webserver": []string{"group:accountant"},
					},
				},
				stripEmailDomain: true,
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "Forced tag defined",
			args: args{
				alias: "tag:hr-webserver",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace:  Namespace{Name: "joe"},
						ForcedTags: []string{"tag:hr-webserver"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace:  Namespace{Name: "joe"},
						ForcedTags: []string{"tag:hr-webserver"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.3"),
						},
						Namespace: Namespace{Name: "marc"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.4"),
						},
						Namespace: Namespace{Name: "mickael"},
					},
				},
				aclPolicy:        ACLPolicy{},
				stripEmailDomain: true,
			},
			want:    []string{"100.64.0.1", "100.64.0.2"},
			wantErr: false,
		},
		{
			name: "Forced tag with legitimate tagOwner",
			args: args{
				alias: "tag:hr-webserver",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace:  Namespace{Name: "joe"},
						ForcedTags: []string{"tag:hr-webserver"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.3"),
						},
						Namespace: Namespace{Name: "marc"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.4"),
						},
						Namespace: Namespace{Name: "mickael"},
					},
				},
				aclPolicy: ACLPolicy{
					TagOwners: TagOwners{
						"tag:hr-webserver": []string{"joe"},
					},
				},
				stripEmailDomain: true,
			},
			want:    []string{"100.64.0.1", "100.64.0.2"},
			wantErr: false,
		},
		{
			name: "list host in namespace without correctly tagged servers",
			args: args{
				alias: "joe",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.3"),
						},
						Namespace: Namespace{Name: "marc"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.4"),
						},
						Namespace: Namespace{Name: "joe"},
					},
				},
				aclPolicy: ACLPolicy{
					TagOwners: TagOwners{"tag:accountant-webserver": []string{"joe"}},
				},
				stripEmailDomain: true,
			},
			want:    []string{"100.64.0.4"},
			wantErr: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := expandAlias(
				test.args.machines,
				test.args.aclPolicy,
				test.args.alias,
				test.args.stripEmailDomain,
			)
			if (err != nil) != test.wantErr {
				t.Errorf("expandAlias() error = %v, wantErr %v", err, test.wantErr)

				return
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("expandAlias() = %v, want %v", got, test.want)
			}
		})
	}
}

func Test_excludeCorrectlyTaggedNodes(t *testing.T) {
	type args struct {
		aclPolicy ACLPolicy
		nodes     []Machine
		namespace string
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
				aclPolicy: ACLPolicy{
					TagOwners: TagOwners{"tag:accountant-webserver": []string{"joe"}},
				},
				nodes: []Machine{
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.4"),
						},
						Namespace: Namespace{Name: "joe"},
					},
				},
				namespace: "joe",
			},
			want: []Machine{
				{
					IPAddresses: MachineAddresses{netaddr.MustParseIP("100.64.0.4")},
					Namespace:   Namespace{Name: "joe"},
				},
			},
		},
		{
			name: "exclude nodes with valid tags and with forced tags",
			args: args{
				aclPolicy: ACLPolicy{
					TagOwners: TagOwners{"tag:accountant-webserver": []string{"joe"}},
				},
				nodes: []Machine{
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "foo",
							RequestTags: []string{"tag:accountant-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace:  Namespace{Name: "joe"},
						ForcedTags: []string{"tag:accountant-webserver"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.4"),
						},
						Namespace: Namespace{Name: "joe"},
					},
				},
				namespace: "joe",
			},
			want: []Machine{
				{
					IPAddresses: MachineAddresses{netaddr.MustParseIP("100.64.0.4")},
					Namespace:   Namespace{Name: "joe"},
				},
			},
		},
		{
			name: "all nodes have invalid tags, don't exclude them",
			args: args{
				aclPolicy: ACLPolicy{
					TagOwners: TagOwners{"tag:accountant-webserver": []string{"joe"}},
				},
				nodes: []Machine{
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "hr-web1",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "joe"},
						HostInfo: HostInfo{
							OS:          "centos",
							Hostname:    "hr-web2",
							RequestTags: []string{"tag:hr-webserver"},
						},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.4"),
						},
						Namespace: Namespace{Name: "joe"},
					},
				},
				namespace: "joe",
			},
			want: []Machine{
				{
					IPAddresses: MachineAddresses{
						netaddr.MustParseIP("100.64.0.1"),
					},
					Namespace: Namespace{Name: "joe"},
					HostInfo: HostInfo{
						OS:          "centos",
						Hostname:    "hr-web1",
						RequestTags: []string{"tag:hr-webserver"},
					},
				},
				{
					IPAddresses: MachineAddresses{
						netaddr.MustParseIP("100.64.0.2"),
					},
					Namespace: Namespace{Name: "joe"},
					HostInfo: HostInfo{
						OS:          "centos",
						Hostname:    "hr-web2",
						RequestTags: []string{"tag:hr-webserver"},
					},
				},
				{
					IPAddresses: MachineAddresses{
						netaddr.MustParseIP("100.64.0.4"),
					},
					Namespace: Namespace{Name: "joe"},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := excludeCorrectlyTaggedNodes(
				test.args.aclPolicy,
				test.args.nodes,
				test.args.namespace,
			)
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("excludeCorrectlyTaggedNodes() = %v, want %v", got, test.want)
			}
		})
	}
}
