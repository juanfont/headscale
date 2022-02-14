package headscale

import (
	"errors"
	"reflect"
	"testing"

	"gopkg.in/check.v1"
	"gorm.io/datatypes"
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

func (s *Suite) TestInvalidAction(c *check.C) {
	app.aclPolicy = &ACLPolicy{
		ACLs: []ACL{
			{Action: "invalidAction", Users: []string{"*"}, Ports: []string{"*:*"}},
		},
	}
	err := app.UpdateACLRules()
	c.Assert(errors.Is(err, errInvalidAction), check.Equals, true)
}

func (s *Suite) TestInvalidGroupInGroup(c *check.C) {
	// this ACL is wrong because the group in users sections doesn't exist
	app.aclPolicy = &ACLPolicy{
		Groups: Groups{
			"group:test":  []string{"foo"},
			"group:error": []string{"foo", "group:test"},
		},
		ACLs: []ACL{
			{Action: "accept", Users: []string{"group:error"}, Ports: []string{"*:*"}},
		},
	}
	err := app.UpdateACLRules()
	c.Assert(errors.Is(err, errInvalidGroup), check.Equals, true)
}

func (s *Suite) TestInvalidTagOwners(c *check.C) {
	// this ACL is wrong because no tagOwners own the requested tag for the server
	app.aclPolicy = &ACLPolicy{
		ACLs: []ACL{
			{Action: "accept", Users: []string{"tag:foo"}, Ports: []string{"*:*"}},
		},
	}
	err := app.UpdateACLRules()
	c.Assert(errors.Is(err, errInvalidTag), check.Equals, true)
}

// this test should validate that we can expand a group in a TagOWner section and
// match properly the IP's of the related hosts. The owner is valid and the tag is also valid.
// the tag is matched in the Users section.
func (s *Suite) TestValidExpandTagOwnersInUsers(c *check.C) {
	namespace, err := app.CreateNamespace("foo")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("foo", "testmachine")
	c.Assert(err, check.NotNil)
	hostInfo := []byte(
		"{\"OS\":\"centos\",\"Hostname\":\"foo\",\"RequestTags\":[\"tag:test\"]}",
	)
	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		IPAddresses:    MachineAddresses{netaddr.MustParseIP("100.64.0.1")},
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       datatypes.JSON(hostInfo),
	}
	app.db.Save(&machine)

	app.aclPolicy = &ACLPolicy{
		Groups:    Groups{"group:test": []string{"foo", "foobar"}},
		TagOwners: TagOwners{"tag:test": []string{"bar", "group:test"}},
		ACLs: []ACL{
			{Action: "accept", Users: []string{"tag:test"}, Ports: []string{"*:*"}},
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
// the tag is matched in the Ports section.
func (s *Suite) TestValidExpandTagOwnersInPorts(c *check.C) {
	namespace, err := app.CreateNamespace("foo")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("foo", "testmachine")
	c.Assert(err, check.NotNil)
	hostInfo := []byte(
		"{\"OS\":\"centos\",\"Hostname\":\"foo\",\"RequestTags\":[\"tag:test\"]}",
	)
	machine := Machine{
		ID:             1,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		IPAddresses:    MachineAddresses{netaddr.MustParseIP("100.64.0.1")},
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       datatypes.JSON(hostInfo),
	}
	app.db.Save(&machine)

	app.aclPolicy = &ACLPolicy{
		Groups:    Groups{"group:test": []string{"foo", "foobar"}},
		TagOwners: TagOwners{"tag:test": []string{"bar", "group:test"}},
		ACLs: []ACL{
			{Action: "accept", Users: []string{"*"}, Ports: []string{"tag:test:*"}},
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
	namespace, err := app.CreateNamespace("foo")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("foo", "testmachine")
	c.Assert(err, check.NotNil)
	hostInfo := []byte(
		"{\"OS\":\"centos\",\"Hostname\":\"foo\",\"RequestTags\":[\"tag:foo\"]}",
	)
	machine := Machine{
		ID:             1,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		IPAddresses:    MachineAddresses{netaddr.MustParseIP("100.64.0.1")},
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       datatypes.JSON(hostInfo),
	}
	app.db.Save(&machine)

	app.aclPolicy = &ACLPolicy{
		TagOwners: TagOwners{"tag:test": []string{"foo"}},
		ACLs: []ACL{
			{Action: "accept", Users: []string{"foo"}, Ports: []string{"*:*"}},
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
	namespace, err := app.CreateNamespace("foo")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("foo", "webserver")
	c.Assert(err, check.NotNil)
	hostInfo := []byte(
		"{\"OS\":\"centos\",\"Hostname\":\"webserver\",\"RequestTags\":[\"tag:webapp\"]}",
	)
	machine := Machine{
		ID:             1,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "webserver",
		IPAddresses:    MachineAddresses{netaddr.MustParseIP("100.64.0.1")},
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       datatypes.JSON(hostInfo),
	}
	app.db.Save(&machine)
	_, err = app.GetMachine("foo", "user")
	hostInfo = []byte("{\"OS\":\"debian\",\"Hostname\":\"user\"}")
	c.Assert(err, check.NotNil)
	machine = Machine{
		ID:             2,
		MachineKey:     "foo2",
		NodeKey:        "bar2",
		DiscoKey:       "faab",
		Name:           "user",
		IPAddresses:    MachineAddresses{netaddr.MustParseIP("100.64.0.2")},
		NamespaceID:    namespace.ID,
		Registered:     true,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo:       datatypes.JSON(hostInfo),
	}
	app.db.Save(&machine)

	app.aclPolicy = &ACLPolicy{
		TagOwners: TagOwners{"tag:webapp": []string{"foo"}},
		ACLs: []ACL{
			{
				Action: "accept",
				Users:  []string{"foo"},
				Ports:  []string{"tag:webapp:80,443"},
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
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		NamespaceID:    namespace.ID,
		Registered:     true,
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
		Name:           "testmachine",
		NamespaceID:    namespace.ID,
		Registered:     true,
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
		aclPolicy ACLPolicy
		group     string
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
						"group:test": []string{"g1", "foo", "test"},
						"group:foo":  []string{"foo", "test"},
					},
				},
				group: "group:test",
			},
			want:    []string{"g1", "foo", "test"},
			wantErr: false,
		},
		{
			name: "InexistantGroup",
			args: args{
				aclPolicy: ACLPolicy{
					Groups: Groups{
						"group:test": []string{"g1", "foo", "test"},
						"group:foo":  []string{"foo", "test"},
					},
				},
				group: "group:bar",
			},
			want:    []string{},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := expandGroup(test.args.aclPolicy, test.args.group)
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
		aclPolicy ACLPolicy
		tag       string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "simple tag",
			args: args{
				aclPolicy: ACLPolicy{
					TagOwners: TagOwners{"tag:test": []string{"namespace1"}},
				},
				tag: "tag:test",
			},
			want:    []string{"namespace1"},
			wantErr: false,
		},
		{
			name: "tag and group",
			args: args{
				aclPolicy: ACLPolicy{
					Groups:    Groups{"group:foo": []string{"n1", "bar"}},
					TagOwners: TagOwners{"tag:test": []string{"group:foo"}},
				},
				tag: "tag:test",
			},
			want:    []string{"n1", "bar"},
			wantErr: false,
		},
		{
			name: "namespace and group",
			args: args{
				aclPolicy: ACLPolicy{
					Groups:    Groups{"group:foo": []string{"n1", "bar"}},
					TagOwners: TagOwners{"tag:test": []string{"group:foo", "home"}},
				},
				tag: "tag:test",
			},
			want:    []string{"n1", "bar", "home"},
			wantErr: false,
		},
		{
			name: "invalid tag",
			args: args{
				aclPolicy: ACLPolicy{
					TagOwners: TagOwners{"tag:foo": []string{"group:foo", "home"}},
				},
				tag: "tag:test",
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "invalid group",
			args: args{
				aclPolicy: ACLPolicy{
					Groups:    Groups{"group:bar": []string{"n1", "foo"}},
					TagOwners: TagOwners{"tag:test": []string{"group:foo", "home"}},
				},
				tag: "tag:test",
			},
			want:    []string{},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := expandTagOwners(test.args.aclPolicy, test.args.tag)
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
		portsStr string
	}
	tests := []struct {
		name    string
		args    args
		want    *[]tailcfg.PortRange
		wantErr bool
	}{
		{
			name: "wildcard",
			args: args{portsStr: "*"},
			want: &[]tailcfg.PortRange{
				{First: portRangeBegin, Last: portRangeEnd},
			},
			wantErr: false,
		},
		{
			name: "two ports",
			args: args{portsStr: "80,443"},
			want: &[]tailcfg.PortRange{
				{First: 80, Last: 80},
				{First: 443, Last: 443},
			},
			wantErr: false,
		},
		{
			name: "a range and a port",
			args: args{portsStr: "80-1024,443"},
			want: &[]tailcfg.PortRange{
				{First: 80, Last: 1024},
				{First: 443, Last: 443},
			},
			wantErr: false,
		},
		{
			name:    "out of bounds",
			args:    args{portsStr: "854038"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong port",
			args:    args{portsStr: "85a38"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong port in first",
			args:    args{portsStr: "a-80"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong port in last",
			args:    args{portsStr: "80-85a38"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "wrong port format",
			args:    args{portsStr: "80-85a38-3"},
			want:    nil,
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := expandPorts(test.args.portsStr)
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
					{Namespace: Namespace{Name: "test"}},
				},
				namespace: "test",
			},
			want: []Machine{
				{Namespace: Namespace{Name: "test"}},
			},
		},
		{
			name: "3 machines, 2 in namespace",
			args: args{
				machines: []Machine{
					{ID: 1, Namespace: Namespace{Name: "test"}},
					{ID: 2, Namespace: Namespace{Name: "foo"}},
					{ID: 3, Namespace: Namespace{Name: "foo"}},
				},
				namespace: "foo",
			},
			want: []Machine{
				{ID: 2, Namespace: Namespace{Name: "foo"}},
				{ID: 3, Namespace: Namespace{Name: "foo"}},
			},
		},
		{
			name: "5 machines, 0 in namespace",
			args: args{
				machines: []Machine{
					{ID: 1, Namespace: Namespace{Name: "test"}},
					{ID: 2, Namespace: Namespace{Name: "foo"}},
					{ID: 3, Namespace: Namespace{Name: "foo"}},
					{ID: 4, Namespace: Namespace{Name: "foo"}},
					{ID: 5, Namespace: Namespace{Name: "foo"}},
				},
				namespace: "bar",
			},
			want: []Machine{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := listMachinesInNamespace(tt.args.machines, tt.args.namespace); !reflect.DeepEqual(
				got,
				tt.want,
			) {
				t.Errorf("listMachinesInNamespace() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_expandAlias(t *testing.T) {
	type args struct {
		machines  []Machine
		aclPolicy ACLPolicy
		alias     string
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
				aclPolicy: ACLPolicy{},
			},
			want:    []string{"*"},
			wantErr: false,
		},
		{
			name: "simple group",
			args: args{
				alias: "group:foo",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "foo"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "foo"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.3"),
						},
						Namespace: Namespace{Name: "bar"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.4"),
						},
						Namespace: Namespace{Name: "test"},
					},
				},
				aclPolicy: ACLPolicy{
					Groups: Groups{"group:foo": []string{"foo", "bar"}},
				},
			},
			want:    []string{"100.64.0.1", "100.64.0.2", "100.64.0.3"},
			wantErr: false,
		},
		{
			name: "wrong group",
			args: args{
				alias: "group:test",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "foo"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "foo"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.3"),
						},
						Namespace: Namespace{Name: "bar"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.4"),
						},
						Namespace: Namespace{Name: "test"},
					},
				},
				aclPolicy: ACLPolicy{
					Groups: Groups{"group:foo": []string{"foo", "bar"}},
				},
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "simple ipaddress",
			args: args{
				alias:     "10.0.0.3",
				machines:  []Machine{},
				aclPolicy: ACLPolicy{},
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
			},
			want:    []string{"192.168.1.0/24"},
			wantErr: false,
		},
		{
			name: "simple host",
			args: args{
				alias:     "10.0.0.1",
				machines:  []Machine{},
				aclPolicy: ACLPolicy{},
			},
			want:    []string{"10.0.0.1"},
			wantErr: false,
		},
		{
			name: "simple CIDR",
			args: args{
				alias:     "10.0.0.0/16",
				machines:  []Machine{},
				aclPolicy: ACLPolicy{},
			},
			want:    []string{"10.0.0.0/16"},
			wantErr: false,
		},
		{
			name: "simple tag",
			args: args{
				alias: "tag:test",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "foo"},
						HostInfo: []byte(
							"{\"OS\":\"centos\",\"Hostname\":\"foo\",\"RequestTags\":[\"tag:test\"]}",
						),
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "foo"},
						HostInfo: []byte(
							"{\"OS\":\"centos\",\"Hostname\":\"foo\",\"RequestTags\":[\"tag:test\"]}",
						),
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.3"),
						},
						Namespace: Namespace{Name: "bar"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.4"),
						},
						Namespace: Namespace{Name: "foo"},
					},
				},
				aclPolicy: ACLPolicy{
					TagOwners: TagOwners{"tag:test": []string{"foo"}},
				},
			},
			want:    []string{"100.64.0.1", "100.64.0.2"},
			wantErr: false,
		},
		{
			name: "No tag defined",
			args: args{
				alias: "tag:foo",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "foo"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "foo"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.3"),
						},
						Namespace: Namespace{Name: "bar"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.4"),
						},
						Namespace: Namespace{Name: "test"},
					},
				},
				aclPolicy: ACLPolicy{
					Groups:    Groups{"group:foo": []string{"foo", "bar"}},
					TagOwners: TagOwners{"tag:test": []string{"group:foo"}},
				},
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name: "list host in namespace without correctly tagged servers",
			args: args{
				alias: "foo",
				machines: []Machine{
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "foo"},
						HostInfo: []byte(
							"{\"OS\":\"centos\",\"Hostname\":\"foo\",\"RequestTags\":[\"tag:test\"]}",
						),
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "foo"},
						HostInfo: []byte(
							"{\"OS\":\"centos\",\"Hostname\":\"foo\",\"RequestTags\":[\"tag:test\"]}",
						),
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.3"),
						},
						Namespace: Namespace{Name: "bar"},
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.4"),
						},
						Namespace: Namespace{Name: "foo"},
					},
				},
				aclPolicy: ACLPolicy{
					TagOwners: TagOwners{"tag:test": []string{"foo"}},
				},
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
					TagOwners: TagOwners{"tag:test": []string{"foo"}},
				},
				nodes: []Machine{
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "foo"},
						HostInfo: []byte(
							"{\"OS\":\"centos\",\"Hostname\":\"foo\",\"RequestTags\":[\"tag:test\"]}",
						),
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "foo"},
						HostInfo: []byte(
							"{\"OS\":\"centos\",\"Hostname\":\"foo\",\"RequestTags\":[\"tag:test\"]}",
						),
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.4"),
						},
						Namespace: Namespace{Name: "foo"},
					},
				},
				namespace: "foo",
			},
			want: []Machine{
				{
					IPAddresses: MachineAddresses{netaddr.MustParseIP("100.64.0.4")},
					Namespace:   Namespace{Name: "foo"},
				},
			},
			wantErr: false,
		},
		{
			name: "all nodes have invalid tags, don't exclude them",
			args: args{
				aclPolicy: ACLPolicy{
					TagOwners: TagOwners{"tag:foo": []string{"foo"}},
				},
				nodes: []Machine{
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "foo"},
						HostInfo: []byte(
							"{\"OS\":\"centos\",\"Hostname\":\"foo\",\"RequestTags\":[\"tag:test\"]}",
						),
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "foo"},
						HostInfo: []byte(
							"{\"OS\":\"centos\",\"Hostname\":\"foo\",\"RequestTags\":[\"tag:test\"]}",
						),
					},
					{
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.4"),
						},
						Namespace: Namespace{Name: "foo"},
					},
				},
				namespace: "foo",
			},
			want: []Machine{
				{
					IPAddresses: MachineAddresses{netaddr.MustParseIP("100.64.0.1")},
					Namespace:   Namespace{Name: "foo"},
					HostInfo: []byte(
						"{\"OS\":\"centos\",\"Hostname\":\"foo\",\"RequestTags\":[\"tag:test\"]}",
					),
				},
				{
					IPAddresses: MachineAddresses{netaddr.MustParseIP("100.64.0.2")},
					Namespace:   Namespace{Name: "foo"},
					HostInfo: []byte(
						"{\"OS\":\"centos\",\"Hostname\":\"foo\",\"RequestTags\":[\"tag:test\"]}",
					),
				},
				{
					IPAddresses: MachineAddresses{netaddr.MustParseIP("100.64.0.4")},
					Namespace:   Namespace{Name: "foo"},
				},
			},
			wantErr: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := excludeCorrectlyTaggedNodes(
				test.args.aclPolicy,
				test.args.nodes,
				test.args.namespace,
			)
			if (err != nil) != test.wantErr {
				t.Errorf(
					"excludeCorrectlyTaggedNodes() error = %v, wantErr %v",
					err,
					test.wantErr,
				)

				return
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("excludeCorrectlyTaggedNodes() = %v, want %v", got, test.want)
			}
		})
	}
}
