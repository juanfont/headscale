package headscale

import (
	"fmt"
	"reflect"
	"strconv"
	"testing"
	"time"

	"gopkg.in/check.v1"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
)

func (s *Suite) TestGetMachine(c *check.C) {
	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("test", "testmachine")
	c.Assert(err, check.NotNil)

	machine := &Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		NamespaceID:    namespace.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(machine)

	_, err = app.GetMachine("test", "testmachine")
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetMachineByID(c *check.C) {
	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachineByID(0)
	c.Assert(err, check.NotNil)

	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		NamespaceID:    namespace.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

	_, err = app.GetMachineByID(0)
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestDeleteMachine(c *check.C) {
	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)
	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		NamespaceID:    namespace.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(1),
	}
	app.db.Save(&machine)

	err = app.DeleteMachine(&machine)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine(namespace.Name, "testmachine")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestHardDeleteMachine(c *check.C) {
	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)
	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine3",
		NamespaceID:    namespace.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(1),
	}
	app.db.Save(&machine)

	err = app.HardDeleteMachine(&machine)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine(namespace.Name, "testmachine3")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestListPeers(c *check.C) {
	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachineByID(0)
	c.Assert(err, check.NotNil)

	for index := 0; index <= 10; index++ {
		machine := Machine{
			ID:             uint64(index),
			MachineKey:     "foo" + strconv.Itoa(index),
			NodeKey:        "bar" + strconv.Itoa(index),
			DiscoKey:       "faa" + strconv.Itoa(index),
			Name:           "testmachine" + strconv.Itoa(index),
			NamespaceID:    namespace.ID,
			RegisterMethod: RegisterMethodAuthKey,
			AuthKeyID:      uint(pak.ID),
		}
		app.db.Save(&machine)
	}

	machine0ByID, err := app.GetMachineByID(0)
	c.Assert(err, check.IsNil)

	peersOfMachine0, err := app.ListPeers(machine0ByID)
	c.Assert(err, check.IsNil)

	c.Assert(len(peersOfMachine0), check.Equals, 9)
	c.Assert(peersOfMachine0[0].Name, check.Equals, "testmachine2")
	c.Assert(peersOfMachine0[5].Name, check.Equals, "testmachine7")
	c.Assert(peersOfMachine0[8].Name, check.Equals, "testmachine10")
}

func (s *Suite) TestGetACLFilteredPeers(c *check.C) {
	type base struct {
		namespace *Namespace
		key       *PreAuthKey
	}

	stor := make([]base, 0)

	for _, name := range []string{"test", "admin"} {
		namespace, err := app.CreateNamespace(name)
		c.Assert(err, check.IsNil)
		pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
		c.Assert(err, check.IsNil)
		stor = append(stor, base{namespace, pak})
	}

	_, err := app.GetMachineByID(0)
	c.Assert(err, check.NotNil)

	for index := 0; index <= 10; index++ {
		machine := Machine{
			ID:         uint64(index),
			MachineKey: "foo" + strconv.Itoa(index),
			NodeKey:    "bar" + strconv.Itoa(index),
			DiscoKey:   "faa" + strconv.Itoa(index),
			IPAddresses: MachineAddresses{
				netaddr.MustParseIP(fmt.Sprintf("100.64.0.%v", strconv.Itoa(index+1))),
			},
			Name:           "testmachine" + strconv.Itoa(index),
			NamespaceID:    stor[index%2].namespace.ID,
			RegisterMethod: RegisterMethodAuthKey,
			AuthKeyID:      uint(stor[index%2].key.ID),
		}
		app.db.Save(&machine)
	}

	app.aclPolicy = &ACLPolicy{
		Groups: map[string][]string{
			"group:test": {"admin"},
		},
		Hosts:     map[string]netaddr.IPPrefix{},
		TagOwners: map[string][]string{},
		ACLs: []ACL{
			{Action: "accept", Users: []string{"admin"}, Ports: []string{"*:*"}},
			{Action: "accept", Users: []string{"test"}, Ports: []string{"test:*"}},
		},
		Tests: []ACLTest{},
	}

	err = app.UpdateACLRules()
	c.Assert(err, check.IsNil)

	adminMachine, err := app.GetMachineByID(1)
	c.Logf("Machine(%v), namespace: %v", adminMachine.Name, adminMachine.Namespace)
	c.Assert(err, check.IsNil)

	testMachine, err := app.GetMachineByID(2)
	c.Logf("Machine(%v), namespace: %v", testMachine.Name, testMachine.Namespace)
	c.Assert(err, check.IsNil)

	machines, err := app.ListMachines()
	c.Assert(err, check.IsNil)

	peersOfTestMachine := getFilteredByACLPeers(machines, app.aclRules, testMachine)
	peersOfAdminMachine := getFilteredByACLPeers(machines, app.aclRules, adminMachine)

	c.Log(peersOfTestMachine)
	c.Assert(len(peersOfTestMachine), check.Equals, 4)
	c.Assert(peersOfTestMachine[0].Name, check.Equals, "testmachine4")
	c.Assert(peersOfTestMachine[1].Name, check.Equals, "testmachine6")
	c.Assert(peersOfTestMachine[3].Name, check.Equals, "testmachine10")

	c.Log(peersOfAdminMachine)
	c.Assert(len(peersOfAdminMachine), check.Equals, 9)
	c.Assert(peersOfAdminMachine[0].Name, check.Equals, "testmachine2")
	c.Assert(peersOfAdminMachine[2].Name, check.Equals, "testmachine4")
	c.Assert(peersOfAdminMachine[5].Name, check.Equals, "testmachine7")
}

func (s *Suite) TestExpireMachine(c *check.C) {
	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("test", "testmachine")
	c.Assert(err, check.NotNil)

	machine := &Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Name:           "testmachine",
		NamespaceID:    namespace.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		Expiry:         &time.Time{},
	}
	app.db.Save(machine)

	machineFromDB, err := app.GetMachine("test", "testmachine")
	c.Assert(err, check.IsNil)

	c.Assert(machineFromDB.isExpired(), check.Equals, false)

	app.ExpireMachine(machineFromDB)

	c.Assert(machineFromDB.isExpired(), check.Equals, true)
}

func (s *Suite) TestSerdeAddressStrignSlice(c *check.C) {
	input := MachineAddresses([]netaddr.IP{
		netaddr.MustParseIP("192.0.2.1"),
		netaddr.MustParseIP("2001:db8::1"),
	})
	serialized, err := input.Value()
	c.Assert(err, check.IsNil)
	if serial, ok := serialized.(string); ok {
		c.Assert(serial, check.Equals, "192.0.2.1,2001:db8::1")
	}

	var deserialized MachineAddresses
	err = deserialized.Scan(serialized)
	c.Assert(err, check.IsNil)

	c.Assert(len(deserialized), check.Equals, len(input))
	for i := range deserialized {
		c.Assert(deserialized[i], check.Equals, input[i])
	}
}

func Test_getTags(t *testing.T) {
	type args struct {
		aclPolicy        ACLPolicy
		machine          Machine
		stripEmailDomain bool
	}
	tests := []struct {
		name        string
		args        args
		wantInvalid []string
		wantValid   []string
	}{
		{
			name: "valid tag one machine",
			args: args{
				aclPolicy: ACLPolicy{
					TagOwners: TagOwners{
						"tag:valid": []string{"joe"},
					},
				},
				machine: Machine{
					Namespace: Namespace{
						Name: "joe",
					},
					HostInfo: HostInfo{
						RequestTags: []string{"tag:valid"},
					},
				},
				stripEmailDomain: false,
			},
			wantValid:   []string{"tag:valid"},
			wantInvalid: nil,
		},
		{
			name: "invalid tag and valid tag one machine",
			args: args{
				aclPolicy: ACLPolicy{
					TagOwners: TagOwners{
						"tag:valid": []string{"joe"},
					},
				},
				machine: Machine{
					Namespace: Namespace{
						Name: "joe",
					},
					HostInfo: HostInfo{
						RequestTags: []string{"tag:valid", "tag:invalid"},
					},
				},
				stripEmailDomain: false,
			},
			wantValid:   []string{"tag:valid"},
			wantInvalid: []string{"tag:invalid"},
		},
		{
			name: "multiple invalid and identical tags, should return only one invalid tag",
			args: args{
				aclPolicy: ACLPolicy{
					TagOwners: TagOwners{
						"tag:valid": []string{"joe"},
					},
				},
				machine: Machine{
					Namespace: Namespace{
						Name: "joe",
					},
					HostInfo: HostInfo{
						RequestTags: []string{
							"tag:invalid",
							"tag:valid",
							"tag:invalid",
						},
					},
				},
				stripEmailDomain: false,
			},
			wantValid:   []string{"tag:valid"},
			wantInvalid: []string{"tag:invalid"},
		},
		{
			name: "only invalid tags",
			args: args{
				aclPolicy: ACLPolicy{
					TagOwners: TagOwners{
						"tag:valid": []string{"joe"},
					},
				},
				machine: Machine{
					Namespace: Namespace{
						Name: "joe",
					},
					HostInfo: HostInfo{
						RequestTags: []string{"tag:invalid", "very-invalid"},
					},
				},
				stripEmailDomain: false,
			},
			wantValid:   nil,
			wantInvalid: []string{"tag:invalid", "very-invalid"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotValid, gotInvalid := getTags(
				test.args.aclPolicy,
				test.args.machine,
				test.args.stripEmailDomain,
			)
			for _, valid := range gotValid {
				if !contains(test.wantValid, valid) {
					t.Errorf(
						"valids: getTags() = %v, want %v",
						gotValid,
						test.wantValid,
					)

					break
				}
			}
			for _, invalid := range gotInvalid {
				if !contains(test.wantInvalid, invalid) {
					t.Errorf(
						"invalids: getTags() = %v, want %v",
						gotInvalid,
						test.wantInvalid,
					)

					break
				}
			}
		})
	}
}

// nolint
func Test_getFilteredByACLPeers(t *testing.T) {
	type args struct {
		machines []Machine
		rules    []tailcfg.FilterRule
		machine  *Machine
	}
	tests := []struct {
		name string
		args args
		want Machines
	}{
		{
			name: "all hosts can talk to each other",
			args: args{
				machines: []Machine{ // list of all machines in the database
					{
						ID: 1,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.3"),
						},
						Namespace: Namespace{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						SrcIPs: []string{"100.64.0.1", "100.64.0.2", "100.64.0.3"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*"},
						},
					},
				},
				machine: &Machine{ // current machine
					ID:          1,
					IPAddresses: MachineAddresses{netaddr.MustParseIP("100.64.0.1")},
					Namespace:   Namespace{Name: "joe"},
				},
			},
			want: Machines{
				{
					ID:          2,
					IPAddresses: MachineAddresses{netaddr.MustParseIP("100.64.0.2")},
					Namespace:   Namespace{Name: "marc"},
				},
				{
					ID:          3,
					IPAddresses: MachineAddresses{netaddr.MustParseIP("100.64.0.3")},
					Namespace:   Namespace{Name: "mickael"},
				},
			},
		},
		{
			name: "One host can talk to another, but not all hosts",
			args: args{
				machines: []Machine{ // list of all machines in the database
					{
						ID: 1,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.3"),
						},
						Namespace: Namespace{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						SrcIPs: []string{"100.64.0.1", "100.64.0.2", "100.64.0.3"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.2"},
						},
					},
				},
				machine: &Machine{ // current machine
					ID:          1,
					IPAddresses: MachineAddresses{netaddr.MustParseIP("100.64.0.1")},
					Namespace:   Namespace{Name: "joe"},
				},
			},
			want: Machines{
				{
					ID:          2,
					IPAddresses: MachineAddresses{netaddr.MustParseIP("100.64.0.2")},
					Namespace:   Namespace{Name: "marc"},
				},
			},
		},
		{
			name: "host cannot directly talk to destination, but return path is authorized",
			args: args{
				machines: []Machine{ // list of all machines in the database
					{
						ID: 1,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.3"),
						},
						Namespace: Namespace{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						SrcIPs: []string{"100.64.0.3"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.2"},
						},
					},
				},
				machine: &Machine{ // current machine
					ID:          2,
					IPAddresses: MachineAddresses{netaddr.MustParseIP("100.64.0.2")},
					Namespace:   Namespace{Name: "marc"},
				},
			},
			want: Machines{
				{
					ID:          3,
					IPAddresses: MachineAddresses{netaddr.MustParseIP("100.64.0.3")},
					Namespace:   Namespace{Name: "mickael"},
				},
			},
		},
		{
			name: "rules allows all hosts to reach one destination",
			args: args{
				machines: []Machine{ // list of all machines in the database
					{
						ID: 1,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.3"),
						},
						Namespace: Namespace{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						SrcIPs: []string{"*"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.2"},
						},
					},
				},
				machine: &Machine{ // current machine
					ID: 1,
					IPAddresses: MachineAddresses{
						netaddr.MustParseIP("100.64.0.1"),
					},
					Namespace: Namespace{Name: "joe"},
				},
			},
			want: Machines{
				{
					ID: 2,
					IPAddresses: MachineAddresses{
						netaddr.MustParseIP("100.64.0.2"),
					},
					Namespace: Namespace{Name: "marc"},
				},
			},
		},
		{
			name: "rules allows all hosts to reach one destination, destination can reach all hosts",
			args: args{
				machines: []Machine{ // list of all machines in the database
					{
						ID: 1,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.3"),
						},
						Namespace: Namespace{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						SrcIPs: []string{"*"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.2"},
						},
					},
				},
				machine: &Machine{ // current machine
					ID: 2,
					IPAddresses: MachineAddresses{
						netaddr.MustParseIP("100.64.0.2"),
					},
					Namespace: Namespace{Name: "marc"},
				},
			},
			want: Machines{
				{
					ID: 1,
					IPAddresses: MachineAddresses{
						netaddr.MustParseIP("100.64.0.1"),
					},
					Namespace: Namespace{Name: "joe"},
				},
				{
					ID: 3,
					IPAddresses: MachineAddresses{
						netaddr.MustParseIP("100.64.0.3"),
					},
					Namespace: Namespace{Name: "mickael"},
				},
			},
		},
		{
			name: "rule allows all hosts to reach all destinations",
			args: args{
				machines: []Machine{ // list of all machines in the database
					{
						ID: 1,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.3"),
						},
						Namespace: Namespace{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
					{
						SrcIPs: []string{"*"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*"},
						},
					},
				},
				machine: &Machine{ // current machine
					ID:          2,
					IPAddresses: MachineAddresses{netaddr.MustParseIP("100.64.0.2")},
					Namespace:   Namespace{Name: "marc"},
				},
			},
			want: Machines{
				{
					ID: 1,
					IPAddresses: MachineAddresses{
						netaddr.MustParseIP("100.64.0.1"),
					},
					Namespace: Namespace{Name: "joe"},
				},
				{
					ID:          3,
					IPAddresses: MachineAddresses{netaddr.MustParseIP("100.64.0.3")},
					Namespace:   Namespace{Name: "mickael"},
				},
			},
		},
		{
			name: "without rule all communications are forbidden",
			args: args{
				machines: []Machine{ // list of all machines in the database
					{
						ID: 1,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.1"),
						},
						Namespace: Namespace{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.2"),
						},
						Namespace: Namespace{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: MachineAddresses{
							netaddr.MustParseIP("100.64.0.3"),
						},
						Namespace: Namespace{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
				},
				machine: &Machine{ // current machine
					ID:          2,
					IPAddresses: MachineAddresses{netaddr.MustParseIP("100.64.0.2")},
					Namespace:   Namespace{Name: "marc"},
				},
			},
			want: Machines{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getFilteredByACLPeers(
				tt.args.machines,
				tt.args.rules,
				tt.args.machine,
			)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getFilteredByACLPeers() = %v, want %v", got, tt.want)
			}
		})
	}
}
