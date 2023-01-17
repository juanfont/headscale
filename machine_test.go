package headscale

import (
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"testing"
	"time"

	"gopkg.in/check.v1"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func (s *Suite) TestGetMachine(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("test", "testmachine")
	c.Assert(err, check.NotNil)

	machine := &Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(machine)

	_, err = app.GetMachine("test", "testmachine")
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetMachineByID(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachineByID(0)
	c.Assert(err, check.NotNil)

	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

	_, err = app.GetMachineByID(0)
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetMachineByNodeKey(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachineByID(0)
	c.Assert(err, check.NotNil)

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()

	machine := Machine{
		ID:             0,
		MachineKey:     MachinePublicKeyStripPrefix(machineKey.Public()),
		NodeKey:        NodePublicKeyStripPrefix(nodeKey.Public()),
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

	_, err = app.GetMachineByNodeKey(nodeKey.Public())
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetMachineByAnyNodeKey(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachineByID(0)
	c.Assert(err, check.NotNil)

	nodeKey := key.NewNode()
	oldNodeKey := key.NewNode()

	machineKey := key.NewMachine()

	machine := Machine{
		ID:             0,
		MachineKey:     MachinePublicKeyStripPrefix(machineKey.Public()),
		NodeKey:        NodePublicKeyStripPrefix(nodeKey.Public()),
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

	_, err = app.GetMachineByAnyKey(machineKey.Public(), nodeKey.Public(), oldNodeKey.Public())
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestDeleteMachine(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)
	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(1),
	}
	app.db.Save(&machine)

	err = app.DeleteMachine(&machine)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine(user.Name, "testmachine")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestHardDeleteMachine(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)
	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine3",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(1),
	}
	app.db.Save(&machine)

	err = app.HardDeleteMachine(&machine)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine(user.Name, "testmachine3")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestListPeers(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachineByID(0)
	c.Assert(err, check.NotNil)

	for index := 0; index <= 10; index++ {
		machine := Machine{
			ID:             uint64(index),
			MachineKey:     "foo" + strconv.Itoa(index),
			NodeKey:        "bar" + strconv.Itoa(index),
			DiscoKey:       "faa" + strconv.Itoa(index),
			Hostname:       "testmachine" + strconv.Itoa(index),
			UserID:         user.ID,
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
	c.Assert(peersOfMachine0[0].Hostname, check.Equals, "testmachine2")
	c.Assert(peersOfMachine0[5].Hostname, check.Equals, "testmachine7")
	c.Assert(peersOfMachine0[8].Hostname, check.Equals, "testmachine10")
}

func (s *Suite) TestGetACLFilteredPeers(c *check.C) {
	type base struct {
		user *User
		key  *PreAuthKey
	}

	stor := make([]base, 0)

	for _, name := range []string{"test", "admin"} {
		user, err := app.CreateUser(name)
		c.Assert(err, check.IsNil)
		pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
		c.Assert(err, check.IsNil)
		stor = append(stor, base{user, pak})
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
				netip.MustParseAddr(fmt.Sprintf("100.64.0.%v", strconv.Itoa(index+1))),
			},
			Hostname:       "testmachine" + strconv.Itoa(index),
			UserID:         stor[index%2].user.ID,
			RegisterMethod: RegisterMethodAuthKey,
			AuthKeyID:      uint(stor[index%2].key.ID),
		}
		app.db.Save(&machine)
	}

	app.aclPolicy = &ACLPolicy{
		Groups: map[string][]string{
			"group:test": {"admin"},
		},
		Hosts:     map[string]netip.Prefix{},
		TagOwners: map[string][]string{},
		ACLs: []ACL{
			{
				Action:       "accept",
				Sources:      []string{"admin"},
				Destinations: []string{"*:*"},
			},
			{
				Action:       "accept",
				Sources:      []string{"test"},
				Destinations: []string{"test:*"},
			},
		},
		Tests: []ACLTest{},
	}

	err = app.UpdateACLRules()
	c.Assert(err, check.IsNil)

	adminMachine, err := app.GetMachineByID(1)
	c.Logf("Machine(%v), user: %v", adminMachine.Hostname, adminMachine.User)
	c.Assert(err, check.IsNil)

	testMachine, err := app.GetMachineByID(2)
	c.Logf("Machine(%v), user: %v", testMachine.Hostname, testMachine.User)
	c.Assert(err, check.IsNil)

	machines, err := app.ListMachines()
	c.Assert(err, check.IsNil)

	peersOfTestMachine := getFilteredByACLPeers(machines, app.aclRules, testMachine)
	peersOfAdminMachine := getFilteredByACLPeers(machines, app.aclRules, adminMachine)

	c.Log(peersOfTestMachine)
	c.Assert(len(peersOfTestMachine), check.Equals, 4)
	c.Assert(peersOfTestMachine[0].Hostname, check.Equals, "testmachine4")
	c.Assert(peersOfTestMachine[1].Hostname, check.Equals, "testmachine6")
	c.Assert(peersOfTestMachine[3].Hostname, check.Equals, "testmachine10")

	c.Log(peersOfAdminMachine)
	c.Assert(len(peersOfAdminMachine), check.Equals, 9)
	c.Assert(peersOfAdminMachine[0].Hostname, check.Equals, "testmachine2")
	c.Assert(peersOfAdminMachine[2].Hostname, check.Equals, "testmachine4")
	c.Assert(peersOfAdminMachine[5].Hostname, check.Equals, "testmachine7")
}

func (s *Suite) TestExpireMachine(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("test", "testmachine")
	c.Assert(err, check.NotNil)

	machine := &Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		Expiry:         &time.Time{},
	}
	app.db.Save(machine)

	machineFromDB, err := app.GetMachine("test", "testmachine")
	c.Assert(err, check.IsNil)
	c.Assert(machineFromDB, check.NotNil)

	c.Assert(machineFromDB.isExpired(), check.Equals, false)

	err = app.ExpireMachine(machineFromDB)
	c.Assert(err, check.IsNil)

	c.Assert(machineFromDB.isExpired(), check.Equals, true)
}

func (s *Suite) TestSerdeAddressStrignSlice(c *check.C) {
	input := MachineAddresses([]netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
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

func (s *Suite) TestGenerateGivenName(c *check.C) {
	user1, err := app.CreateUser("user-1")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user1.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("user-1", "testmachine")
	c.Assert(err, check.NotNil)

	machine := &Machine{
		ID:             0,
		MachineKey:     "machine-key-1",
		NodeKey:        "node-key-1",
		DiscoKey:       "disco-key-1",
		Hostname:       "hostname-1",
		GivenName:      "hostname-1",
		UserID:         user1.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(machine)

	givenName, err := app.GenerateGivenName("machine-key-2", "hostname-2")
	comment := check.Commentf("Same user, unique machines, unique hostnames, no conflict")
	c.Assert(err, check.IsNil, comment)
	c.Assert(givenName, check.Equals, "hostname-2", comment)

	givenName, err = app.GenerateGivenName("machine-key-1", "hostname-1")
	comment = check.Commentf("Same user, same machine, same hostname, no conflict")
	c.Assert(err, check.IsNil, comment)
	c.Assert(givenName, check.Equals, "hostname-1", comment)

	givenName, err = app.GenerateGivenName("machine-key-2", "hostname-1")
	comment = check.Commentf("Same user, unique machines, same hostname, conflict")
	c.Assert(err, check.IsNil, comment)
	c.Assert(givenName, check.Matches, fmt.Sprintf("^hostname-1-[a-z0-9]{%d}$", MachineGivenNameHashLength), comment)

	givenName, err = app.GenerateGivenName("machine-key-2", "hostname-1")
	comment = check.Commentf("Unique users, unique machines, same hostname, conflict")
	c.Assert(err, check.IsNil, comment)
	c.Assert(givenName, check.Matches, fmt.Sprintf("^hostname-1-[a-z0-9]{%d}$", MachineGivenNameHashLength), comment)
}

func (s *Suite) TestSetTags(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine("test", "testmachine")
	c.Assert(err, check.NotNil)

	machine := &Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(machine)

	// assign simple tags
	sTags := []string{"tag:test", "tag:foo"}
	err = app.SetTags(machine, sTags)
	c.Assert(err, check.IsNil)
	machine, err = app.GetMachine("test", "testmachine")
	c.Assert(err, check.IsNil)
	c.Assert(machine.ForcedTags, check.DeepEquals, StringList(sTags))

	// assign duplicat tags, expect no errors but no doubles in DB
	eTags := []string{"tag:bar", "tag:test", "tag:unknown", "tag:test"}
	err = app.SetTags(machine, eTags)
	c.Assert(err, check.IsNil)
	machine, err = app.GetMachine("test", "testmachine")
	c.Assert(err, check.IsNil)
	c.Assert(
		machine.ForcedTags,
		check.DeepEquals,
		StringList([]string{"tag:bar", "tag:test", "tag:unknown"}),
	)
}

func Test_getTags(t *testing.T) {
	type args struct {
		aclPolicy        *ACLPolicy
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
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{
						"tag:valid": []string{"joe"},
					},
				},
				machine: Machine{
					User: User{
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
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{
						"tag:valid": []string{"joe"},
					},
				},
				machine: Machine{
					User: User{
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
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{
						"tag:valid": []string{"joe"},
					},
				},
				machine: Machine{
					User: User{
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
				aclPolicy: &ACLPolicy{
					TagOwners: TagOwners{
						"tag:valid": []string{"joe"},
					},
				},
				machine: Machine{
					User: User{
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
		{
			name: "empty ACLPolicy should return empty tags and should not panic",
			args: args{
				aclPolicy: nil,
				machine: Machine{
					User: User{
						Name: "joe",
					},
					HostInfo: HostInfo{
						RequestTags: []string{"tag:invalid", "very-invalid"},
					},
				},
				stripEmailDomain: false,
			},
			wantValid:   nil,
			wantInvalid: nil,
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
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "mickael"},
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
					IPAddresses: MachineAddresses{netip.MustParseAddr("100.64.0.1")},
					User:        User{Name: "joe"},
				},
			},
			want: Machines{
				{
					ID:          2,
					IPAddresses: MachineAddresses{netip.MustParseAddr("100.64.0.2")},
					User:        User{Name: "marc"},
				},
				{
					ID:          3,
					IPAddresses: MachineAddresses{netip.MustParseAddr("100.64.0.3")},
					User:        User{Name: "mickael"},
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
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "mickael"},
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
					IPAddresses: MachineAddresses{netip.MustParseAddr("100.64.0.1")},
					User:        User{Name: "joe"},
				},
			},
			want: Machines{
				{
					ID:          2,
					IPAddresses: MachineAddresses{netip.MustParseAddr("100.64.0.2")},
					User:        User{Name: "marc"},
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
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "mickael"},
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
					IPAddresses: MachineAddresses{netip.MustParseAddr("100.64.0.2")},
					User:        User{Name: "marc"},
				},
			},
			want: Machines{
				{
					ID:          3,
					IPAddresses: MachineAddresses{netip.MustParseAddr("100.64.0.3")},
					User:        User{Name: "mickael"},
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
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "mickael"},
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
						netip.MustParseAddr("100.64.0.1"),
					},
					User: User{Name: "joe"},
				},
			},
			want: Machines{
				{
					ID: 2,
					IPAddresses: MachineAddresses{
						netip.MustParseAddr("100.64.0.2"),
					},
					User: User{Name: "marc"},
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
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "mickael"},
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
						netip.MustParseAddr("100.64.0.2"),
					},
					User: User{Name: "marc"},
				},
			},
			want: Machines{
				{
					ID: 1,
					IPAddresses: MachineAddresses{
						netip.MustParseAddr("100.64.0.1"),
					},
					User: User{Name: "joe"},
				},
				{
					ID: 3,
					IPAddresses: MachineAddresses{
						netip.MustParseAddr("100.64.0.3"),
					},
					User: User{Name: "mickael"},
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
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "mickael"},
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
					IPAddresses: MachineAddresses{netip.MustParseAddr("100.64.0.2")},
					User:        User{Name: "marc"},
				},
			},
			want: Machines{
				{
					ID: 1,
					IPAddresses: MachineAddresses{
						netip.MustParseAddr("100.64.0.1"),
					},
					User: User{Name: "joe"},
				},
				{
					ID:          3,
					IPAddresses: MachineAddresses{netip.MustParseAddr("100.64.0.3")},
					User:        User{Name: "mickael"},
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
							netip.MustParseAddr("100.64.0.1"),
						},
						User: User{Name: "joe"},
					},
					{
						ID: 2,
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.2"),
						},
						User: User{Name: "marc"},
					},
					{
						ID: 3,
						IPAddresses: MachineAddresses{
							netip.MustParseAddr("100.64.0.3"),
						},
						User: User{Name: "mickael"},
					},
				},
				rules: []tailcfg.FilterRule{ // list of all ACLRules registered
				},
				machine: &Machine{ // current machine
					ID:          2,
					IPAddresses: MachineAddresses{netip.MustParseAddr("100.64.0.2")},
					User:        User{Name: "marc"},
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

func TestHeadscale_generateGivenName(t *testing.T) {
	type args struct {
		suppliedName string
		randomSuffix bool
	}
	tests := []struct {
		name    string
		h       *Headscale
		args    args
		want    *regexp.Regexp
		wantErr bool
	}{
		{
			name: "simple machine name generation",
			h: &Headscale{
				cfg: &Config{
					OIDC: OIDCConfig{
						StripEmaildomain: true,
					},
				},
			},
			args: args{
				suppliedName: "testmachine",
				randomSuffix: false,
			},
			want:    regexp.MustCompile("^testmachine$"),
			wantErr: false,
		},
		{
			name: "machine name with 53 chars",
			h: &Headscale{
				cfg: &Config{
					OIDC: OIDCConfig{
						StripEmaildomain: true,
					},
				},
			},
			args: args{
				suppliedName: "testmaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaachine",
				randomSuffix: false,
			},
			want:    regexp.MustCompile("^testmaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaachine$"),
			wantErr: false,
		},
		{
			name: "machine name with 63 chars",
			h: &Headscale{
				cfg: &Config{
					OIDC: OIDCConfig{
						StripEmaildomain: true,
					},
				},
			},
			args: args{
				suppliedName: "machineeee12345678901234567890123456789012345678901234567890123",
				randomSuffix: false,
			},
			want:    regexp.MustCompile("^machineeee12345678901234567890123456789012345678901234567890123$"),
			wantErr: false,
		},
		{
			name: "machine name with 64 chars",
			h: &Headscale{
				cfg: &Config{
					OIDC: OIDCConfig{
						StripEmaildomain: true,
					},
				},
			},
			args: args{
				suppliedName: "machineeee123456789012345678901234567890123456789012345678901234",
				randomSuffix: false,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "machine name with 73 chars",
			h: &Headscale{
				cfg: &Config{
					OIDC: OIDCConfig{
						StripEmaildomain: true,
					},
				},
			},
			args: args{
				suppliedName: "machineeee123456789012345678901234567890123456789012345678901234567890123",
				randomSuffix: false,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "machine name with random suffix",
			h: &Headscale{
				cfg: &Config{
					OIDC: OIDCConfig{
						StripEmaildomain: true,
					},
				},
			},
			args: args{
				suppliedName: "test",
				randomSuffix: true,
			},
			want:    regexp.MustCompile(fmt.Sprintf("^test-[a-z0-9]{%d}$", MachineGivenNameHashLength)),
			wantErr: false,
		},
		{
			name: "machine name with 63 chars with random suffix",
			h: &Headscale{
				cfg: &Config{
					OIDC: OIDCConfig{
						StripEmaildomain: true,
					},
				},
			},
			args: args{
				suppliedName: "machineeee12345678901234567890123456789012345678901234567890123",
				randomSuffix: true,
			},
			want:    regexp.MustCompile(fmt.Sprintf("^machineeee1234567890123456789012345678901234567890123-[a-z0-9]{%d}$", MachineGivenNameHashLength)),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.generateGivenName(tt.args.suppliedName, tt.args.randomSuffix)
			if (err != nil) != tt.wantErr {
				t.Errorf(
					"Headscale.GenerateGivenName() error = %v, wantErr %v",
					err,
					tt.wantErr,
				)

				return
			}

			if tt.want != nil && !tt.want.MatchString(got) {
				t.Errorf(
					"Headscale.GenerateGivenName() = %v, does not match %v",
					tt.want,
					got,
				)
			}

			if len(got) > labelHostnameLength {
				t.Errorf(
					"Headscale.GenerateGivenName() = %v is larger than allowed DNS segment %d",
					got,
					labelHostnameLength,
				)
			}
		})
	}
}

func (s *Suite) TestAutoApproveRoutes(c *check.C) {
	err := app.LoadACLPolicy("./tests/acls/acl_policy_autoapprovers.hujson")
	c.Assert(err, check.IsNil)

	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	nodeKey := key.NewNode()

	defaultRoute := netip.MustParsePrefix("0.0.0.0/0")
	route1 := netip.MustParsePrefix("10.10.0.0/16")
	// Check if a subprefix of an autoapproved route is approved
	route2 := netip.MustParsePrefix("10.11.0.0/24")

	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        NodePublicKeyStripPrefix(nodeKey.Public()),
		DiscoKey:       "faa",
		Hostname:       "test",
		UserID:         user.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo: HostInfo{
			RequestTags: []string{"tag:exit"},
			RoutableIPs: []netip.Prefix{defaultRoute, route1, route2},
		},
		IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
	}

	app.db.Save(&machine)

	err = app.processMachineRoutes(&machine)
	c.Assert(err, check.IsNil)

	machine0ByID, err := app.GetMachineByID(0)
	c.Assert(err, check.IsNil)

	err = app.EnableAutoApprovedRoutes(machine0ByID)
	c.Assert(err, check.IsNil)

	enabledRoutes, err := app.GetEnabledRoutes(machine0ByID)
	c.Assert(err, check.IsNil)
	c.Assert(enabledRoutes, check.HasLen, 3)
}
