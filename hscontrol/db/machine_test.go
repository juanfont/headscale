package db

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"gopkg.in/check.v1"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func (s *Suite) TestGetMachine(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetMachine("test", "testmachine")
	c.Assert(err, check.NotNil)

	machine := &types.Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	db.db.Save(machine)

	_, err = db.GetMachine("test", "testmachine")
	c.Assert(err, check.IsNil)

	c.Assert(channelUpdates, check.Equals, int32(0))
}

func (s *Suite) TestGetMachineByID(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetMachineByID(0)
	c.Assert(err, check.NotNil)

	machine := types.Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	db.db.Save(&machine)

	_, err = db.GetMachineByID(0)
	c.Assert(err, check.IsNil)

	c.Assert(channelUpdates, check.Equals, int32(0))
}

func (s *Suite) TestGetMachineByNodeKey(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetMachineByID(0)
	c.Assert(err, check.NotNil)

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()

	machine := types.Machine{
		ID:             0,
		MachineKey:     util.MachinePublicKeyStripPrefix(machineKey.Public()),
		NodeKey:        util.NodePublicKeyStripPrefix(nodeKey.Public()),
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	db.db.Save(&machine)

	_, err = db.GetMachineByNodeKey(nodeKey.Public())
	c.Assert(err, check.IsNil)

	c.Assert(channelUpdates, check.Equals, int32(0))
}

func (s *Suite) TestGetMachineByAnyNodeKey(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetMachineByID(0)
	c.Assert(err, check.NotNil)

	nodeKey := key.NewNode()
	oldNodeKey := key.NewNode()

	machineKey := key.NewMachine()

	machine := types.Machine{
		ID:             0,
		MachineKey:     util.MachinePublicKeyStripPrefix(machineKey.Public()),
		NodeKey:        util.NodePublicKeyStripPrefix(nodeKey.Public()),
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	db.db.Save(&machine)

	_, err = db.GetMachineByAnyKey(machineKey.Public(), nodeKey.Public(), oldNodeKey.Public())
	c.Assert(err, check.IsNil)

	c.Assert(channelUpdates, check.Equals, int32(0))
}

func (s *Suite) TestDeleteMachine(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)
	machine := types.Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(1),
	}
	db.db.Save(&machine)

	err = db.DeleteMachine(&machine)
	c.Assert(err, check.IsNil)

	_, err = db.GetMachine(user.Name, "testmachine")
	c.Assert(err, check.NotNil)

	c.Assert(channelUpdates, check.Equals, int32(0))
}

func (s *Suite) TestHardDeleteMachine(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)
	machine := types.Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine3",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(1),
	}
	db.db.Save(&machine)

	err = db.HardDeleteMachine(&machine)
	c.Assert(err, check.IsNil)

	_, err = db.GetMachine(user.Name, "testmachine3")
	c.Assert(err, check.NotNil)

	c.Assert(channelUpdates, check.Equals, int32(0))
}

func (s *Suite) TestListPeers(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetMachineByID(0)
	c.Assert(err, check.NotNil)

	for index := 0; index <= 10; index++ {
		machine := types.Machine{
			ID:             uint64(index),
			MachineKey:     "foo" + strconv.Itoa(index),
			NodeKey:        "bar" + strconv.Itoa(index),
			DiscoKey:       "faa" + strconv.Itoa(index),
			Hostname:       "testmachine" + strconv.Itoa(index),
			UserID:         user.ID,
			RegisterMethod: util.RegisterMethodAuthKey,
			AuthKeyID:      uint(pak.ID),
		}
		db.db.Save(&machine)
	}

	machine0ByID, err := db.GetMachineByID(0)
	c.Assert(err, check.IsNil)

	peersOfMachine0, err := db.ListPeers(machine0ByID)
	c.Assert(err, check.IsNil)

	c.Assert(len(peersOfMachine0), check.Equals, 9)
	c.Assert(peersOfMachine0[0].Hostname, check.Equals, "testmachine2")
	c.Assert(peersOfMachine0[5].Hostname, check.Equals, "testmachine7")
	c.Assert(peersOfMachine0[8].Hostname, check.Equals, "testmachine10")

	c.Assert(channelUpdates, check.Equals, int32(0))
}

func (s *Suite) TestGetACLFilteredPeers(c *check.C) {
	type base struct {
		user *types.User
		key  *types.PreAuthKey
	}

	stor := make([]base, 0)

	for _, name := range []string{"test", "admin"} {
		user, err := db.CreateUser(name)
		c.Assert(err, check.IsNil)
		pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
		c.Assert(err, check.IsNil)
		stor = append(stor, base{user, pak})
	}

	_, err := db.GetMachineByID(0)
	c.Assert(err, check.NotNil)

	for index := 0; index <= 10; index++ {
		machine := types.Machine{
			ID:         uint64(index),
			MachineKey: "foo" + strconv.Itoa(index),
			NodeKey:    "bar" + strconv.Itoa(index),
			DiscoKey:   "faa" + strconv.Itoa(index),
			IPAddresses: types.MachineAddresses{
				netip.MustParseAddr(fmt.Sprintf("100.64.0.%v", strconv.Itoa(index+1))),
			},
			Hostname:       "testmachine" + strconv.Itoa(index),
			UserID:         stor[index%2].user.ID,
			RegisterMethod: util.RegisterMethodAuthKey,
			AuthKeyID:      uint(stor[index%2].key.ID),
		}
		db.db.Save(&machine)
	}

	aclPolicy := &policy.ACLPolicy{
		Groups: map[string][]string{
			"group:test": {"admin"},
		},
		Hosts:     map[string]netip.Prefix{},
		TagOwners: map[string][]string{},
		ACLs: []policy.ACL{
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
		Tests: []policy.ACLTest{},
	}

	adminMachine, err := db.GetMachineByID(1)
	c.Logf("Machine(%v), user: %v", adminMachine.Hostname, adminMachine.User)
	c.Assert(err, check.IsNil)

	testMachine, err := db.GetMachineByID(2)
	c.Logf("Machine(%v), user: %v", testMachine.Hostname, testMachine.User)
	c.Assert(err, check.IsNil)

	adminPeers, err := db.ListPeers(adminMachine)
	c.Assert(err, check.IsNil)

	testPeers, err := db.ListPeers(testMachine)
	c.Assert(err, check.IsNil)

	adminRules, _, err := policy.GenerateFilterRules(aclPolicy, adminMachine, adminPeers, false)
	c.Assert(err, check.IsNil)

	testRules, _, err := policy.GenerateFilterRules(aclPolicy, testMachine, testPeers, false)
	c.Assert(err, check.IsNil)

	peersOfAdminMachine := policy.FilterMachinesByACL(adminMachine, adminPeers, adminRules)
	peersOfTestMachine := policy.FilterMachinesByACL(testMachine, testPeers, testRules)

	c.Log(peersOfTestMachine)
	c.Assert(len(peersOfTestMachine), check.Equals, 9)
	c.Assert(peersOfTestMachine[0].Hostname, check.Equals, "testmachine1")
	c.Assert(peersOfTestMachine[1].Hostname, check.Equals, "testmachine3")
	c.Assert(peersOfTestMachine[3].Hostname, check.Equals, "testmachine5")

	c.Log(peersOfAdminMachine)
	c.Assert(len(peersOfAdminMachine), check.Equals, 9)
	c.Assert(peersOfAdminMachine[0].Hostname, check.Equals, "testmachine2")
	c.Assert(peersOfAdminMachine[2].Hostname, check.Equals, "testmachine4")
	c.Assert(peersOfAdminMachine[5].Hostname, check.Equals, "testmachine7")

	c.Assert(channelUpdates, check.Equals, int32(0))
}

func (s *Suite) TestExpireMachine(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetMachine("test", "testmachine")
	c.Assert(err, check.NotNil)

	machine := &types.Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		Expiry:         &time.Time{},
	}
	db.db.Save(machine)

	machineFromDB, err := db.GetMachine("test", "testmachine")
	c.Assert(err, check.IsNil)
	c.Assert(machineFromDB, check.NotNil)

	c.Assert(machineFromDB.IsExpired(), check.Equals, false)

	err = db.ExpireMachine(machineFromDB)
	c.Assert(err, check.IsNil)

	c.Assert(machineFromDB.IsExpired(), check.Equals, true)

	c.Assert(channelUpdates, check.Equals, int32(1))
}

func (s *Suite) TestSerdeAddressStrignSlice(c *check.C) {
	input := types.MachineAddresses([]netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	})
	serialized, err := input.Value()
	c.Assert(err, check.IsNil)
	if serial, ok := serialized.(string); ok {
		c.Assert(serial, check.Equals, "192.0.2.1,2001:db8::1")
	}

	var deserialized types.MachineAddresses
	err = deserialized.Scan(serialized)
	c.Assert(err, check.IsNil)

	c.Assert(len(deserialized), check.Equals, len(input))
	for i := range deserialized {
		c.Assert(deserialized[i], check.Equals, input[i])
	}

	c.Assert(channelUpdates, check.Equals, int32(0))
}

func (s *Suite) TestGenerateGivenName(c *check.C) {
	user1, err := db.CreateUser("user-1")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user1.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetMachine("user-1", "testmachine")
	c.Assert(err, check.NotNil)

	machine := &types.Machine{
		ID:             0,
		MachineKey:     "machine-key-1",
		NodeKey:        "node-key-1",
		DiscoKey:       "disco-key-1",
		Hostname:       "hostname-1",
		GivenName:      "hostname-1",
		UserID:         user1.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	db.db.Save(machine)

	givenName, err := db.GenerateGivenName("machine-key-2", "hostname-2")
	comment := check.Commentf("Same user, unique machines, unique hostnames, no conflict")
	c.Assert(err, check.IsNil, comment)
	c.Assert(givenName, check.Equals, "hostname-2", comment)

	givenName, err = db.GenerateGivenName("machine-key-1", "hostname-1")
	comment = check.Commentf("Same user, same machine, same hostname, no conflict")
	c.Assert(err, check.IsNil, comment)
	c.Assert(givenName, check.Equals, "hostname-1", comment)

	givenName, err = db.GenerateGivenName("machine-key-2", "hostname-1")
	comment = check.Commentf("Same user, unique machines, same hostname, conflict")
	c.Assert(err, check.IsNil, comment)
	c.Assert(givenName, check.Matches, fmt.Sprintf("^hostname-1-[a-z0-9]{%d}$", MachineGivenNameHashLength), comment)

	givenName, err = db.GenerateGivenName("machine-key-2", "hostname-1")
	comment = check.Commentf("Unique users, unique machines, same hostname, conflict")
	c.Assert(err, check.IsNil, comment)
	c.Assert(givenName, check.Matches, fmt.Sprintf("^hostname-1-[a-z0-9]{%d}$", MachineGivenNameHashLength), comment)

	c.Assert(channelUpdates, check.Equals, int32(0))
}

func (s *Suite) TestSetTags(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetMachine("test", "testmachine")
	c.Assert(err, check.NotNil)

	machine := &types.Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	db.db.Save(machine)

	// assign simple tags
	sTags := []string{"tag:test", "tag:foo"}
	err = db.SetTags(machine, sTags)
	c.Assert(err, check.IsNil)
	machine, err = db.GetMachine("test", "testmachine")
	c.Assert(err, check.IsNil)
	c.Assert(machine.ForcedTags, check.DeepEquals, types.StringList(sTags))

	// assign duplicat tags, expect no errors but no doubles in DB
	eTags := []string{"tag:bar", "tag:test", "tag:unknown", "tag:test"}
	err = db.SetTags(machine, eTags)
	c.Assert(err, check.IsNil)
	machine, err = db.GetMachine("test", "testmachine")
	c.Assert(err, check.IsNil)
	c.Assert(
		machine.ForcedTags,
		check.DeepEquals,
		types.StringList([]string{"tag:bar", "tag:test", "tag:unknown"}),
	)

	c.Assert(channelUpdates, check.Equals, int32(2))
}

func TestHeadscale_generateGivenName(t *testing.T) {
	type args struct {
		suppliedName string
		randomSuffix bool
	}
	tests := []struct {
		name    string
		db      *HSDatabase
		args    args
		want    *regexp.Regexp
		wantErr bool
	}{
		{
			name: "simple machine name generation",
			db: &HSDatabase{
				stripEmailDomain: true,
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
			db: &HSDatabase{
				stripEmailDomain: true,
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
			db: &HSDatabase{
				stripEmailDomain: true,
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
			db: &HSDatabase{
				stripEmailDomain: true,
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
			db: &HSDatabase{
				stripEmailDomain: true,
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
			db: &HSDatabase{
				stripEmailDomain: true,
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
			db: &HSDatabase{
				stripEmailDomain: true,
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
			got, err := tt.db.generateGivenName(tt.args.suppliedName, tt.args.randomSuffix)
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

			if len(got) > util.LabelHostnameLength {
				t.Errorf(
					"Headscale.GenerateGivenName() = %v is larger than allowed DNS segment %d",
					got,
					util.LabelHostnameLength,
				)
			}
		})
	}
}

func (s *Suite) TestAutoApproveRoutes(c *check.C) {
	acl := []byte(`
{
	"tagOwners": {
		"tag:exit": ["test"],
	},

	"groups": {
		"group:test": ["test"]
	},

	"acls": [
		{"action": "accept", "users": ["*"], "ports": ["*:*"]},
	],

	"autoApprovers": {
		"exitNode": ["tag:exit"],
		"routes": {
			"10.10.0.0/16": ["group:test"],
			"10.11.0.0/16": ["test"],
		}
	}
}
	`)

	pol, err := policy.LoadACLPolicyFromBytes(acl, "hujson")
	c.Assert(err, check.IsNil)
	c.Assert(pol, check.NotNil)

	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	nodeKey := key.NewNode()

	defaultRouteV4 := netip.MustParsePrefix("0.0.0.0/0")
	defaultRouteV6 := netip.MustParsePrefix("::/0")
	route1 := netip.MustParsePrefix("10.10.0.0/16")
	// Check if a subprefix of an autoapproved route is approved
	route2 := netip.MustParsePrefix("10.11.0.0/24")

	machine := types.Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        util.NodePublicKeyStripPrefix(nodeKey.Public()),
		DiscoKey:       "faa",
		Hostname:       "test",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		HostInfo: types.HostInfo{
			RequestTags: []string{"tag:exit"},
			RoutableIPs: []netip.Prefix{defaultRouteV4, defaultRouteV6, route1, route2},
		},
		IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
	}

	db.db.Save(&machine)

	err = db.ProcessMachineRoutes(&machine)
	c.Assert(err, check.IsNil)

	machine0ByID, err := db.GetMachineByID(0)
	c.Assert(err, check.IsNil)

	err = db.EnableAutoApprovedRoutes(pol, machine0ByID)
	c.Assert(err, check.IsNil)

	enabledRoutes, err := db.GetEnabledRoutes(machine0ByID)
	c.Assert(err, check.IsNil)
	c.Assert(enabledRoutes, check.HasLen, 4)

	c.Assert(channelUpdates, check.Equals, int32(4))
}

func TestMachine_canAccess(t *testing.T) {
	type args struct {
		filter   []tailcfg.FilterRule
		machine2 *types.Machine
	}
	tests := []struct {
		name    string
		machine types.Machine
		args    args
		want    bool
	}{
		{
			name: "no-rules",
			machine: types.Machine{
				IPAddresses: types.MachineAddresses{
					netip.MustParseAddr("10.0.0.1"),
				},
			},
			args: args{
				filter: []tailcfg.FilterRule{},
				machine2: &types.Machine{
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("10.0.0.2"),
					},
				},
			},
			want: false,
		},
		{
			name: "wildcard",
			machine: types.Machine{
				IPAddresses: types.MachineAddresses{
					netip.MustParseAddr("10.0.0.1"),
				},
			},
			args: args{
				filter: []tailcfg.FilterRule{
					{
						SrcIPs: []string{"*"},
						DstPorts: []tailcfg.NetPortRange{
							{
								IP: "*",
								Ports: tailcfg.PortRange{
									First: 0,
									Last:  65535,
								},
							},
						},
					},
				},
				machine2: &types.Machine{
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("10.0.0.2"),
					},
				},
			},
			want: true,
		},
		{
			name: "explicit-m1-to-m2",
			machine: types.Machine{
				IPAddresses: types.MachineAddresses{
					netip.MustParseAddr("10.0.0.1"),
				},
			},
			args: args{
				filter: []tailcfg.FilterRule{
					{
						SrcIPs: []string{"10.0.0.1"},
						DstPorts: []tailcfg.NetPortRange{
							{
								IP: "10.0.0.2",
								Ports: tailcfg.PortRange{
									First: 0,
									Last:  65535,
								},
							},
						},
					},
				},
				machine2: &types.Machine{
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("10.0.0.2"),
					},
				},
			},
			want: true,
		},
		{
			name: "explicit-m2-to-m1",
			machine: types.Machine{
				IPAddresses: types.MachineAddresses{
					netip.MustParseAddr("10.0.0.1"),
				},
			},
			args: args{
				filter: []tailcfg.FilterRule{
					{
						SrcIPs: []string{"10.0.0.2"},
						DstPorts: []tailcfg.NetPortRange{
							{
								IP: "10.0.0.1",
								Ports: tailcfg.PortRange{
									First: 0,
									Last:  65535,
								},
							},
						},
					},
				},
				machine2: &types.Machine{
					IPAddresses: types.MachineAddresses{
						netip.MustParseAddr("10.0.0.2"),
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.machine.CanAccess(tt.args.filter, tt.args.machine2); got != tt.want {
				t.Errorf("Machine.CanAccess() = %v, want %v", got, tt.want)
			}
		})
	}
}
