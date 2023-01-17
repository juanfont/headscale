package headscale

import (
	"net/netip"
	"testing"

	"gopkg.in/check.v1"
	"gorm.io/gorm"
)

func (s *Suite) TestCreateAndDestroyUser(c *check.C) {
	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)
	c.Assert(user.Name, check.Equals, "test")

	users, err := app.ListUsers()
	c.Assert(err, check.IsNil)
	c.Assert(len(users), check.Equals, 1)

	err = app.DestroyUser("test")
	c.Assert(err, check.IsNil)

	_, err = app.GetUser("test")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestDestroyUserErrors(c *check.C) {
	err := app.DestroyUser("test")
	c.Assert(err, check.Equals, ErrUserNotFound)

	user, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	err = app.DestroyUser("test")
	c.Assert(err, check.IsNil)

	result := app.db.Preload("User").First(&pak, "key = ?", pak.Key)
	// destroying a user also deletes all associated preauthkeys
	c.Assert(result.Error, check.Equals, gorm.ErrRecordNotFound)

	user, err = app.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err = app.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

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

	err = app.DestroyUser("test")
	c.Assert(err, check.Equals, ErrUserStillHasNodes)
}

func (s *Suite) TestRenameUser(c *check.C) {
	userTest, err := app.CreateUser("test")
	c.Assert(err, check.IsNil)
	c.Assert(userTest.Name, check.Equals, "test")

	users, err := app.ListUsers()
	c.Assert(err, check.IsNil)
	c.Assert(len(users), check.Equals, 1)

	err = app.RenameUser("test", "test-renamed")
	c.Assert(err, check.IsNil)

	_, err = app.GetUser("test")
	c.Assert(err, check.Equals, ErrUserNotFound)

	_, err = app.GetUser("test-renamed")
	c.Assert(err, check.IsNil)

	err = app.RenameUser("test-does-not-exit", "test")
	c.Assert(err, check.Equals, ErrUserNotFound)

	userTest2, err := app.CreateUser("test2")
	c.Assert(err, check.IsNil)
	c.Assert(userTest2.Name, check.Equals, "test2")

	err = app.RenameUser("test2", "test-renamed")
	c.Assert(err, check.Equals, ErrUserExists)
}

func (s *Suite) TestGetMapResponseUserProfiles(c *check.C) {
	userShared1, err := app.CreateUser("shared1")
	c.Assert(err, check.IsNil)

	userShared2, err := app.CreateUser("shared2")
	c.Assert(err, check.IsNil)

	userShared3, err := app.CreateUser("shared3")
	c.Assert(err, check.IsNil)

	preAuthKeyShared1, err := app.CreatePreAuthKey(
		userShared1.Name,
		false,
		false,
		nil,
		nil,
	)
	c.Assert(err, check.IsNil)

	preAuthKeyShared2, err := app.CreatePreAuthKey(
		userShared2.Name,
		false,
		false,
		nil,
		nil,
	)
	c.Assert(err, check.IsNil)

	preAuthKeyShared3, err := app.CreatePreAuthKey(
		userShared3.Name,
		false,
		false,
		nil,
		nil,
	)
	c.Assert(err, check.IsNil)

	preAuthKey2Shared1, err := app.CreatePreAuthKey(
		userShared1.Name,
		false,
		false,
		nil,
		nil,
	)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine(userShared1.Name, "test_get_shared_nodes_1")
	c.Assert(err, check.NotNil)

	machineInShared1 := &Machine{
		ID:             1,
		MachineKey:     "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		NodeKey:        "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		DiscoKey:       "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		Hostname:       "test_get_shared_nodes_1",
		UserID:         userShared1.ID,
		User:           *userShared1,
		RegisterMethod: RegisterMethodAuthKey,
		IPAddresses:    []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		AuthKeyID:      uint(preAuthKeyShared1.ID),
	}
	app.db.Save(machineInShared1)

	_, err = app.GetMachine(userShared1.Name, machineInShared1.Hostname)
	c.Assert(err, check.IsNil)

	machineInShared2 := &Machine{
		ID:             2,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Hostname:       "test_get_shared_nodes_2",
		UserID:         userShared2.ID,
		User:           *userShared2,
		RegisterMethod: RegisterMethodAuthKey,
		IPAddresses:    []netip.Addr{netip.MustParseAddr("100.64.0.2")},
		AuthKeyID:      uint(preAuthKeyShared2.ID),
	}
	app.db.Save(machineInShared2)

	_, err = app.GetMachine(userShared2.Name, machineInShared2.Hostname)
	c.Assert(err, check.IsNil)

	machineInShared3 := &Machine{
		ID:             3,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Hostname:       "test_get_shared_nodes_3",
		UserID:         userShared3.ID,
		User:           *userShared3,
		RegisterMethod: RegisterMethodAuthKey,
		IPAddresses:    []netip.Addr{netip.MustParseAddr("100.64.0.3")},
		AuthKeyID:      uint(preAuthKeyShared3.ID),
	}
	app.db.Save(machineInShared3)

	_, err = app.GetMachine(userShared3.Name, machineInShared3.Hostname)
	c.Assert(err, check.IsNil)

	machine2InShared1 := &Machine{
		ID:             4,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Hostname:       "test_get_shared_nodes_4",
		UserID:         userShared1.ID,
		User:           *userShared1,
		RegisterMethod: RegisterMethodAuthKey,
		IPAddresses:    []netip.Addr{netip.MustParseAddr("100.64.0.4")},
		AuthKeyID:      uint(preAuthKey2Shared1.ID),
	}
	app.db.Save(machine2InShared1)

	peersOfMachine1InShared1, err := app.getPeers(machineInShared1)
	c.Assert(err, check.IsNil)

	userProfiles := app.getMapResponseUserProfiles(
		*machineInShared1,
		peersOfMachine1InShared1,
	)

	c.Assert(len(userProfiles), check.Equals, 3)

	found := false
	for _, userProfiles := range userProfiles {
		if userProfiles.DisplayName == userShared1.Name {
			found = true

			break
		}
	}
	c.Assert(found, check.Equals, true)

	found = false
	for _, userProfile := range userProfiles {
		if userProfile.DisplayName == userShared2.Name {
			found = true

			break
		}
	}
	c.Assert(found, check.Equals, true)
}

func TestNormalizeToFQDNRules(t *testing.T) {
	type args struct {
		name             string
		stripEmailDomain bool
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "normalize simple name",
			args: args{
				name:             "normalize-simple.name",
				stripEmailDomain: false,
			},
			want:    "normalize-simple.name",
			wantErr: false,
		},
		{
			name: "normalize an email",
			args: args{
				name:             "foo.bar@example.com",
				stripEmailDomain: false,
			},
			want:    "foo.bar.example.com",
			wantErr: false,
		},
		{
			name: "normalize an email domain should be removed",
			args: args{
				name:             "foo.bar@example.com",
				stripEmailDomain: true,
			},
			want:    "foo.bar",
			wantErr: false,
		},
		{
			name: "strip enabled no email passed as argument",
			args: args{
				name:             "not-email-and-strip-enabled",
				stripEmailDomain: true,
			},
			want:    "not-email-and-strip-enabled",
			wantErr: false,
		},
		{
			name: "normalize complex email",
			args: args{
				name:             "foo.bar+complex-email@example.com",
				stripEmailDomain: false,
			},
			want:    "foo.bar-complex-email.example.com",
			wantErr: false,
		},
		{
			name: "user name with space",
			args: args{
				name:             "name space",
				stripEmailDomain: false,
			},
			want:    "name-space",
			wantErr: false,
		},
		{
			name: "user with quote",
			args: args{
				name:             "Jamie's iPhone 5",
				stripEmailDomain: false,
			},
			want:    "jamies-iphone-5",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeToFQDNRules(tt.args.name, tt.args.stripEmailDomain)
			if (err != nil) != tt.wantErr {
				t.Errorf(
					"NormalizeToFQDNRules() error = %v, wantErr %v",
					err,
					tt.wantErr,
				)

				return
			}
			if got != tt.want {
				t.Errorf("NormalizeToFQDNRules() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckForFQDNRules(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "valid: user",
			args:    args{name: "valid-user"},
			wantErr: false,
		},
		{
			name:    "invalid: capitalized user",
			args:    args{name: "Invalid-CapItaLIzed-user"},
			wantErr: true,
		},
		{
			name:    "invalid: email as user",
			args:    args{name: "foo.bar@example.com"},
			wantErr: true,
		},
		{
			name:    "invalid: chars in user name",
			args:    args{name: "super-user+name"},
			wantErr: true,
		},
		{
			name: "invalid: too long name for user",
			args: args{
				name: "super-long-useruseruser-name-that-should-be-a-little-more-than-63-chars",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckForFQDNRules(tt.args.name); (err != nil) != tt.wantErr {
				t.Errorf("CheckForFQDNRules() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func (s *Suite) TestSetMachineUser(c *check.C) {
	oldUser, err := app.CreateUser("old")
	c.Assert(err, check.IsNil)

	newUser, err := app.CreateUser("new")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(oldUser.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		UserID:         oldUser.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)
	c.Assert(machine.UserID, check.Equals, oldUser.ID)

	err = app.SetMachineUser(&machine, newUser.Name)
	c.Assert(err, check.IsNil)
	c.Assert(machine.UserID, check.Equals, newUser.ID)
	c.Assert(machine.User.Name, check.Equals, newUser.Name)

	err = app.SetMachineUser(&machine, "non-existing-user")
	c.Assert(err, check.Equals, ErrUserNotFound)

	err = app.SetMachineUser(&machine, newUser.Name)
	c.Assert(err, check.IsNil)
	c.Assert(machine.UserID, check.Equals, newUser.ID)
	c.Assert(machine.User.Name, check.Equals, newUser.Name)
}
