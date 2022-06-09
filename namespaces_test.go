package headscale

import (
	"testing"

	"gopkg.in/check.v1"
	"gorm.io/gorm"
	"inet.af/netaddr"
)

func (s *Suite) TestCreateAndDestroyNamespace(c *check.C) {
	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)
	c.Assert(namespace.Name, check.Equals, "test")

	namespaces, err := app.ListNamespaces()
	c.Assert(err, check.IsNil)
	c.Assert(len(namespaces), check.Equals, 1)

	err = app.DestroyNamespace("test")
	c.Assert(err, check.IsNil)

	_, err = app.GetNamespace("test")
	c.Assert(err, check.NotNil)
}

func (s *Suite) TestDestroyNamespaceErrors(c *check.C) {
	err := app.DestroyNamespace("test")
	c.Assert(err, check.Equals, errNamespaceNotFound)

	namespace, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	err = app.DestroyNamespace("test")
	c.Assert(err, check.IsNil)

	result := app.db.Preload("Namespace").First(&pak, "key = ?", pak.Key)
	// destroying a namespace also deletes all associated preauthkeys
	c.Assert(result.Error, check.Equals, gorm.ErrRecordNotFound)

	namespace, err = app.CreateNamespace("test")
	c.Assert(err, check.IsNil)

	pak, err = app.CreatePreAuthKey(namespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		NamespaceID:    namespace.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)

	err = app.DestroyNamespace("test")
	c.Assert(err, check.Equals, errNamespaceNotEmptyOfNodes)
}

func (s *Suite) TestRenameNamespace(c *check.C) {
	namespaceTest, err := app.CreateNamespace("test")
	c.Assert(err, check.IsNil)
	c.Assert(namespaceTest.Name, check.Equals, "test")

	namespaces, err := app.ListNamespaces()
	c.Assert(err, check.IsNil)
	c.Assert(len(namespaces), check.Equals, 1)

	err = app.RenameNamespace("test", "test-renamed")
	c.Assert(err, check.IsNil)

	_, err = app.GetNamespace("test")
	c.Assert(err, check.Equals, errNamespaceNotFound)

	_, err = app.GetNamespace("test-renamed")
	c.Assert(err, check.IsNil)

	err = app.RenameNamespace("test-does-not-exit", "test")
	c.Assert(err, check.Equals, errNamespaceNotFound)

	namespaceTest2, err := app.CreateNamespace("test2")
	c.Assert(err, check.IsNil)
	c.Assert(namespaceTest2.Name, check.Equals, "test2")

	err = app.RenameNamespace("test2", "test-renamed")
	c.Assert(err, check.Equals, errNamespaceExists)
}

func (s *Suite) TestGetMapResponseUserProfiles(c *check.C) {
	namespaceShared1, err := app.CreateNamespace("shared1")
	c.Assert(err, check.IsNil)

	namespaceShared2, err := app.CreateNamespace("shared2")
	c.Assert(err, check.IsNil)

	namespaceShared3, err := app.CreateNamespace("shared3")
	c.Assert(err, check.IsNil)

	preAuthKeyShared1, err := app.CreatePreAuthKey(
		namespaceShared1.Name,
		false,
		false,
		nil,
	)
	c.Assert(err, check.IsNil)

	preAuthKeyShared2, err := app.CreatePreAuthKey(
		namespaceShared2.Name,
		false,
		false,
		nil,
	)
	c.Assert(err, check.IsNil)

	preAuthKeyShared3, err := app.CreatePreAuthKey(
		namespaceShared3.Name,
		false,
		false,
		nil,
	)
	c.Assert(err, check.IsNil)

	preAuthKey2Shared1, err := app.CreatePreAuthKey(
		namespaceShared1.Name,
		false,
		false,
		nil,
	)
	c.Assert(err, check.IsNil)

	_, err = app.GetMachine(namespaceShared1.Name, "test_get_shared_nodes_1")
	c.Assert(err, check.NotNil)

	machineInShared1 := &Machine{
		ID:             1,
		MachineKey:     "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		NodeKey:        "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		DiscoKey:       "686824e749f3b7f2a5927ee6c1e422aee5292592d9179a271ed7b3e659b44a66",
		Hostname:       "test_get_shared_nodes_1",
		NamespaceID:    namespaceShared1.ID,
		Namespace:      *namespaceShared1,
		RegisterMethod: RegisterMethodAuthKey,
		IPAddresses:    []netaddr.IP{netaddr.MustParseIP("100.64.0.1")},
		AuthKeyID:      uint(preAuthKeyShared1.ID),
	}
	app.db.Save(machineInShared1)

	_, err = app.GetMachine(namespaceShared1.Name, machineInShared1.Hostname)
	c.Assert(err, check.IsNil)

	machineInShared2 := &Machine{
		ID:             2,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Hostname:       "test_get_shared_nodes_2",
		NamespaceID:    namespaceShared2.ID,
		Namespace:      *namespaceShared2,
		RegisterMethod: RegisterMethodAuthKey,
		IPAddresses:    []netaddr.IP{netaddr.MustParseIP("100.64.0.2")},
		AuthKeyID:      uint(preAuthKeyShared2.ID),
	}
	app.db.Save(machineInShared2)

	_, err = app.GetMachine(namespaceShared2.Name, machineInShared2.Hostname)
	c.Assert(err, check.IsNil)

	machineInShared3 := &Machine{
		ID:             3,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Hostname:       "test_get_shared_nodes_3",
		NamespaceID:    namespaceShared3.ID,
		Namespace:      *namespaceShared3,
		RegisterMethod: RegisterMethodAuthKey,
		IPAddresses:    []netaddr.IP{netaddr.MustParseIP("100.64.0.3")},
		AuthKeyID:      uint(preAuthKeyShared3.ID),
	}
	app.db.Save(machineInShared3)

	_, err = app.GetMachine(namespaceShared3.Name, machineInShared3.Hostname)
	c.Assert(err, check.IsNil)

	machine2InShared1 := &Machine{
		ID:             4,
		MachineKey:     "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		NodeKey:        "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		DiscoKey:       "dec46ef9dc45c7d2f03bfcd5a640d9e24e3cc68ce3d9da223867c9bc6d5e9863",
		Hostname:       "test_get_shared_nodes_4",
		NamespaceID:    namespaceShared1.ID,
		Namespace:      *namespaceShared1,
		RegisterMethod: RegisterMethodAuthKey,
		IPAddresses:    []netaddr.IP{netaddr.MustParseIP("100.64.0.4")},
		AuthKeyID:      uint(preAuthKey2Shared1.ID),
	}
	app.db.Save(machine2InShared1)

	peersOfMachine1InShared1, err := app.getPeers(machineInShared1)
	c.Assert(err, check.IsNil)

	userProfiles := getMapResponseUserProfiles(
		*machineInShared1,
		peersOfMachine1InShared1,
	)

	c.Assert(len(userProfiles), check.Equals, 3)

	found := false
	for _, userProfiles := range userProfiles {
		if userProfiles.DisplayName == namespaceShared1.Name {
			found = true

			break
		}
	}
	c.Assert(found, check.Equals, true)

	found = false
	for _, userProfile := range userProfiles {
		if userProfile.DisplayName == namespaceShared2.Name {
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
			name: "namespace name with space",
			args: args{
				name:             "name space",
				stripEmailDomain: false,
			},
			want:    "name-space",
			wantErr: false,
		},
		{
			name: "namespace with quote",
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
			name:    "valid: namespace",
			args:    args{name: "valid-namespace"},
			wantErr: false,
		},
		{
			name:    "invalid: capitalized namespace",
			args:    args{name: "Invalid-CapItaLIzed-namespace"},
			wantErr: true,
		},
		{
			name:    "invalid: email as namespace",
			args:    args{name: "foo.bar@example.com"},
			wantErr: true,
		},
		{
			name:    "invalid: chars in namespace name",
			args:    args{name: "super-namespace+name"},
			wantErr: true,
		},
		{
			name: "invalid: too long name for namespace",
			args: args{
				name: "super-long-namespace-name-that-should-be-a-little-more-than-63-chars",
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

func (s *Suite) TestSetMachineNamespace(c *check.C) {
	oldNamespace, err := app.CreateNamespace("old")
	c.Assert(err, check.IsNil)

	newNamespace, err := app.CreateNamespace("new")
	c.Assert(err, check.IsNil)

	pak, err := app.CreatePreAuthKey(oldNamespace.Name, false, false, nil)
	c.Assert(err, check.IsNil)

	machine := Machine{
		ID:             0,
		MachineKey:     "foo",
		NodeKey:        "bar",
		DiscoKey:       "faa",
		Hostname:       "testmachine",
		NamespaceID:    oldNamespace.ID,
		RegisterMethod: RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
	}
	app.db.Save(&machine)
	c.Assert(machine.NamespaceID, check.Equals, oldNamespace.ID)

	err = app.SetMachineNamespace(&machine, newNamespace.Name)
	c.Assert(err, check.IsNil)
	c.Assert(machine.NamespaceID, check.Equals, newNamespace.ID)
	c.Assert(machine.Namespace.Name, check.Equals, newNamespace.Name)

	err = app.SetMachineNamespace(&machine, "non-existing-namespace")
	c.Assert(err, check.Equals, errNamespaceNotFound)

	err = app.SetMachineNamespace(&machine, newNamespace.Name)
	c.Assert(err, check.IsNil)
	c.Assert(machine.NamespaceID, check.Equals, newNamespace.ID)
	c.Assert(machine.Namespace.Name, check.Equals, newNamespace.Name)
}
