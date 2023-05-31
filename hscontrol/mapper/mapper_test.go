package mapper

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"gopkg.in/check.v1"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

func (s *Suite) TestGetMapResponseUserProfiles(c *check.C) {
	mach := func(hostname, username string, userid uint) types.Machine {
		return types.Machine{
			Hostname: hostname,
			UserID:   userid,
			User: types.User{
				Name: username,
			},
		}
	}

	machineInShared1 := mach("test_get_shared_nodes_1", "user1", 1)
	machineInShared2 := mach("test_get_shared_nodes_2", "user2", 2)
	machineInShared3 := mach("test_get_shared_nodes_3", "user3", 3)
	machine2InShared1 := mach("test_get_shared_nodes_4", "user1", 1)

	userProfiles := generateUserProfiles(
		&machineInShared1,
		types.Machines{
			machineInShared2, machineInShared3, machine2InShared1,
		},
		"",
	)

	c.Assert(len(userProfiles), check.Equals, 3)

	users := []string{
		"user1", "user2", "user3",
	}

	for _, user := range users {
		found := false
		for _, userProfile := range userProfiles {
			if userProfile.DisplayName == user {
				found = true

				break
			}
		}
		c.Assert(found, check.Equals, true)
	}
}

func TestDNSConfigMapResponse(t *testing.T) {
	tests := []struct {
		magicDNS bool
		want     *tailcfg.DNSConfig
	}{
		{
			magicDNS: true,
			want: &tailcfg.DNSConfig{
				Routes: map[string][]*dnstype.Resolver{
					"shared1.foobar.headscale.net": {},
					"shared2.foobar.headscale.net": {},
					"shared3.foobar.headscale.net": {},
				},
				Domains: []string{
					"foobar.headscale.net",
					"shared1.foobar.headscale.net",
				},
				Proxied: true,
			},
		},
		{
			magicDNS: false,
			want: &tailcfg.DNSConfig{
				Domains: []string{"foobar.headscale.net"},
				Proxied: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("with-magicdns-%v", tt.magicDNS), func(t *testing.T) {
			mach := func(hostname, username string, userid uint) types.Machine {
				return types.Machine{
					Hostname: hostname,
					UserID:   userid,
					User: types.User{
						Name: username,
					},
				}
			}

			baseDomain := "foobar.headscale.net"

			dnsConfigOrig := tailcfg.DNSConfig{
				Routes:  make(map[string][]*dnstype.Resolver),
				Domains: []string{baseDomain},
				Proxied: tt.magicDNS,
			}

			machineInShared1 := mach("test_get_shared_nodes_1", "shared1", 1)
			machineInShared2 := mach("test_get_shared_nodes_2", "shared2", 2)
			machineInShared3 := mach("test_get_shared_nodes_3", "shared3", 3)
			machine2InShared1 := mach("test_get_shared_nodes_4", "shared1", 1)

			peersOfMachineInShared1 := types.Machines{
				machineInShared1,
				machineInShared2,
				machineInShared3,
				machine2InShared1,
			}

			got := generateDNSConfig(
				&dnsConfigOrig,
				baseDomain,
				machineInShared1,
				peersOfMachineInShared1,
			)

			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("expandAlias() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}
