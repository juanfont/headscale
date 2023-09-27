package mapper

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"gopkg.in/check.v1"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
)

func (s *Suite) TestGetMapResponseUserProfiles(c *check.C) {
	mach := func(hostname, username string, userid uint) *types.Node {
		return &types.Node{
			Hostname: hostname,
			UserID:   userid,
			User: types.User{
				Name: username,
			},
		}
	}

	nodeInShared1 := mach("test_get_shared_nodes_1", "user1", 1)
	nodeInShared2 := mach("test_get_shared_nodes_2", "user2", 2)
	nodeInShared3 := mach("test_get_shared_nodes_3", "user3", 3)
	node2InShared1 := mach("test_get_shared_nodes_4", "user1", 1)

	userProfiles := generateUserProfiles(
		nodeInShared1,
		types.Nodes{
			nodeInShared2, nodeInShared3, node2InShared1,
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
			mach := func(hostname, username string, userid uint) *types.Node {
				return &types.Node{
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

			nodeInShared1 := mach("test_get_shared_nodes_1", "shared1", 1)
			nodeInShared2 := mach("test_get_shared_nodes_2", "shared2", 2)
			nodeInShared3 := mach("test_get_shared_nodes_3", "shared3", 3)
			node2InShared1 := mach("test_get_shared_nodes_4", "shared1", 1)

			peersOfNodeInShared1 := types.Nodes{
				nodeInShared1,
				nodeInShared2,
				nodeInShared3,
				node2InShared1,
			}

			got := generateDNSConfig(
				&dnsConfigOrig,
				baseDomain,
				nodeInShared1,
				peersOfNodeInShared1,
			)

			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("expandAlias() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_fullMapResponse(t *testing.T) {
	mustNK := func(str string) key.NodePublic {
		var k key.NodePublic
		_ = k.UnmarshalText([]byte(str))

		return k
	}

	mustDK := func(str string) key.DiscoPublic {
		var k key.DiscoPublic
		_ = k.UnmarshalText([]byte(str))

		return k
	}

	mustMK := func(str string) key.MachinePublic {
		var k key.MachinePublic
		_ = k.UnmarshalText([]byte(str))

		return k
	}

	hiview := func(hoin tailcfg.Hostinfo) tailcfg.HostinfoView {
		return hoin.View()
	}

	created := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	lastSeen := time.Date(2009, time.November, 10, 23, 9, 0, 0, time.UTC)
	expire := time.Date(2500, time.November, 11, 23, 0, 0, 0, time.UTC)

	mini := &types.Node{
		ID:          0,
		MachineKey:  "mkey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		NodeKey:     "nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		DiscoKey:    "discokey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
		IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		Hostname:    "mini",
		GivenName:   "mini",
		UserID:      0,
		User:        types.User{Name: "mini"},
		ForcedTags:  []string{},
		AuthKeyID:   0,
		AuthKey:     &types.PreAuthKey{},
		LastSeen:    &lastSeen,
		Expiry:      &expire,
		HostInfo:    types.HostInfo{},
		Endpoints:   []string{},
		Routes: []types.Route{
			{
				Prefix:     types.IPPrefix(netip.MustParsePrefix("0.0.0.0/0")),
				Advertised: true,
				Enabled:    true,
				IsPrimary:  false,
			},
			{
				Prefix:     types.IPPrefix(netip.MustParsePrefix("192.168.0.0/24")),
				Advertised: true,
				Enabled:    true,
				IsPrimary:  true,
			},
			{
				Prefix:     types.IPPrefix(netip.MustParsePrefix("172.0.0.0/10")),
				Advertised: true,
				Enabled:    false,
				IsPrimary:  true,
			},
		},
		CreatedAt: created,
	}

	tailMini := &tailcfg.Node{
		ID:       0,
		StableID: "0",
		Name:     "mini",
		User:     0,
		Key: mustNK(
			"nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		),
		KeyExpiry: expire,
		Machine: mustMK(
			"mkey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		),
		DiscoKey: mustDK(
			"discokey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
		),
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("100.64.0.1/32"),
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("192.168.0.0/24"),
		},
		Endpoints:         []string{},
		DERP:              "127.3.3.40:0",
		Hostinfo:          hiview(tailcfg.Hostinfo{}),
		Created:           created,
		Tags:              []string{},
		PrimaryRoutes:     []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")},
		LastSeen:          &lastSeen,
		Online:            new(bool),
		MachineAuthorized: true,
		Capabilities: []tailcfg.NodeCapability{
			tailcfg.CapabilityFileSharing,
			tailcfg.CapabilityAdmin,
			tailcfg.CapabilitySSH,
			tailcfg.NodeAttrDisableUPnP,
		},
	}

	peer1 := &types.Node{
		ID:          1,
		MachineKey:  "mkey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		NodeKey:     "nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		DiscoKey:    "discokey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
		IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
		Hostname:    "peer1",
		GivenName:   "peer1",
		UserID:      0,
		User:        types.User{Name: "mini"},
		ForcedTags:  []string{},
		LastSeen:    &lastSeen,
		Expiry:      &expire,
		HostInfo:    types.HostInfo{},
		Endpoints:   []string{},
		Routes:      []types.Route{},
		CreatedAt:   created,
	}

	tailPeer1 := &tailcfg.Node{
		ID:       1,
		StableID: "1",
		Name:     "peer1",
		Key: mustNK(
			"nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		),
		KeyExpiry: expire,
		Machine: mustMK(
			"mkey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		),
		DiscoKey: mustDK(
			"discokey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
		),
		Addresses:         []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		AllowedIPs:        []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		Endpoints:         []string{},
		DERP:              "127.3.3.40:0",
		Hostinfo:          hiview(tailcfg.Hostinfo{}),
		Created:           created,
		Tags:              []string{},
		PrimaryRoutes:     []netip.Prefix{},
		LastSeen:          &lastSeen,
		Online:            new(bool),
		MachineAuthorized: true,
		Capabilities: []tailcfg.NodeCapability{
			tailcfg.CapabilityFileSharing,
			tailcfg.CapabilityAdmin,
			tailcfg.CapabilitySSH,
			tailcfg.NodeAttrDisableUPnP,
		},
	}

	peer2 := &types.Node{
		ID:          2,
		MachineKey:  "mkey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		NodeKey:     "nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		DiscoKey:    "discokey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
		IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
		Hostname:    "peer2",
		GivenName:   "peer2",
		UserID:      1,
		User:        types.User{Name: "peer2"},
		ForcedTags:  []string{},
		LastSeen:    &lastSeen,
		Expiry:      &expire,
		HostInfo:    types.HostInfo{},
		Endpoints:   []string{},
		Routes:      []types.Route{},
		CreatedAt:   created,
	}

	tests := []struct {
		name  string
		pol   *policy.ACLPolicy
		node  *types.Node
		peers types.Nodes

		baseDomain       string
		dnsConfig        *tailcfg.DNSConfig
		derpMap          *tailcfg.DERPMap
		logtail          bool
		randomClientPort bool
		want             *tailcfg.MapResponse
		wantErr          bool
	}{
		// {
		// 	name:             "empty-node",
		// 	node:          types.Node{},
		// 	pol:              &policy.ACLPolicy{},
		// 	dnsConfig:        &tailcfg.DNSConfig{},
		// 	baseDomain:       "",
		// 	want:             nil,
		// 	wantErr:          true,
		// },
		{
			name:             "no-pol-no-peers-map-response",
			pol:              &policy.ACLPolicy{},
			node:             mini,
			peers:            types.Nodes{},
			baseDomain:       "",
			dnsConfig:        &tailcfg.DNSConfig{},
			derpMap:          &tailcfg.DERPMap{},
			logtail:          false,
			randomClientPort: false,
			want: &tailcfg.MapResponse{
				Node:            tailMini,
				KeepAlive:       false,
				DERPMap:         &tailcfg.DERPMap{},
				Peers:           []*tailcfg.Node{},
				DNSConfig:       &tailcfg.DNSConfig{},
				Domain:          "",
				CollectServices: "false",
				PacketFilter:    []tailcfg.FilterRule{},
				UserProfiles:    []tailcfg.UserProfile{{LoginName: "mini", DisplayName: "mini"}},
				SSHPolicy:       &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{}},
				ControlTime:     &time.Time{},
				Debug: &tailcfg.Debug{
					DisableLogTail: true,
				},
			},
			wantErr: false,
		},
		{
			name: "no-pol-with-peer-map-response",
			pol:  &policy.ACLPolicy{},
			node: mini,
			peers: types.Nodes{
				peer1,
			},
			baseDomain:       "",
			dnsConfig:        &tailcfg.DNSConfig{},
			derpMap:          &tailcfg.DERPMap{},
			logtail:          false,
			randomClientPort: false,
			want: &tailcfg.MapResponse{
				KeepAlive: false,
				Node:      tailMini,
				DERPMap:   &tailcfg.DERPMap{},
				Peers: []*tailcfg.Node{
					tailPeer1,
				},
				DNSConfig:       &tailcfg.DNSConfig{},
				Domain:          "",
				CollectServices: "false",
				OnlineChange:    map[tailcfg.NodeID]bool{tailPeer1.ID: false},
				PacketFilter:    []tailcfg.FilterRule{},
				UserProfiles:    []tailcfg.UserProfile{{LoginName: "mini", DisplayName: "mini"}},
				SSHPolicy:       &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{}},
				ControlTime:     &time.Time{},
				Debug: &tailcfg.Debug{
					DisableLogTail: true,
				},
			},
			wantErr: false,
		},
		{
			name: "with-pol-map-response",
			pol: &policy.ACLPolicy{
				ACLs: []policy.ACL{
					{
						Action:       "accept",
						Sources:      []string{"100.64.0.2"},
						Destinations: []string{"mini:*"},
					},
				},
			},
			node: mini,
			peers: types.Nodes{
				peer1,
				peer2,
			},
			baseDomain:       "",
			dnsConfig:        &tailcfg.DNSConfig{},
			derpMap:          &tailcfg.DERPMap{},
			logtail:          false,
			randomClientPort: false,
			want: &tailcfg.MapResponse{
				KeepAlive: false,
				Node:      tailMini,
				DERPMap:   &tailcfg.DERPMap{},
				Peers: []*tailcfg.Node{
					tailPeer1,
				},
				DNSConfig:       &tailcfg.DNSConfig{},
				Domain:          "",
				CollectServices: "false",
				OnlineChange: map[tailcfg.NodeID]bool{
					tailPeer1.ID:             false,
					tailcfg.NodeID(peer2.ID): false,
				},
				PacketFilter: []tailcfg.FilterRule{
					{
						SrcIPs: []string{"100.64.0.2/32"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.1/32", Ports: tailcfg.PortRangeAny},
						},
					},
				},
				UserProfiles: []tailcfg.UserProfile{
					{LoginName: "mini", DisplayName: "mini"},
				},
				SSHPolicy:   &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{}},
				ControlTime: &time.Time{},
				Debug: &tailcfg.Debug{
					DisableLogTail: true,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mappy := NewMapper(
				tt.node,
				tt.peers,
				nil,
				false,
				0,
				tt.derpMap,
				tt.baseDomain,
				tt.dnsConfig,
				tt.logtail,
				tt.randomClientPort,
			)

			got, err := mappy.fullMapResponse(
				tt.node,
				tt.pol,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("fullMapResponse() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			spew.Dump(got)

			if diff := cmp.Diff(
				tt.want,
				got,
				cmpopts.EquateEmpty(),
				// Ignore ControlTime, it is set to now and we dont really need to mock it.
				cmpopts.IgnoreFields(tailcfg.MapResponse{}, "ControlTime"),
			); diff != "" {
				t.Errorf("fullMapResponse() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}
