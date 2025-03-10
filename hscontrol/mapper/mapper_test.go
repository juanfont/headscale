package mapper

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/routes"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
)

var iap = func(ipStr string) *netip.Addr {
	ip := netip.MustParseAddr(ipStr)
	return &ip
}

func TestDNSConfigMapResponse(t *testing.T) {
	tests := []struct {
		magicDNS bool
		want     *tailcfg.DNSConfig
	}{
		{
			magicDNS: true,
			want: &tailcfg.DNSConfig{
				Routes: map[string][]*dnstype.Resolver{},
				Domains: []string{
					"foobar.headscale.net",
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

			got := generateDNSConfig(
				&types.Config{
					TailcfgDNSConfig: &dnsConfigOrig,
				},
				nodeInShared1,
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

	user1 := types.User{Model: gorm.Model{ID: 1}, Name: "user1"}
	user2 := types.User{Model: gorm.Model{ID: 2}, Name: "user2"}

	mini := &types.Node{
		ID: 1,
		MachineKey: mustMK(
			"mkey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		),
		NodeKey: mustNK(
			"nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		),
		DiscoKey: mustDK(
			"discokey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
		),
		IPv4:       iap("100.64.0.1"),
		Hostname:   "mini",
		GivenName:  "mini",
		UserID:     user1.ID,
		User:       user1,
		ForcedTags: []string{},
		AuthKey:    &types.PreAuthKey{},
		LastSeen:   &lastSeen,
		Expiry:     &expire,
		Hostinfo: &tailcfg.Hostinfo{
			RoutableIPs: []netip.Prefix{
				tsaddr.AllIPv4(),
				netip.MustParsePrefix("192.168.0.0/24"),
				netip.MustParsePrefix("172.0.0.0/10"),
			},
		},
		ApprovedRoutes: []netip.Prefix{tsaddr.AllIPv4(), netip.MustParsePrefix("192.168.0.0/24")},
		CreatedAt:      created,
	}

	tailMini := &tailcfg.Node{
		ID:       1,
		StableID: "1",
		Name:     "mini",
		User:     tailcfg.UserID(user1.ID),
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
			tsaddr.AllIPv4(),
			netip.MustParsePrefix("192.168.0.0/24"),
		},
		HomeDERP:         0,
		LegacyDERPString: "127.3.3.40:0",
		Hostinfo: hiview(tailcfg.Hostinfo{
			RoutableIPs: []netip.Prefix{
				tsaddr.AllIPv4(),
				netip.MustParsePrefix("192.168.0.0/24"),
				netip.MustParsePrefix("172.0.0.0/10"),
			},
		}),
		Created:           created,
		Tags:              []string{},
		LastSeen:          &lastSeen,
		MachineAuthorized: true,

		CapMap: tailcfg.NodeCapMap{
			tailcfg.CapabilityFileSharing: []tailcfg.RawMessage{},
			tailcfg.CapabilityAdmin:       []tailcfg.RawMessage{},
			tailcfg.CapabilitySSH:         []tailcfg.RawMessage{},
		},
	}

	peer1 := &types.Node{
		ID: 2,
		MachineKey: mustMK(
			"mkey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
		),
		NodeKey: mustNK(
			"nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
		),
		DiscoKey: mustDK(
			"discokey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
		),
		IPv4:       iap("100.64.0.2"),
		Hostname:   "peer1",
		GivenName:  "peer1",
		UserID:     user2.ID,
		User:       user2,
		ForcedTags: []string{},
		LastSeen:   &lastSeen,
		Expiry:     &expire,
		Hostinfo:   &tailcfg.Hostinfo{},
		CreatedAt:  created,
	}

	tailPeer1 := &tailcfg.Node{
		ID:       2,
		StableID: "2",
		Name:     "peer1",
		User:     tailcfg.UserID(user2.ID),
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
		HomeDERP:          0,
		LegacyDERPString:  "127.3.3.40:0",
		Hostinfo:          hiview(tailcfg.Hostinfo{}),
		Created:           created,
		Tags:              []string{},
		LastSeen:          &lastSeen,
		MachineAuthorized: true,

		CapMap: tailcfg.NodeCapMap{
			tailcfg.CapabilityFileSharing: []tailcfg.RawMessage{},
			tailcfg.CapabilityAdmin:       []tailcfg.RawMessage{},
			tailcfg.CapabilitySSH:         []tailcfg.RawMessage{},
		},
	}

	tests := []struct {
		name  string
		pol   []byte
		node  *types.Node
		peers types.Nodes

		derpMap *tailcfg.DERPMap
		cfg     *types.Config
		want    *tailcfg.MapResponse
		wantErr bool
	}{
		// {
		// 	name:             "empty-node",
		// 	node:          types.Node{},
		// 	pol:              &policyv1.ACLPolicy{},
		// 	dnsConfig:        &tailcfg.DNSConfig{},
		// 	baseDomain:       "",
		// 	want:             nil,
		// 	wantErr:          true,
		// },
		{
			name:    "no-pol-no-peers-map-response",
			node:    mini,
			peers:   types.Nodes{},
			derpMap: &tailcfg.DERPMap{},
			cfg: &types.Config{
				BaseDomain:          "",
				TailcfgDNSConfig:    &tailcfg.DNSConfig{},
				LogTail:             types.LogTailConfig{Enabled: false},
				RandomizeClientPort: false,
			},
			want: &tailcfg.MapResponse{
				Node:            tailMini,
				KeepAlive:       false,
				DERPMap:         &tailcfg.DERPMap{},
				Peers:           []*tailcfg.Node{},
				DNSConfig:       &tailcfg.DNSConfig{},
				Domain:          "",
				CollectServices: "false",
				UserProfiles: []tailcfg.UserProfile{
					{
						ID:          tailcfg.UserID(user1.ID),
						LoginName:   "user1",
						DisplayName: "user1",
					},
				},
				ControlTime:   &time.Time{},
				PacketFilters: map[string][]tailcfg.FilterRule{"base": tailcfg.FilterAllowAll},
				Debug: &tailcfg.Debug{
					DisableLogTail: true,
				},
			},
			wantErr: false,
		},
		{
			name: "no-pol-with-peer-map-response",
			node: mini,
			peers: types.Nodes{
				peer1,
			},
			derpMap: &tailcfg.DERPMap{},
			cfg: &types.Config{
				BaseDomain:          "",
				TailcfgDNSConfig:    &tailcfg.DNSConfig{},
				LogTail:             types.LogTailConfig{Enabled: false},
				RandomizeClientPort: false,
			},
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
				UserProfiles: []tailcfg.UserProfile{
					{ID: tailcfg.UserID(user1.ID), LoginName: "user1", DisplayName: "user1"},
					{ID: tailcfg.UserID(user2.ID), LoginName: "user2", DisplayName: "user2"},
				},
				ControlTime:   &time.Time{},
				PacketFilters: map[string][]tailcfg.FilterRule{"base": tailcfg.FilterAllowAll},
				Debug: &tailcfg.Debug{
					DisableLogTail: true,
				},
			},
			wantErr: false,
		},
		{
			name: "with-pol-map-response",
			pol: []byte(`
				{
					"acls": [
						{
							"action": "accept",
							"src": ["100.64.0.2"],
							"dst": ["user1:*"],
						},
					],
				}
				`),
			node: mini,
			peers: types.Nodes{
				peer1,
			},
			derpMap: &tailcfg.DERPMap{},
			cfg: &types.Config{
				BaseDomain:          "",
				TailcfgDNSConfig:    &tailcfg.DNSConfig{},
				LogTail:             types.LogTailConfig{Enabled: false},
				RandomizeClientPort: false,
			},
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
				PacketFilters: map[string][]tailcfg.FilterRule{
					"base": {
						{
							SrcIPs: []string{"100.64.0.2/32"},
							DstPorts: []tailcfg.NetPortRange{
								{IP: "100.64.0.1/32", Ports: tailcfg.PortRangeAny},
							},
						},
					},
				},
				SSHPolicy: &tailcfg.SSHPolicy{},
				UserProfiles: []tailcfg.UserProfile{
					{ID: tailcfg.UserID(user1.ID), LoginName: "user1", DisplayName: "user1"},
					{ID: tailcfg.UserID(user2.ID), LoginName: "user2", DisplayName: "user2"},
				},
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
			polMan, err := policy.NewPolicyManager(tt.pol, []types.User{user1, user2}, append(tt.peers, tt.node))
			require.NoError(t, err)
			primary := routes.New()

			primary.SetRoutes(tt.node.ID, tt.node.SubnetRoutes()...)
			for _, peer := range tt.peers {
				primary.SetRoutes(peer.ID, peer.SubnetRoutes()...)
			}

			mappy := NewMapper(
				nil,
				tt.cfg,
				tt.derpMap,
				nil,
				polMan,
				primary,
			)

			got, err := mappy.fullMapResponse(
				tt.node,
				tt.peers,
				0,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("fullMapResponse() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

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
