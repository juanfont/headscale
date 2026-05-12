package mapper

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
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
					UserID:   new(userid),
					User: &types.User{
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
				nodeInShared1.View(),
			)

			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("expandAlias() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGenerateDNSConfigProfiles(t *testing.T) {
	ip1 := netip.MustParseAddr("100.64.0.2")
	ip2 := netip.MustParseAddr("100.64.0.3")

	baseDNS := &tailcfg.DNSConfig{
		Routes:  make(map[string][]*dnstype.Resolver),
		Domains: []string{"example.com"},
		Proxied: true,
		Resolvers: []*dnstype.Resolver{
			{Addr: "1.1.1.1"},
		},
	}

	profiles := []types.DNSProfile{
		{
			IPs:         []string{"100.64.0.2"},
			Nameservers: []string{"1.1.1.1", "1.0.0.1"},
		},
		{
			IPs:         []string{"100.64.0.3"},
			Nameservers: []string{"8.8.8.8", "8.8.4.4"},
		},
	}

	tests := []struct {
		name string
		node *types.Node
		want []*dnstype.Resolver
	}{
		{
			name: "node-matches-first-profile",
			node: &types.Node{IPv4: &ip1},
			want: []*dnstype.Resolver{
				{Addr: "1.1.1.1"},
				{Addr: "1.0.0.1"},
			},
		},
		{
			name: "node-matches-second-profile",
			node: &types.Node{IPv4: &ip2},
			want: []*dnstype.Resolver{
				{Addr: "8.8.8.8"},
				{Addr: "8.8.4.4"},
			},
		},
		{
			name: "node-no-profile-match-keeps-default",
			node: &types.Node{},
			want: []*dnstype.Resolver{
				{Addr: "1.1.1.1"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateDNSConfig(
				&types.Config{
					TailcfgDNSConfig: baseDNS,
					DNSConfig: types.DNSConfig{
						Profiles: profiles,
					},
				},
				tt.node.View(),
			)

			if diff := cmp.Diff(tt.want, got.Resolvers, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("generateDNSConfig() resolvers mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
