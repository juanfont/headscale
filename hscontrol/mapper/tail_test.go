package mapper

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestTailNode(t *testing.T) {
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

	tests := []struct {
		name       string
		node       *types.Node
		pol        *policy.ACLPolicy
		dnsConfig  *tailcfg.DNSConfig
		baseDomain string
		want       *tailcfg.Node
		wantErr    bool
	}{
		{
			name:       "empty-node",
			node:       &types.Node{},
			pol:        &policy.ACLPolicy{},
			dnsConfig:  &tailcfg.DNSConfig{},
			baseDomain: "",
			want:       nil,
			wantErr:    true,
		},
		{
			name: "minimal-node",
			node: &types.Node{
				ID:         0,
				MachineKey: "mkey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
				NodeKey:    "nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
				DiscoKey:   "discokey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
				IPAddresses: []netip.Addr{
					netip.MustParseAddr("100.64.0.1"),
				},
				Hostname:  "mini",
				GivenName: "mini",
				UserID:    0,
				User: types.User{
					Name: "mini",
				},
				ForcedTags: []string{},
				AuthKeyID:  0,
				AuthKey:    &types.PreAuthKey{},
				LastSeen:   &lastSeen,
				Expiry:     &expire,
				HostInfo:   types.HostInfo{},
				Endpoints:  []string{},
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
			},
			pol:        &policy.ACLPolicy{},
			dnsConfig:  &tailcfg.DNSConfig{},
			baseDomain: "",
			want: &tailcfg.Node{
				ID:       0,
				StableID: "0",
				Name:     "mini",

				User: 0,

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
				Endpoints: []string{},
				DERP:      "127.3.3.40:0",
				Hostinfo:  hiview(tailcfg.Hostinfo{}),
				Created:   created,

				Tags: []string{},

				PrimaryRoutes: []netip.Prefix{
					netip.MustParsePrefix("192.168.0.0/24"),
				},

				LastSeen:          &lastSeen,
				Online:            new(bool),
				MachineAuthorized: true,

				Capabilities: []tailcfg.NodeCapability{
					tailcfg.CapabilityFileSharing,
					tailcfg.CapabilityAdmin,
					tailcfg.CapabilitySSH,
					tailcfg.NodeAttrDisableUPnP,
				},
			},
			wantErr: false,
		},
		// TODO: Add tests to check other aspects of the node conversion:
		// - With tags and policy
		// - dnsconfig and basedomain
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tailNode(
				tt.node,
				0,
				tt.pol,
				tt.dnsConfig,
				tt.baseDomain,
				false,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("tailNode() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("tailNode() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}
