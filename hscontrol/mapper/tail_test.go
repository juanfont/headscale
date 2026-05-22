package mapper

import (
	"encoding/json"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestTailNode(t *testing.T) {
	t.Parallel()

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
		dnsConfig  *tailcfg.DNSConfig
		baseDomain string
		want       *tailcfg.Node
		wantErr    bool
	}{
		{
			name: "empty-node",
			node: &types.Node{
				GivenName: "empty",
				Hostinfo:  &tailcfg.Hostinfo{},
			},
			dnsConfig:  &tailcfg.DNSConfig{},
			baseDomain: "",
			want: &tailcfg.Node{
				Name:              "empty",
				StableID:          "0",
				HomeDERP:          0,
				Hostinfo:          hiview(tailcfg.Hostinfo{}),
				MachineAuthorized: true,

				CapMap: tailcfg.NodeCapMap{
					tailcfg.CapabilityAdmin:           []tailcfg.RawMessage{},
					tailcfg.CapabilitySSH:             []tailcfg.RawMessage{},
					tailcfg.CapabilityFileSharing:     []tailcfg.RawMessage{},
					tailcfg.NodeAttrDefaultAutoUpdate: []tailcfg.RawMessage{tailcfg.RawMessage("false")},
				},
			},
			wantErr: false,
		},
		{
			name: "minimal-node",
			node: &types.Node{
				ID: 0,
				MachineKey: mustMK(
					"mkey:f08305b4ee4250b95a70f3b7504d048d75d899993c624a26d422c67af0422507",
				),
				NodeKey: mustNK(
					"nodekey:9b2ffa7e08cc421a3d2cca9012280f6a236fd0de0b4ce005b30a98ad930306fe",
				),
				DiscoKey: mustDK(
					"discokey:cf7b0fd05da556fdc3bab365787b506fd82d64a70745db70e00e86c1b1c03084",
				),
				IPv4:      iap("100.64.0.1"),
				Hostname:  "mini",
				GivenName: "mini",
				UserID:    new(uint(0)),
				User: &types.User{
					Name: "mini",
				},
				Tags:     []string{},
				AuthKey:  &types.PreAuthKey{},
				LastSeen: &lastSeen,
				Expiry:   &expire,
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						tsaddr.AllIPv4(),
						tsaddr.AllIPv6(),
						netip.MustParsePrefix("192.168.0.0/24"),
						netip.MustParsePrefix("172.0.0.0/10"),
					},
				},
				ApprovedRoutes: []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6(), netip.MustParsePrefix("192.168.0.0/24")},
				CreatedAt:      created,
			},
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
					tsaddr.AllIPv4(),
					netip.MustParsePrefix("100.64.0.1/32"),
					netip.MustParsePrefix("192.168.0.0/24"),
					tsaddr.AllIPv6(),
				},
				PrimaryRoutes: []netip.Prefix{
					netip.MustParsePrefix("192.168.0.0/24"),
				},
				HomeDERP: 0,
				Hostinfo: hiview(tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						tsaddr.AllIPv4(),
						tsaddr.AllIPv6(),
						netip.MustParsePrefix("192.168.0.0/24"),
						netip.MustParsePrefix("172.0.0.0/10"),
					},
				}),
				Created: created,

				Tags: []string{},

				MachineAuthorized: true,

				CapMap: tailcfg.NodeCapMap{
					tailcfg.CapabilityAdmin:           []tailcfg.RawMessage{},
					tailcfg.CapabilitySSH:             []tailcfg.RawMessage{},
					tailcfg.CapabilityFileSharing:     []tailcfg.RawMessage{},
					tailcfg.NodeAttrDefaultAutoUpdate: []tailcfg.RawMessage{tailcfg.RawMessage("false")},
				},
			},
			wantErr: false,
		},
		{
			name: "check-dot-suffix-on-node-name",
			node: &types.Node{
				GivenName: "minimal",
				Hostinfo:  &tailcfg.Hostinfo{},
			},
			dnsConfig:  &tailcfg.DNSConfig{},
			baseDomain: "example.com",
			want: &tailcfg.Node{
				// a node name should have a dot appended
				Name:              "minimal.example.com.",
				StableID:          "0",
				HomeDERP:          0,
				Hostinfo:          hiview(tailcfg.Hostinfo{}),
				MachineAuthorized: true,

				CapMap: tailcfg.NodeCapMap{
					tailcfg.CapabilityAdmin:           []tailcfg.RawMessage{},
					tailcfg.CapabilitySSH:             []tailcfg.RawMessage{},
					tailcfg.CapabilityFileSharing:     []tailcfg.RawMessage{},
					tailcfg.NodeAttrDefaultAutoUpdate: []tailcfg.RawMessage{tailcfg.RawMessage("false")},
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
			t.Parallel()

			cfg := &types.Config{
				BaseDomain:       tt.baseDomain,
				TailcfgDNSConfig: tt.dnsConfig,
				Taildrop:         types.TaildropConfig{Enabled: true},
			}

			// Stub primary-route lookup: tt.node owns its SubnetRoutes,
			// node ID 2 owns 192.168.0.0/24 (a hack carried over from
			// the original routes-package-driven version of this test —
			// avoids spinning up a second node just to validate that
			// other nodes' primaries don't leak into tt.node's TailNode
			// output).
			primaries := map[types.NodeID][]netip.Prefix{
				tt.node.ID: tt.node.SubnetRoutes(),
				2:          {netip.MustParsePrefix("192.168.0.0/24")},
			}
			nv := tt.node.View()
			got, err := nv.TailNode(
				0,
				func(id types.NodeID) []netip.Prefix {
					// Route function returns primaries + exit routes
					// (matching the real caller contract).
					return slices.Concat(primaries[id], nv.ExitRoutes())
				},
				cfg,
				nil,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("TailNode() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("TailNode() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

// TestTailNodeBaselineGates focuses on the cfg-driven baseline cap
// emission: cfg.Taildrop.Enabled gates [tailcfg.CapabilityFileSharing]
// and cfg.AutoUpdate.Enabled controls the value of
// [tailcfg.NodeAttrDefaultAutoUpdate]. Admin and SSH are unconditional
// baseline.
func TestTailNodeBaselineGates(t *testing.T) {
	t.Parallel()

	autoUpdate := func(b bool) []tailcfg.RawMessage {
		if b {
			return []tailcfg.RawMessage{tailcfg.RawMessage("true")}
		}

		return []tailcfg.RawMessage{tailcfg.RawMessage("false")}
	}

	tests := []struct {
		name string
		cfg  *types.Config
		want tailcfg.NodeCapMap
	}{
		{
			name: "taildrop_on_autoupdate_off",
			cfg: &types.Config{
				Taildrop:   types.TaildropConfig{Enabled: true},
				AutoUpdate: types.AutoUpdateConfig{Enabled: false},
			},
			want: tailcfg.NodeCapMap{
				tailcfg.CapabilityAdmin:           []tailcfg.RawMessage{},
				tailcfg.CapabilitySSH:             []tailcfg.RawMessage{},
				tailcfg.CapabilityFileSharing:     []tailcfg.RawMessage{},
				tailcfg.NodeAttrDefaultAutoUpdate: autoUpdate(false),
			},
		},
		{
			name: "taildrop_off_autoupdate_off",
			cfg: &types.Config{
				Taildrop:   types.TaildropConfig{Enabled: false},
				AutoUpdate: types.AutoUpdateConfig{Enabled: false},
			},
			want: tailcfg.NodeCapMap{
				tailcfg.CapabilityAdmin:           []tailcfg.RawMessage{},
				tailcfg.CapabilitySSH:             []tailcfg.RawMessage{},
				tailcfg.NodeAttrDefaultAutoUpdate: autoUpdate(false),
			},
		},
		{
			name: "taildrop_on_autoupdate_on",
			cfg: &types.Config{
				Taildrop:   types.TaildropConfig{Enabled: true},
				AutoUpdate: types.AutoUpdateConfig{Enabled: true},
			},
			want: tailcfg.NodeCapMap{
				tailcfg.CapabilityAdmin:           []tailcfg.RawMessage{},
				tailcfg.CapabilitySSH:             []tailcfg.RawMessage{},
				tailcfg.CapabilityFileSharing:     []tailcfg.RawMessage{},
				tailcfg.NodeAttrDefaultAutoUpdate: autoUpdate(true),
			},
		},
		{
			name: "taildrop_off_autoupdate_on",
			cfg: &types.Config{
				Taildrop:   types.TaildropConfig{Enabled: false},
				AutoUpdate: types.AutoUpdateConfig{Enabled: true},
			},
			want: tailcfg.NodeCapMap{
				tailcfg.CapabilityAdmin:           []tailcfg.RawMessage{},
				tailcfg.CapabilitySSH:             []tailcfg.RawMessage{},
				tailcfg.NodeAttrDefaultAutoUpdate: autoUpdate(true),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			node := &types.Node{GivenName: "baseline-node", Hostinfo: &tailcfg.Hostinfo{}}

			got, err := node.View().TailNode(
				0,
				func(types.NodeID) []netip.Prefix { return nil },
				tt.cfg,
				nil,
			)
			if err != nil {
				t.Fatalf("TailNode: %v", err)
			}

			if diff := cmp.Diff(tt.want, got.CapMap, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("CapMap mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestTailNodeDisableIPv4 asserts that a node with the disable-ipv4
// nodeAttr has its own IPv4 (the CGNAT /32) stripped from Addresses
// and AllowedIPs, while subnet routes the node advertises -- even
// IPv4 ones -- remain in AllowedIPs and PrimaryRoutes. Matches the
// SaaS behaviour captured in
// hscontrol/policy/v2/testdata/nodeattrs_results/nodeattrs-attr-c1{5,6}-disable-ipv4*.hujson.
func TestTailNodeDisableIPv4(t *testing.T) {
	t.Parallel()

	const NodeAttrDisableIPv4 tailcfg.NodeCapability = "disable-ipv4"

	v4 := iap("100.64.0.1")
	v6Addr := netip.MustParseAddr("fd7a:115c:a1e0::1")
	v6 := &v6Addr
	subnet := netip.MustParsePrefix("10.33.0.0/16")

	tests := []struct {
		name        string
		hasCap      bool
		approved    []netip.Prefix
		wantAllowed []netip.Prefix
		wantPrimary []netip.Prefix
		wantAddrs   []netip.Prefix
	}{
		{
			name:        "no-cap_emits_both_families",
			hasCap:      false,
			wantAllowed: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("fd7a:115c:a1e0::1/128")},
			wantAddrs:   []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("fd7a:115c:a1e0::1/128")},
		},
		{
			name:        "cap_strips_own_ipv4",
			hasCap:      true,
			wantAllowed: []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0::1/128")},
			wantAddrs:   []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0::1/128")},
		},
		{
			name:     "cap_keeps_advertised_subnet_route",
			hasCap:   true,
			approved: []netip.Prefix{subnet},
			// AllowedIPs is sorted by netip.Prefix.Compare so IPv4
			// sorts before IPv6.
			wantAllowed: []netip.Prefix{
				subnet,
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
			},
			wantPrimary: []netip.Prefix{subnet},
			wantAddrs:   []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0::1/128")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			node := &types.Node{
				GivenName: "ipv4-disabled-node",
				IPv4:      v4,
				IPv6:      v6,
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: tt.approved,
				},
				ApprovedRoutes: tt.approved,
			}

			var selfCaps tailcfg.NodeCapMap
			if tt.hasCap {
				selfCaps = tailcfg.NodeCapMap{NodeAttrDisableIPv4: nil}
			}

			got, err := node.View().TailNode(
				0,
				func(types.NodeID) []netip.Prefix {
					return tt.approved
				},
				&types.Config{Taildrop: types.TaildropConfig{Enabled: true}},
				selfCaps,
			)
			if err != nil {
				t.Fatalf("TailNode: %v", err)
			}

			prefStrings := func(ps []netip.Prefix) []string {
				out := make([]string, len(ps))
				for i, p := range ps {
					out[i] = p.String()
				}

				return out
			}

			if diff := cmp.Diff(prefStrings(tt.wantAddrs), prefStrings(got.Addresses), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Addresses (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(prefStrings(tt.wantAllowed), prefStrings(got.AllowedIPs), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("AllowedIPs (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(prefStrings(tt.wantPrimary), prefStrings(got.PrimaryRoutes), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("PrimaryRoutes (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNodeExpiry(t *testing.T) {
	tp := func(t time.Time) *time.Time {
		return &t
	}
	tests := []struct {
		name         string
		exp          *time.Time
		wantTime     time.Time
		wantTimeZero bool
	}{
		{
			name:         "no-expiry",
			exp:          nil,
			wantTimeZero: true,
		},
		{
			name:         "zero-expiry",
			exp:          &time.Time{},
			wantTimeZero: true,
		},
		{
			name:         "localtime",
			exp:          tp(time.Time{}.Local()), //nolint:gosmopolitan
			wantTimeZero: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &types.Node{
				ID:        0,
				GivenName: "test",
				Expiry:    tt.exp,
			}

			tn, err := node.View().TailNode(
				0,
				func(id types.NodeID) []netip.Prefix {
					return []netip.Prefix{}
				},
				&types.Config{Taildrop: types.TaildropConfig{Enabled: true}},
				nil,
			)
			if err != nil {
				t.Fatalf("nodeExpiry() error = %v", err)
			}

			// Round trip the node through JSON to ensure the time is serialized correctly
			seri, err := json.Marshal(tn)
			if err != nil {
				t.Fatalf("nodeExpiry() error = %v", err)
			}

			var deseri tailcfg.Node

			err = json.Unmarshal(seri, &deseri)
			if err != nil {
				t.Fatalf("nodeExpiry() error = %v", err)
			}

			if tt.wantTimeZero {
				if !deseri.KeyExpiry.IsZero() {
					t.Errorf("nodeExpiry() = %v, want zero", deseri.KeyExpiry)
				}
			} else if deseri.KeyExpiry != tt.wantTime {
				t.Errorf("nodeExpiry() = %v, want %v", deseri.KeyExpiry, tt.wantTime)
			}
		})
	}
}
