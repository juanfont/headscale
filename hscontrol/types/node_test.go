package types

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/dnsname"
)

func Test_NodeCanAccess(t *testing.T) {
	iap := func(ipStr string) *netip.Addr {
		ip := netip.MustParseAddr(ipStr)
		return &ip
	}
	tests := []struct {
		name  string
		node1 Node
		node2 Node
		rules []tailcfg.FilterRule
		want  bool
	}{
		{
			name: "no-rules",
			node1: Node{
				IPv4: iap("10.0.0.1"),
			},
			node2: Node{
				IPv4: iap("10.0.0.2"),
			},
			rules: []tailcfg.FilterRule{},
			want:  false,
		},
		{
			name: "wildcard",
			node1: Node{
				IPv4: iap("10.0.0.1"),
			},
			node2: Node{
				IPv4: iap("10.0.0.2"),
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"*"},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "*",
							Ports: tailcfg.PortRangeAny,
						},
					},
				},
			},
			want: true,
		},
		{
			name: "other-cant-access-src",
			node1: Node{
				IPv4: iap("100.64.0.1"),
			},
			node2: Node{
				IPv4: iap("100.64.0.3"),
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			want: false,
		},
		{
			name: "dest-cant-access-src",
			node1: Node{
				IPv4: iap("100.64.0.3"),
			},
			node2: Node{
				IPv4: iap("100.64.0.2"),
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			want: false,
		},
		{
			name: "src-can-access-dest",
			node1: Node{
				IPv4: iap("100.64.0.2"),
			},
			node2: Node{
				IPv4: iap("100.64.0.3"),
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			want: true,
		},
		// Subnet-to-subnet tests.
		// When ACL src and dst are both subnet CIDRs, subnet
		// routers advertising those subnets must see each other.
		{
			name: "subnet-to-subnet-src-router-sees-dst-router-3157",
			node1: Node{
				IPv4: iap("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.88.8.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.88.8.0/24"),
				},
			},
			node2: Node{
				IPv4: iap("100.64.0.2"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.99.9.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.99.9.0/24"),
				},
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"10.88.8.0/24"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "10.99.9.0/24", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			want: true,
		},
		{
			// With a unidirectional ACL (src=A→dst=B), the dst
			// router cannot access the src router. Bidirectional
			// peer visibility comes from BuildPeerMap checking
			// both A.CanAccess(B) || B.CanAccess(A).
			name: "subnet-to-subnet-unidirectional-dst-cannot-access-src-3157",
			node1: Node{
				IPv4: iap("100.64.0.2"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.99.9.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.99.9.0/24"),
				},
			},
			node2: Node{
				IPv4: iap("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.88.8.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.88.8.0/24"),
				},
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"10.88.8.0/24"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "10.99.9.0/24", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			want: false,
		},
		{
			// With a bidirectional ACL, both routers can access
			// each other.
			name: "subnet-to-subnet-bidirectional-3157",
			node1: Node{
				IPv4: iap("100.64.0.2"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.99.9.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.99.9.0/24"),
				},
			},
			node2: Node{
				IPv4: iap("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.88.8.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.88.8.0/24"),
				},
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"10.88.8.0/24"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "10.99.9.0/24", Ports: tailcfg.PortRangeAny},
					},
				},
				{
					SrcIPs: []string{"10.99.9.0/24"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "10.88.8.0/24", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			want: true,
		},
		{
			name: "subnet-to-subnet-regular-node-excluded-3157",
			node1: Node{
				IPv4: iap("100.64.0.3"),
			},
			node2: Node{
				IPv4: iap("100.64.0.2"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.99.9.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.99.9.0/24"),
				},
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"10.88.8.0/24"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "10.99.9.0/24", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			want: false,
		},
		{
			name: "subnet-to-subnet-unrelated-router-excluded-3157",
			node1: Node{
				IPv4: iap("100.64.0.3"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("172.16.0.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("172.16.0.0/24"),
				},
			},
			node2: Node{
				IPv4: iap("100.64.0.2"),
				Hostinfo: &tailcfg.Hostinfo{
					RoutableIPs: []netip.Prefix{
						netip.MustParsePrefix("10.99.9.0/24"),
					},
				},
				ApprovedRoutes: []netip.Prefix{
					netip.MustParsePrefix("10.99.9.0/24"),
				},
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"10.88.8.0/24"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "10.99.9.0/24", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matchers := matcher.MatchesFromFilterRules(tt.rules)
			got := tt.node1.CanAccess(matchers, &tt.node2)

			if got != tt.want {
				t.Errorf("canAccess() failed: want (%t), got (%t)", tt.want, got)
			}
		})
	}
}

// Test_NodeCanAccess_Unidirectional asserts that a one-way rule grants
// access in one direction only. A unidirectional ACL is a valid and
// intentional pattern; the "OR" aggregation in the v1 compat harness
// loses this asymmetry, which motivated the directional split in
// TestRoutesCompatPeerVisibility.
func Test_NodeCanAccess_Unidirectional(t *testing.T) {
	iap := func(ipStr string) *netip.Addr {
		ip := netip.MustParseAddr(ipStr)
		return &ip
	}

	nodeA := Node{IPv4: iap("100.64.0.1")}
	nodeB := Node{IPv4: iap("100.64.0.2")}

	rules := []tailcfg.FilterRule{
		{
			SrcIPs: []string{"100.64.0.1/32"},
			DstPorts: []tailcfg.NetPortRange{
				{IP: "100.64.0.2/32", Ports: tailcfg.PortRangeAny},
			},
		},
	}

	matchers := matcher.MatchesFromFilterRules(rules)

	if !nodeA.CanAccess(matchers, &nodeB) {
		t.Errorf("A→B: want true, got false")
	}

	if nodeB.CanAccess(matchers, &nodeA) {
		t.Errorf("B→A: want false, got true (unidirectional rule leaked reverse access)")
	}
}

func TestNodeFQDN(t *testing.T) {
	tests := []struct {
		name    string
		node    Node
		domain  string
		want    string
		wantErr string
	}{
		{
			name: "no-dnsconfig-with-username",
			node: Node{
				GivenName: "test",
				User: &User{
					Name: "user",
				},
			},
			domain: "example.com",
			want:   "test.example.com.",
		},
		{
			name: "all-set",
			node: Node{
				GivenName: "test",
				User: &User{
					Name: "user",
				},
			},
			domain: "example.com",
			want:   "test.example.com.",
		},
		{
			name: "no-given-name",
			node: Node{
				User: &User{
					Name: "user",
				},
			},
			domain:  "example.com",
			wantErr: "creating valid FQDN: node has no given name",
		},
		{
			name: "too-long-username",
			node: Node{
				GivenName: strings.Repeat("a", 256),
			},
			domain:  "example.com",
			wantErr: fmt.Sprintf("creating valid FQDN (%s.example.com.): hostname too long, cannot accept more than 255 ASCII chars", strings.Repeat("a", 256)),
		},
		{
			name: "no-dnsconfig",
			node: Node{
				GivenName: "test",
				User: &User{
					Name: "user",
				},
			},
			domain: "example.com",
			want:   "test.example.com.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.node.GetFQDN(tc.domain)

			t.Logf("GOT: %q, %q", got, tc.domain)

			if (err != nil) && (err.Error() != tc.wantErr) {
				t.Errorf("GetFQDN() error = %s, wantErr %s", err, tc.wantErr)

				return
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("GetFQDN unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestValidateGivenName(t *testing.T) {
	tests := []struct {
		name       string
		givenName  string
		baseDomain string
		wantErr    bool
	}{
		{"valid", "test", "example.com", false},
		{"empty", "", "example.com", true},
		{"invalid label chars", "not valid", "example.com", true},
		{"label too long", strings.Repeat("a", 64), "example.com", true},
		// A valid 63-char label whose FQDN overflows only because the base
		// domain is long: ValidLabel passes, the FQDN-length bound rejects it.
		{"fqdn too long under long base domain", strings.Repeat("a", 63), strings.Repeat("b", 200) + ".example.com", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateGivenName(tc.givenName, tc.baseDomain)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateGivenName(%q, %q) error = %v, wantErr %v",
					tc.givenName, tc.baseDomain, err, tc.wantErr)
			}
		})
	}
}

func TestPeerChangeFromMapRequest(t *testing.T) {
	nKeys := []key.NodePublic{
		key.NewNode().Public(),
		key.NewNode().Public(),
		key.NewNode().Public(),
	}

	dKeys := []key.DiscoPublic{
		key.NewDisco().Public(),
		key.NewDisco().Public(),
		key.NewDisco().Public(),
	}

	tests := []struct {
		name   string
		node   Node
		mapReq tailcfg.MapRequest
		want   tailcfg.PeerChange
	}{
		{
			name: "preferred-derp-changed",
			node: Node{
				ID:        1,
				NodeKey:   nKeys[0],
				DiscoKey:  dKeys[0],
				Endpoints: []netip.AddrPort{},
				Hostinfo: &tailcfg.Hostinfo{
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 998,
					},
				},
			},
			mapReq: tailcfg.MapRequest{
				NodeKey:  nKeys[0],
				DiscoKey: dKeys[0],
				Hostinfo: &tailcfg.Hostinfo{
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 999,
					},
				},
			},
			want: tailcfg.PeerChange{
				NodeID:     1,
				DERPRegion: 999,
			},
		},
		{
			name: "preferred-derp-no-changed",
			node: Node{
				ID:        1,
				NodeKey:   nKeys[0],
				DiscoKey:  dKeys[0],
				Endpoints: []netip.AddrPort{},
				Hostinfo: &tailcfg.Hostinfo{
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 100,
					},
				},
			},
			mapReq: tailcfg.MapRequest{
				NodeKey:  nKeys[0],
				DiscoKey: dKeys[0],
				Hostinfo: &tailcfg.Hostinfo{
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 100,
					},
				},
			},
			want: tailcfg.PeerChange{
				NodeID:     1,
				DERPRegion: 0,
			},
		},
		{
			name: "preferred-derp-no-mapreq-netinfo",
			node: Node{
				ID:        1,
				NodeKey:   nKeys[0],
				DiscoKey:  dKeys[0],
				Endpoints: []netip.AddrPort{},
				Hostinfo: &tailcfg.Hostinfo{
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 200,
					},
				},
			},
			mapReq: tailcfg.MapRequest{
				NodeKey:  nKeys[0],
				DiscoKey: dKeys[0],
				Hostinfo: &tailcfg.Hostinfo{},
			},
			want: tailcfg.PeerChange{
				NodeID:     1,
				DERPRegion: 0,
			},
		},
		{
			name: "preferred-derp-no-node-netinfo",
			node: Node{
				ID:        1,
				NodeKey:   nKeys[0],
				DiscoKey:  dKeys[0],
				Endpoints: []netip.AddrPort{},
				Hostinfo:  &tailcfg.Hostinfo{},
			},
			mapReq: tailcfg.MapRequest{
				NodeKey:  nKeys[0],
				DiscoKey: dKeys[0],
				Hostinfo: &tailcfg.Hostinfo{
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 200,
					},
				},
			},
			want: tailcfg.PeerChange{
				NodeID:     1,
				DERPRegion: 200,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.node.PeerChangeFromMapRequest(tc.mapReq)

			if diff := cmp.Diff(tc.want, got, cmpopts.IgnoreFields(tailcfg.PeerChange{}, "LastSeen")); diff != "" {
				t.Errorf("Patch unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestApplyPeerChange(t *testing.T) {
	tests := []struct {
		name       string
		nodeBefore Node
		change     *tailcfg.PeerChange
		want       Node
	}{
		{
			name:       "hostinfo-and-netinfo-not-exists",
			nodeBefore: Node{},
			change: &tailcfg.PeerChange{
				DERPRegion: 1,
			},
			want: Node{
				Hostinfo: &tailcfg.Hostinfo{
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 1,
					},
				},
			},
		},
		{
			name: "hostinfo-netinfo-not-exists",
			nodeBefore: Node{
				Hostinfo: &tailcfg.Hostinfo{
					Hostname: "test",
				},
			},
			change: &tailcfg.PeerChange{
				DERPRegion: 3,
			},
			want: Node{
				Hostinfo: &tailcfg.Hostinfo{
					Hostname: "test",
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 3,
					},
				},
			},
		},
		{
			name: "hostinfo-netinfo-exists-derp-set",
			nodeBefore: Node{
				Hostinfo: &tailcfg.Hostinfo{
					Hostname: "test",
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 999,
					},
				},
			},
			change: &tailcfg.PeerChange{
				DERPRegion: 2,
			},
			want: Node{
				Hostinfo: &tailcfg.Hostinfo{
					Hostname: "test",
					NetInfo: &tailcfg.NetInfo{
						PreferredDERP: 2,
					},
				},
			},
		},
		{
			name:       "endpoints-not-set",
			nodeBefore: Node{},
			change: &tailcfg.PeerChange{
				Endpoints: []netip.AddrPort{
					netip.MustParseAddrPort("8.8.8.8:88"),
				},
			},
			want: Node{
				Endpoints: []netip.AddrPort{
					netip.MustParseAddrPort("8.8.8.8:88"),
				},
			},
		},
		{
			name: "endpoints-set",
			nodeBefore: Node{
				Endpoints: []netip.AddrPort{
					netip.MustParseAddrPort("6.6.6.6:66"),
				},
			},
			change: &tailcfg.PeerChange{
				Endpoints: []netip.AddrPort{
					netip.MustParseAddrPort("8.8.8.8:88"),
				},
			},
			want: Node{
				Endpoints: []netip.AddrPort{
					netip.MustParseAddrPort("8.8.8.8:88"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.nodeBefore.ApplyPeerChange(tt.change)

			if diff := cmp.Diff(tt.want, tt.nodeBefore, util.Comparers...); diff != "" {
				t.Errorf("Patch unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

// TestHasPolicyChangeAddressesAndRoutes covers the addresses and served
// routes that policy evaluation reads.
func TestHasPolicyChangeAddressesAndRoutes(t *testing.T) {
	mustIPPtr := func(s string) *netip.Addr {
		ip := netip.MustParseAddr(s)
		return &ip
	}

	tests := []struct {
		name    string
		old     *Node
		new     *Node
		changed bool
	}{
		{
			name: "no changes",
			old: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				IPv6:           mustIPPtr("fd7a:115c:a1e0::1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")},
			},
			new: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				IPv6:           mustIPPtr("fd7a:115c:a1e0::1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")},
			},
			changed: false,
		},
		{
			name: "IPv4 changed",
			old: &Node{
				ID:   1,
				IPv4: mustIPPtr("100.64.0.1"),
				IPv6: mustIPPtr("fd7a:115c:a1e0::1"),
			},
			new: &Node{
				ID:   1,
				IPv4: mustIPPtr("100.64.0.2"),
				IPv6: mustIPPtr("fd7a:115c:a1e0::1"),
			},
			changed: true,
		},
		{
			name: "IPv6 changed",
			old: &Node{
				ID:   1,
				IPv4: mustIPPtr("100.64.0.1"),
				IPv6: mustIPPtr("fd7a:115c:a1e0::1"),
			},
			new: &Node{
				ID:   1,
				IPv4: mustIPPtr("100.64.0.1"),
				IPv6: mustIPPtr("fd7a:115c:a1e0::2"),
			},
			changed: true,
		},
		{
			name: "RoutableIPs added",
			old: &Node{
				ID:       1,
				IPv4:     mustIPPtr("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{},
			},
			new: &Node{
				ID:       1,
				IPv4:     mustIPPtr("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}},
			},
			changed: false,
		},
		{
			name: "RoutableIPs removed",
			old: &Node{
				ID:       1,
				IPv4:     mustIPPtr("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}},
			},
			new: &Node{
				ID:       1,
				IPv4:     mustIPPtr("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{},
			},
			changed: false,
		},
		{
			name: "RoutableIPs changed",
			old: &Node{
				ID:       1,
				IPv4:     mustIPPtr("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}},
			},
			new: &Node{
				ID:       1,
				IPv4:     mustIPPtr("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")}},
			},
			changed: false,
		},
		{
			name: "SubnetRoutes added",
			old: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{},
			},
			new: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")},
			},
			changed: true,
		},
		{
			name: "SubnetRoutes removed",
			old: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")},
			},
			new: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{},
			},
			changed: true,
		},
		{
			name: "SubnetRoutes changed",
			old: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("192.168.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
			},
			new: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("192.168.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")},
			},
			changed: true,
		},
		{
			name: "irrelevant property changed (Hostname)",
			old: &Node{
				ID:       1,
				IPv4:     mustIPPtr("100.64.0.1"),
				Hostname: "old-name",
			},
			new: &Node{
				ID:       1,
				IPv4:     mustIPPtr("100.64.0.1"),
				Hostname: "new-name",
			},
			changed: false,
		},
		{
			name: "ExitRoutes approved",
			old: &Node{
				ID:       1,
				IPv4:     mustIPPtr("100.64.0.1"),
				Hostinfo: &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}},
			},
			new: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
			},
			changed: true,
		},
		{
			name: "ExitRoutes unchanged when SubnetRoutes change",
			old: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"), netip.MustParsePrefix("10.0.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
			},
			new: &Node{
				ID:             1,
				IPv4:           mustIPPtr("100.64.0.1"),
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"), netip.MustParsePrefix("10.0.0.0/24")}},
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"), netip.MustParsePrefix("10.0.0.0/24")},
			},
			changed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.new.View().HasPolicyChange(tt.old.View())
			if got != tt.changed {
				t.Errorf("HasPolicyChange() = %v, want %v", got, tt.changed)
			}
		})
	}
}

func policyChangeTestNode() Node {
	ipv4 := netip.MustParseAddr("100.64.0.1")
	now := time.Now()

	return Node{
		ID:         1,
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		DiscoKey:   key.NewDisco().Public(),
		Hostname:   "node",
		GivenName:  "node",
		IPv4:       &ipv4,
		CreatedAt:  now,
		UpdatedAt:  now,
		Hostinfo:   &tailcfg.Hostinfo{Hostname: "node"},
	}
}

// TestHasPolicyChangeUserIDPointerIdentity ensures two distinct *uint
// values holding the same user ID do not register as a policy change.
func TestHasPolicyChangeUserIDPointerIdentity(t *testing.T) {
	userID := uint(7)

	a := policyChangeTestNode()
	a.UserID = &userID

	b := policyChangeTestNode()
	otherPtr := new(uint)
	*otherPtr = 7
	b.UserID = otherPtr

	// Different pointers, same value.
	require.NotSame(t, a.UserID, b.UserID)
	require.False(t, a.View().HasPolicyChange(b.View()),
		"same UserID value via distinct pointers must not register as policy change")

	// And a real change must register.
	c := policyChangeTestNode()
	otherVal := uint(8)
	c.UserID = &otherVal
	require.True(t, a.View().HasPolicyChange(c.View()),
		"different UserID value must register as policy change")
}

// TestHasPolicyChangeUserIDValidity covers the nil vs non-nil transition.
func TestHasPolicyChangeUserIDValidity(t *testing.T) {
	a := policyChangeTestNode()
	// a.UserID nil
	b := policyChangeTestNode()
	v := uint(1)
	b.UserID = &v

	require.True(t, a.View().HasPolicyChange(b.View()),
		"nil -> non-nil UserID must register as policy change")
}

// TestHasPolicyChangeExitRoutes covers the missing ExitRoutes comparison.
func TestHasPolicyChangeExitRoutes(t *testing.T) {
	exitV4 := netip.MustParsePrefix("0.0.0.0/0")
	exitV6 := netip.MustParsePrefix("::/0")

	base := policyChangeTestNode()
	base.Hostinfo.RoutableIPs = []netip.Prefix{exitV4, exitV6}
	base.ApprovedRoutes = nil // not approved -> no exit routes

	b := policyChangeTestNode()
	b.Hostinfo.RoutableIPs = []netip.Prefix{exitV4, exitV6}
	b.ApprovedRoutes = []netip.Prefix{exitV4, exitV6} // approved -> exit routes live

	require.True(t, base.View().HasPolicyChange(b.View()),
		"enabling exit routes must register as policy change")

	// Reverse: approved on both, no change.
	c := policyChangeTestNode()
	c.Hostinfo.RoutableIPs = []netip.Prefix{exitV4, exitV6}
	c.ApprovedRoutes = []netip.Prefix{exitV4, exitV6}

	require.False(t, b.View().HasPolicyChange(c.View()),
		"identical exit-route state must not register as policy change")
}

func TestHasPolicyChangeFields(t *testing.T) {
	subnet := netip.MustParsePrefix("10.0.0.0/24")
	exit := netip.MustParsePrefix("0.0.0.0/0")

	tests := []struct {
		name   string
		mutate func(*Node)
		want   bool
	}{
		{name: "no change", mutate: func(*Node) {}, want: false},
		{name: "last seen", mutate: func(n *Node) { n.LastSeen = new(time.Now()) }, want: false},
		{name: "expiry", mutate: func(n *Node) { n.Expiry = new(time.Now()) }, want: false},
		{name: "hostname", mutate: func(n *Node) { n.Hostname = "other" }, want: false},
		{name: "tags", mutate: func(n *Node) { n.Tags = []string{"tag:x"} }, want: true},
		{
			name: "ipv4",
			mutate: func(n *Node) {
				ip := netip.MustParseAddr("100.64.0.2")
				n.IPv4 = &ip
			},
			want: true,
		},
		{
			name:   "announced but unapproved subnet",
			mutate: func(n *Node) { n.Hostinfo.RoutableIPs = []netip.Prefix{subnet} },
			want:   false,
		},
		{
			name: "approved and announced subnet",
			mutate: func(n *Node) {
				n.Hostinfo.RoutableIPs = []netip.Prefix{subnet}
				n.ApprovedRoutes = []netip.Prefix{subnet}
			},
			want: true,
		},
		{
			name: "approved and announced exit",
			mutate: func(n *Node) {
				n.Hostinfo.RoutableIPs = []netip.Prefix{exit}
				n.ApprovedRoutes = []netip.Prefix{exit}
			},
			want: true,
		},
		{
			name:   "user association cleared",
			mutate: func(n *Node) { n.User = nil },
			want:   true,
		},
		{
			name:   "user association moved",
			mutate: func(n *Node) { n.User = &User{ID: 8} },
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userID := uint(7)

			base := policyChangeTestNode()
			base.UserID = &userID
			base.User = &User{ID: userID}

			other := *base.Clone()
			tt.mutate(&other)

			require.Equal(t, tt.want, other.View().HasPolicyChange(base.View()))
		})
	}
}

func TestNodeIsExpiredAt(t *testing.T) {
	now := time.Now()
	zero := time.Time{}
	justBefore := now.Add(-time.Nanosecond)

	tests := []struct {
		name   string
		expiry *time.Time
		want   bool
	}{
		{name: "nil expiry", expiry: nil, want: false},
		{name: "zero expiry", expiry: &zero, want: false},
		{name: "expiry equals now", expiry: &now, want: false},
		{name: "now one nanosecond after expiry", expiry: &justBefore, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Node{Expiry: tt.expiry}
			require.Equal(t, tt.want, n.IsExpiredAt(now))
			require.Equal(t, tt.want, n.View().IsExpiredAt(now))
		})
	}

	t.Run("invalid view", func(t *testing.T) {
		require.True(t, NodeView{}.IsExpiredAt(now),
			"an invalid view counts as expired, like IsExpired")
	})
}

func TestHasPolicyChangeSharedRouteInputs(t *testing.T) {
	subnet := netip.MustParsePrefix("10.0.0.0/24")
	exit := netip.MustParsePrefix("::/0")
	base := Node{
		Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{subnet, exit}},
		ApprovedRoutes: []netip.Prefix{subnet, exit},
	}

	for _, tt := range []struct {
		name   string
		mutate func(*Node)
		want   bool
	}{
		{name: "shared slices", mutate: func(*Node) {}},
		{name: "equal slices", mutate: func(n *Node) {
			n.Hostinfo = n.Hostinfo.Clone()
			n.ApprovedRoutes = []netip.Prefix{subnet, exit}
		}},
		{name: "reordered slices", mutate: func(n *Node) {
			n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{exit, subnet}}
			n.ApprovedRoutes = []netip.Prefix{exit, subnet}
		}},
		{name: "approval removed", mutate: func(n *Node) {
			n.ApprovedRoutes = []netip.Prefix{subnet}
		}, want: true},
		{name: "announcement removed", mutate: func(n *Node) {
			n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{subnet}}
		}, want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			other := base
			tt.mutate(&other)
			require.Equal(t, tt.want, base.View().HasPolicyChange(other.View()))
		})
	}

	shared := base

	var changed bool

	allocs := testing.AllocsPerRun(10, func() {
		changed = base.View().HasPolicyChange(shared.View())
	})

	require.False(t, changed)
	require.Zero(t, allocs, "unchanged route inputs should not derive route lists")
}

func TestNodeDerivedRoutes(t *testing.T) {
	a := netip.MustParsePrefix("10.0.0.0/24")
	b := netip.MustParsePrefix("10.1.0.0/24")
	x := netip.MustParsePrefix("10.2.0.0/24")
	exit4 := netip.MustParsePrefix("0.0.0.0/0")
	exit6 := netip.MustParsePrefix("::/0")

	for _, tt := range []struct {
		name                                string
		announced, approved, subnets, exits []netip.Prefix
	}{
		{
			name:      "subnets follow announcement order without duplicates",
			announced: []netip.Prefix{b, a, x, b, a, b},
			approved:  []netip.Prefix{a, b, b},
			subnets:   []netip.Prefix{b, a},
		},
		{
			name:      "exit routes follow announcement order without duplicates",
			announced: []netip.Prefix{exit6, exit4, exit6, exit4, a},
			approved:  []netip.Prefix{exit4, exit6, exit4},
			exits:     []netip.Prefix{exit6, exit4},
		},
		{
			name:      "mixed routes",
			announced: []netip.Prefix{b, exit6, x, exit6, a, b, exit4},
			approved:  []netip.Prefix{exit4, a, exit6, b},
			subnets:   []netip.Prefix{b, a},
			exits:     []netip.Prefix{exit6, exit4},
		},
		{name: "nothing approved", announced: []netip.Prefix{b, exit6, a, exit4}},
		{
			name:      "empty approvals",
			announced: []netip.Prefix{a, exit4},
			approved:  []netip.Prefix{},
		},
		{name: "nothing announced", approved: []netip.Prefix{a, exit4}},
		{
			name:      "unannounced approvals",
			announced: []netip.Prefix{a},
			approved:  []netip.Prefix{b, exit4},
		},
		{
			name:      "exit families differ",
			announced: []netip.Prefix{exit4},
			approved:  []netip.Prefix{exit6},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			announced := slices.Clone(tt.announced)
			approved := slices.Clone(tt.approved)
			n := Node{
				Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: tt.announced},
				ApprovedRoutes: tt.approved,
			}

			require.Equal(t, tt.subnets, n.SubnetRoutes())
			require.Equal(t, tt.exits, n.ExitRoutes())
			require.Equal(t, announced, n.AnnouncedRoutes(),
				"announcements must remain immutable")
			require.Equal(t, Prefixes(approved), n.ApprovedRoutes,
				"approvals must remain immutable")
		})
	}

	n := Node{ApprovedRoutes: []netip.Prefix{a, exit4}}
	require.Nil(t, n.SubnetRoutes())
	require.Nil(t, n.ExitRoutes())
}

func subnetRouter(count int) Node {
	routes := make([]netip.Prefix, count)

	ip := netip.MustParseAddr("10.0.0.0")
	for i := range routes {
		routes[i] = netip.PrefixFrom(ip, 32)
		ip = ip.Next()
	}

	return Node{
		Hostinfo:       &tailcfg.Hostinfo{RoutableIPs: routes},
		ApprovedRoutes: routes,
	}
}

// IsExitNode runs per viewer and peer pair; a subnet router must answer it
// without collecting its subnet routes.
func TestIsExitNodeSubnetRouterAllocs(t *testing.T) {
	n := subnetRouter(4096)

	var exit bool

	allocs := testing.AllocsPerRun(10, func() {
		exit = n.IsExitNode()
	})

	require.False(t, exit)
	require.Zero(t, allocs)
}

// TestCanAccessRoutesExitNeedsInternet checks that a viewer is offered a
// peer's exit routes only when one of its rules reaches the internet, not for
// any rule whose destination overlaps /0.
func TestCanAccessRoutesExitNeedsInternet(t *testing.T) {
	viewer := Node{IPv4: new(netip.MustParseAddr("100.64.0.1"))}
	routes := []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6(), netip.MustParsePrefix("10.40.7.0/24")}
	rule := func(src string, dsts ...string) []matcher.Match {
		r := tailcfg.FilterRule{SrcIPs: []string{src}}
		for _, dst := range dsts {
			r.DstPorts = append(r.DstPorts, tailcfg.NetPortRange{IP: dst, Ports: tailcfg.PortRangeAny})
		}

		return matcher.MatchesFromFilterRules([]tailcfg.FilterRule{r})
	}

	internet := util.PrefixesToString(util.TheInternet().Prefixes())

	for name, tt := range map[string]struct {
		matchers []matcher.Match
		want     []netip.Prefix
	}{
		"to a subnet":       {rule("100.64.0.1", "10.40.7.0/24"), routes[2:]},
		"from anywhere":     {rule("*", "100.64.0.1"), routes[2:]},
		"to everything":     {rule("100.64.0.1", "*"), routes},
		"to the internet":   {rule("100.64.0.1", internet...), routes[:2]},
		"to another viewer": {rule("100.64.0.1", "100.64.0.2"), nil},
	} {
		assert.Equalf(t, tt.want, viewer.CanAccessRoutes(tt.matchers, routes), "%s", name)
	}
}

func TestCanAccessRoutesMatchesReference(t *testing.T) {
	prefixStrings := []string{
		"100.64.0.1/32", "100.64.0.2/32", "100.64.0.0/24",
		"10.0.0.0/24", "10.0.1.0/24", "10.0.0.0/8", "192.168.0.0/16",
		"fd7a:115c:a1e0::1/128", "fd7a:115c:a1e0::2/128", "fd7a:115c:a1e0::/64",
		"2001:db8::/32", "2001:db8:1::/64",
		"fd7a:115c:a1e0:b1a:0:7:a00:0/120",
		"0.0.0.0/0", "::/0", "0.0.0.0/1", "::/1",
	}
	prefixes := util.MustStringsToPrefixes(prefixStrings)
	routePool := append(slices.Clone(prefixes), netip.Prefix{})
	matchPool := append([]string{"*"}, prefixStrings...)
	prefixGen := rapid.SampledFrom(prefixes)
	matchGen := rapid.SampledFrom(matchPool)

	rapid.Check(t, func(rt *rapid.T) {
		n := Node{
			Hostinfo: &tailcfg.Hostinfo{
				RoutableIPs: rapid.SliceOfN(prefixGen, 0, 8).Draw(rt, "announced"),
			},
			ApprovedRoutes: rapid.SliceOfN(prefixGen, 0, 8).Draw(rt, "approved"),
		}
		if rapid.Bool().Draw(rt, "hasIPv4") {
			ip := rapid.SampledFrom([]string{
				"100.64.0.1", "100.64.0.2", "10.0.0.1", "192.168.1.1",
			}).Draw(rt, "ipv4")
			n.IPv4 = new(netip.MustParseAddr(ip))
		}

		if rapid.Bool().Draw(rt, "hasIPv6") {
			ip := rapid.SampledFrom([]string{
				"fd7a:115c:a1e0::1", "fd7a:115c:a1e0::2", "2001:db8::1",
			}).Draw(rt, "ipv6")
			n.IPv6 = new(netip.MustParseAddr(ip))
		}

		count := rapid.IntRange(0, 5).Draw(rt, "matchers")
		matchers := make([]matcher.Match, 0, count)

		for i := range count {
			sources := rapid.SliceOfN(matchGen, 0, 4).Draw(
				rt, fmt.Sprintf("sources-%d", i),
			)
			destinations := rapid.SliceOfN(matchGen, 0, 4).Draw(
				rt, fmt.Sprintf("destinations-%d", i),
			)

			rule := tailcfg.FilterRule{SrcIPs: sources}
			for _, dst := range destinations {
				rule.DstPorts = append(rule.DstPorts, tailcfg.NetPortRange{
					IP: dst, Ports: tailcfg.PortRangeAny,
				})
			}

			matchers = append(matchers, matcher.MatchFromFilterRule(rule))
		}

		routes := rapid.SliceOfN(rapid.SampledFrom(routePool), 0, 16).Draw(rt, "routes")

		var want []netip.Prefix

		for _, route := range routes {
			allowed := canAccessRouteReference(&n, matchers, route)
			require.Equal(rt, allowed, n.CanAccessRoute(matchers, route))

			if allowed {
				want = append(want, route)
			}
		}

		require.Equal(rt, want, n.CanAccessRoutes(matchers, routes))
		require.Equal(rt, want, n.View().CanAccessRoutes(matchers, routes))
	})

	var invalid NodeView

	require.Nil(t, invalid.CanAccessRoutes(
		matcher.MatchesFromFilterRules(tailcfg.FilterAllowAll), prefixes,
	))
}

func canAccessRouteReference(
	node *Node,
	matchers []matcher.Match,
	route netip.Prefix,
) bool {
	src := node.IPs()
	subnetRoutes := node.SubnetRoutes()

	if tsaddr.IsExitRoute(route) {
		for _, matcher := range matchers {
			fromNode := matcher.SrcsContainsIPs(src...) ||
				(len(subnetRoutes) > 0 && matcher.SrcsOverlapsPrefixes(subnetRoutes...))
			if fromNode && matcher.DestsIsTheInternet() {
				return true
			}
		}

		return false
	}

	for _, matcher := range matchers {
		if matcher.SrcsContainsIPs(src...) && matcher.DestsOverlapsPrefixes(route) {
			return true
		}

		if matcher.SrcsOverlapsPrefixes(route) && matcher.DestsContainsIP(src...) {
			return true
		}

		// A subnet router acts on behalf of its advertised subnets.
		// If the node's approved subnet routes overlap the source set
		// and the route overlaps the destination set, the router needs
		// this route to forward traffic from its local subnet.
		if len(subnetRoutes) > 0 {
			if matcher.SrcsOverlapsPrefixes(subnetRoutes...) &&
				matcher.DestsOverlapsPrefixes(route) {
				return true
			}

			// Reverse: traffic from the route's subnet is destined for
			// this node's subnets; the router needs the route for return
			// traffic.
			if matcher.SrcsOverlapsPrefixes(route) &&
				matcher.DestsOverlapsPrefixes(subnetRoutes...) {
				return true
			}
		}
	}

	return false
}

func TestBoundHostinfo(t *testing.T) {
	stock := func() *tailcfg.Hostinfo {
		return &tailcfg.Hostinfo{
			IPNVersion:   "1.96.0",
			OS:           "linux",
			OSVersion:    "6.12.0",
			Hostname:     "laptop",
			RoutableIPs:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
			RequestTags:  []string{"tag:server"},
			Services:     []tailcfg.Service{{Proto: tailcfg.PeerAPI4, Port: 41641}},
			SSH_HostKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPc"},
			NetInfo: &tailcfg.NetInfo{
				PreferredDERP: 1,
				DERPLatency:   map[string]float64{"1-v4": 0.01, "2-v4": 0.02},
			},
		}
	}

	strs := func(n int) []string {
		s := make([]string, n)
		for i := range s {
			s[i] = fmt.Sprintf("entry-%d", i)
		}

		return s
	}

	t.Run("stock report is kept as is", func(t *testing.T) {
		hi := stock()
		want := hi.Clone()
		services := hi.Services

		require.NoError(t, BoundHostinfo(hi))
		require.Equal(t, want, hi)
		require.Same(t, &services[0], &hi.Services[0],
			"a list within bounds must not be copied")
	})

	// The longest hostnames in the node name capture: SaaS keeps each raw
	// and derives a label cut at 63 bytes, so the bound must not cut them.
	t.Run("captured long hostnames are kept as is", func(t *testing.T) {
		for _, tc := range []struct{ hostname, label string }{
			{
				hostname: "label63-" + strings.Repeat("a", 55),
				label:    "label63-" + strings.Repeat("a", 55),
			},
			{
				hostname: "label64-" + strings.Repeat("b", 56),
				label:    "label64-" + strings.Repeat("b", 55),
			},
			{
				hostname: "dotted-" + strings.Repeat("d", 56) +
					"." + strings.Repeat("e", 63) +
					"." + strings.Repeat("f", 63) +
					"." + strings.Repeat("g", 61),
				label: "dotted-" + strings.Repeat("d", 56),
			},
		} {
			hi := stock()
			hi.Hostname = tc.hostname

			require.NoError(t, BoundHostinfo(hi))
			require.Equal(t, tc.hostname, hi.Hostname)
			require.Equal(t, tc.label, dnsname.SanitizeHostname(hi.Hostname))
		}
	})

	t.Run("long lists are cut to their head and copied", func(t *testing.T) {
		hi := stock()

		hi.Services = make([]tailcfg.Service, 1000)
		for i := range hi.Services {
			hi.Services[i] = tailcfg.Service{Proto: tailcfg.TCP, Port: uint16(i)}
		}

		hi.RequestTags = strs(1000)
		hi.WoLMACs = strs(1000)
		hi.SSH_HostKeys = strs(1000)

		services := hi.Services
		lists := map[string][]string{
			"RequestTags":  hi.RequestTags,
			"WoLMACs":      hi.WoLMACs,
			"SSH_HostKeys": hi.SSH_HostKeys,
		}

		require.NoError(t, BoundHostinfo(hi))

		require.Len(t, hi.Services, MaxReportedListLen)
		require.NotSame(t, &services[0], &hi.Services[0],
			"the cut tail must not stay reachable")
		require.Equal(t, uint16(MaxReportedListLen-1),
			hi.Services[MaxReportedListLen-1].Port)

		for name, got := range map[string][]string{
			"RequestTags":  hi.RequestTags,
			"WoLMACs":      hi.WoLMACs,
			"SSH_HostKeys": hi.SSH_HostKeys,
		} {
			require.Len(t, got, MaxReportedListLen, name)
			require.NotSame(t, &lists[name][0], &got[0], name)
			require.Equal(t, "entry-0", got[0], name)
		}
	})

	t.Run("long hostname is cut", func(t *testing.T) {
		hi := stock()
		hi.Hostname = strings.Repeat("a", 1<<20)

		require.NoError(t, BoundHostinfo(hi))

		// Compare lengths, not strings: a failure must not print a megabyte.
		got := len(hi.Hostname)
		require.Equal(t, MaxHostnameLength, got)
	})

	t.Run("long hostname is cut at a rune boundary", func(t *testing.T) {
		long := strings.Repeat("é", 1<<19)

		hi := stock()
		hi.Hostname = long

		require.NoError(t, BoundHostinfo(hi))
		require.True(t, utf8.ValidString(hi.Hostname), "cut must not split a rune")
		require.LessOrEqual(t, len(hi.Hostname), MaxHostnameLength)
		require.GreaterOrEqual(t, len(hi.Hostname), MaxHostnameLength-utf8.UTFMax)
		require.True(t, strings.HasPrefix(long, hi.Hostname))
	})

	t.Run("routes are cut at the route bound", func(t *testing.T) {
		hi := stock()

		hi.RoutableIPs = make([]netip.Prefix, 5000)
		for i := range hi.RoutableIPs {
			addr := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
			hi.RoutableIPs[i] = netip.PrefixFrom(addr, 32)
		}

		routes := hi.RoutableIPs

		require.NoError(t, BoundHostinfo(hi))
		require.Len(t, hi.RoutableIPs, MaxRoutableIPs)
		require.NotSame(t, &routes[0], &hi.RoutableIPs[0])
		require.Equal(t, routes[:MaxRoutableIPs], hi.RoutableIPs)
	})

	t.Run("routes do not count against the size budget", func(t *testing.T) {
		hi := stock()

		hi.RoutableIPs = make([]netip.Prefix, MaxRoutableIPs)
		for i := range hi.RoutableIPs {
			addr := netip.AddrFrom16(
				[16]byte{0xfd, 0, 0, 0, 0, 0, byte(i >> 8), byte(i)},
			)
			hi.RoutableIPs[i] = netip.PrefixFrom(addr, 64)
		}

		require.NoError(t, BoundHostinfo(hi))
		require.Len(t, hi.RoutableIPs, MaxRoutableIPs)
	})

	t.Run("large DERP latency map is dropped", func(t *testing.T) {
		hi := stock()

		hi.NetInfo.DERPLatency = make(map[string]float64, 1000)
		for i := range 1000 {
			hi.NetInfo.DERPLatency[fmt.Sprintf("%d-v4", i)] = 0.01
		}

		require.NoError(t, BoundHostinfo(hi))
		require.Nil(t, hi.NetInfo.DERPLatency)
		require.Equal(t, tailcfg.DERPRegionID(1), hi.NetInfo.PreferredDERP,
			"the rest of NetInfo is kept")
	})

	t.Run("oversized remaining fields are refused", func(t *testing.T) {
		hi := stock()
		hi.OSVersion = strings.Repeat("v", 64<<10)

		err := BoundHostinfo(hi)
		require.ErrorIs(t, err, ErrHostinfoTooLarge)
	})

	t.Run("NetInfo has a budget of its own", func(t *testing.T) {
		// A report without NetInfo keeps the stored one, so what is stored
		// can hold a full NetInfo next to full other fields.
		hi := stock()
		hi.OSVersion = strings.Repeat("v", 60<<10)
		hi.NetInfo.LinkType = strings.Repeat("l", 60<<10)
		require.NoError(t, BoundHostinfo(hi))

		hi.NetInfo.LinkType = strings.Repeat("l", 64<<10)
		require.ErrorIs(t, BoundHostinfo(hi), ErrHostinfoTooLarge)
	})

	t.Run("nil is fine", func(t *testing.T) {
		require.NoError(t, BoundHostinfo(nil))
	})
}

func TestBoundMapRequest(t *testing.T) {
	endpoints := make([]netip.AddrPort, 1000)
	endpointTypes := make([]tailcfg.EndpointType, 1000)

	for i := range endpoints {
		endpoints[i] = netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(i))
		endpointTypes[i] = tailcfg.EndpointType(i % 5)
	}

	req := &tailcfg.MapRequest{
		Endpoints:     slices.Clone(endpoints),
		EndpointTypes: slices.Clone(endpointTypes),
		Hostinfo:      &tailcfg.Hostinfo{Hostname: strings.Repeat("a", 1<<20)},
	}

	require.NoError(t, BoundMapRequest(req))

	require.Equal(t, endpoints[:MaxReportedListLen], req.Endpoints)

	require.Equal(t, endpointTypes[:MaxReportedListLen], req.EndpointTypes,
		"types must stay aligned with their endpoints")

	gotHostname := len(req.Hostinfo.Hostname)
	require.Equal(t, MaxHostnameLength, gotHostname, "the Hostinfo is bounded too")

	t.Run("no Hostinfo and no endpoints", func(t *testing.T) {
		req := &tailcfg.MapRequest{}
		require.NoError(t, BoundMapRequest(req))
		require.Nil(t, req.Endpoints, "nil endpoints mean unchanged and must stay nil")
	})

	t.Run("oversized Hostinfo is refused", func(t *testing.T) {
		req := &tailcfg.MapRequest{
			Hostinfo: &tailcfg.Hostinfo{OSVersion: strings.Repeat("v", 64<<10)},
		}
		require.ErrorIs(t, BoundMapRequest(req), ErrHostinfoTooLarge)
	})
}

// TestBoundMapRequestRepeatedKeys pins that a list sent twice in one body
// keeps nothing of the first. The decoder reuses the slice for the second
// list, so a bound that only reads the length leaves the first in capacity.
func TestBoundMapRequestRepeatedKeys(t *testing.T) {
	report := func(n int) []byte {
		req := tailcfg.MapRequest{Hostinfo: &tailcfg.Hostinfo{}}
		hi := req.Hostinfo

		for i := range n {
			req.Endpoints = append(req.Endpoints,
				netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(i)))
			req.EndpointTypes = append(req.EndpointTypes, tailcfg.EndpointLocal)
			hi.RoutableIPs = append(hi.RoutableIPs,
				netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), 32))
			hi.RequestTags = append(hi.RequestTags, fmt.Sprintf("tag:t%d", i))
			hi.WoLMACs = append(hi.WoLMACs, fmt.Sprintf("00:00:00:00:00:%02x", i))
			hi.SSH_HostKeys = append(hi.SSH_HostKeys, fmt.Sprintf("key-%d", i))
			hi.Services = append(hi.Services, tailcfg.Service{
				Proto:       tailcfg.TCP,
				Port:        uint16(i),
				Description: strings.Repeat("d", 1<<10),
			})
		}

		encoded, err := json.Marshal(req)
		require.NoError(t, err)

		return encoded
	}

	// Every key of the long report appears again with a one-entry list.
	long, short := report(8), report(1)
	raw := slices.Concat(long[:len(long)-1], []byte{','}, short[1:])

	var req tailcfg.MapRequest
	require.NoError(t, json.Unmarshal(raw, &req))
	require.NoError(t, BoundMapRequest(&req))

	hi := req.Hostinfo
	for name, lenCap := range map[string][2]int{
		"Endpoints":     {len(req.Endpoints), cap(req.Endpoints)},
		"EndpointTypes": {len(req.EndpointTypes), cap(req.EndpointTypes)},
		"RoutableIPs":   {len(hi.RoutableIPs), cap(hi.RoutableIPs)},
		"RequestTags":   {len(hi.RequestTags), cap(hi.RequestTags)},
		"WoLMACs":       {len(hi.WoLMACs), cap(hi.WoLMACs)},
		"SSH_HostKeys":  {len(hi.SSH_HostKeys), cap(hi.SSH_HostKeys)},
		"Services":      {len(hi.Services), cap(hi.Services)},
	} {
		require.Equal(t, 1, lenCap[0], name)
		require.Equal(t, lenCap[0], lenCap[1],
			"%s keeps the first list past its length", name)
	}
}
