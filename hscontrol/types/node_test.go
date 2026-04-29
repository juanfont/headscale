package types

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
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
		// Subnet-to-subnet tests for issue #3157.
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
			// peer visibility comes from ReduceNodes checking
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

func TestNodeRegisterMethodToV1Enum(t *testing.T) {
	tests := []struct {
		name string
		node Node
		want v1.RegisterMethod
	}{
		{
			name: "authkey",
			node: Node{
				ID:             1,
				RegisterMethod: util.RegisterMethodAuthKey,
			},
			want: v1.RegisterMethod_REGISTER_METHOD_AUTH_KEY,
		},
		{
			name: "oidc",
			node: Node{
				ID:             1,
				RegisterMethod: util.RegisterMethodOIDC,
			},
			want: v1.RegisterMethod_REGISTER_METHOD_OIDC,
		},
		{
			name: "cli",
			node: Node{
				ID:             1,
				RegisterMethod: util.RegisterMethodCLI,
			},
			want: v1.RegisterMethod_REGISTER_METHOD_CLI,
		},
		{
			name: "unknown",
			node: Node{
				ID: 0,
			},
			want: v1.RegisterMethod_REGISTER_METHOD_UNSPECIFIED,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.node.RegisterMethodToV1Enum()

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("RegisterMethodToV1Enum() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

// TestHasNetworkChanges tests the NodeView method for detecting
// when a node's network properties have changed.
func TestHasNetworkChanges(t *testing.T) {
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
			changed: true,
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
			changed: true,
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
			changed: true,
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
			got := tt.new.View().HasNetworkChanges(tt.old.View())
			if got != tt.changed {
				t.Errorf("HasNetworkChanges() = %v, want %v", got, tt.changed)
			}
		})
	}
}

func TestNodeProto_ClientVersion(t *testing.T) {
	tests := []struct {
		name        string
		hostinfo    *tailcfg.Hostinfo
		wantVersion string
	}{
		{
			name:        "node-with-client-version",
			hostinfo:    &tailcfg.Hostinfo{IPNVersion: "1.50.0"},
			wantVersion: "1.50.0",
		},
		{
			name:        "node-with-different-version",
			hostinfo:    &tailcfg.Hostinfo{IPNVersion: "1.76.1"},
			wantVersion: "1.76.1",
		},
		{
			name:        "node-without-hostinfo",
			hostinfo:    nil,
			wantVersion: "",
		},
		{
			name:        "node-with-empty-version",
			hostinfo:    &tailcfg.Hostinfo{IPNVersion: ""},
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &Node{
				ID:       1,
				Hostname: "test-node",
				Hostinfo: tt.hostinfo,
			}
			proto := node.Proto()
			if got := proto.GetClientVersion(); got != tt.wantVersion {
				t.Errorf("Proto().GetClientVersion() = %q, want %q", got, tt.wantVersion)
			}
		})
	}
}
