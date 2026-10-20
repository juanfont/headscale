package packetfilter

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/ipset"
	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
)

func TestToTailcfgSourceForms(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name   string
		source string
		want   string
	}{
		{"all", "*", "*"},
		{"ipv4 host", "192.0.2.1/32", "192.0.2.1"},
		{"ipv6 host", "2001:db8::1/128", "2001:db8::1"},
		{"ipv4 range", "192.0.2.1-192.0.2.2", "192.0.2.1-192.0.2.2"},
		{"ipv6 range", "2001:db8::1-2001:db8::2", "2001:db8::1-2001:db8::2"},
		{"aligned range", "192.0.2.0-192.0.2.255", "192.0.2.0/24"},
		{"ipv6 prefix", "2001:db8::/64", "2001:db8::/64"},
		{"ipv4 all", "0.0.0.0/0", "0.0.0.0/0"},
		{"ipv6 all", "::/0", "::/0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sources, err := util.ParseIPSet(tt.source, nil)
			if err != nil {
				t.Fatal(err)
			}

			rules := []Rule{
				NewNetworkRule(sources, []Destination{{
					Addresses: ipset.All(), Ports: tailcfg.PortRangeAny,
				}}, nil),
				NewCapabilityRule(sources, []CapabilityGrant{{
					Addresses: ipset.All(),
					CapMap:    tailcfg.PeerCapMap{"example.com/access": nil},
				}}),
			}
			for _, wire := range ToTailcfg(rules) {
				if !slices.Equal(wire.SrcIPs, []string{tt.want}) {
					t.Fatalf("got SrcIPs %v, want %q", wire.SrcIPs, tt.want)
				}
			}
		})
	}
}

func TestToTailcfgCanonicalAddresses(t *testing.T) {
	sources := testSet(
		t,
		"2001:0db8:0:0::1/128",
		"100.64.0.0/25",
		"100.64.0.128/25",
		"::ffff:192.0.2.1/128",
	)
	destinations := []Destination{
		{
			Addresses: testSet(t, "100.64.0.1/32"),
			Ports:     tailcfg.PortRange{First: 443, Last: 443},
		},
		{Addresses: ipset.All(), Ports: tailcfg.PortRangeAny},
		{
			Addresses: testSet(t, "192.0.2.0/25", "192.0.2.128/25", "2001:0db8::2/128"),
			Ports:     tailcfg.PortRange{First: 80, Last: 90},
		},
		{
			Addresses: testSet(t, "100.64.0.1/32"),
			Ports:     tailcfg.PortRange{First: 443, Last: 443},
		},
	}
	network := NewNetworkRule(sources, destinations, []ipproto.Proto{132, 47, 47})
	capability := NewCapabilityRule(sources, []CapabilityGrant{{
		Addresses: testSet(t, "100.64.0.2/32", "2001:db8::/64"),
		CapMap:    tailcfg.PeerCapMap{"example.com/access": {`{"role":"reader"}`}},
	}})
	got := ToTailcfg([]Rule{{}, network, capability})
	wantSources := []string{"100.64.0.0/24", "::ffff:192.0.2.1", "2001:db8::1"}

	want := []tailcfg.FilterRule{
		{
			SrcIPs: wantSources,
			DstPorts: []tailcfg.NetPortRange{
				{IP: "100.64.0.1", Ports: tailcfg.PortRange{First: 443, Last: 443}},
				{IP: "*", Ports: tailcfg.PortRangeAny},
				{IP: "192.0.2.0/24", Ports: tailcfg.PortRange{First: 80, Last: 90}},
				{IP: "2001:db8::2", Ports: tailcfg.PortRange{First: 80, Last: 90}},
				{IP: "100.64.0.1", Ports: tailcfg.PortRange{First: 443, Last: 443}},
			},
			IPProto: []int{47, 132},
		},
		{
			SrcIPs: wantSources,
			CapGrant: []tailcfg.CapGrant{
				{
					Dsts: []netip.Prefix{
						netip.MustParsePrefix("100.64.0.2/32"),
						netip.MustParsePrefix("2001:db8::/64"),
					},
					CapMap: tailcfg.PeerCapMap{
						"example.com/access": {`{"role":"reader"}`},
					},
				},
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("canonical encoder output\ngot:  %#v\nwant: %#v", got, want)
	}

	got[0].SrcIPs[0] = "*"
	got[0].IPProto[0] = 6
	got[0].DstPorts[0].Ports.First = 22
	got[1].CapGrant[0].Dsts[0] = netip.MustParsePrefix("0.0.0.0/0")
	got[1].CapGrant[0].CapMap["example.com/access"][0] = `{"role":"admin"}`

	if !reflect.DeepEqual(ToTailcfg([]Rule{network, capability}), want) {
		t.Fatal("wire output mutation reached immutable rule")
	}

	if got[1].SrcIPs[0] != "100.64.0.0/24" {
		t.Fatal("wire rules share mutable source slices")
	}
}

func TestToTailcfgProtocols(t *testing.T) {
	destination := []Destination{{Addresses: ipset.All(), Ports: tailcfg.PortRangeAny}}
	for _, protocols := range [][]ipproto.Proto{nil, {}, {58, 1, 6, 17, 1}} {
		rule := NewNetworkRule(ipset.All(), destination, protocols)
		if !slices.Equal(
			slices.Collect(rule.Protocols()),
			[]ipproto.Proto{1, 6, 17, 58},
		) {
			t.Fatal("client defaults not explicit in typed rule")
		}

		if len(ToTailcfg([]Rule{rule})[0].IPProto) != 0 {
			t.Fatal("exact client defaults should be omitted on wire")
		}
	}

	for _, protocols := range [][]ipproto.Proto{{1, 6, 17}, {47}, {132}, {1, 6, 17, 47, 58}} {
		rule := NewNetworkRule(ipset.All(), destination, protocols)
		got := ToTailcfg([]Rule{rule})[0].IPProto

		want := make([]int, len(protocols))
		for i, protocol := range protocols {
			want[i] = int(protocol)
		}

		if !slices.Equal(got, want) {
			t.Fatalf(
				"explicit protocol restriction widened: got %v, want %v",
				got,
				want,
			)
		}
	}
}

func TestToTailcfgEmptyRevocation(t *testing.T) {
	for _, rules := range [][]Rule{nil, {}, {{}}} {
		got := ToTailcfg(rules)
		if got == nil || len(got) != 0 {
			t.Fatalf("revocation must be an explicit empty slice: %#v", got)
		}
	}
}

func TestToTailcfgIndependentRules(t *testing.T) {
	addresses := testSet(t, "100.64.0.1/32")
	capMap := tailcfg.PeerCapMap{"example.com/access": {`{"role":"reader"}`}}
	grants := []CapabilityGrant{
		{Addresses: addresses, CapMap: capMap},
		{Addresses: addresses, CapMap: capMap},
	}
	a := NewCapabilityRule(addresses, grants)
	b := NewCapabilityRule(addresses, grants)
	wire := ToTailcfg([]Rule{a, a, b})
	wire[0].CapGrant[0].CapMap["example.com/access"][0] = `{"role":"admin"}`

	wire[0].CapGrant[0].Dsts[0] = netip.MustParsePrefix("0.0.0.0/0")
	if wire[0].CapGrant[1].CapMap["example.com/access"][0] != `{"role":"reader"}` {
		t.Fatal("encoded grants share mutable capability values")
	}

	for _, index := range []int{1, 2} {
		if wire[index].CapGrant[0].CapMap["example.com/access"][0] != `{"role":"reader"}` ||
			wire[index].CapGrant[0].Dsts[0] != netip.MustParsePrefix("100.64.0.1/32") {
			t.Fatal("encoded rules share mutable payloads or destination slices")
		}
	}

	if !a.Equal(b) || a.Hash() != b.Hash() {
		t.Fatal("wire mutation reached a source rule")
	}
}
