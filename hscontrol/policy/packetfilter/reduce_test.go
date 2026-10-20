package packetfilter

import (
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"testing"

	"github.com/juanfont/headscale/hscontrol/ipset"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
)

func addrPointer(value string) *netip.Addr {
	addr := netip.MustParseAddr(value)
	return &addr
}

func TestReduceAllocationTracksSelectedRules(t *testing.T) {
	selected := NewNetworkRule(testSet(t, "192.0.2.1/32"), []Destination{
		{Addresses: testSet(t, "100.64.0.1/32"), Ports: tailcfg.PortRangeAny},
	}, []ipproto.Proto{6})
	unrelated := NewNetworkRule(ipset.All(), []Destination{
		{Addresses: testSet(t, "100.64.0.99/32"), Ports: tailcfg.PortRangeAny},
	}, nil)
	target := Target{IPv4: addrPointer("100.64.0.1")}

	for _, inputSize := range []int{16, 4096} {
		t.Run(strconv.Itoa(inputSize), func(t *testing.T) {
			rules := slices.Repeat([]Rule{unrelated}, inputSize)
			rules[inputSize/2] = selected

			var results [16][]Rule

			runtime.GC()

			var before, after runtime.MemStats

			runtime.ReadMemStats(&before)

			for i := range results {
				results[i] = Reduce(rules, target)
			}

			runtime.ReadMemStats(&after)

			// One selected rule must not allocate storage for unrelated rules.
			bytesPerResult := (after.TotalAlloc - before.TotalAlloc) / uint64(len(results))
			t.Logf("%d input rules: %d allocated bytes/result", inputSize, bytesPerResult)

			if bytesPerResult > 8<<10 {
				t.Errorf("one selected rule allocated %d bytes; budget is 8 KiB", bytesPerResult)
			}

			for _, result := range results {
				if len(result) != 1 || !result[0].Equal(selected) {
					t.Fatal("reduction changed the selected rule")
				}
			}

			results[0][0] = Rule{}
			if !rules[inputSize/2].Equal(selected) || !results[1][0].Equal(selected) {
				t.Fatal("reduced rule containers share mutable storage")
			}

			runtime.KeepAlive(results)
			runtime.KeepAlive(rules)
		})
	}

	wire := ToTailcfg(Reduce([]Rule{unrelated}, target))
	if wire == nil || len(wire) != 0 {
		t.Fatal("no matching rules must encode an explicit empty revocation")
	}
}

func TestOrdinaryAliasReductionKeepsOnlyRecipient(t *testing.T) {
	// tag:web resolves to two unrelated prefixes, each independently reducible.
	destinations := []Destination{
		{
			Addresses: testSet(t, "100.64.0.1/32"),
			Ports:     tailcfg.PortRange{First: 443, Last: 443},
		},
		{
			Addresses: testSet(t, "100.64.0.3/32"),
			Ports:     tailcfg.PortRange{First: 443, Last: 443},
		},
	}

	rule := NewNetworkRule(ipset.All(), destinations, nil)
	for _, address := range []string{"100.64.0.1", "100.64.0.3"} {
		got := ToTailcfg(Reduce([]Rule{rule}, Target{IPv4: addrPointer(address)}))
		if len(got) != 1 || len(got[0].DstPorts) != 1 ||
			got[0].DstPorts[0].IP != address ||
			got[0].DstPorts[0].Ports != (tailcfg.PortRange{First: 443, Last: 443}) {
			t.Fatalf(
				"%s received another alias member's destination: %+v",
				address,
				got,
			)
		}
	}
}

func TestReduceDestinationGroups(t *testing.T) {
	rangeGroup := testSet(t, "100.64.0.1/32", "100.64.0.2/31", "100.64.0.4/30")
	destinations := []Destination{
		{
			Addresses: testSet(t, "100.64.0.99/32"),
			Ports:     tailcfg.PortRange{First: 22, Last: 22},
		},
		{Addresses: ipset.All(), Ports: tailcfg.PortRange{First: 80, Last: 90}},
		{Addresses: rangeGroup, Ports: tailcfg.PortRange{First: 443, Last: 443}},
		{Addresses: rangeGroup, Ports: tailcfg.PortRange{First: 443, Last: 443}},
	}
	rule := NewNetworkRule(
		testSet(t, "192.0.2.1/32"),
		destinations,
		[]ipproto.Proto{47, 132},
	)

	got := Reduce([]Rule{rule}, Target{IPv4: addrPointer("100.64.0.2")})
	if len(got) != 1 {
		t.Fatalf("got %d rules, want 1", len(got))
	}

	selected := slices.Collect(got[0].Destinations())
	if len(selected) != 3 || !selected[0].Addresses.Equal(ipset.All()) ||
		!selected[1].Addresses.Equal(
			rangeGroup,
		) || !selected[2].Addresses.Equal(rangeGroup) ||
		selected[0].Ports != destinations[1].Ports || selected[1].Ports != destinations[2].Ports ||
		!slices.Equal(slices.Collect(got[0].Protocols()), []ipproto.Proto{47, 132}) {
		t.Fatalf(
			"group coverage, order, duplicate, ports or protocols lost: %+v",
			selected,
		)
	}

	if len(slices.Collect(rule.Destinations())) != 4 ||
		!got[0].Sources().Equal(rule.Sources()) {
		t.Fatal("reduction mutated original rule or sources")
	}
}

func TestReduceApprovedRoutes(t *testing.T) {
	rule := NewNetworkRule(ipset.All(), []Destination{
		{Addresses: testSet(t, "10.20.0.0/16"), Ports: tailcfg.PortRangeAny},
		{Addresses: testSet(t, "2001:db8::/64"), Ports: tailcfg.PortRangeAny},
	}, nil)
	for _, test := range []struct {
		name   string
		target Target
		want   int
	}{
		{name: "unapproved excluded", target: Target{IPv4: addrPointer("100.64.0.1")}, want: 0},
		{name: "subnet overlap narrower", target: Target{SubnetRoutes: []netip.Prefix{netip.MustParsePrefix("10.20.1.0/24")}}, want: 1},
		{name: "subnet overlap broader", target: Target{SubnetRoutes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}, want: 1},
		{name: "IPv4 exit", target: Target{ExitRoutes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}, want: 1},
		{name: "dual exit", target: Target{ExitRoutes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}}, want: 2},
		{name: "IPv6 recipient", target: Target{IPv6: addrPointer("2001:db8::1")}, want: 1},
		{name: "mapped is not native", target: Target{IPv6: addrPointer("::ffff:10.20.1.1")}, want: 0},
		{name: "zone rejected", target: Target{IPv6: addrPointer("2001:db8::1%eth0")}, want: 0},
		{name: "invalid rejected", target: Target{IPv4: new(netip.Addr)}, want: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := Reduce([]Rule{{}, rule}, test.target)

			count := 0
			for _, reduced := range got {
				count += len(slices.Collect(reduced.Destinations()))
			}

			if count != test.want {
				t.Fatalf("got %d selected groups, want %d", count, test.want)
			}
		})
	}
}

func TestReduceCapabilities(t *testing.T) {
	capMap := tailcfg.PeerCapMap{
		"example.com/access": {`{"role":"reader"}`, `{"scope":"all"}`},
	}
	rule := NewCapabilityRule(testSet(t, "192.0.2.1/32"), []CapabilityGrant{
		{Addresses: testSet(t, "100.64.0.0/10", "fd7a:115c:a1e0::/48"), CapMap: capMap},
		{Addresses: testSet(t, "10.20.0.0/16", "10.30.0.0/16"), CapMap: capMap},
		{Addresses: testSet(t, "100.64.0.9/32"), CapMap: nil},
	})
	target := Target{
		IPv4: addrPointer("100.64.0.1"),
		IPv6: addrPointer("fd7a:115c:a1e0::1"),
		SubnetRoutes: []netip.Prefix{
			netip.MustParsePrefix("10.20.1.0/24"),
			netip.MustParsePrefix("10.20.2.0/24"),
		},
		ExitRoutes: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		},
	}

	got := Reduce([]Rule{rule}, target)
	if len(got) != 1 {
		t.Fatalf("capability-only rule was not reachable: %+v", got)
	}

	grants := got[0].CapGrants()
	if len(grants) != 2 || !grants[0].Addresses.Equal(testSet(t, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")) ||
		!grants[1].Addresses.Equal(testSet(t, "10.20.0.0/16")) ||
		!reflect.DeepEqual(grants[0].CapMap, capMap) ||
		!reflect.DeepEqual(grants[1].CapMap, capMap) {
		t.Fatalf("capability narrowing, subnet scope, or payload lost: %+v", grants)
	}

	if !got[0].DestinationSet().
		Equal(testSet(t, "100.64.0.1/32", "fd7a:115c:a1e0::1/128", "10.20.0.0/16")) {
		t.Fatal("reduced capability union does not match grants")
	}

	if len(Reduce([]Rule{rule}, Target{ExitRoutes: target.ExitRoutes})) != 0 {
		t.Fatal("exit routes selected capability grants")
	}

	if len(Reduce([]Rule{rule}, Target{IPv6: addrPointer("::ffff:100.64.0.1")})) != 0 ||
		len(
			Reduce([]Rule{rule}, Target{IPv6: addrPointer("fd7a:115c:a1e0::1%eth0")}),
		) != 0 {
		t.Fatal("mapped or zoned address selected capability grants")
	}

	if len(rule.CapGrants()) != 3 {
		t.Fatal("capability reduction mutated input rule")
	}
}
