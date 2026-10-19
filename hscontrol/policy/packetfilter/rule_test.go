package packetfilter

import (
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/ipset"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
)

func testSet(tb testing.TB, prefixes ...string) ipset.Set {
	tb.Helper()

	var builder ipset.Builder
	for _, prefix := range prefixes {
		builder.AddPrefix(netip.MustParsePrefix(prefix))
	}

	set, err := builder.Build()
	if err != nil {
		tb.Fatal(err)
	}

	return set
}

func TestRuleOwnsInputs(t *testing.T) {
	sources := testSet(t, "100.64.0.1/32")
	destinations := []Destination{{
		Addresses: testSet(t, "100.64.0.2/32"),
		Ports:     tailcfg.PortRange{First: 443, Last: 443},
	}}
	protocols := []ipproto.Proto{17, 6, 6}
	network := NewNetworkRule(sources, destinations, protocols)
	networkHash := network.Hash()
	destinations[0].Ports.First = 80
	destinations[0].Addresses = ipset.All()
	protocols[0] = 47

	got := slices.Collect(network.Destinations())
	if len(got) != 1 || got[0].Ports != (tailcfg.PortRange{First: 443, Last: 443}) ||
		!got[0].Addresses.Equal(testSet(t, "100.64.0.2/32")) {
		t.Fatalf("constructor retained destination inputs: %+v", got)
	}

	got[0].Ports.First = 22

	if !slices.Equal(slices.Collect(network.Protocols()), []ipproto.Proto{6, 17}) ||
		network.Hash() != networkHash || !network.Sources().Equal(sources) {
		t.Fatal("network input mutation changed rule")
	}

	values := []tailcfg.RawMessage{`{"role":"reader"}`, `{"scope":[1,2]}`}
	capMap := tailcfg.PeerCapMap{"example.com/access": values, "example.com/empty": {}}
	grants := []CapabilityGrant{{Addresses: got[0].Addresses, CapMap: capMap}}
	capability := NewCapabilityRule(sources, grants)
	capabilityHash := capability.Hash()
	values[0] = `{"role":"admin"}`

	delete(capMap, "example.com/empty")
	capMap["example.com/new"] = nil
	grants[0].Addresses = ipset.All()
	grants[0].CapMap = nil
	wantMap := tailcfg.PeerCapMap{
		"example.com/access": {`{"role":"reader"}`, `{"scope":[1,2]}`},
		"example.com/empty":  {},
	}

	read := capability.CapGrants()
	if len(read) != 1 || !reflect.DeepEqual(read[0].CapMap, wantMap) ||
		!read[0].Addresses.Equal(testSet(t, "100.64.0.2/32")) {
		t.Fatalf("constructor retained capability inputs: %+v", read)
	}

	read[0].CapMap["example.com/access"][0] = `false`
	delete(read[0].CapMap, "example.com/empty")
	read[0] = CapabilityGrant{}

	if !reflect.DeepEqual(capability.CapGrants()[0].CapMap, wantMap) ||
		capability.Hash() != capabilityHash {
		t.Fatal("CapGrants exposed mutable rule contents")
	}

	if network.Kind() != KindNetwork || capability.Kind() != KindCapability ||
		!capability.DestinationSet().Equal(testSet(t, "100.64.0.2/32")) {
		t.Fatal("kind or derived capability destination index is wrong")
	}
}

func TestRuleHashUsesTypedContent(t *testing.T) {
	source := testSet(t, "100.64.0.0/25", "100.64.0.128/25", "fd7a:115c:a1e0::1/128")
	equivalent := testSet(t, "fd7a:115c:a1e0::1/128", "100.64.0.0/24")
	destinations := []Destination{
		{Addresses: source, Ports: tailcfg.PortRange{First: 80, Last: 90}},
		{Addresses: testSet(t, "100.64.1.1/32"), Ports: tailcfg.PortRangeAny},
	}
	a := NewNetworkRule(source, destinations, []ipproto.Proto{17, 6, 6})

	b := NewNetworkRule(equivalent, destinations, []ipproto.Proto{6, 17})
	if !a.Equal(b) || a.Hash() != b.Hash() {
		t.Fatal("equal typed content depends on construction order or storage")
	}

	if !NewNetworkRule(source, destinations, nil).Equal(
		NewNetworkRule(equivalent, destinations, []ipproto.Proto{58, 17, 6, 1, 6}),
	) {
		t.Fatal("omitted protocols differ from explicit client defaults")
	}

	mutatedPorts := slices.Clone(destinations)
	mutatedPorts[0].Ports.Last++
	reordered := slices.Clone(destinations)
	slices.Reverse(reordered)

	variants := []Rule{
		NewNetworkRule(
			testSet(t, "100.65.0.0/24"),
			destinations,
			[]ipproto.Proto{6, 17},
		),
		NewNetworkRule(source, mutatedPorts, []ipproto.Proto{6, 17}),
		NewNetworkRule(source, reordered, []ipproto.Proto{6, 17}),
		NewNetworkRule(
			source,
			append(slices.Clone(destinations), destinations[0]),
			[]ipproto.Proto{6, 17},
		),
		NewNetworkRule(source, destinations, []ipproto.Proto{6, 17, 47}),
		NewCapabilityRule(source, []CapabilityGrant{{Addresses: source}}),
	}
	for i, variant := range variants {
		if a.Equal(variant) || a.Hash() == variant.Hash() {
			t.Errorf("network semantic difference %d lost", i)
		}
	}

	firstMap := tailcfg.PeerCapMap{}
	firstMap["example.com/b"] = []tailcfg.RawMessage{`1`, `2`}
	firstMap["example.com/a"] = nil
	secondMap := tailcfg.PeerCapMap{}
	secondMap["example.com/a"] = nil
	secondMap["example.com/b"] = []tailcfg.RawMessage{`1`, `2`}
	capRule := func(capMap tailcfg.PeerCapMap) Rule {
		return NewCapabilityRule(
			source,
			[]CapabilityGrant{{Addresses: equivalent, CapMap: capMap}},
		)
	}

	c, d := capRule(firstMap), capRule(secondMap)
	if !c.Equal(d) || c.Hash() != d.Hash() {
		t.Fatal("capability key insertion order changed hash or equality")
	}

	for _, capMap := range []tailcfg.PeerCapMap{
		{"example.com/b": {`2`, `1`}, "example.com/a": nil},
		{"example.com/b": {`1`, `3`}, "example.com/a": nil},
		{"example.com/b": {`1`, `2`}},
		{"example.com/b": {`1`, `2`}, "example.com/a": {}},
	} {
		other := capRule(capMap)
		if c.Equal(other) || c.Hash() == other.Hash() {
			t.Errorf("complete capability payload not compared: %#v", capMap)
		}
	}

	nilMap, emptyMap := capRule(nil), capRule(tailcfg.PeerCapMap{})
	if nilMap.Equal(emptyMap) || nilMap.Hash() == emptyMap.Hash() {
		t.Fatal("nil and empty capability maps lost their distinction")
	}

	if !NewNetworkRule(
		source,
		nil,
		nil,
	).Equal(NewNetworkRule(source, []Destination{}, nil)) {
		t.Fatal("empty network destinations should have equal content")
	}

	if NewNetworkRule(
		source,
		nil,
		nil,
	).Hash() !=
		NewNetworkRule(
			source,
			[]Destination{},
			nil,
		).Hash() {
		t.Fatal("equal empty destination lists hash differently")
	}
}

func TestRuleHashCollisionConfirmation(t *testing.T) {
	source := testSet(t, "100.64.0.1/32")
	a := NewNetworkRule(
		source,
		[]Destination{{Addresses: source, Ports: tailcfg.PortRangeAny}},
		nil,
	)
	b := NewNetworkRule(
		source,
		[]Destination{{Addresses: ipset.All(), Ports: tailcfg.PortRangeAny}},
		nil,
	)

	b.hash = a.hash
	if a.Equal(b) {
		t.Fatal("hash collision bypassed typed equality")
	}

	var zero Rule
	if zero.Kind() != KindInvalid || !zero.Sources().IsEmpty() ||
		!zero.DestinationSet().IsEmpty() || !zero.Equal(Rule{}) || zero.Equal(a) {
		t.Fatal("zero rule is not an empty invalid rule")
	}
}

func TestRuleIterationStops(t *testing.T) {
	destination := Destination{Addresses: ipset.All(), Ports: tailcfg.PortRangeAny}
	rule := NewNetworkRule(ipset.All(), []Destination{destination, destination}, nil)

	count := 0
	for range rule.Destinations() {
		count++
		break
	}

	if count != 1 {
		t.Fatal("destination iteration did not stop")
	}

	count = 0
	for range rule.Protocols() {
		count++
		break
	}

	if count != 1 {
		t.Fatal("protocol iteration did not stop")
	}
}

var benchmarkRules []Rule

func BenchmarkRuleConstruction(b *testing.B) {
	source := testSet(b, "100.64.0.1/32", "fd7a:115c:a1e0::1/128")
	ports := []tailcfg.PortRange{
		{First: 80, Last: 80},
		{First: 443, Last: 443},
		{First: 8000, Last: 8100},
	}
	protocols := [][]ipproto.Proto{{6}, {17}, {1, 58}}
	ordinary := make([]Destination, 0, 4096*len(ports))

	for i := range 4096 {
		var builder ipset.Builder
		builder.AddAddr(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}))

		set, err := builder.Build()
		if err != nil {
			b.Fatal(err)
		}

		for _, port := range ports {
			ordinary = append(ordinary, Destination{Addresses: set, Ports: port})
		}
	}

	irregular := testSet(
		b,
		"10.0.0.1/32",
		"10.0.0.2/31",
		"10.0.0.4/30",
		"2001:db8::1/128",
	)

	self := NewNetworkRule(
		source,
		[]Destination{{Addresses: source, Ports: tailcfg.PortRangeAny}},
		nil,
	)
	for name, destinations := range map[string][]Destination{
		"4096_unique_shared_prefixes": ordinary,
		"irregular_groups": {
			{Addresses: irregular, Ports: ports[0]},
			{Addresses: irregular, Ports: ports[1]},
			{Addresses: ipset.All(), Ports: ports[2]},
		},
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				rules := make([]Rule, 0, len(protocols)+1)
				for _, protocol := range protocols {
					rules = append(
						rules,
						NewNetworkRule(source, destinations, protocol),
					)
				}

				benchmarkRules = append(rules, self)
			}

			b.StopTimer()

			benchmarkRules = nil

			runtime.GC()

			var before, live runtime.MemStats
			runtime.ReadMemStats(&before)

			const generations = 16

			retained := make([][]Rule, generations)
			for i := range retained {
				for _, protocol := range protocols {
					retained[i] = append(
						retained[i],
						NewNetworkRule(source, destinations, protocol),
					)
				}

				retained[i] = append(retained[i], self)
			}

			runtime.GC()
			runtime.ReadMemStats(&live)
			b.ReportMetric(
				(float64(live.HeapAlloc)-float64(before.HeapAlloc))/generations,
				"retained-B/generation",
			)
			runtime.KeepAlive(retained)
		})
	}
}
