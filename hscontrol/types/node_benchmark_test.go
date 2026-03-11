package types

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"tailscale.com/tailcfg"
)

func BenchmarkNodeViewCanAccess(b *testing.B) {
	addr := func(ip string) *netip.Addr {
		parsed := netip.MustParseAddr(ip)
		return &parsed
	}

	rules := []tailcfg.FilterRule{
		{
			SrcIPs: []string{"100.64.0.1/32"},
			DstPorts: []tailcfg.NetPortRange{
				{
					IP:    "100.64.0.2/32",
					Ports: tailcfg.PortRangeAny,
				},
			},
		},
	}
	matchers := matcher.MatchesFromFilterRules(rules)

	derpLatency := make(map[string]float64, 256)
	for i := range 128 {
		derpLatency[fmt.Sprintf("%d-v4", i)] = float64(i) / 10
		derpLatency[fmt.Sprintf("%d-v6", i)] = float64(i) / 10
	}

	src := Node{
		IPv4: addr("100.64.0.1"),
	}
	dst := Node{
		IPv4: addr("100.64.0.2"),
		Hostinfo: &tailcfg.Hostinfo{
			NetInfo: &tailcfg.NetInfo{
				DERPLatency: derpLatency,
			},
		},
	}

	srcView := src.View()
	dstView := dst.View()

	if !srcView.CanAccess(matchers, dstView) {
		b.Fatal("benchmark setup error: expected source to access destination")
	}

	b.Run("pointer", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for b.Loop() {
			srcView.CanAccess(matchers, dstView)
		}
	})

	b.Run("struct clone", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for b.Loop() {
			src.CanAccess(matchers, dstView.AsStruct())
		}
	})
}
