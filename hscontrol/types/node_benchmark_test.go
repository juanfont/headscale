package types

import (
	"fmt"
	"net/netip"
	"slices"
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

func BenchmarkNodeDerivedRoutes(b *testing.B) {
	for _, count := range []int{1024, 8192} {
		announced := make([]netip.Prefix, count, count+2)

		ip := netip.MustParseAddr("10.0.0.0")
		for i := range announced {
			announced[i] = netip.PrefixFrom(ip, 32)
			ip = ip.Next()
		}

		announced = append(announced,
			netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"))

		for _, approved := range []bool{false, true} {
			name := fmt.Sprintf("approved=%t/routes=%d", approved, count)
			b.Run(name, func(b *testing.B) {
				n := Node{Hostinfo: &tailcfg.Hostinfo{RoutableIPs: announced}}
				if approved {
					n.ApprovedRoutes = slices.Clone(announced)
				}

				var subnets, exits []netip.Prefix

				b.ReportAllocs()

				for b.Loop() {
					subnets = n.SubnetRoutes()
					exits = n.ExitRoutes()
				}

				if approved {
					if len(subnets) != count || len(exits) != 2 {
						b.Fatalf("unexpected derived routes: %d subnets, %d exits",
							len(subnets), len(exits))
					}
				} else if len(subnets) != 0 || len(exits) != 0 {
					b.Fatal("unapproved routes must not be served")
				}
			})
		}
	}
}

func BenchmarkNodeIsExitNodeSubnetRouter(b *testing.B) {
	for _, count := range []int{4096, 16384} {
		b.Run(fmt.Sprintf("routes=%d", count), func(b *testing.B) {
			n := subnetRouter(count)

			b.ReportAllocs()

			for b.Loop() {
				n.IsExitNode()
			}
		})
	}
}
