package matcher

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func TestMatchFromFilterRuleIncludesCapGrantDests(t *testing.T) {
	rule := tailcfg.FilterRule{
		SrcIPs: []string{"100.64.0.1/32"},
		DstPorts: []tailcfg.NetPortRange{
			{
				IP:    "100.64.0.2",
				Ports: tailcfg.PortRangeAny,
			},
		},
		CapGrant: []tailcfg.CapGrant{
			{
				Dsts: []netip.Prefix{
					netip.MustParsePrefix("100.64.0.3/32"),
					netip.MustParsePrefix("100.64.0.0/24"),
				},
			},
		},
	}

	got := MatchFromFilterRule(rule)

	require.True(t, got.SrcsContainsIPs(netip.MustParseAddr("100.64.0.1")))
	require.True(
		t,
		got.DestsContainsIP(
			netip.MustParseAddr("100.64.0.2"),
			netip.MustParseAddr("100.64.0.3"),
			netip.MustParseAddr("100.64.0.77"),
		),
	)
}
