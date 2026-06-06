package v2

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"tailscale.com/tailcfg"
)

// TestCanAccessWithRoutesMatchesCanAccess guards the peer-map optimization:
// CanAccessWithRoutes, fed the same route data CanAccess computes internally,
// must produce identical results. BuildPeerMap relies on this to precompute
// each node's routes once instead of per pair.
func TestCanAccessWithRoutesMatchesCanAccess(t *testing.T) {
	user := types.User{Name: "u"}

	subnetRouter := node("subnet", "100.64.0.1", "fd7a:115c:a1e0::1", user)
	subnetRouter.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}
	subnetRouter.ApprovedRoutes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}

	exitNode := node("exit", "100.64.0.2", "fd7a:115c:a1e0::2", user)
	exitNode.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}
	exitNode.ApprovedRoutes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}

	plain := node("plain", "100.64.0.3", "fd7a:115c:a1e0::3", user)

	matchers := matcher.MatchesFromFilterRules([]tailcfg.FilterRule{
		{
			SrcIPs:   []string{"*"},
			DstPorts: []tailcfg.NetPortRange{{IP: "*", Ports: tailcfg.PortRangeAny}},
		},
	})

	views := []types.NodeView{subnetRouter.View(), exitNode.View(), plain.View()}

	for _, a := range views {
		for _, b := range views {
			if a.ID() == b.ID() {
				continue
			}

			want := a.CanAccess(matchers, b)
			got := a.CanAccessWithRoutes(matchers, b, a.SubnetRoutes(), b.SubnetRoutes(), b.IsExitNode())
			assert.Equalf(t, want, got, "%s -> %s", a.Hostname(), b.Hostname())
		}
	}
}
