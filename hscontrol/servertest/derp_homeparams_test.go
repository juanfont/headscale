package servertest_test

import (
	"maps"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// TestDERPHomeParamsReachClient pins what a real client keeps of the
// DERP region scores headscale sends (#2918). Without scores the map has no
// HomeParams, as SaaS sends (nodeattrs-derpmap-* captures). A client keeps
// its last scores when a later map has none: nil means "no change", and an
// empty map is dropped by omitempty on the wire. Only a new map session
// clears them, which docs/ref/derp.md tells operators.
func TestDERPHomeParamsReachClient(t *testing.T) {
	srv := servertest.NewServer(t)
	client := servertest.NewClient(t, srv, "node", servertest.WithUser(srv.CreateUser(t, "derp")))

	// The region name changes with every push so each step can wait for
	// its own map before looking at the scores.
	push := func(name string, hp *tailcfg.DERPHomeParams) {
		t.Helper()

		srv.State().SetDERPMap(&tailcfg.DERPMap{
			HomeParams: hp,
			Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
				900: {
					RegionID:   900,
					RegionCode: "test",
					RegionName: name,
					Nodes: []*tailcfg.DERPNode{{
						Name:     "test0",
						RegionID: 900,
						HostName: "127.0.0.1",
						IPv4:     "127.0.0.1",
						DERPPort: -1,
					}},
				},
			},
		})
		srv.App.Change(change.DERPMap())
	}

	waitScores := func(name string, want map[tailcfg.DERPRegionID]float64) {
		t.Helper()

		var got map[tailcfg.DERPRegionID]float64

		client.WaitForCondition(t, name, 10*time.Second, func(nm *netmap.NetworkMap) bool {
			dm := nm.DERPMap
			if dm == nil || dm.Regions[900] == nil || dm.Regions[900].RegionName != name {
				return false
			}

			got = nil
			if dm.HomeParams != nil {
				got = dm.HomeParams.RegionScore
			}

			return maps.Equal(got, want)
		})
	}

	client.WaitForCondition(t, "initial map", 10*time.Second, func(nm *netmap.NetworkMap) bool {
		return nm.DERPMap != nil
	})

	if hp := client.Netmap().DERPMap.HomeParams; hp != nil {
		t.Fatalf("HomeParams = %+v without scores, want nil like SaaS", hp)
	}

	push("scored", &tailcfg.DERPHomeParams{RegionScore: map[tailcfg.DERPRegionID]float64{900: 0.5}})
	waitScores("scored", map[tailcfg.DERPRegionID]float64{900: 0.5})

	push("rescored", &tailcfg.DERPHomeParams{RegionScore: map[tailcfg.DERPRegionID]float64{900: 2}})
	waitScores("rescored", map[tailcfg.DERPRegionID]float64{900: 2})

	push("removed", nil)
	waitScores("removed", map[tailcfg.DERPRegionID]float64{900: 2})

	push("emptied", &tailcfg.DERPHomeParams{RegionScore: map[tailcfg.DERPRegionID]float64{}})
	waitScores("emptied", map[tailcfg.DERPRegionID]float64{900: 2})

	push("reset", &tailcfg.DERPHomeParams{RegionScore: map[tailcfg.DERPRegionID]float64{900: 1}})
	waitScores("reset", map[tailcfg.DERPRegionID]float64{900: 1})

	push("reconnected", nil)
	client.Reconnect(t)
	waitScores("reconnected", nil)
}
