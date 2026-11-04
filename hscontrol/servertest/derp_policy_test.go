package servertest_test

import (
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// TestPolicyDERPMapReachesClient pins that a policy derpMap changes the map
// clients get, on a policy write that changes nothing else and on a DERP
// map refresh, as on SaaS (nodeattrs-derpmap-* captures).
func TestPolicyDERPMapReachesClient(t *testing.T) {
	srv := servertest.NewServer(t)
	client := servertest.NewClient(t, srv, "node", servertest.WithUser(srv.CreateUser(t, "derp")))

	waitRegions := func(desc string, want ...tailcfg.DERPRegionID) {
		t.Helper()

		client.WaitForCondition(t, desc, 10*time.Second, func(nm *netmap.NetworkMap) bool {
			return nm.DERPMap != nil &&
				slices.Equal(slices.Sorted(maps.Keys(nm.DERPMap.Regions)), want)
		})
	}

	setPolicy := func(pol string) {
		t.Helper()

		_, changes, err := srv.State().UpdatePolicy([]byte(pol))
		require.NoError(t, err)
		srv.App.Change(changes...)
	}

	const region901 = `"901": {"RegionID": 901, "RegionCode": "custom", "Nodes": [
		{"Name": "901a", "RegionID": 901, "HostName": "127.0.0.1", "DERPPort": -1}]}`

	waitRegions("configured map", 900)

	setPolicy(`{"derpMap": {"Regions": {` + region901 + `}}}`)
	waitRegions("policy region added", 900, 901)

	setPolicy(`{"derpMap": {"OmitDefaultRegions": true, "Regions": {` + region901 + `}}}`)
	waitRegions("configured regions omitted", 901)

	// A refresh of the configured map keeps the policy applied.
	srv.State().SetDERPMap(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
		902: {RegionID: 902, Nodes: []*tailcfg.DERPNode{{Name: "902a", RegionID: 902, DERPPort: -1}}},
	}})
	srv.App.Change(change.DERPMap())

	setPolicy(`{"derpMap": {"Regions": {` + region901 + `}}}`)
	waitRegions("refreshed map with policy region", 901, 902)

	setPolicy(`{}`)
	waitRegions("policy derpMap removed", 902)
}
