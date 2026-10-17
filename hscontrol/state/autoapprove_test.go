package state

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestRouteApprovalWaitsForAnnouncement: approvers run when the announced
// set changes, over every announced route, and neither on a policy reload
// nor on a report that keeps the routes.
func TestRouteApprovalWaitsForAnnouncement(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	route := netip.MustParsePrefix("10.0.0.0/24")
	added := netip.MustParsePrefix("10.0.1.0/24")

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	report := func(hostname string, routes ...netip.Prefix) {
		t.Helper()

		_, err := s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
			NodeKey:  nv.NodeKey(),
			DiscoKey: nv.DiscoKey(),
			Hostinfo: &tailcfg.Hostinfo{Hostname: hostname, RoutableIPs: routes},
		})
		require.NoError(t, err)
	}
	approved := func() []netip.Prefix {
		t.Helper()

		current, ok := s.GetNodeByID(nodeID)
		require.True(t, ok)

		return current.ApprovedRoutes().AsSlice()
	}

	report("router", route)
	require.Empty(t, approved())

	_, err := s.db.SetPolicy(`{
		"autoApprovers": {"routes": {"10.0.0.0/16": ["persist-user@"]}},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`)
	require.NoError(t, err)

	_, err = s.ReloadPolicy()
	require.NoError(t, err)
	assert.Empty(t, approved(), "a reload approves nothing")

	report("router-renamed", route)
	assert.Empty(t, approved(), "a report that keeps the routes approves nothing")

	report("router-renamed", route, added)
	assert.ElementsMatch(t, []netip.Prefix{route, added}, approved(),
		"a new announcement runs approvers over every announced route")
}

// TestAutoApproveKeepsCurrentManualRoutes: registration approval runs on
// the node the writer replaces, so an admin write that lands after the
// caller read its view survives.
func TestAutoApproveKeepsCurrentManualRoutes(t *testing.T) {
	manual := netip.MustParsePrefix("10.0.0.0/24")
	automatic := netip.MustParsePrefix("10.1.0.0/24")
	addition := netip.MustParsePrefix("10.2.0.0/24")

	for _, tt := range []struct {
		name        string
		replacement []netip.Prefix
		want        []netip.Prefix
	}{
		{name: "revoke", want: []netip.Prefix{automatic}},
		{name: "add", replacement: []netip.Prefix{manual, addition}, want: []netip.Prefix{manual, automatic, addition}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, s, nodeID := persistTestSetup(t)
			t.Cleanup(func() { _ = s.Close() })

			_, err := s.SetPolicy([]byte(`{
				"autoApprovers": {"routes": {"10.1.0.0/24": ["persist-user@"]}},
				"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
			}`))
			require.NoError(t, err)

			_, ok := s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
				n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{manual, automatic}}
			})
			require.True(t, ok)

			stale, _, err := s.SetApprovedRoutes(nodeID, []netip.Prefix{manual})
			require.NoError(t, err)

			_, _, err = s.SetApprovedRoutes(nodeID, tt.replacement)
			require.NoError(t, err)

			_, err = s.AutoApproveRoutes(stale)
			require.NoError(t, err)

			current, ok := s.GetNodeByID(nodeID)
			require.True(t, ok)
			assert.ElementsMatch(t, tt.want, current.ApprovedRoutes().AsSlice())

			stored, err := s.db.GetNodeByID(nodeID)
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.want, stored.ApprovedRoutes.List())
		})
	}
}
