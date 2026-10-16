// A via grant scoping autogroup:internet to a tag must surface only
// the matching exit node to the source — not strip every exit node
// from the source's view.
//
// Spec: https://tailscale.com/docs/features/access-control/grants/grants-via#route-users-through-exit-nodes-based-on-location
package v2

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
)

// TestIssue3233ViaInternetExitVisibility loads a policy where alice's
// only access to autogroup:internet is via tag:exit1. Alice sees her
// tag:exit1 exit node as a peer with 0.0.0.0/0 + ::/0 in AllowedIPs,
// and does not see bob's tag:exit2 exit node.
func TestIssue3233ViaInternetExitVisibility(t *testing.T) {
	t.Parallel()

	users := types.Users{
		{ID: 1, Name: "alice", Email: "alice@headscale.net"},
		{ID: 2, Name: "bob", Email: "bob@headscale.net"},
	}

	exitRoutes := []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6()}

	aliceLaptop := node("alice-laptop", "100.64.0.10", "fd7a:115c:a1e0::a", users[0])
	aliceLaptop.ID = 1

	aliceExit := node("alice-exit", "100.64.0.11", "fd7a:115c:a1e0::b", users[0])
	aliceExit.ID = 2
	aliceExit.Tags = []string{"tag:exit1"}
	aliceExit.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: exitRoutes}
	aliceExit.ApprovedRoutes = exitRoutes

	bobExit := node("bob-exit", "100.64.0.21", "fd7a:115c:a1e0::15", users[1])
	bobExit.ID = 3
	bobExit.Tags = []string{"tag:exit2"}
	bobExit.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: exitRoutes}
	bobExit.ApprovedRoutes = exitRoutes

	nodes := types.Nodes{aliceLaptop, aliceExit, bobExit}

	policy := `{
		"tagOwners": {
			"tag:exit1": ["alice@headscale.net"],
			"tag:exit2": ["bob@headscale.net"]
		},
		"grants": [
			{
				"src": ["alice@headscale.net"],
				"dst": ["autogroup:internet"],
				"via": ["tag:exit1"],
				"ip": ["*"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	t.Run("BuildPeerMap_includes_via_tagged_exit", func(t *testing.T) {
		t.Parallel()

		peerMap := pm.BuildPeerMap(nodes.ViewSlice())

		require.True(t,
			slices.Contains(peerMap[aliceLaptop.ID], aliceExit.ID),
			"alice must see her tag:exit1 exit node as a peer")

		require.False(t,
			slices.Contains(peerMap[aliceLaptop.ID], bobExit.ID),
			"alice must not see bob's tag:exit2 exit node — via grant scopes to tag:exit1")
	})

	t.Run("ViaRoutesForPeer_includes_exit_for_matching_tag", func(t *testing.T) {
		t.Parallel()

		result := pm.ViaRoutesForPeer(aliceLaptop.View(), aliceExit.View())
		require.Contains(t, result.Include, tsaddr.AllIPv4(),
			"alice viewing tag:exit1 exit must Include 0.0.0.0/0 — drives AllowedIPs in state.RoutesForPeer")
		require.Contains(t, result.Include, tsaddr.AllIPv6(),
			"alice viewing tag:exit1 exit must Include ::/0 — drives AllowedIPs in state.RoutesForPeer")
	})

	t.Run("ViaRoutesForPeer_excludes_exit_for_other_tag", func(t *testing.T) {
		t.Parallel()

		result := pm.ViaRoutesForPeer(aliceLaptop.View(), bobExit.View())
		require.Contains(t, result.Exclude, tsaddr.AllIPv4(),
			"alice viewing tag:exit2 exit must Exclude 0.0.0.0/0 — strips it from AllowedIPs")
		require.Contains(t, result.Exclude, tsaddr.AllIPv6(),
			"alice viewing tag:exit2 exit must Exclude ::/0 — strips it from AllowedIPs")
	})
}

// TestViaInternetExitSteeringSurvivesUnrelatedRules checks that a
// regular rule matching the viewer only lifts via exit steering when its
// destination actually reaches the internet. Narrow destinations overlap
// 0.0.0.0/0 but must not evict it from Exclude.
func TestViaInternetExitSteeringSurvivesUnrelatedRules(t *testing.T) {
	t.Parallel()

	users := types.Users{
		{ID: 1, Name: "alice", Email: "alice@headscale.net"},
		{ID: 2, Name: "bob", Email: "bob@headscale.net"},
	}

	exitRoutes := []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6()}

	aliceLaptop := node("alice-laptop", "100.64.0.10", "fd7a:115c:a1e0::a", users[0])
	aliceLaptop.ID = 1

	exitA := node("exit-a", "100.64.0.11", "fd7a:115c:a1e0::b", users[0])
	exitA.ID = 2
	exitA.Tags = []string{"tag:exit-a"}
	exitA.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: exitRoutes}
	exitA.ApprovedRoutes = exitRoutes

	exitB := node("exit-b", "100.64.0.12", "fd7a:115c:a1e0::c", users[0])
	exitB.ID = 3
	exitB.Tags = []string{"tag:exit-b"}
	exitB.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: exitRoutes}
	exitB.ApprovedRoutes = exitRoutes

	nodes := types.Nodes{aliceLaptop, exitA, exitB}

	tests := []struct {
		name  string
		extra string
		// wantExcluded: exit-b's exit routes stay hidden from alice.
		wantExcluded bool
	}{
		{
			name:         "via-grant-only",
			wantExcluded: true,
		},
		{
			name:         "acl-autogroup-self",
			extra:        `"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}],`,
			wantExcluded: true,
		},
		{
			name:         "acl-single-host",
			extra:        `"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["100.64.0.15:53"]}],`,
			wantExcluded: true,
		},
		{
			name:         "acl-private-subnet",
			extra:        `"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["10.0.0.0/8:*"]}],`,
			wantExcluded: true,
		},
		{
			name:         "acl-other-exit-node",
			extra:        `"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:exit-b:*"]}],`,
			wantExcluded: true,
		},
		{
			name:         "acl-autogroup-internet",
			extra:        `"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:internet:*"]}],`,
			wantExcluded: false,
		},
		{
			name:         "acl-wildcard",
			extra:        `"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["*:*"]}],`,
			wantExcluded: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			policy := `{
				"tagOwners": {
					"tag:exit-a": ["alice@headscale.net"],
					"tag:exit-b": ["alice@headscale.net"]
				},
				` + tt.extra + `
				"grants": [{
					"src": ["autogroup:member"],
					"dst": ["autogroup:internet"],
					"ip":  ["*"],
					"via": ["tag:exit-a"]
				}]
			}`

			pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
			require.NoError(t, err)

			viaPeer := pm.ViaRoutesForPeer(aliceLaptop.View(), exitA.View())
			require.Contains(t, viaPeer.Include, tsaddr.AllIPv4())

			other := pm.ViaRoutesForPeer(aliceLaptop.View(), exitB.View())
			for _, p := range exitRoutes {
				require.Equal(t, tt.wantExcluded, slices.Contains(other.Exclude, p),
					"exit-b %s in Exclude: got %v", p, other.Exclude)
			}
		})
	}
}
