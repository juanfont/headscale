package state

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// mp wraps netip.MustParsePrefix.
func mp(prefix string) netip.Prefix {
	return netip.MustParsePrefix(prefix)
}

// primariesFixture builds a NodeStore with the requested node IDs
// pre-registered (offline, no routes) and provides terse helpers for
// driving the kinds of state transitions the algorithm cares about.
type primariesFixture struct {
	t  *testing.T
	ns *NodeStore
}

func newPrimariesFixture(t *testing.T, ids ...types.NodeID) *primariesFixture {
	t.Helper()

	ns := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)
	ns.Start()
	t.Cleanup(ns.Stop)

	for _, id := range ids {
		ns.PutNode(nodeForRapid(id))
	}

	return &primariesFixture{t: t, ns: ns}
}

// advertise mirrors State.Connect: marks the node online, clears
// Unhealthy, and sets approved + announced routes to prefs. An empty
// prefs argument leaves the node online but advertising nothing.
func (f *primariesFixture) advertise(id types.NodeID, prefs ...netip.Prefix) {
	f.t.Helper()
	f.ns.UpdateNode(id, func(n *types.Node) {
		n.IsOnline = new(true)
		n.Unhealthy = false
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: prefs}
		n.ApprovedRoutes = prefs
	})
}

// approveRoutes mirrors State.SetApprovedRoutes / Hostinfo updates:
// it changes the node's announced + approved set without touching
// Unhealthy.
func (f *primariesFixture) approveRoutes(id types.NodeID, prefs ...netip.Prefix) {
	f.t.Helper()
	f.ns.UpdateNode(id, func(n *types.Node) {
		n.IsOnline = new(true)
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: prefs}
		n.ApprovedRoutes = prefs
	})
}

// disconnect mirrors State.Disconnect: marks the node offline. The
// snapshot rebuild treats an offline node as a non-advertiser.
func (f *primariesFixture) disconnect(id types.NodeID) {
	f.t.Helper()
	f.ns.UpdateNode(id, func(n *types.Node) {
		n.IsOnline = new(false)
	})
}

// unhealthy mirrors State.SetNodeUnhealthy(id, true).
func (f *primariesFixture) unhealthy(id types.NodeID) {
	f.t.Helper()
	f.ns.UpdateNode(id, func(n *types.Node) {
		n.Unhealthy = true
	})
}

// healthy mirrors State.SetNodeUnhealthy(id, false).
func (f *primariesFixture) healthy(id types.NodeID) {
	f.t.Helper()
	f.ns.UpdateNode(id, func(n *types.Node) {
		n.Unhealthy = false
	})
}

// requirePrimary asserts that prefix has node id as its primary.
func (f *primariesFixture) requirePrimary(prefix netip.Prefix, id types.NodeID) {
	f.t.Helper()
	got, ok := f.ns.PrimaryRouteFor(prefix)
	require.True(f.t, ok, "expected a primary for %s, got none", prefix)
	require.Equal(f.t, id, got, "primary for %s", prefix)
}

// requireNoPrimary asserts that prefix has no primary at all.
func (f *primariesFixture) requireNoPrimary(prefix netip.Prefix) {
	f.t.Helper()
	_, ok := f.ns.PrimaryRouteFor(prefix)
	require.False(f.t, ok, "expected no primary for %s", prefix)
}

// requireNodeRoutes asserts the set of prefixes for which id is the
// primary, regardless of order.
func (f *primariesFixture) requireNodeRoutes(id types.NodeID, want ...netip.Prefix) {
	f.t.Helper()
	got := f.ns.PrimaryRoutesForNode(id)

	gotSorted := slices.Clone(got)
	wantSorted := slices.Clone(want)

	slices.SortFunc(gotSorted, netip.Prefix.Compare)
	slices.SortFunc(wantSorted, netip.Prefix.Compare)

	require.Equal(f.t, wantSorted, gotSorted, "primary routes for node %d", id)
}

func TestPrimaries_SingleNodeSingleRoute(t *testing.T) {
	f := newPrimariesFixture(t, 1)
	f.advertise(1, mp("192.168.1.0/24"))

	f.requirePrimary(mp("192.168.1.0/24"), 1)
	f.requireNodeRoutes(1, mp("192.168.1.0/24"))
}

func TestPrimaries_TwoNodesDifferentRoutes(t *testing.T) {
	f := newPrimariesFixture(t, 1, 2)
	f.advertise(1, mp("192.168.1.0/24"))
	f.advertise(2, mp("192.168.2.0/24"))

	f.requirePrimary(mp("192.168.1.0/24"), 1)
	f.requirePrimary(mp("192.168.2.0/24"), 2)
}

func TestPrimaries_OverlappingRoutesLowerIDWins(t *testing.T) {
	f := newPrimariesFixture(t, 1, 2)
	f.advertise(1, mp("192.168.1.0/24"))
	f.advertise(2, mp("192.168.1.0/24"))

	f.requirePrimary(mp("192.168.1.0/24"), 1)
	f.requireNodeRoutes(1, mp("192.168.1.0/24"))
	f.requireNodeRoutes(2)
}

func TestPrimaries_AntiFlapPreservesCurrentPrimary(t *testing.T) {
	// A primary that disappears (advertiser leaves the set) should
	// trigger failover. When the original primary returns, the new
	// primary keeps the assignment — anti-flap.
	f := newPrimariesFixture(t, 1, 2)
	f.advertise(1, mp("192.168.1.0/24"))
	f.advertise(2, mp("192.168.1.0/24"))
	f.requirePrimary(mp("192.168.1.0/24"), 1)

	f.disconnect(1)
	f.requirePrimary(mp("192.168.1.0/24"), 2)

	f.advertise(1, mp("192.168.1.0/24"))
	f.requirePrimary(mp("192.168.1.0/24"), 2)
}

func TestPrimaries_ClearRoutesDropsPrimary(t *testing.T) {
	f := newPrimariesFixture(t, 1)
	f.advertise(1, mp("192.168.1.0/24"))
	f.requirePrimary(mp("192.168.1.0/24"), 1)

	f.approveRoutes(1)
	f.requireNoPrimary(mp("192.168.1.0/24"))
}

func TestPrimaries_DisconnectDropsLastAdvertiserPrimary(t *testing.T) {
	f := newPrimariesFixture(t, 1)
	f.advertise(1, mp("192.168.1.0/24"))
	f.requirePrimary(mp("192.168.1.0/24"), 1)

	f.disconnect(1)
	f.requireNoPrimary(mp("192.168.1.0/24"))
}

func TestPrimaries_UnhealthyTriggersFailover(t *testing.T) {
	f := newPrimariesFixture(t, 1, 2)
	f.advertise(1, mp("192.168.1.0/24"))
	f.advertise(2, mp("192.168.1.0/24"))
	f.requirePrimary(mp("192.168.1.0/24"), 1)

	f.unhealthy(1)
	f.requirePrimary(mp("192.168.1.0/24"), 2)
}

func TestPrimaries_RecoveryFromUnhealthyNoFlap(t *testing.T) {
	f := newPrimariesFixture(t, 1, 2)
	f.advertise(1, mp("192.168.1.0/24"))
	f.advertise(2, mp("192.168.1.0/24"))
	f.unhealthy(1)
	f.requirePrimary(mp("192.168.1.0/24"), 2)

	f.healthy(1)
	f.requirePrimary(mp("192.168.1.0/24"), 2)
}

func TestPrimaries_AllUnhealthyKeepsAPrimary(t *testing.T) {
	// Anti-blackhole: when every advertiser is unhealthy the
	// algorithm keeps *some* primary so peers can recover once one
	// flips healthy. The specific node is the prev primary when
	// reachable (see PreservesPrevious); this test only pins the
	// existence rule.
	prefix := mp("192.168.1.0/24")
	f := newPrimariesFixture(t, 1, 2)
	f.advertise(1, prefix)
	f.advertise(2, prefix)
	f.unhealthy(1)
	f.unhealthy(2)

	_, ok := f.ns.PrimaryRouteFor(prefix)
	require.True(t, ok, "all-unhealthy must still produce some primary")
}

func TestPrimaries_AllUnhealthyPreservesPrevious(t *testing.T) {
	// Issue #3203: once a failover has moved primary to a higher-ID
	// node, a subsequent all-unhealthy state must NOT churn primary
	// back to the lowest-ID candidate. Under cable-pull semantics
	// both nodes can linger as IsOnline=true (half-open TCP) and
	// both go Unhealthy — naive `candidates[0]` would flap the
	// primary to a node that is itself unreachable.
	prefix := mp("10.0.0.0/24")
	f := newPrimariesFixture(t, 1, 2)
	f.advertise(1, prefix)
	f.advertise(2, prefix)
	f.requirePrimary(prefix, 1)

	f.unhealthy(1)
	f.requirePrimary(prefix, 2)

	f.unhealthy(2)
	f.requirePrimary(prefix, 2)
}

func TestPrimaries_ExitRouteNotElected(t *testing.T) {
	// Exit routes (0.0.0.0/0, ::/0) are not subject to HA primary
	// election — every approved exit-route advertiser keeps it.
	f := newPrimariesFixture(t, 1)
	exitV4 := mp("0.0.0.0/0")
	f.advertise(1, exitV4)

	f.requireNoPrimary(exitV4)
}

func TestPrimaries_RegressionIssue3203_BothOfflineThenOneReturns(t *testing.T) {
	// Issue #3203: with two HA advertisers, dropping both then
	// bringing one back used to leave the prefix without any
	// primary. After the refactor the snapshot recomputes primaries
	// on every NodeStore write, so the returning advertiser must
	// be elected.
	prefix := mp("10.0.0.0/24")
	f := newPrimariesFixture(t, 1, 2)
	f.advertise(1, prefix)
	f.advertise(2, prefix)
	f.requirePrimary(prefix, 1)

	f.disconnect(1)
	f.requirePrimary(prefix, 2)

	f.disconnect(2)
	f.requireNoPrimary(prefix)

	f.advertise(2, prefix)
	f.requirePrimary(prefix, 2)
}

func TestPrimaries_HANodes(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*primariesFixture)
		want  map[netip.Prefix][]types.NodeID
	}{
		{
			name: "single-node-not-ha",
			setup: func(f *primariesFixture) {
				f.advertise(1, mp("192.168.1.0/24"))
			},
			want: map[netip.Prefix][]types.NodeID{},
		},
		{
			name: "two-nodes-same-prefix-is-ha",
			setup: func(f *primariesFixture) {
				f.advertise(1, mp("192.168.1.0/24"))
				f.advertise(2, mp("192.168.1.0/24"))
			},
			want: map[netip.Prefix][]types.NodeID{
				mp("192.168.1.0/24"): {1, 2},
			},
		},
		{
			name: "two-nodes-different-prefixes-not-ha",
			setup: func(f *primariesFixture) {
				f.advertise(1, mp("192.168.1.0/24"))
				f.advertise(2, mp("192.168.2.0/24"))
			},
			want: map[netip.Prefix][]types.NodeID{},
		},
		{
			name: "three-nodes-two-share-prefix",
			setup: func(f *primariesFixture) {
				f.advertise(1, mp("192.168.1.0/24"))
				f.advertise(2, mp("192.168.1.0/24"))
				f.advertise(3, mp("10.0.0.0/8"))
			},
			want: map[netip.Prefix][]types.NodeID{
				mp("192.168.1.0/24"): {1, 2},
			},
		},
		{
			name: "three-nodes-all-share",
			setup: func(f *primariesFixture) {
				f.advertise(1, mp("192.168.1.0/24"))
				f.advertise(2, mp("192.168.1.0/24"))
				f.advertise(3, mp("192.168.1.0/24"))
			},
			want: map[netip.Prefix][]types.NodeID{
				mp("192.168.1.0/24"): {1, 2, 3},
			},
		},
		{
			name: "empty",
			setup: func(*primariesFixture) {
			},
			want: map[netip.Prefix][]types.NodeID{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newPrimariesFixture(t, 1, 2, 3)
			tt.setup(f)

			got := f.ns.HANodes()
			assert.Equal(t, tt.want, got)
		})
	}
}
