package state

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// model mirrors the expected primary-route assignment given the
// operations applied so far. It is intentionally simple — close to
// what computePrimaries (node_store.go) prescribes — so divergence
// between the model and the snapshot's primaries map flags a bug in
// the algorithm.
//
// The model lives in the test file because the algorithm under test
// is the one inside snapshotFromNodes; the model's job is to predict
// the same answer from a separate, deliberately direct implementation.
type primariesModel struct {
	connected map[types.NodeID]bool
	prefixes  map[types.NodeID][]netip.Prefix
	unhealthy map[types.NodeID]bool

	// primary[p] is the current primary for prefix p. The
	// implementation preserves the current primary across changes to
	// avoid flapping, so the model has to track this across
	// operations rather than recompute a fresh choice each time.
	primary map[netip.Prefix]types.NodeID
}

func newPrimariesModel() *primariesModel {
	return &primariesModel{
		connected: map[types.NodeID]bool{},
		prefixes:  map[types.NodeID][]netip.Prefix{},
		unhealthy: map[types.NodeID]bool{},
		primary:   map[netip.Prefix]types.NodeID{},
	}
}

// advertisersByPrefix returns the connected nodes that announce each
// prefix, sorted by NodeID (matches computePrimaries' iteration).
func (m *primariesModel) advertisersByPrefix() map[netip.Prefix][]types.NodeID {
	out := map[netip.Prefix][]types.NodeID{}

	for n, prefs := range m.prefixes {
		if !m.connected[n] {
			continue
		}

		for _, p := range prefs {
			out[p] = append(out[p], n)
		}
	}

	for _, nodes := range out {
		slices.Sort(nodes)
	}

	return out
}

// updatePrimaries reapplies the algorithm to recompute the primary
// for each prefix. Called after every operation.
func (m *primariesModel) updatePrimaries() {
	advertisers := m.advertisersByPrefix()

	// Drop primaries for prefixes that no longer have any advertiser.
	for p := range m.primary {
		if _, ok := advertisers[p]; !ok {
			delete(m.primary, p)
		}
	}

	for p, nodes := range advertisers {
		if cur, ok := m.primary[p]; ok {
			if slices.Contains(nodes, cur) && !m.unhealthy[cur] {
				continue
			}
		}

		var (
			selected types.NodeID
			found    bool
		)

		for _, n := range nodes {
			if !m.unhealthy[n] {
				selected = n
				found = true

				break
			}
		}

		if !found && len(nodes) >= 1 {
			if cur, ok := m.primary[p]; ok && slices.Contains(nodes, cur) {
				selected = cur
			} else {
				selected = nodes[0]
			}

			found = true
		}

		if found {
			m.primary[p] = selected
		}
	}
}

// allPrefixes returns every prefix mentioned by any connected node.
func (m *primariesModel) allPrefixes() []netip.Prefix {
	seen := map[netip.Prefix]bool{}

	for n, prefs := range m.prefixes {
		if !m.connected[n] {
			continue
		}

		for _, p := range prefs {
			seen[p] = true
		}
	}

	out := make([]netip.Prefix, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}

	return out
}

func samePrefixSet(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}

	aa := slices.Clone(a)
	bb := slices.Clone(b)

	slices.SortFunc(aa, netip.Prefix.Compare)
	slices.SortFunc(bb, netip.Prefix.Compare)

	return slices.Equal(aa, bb)
}

// checkPrimariesProperties asserts every rule we expect of the snapshot's
// primaries map given the model.
func checkPrimariesProperties(rt *rapid.T, ns *NodeStore, m *primariesModel, nodeIDs []types.NodeID) {
	rt.Helper()

	expectedByNode := map[types.NodeID][]netip.Prefix{}
	for p, owner := range m.primary {
		expectedByNode[owner] = append(expectedByNode[owner], p)
	}

	for _, id := range nodeIDs {
		got := ns.PrimaryRoutesForNode(id)
		want := expectedByNode[id]

		if !samePrefixSet(got, want) {
			rt.Fatalf(
				"PrimaryRoutesForNode(%d) = %v, model expected %v",
				id, got, want,
			)
		}

		if want := !m.unhealthy[id]; ns.IsNodeHealthy(id) != want {
			rt.Fatalf(
				"IsNodeHealthy(%d) = %v, want %v",
				id, ns.IsNodeHealthy(id), want,
			)
		}
	}

	// Every prefix that has at least one connected advertiser must
	// have a primary in the snapshot. Issue #3203 manifests as a
	// prefix silently losing its primary after a disconnect/reconnect
	// cycle.
	for _, p := range m.allPrefixes() {
		want, expectExists := m.primary[p]
		if !expectExists {
			continue
		}

		got, ok := ns.PrimaryRouteFor(p)
		if !ok {
			rt.Fatalf(
				"prefix %s has at least one advertiser in the model but no primary in NodeStore",
				p,
			)
		}

		if want != got {
			rt.Fatalf(
				"prefix %s: snapshot primary = %d, model expected %d",
				p, got, want,
			)
		}
	}
}

// nodeForRapid builds a minimal types.Node for use in property
// tests. Tests drive (IsOnline, Hostinfo.RoutableIPs, ApprovedRoutes,
// Unhealthy) via UpdateNode; the rest stays fixed.
func nodeForRapid(id types.NodeID) types.Node {
	mk := key.NewMachine()
	nk := key.NewNode()

	return types.Node{
		ID:         id,
		Hostname:   fmt.Sprintf("rapid-%d", id),
		MachineKey: mk.Public(),
		NodeKey:    nk.Public(),
		UserID:     new(uint(1)),
		User:       &types.User{Name: "rapid"},
		IsOnline:   new(false),
		Hostinfo:   &tailcfg.Hostinfo{},
	}
}

// TestPrimaryRoutesProperty drives NodeStore with a randomised
// sequence of high-level operations and checks that the snapshot's
// primaries map matches a reference model after every step.
//
// Background: issue #3203 reports that HA tracking enters a stuck
// state after a sequence of disconnect/reconnect events. The narrow
// integration and servertest reproductions written for the bug do
// not fail on upstream/main, so this property test broadens the
// search by letting rapid generate sequences we have not enumerated
// by hand.
func TestPrimaryRoutesProperty(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		const numNodes = 4

		nodeIDs := make([]types.NodeID, 0, numNodes)
		for i := 1; i <= numNodes; i++ {
			nodeIDs = append(nodeIDs, types.NodeID(i))
		}

		prefixes := []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
			netip.MustParsePrefix("10.0.1.0/24"),
		}

		ns := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

		ns.Start()
		defer ns.Stop()

		for _, id := range nodeIDs {
			ns.PutNode(nodeForRapid(id))
		}

		m := newPrimariesModel()

		nodeGen := rapid.SampledFrom(nodeIDs)
		prefixSubsetGen := rapid.SliceOfNDistinct(
			rapid.SampledFrom(prefixes),
			0, len(prefixes),
			func(p netip.Prefix) string { return p.String() },
		)

		opCount := rapid.IntRange(5, 60).Draw(rt, "opCount")
		for step := range opCount {
			op := rapid.IntRange(0, 4).Draw(rt, fmt.Sprintf("op_%d", step))
			id := nodeGen.Draw(rt, fmt.Sprintf("id_%d", step))

			switch op {
			case 0: // ConnectAdvertise — Connect path clears Unhealthy.
				prefs := prefixSubsetGen.Draw(rt, fmt.Sprintf("prefs_%d", step))

				ns.UpdateNode(id, func(n *types.Node) {
					n.IsOnline = new(true)
					n.Unhealthy = false
					n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: prefs}
					n.ApprovedRoutes = prefs
				})

				if len(prefs) == 0 {
					delete(m.connected, id)
					delete(m.prefixes, id)
				} else {
					m.connected[id] = true
					m.prefixes[id] = prefs
				}

				delete(m.unhealthy, id)

			case 1: // Disconnect — IsOnline=false; ApprovedRoutes persists.
				ns.UpdateNode(id, func(n *types.Node) {
					n.IsOnline = new(false)
				})
				delete(m.connected, id)

			case 2: // ProbeUnhealthy — HA prober marks node bad.
				ns.UpdateNode(id, func(n *types.Node) {
					n.Unhealthy = true
				})
				m.unhealthy[id] = true

			case 3: // ProbeHealthy — HA prober marks node good.
				ns.UpdateNode(id, func(n *types.Node) {
					n.Unhealthy = false
				})
				delete(m.unhealthy, id)

			case 4: // ApprovedRoutesChange — change advertised prefs without touching health.
				prefs := prefixSubsetGen.Draw(rt, fmt.Sprintf("prefs_%d", step))

				ns.UpdateNode(id, func(n *types.Node) {
					n.IsOnline = new(true)
					n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: prefs}
					n.ApprovedRoutes = prefs
				})

				if len(prefs) == 0 {
					delete(m.connected, id)
					delete(m.prefixes, id)
				} else {
					m.connected[id] = true
					m.prefixes[id] = prefs
				}
			}

			m.updatePrimaries()

			checkPrimariesProperties(rt, ns, m, nodeIDs)
		}
	})
}
