package routes

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
)

// model mirrors the expected state of PrimaryRoutes given the operations
// applied so far. It is intentionally simple — close to what a careful
// reading of primary.go's invariants prescribes — so divergence between
// the model and the real PrimaryRoutes flags a bug in the algorithm.
type model struct {
	// connected[n] is true if node n's routes are currently registered
	// (SetRoutes with at least one prefix has been called and not since
	// followed by SetRoutes with empty prefixes).
	connected map[types.NodeID]bool

	// prefixes[n] is the latest non-empty SetRoutes input for n. Cleared
	// on Disconnect.
	prefixes map[types.NodeID][]netip.Prefix

	// unhealthy[n] mirrors PrimaryRoutes.unhealthy.
	unhealthy map[types.NodeID]bool

	// primary[p] is the current primary for prefix p. The implementation
	// preserves the current primary across changes to avoid flapping, so
	// the model has to track this across operations rather than recompute
	// a fresh choice each time.
	primary map[netip.Prefix]types.NodeID
}

func newModel() *model {
	return &model{
		connected: map[types.NodeID]bool{},
		prefixes:  map[types.NodeID][]netip.Prefix{},
		unhealthy: map[types.NodeID]bool{},
		primary:   map[netip.Prefix]types.NodeID{},
	}
}

// advertisersByPrefix returns the connected nodes that announce each
// prefix, sorted by NodeID (matches updatePrimaryLocked's iteration
// order).
func (m *model) advertisersByPrefix() map[netip.Prefix][]types.NodeID {
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

// updatePrimaries reapplies the implementation's algorithm to recompute
// the primary for each prefix. Called after every operation.
func (m *model) updatePrimaries() {
	advertisers := m.advertisersByPrefix()

	// Step 1: drop primaries for prefixes that no longer have any
	// advertiser at all.
	for p := range m.primary {
		if _, ok := advertisers[p]; !ok {
			delete(m.primary, p)
		}
	}

	// Step 2: for each prefix with advertisers, keep current primary
	// if it is still in the advertiser set and not unhealthy. Otherwise
	// select the first healthy advertiser; if all are unhealthy fall
	// back to the lowest NodeID (degraded primary).
	for p, nodes := range advertisers {
		if cur, ok := m.primary[p]; ok {
			if slices.Contains(nodes, cur) && !m.unhealthy[cur] {
				continue
			}
		}

		var selected types.NodeID
		var found bool
		for _, n := range nodes {
			if !m.unhealthy[n] {
				selected = n
				found = true
				break
			}
		}
		if !found && len(nodes) >= 1 {
			selected = nodes[0]
			found = true
		}
		if found {
			m.primary[p] = selected
		}
	}
}

// allPrefixes returns every prefix mentioned by any connected node.
func (m *model) allPrefixes() []netip.Prefix {
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

// checkInvariants asserts every property we expect of the real
// PrimaryRoutes given the model.
func checkInvariants(rt *rapid.T, pr *PrimaryRoutes, m *model, nodeIDs []types.NodeID) {
	rt.Helper()

	// Per-node primary set must match the model's expectations.
	expectedByNode := map[types.NodeID][]netip.Prefix{}
	for p, owner := range m.primary {
		expectedByNode[owner] = append(expectedByNode[owner], p)
	}

	for _, id := range nodeIDs {
		got := pr.PrimaryRoutes(id)
		want := expectedByNode[id]

		if !samePrefixSet(got, want) {
			rt.Fatalf(
				"PrimaryRoutes(%d) = %v, model expected %v\nstate: %s",
				id, got, want, pr.String(),
			)
		}

		if want := !m.unhealthy[id]; pr.IsNodeHealthy(id) != want {
			rt.Fatalf(
				"IsNodeHealthy(%d) = %v, want %v",
				id, pr.IsNodeHealthy(id), want,
			)
		}
	}

	// Every prefix that has at least one connected advertiser must have a
	// primary in the real PrimaryRoutes. Issue #3203 manifests as a prefix
	// silently losing its primary after a disconnect/reconnect cycle.
	for _, p := range m.allPrefixes() {
		want, expectExists := m.primary[p]
		if !expectExists {
			continue
		}

		var foundOwner types.NodeID
		var found bool
		for _, id := range nodeIDs {
			for _, got := range pr.PrimaryRoutes(id) {
				if got == p {
					foundOwner = id
					found = true
					break
				}
			}
			if found {
				break
			}
		}

		if !found {
			rt.Fatalf(
				"prefix %s has at least one advertiser in the model but no primary in PrimaryRoutes\nstate: %s",
				p, pr.String(),
			)
		}

		if want != foundOwner {
			rt.Fatalf(
				"prefix %s: PrimaryRoutes assigned to node %d, model expected %d\nstate: %s",
				p, foundOwner, want, pr.String(),
			)
		}
	}
}

// TestPrimaryRoutesProperty drives PrimaryRoutes with a randomised
// sequence of high-level operations (ConnectAdvertise, Disconnect,
// ProbeUnhealthy, ProbeHealthy, ApprovedRoutesChange) and checks that
// the per-prefix primary chosen by the implementation matches a
// reference model after every step.
//
// Background: issue #3203 reports that HA tracking enters a stuck
// state after a sequence of disconnect/reconnect events. The narrow
// integration and servertest reproductions written for the bug do not
// fail on upstream/main, so this property test broadens the search by
// letting rapid generate sequences we have not enumerated by hand.
func TestPrimaryRoutesProperty(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Small fixed pools so rapid can collide on the same nodes
		// and prefixes — that is where the interesting interleavings
		// live.
		const numNodes = 4
		nodeIDs := make([]types.NodeID, 0, numNodes)
		for i := 1; i <= numNodes; i++ {
			nodeIDs = append(nodeIDs, types.NodeID(i))
		}

		prefixes := []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
			netip.MustParsePrefix("10.0.1.0/24"),
		}

		pr := New()
		m := newModel()

		nodeGen := rapid.SampledFrom(nodeIDs)
		prefixSubsetGen := rapid.SliceOfNDistinct(
			rapid.SampledFrom(prefixes),
			0, len(prefixes),
			func(p netip.Prefix) string { return p.String() },
		)

		opCount := rapid.IntRange(5, 60).Draw(rt, "opCount")
		for step := 0; step < opCount; step++ {
			op := rapid.IntRange(0, 4).Draw(rt, fmt.Sprintf("op_%d", step))
			id := nodeGen.Draw(rt, fmt.Sprintf("id_%d", step))

			switch op {
			case 0: // ConnectAdvertise
				prefs := prefixSubsetGen.Draw(rt, fmt.Sprintf("prefs_%d", step))

				// Mirror state.Connect: ClearUnhealthy then SetRoutes.
				pr.ClearUnhealthy(id)
				delete(m.unhealthy, id)

				if len(prefs) == 0 {
					pr.SetRoutes(id)
					delete(m.connected, id)
					delete(m.prefixes, id)
				} else {
					pr.SetRoutes(id, prefs...)
					m.connected[id] = true
					m.prefixes[id] = prefs
				}

			case 1: // Disconnect (state.Disconnect path).
				wasConnected := m.connected[id]
				pr.SetRoutes(id)
				delete(m.connected, id)
				delete(m.prefixes, id)
				// SetRoutes(empty) only clears unhealthy if the node
				// was previously in the routes map. See primary.go.
				if wasConnected {
					delete(m.unhealthy, id)
				}

			case 2: // ProbeUnhealthy
				pr.SetNodeHealthy(id, false)
				m.unhealthy[id] = true

			case 3: // ProbeHealthy
				pr.SetNodeHealthy(id, true)
				delete(m.unhealthy, id)

			case 4: // ApprovedRoutesChange (no ClearUnhealthy)
				wasConnected := m.connected[id]
				prefs := prefixSubsetGen.Draw(rt, fmt.Sprintf("prefs_%d", step))

				if len(prefs) == 0 {
					pr.SetRoutes(id)
					delete(m.connected, id)
					delete(m.prefixes, id)
					if wasConnected {
						delete(m.unhealthy, id)
					}
				} else {
					pr.SetRoutes(id, prefs...)
					m.connected[id] = true
					m.prefixes[id] = prefs
				}
			}

			m.updatePrimaries()

			checkInvariants(rt, pr, m, nodeIDs)
		}
	})
}
