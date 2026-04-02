package routes

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
	"tailscale.com/net/tsaddr"
)

// prefixPool is a fixed set of 6 non-exit subnet prefixes used in the PBT.
var prefixPool = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/24"),
	netip.MustParsePrefix("10.0.1.0/24"),
	netip.MustParsePrefix("192.168.1.0/24"),
	netip.MustParsePrefix("192.168.2.0/24"),
	netip.MustParsePrefix("172.16.0.0/16"),
	netip.MustParsePrefix("fd00::/64"),
}

// exitRoutes are the 2 exit route prefixes that should always be filtered out.
var exitRoutes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/0"),
	netip.MustParsePrefix("::/0"),
}

// allGeneratable includes both normal and exit prefixes for the generator.
var allGeneratable = append(append([]netip.Prefix{}, prefixPool...), exitRoutes...)

// genNodeID draws a small NodeID from [1, 8].
func genNodeID(t *rapid.T) types.NodeID {
	return types.NodeID(rapid.Uint64Range(1, 8).Draw(t, "nodeID"))
}

// genPrefixes draws a distinct subset of allGeneratable (including possible exit routes).
func genPrefixes(t *rapid.T) []netip.Prefix {
	return rapid.SliceOfNDistinct(
		rapid.SampledFrom(allGeneratable),
		0, len(allGeneratable),
		func(p netip.Prefix) string { return p.String() },
	).Draw(t, "prefixes")
}

// referenceModel is a simple model that tracks the same state as PrimaryRoutes
// but with a straightforward implementation for comparison.
type referenceModel struct {
	// routes maps nodeID -> set of non-exit prefixes advertised by that node.
	routes map[types.NodeID]map[netip.Prefix]struct{}

	// primaries maps prefix -> primary nodeID.
	// Mirrors PrimaryRoutes.primaries semantics:
	// - Stability: if old primary still advertises, keep it.
	// - Selection: lowest nodeID among advertisers for new primaries.
	primaries map[netip.Prefix]types.NodeID
}

func newReferenceModel() *referenceModel {
	return &referenceModel{
		routes:    make(map[types.NodeID]map[netip.Prefix]struct{}),
		primaries: make(map[netip.Prefix]types.NodeID),
	}
}

// setRoutes mirrors PrimaryRoutes.SetRoutes logic in the reference model.
// Returns true if primaries changed.
func (m *referenceModel) setRoutes(node types.NodeID, prefixes []netip.Prefix) bool {
	// Filter out exit routes and build the set.
	filtered := make(map[netip.Prefix]struct{})
	for _, p := range prefixes {
		if !tsaddr.IsExitRoute(p) {
			filtered[p] = struct{}{}
		}
	}

	if len(filtered) == 0 {
		delete(m.routes, node)
	} else {
		m.routes[node] = filtered
	}

	return m.recalcPrimaries()
}

// recalcPrimaries mirrors updatePrimaryLocked.
func (m *referenceModel) recalcPrimaries() bool {
	// Build prefix -> sorted list of advertisers.
	advertisers := make(map[netip.Prefix][]types.NodeID)
	for nid, prefixes := range m.routes {
		for p := range prefixes {
			advertisers[p] = append(advertisers[p], nid)
		}
	}
	// Sort each list by NodeID (ascending) for deterministic selection.
	for p := range advertisers {
		sort.Slice(advertisers[p], func(i, j int) bool {
			return advertisers[p][i] < advertisers[p][j]
		})
	}

	changed := false

	// For each prefix with advertisers, determine primary.
	for prefix, nodes := range advertisers {
		if currentPrimary, ok := m.primaries[prefix]; ok {
			if slices.Contains(nodes, currentPrimary) {
				// Stability: current primary still advertises, keep it.
				continue
			}
		}
		// New primary needed: pick lowest NodeID.
		m.primaries[prefix] = nodes[0]
		changed = true
	}

	// Clean up primaries for prefixes no longer advertised.
	for prefix := range m.primaries {
		if _, ok := advertisers[prefix]; !ok {
			delete(m.primaries, prefix)
			changed = true
		}
	}

	return changed
}

// primaryRoutesFor returns sorted primary prefixes for a node
// (mirrors PrimaryRoutes.PrimaryRoutes).
func (m *referenceModel) primaryRoutesFor(id types.NodeID) []netip.Prefix {
	var routes []netip.Prefix
	for prefix, nid := range m.primaries {
		if nid == id {
			routes = append(routes, prefix)
		}
	}
	slices.SortFunc(routes, netip.Prefix.Compare)
	return routes
}

// allNodeIDs returns the set of all nodeIDs that appear in the model routes.
func (m *referenceModel) allNodeIDs() []types.NodeID {
	seen := make(map[types.NodeID]struct{})
	for nid := range m.routes {
		seen[nid] = struct{}{}
	}
	ids := make([]types.NodeID, 0, len(seen))
	for nid := range seen {
		ids = append(ids, nid)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func TestRapid(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pr := New()
		model := newReferenceModel()

		t.Repeat(map[string]func(*rapid.T){
			"addRoutes": func(t *rapid.T) {
				node := genNodeID(t)
				prefixes := genPrefixes(t)

				gotChanged := pr.SetRoutes(node, prefixes...)
				modelChanged := model.setRoutes(node, prefixes)

				if gotChanged != modelChanged {
					t.Fatalf("addRoutes(node=%d, prefixes=%v): changed mismatch: got %v, model %v",
						node, prefixes, gotChanged, modelChanged)
				}
			},

			"removeNode": func(t *rapid.T) {
				node := genNodeID(t)

				gotChanged := pr.SetRoutes(node) // empty = remove
				modelChanged := model.setRoutes(node, nil)

				if gotChanged != modelChanged {
					t.Fatalf("removeNode(node=%d): changed mismatch: got %v, model %v",
						node, gotChanged, modelChanged)
				}
			},

			"queryPrimary": func(t *rapid.T) {
				node := genNodeID(t)

				gotRoutes := pr.PrimaryRoutes(node)
				wantRoutes := model.primaryRoutesFor(node)

				// Normalize nil vs empty for comparison.
				if len(gotRoutes) == 0 {
					gotRoutes = nil
				}
				if len(wantRoutes) == 0 {
					wantRoutes = nil
				}

				if !slices.Equal(gotRoutes, wantRoutes) {
					t.Fatalf("queryPrimary(node=%d): got %v, want %v",
						node, gotRoutes, wantRoutes)
				}
			},

			// Invariant checker runs after every operation.
			"": func(t *rapid.T) {
				checkAllInvariants(t, pr, model)
			},
		})
	})
}

// checkAllInvariants verifies all required invariants hold.
// Uses DebugJSON() and PrimaryRoutes() (public API) for verification.
func checkAllInvariants(t *rapid.T, pr *PrimaryRoutes, model *referenceModel) {
	debug := pr.DebugJSON()

	// Collect all advertised prefixes (union across all nodes).
	allAdvertised := make(map[netip.Prefix]bool)
	for _, prefixes := range debug.AvailableRoutes {
		for _, p := range prefixes {
			allAdvertised[p] = true
		}
	}

	// Collect all primary assignments from DebugJSON.
	primaries := make(map[netip.Prefix]types.NodeID, len(debug.PrimaryRoutes))
	for prefixStr, nodeID := range debug.PrimaryRoutes {
		p := netip.MustParsePrefix(prefixStr)
		primaries[p] = nodeID
	}

	// Invariant 1: Every advertised prefix has exactly one primary.
	for p := range allAdvertised {
		if _, ok := primaries[p]; !ok {
			t.Fatalf("invariant 1: prefix %s is advertised but has no primary", p)
		}
	}
	// Count: number of primaries must equal number of advertised prefixes.
	if len(primaries) != len(allAdvertised) {
		t.Fatalf("invariant 1: primaries count (%d) != advertised prefixes count (%d)\nprimaries: %v\nadvertised: %v",
			len(primaries), len(allAdvertised), primaries, allAdvertised)
	}

	// Invariant 2: Primary is a valid advertiser for that prefix.
	for p, nodeID := range primaries {
		nodeRoutes, ok := debug.AvailableRoutes[nodeID]
		if !ok {
			t.Fatalf("invariant 2: primary node %d for prefix %s has no routes at all", nodeID, p)
		}
		if !slices.Contains(nodeRoutes, p) {
			t.Fatalf("invariant 2: primary node %d for prefix %s does not advertise that prefix (routes: %v)",
				nodeID, p, nodeRoutes)
		}
	}

	// Invariant 3: No orphaned primaries (prefix in primaries but nobody advertises).
	for p := range primaries {
		if !allAdvertised[p] {
			t.Fatalf("invariant 3: prefix %s has a primary but no advertisers", p)
		}
	}

	// Invariant 4: No exit routes anywhere in the system.
	for _, prefixes := range debug.AvailableRoutes {
		for _, p := range prefixes {
			if tsaddr.IsExitRoute(p) {
				t.Fatalf("invariant 4: exit route %s found in available routes", p)
			}
		}
	}
	for prefixStr := range debug.PrimaryRoutes {
		p := netip.MustParsePrefix(prefixStr)
		if tsaddr.IsExitRoute(p) {
			t.Fatalf("invariant 4: exit route %s found in primaries", p)
		}
	}

	// Invariant 5: isPrimary index is consistent.
	// A node isPrimary iff it is primary for some prefix.
	// We verify this through the public API: for every node in [1,8],
	// PrimaryRoutes(id) returns non-nil iff the node is a primary for something.
	expectedPrimaryNodes := make(map[types.NodeID]bool)
	for _, nodeID := range primaries {
		expectedPrimaryNodes[nodeID] = true
	}
	for id := types.NodeID(1); id <= 8; id++ {
		routes := pr.PrimaryRoutes(id)
		hasPrimaries := len(routes) > 0
		shouldHave := expectedPrimaryNodes[id]
		if hasPrimaries != shouldHave {
			t.Fatalf("invariant 5: isPrimary inconsistency for node %d: PrimaryRoutes returned %v but expected isPrimary=%v",
				id, routes, shouldHave)
		}
	}

	// Invariant 6: Deterministic selection - lowest remaining ID wins when new primary needed.
	// We verify this by checking the model's primaries match the SUT's primaries exactly.
	// The model implements the same lowest-ID selection rule.
	for p, modelNode := range model.primaries {
		sutNode, ok := primaries[p]
		if !ok {
			t.Fatalf("invariant 6: prefix %s in model primaries but not in SUT", p)
		}
		if sutNode != modelNode {
			t.Fatalf("invariant 6: primary for %s: SUT=%d, model=%d (lowest-ID violation)",
				p, sutNode, modelNode)
		}
	}
	for p, sutNode := range primaries {
		modelNode, ok := model.primaries[p]
		if !ok {
			t.Fatalf("invariant 6: prefix %s in SUT primaries but not in model", p)
		}
		if sutNode != modelNode {
			t.Fatalf("invariant 6: primary for %s: SUT=%d, model=%d", p, sutNode, modelNode)
		}
	}

	// Invariant 7: Stability - if old primary still advertises, it stays.
	// This is enforced by the model comparison above: the model implements stability,
	// so if the SUT matches the model, stability is preserved.
	// Additionally, we can verify per-node that PrimaryRoutes output matches model.
	allNodeIDs := model.allNodeIDs()
	// Also include nodes that might be in the SUT but not in model routes.
	for nodeID := range debug.AvailableRoutes {
		found := false
		for _, id := range allNodeIDs {
			if id == nodeID {
				found = true
				break
			}
		}
		if !found {
			allNodeIDs = append(allNodeIDs, nodeID)
		}
	}
	for _, nodeID := range allNodeIDs {
		gotRoutes := pr.PrimaryRoutes(nodeID)
		wantRoutes := model.primaryRoutesFor(nodeID)
		if len(gotRoutes) == 0 {
			gotRoutes = nil
		}
		if len(wantRoutes) == 0 {
			wantRoutes = nil
		}
		if !slices.Equal(gotRoutes, wantRoutes) {
			t.Fatalf("invariant 7 (stability via model): PrimaryRoutes(%d): got %v, want %v",
				nodeID, gotRoutes, wantRoutes)
		}
	}

	// Cross-check: every primary prefix appears exactly once across all nodes'
	// PrimaryRoutes results.
	seenPrefixes := make(map[netip.Prefix]types.NodeID)
	for id := types.NodeID(1); id <= 8; id++ {
		for _, p := range pr.PrimaryRoutes(id) {
			if prev, ok := seenPrefixes[p]; ok {
				t.Fatalf("invariant cross-check: prefix %s claimed by both node %d and node %d",
					p, prev, id)
			}
			seenPrefixes[p] = id
		}
	}
	if len(seenPrefixes) != len(primaries) {
		t.Fatalf("invariant cross-check: PrimaryRoutes across all nodes yields %d prefixes, but DebugJSON has %d",
			len(seenPrefixes), len(primaries))
	}
	for p, nodeID := range seenPrefixes {
		if primaries[p] != nodeID {
			t.Fatalf("invariant cross-check: prefix %s: PrimaryRoutes says node %d, DebugJSON says node %d",
				p, nodeID, primaries[p])
		}
	}

	// Verify DebugJSON available routes match model routes.
	if len(debug.AvailableRoutes) != len(model.routes) {
		t.Fatalf("available routes count mismatch: SUT=%d, model=%d",
			len(debug.AvailableRoutes), len(model.routes))
	}
	for nodeID, modelPrefixes := range model.routes {
		sutPrefixes, ok := debug.AvailableRoutes[nodeID]
		if !ok {
			t.Fatalf("node %d in model routes but not in SUT AvailableRoutes", nodeID)
		}
		modelSorted := make([]netip.Prefix, 0, len(modelPrefixes))
		for p := range modelPrefixes {
			modelSorted = append(modelSorted, p)
		}
		slices.SortFunc(modelSorted, netip.Prefix.Compare)
		// sutPrefixes are already sorted by DebugJSON.
		if !slices.Equal(sutPrefixes, modelSorted) {
			t.Fatalf("node %d routes mismatch:\n  SUT:   %v\n  model: %v",
				nodeID, sutPrefixes, modelSorted)
		}
	}

	_ = fmt.Sprintf("invariants checked: %d primaries, %d nodes", len(primaries), len(debug.AvailableRoutes))
}

// checkInvariantsStandalone verifies all required invariants without a reference model.
// Used by tests that don't maintain a parallel model but still want to check structural integrity.
func checkInvariantsStandalone(t *rapid.T, pr *PrimaryRoutes, knownNodeIDs []types.NodeID) {

	debug := pr.DebugJSON()

	// Collect all advertised prefixes.
	allAdvertised := make(map[netip.Prefix]bool)
	for _, prefixes := range debug.AvailableRoutes {
		for _, p := range prefixes {
			allAdvertised[p] = true
		}
	}

	// Collect primary assignments.
	primaries := make(map[netip.Prefix]types.NodeID, len(debug.PrimaryRoutes))
	for prefixStr, nodeID := range debug.PrimaryRoutes {
		p := netip.MustParsePrefix(prefixStr)
		primaries[p] = nodeID
	}

	// Invariant 1: Every advertised prefix has exactly one primary.
	for p := range allAdvertised {
		if _, ok := primaries[p]; !ok {
			t.Fatalf("invariant 1: prefix %s is advertised but has no primary", p)
		}
	}
	if len(primaries) != len(allAdvertised) {
		t.Fatalf("invariant 1: primaries count (%d) != advertised prefixes count (%d)",
			len(primaries), len(allAdvertised))
	}

	// Invariant 2: Primary is a valid advertiser.
	for p, nodeID := range primaries {
		nodeRoutes, ok := debug.AvailableRoutes[nodeID]
		if !ok {
			t.Fatalf("invariant 2: primary node %d for prefix %s has no routes", nodeID, p)
		}
		if !slices.Contains(nodeRoutes, p) {
			t.Fatalf("invariant 2: primary node %d for prefix %s does not advertise it", nodeID, p)
		}
	}

	// Invariant 3: No orphaned primaries.
	for p := range primaries {
		if !allAdvertised[p] {
			t.Fatalf("invariant 3: prefix %s has primary but no advertisers", p)
		}
	}

	// Invariant 4: No exit routes.
	for _, prefixes := range debug.AvailableRoutes {
		for _, p := range prefixes {
			if tsaddr.IsExitRoute(p) {
				t.Fatalf("invariant 4: exit route %s in available routes", p)
			}
		}
	}

	// Invariant 5: isPrimary index consistent - check all known nodes.
	expectedPrimaryNodes := make(map[types.NodeID]bool)
	for _, nodeID := range primaries {
		expectedPrimaryNodes[nodeID] = true
	}
	for _, id := range knownNodeIDs {
		routes := pr.PrimaryRoutes(id)
		hasPrimaries := len(routes) > 0
		shouldHave := expectedPrimaryNodes[id]
		if hasPrimaries != shouldHave {
			t.Fatalf("invariant 5: isPrimary inconsistency for node %d: has=%v, expected=%v",
				id, hasPrimaries, shouldHave)
		}
	}

	// Cross-check: each primary prefix appears exactly once.
	seenPrefixes := make(map[netip.Prefix]types.NodeID)
	for _, id := range knownNodeIDs {
		for _, p := range pr.PrimaryRoutes(id) {
			if prev, ok := seenPrefixes[p]; ok {
				t.Fatalf("cross-check: prefix %s claimed by both node %d and node %d", p, prev, id)
			}
			seenPrefixes[p] = id
		}
	}
}

// ---------- Test 1: Failover Chain ----------

// TestRapid_PrimaryRoutes_FailoverChain starts with N nodes (3-8, random non-sequential IDs)
// all advertising the same prefix, then removes them one at a time in random order.
// The test verifies the stability + failover interaction:
//   - The first node added is primary (stability).
//   - Removing a non-primary node does NOT change the primary.
//   - Removing the current primary causes failover to the lowest remaining ID.
//   - After all are removed, no primaries remain.
func TestRapid_PrimaryRoutes_FailoverChain(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate 3-8 distinct non-sequential node IDs from a wide range.
		numNodes := rapid.IntRange(3, 8).Draw(t, "numNodes")
		nodeIDs := rapid.SliceOfNDistinct(
			rapid.Custom(func(t *rapid.T) types.NodeID {
				return types.NodeID(rapid.Uint64Range(1, 500).Draw(t, "nid"))
			}),
			numNodes, numNodes,
			func(id types.NodeID) string { return fmt.Sprintf("%d", id) },
		).Draw(t, "nodeIDs")

		// Pick one random prefix.
		prefix := rapid.SampledFrom(prefixPool).Draw(t, "prefix")

		pr := New()
		model := newReferenceModel()

		// All nodes advertise the same prefix (add in generated order).
		for _, nid := range nodeIDs {
			pr.SetRoutes(nid, prefix)
			model.setRoutes(nid, []netip.Prefix{prefix})
		}

		allIDs := make([]types.NodeID, len(nodeIDs))
		copy(allIDs, nodeIDs)

		// Verify initial primary matches model (first node added, due to stability).
		debug := pr.DebugJSON()
		gotPrimary := debug.PrimaryRoutes[prefix.String()]
		wantPrimary := model.primaries[prefix]
		if gotPrimary != wantPrimary {
			t.Fatalf("initial primary: got %d, want %d (model)", gotPrimary, wantPrimary)
		}

		// Generate a random removal order by permuting a copy of the nodeIDs.
		removalOrder := rapid.Permutation(append([]types.NodeID(nil), nodeIDs...)).Draw(t, "removalOrder")

		remaining := make(map[types.NodeID]bool, len(nodeIDs))
		for _, id := range nodeIDs {
			remaining[id] = true
		}

		for step, removedID := range removalOrder {
			wasCurrentPrimary := (removedID == model.primaries[prefix])

			pr.SetRoutes(removedID) // remove
			model.setRoutes(removedID, nil)
			delete(remaining, removedID)

			if len(remaining) == 0 {
				// All removed: no primaries should exist.
				debug := pr.DebugJSON()
				if len(debug.PrimaryRoutes) != 0 {
					t.Fatalf("step %d: all nodes removed but primaries remain: %v", step, debug.PrimaryRoutes)
				}
				if len(model.primaries) != 0 {
					t.Fatalf("step %d: all nodes removed but model primaries remain: %v", step, model.primaries)
				}
				break
			}

			debug := pr.DebugJSON()
			gotPrimary, ok := debug.PrimaryRoutes[prefix.String()]
			if !ok {
				t.Fatalf("step %d: prefix %s has no primary after removing node %d",
					step, prefix, removedID)
			}
			wantPrimary := model.primaries[prefix]

			if gotPrimary != wantPrimary {
				t.Fatalf("step %d: after removing node %d (wasPrimary=%v), primary is %d, model wants %d",
					step, removedID, wasCurrentPrimary, gotPrimary, wantPrimary)
			}

			// If we removed the primary, the new primary must be the lowest remaining ID.
			if wasCurrentPrimary {
				remainingIDs := make([]types.NodeID, 0, len(remaining))
				for id := range remaining {
					remainingIDs = append(remainingIDs, id)
				}
				sort.Slice(remainingIDs, func(i, j int) bool { return remainingIDs[i] < remainingIDs[j] })
				expectedMinID := remainingIDs[0]
				if gotPrimary != expectedMinID {
					t.Fatalf("step %d: after removing primary %d, new primary is %d, want lowest remaining %d",
						step, removedID, gotPrimary, expectedMinID)
				}
			}

			// Also check structural invariants.
			checkInvariantsStandalone(t, pr, allIDs)
		}
	})
}

// ---------- Test 2: Overlapping Prefixes ----------

// TestRapid_PrimaryRoutes_OverlappingPrefixes tests that prefixes that share IP space
// (e.g., 10.X.0.0/16 and 10.X.0.0/24) are tracked independently with separate primaries.
// It verifies that operations on one prefix never affect the primary of another prefix,
// even when those prefixes overlap in IP address space.
func TestRapid_PrimaryRoutes_OverlappingPrefixes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a second octet to create a family of overlapping prefixes.
		secondOctet := rapid.IntRange(0, 255).Draw(t, "secondOctet")
		widePrefix := netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/16", secondOctet))
		narrowPrefix := netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/24", secondOctet))
		midPrefix := netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/20", secondOctet))

		// Generate 4 distinct node IDs.
		nodeIDs := rapid.SliceOfNDistinct(
			rapid.Custom(func(t *rapid.T) types.NodeID {
				return types.NodeID(rapid.Uint64Range(1, 200).Draw(t, "nid"))
			}),
			4, 4,
			func(id types.NodeID) string { return fmt.Sprintf("%d", id) },
		).Draw(t, "nodeIDs")
		nWide1, nWide2, nNarrow, nMid := nodeIDs[0], nodeIDs[1], nodeIDs[2], nodeIDs[3]

		pr := New()
		model := newReferenceModel()

		// Helper: verify SUT matches model for all three prefixes.
		checkPrimariesMatchModel := func(step string) {
			debug := pr.DebugJSON()
			for _, pfx := range []netip.Prefix{widePrefix, narrowPrefix, midPrefix} {
				modelPrimary, modelHas := model.primaries[pfx]
				sutPrimary, sutHas := debug.PrimaryRoutes[pfx.String()]
				if modelHas != sutHas {
					t.Fatalf("%s: prefix %s: model has primary=%v, SUT has primary=%v",
						step, pfx, modelHas, sutHas)
				}
				if modelHas && modelPrimary != sutPrimary {
					t.Fatalf("%s: prefix %s: model primary=%d, SUT primary=%d",
						step, pfx, modelPrimary, sutPrimary)
				}
			}
		}

		// Two nodes advertise the wide prefix.
		pr.SetRoutes(nWide1, widePrefix)
		model.setRoutes(nWide1, []netip.Prefix{widePrefix})
		pr.SetRoutes(nWide2, widePrefix)
		model.setRoutes(nWide2, []netip.Prefix{widePrefix})

		// One node advertises the narrow prefix.
		pr.SetRoutes(nNarrow, narrowPrefix)
		model.setRoutes(nNarrow, []netip.Prefix{narrowPrefix})

		// One node advertises the mid prefix.
		pr.SetRoutes(nMid, midPrefix)
		model.setRoutes(nMid, []netip.Prefix{midPrefix})

		// Check: three distinct prefixes, each with its own primary.
		debug := pr.DebugJSON()
		if len(debug.PrimaryRoutes) != 3 {
			t.Fatalf("expected 3 primary routes (wide, narrow, mid), got %d: %v",
				len(debug.PrimaryRoutes), debug.PrimaryRoutes)
		}

		// Wide primary should be nWide1 (first added, stability).
		checkPrimariesMatchModel("after initial setup")

		// Narrow prefix primary should be nNarrow (only advertiser).
		narrowPrimary := debug.PrimaryRoutes[narrowPrefix.String()]
		if narrowPrimary != nNarrow {
			t.Fatalf("narrow prefix %s: primary %d, want %d", narrowPrefix, narrowPrimary, nNarrow)
		}

		// Mid prefix primary should be nMid (only advertiser).
		midPrimary := debug.PrimaryRoutes[midPrefix.String()]
		if midPrimary != nMid {
			t.Fatalf("mid prefix %s: primary %d, want %d", midPrefix, midPrimary, nMid)
		}

		// Independence test: remove the wide prefix primary. Narrow and mid must be unaffected.
		widePrimary := model.primaries[widePrefix]
		pr.SetRoutes(widePrimary) // remove
		model.setRoutes(widePrimary, nil)

		checkPrimariesMatchModel("after removing wide primary")

		debug = pr.DebugJSON()
		// Narrow primary unchanged.
		if debug.PrimaryRoutes[narrowPrefix.String()] != nNarrow {
			t.Fatalf("after removing wide primary, narrow primary changed: got %d, want %d",
				debug.PrimaryRoutes[narrowPrefix.String()], nNarrow)
		}
		// Mid primary unchanged.
		if debug.PrimaryRoutes[midPrefix.String()] != nMid {
			t.Fatalf("after removing wide primary, mid primary changed: got %d, want %d",
				debug.PrimaryRoutes[midPrefix.String()], nMid)
		}

		// Now have the narrow node ALSO advertise the wide prefix.
		pr.SetRoutes(nNarrow, narrowPrefix, widePrefix)
		model.setRoutes(nNarrow, []netip.Prefix{narrowPrefix, widePrefix})

		checkPrimariesMatchModel("after narrow node adds wide")

		debug = pr.DebugJSON()
		// Narrow node should still be primary for narrow prefix.
		if debug.PrimaryRoutes[narrowPrefix.String()] != nNarrow {
			t.Fatalf("narrow prefix primary changed after adding wide to narrow node: got %d, want %d",
				debug.PrimaryRoutes[narrowPrefix.String()], nNarrow)
		}

		checkInvariantsStandalone(t, pr, nodeIDs)
	})
}

// ---------- Test 3: Rapid Flap ----------

// TestRapid_PrimaryRoutes_RapidFlap rapidly adds and removes the same nodes
// with changing prefix sets, verifying all invariants after every operation.
func TestRapid_PrimaryRoutes_RapidFlap(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pr := New()
		model := newReferenceModel()

		// Fixed set of 3 nodes and 2 prefixes.
		nodes := [3]types.NodeID{
			types.NodeID(rapid.Uint64Range(1, 100).Draw(t, "node0")),
			types.NodeID(rapid.Uint64Range(101, 200).Draw(t, "node1")),
			types.NodeID(rapid.Uint64Range(201, 300).Draw(t, "node2")),
		}
		allKnownIDs := nodes[:]
		prefixes := [2]netip.Prefix{
			rapid.SampledFrom(prefixPool).Draw(t, "prefix0"),
			rapid.SampledFrom(prefixPool[1:]).Draw(t, "prefix1"),
		}

		numOps := rapid.IntRange(20, 50).Draw(t, "numOps")

		for i := 0; i < numOps; i++ {
			// Pick a random node.
			nodeIdx := rapid.IntRange(0, 2).Draw(t, fmt.Sprintf("op%d_nodeIdx", i))
			node := nodes[nodeIdx]

			// Pick a random action: 0=remove, 1=add prefix0, 2=add prefix1, 3=add both.
			action := rapid.IntRange(0, 3).Draw(t, fmt.Sprintf("op%d_action", i))

			var setPrefixes []netip.Prefix
			switch action {
			case 0:
				// Remove: set empty.
				setPrefixes = nil
			case 1:
				setPrefixes = []netip.Prefix{prefixes[0]}
			case 2:
				setPrefixes = []netip.Prefix{prefixes[1]}
			case 3:
				setPrefixes = []netip.Prefix{prefixes[0], prefixes[1]}
			}

			gotChanged := pr.SetRoutes(node, setPrefixes...)
			modelChanged := model.setRoutes(node, setPrefixes)

			if gotChanged != modelChanged {
				t.Fatalf("op %d: SetRoutes(node=%d, prefixes=%v): changed mismatch: got %v, model %v\nSUT: %s",
					i, node, setPrefixes, gotChanged, modelChanged, pr.String())
			}

			// Check ALL invariants after every single operation.
			debug := pr.DebugJSON()
			primaries := make(map[netip.Prefix]types.NodeID)
			for pStr, nid := range debug.PrimaryRoutes {
				primaries[netip.MustParsePrefix(pStr)] = nid
			}

			// Cross-check with model.
			for p, modelNode := range model.primaries {
				sutNode, ok := primaries[p]
				if !ok {
					t.Fatalf("op %d: prefix %s in model but not SUT", i, p)
				}
				if sutNode != modelNode {
					t.Fatalf("op %d: prefix %s: SUT primary=%d, model primary=%d",
						i, p, sutNode, modelNode)
				}
			}
			for p, sutNode := range primaries {
				modelNode, ok := model.primaries[p]
				if !ok {
					t.Fatalf("op %d: prefix %s in SUT but not model", i, p)
				}
				if sutNode != modelNode {
					t.Fatalf("op %d: prefix %s: SUT primary=%d, model primary=%d",
						i, p, sutNode, modelNode)
				}
			}

			checkInvariantsStandalone(t, pr, allKnownIDs)
		}
	})
}

// ---------- Test 4: Bulk Operations ----------

// TestRapid_PrimaryRoutes_BulkOperations tests that SetRoutes with many prefixes
// at once works correctly, and that failover of many prefixes is atomic.
func TestRapid_PrimaryRoutes_BulkOperations(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate 10-20 distinct non-exit prefixes.
		numPrefixes := rapid.IntRange(10, 20).Draw(t, "numPrefixes")
		bulkPrefixes := make([]netip.Prefix, numPrefixes)
		for i := 0; i < numPrefixes; i++ {
			// Use 10.{i/256}.{i%256}.0/24 to guarantee uniqueness.
			bulkPrefixes[i] = netip.MustParsePrefix(
				fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
			)
		}

		node1 := types.NodeID(rapid.Uint64Range(1, 100).Draw(t, "node1"))
		node2 := types.NodeID(rapid.Uint64Range(101, 200).Draw(t, "node2"))
		allIDs := []types.NodeID{node1, node2}

		pr := New()

		// Node1 advertises all prefixes at once.
		changed := pr.SetRoutes(node1, bulkPrefixes...)
		if !changed {
			t.Fatal("adding all prefixes to node1 should report changed=true")
		}

		// Verify node1 is primary for all prefixes.
		debug := pr.DebugJSON()
		if len(debug.PrimaryRoutes) != numPrefixes {
			t.Fatalf("expected %d primaries, got %d", numPrefixes, len(debug.PrimaryRoutes))
		}
		for _, p := range bulkPrefixes {
			primary, ok := debug.PrimaryRoutes[p.String()]
			if !ok {
				t.Fatalf("prefix %s has no primary after node1 added", p)
			}
			if primary != node1 {
				t.Fatalf("prefix %s: primary is %d, want node1=%d", p, primary, node1)
			}
		}

		// Node2 also advertises ALL the same prefixes.
		changed = pr.SetRoutes(node2, bulkPrefixes...)
		// changed should be false: node1 is already primary for all, and it's still advertising.
		// Actually, node1 is still advertising so primaries don't change.
		if changed {
			t.Fatal("adding node2 as second advertiser should not change primaries (node1 still primary)")
		}

		// Verify node1 is still primary for all (stability).
		debug = pr.DebugJSON()
		for _, p := range bulkPrefixes {
			primary := debug.PrimaryRoutes[p.String()]
			if primary != node1 {
				t.Fatalf("after adding node2, prefix %s: primary is %d, want node1=%d (stability violation)",
					p, primary, node1)
			}
		}

		// Remove node1: ALL prefixes should fail over to node2 atomically.
		changed = pr.SetRoutes(node1) // remove
		if !changed {
			t.Fatal("removing node1 (primary for all) should report changed=true")
		}

		debug = pr.DebugJSON()
		if len(debug.PrimaryRoutes) != numPrefixes {
			t.Fatalf("after removing node1: expected %d primaries, got %d", numPrefixes, len(debug.PrimaryRoutes))
		}
		for _, p := range bulkPrefixes {
			primary, ok := debug.PrimaryRoutes[p.String()]
			if !ok {
				t.Fatalf("prefix %s has no primary after node1 removed", p)
			}
			if primary != node2 {
				t.Fatalf("prefix %s: primary is %d, want node2=%d after failover", p, primary, node2)
			}
		}

		checkInvariantsStandalone(t, pr, allIDs)

		// Remove node2: everything should be clean.
		changed = pr.SetRoutes(node2) // remove
		if !changed {
			t.Fatal("removing last node should report changed=true")
		}

		debug = pr.DebugJSON()
		if len(debug.PrimaryRoutes) != 0 {
			t.Fatalf("after removing all nodes, %d primaries remain", len(debug.PrimaryRoutes))
		}
		if len(debug.AvailableRoutes) != 0 {
			t.Fatalf("after removing all nodes, %d available routes remain", len(debug.AvailableRoutes))
		}
	})
}

// ---------- Test 5: Changed Return Value Oracle ----------

// TestRapid_PrimaryRoutes_ChangedReturnValue is an oracle test that tracks expected
// primaries manually and verifies that the `changed` return value from SetRoutes
// is true if and only if the set of (prefix, primary) pairs actually changed.
func TestRapid_PrimaryRoutes_ChangedReturnValue(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pr := New()

		// Track primaries as an oracle.
		oraclePrimaries := make(map[string]types.NodeID) // prefix string -> primary node

		// Snapshot the current primaries from the SUT.
		snapshotPrimaries := func() map[string]types.NodeID {
			debug := pr.DebugJSON()
			snap := make(map[string]types.NodeID, len(debug.PrimaryRoutes))
			for k, v := range debug.PrimaryRoutes {
				snap[k] = v
			}
			return snap
		}

		// Compare two primary maps.
		primariesEqual := func(a, b map[string]types.NodeID) bool {
			if len(a) != len(b) {
				return false
			}
			for k, v := range a {
				if b[k] != v {
					return false
				}
			}
			return true
		}

		allKnownIDs := make(map[types.NodeID]bool)

		numOps := rapid.IntRange(20, 50).Draw(t, "numOps")

		for i := 0; i < numOps; i++ {
			node := types.NodeID(rapid.Uint64Range(1, 20).Draw(t, fmt.Sprintf("op%d_node", i)))
			allKnownIDs[node] = true

			// Generate random prefixes (including possibly empty = removal).
			numP := rapid.IntRange(0, 4).Draw(t, fmt.Sprintf("op%d_numP", i))
			var setPrefixes []netip.Prefix
			for j := 0; j < numP; j++ {
				p := rapid.SampledFrom(prefixPool).Draw(t, fmt.Sprintf("op%d_p%d", i, j))
				setPrefixes = append(setPrefixes, p)
			}

			// Snapshot BEFORE the operation.
			before := snapshotPrimaries()

			// Execute.
			changed := pr.SetRoutes(node, setPrefixes...)

			// Snapshot AFTER the operation.
			after := snapshotPrimaries()

			// The oracle: changed should be true iff primaries actually differ.
			actuallyChanged := !primariesEqual(before, after)

			if changed != actuallyChanged {
				t.Fatalf("op %d: SetRoutes(node=%d, prefixes=%v): changed=%v, but primaries before=%v, after=%v (actuallyChanged=%v)",
					i, node, setPrefixes, changed, before, after, actuallyChanged)
			}

			// Update oracle.
			oraclePrimaries = after

			// Structural invariants.
			ids := make([]types.NodeID, 0, len(allKnownIDs))
			for id := range allKnownIDs {
				ids = append(ids, id)
			}
			checkInvariantsStandalone(t, pr, ids)
		}

		_ = oraclePrimaries // used implicitly via snapshotPrimaries
	})
}
