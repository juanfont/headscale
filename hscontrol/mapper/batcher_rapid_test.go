package mapper

// Property-based tests (rapid) for batcher and node_conn components
// that are testable without a database.

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/puzpuzpuz/xsync/v4"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
)

// ============================================================================
// Generators
// ============================================================================

// genTailcfgNodeID generates a tailcfg.NodeID in [1, 50].
func genTailcfgNodeID(t *rapid.T) tailcfg.NodeID {
	return tailcfg.NodeID(rapid.Uint64Range(1, 50).Draw(t, "tailcfgNodeID")) //nolint:gosec // test with small bounded values
}

// genTailcfgNodeIDSlice generates a slice of 0..maxLen unique tailcfg.NodeIDs.
func genTailcfgNodeIDSlice(maxLen int) *rapid.Generator[[]tailcfg.NodeID] {
	return rapid.Custom[[]tailcfg.NodeID](func(t *rapid.T) []tailcfg.NodeID {
		n := rapid.IntRange(0, maxLen).Draw(t, "numPeerIDs")
		seen := make(map[tailcfg.NodeID]bool, n)

		result := make([]tailcfg.NodeID, 0, n)
		for len(result) < n {
			id := genTailcfgNodeID(t)
			if !seen[id] {
				seen[id] = true
				result = append(result, id)
			}
		}

		return result
	})
}

// genTailcfgNodeIDSet generates a set (unique, sorted slice) of tailcfg.NodeIDs.
func genTailcfgNodeIDSet(maxLen int) *rapid.Generator[[]tailcfg.NodeID] {
	return rapid.Custom[[]tailcfg.NodeID](func(t *rapid.T) []tailcfg.NodeID {
		ids := genTailcfgNodeIDSlice(maxLen).Draw(t, "idSet")
		slices.Sort(ids)

		return ids
	})
}

// genNodeID generates a types.NodeID in [1, 20].
func genNodeID(t *rapid.T) types.NodeID {
	return types.NodeID(rapid.Uint64Range(1, 20).Draw(t, "nodeID"))
}

// genNodeIDSlice generates 0..maxLen unique NodeIDs.
func genNodeIDSlice(maxLen int) *rapid.Generator[[]types.NodeID] {
	return rapid.Custom[[]types.NodeID](func(t *rapid.T) []types.NodeID {
		n := rapid.IntRange(0, maxLen).Draw(t, "numNodeIDs")
		seen := make(map[types.NodeID]bool, n)

		result := make([]types.NodeID, 0, n)
		for len(result) < n {
			id := genNodeID(t)
			if !seen[id] {
				seen[id] = true
				result = append(result, id)
			}
		}

		return result
	})
}

// genMapResponseWithPeers generates a MapResponse with a Peers field containing
// the given IDs. If withPeersChanged or withPeersRemoved are true, those fields
// are also populated.
func genMapResponseFull(t *rapid.T) *tailcfg.MapResponse {
	now := time.Now()
	resp := &tailcfg.MapResponse{ControlTime: &now}

	mode := rapid.IntRange(0, 2).Draw(t, "respMode")
	switch mode {
	case 0: // Full peer list
		peerIDs := genTailcfgNodeIDSlice(15).Draw(t, "peersFull")

		resp.Peers = make([]*tailcfg.Node, len(peerIDs))
		for i, id := range peerIDs {
			resp.Peers[i] = &tailcfg.Node{ID: id}
		}
	case 1: // Incremental: PeersChanged
		changedIDs := genTailcfgNodeIDSlice(8).Draw(t, "peersChanged")

		resp.PeersChanged = make([]*tailcfg.Node, len(changedIDs))
		for i, id := range changedIDs {
			resp.PeersChanged[i] = &tailcfg.Node{ID: id}
		}
	case 2: // Incremental: PeersRemoved
		resp.PeersRemoved = genTailcfgNodeIDSlice(8).Draw(t, "peersRemoved")
	}

	return resp
}

// genChange generates a change.Change with various flag combinations.
func genChangeForBatcher(t *rapid.T) change.Change {
	return change.Change{
		Reason:                         rapid.SampledFrom([]string{"", "test", "policy"}).Draw(t, "reason"),
		TargetNode:                     types.NodeID(rapid.Uint64Range(0, 10).Draw(t, "targetNode")),
		OriginNode:                     types.NodeID(rapid.Uint64Range(0, 10).Draw(t, "originNode")),
		IncludeSelf:                    rapid.Bool().Draw(t, "includeSelf"),
		IncludeDERPMap:                 rapid.Bool().Draw(t, "includeDERPMap"),
		IncludeDNS:                     rapid.Bool().Draw(t, "includeDNS"),
		IncludeDomain:                  rapid.Bool().Draw(t, "includeDomain"),
		IncludePolicy:                  rapid.Bool().Draw(t, "includePolicy"),
		SendAllPeers:                   rapid.Bool().Draw(t, "sendAllPeers"),
		RequiresRuntimePeerComputation: rapid.Bool().Draw(t, "reqRuntimePeer"),
		PeersChanged:                   genNodeIDSlice(5).Draw(t, "peersChanged"),
		PeersRemoved:                   genNodeIDSlice(5).Draw(t, "peersRemoved"),
	}
}

// genAdversarialChange generates changes with conflicting or unusual flag
// combinations to stress edge cases in addToBatch:
//   - SendAllPeers + TargetNode set (broadcast override with target)
//   - PeersChanged ∩ PeersRemoved overlap (same node in both)
//   - OriginNode == TargetNode (self-referencing change)
//   - All flags true simultaneously
//   - Empty change with TargetNode set (should be filtered as no-op)
func genAdversarialChange(t *rapid.T) change.Change {
	mode := rapid.IntRange(0, 4).Draw(t, "adversarialMode")
	switch mode {
	case 0: // SendAllPeers + TargetNode set
		return change.Change{
			Reason:       "adversarial-sendall-target",
			TargetNode:   types.NodeID(rapid.Uint64Range(1, 10).Draw(t, "advTarget")),
			SendAllPeers: true,
			IncludeSelf:  rapid.Bool().Draw(t, "advSelf"),
			PeersChanged: genNodeIDSlice(3).Draw(t, "advChanged"),
		}
	case 1: // PeersChanged ∩ PeersRemoved overlap
		// Use high NodeIDs (100+) for ALL IDs in PeersRemoved (including
		// overlap) to avoid triggering the batcher's node cleanup logic
		// which deletes nodes whose IDs appear in change.PeersRemoved.
		nOverlap := rapid.IntRange(0, 3).Draw(t, "advOverlapN")

		overlap := make([]types.NodeID, nOverlap)
		for i := range overlap {
			overlap[i] = types.NodeID(rapid.Uint64Range(100, 200).Draw(t, fmt.Sprintf("advOverlap%d", i)))
		}

		extraChanged := genNodeIDSlice(2).Draw(t, "advExtraChanged")
		nExtra := rapid.IntRange(0, 2).Draw(t, "advExtraRemovedN")

		extraRemoved := make([]types.NodeID, nExtra)
		for i := range extraRemoved {
			extraRemoved[i] = types.NodeID(rapid.Uint64Range(100, 200).Draw(t, fmt.Sprintf("advExtraRemoved%d", i)))
		}

		return change.Change{
			Reason:       "adversarial-overlap",
			TargetNode:   0,
			PeersChanged: append(slices.Clone(overlap), extraChanged...),
			PeersRemoved: append(slices.Clone(overlap), extraRemoved...),
			IncludeSelf:  true,
		}
	case 2: // OriginNode == TargetNode (self-referencing)
		selfID := types.NodeID(rapid.Uint64Range(1, 10).Draw(t, "advSelfID"))

		return change.Change{
			Reason:       "adversarial-self-ref",
			TargetNode:   selfID,
			OriginNode:   selfID,
			IncludeSelf:  true,
			PeersChanged: []types.NodeID{selfID},
		}
	case 3: // All flags true simultaneously
		// Use high NodeIDs (100+) for PeersRemoved to avoid batcher node cleanup.
		nRemoved := rapid.IntRange(0, 5).Draw(t, "advAllRemovedN")

		removed := make([]types.NodeID, nRemoved)
		for i := range removed {
			removed[i] = types.NodeID(rapid.Uint64Range(100, 200).Draw(t, fmt.Sprintf("advAllRemoved%d", i)))
		}

		return change.Change{
			Reason:                         "adversarial-all-flags",
			TargetNode:                     types.NodeID(rapid.Uint64Range(1, 10).Draw(t, "advAllTarget")),
			OriginNode:                     types.NodeID(rapid.Uint64Range(1, 10).Draw(t, "advAllOrigin")),
			IncludeSelf:                    true,
			IncludeDERPMap:                 true,
			IncludeDNS:                     true,
			IncludeDomain:                  true,
			IncludePolicy:                  true,
			SendAllPeers:                   true,
			RequiresRuntimePeerComputation: true,
			PeersChanged:                   genNodeIDSlice(5).Draw(t, "advAllChanged"),
			PeersRemoved:                   removed,
		}
	default: // Empty change with TargetNode set
		return change.Change{
			Reason:     "adversarial-empty-target",
			TargetNode: types.NodeID(rapid.Uint64Range(1, 10).Draw(t, "advEmptyTarget")),
		}
	}
}

// genFullChange returns a change.FullUpdate() deterministically.
func genFullChange() change.Change {
	return change.FullUpdate()
}

// genTargetedChange generates a change targeted to a specific node.
func genTargetedChange(t *rapid.T, target types.NodeID) change.Change {
	return change.Change{
		Reason:       "targeted",
		TargetNode:   target,
		IncludeSelf:  rapid.Bool().Draw(t, "tIncSelf"),
		PeersChanged: genNodeIDSlice(3).Draw(t, "tPeersChanged"),
	}
}

// genBroadcastChange generates a change with TargetNode=0 (broadcast).
func genBroadcastChange(t *rapid.T) change.Change {
	return change.Change{
		Reason:       "broadcast",
		TargetNode:   0,
		IncludeSelf:  rapid.Bool().Draw(t, "bIncSelf"),
		PeersChanged: genNodeIDSlice(3).Draw(t, "bPeersChanged"),
	}
}

// ============================================================================
// Mock nodeConnection for generateMapResponse tests
// ============================================================================

// mockNC implements nodeConnection for testing generateMapResponse branching.
type mockNC struct {
	nid         types.NodeID
	ver         tailcfg.CapabilityVersion
	peers       *xsync.Map[tailcfg.NodeID, struct{}]
	sendCalled  int
	sendErr     error
	updateCalls int
}

func newMockNC(id types.NodeID) *mockNC {
	return &mockNC{
		nid:   id,
		ver:   100,
		peers: xsync.NewMap[tailcfg.NodeID, struct{}](),
	}
}

func (m *mockNC) nodeID() types.NodeID               { return m.nid }
func (m *mockNC) version() tailcfg.CapabilityVersion { return m.ver }

func (m *mockNC) send(data *tailcfg.MapResponse) error {
	m.sendCalled++
	return m.sendErr
}

func (m *mockNC) computePeerDiff(currentPeers []tailcfg.NodeID) []tailcfg.NodeID {
	currentSet := make(map[tailcfg.NodeID]struct{}, len(currentPeers))
	for _, id := range currentPeers {
		currentSet[id] = struct{}{}
	}

	var removed []tailcfg.NodeID

	m.peers.Range(func(id tailcfg.NodeID, _ struct{}) bool {
		if _, exists := currentSet[id]; !exists {
			removed = append(removed, id)
		}

		return true
	})

	return removed
}

func (m *mockNC) updateSentPeers(resp *tailcfg.MapResponse) {
	m.updateCalls++

	if resp == nil {
		return
	}

	if resp.Peers != nil {
		m.peers.Clear()

		for _, peer := range resp.Peers {
			m.peers.Store(peer.ID, struct{}{})
		}
	}

	for _, peer := range resp.PeersChanged {
		m.peers.Store(peer.ID, struct{}{})
	}

	for _, id := range resp.PeersRemoved {
		m.peers.Delete(id)
	}
}

// ============================================================================
// Property 1: computePeerDiff correctness
//
// For any lastSentPeers set L and currentPeers list C,
// computePeerDiff(C) returns exactly { x ∈ L | x ∉ C }.
// ============================================================================

func TestRapid_ComputePeerDiff_IsSetDifference(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mc := newMultiChannelNodeConn(1, nil)

		// Generate the "last sent" set and populate the xsync.Map.
		lastSent := genTailcfgNodeIDSet(20).Draw(t, "lastSent")
		for _, id := range lastSent {
			mc.lastSentPeers.Store(id, struct{}{})
		}

		// Generate the "current" peers (may overlap, may not).
		current := genTailcfgNodeIDSlice(20).Draw(t, "current")

		got := mc.computePeerDiff(current)

		// Build the expected set difference: lastSent \ current.
		currentSet := make(map[tailcfg.NodeID]struct{}, len(current))
		for _, id := range current {
			currentSet[id] = struct{}{}
		}

		var expected []tailcfg.NodeID

		for _, id := range lastSent {
			if _, inCurrent := currentSet[id]; !inCurrent {
				expected = append(expected, id)
			}
		}

		// Compare as sets (order is non-deterministic from xsync.Map.Range).
		slices.Sort(got)
		slices.Sort(expected)

		if !slices.Equal(got, expected) {
			t.Fatalf("computePeerDiff mismatch:\n  lastSent=%v\n  current=%v\n  got=%v\n  expected=%v",
				lastSent, current, got, expected)
		}
	})
}

// computePeerDiff with empty lastSentPeers always returns nil/empty.
func TestRapid_ComputePeerDiff_EmptyLastSent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mc := newMultiChannelNodeConn(1, nil)
		// lastSentPeers is empty

		current := genTailcfgNodeIDSlice(15).Draw(t, "current")
		got := mc.computePeerDiff(current)

		if len(got) != 0 {
			t.Fatalf("empty lastSentPeers should produce empty diff, got %v", got)
		}
	})
}

// computePeerDiff with empty current returns all of lastSent.
func TestRapid_ComputePeerDiff_EmptyCurrent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mc := newMultiChannelNodeConn(1, nil)

		lastSent := genTailcfgNodeIDSet(20).Draw(t, "lastSent")
		for _, id := range lastSent {
			mc.lastSentPeers.Store(id, struct{}{})
		}

		got := mc.computePeerDiff(nil)

		slices.Sort(got)
		// lastSent is already sorted from the generator.

		if !slices.Equal(got, lastSent) {
			t.Fatalf("empty current should return all lastSent:\n  lastSent=%v\n  got=%v",
				lastSent, got)
		}
	})
}

// ============================================================================
// Property 2: updateSentPeers + computePeerDiff roundtrip
//
// After updateSentPeers(resp) where resp has a full Peers list,
// computePeerDiff(samePeers) returns empty. If we then remove
// some peers from the current list, computePeerDiff returns exactly
// the removed ones.
// ============================================================================

func TestRapid_UpdateSentPeers_ThenDiff_Roundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mc := newMultiChannelNodeConn(1, nil)

		// Pre-populate with arbitrary old state that should be overwritten.
		oldPeers := genTailcfgNodeIDSlice(5).Draw(t, "oldPeers")
		for _, id := range oldPeers {
			mc.lastSentPeers.Store(id, struct{}{})
		}

		// Generate a new full peer list.
		peerIDs := genTailcfgNodeIDSet(15).Draw(t, "newPeers")
		now := time.Now()

		resp := &tailcfg.MapResponse{
			ControlTime: &now,
			Peers:       make([]*tailcfg.Node, len(peerIDs)),
		}
		for i, id := range peerIDs {
			resp.Peers[i] = &tailcfg.Node{ID: id}
		}

		mc.updateSentPeers(resp)

		// Diffing against the same list should yield nothing removed.
		diff := mc.computePeerDiff(peerIDs)
		if len(diff) != 0 {
			t.Fatalf("diff after sending same peers should be empty, got %v", diff)
		}

		// Now remove a random subset from the "current" list.
		if len(peerIDs) == 0 {
			return // nothing to remove
		}

		nRemove := rapid.IntRange(1, len(peerIDs)).Draw(t, "nRemove")
		// Shuffle deterministically via rapid's sampling.
		removeSet := make(map[tailcfg.NodeID]bool, nRemove)
		remaining := make([]tailcfg.NodeID, len(peerIDs))
		copy(remaining, peerIDs)

		for len(removeSet) < nRemove {
			idx := rapid.IntRange(0, len(remaining)-1).Draw(t, "removeIdx")
			removeSet[remaining[idx]] = true
			// Remove from remaining to avoid picking same index twice.
			remaining = slices.Delete(remaining, idx, idx+1)
		}

		// Build the reduced current list.
		var reduced []tailcfg.NodeID

		for _, id := range peerIDs {
			if !removeSet[id] {
				reduced = append(reduced, id)
			}
		}

		diff2 := mc.computePeerDiff(reduced)
		slices.Sort(diff2)

		// Build expected removed.
		var expectedRemoved []tailcfg.NodeID
		for id := range removeSet {
			expectedRemoved = append(expectedRemoved, id)
		}

		slices.Sort(expectedRemoved)

		if !slices.Equal(diff2, expectedRemoved) {
			t.Fatalf("after removing peers, diff mismatch:\n  removed=%v\n  diff=%v",
				expectedRemoved, diff2)
		}
	})
}

// updateSentPeers with incremental PeersChanged adds to tracked state.
func TestRapid_UpdateSentPeers_IncrementalAdd(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mc := newMultiChannelNodeConn(1, nil)

		// Start with a full list.
		initial := genTailcfgNodeIDSet(10).Draw(t, "initial")
		now := time.Now()

		resp := &tailcfg.MapResponse{
			ControlTime: &now,
			Peers:       make([]*tailcfg.Node, len(initial)),
		}
		for i, id := range initial {
			resp.Peers[i] = &tailcfg.Node{ID: id}
		}

		mc.updateSentPeers(resp)

		// Add some peers via PeersChanged.
		added := genTailcfgNodeIDSlice(5).Draw(t, "added")

		addResp := &tailcfg.MapResponse{
			ControlTime:  &now,
			PeersChanged: make([]*tailcfg.Node, len(added)),
		}
		for i, id := range added {
			addResp.PeersChanged[i] = &tailcfg.Node{ID: id}
		}

		mc.updateSentPeers(addResp)

		// All initial + added should be tracked.
		allExpected := make(map[tailcfg.NodeID]struct{}, len(initial)+len(added))
		for _, id := range initial {
			allExpected[id] = struct{}{}
		}

		for _, id := range added {
			allExpected[id] = struct{}{}
		}

		// Verify each expected peer is tracked.
		for id := range allExpected {
			if _, ok := mc.lastSentPeers.Load(id); !ok {
				t.Fatalf("peer %d should be tracked but is not", id)
			}
		}

		// Verify no extra peers are tracked.
		mc.lastSentPeers.Range(func(id tailcfg.NodeID, _ struct{}) bool {
			if _, ok := allExpected[id]; !ok {
				t.Fatalf("unexpected tracked peer %d", id)
			}

			return true
		})
	})
}

// updateSentPeers with PeersRemoved deletes from tracked state.
func TestRapid_UpdateSentPeers_IncrementalRemove(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mc := newMultiChannelNodeConn(1, nil)

		// Start with a full list.
		initial := genTailcfgNodeIDSet(10).Draw(t, "initial")
		now := time.Now()

		resp := &tailcfg.MapResponse{
			ControlTime: &now,
			Peers:       make([]*tailcfg.Node, len(initial)),
		}
		for i, id := range initial {
			resp.Peers[i] = &tailcfg.Node{ID: id}
		}

		mc.updateSentPeers(resp)

		// Remove some peers.
		toRemove := genTailcfgNodeIDSlice(5).Draw(t, "toRemove")
		removeResp := &tailcfg.MapResponse{
			ControlTime:  &now,
			PeersRemoved: toRemove,
		}
		mc.updateSentPeers(removeResp)

		removeSet := make(map[tailcfg.NodeID]struct{}, len(toRemove))
		for _, id := range toRemove {
			removeSet[id] = struct{}{}
		}

		// Verify removed peers are gone, rest remain.
		for _, id := range initial {
			_, tracked := mc.lastSentPeers.Load(id)

			_, wasRemoved := removeSet[id]
			if wasRemoved && tracked {
				t.Fatalf("peer %d should have been removed but is still tracked", id)
			}

			if !wasRemoved && !tracked {
				t.Fatalf("peer %d should still be tracked but is missing", id)
			}
		}
	})
}

// updateSentPeers with nil response is a no-op.
func TestRapid_UpdateSentPeers_NilIsNoop(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mc := newMultiChannelNodeConn(1, nil)

		initial := genTailcfgNodeIDSet(10).Draw(t, "initial")
		for _, id := range initial {
			mc.lastSentPeers.Store(id, struct{}{})
		}

		mc.updateSentPeers(nil)

		// Count tracked peers - should be unchanged.
		var tracked []tailcfg.NodeID

		mc.lastSentPeers.Range(func(id tailcfg.NodeID, _ struct{}) bool {
			tracked = append(tracked, id)
			return true
		})
		slices.Sort(tracked)

		if !slices.Equal(tracked, initial) {
			t.Fatalf("nil updateSentPeers should be no-op:\n  before=%v\n  after=%v",
				initial, tracked)
		}
	})
}

// Sequence of random MapResponses applied via updateSentPeers maintains
// correct tracked state. Model-based test.
func TestRapid_UpdateSentPeers_ModelCheck(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mc := newMultiChannelNodeConn(1, nil)

		// The model: a plain Go map tracking what should be in lastSentPeers.
		model := make(map[tailcfg.NodeID]struct{})

		nOps := rapid.IntRange(1, 20).Draw(t, "nOps")
		for range nOps {
			resp := genMapResponseFull(t)
			mc.updateSentPeers(resp)

			// Apply same logic to model.
			if resp.Peers != nil {
				model = make(map[tailcfg.NodeID]struct{})
				for _, peer := range resp.Peers {
					model[peer.ID] = struct{}{}
				}
			}

			for _, peer := range resp.PeersChanged {
				model[peer.ID] = struct{}{}
			}

			for _, id := range resp.PeersRemoved {
				delete(model, id)
			}
		}

		// Verify the real state matches the model.
		actual := make(map[tailcfg.NodeID]struct{})

		mc.lastSentPeers.Range(func(id tailcfg.NodeID, _ struct{}) bool {
			actual[id] = struct{}{}
			return true
		})

		// Check model ⊆ actual.
		for id := range model {
			if _, ok := actual[id]; !ok {
				t.Fatalf("model has peer %d but actual does not", id)
			}
		}

		// Check actual ⊆ model.
		for id := range actual {
			if _, ok := model[id]; !ok {
				t.Fatalf("actual has peer %d but model does not", id)
			}
		}
	})
}

// ============================================================================
// Property 3: addToBatch FullUpdate override
//
// If any change in the batch is Full, every node's pending list should
// contain exactly one FullUpdate.
// ============================================================================

func TestRapid_AddToBatch_FullOverride(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b := NewBatcher(time.Hour, 1, nil) // tick won't fire during test

		// Register some nodes.
		nNodes := rapid.IntRange(1, 10).Draw(t, "nNodes")

		nodeIDs := make([]types.NodeID, nNodes)
		for i := range nodeIDs {
			nodeIDs[i] = types.NodeID(i + 1) //nolint:gosec // bounded loop variable
			b.nodes.Store(nodeIDs[i], newMultiChannelNodeConn(nodeIDs[i], nil))
		}

		// Pre-populate nodes with non-Full pending changes so we can
		// verify that a subsequent Full batch replaces them.
		nPreChanges := rapid.IntRange(1, 4).Draw(t, "nPreChanges")

		preChanges := make([]change.Change, nPreChanges)
		for i := range preChanges {
			preChanges[i] = change.Change{
				Reason:      fmt.Sprintf("pre-existing-%d", i),
				IncludeSelf: true, // non-empty
			}
		}
		// Add pre-existing changes as a broadcast (TargetNode=0) so every
		// node gets them.
		b.addToBatch(preChanges...)

		// Verify pre-population: every node should have pending changes.
		b.nodes.Range(func(nodeID types.NodeID, nc *multiChannelNodeConn) bool {
			if nc == nil {
				return true
			}

			nc.pendingMu.Lock()
			n := len(nc.pending)
			nc.pendingMu.Unlock()

			if n == 0 {
				t.Fatalf("node %d: pre-population failed, expected pending changes", nodeID)
			}

			return true
		})

		// Generate a batch of changes, ensuring at least one is Full.
		// Mix in adversarial changes to stress edge cases.
		nChanges := rapid.IntRange(1, 8).Draw(t, "nChanges")

		changes := make([]change.Change, nChanges)
		for i := range changes {
			if rapid.IntRange(0, 2).Draw(t, fmt.Sprintf("changeType%d", i)) == 0 {
				changes[i] = genAdversarialChange(t)
			} else {
				changes[i] = genChangeForBatcher(t)
			}
		}

		// Insert a FullUpdate at a random position.
		fullIdx := rapid.IntRange(0, nChanges-1).Draw(t, "fullIdx")
		changes[fullIdx] = genFullChange()

		b.addToBatch(changes...)

		// Verify: every node should have pending == [FullUpdate()].
		// The pre-existing non-Full changes must have been replaced.
		b.nodes.Range(func(nodeID types.NodeID, nc *multiChannelNodeConn) bool {
			if nc == nil {
				return true
			}

			nc.pendingMu.Lock()
			pending := nc.pending
			nc.pendingMu.Unlock()

			if len(pending) != 1 {
				t.Fatalf("node %d: expected exactly 1 pending change after Full override, got %d (pre-existing changes were not replaced)",
					nodeID, len(pending))
			}

			if !pending[0].IsFull() {
				t.Fatalf("node %d: pending change should be Full, got %+v",
					nodeID, pending[0])
			}

			return true
		})
	})
}

// FullUpdate override is idempotent: two FullUpdates still yield one pending.
func TestRapid_AddToBatch_DoubleFullStillOne(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b := NewBatcher(time.Hour, 1, nil)

		nNodes := rapid.IntRange(1, 5).Draw(t, "nNodes")
		for i := range nNodes {
			id := types.NodeID(i + 1) //nolint:gosec // bounded loop variable
			b.nodes.Store(id, newMultiChannelNodeConn(id, nil))
		}

		// Two FullUpdates.
		b.addToBatch(genFullChange(), genFullChange())

		b.nodes.Range(func(nodeID types.NodeID, nc *multiChannelNodeConn) bool {
			if nc == nil {
				return true
			}

			nc.pendingMu.Lock()
			pending := nc.pending
			nc.pendingMu.Unlock()

			if len(pending) != 1 || !pending[0].IsFull() {
				t.Fatalf("node %d: expected exactly 1 Full pending, got %d changes",
					nodeID, len(pending))
			}

			return true
		})
	})
}

// ============================================================================
// Property 4: addToBatch targeted vs broadcast splitting
//
// Targeted changes (TargetNode != 0) appear only in the target node's
// pending list. Broadcast changes (TargetNode == 0) appear in all nodes'
// pending lists.
// ============================================================================

func TestRapid_AddToBatch_TargetedOnlyInTarget(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b := NewBatcher(time.Hour, 1, nil)

		// Register nodes.
		nNodes := rapid.IntRange(2, 8).Draw(t, "nNodes")

		nodeIDs := make([]types.NodeID, nNodes)
		for i := range nodeIDs {
			nodeIDs[i] = types.NodeID(i + 1) //nolint:gosec // bounded loop variable
			b.nodes.Store(nodeIDs[i], newMultiChannelNodeConn(nodeIDs[i], nil))
		}

		// Pick a target node that exists.
		targetIdx := rapid.IntRange(0, nNodes-1).Draw(t, "targetIdx")
		target := nodeIDs[targetIdx]

		// Generate a targeted change. Must not be Full to avoid the
		// Full override path.
		ch := genTargetedChange(t, target)
		// Ensure it's not Full so the targeted path is taken.
		ch.SendAllPeers = false

		b.addToBatch(ch)

		// Verify: only target has this change.
		b.nodes.Range(func(nodeID types.NodeID, nc *multiChannelNodeConn) bool {
			if nc == nil {
				return true
			}

			nc.pendingMu.Lock()
			pending := nc.pending
			nc.pendingMu.Unlock()

			if nodeID == target {
				if len(pending) == 0 {
					t.Fatalf("target node %d should have pending changes", nodeID)
				}
			} else {
				if len(pending) != 0 {
					t.Fatalf("non-target node %d should have no pending changes, got %d",
						nodeID, len(pending))
				}
			}

			return true
		})
	})
}

func TestRapid_AddToBatch_BroadcastReachesAll(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b := NewBatcher(time.Hour, 1, nil)

		// Register nodes.
		nNodes := rapid.IntRange(1, 8).Draw(t, "nNodes")

		nodeIDs := make([]types.NodeID, nNodes)
		for i := range nodeIDs {
			nodeIDs[i] = types.NodeID(i + 1) //nolint:gosec // bounded loop variable
			b.nodes.Store(nodeIDs[i], newMultiChannelNodeConn(nodeIDs[i], nil))
		}

		// Generate a non-empty broadcast change.
		ch := genBroadcastChange(t)
		if ch.IsEmpty() {
			ch.IncludeSelf = true // ensure non-empty
		}

		b.addToBatch(ch)

		// Verify: every node has at least one pending change.
		b.nodes.Range(func(nodeID types.NodeID, nc *multiChannelNodeConn) bool {
			if nc == nil {
				return true
			}

			nc.pendingMu.Lock()
			pending := nc.pending
			nc.pendingMu.Unlock()

			if len(pending) == 0 {
				t.Fatalf("node %d should have pending broadcast changes", nodeID)
			}

			return true
		})
	})
}

// Mixed targeted + broadcast: targeted appears only in target, broadcast in all.
func TestRapid_AddToBatch_MixedTargetedAndBroadcast(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b := NewBatcher(time.Hour, 1, nil)

		nNodes := rapid.IntRange(2, 6).Draw(t, "nNodes")

		nodeIDs := make([]types.NodeID, nNodes)
		for i := range nodeIDs {
			nodeIDs[i] = types.NodeID(i + 1) //nolint:gosec // bounded loop variable
			b.nodes.Store(nodeIDs[i], newMultiChannelNodeConn(nodeIDs[i], nil))
		}

		// One broadcast (non-empty, non-full).
		bcast := genBroadcastChange(t)
		if bcast.IsEmpty() {
			bcast.IncludeSelf = true
		}

		bcast.SendAllPeers = false
		bcast.IncludePolicy = false
		bcast.IncludeDERPMap = false
		bcast.IncludeDNS = false
		bcast.IncludeDomain = false

		// One targeted.
		targetIdx := rapid.IntRange(0, nNodes-1).Draw(t, "targetIdx")
		target := nodeIDs[targetIdx]
		tgt := genTargetedChange(t, target)
		tgt.SendAllPeers = false

		b.addToBatch(bcast, tgt)

		b.nodes.Range(func(nodeID types.NodeID, nc *multiChannelNodeConn) bool {
			if nc == nil {
				return true
			}

			nc.pendingMu.Lock()
			pending := nc.pending
			nc.pendingMu.Unlock()

			if nodeID == target {
				// Should have both broadcast and targeted.
				if len(pending) < 2 {
					t.Fatalf("target node %d should have ≥2 pending, got %d",
						nodeID, len(pending))
				}
			} else {
				// Should have only broadcast (1 change after FilterForNode).
				// Note: broadcast changes with TargetNode=0 pass FilterForNode
				// for all nodes, so each non-target gets exactly the broadcast.
				hasTargeted := false

				for _, p := range pending {
					if p.TargetNode != 0 && p.TargetNode != nodeID {
						hasTargeted = true
					}
				}

				if hasTargeted {
					t.Fatalf("non-target node %d has targeted change for another node",
						nodeID)
				}
			}

			return true
		})
	})
}

// ============================================================================
// Property 5: generateMapResponse branching logic
//
// Test the guard-clause branches without a real mapper/DB.
// ============================================================================

// Empty change → (nil, nil).
func TestRapid_GenerateMapResponse_EmptyChange_AlwaysNil(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		id := genNodeID(t)
		nc := newMockNC(id)

		resp, err := generateMapResponse(nc, nil, change.Change{})
		if err != nil {
			t.Fatalf("empty change should not error, got %v", err)
		}

		if resp != nil {
			t.Fatal("empty change should return nil response")
		}
	})
}

// nodeID=0 with non-empty change → ErrInvalidNodeID.
func TestRapid_GenerateMapResponse_ZeroNodeID_Error(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ch := genChangeForBatcher(t)
		if ch.IsEmpty() {
			ch.IncludeSelf = true
		}

		nc := newMockNC(0)
		_, err := generateMapResponse(nc, &mapper{}, ch)

		if !errors.Is(err, ErrInvalidNodeID) {
			t.Fatalf("expected ErrInvalidNodeID, got %v", err)
		}
	})
}

// nil mapper with valid nodeID and non-empty change → ErrMapperNil.
func TestRapid_GenerateMapResponse_NilMapper_Error(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		id := genNodeID(t)
		nc := newMockNC(id)

		ch := genChangeForBatcher(t)
		if ch.IsEmpty() {
			ch.IncludeSelf = true
		}

		_, err := generateMapResponse(nc, nil, ch)

		if !errors.Is(err, ErrMapperNil) {
			t.Fatalf("expected ErrMapperNil, got %v", err)
		}
	})
}

// SelfOnly change targeted at a different node → (nil, nil).
func TestRapid_GenerateMapResponse_SelfOnlyOtherNode(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		myID := genNodeID(t)
		// Ensure targetID differs from myID.
		targetID := genNodeID(t)
		if targetID == myID {
			if targetID < 20 {
				targetID++
			} else {
				targetID--
			}
		}

		nc := newMockNC(myID)
		ch := change.SelfUpdate(targetID)

		// SelfUpdate(X) is self-only when X != 0.
		if !ch.IsSelfOnly() {
			t.Skip("generated change is not self-only")
		}

		resp, err := generateMapResponse(nc, &mapper{}, ch)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}

		if resp != nil {
			t.Fatal("self-only change for other node should return nil response")
		}
	})
}

// SelfOnly change targeted at *same* node is NOT short-circuited
// (it proceeds to mapper calls, which we can't test without DB).
// But we can verify the guard condition doesn't filter it.
func TestRapid_GenerateMapResponse_SelfOnlySameNode_NotFiltered(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		id := genNodeID(t)
		ch := change.SelfUpdate(id)

		// Verify the guard: IsSelfOnly() && TargetNode != nodeID should be false.
		if ch.IsSelfOnly() && ch.TargetNode != id {
			t.Fatal("self-update should not be filtered for same node")
		}
	})
}

// ============================================================================
// Property 6: multiChannelNodeConn.send fan-out
//
// Sending to N connections delivers to all active ones and removes
// failed/timed-out ones.
// ============================================================================

func TestRapid_MultiChannelSend_FanOut(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mc := newMultiChannelNodeConn(1, nil)

		nGood := rapid.IntRange(0, 5).Draw(t, "nGood")
		nBad := rapid.IntRange(0, 3).Draw(t, "nBad")

		if nGood+nBad == 0 {
			// No connections: send should succeed silently.
			now := time.Now()

			err := mc.send(&tailcfg.MapResponse{ControlTime: &now})
			if err != nil {
				t.Fatalf("send with 0 connections should succeed, got %v", err)
			}

			return
		}

		goodChans := make([]chan *tailcfg.MapResponse, nGood)
		for i := range goodChans {
			goodChans[i] = make(chan *tailcfg.MapResponse, 1) // buffered = will succeed
			mc.addConnection(makeConnectionEntry(
				fmt.Sprintf("good-%d", i), goodChans[i]))
		}

		badChans := make([]chan *tailcfg.MapResponse, nBad)
		for i := range badChans {
			badChans[i] = make(chan *tailcfg.MapResponse) // unbuffered, no reader = timeout
			mc.addConnection(makeConnectionEntry(
				fmt.Sprintf("bad-%d", i), badChans[i]))
		}

		now := time.Now()
		data := &tailcfg.MapResponse{ControlTime: &now}

		err := mc.send(data)

		if nGood > 0 {
			// At least one success → no error.
			if err != nil {
				t.Fatalf("expected no error with %d good connections, got %v", nGood, err)
			}
		} else {
			// All bad → error expected.
			if err == nil {
				t.Fatal("expected error when all connections fail")
			}
		}

		// Verify good channels received data.
		for i, ch := range goodChans {
			select {
			case received := <-ch:
				if received != data {
					t.Fatalf("good channel %d received wrong data", i)
				}
			default:
				t.Fatalf("good channel %d should have received data", i)
			}
		}

		// Verify bad connections were removed.
		remaining := mc.getActiveConnectionCount()
		if remaining != nGood {
			t.Fatalf("expected %d active connections after send, got %d",
				nGood, remaining)
		}
	})
}

// After sending with partial failure, the failed connections are actually
// removed and subsequent sends only go to remaining good connections.
func TestRapid_MultiChannelSend_FailedRemoved_Persistent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mc := newMultiChannelNodeConn(1, nil)

		nGood := rapid.IntRange(1, 4).Draw(t, "nGood")
		nBad := rapid.IntRange(1, 3).Draw(t, "nBad")

		goodChans := make([]chan *tailcfg.MapResponse, nGood)
		for i := range goodChans {
			goodChans[i] = make(chan *tailcfg.MapResponse, 10)
			mc.addConnection(makeConnectionEntry(
				fmt.Sprintf("good-%d", i), goodChans[i]))
		}

		for i := range nBad {
			badCh := make(chan *tailcfg.MapResponse)
			mc.addConnection(makeConnectionEntry(
				fmt.Sprintf("bad-%d", i), badCh))
		}

		// First send: removes bad connections.
		now := time.Now()
		_ = mc.send(&tailcfg.MapResponse{ControlTime: &now})

		// Second send: should succeed with only good connections.
		now2 := time.Now()
		data2 := &tailcfg.MapResponse{ControlTime: &now2}

		err := mc.send(data2)
		if err != nil {
			t.Fatalf("second send should succeed with only good connections, got %v", err)
		}

		if mc.getActiveConnectionCount() != nGood {
			t.Fatalf("expected %d active after second send, got %d",
				nGood, mc.getActiveConnectionCount())
		}
	})
}

// Concurrent send and add: no panics, data integrity maintained.
func TestRapid_MultiChannelSend_ConcurrentSafety(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mc := newMultiChannelNodeConn(1, nil)

		nInitial := rapid.IntRange(1, 3).Draw(t, "nInitial")
		for i := range nInitial {
			ch := make(chan *tailcfg.MapResponse, 100)
			mc.addConnection(makeConnectionEntry(
				fmt.Sprintf("init-%d", i), ch))
		}

		nSends := rapid.IntRange(1, 10).Draw(t, "nSends")
		nAdds := rapid.IntRange(0, 5).Draw(t, "nAdds")

		var (
			wg       sync.WaitGroup
			panicked atomic.Bool
		)

		// Concurrent sends.

		wg.Go(func() {
			defer func() {
				if r := recover(); r != nil {
					panicked.Store(true)
				}
			}()

			for range nSends {
				now := time.Now()
				_ = mc.send(&tailcfg.MapResponse{ControlTime: &now})
			}
		})

		// Concurrent adds.

		wg.Go(func() {
			defer func() {
				if r := recover(); r != nil {
					panicked.Store(true)
				}
			}()

			for i := range nAdds {
				ch := make(chan *tailcfg.MapResponse, 100)
				mc.addConnection(makeConnectionEntry(
					fmt.Sprintf("add-%d", i), ch))
			}
		})

		wg.Wait()

		if panicked.Load() {
			t.Fatal("concurrent send + add should not panic")
		}
	})
}

// ============================================================================
// Property: addToBatch PeersRemoved cleanup
//
// When changes contain PeersRemoved node IDs, those nodes are deleted
// from the batcher's node map.
// ============================================================================

func TestRapid_AddToBatch_PeersRemovedCleanup(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b := NewBatcher(time.Hour, 1, nil)

		// Register nodes.
		nNodes := rapid.IntRange(2, 10).Draw(t, "nNodes")

		nodeIDs := make([]types.NodeID, nNodes)
		for i := range nodeIDs {
			nodeIDs[i] = types.NodeID(i + 1) //nolint:gosec // bounded loop variable
			b.nodes.Store(nodeIDs[i], newMultiChannelNodeConn(nodeIDs[i], nil))
		}

		// Pick some to remove via PeersRemoved.
		nRemove := rapid.IntRange(0, nNodes/2).Draw(t, "nRemove")
		removedIDs := make([]types.NodeID, nRemove)
		picked := make(map[int]bool)

		for i := range removedIDs {
			idx := rapid.IntRange(0, nNodes-1).Draw(t, fmt.Sprintf("removeIdx%d", i))
			for picked[idx] {
				idx = (idx + 1) % nNodes
			}

			picked[idx] = true
			removedIDs[i] = nodeIDs[idx]
		}

		ch := change.Change{
			Reason:       "node deleted",
			PeersRemoved: removedIDs,
			IncludeSelf:  true, // non-empty
		}

		b.addToBatch(ch)

		// Verify removed nodes are gone from the map.
		removedSet := make(map[types.NodeID]bool, len(removedIDs))
		for _, id := range removedIDs {
			removedSet[id] = true
		}

		b.nodes.Range(func(id types.NodeID, _ *multiChannelNodeConn) bool {
			if removedSet[id] {
				t.Fatalf("node %d should have been removed from batcher", id)
			}

			return true
		})

		// Verify non-removed nodes still exist.
		for _, id := range nodeIDs {
			if removedSet[id] {
				continue
			}

			if _, ok := b.nodes.Load(id); !ok {
				t.Fatalf("node %d should still exist in batcher", id)
			}
		}
	})
}

// ============================================================================
// Property: appendPending + drainPending roundtrip
//
// All appended changes are drained exactly once, in order.
// ============================================================================

func TestRapid_AppendDrainPending_Roundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mc := newMultiChannelNodeConn(1, nil)

		nBatches := rapid.IntRange(1, 5).Draw(t, "nBatches")

		allChanges := make([]change.Change, 0, nBatches*4)

		for i := range nBatches {
			nChanges := rapid.IntRange(0, 4).Draw(t, fmt.Sprintf("nChanges%d", i))

			batch := make([]change.Change, nChanges)
			for j := range batch {
				batch[j] = change.Change{
					Reason: fmt.Sprintf("batch%d-change%d", i, j),
				}
			}

			allChanges = append(allChanges, batch...)
			mc.appendPending(batch...)
		}

		drained := mc.drainPending()

		if len(drained) != len(allChanges) {
			t.Fatalf("drained %d changes, expected %d", len(drained), len(allChanges))
		}

		for i := range allChanges {
			if drained[i].Reason != allChanges[i].Reason {
				t.Fatalf("change %d: got reason %q, expected %q",
					i, drained[i].Reason, allChanges[i].Reason)
			}
		}

		// Second drain should be empty.
		drained2 := mc.drainPending()
		if len(drained2) != 0 {
			t.Fatalf("second drain should be empty, got %d changes", len(drained2))
		}
	})
}

// ============================================================================
// Property: connection lifecycle
//
// markConnected / markDisconnected / isConnected are consistent.
// ============================================================================

func TestRapid_ConnectionLifecycle(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mc := newMultiChannelNodeConn(1, nil)

		// Initially: no connections, but disconnectedAt is nil → isConnected = true.
		// (newly created nodes are considered connected)
		if !mc.isConnected() {
			t.Fatal("newly created node should be considered connected")
		}

		nOps := rapid.IntRange(1, 20).Draw(t, "nOps")

		// Model: track whether we expect connected state.
		hasActiveConns := false
		disconnectedAtNil := true // initially nil

		for range nOps {
			op := rapid.IntRange(0, 3).Draw(t, "op")
			switch op {
			case 0: // add connection
				ch := make(chan *tailcfg.MapResponse, 1)
				mc.addConnection(makeConnectionEntry("c", ch))

				hasActiveConns = true
			case 1: // mark connected
				mc.markConnected()

				disconnectedAtNil = true
			case 2: // mark disconnected
				mc.markDisconnected()

				disconnectedAtNil = false
			case 3: // remove all connections
				mc.mutex.Lock()
				mc.connections = nil
				mc.mutex.Unlock()

				hasActiveConns = false
			}

			// isConnected = hasActiveConnections || disconnectedAt == nil
			expected := hasActiveConns || disconnectedAtNil
			got := mc.isConnected()

			if got != expected {
				t.Fatalf("isConnected mismatch after op %d: got %v, expected %v (hasActive=%v, disconnectedAtNil=%v)",
					op, got, expected, hasActiveConns, disconnectedAtNil)
			}
		}
	})
}

// ============================================================================
// Test 1: FilterForNode does NOT filter out changes where OriginNode == nodeID
//
// The prompt asks: "does FilterForNode skip self-origin changes?"
// Answer: NO. FilterForNode only checks TargetNode (via ShouldSendToNode).
// OriginNode filtering happens later in generateMapResponse.
// This test documents (and verifies) that FilterForNode passes through
// broadcast changes regardless of OriginNode, meaning each node's pending
// list WILL contain changes whose OriginNode matches that node.
// ============================================================================

func TestRapid_AddToBatch_FilterForNode_SkipsSelfOrigin(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b := NewBatcher(time.Hour, 1, nil)

		// 4 fixed nodes
		nodeIDs := []types.NodeID{1, 2, 3, 4}
		for _, id := range nodeIDs {
			b.nodes.Store(id, newMultiChannelNodeConn(id, nil))
		}

		// Generate 3-8 broadcast changes with varying OriginNode values
		nChanges := rapid.IntRange(3, 8).Draw(t, "nChanges")

		changes := make([]change.Change, nChanges)
		for i := range changes {
			origin := rapid.SampledFrom(nodeIDs).Draw(t, fmt.Sprintf("origin%d", i))
			changes[i] = change.Change{
				Reason:       fmt.Sprintf("broadcast-from-%d", origin),
				TargetNode:   0, // broadcast
				OriginNode:   origin,
				PeersChanged: []types.NodeID{origin}, // the origin changed itself
				IncludeSelf:  true,
			}
		}

		b.addToBatch(changes...)

		// Check each node's pending list.
		// KEY FINDING: FilterForNode does NOT remove changes where OriginNode == nodeID.
		// ShouldSendToNode only checks TargetNode, not OriginNode.
		// So each node WILL see broadcast changes even when OriginNode == that node.
		//
		// If FilterForNode DID filter OriginNode, we'd expect:
		//   node 1's pending would NOT contain changes with OriginNode=1
		// But in reality, node 1's pending DOES contain those changes.
		//
		// This documents the actual behavior (not a bug — the OriginNode filtering
		// happens later in generateMapResponse via the isSelfUpdate check).

		for _, nodeID := range nodeIDs {
			nc, ok := b.nodes.Load(nodeID)
			if !ok || nc == nil {
				t.Fatalf("node %d missing from batcher", nodeID)
			}

			nc.pendingMu.Lock()
			pending := make([]change.Change, len(nc.pending))
			copy(pending, nc.pending)
			nc.pendingMu.Unlock()

			// Every broadcast change should appear in every node's pending,
			// including changes where OriginNode == nodeID.
			// This is the ACTUAL behavior of FilterForNode.
			if len(pending) != nChanges {
				t.Fatalf("node %d: expected %d pending changes (all broadcasts), got %d — "+
					"FilterForNode is unexpectedly filtering broadcast changes",
					nodeID, nChanges, len(pending))
			}

			// Verify that self-origin changes ARE present (documenting actual behavior)
			hasSelfOrigin := false

			for _, p := range pending {
				if p.OriginNode == nodeID {
					hasSelfOrigin = true
					break
				}
			}

			// Count how many broadcast changes have this node as origin
			selfOriginCount := 0

			for _, ch := range changes {
				if ch.OriginNode == nodeID {
					selfOriginCount++
				}
			}

			if selfOriginCount > 0 && !hasSelfOrigin {
				t.Fatalf("node %d: expected self-origin changes in pending (FilterForNode doesn't filter OriginNode), "+
					"but none found — this indicates FilterForNode behavior changed",
					nodeID)
			}
		}
	})
}

// ============================================================================
// Test 2: Targeted + Broadcast interaction
//
// When a batch contains BOTH a targeted change for node 1 AND a broadcast
// change, node 1 should get both. Non-target nodes get only broadcast.
// ============================================================================

func TestRapid_AddToBatch_TargetedBroadcastInteraction(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b := NewBatcher(time.Hour, 1, nil)

		// 4 fixed nodes
		nodeIDs := []types.NodeID{1, 2, 3, 4}
		for _, id := range nodeIDs {
			b.nodes.Store(id, newMultiChannelNodeConn(id, nil))
		}

		// A targeted change for node 1
		targeted := change.Change{
			Reason:      "targeted-for-1",
			TargetNode:  1,
			IncludeSelf: true,
			PeersChanged: []types.NodeID{
				rapid.SampledFrom(nodeIDs).Draw(t, "targetedPeer"),
			},
		}

		// A broadcast change with PeersChanged=[2,3]
		broadcast := change.Change{
			Reason:       "broadcast-peers",
			TargetNode:   0,
			PeersChanged: []types.NodeID{2, 3},
		}

		b.addToBatch(targeted, broadcast)

		// Node 1: should have BOTH targeted + broadcast
		nc1, _ := b.nodes.Load(types.NodeID(1))
		nc1.pendingMu.Lock()
		pending1 := make([]change.Change, len(nc1.pending))
		copy(pending1, nc1.pending)
		nc1.pendingMu.Unlock()

		hasTargeted := false
		hasBroadcast := false

		for _, p := range pending1 {
			if p.TargetNode == 1 && p.Reason == "targeted-for-1" {
				hasTargeted = true
			}

			if p.TargetNode == 0 && p.Reason == "broadcast-peers" {
				hasBroadcast = true
			}
		}

		if !hasTargeted {
			t.Fatalf("node 1: missing targeted change, pending=%+v", pending1)
		}

		if !hasBroadcast {
			t.Fatalf("node 1: missing broadcast change, pending=%+v", pending1)
		}

		// Nodes 2, 3, 4: should have only broadcast (not the targeted change)
		for _, nodeID := range []types.NodeID{2, 3, 4} {
			nc, _ := b.nodes.Load(nodeID)
			nc.pendingMu.Lock()
			pending := make([]change.Change, len(nc.pending))
			copy(pending, nc.pending)
			nc.pendingMu.Unlock()

			for _, p := range pending {
				if p.TargetNode == 1 {
					t.Fatalf("node %d: should NOT have targeted change for node 1, but got %+v",
						nodeID, p)
				}
			}

			// Should have exactly the broadcast change
			if len(pending) != 1 {
				t.Fatalf("node %d: expected 1 pending (broadcast only), got %d",
					nodeID, len(pending))
			}

			if pending[0].Reason != "broadcast-peers" {
				t.Fatalf("node %d: expected broadcast change, got %+v",
					nodeID, pending[0])
			}
		}
	})
}

// ============================================================================
// Test 3: FullUpdate overrides targeted changes
//
// When addToBatch receives a Full change mixed with targeted changes,
// ALL nodes should have pending = [FullUpdate] only.
// Pre-existing targeted changes should also be overridden.
// ============================================================================

func TestRapid_AddToBatch_FullUpdateOverridesTargeted(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b := NewBatcher(time.Hour, 1, nil)

		// 4 fixed nodes
		nodeIDs := []types.NodeID{1, 2, 3, 4}
		for _, id := range nodeIDs {
			b.nodes.Store(id, newMultiChannelNodeConn(id, nil))
		}

		// Pre-populate nodes with targeted pending changes
		for _, id := range nodeIDs {
			nc, _ := b.nodes.Load(id)
			nc.appendPending(change.Change{
				Reason:      fmt.Sprintf("pre-existing-targeted-%d", id),
				TargetNode:  id,
				IncludeSelf: true,
			})
		}

		// Verify pre-population
		for _, id := range nodeIDs {
			nc, _ := b.nodes.Load(id)
			nc.pendingMu.Lock()
			n := len(nc.pending)
			nc.pendingMu.Unlock()

			if n == 0 {
				t.Fatalf("node %d: pre-population failed", id)
			}
		}

		// Build a batch containing: targeted change for node 1 + adversarial + FullUpdate
		// The Full should override everything.
		targetedForOne := change.Change{
			Reason:      "targeted-for-1-in-batch",
			TargetNode:  1,
			IncludeSelf: true,
			PeersChanged: []types.NodeID{
				rapid.SampledFrom([]types.NodeID{2, 3}).Draw(t, "peer"),
			},
		}
		fullUpdate := change.FullUpdate()

		// Optionally include an adversarial change in the batch.
		batch := []change.Change{targetedForOne, fullUpdate}
		if rapid.Bool().Draw(t, "includeAdversarial") {
			batch = append(batch, genAdversarialChange(t))
		}

		// Randomize order: sometimes targeted first, sometimes Full first
		if rapid.Bool().Draw(t, "fullFirst") {
			slices.Reverse(batch)
		}

		b.addToBatch(batch...)

		// Verify: ALL nodes should have pending = [FullUpdate()] ONLY.
		// The pre-existing targeted changes and the new targeted-for-1 should be gone.
		for _, id := range nodeIDs {
			nc, _ := b.nodes.Load(id)
			nc.pendingMu.Lock()
			pending := make([]change.Change, len(nc.pending))
			copy(pending, nc.pending)
			nc.pendingMu.Unlock()

			if len(pending) != 1 {
				t.Fatalf("node %d: expected exactly 1 pending change after Full override, got %d: %+v",
					id, len(pending), pending)
			}

			if !pending[0].IsFull() {
				t.Fatalf("node %d: pending change should be Full, got: %+v",
					id, pending[0])
			}
		}
	})
}

// ============================================================================
// Test 4: drainPending atomic swap
//
// After drainPending, the returned slice contains all previously pending
// changes, and the node's pending list is empty. No changes are lost.
// ============================================================================

func TestRapid_DrainPending_AtomicSwap(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		mc := newMultiChannelNodeConn(1, nil)

		// Add 5-20 random changes
		nChanges := rapid.IntRange(5, 20).Draw(t, "nChanges")

		expected := make([]change.Change, nChanges)
		for i := range expected {
			expected[i] = change.Change{
				Reason: fmt.Sprintf("change-%d", i),
				OriginNode: types.NodeID(
					rapid.Uint64Range(1, 10).Draw(t, fmt.Sprintf("origin%d", i)),
				),
				IncludeSelf:  rapid.Bool().Draw(t, fmt.Sprintf("self%d", i)),
				PeersChanged: genNodeIDSlice(3).Draw(t, fmt.Sprintf("peers%d", i)),
			}
		}

		// Append in random-sized batches
		remaining := expected
		for len(remaining) > 0 {
			batchSize := rapid.IntRange(1, len(remaining)).Draw(t, "batchSize")
			mc.appendPending(remaining[:batchSize]...)
			remaining = remaining[batchSize:]
		}

		// Drain
		drained := mc.drainPending()

		// 1. Returned slice contains all previously pending changes, in order
		if len(drained) != nChanges {
			t.Fatalf("expected %d drained changes, got %d", nChanges, len(drained))
		}

		for i, ch := range drained {
			if ch.Reason != expected[i].Reason {
				t.Fatalf("change %d: reason mismatch: got %q, want %q",
					i, ch.Reason, expected[i].Reason)
			}

			if ch.OriginNode != expected[i].OriginNode {
				t.Fatalf("change %d: OriginNode mismatch: got %d, want %d",
					i, ch.OriginNode, expected[i].OriginNode)
			}

			if ch.IncludeSelf != expected[i].IncludeSelf {
				t.Fatalf("change %d: IncludeSelf mismatch: got %v, want %v",
					i, ch.IncludeSelf, expected[i].IncludeSelf)
			}
		}

		// 2. The node's pending list is empty
		mc.pendingMu.Lock()
		pendingAfter := mc.pending
		mc.pendingMu.Unlock()

		if len(pendingAfter) != 0 {
			t.Fatalf("pending should be empty after drain, got %d changes", len(pendingAfter))
		}

		// 3. Second drain returns nothing
		drained2 := mc.drainPending()
		if len(drained2) != 0 {
			t.Fatalf("second drain should return empty, got %d changes", len(drained2))
		}
	})
}

// ============================================================================
// Test 5: PeersRemoved cleanup with PeersChanged conflict
//
// When a change has PeersChanged=[1,2] AND PeersRemoved=[2,3]:
//   - PeersRemoved processing happens FIRST in addToBatch (lines 529-538)
//   - Node 2 and 3 get deleted from batcher's node map
//   - Then broadcast processing runs, but node 2 is already gone
//   - So: node 2 is removed (PeersRemoved wins), node 3 is removed,
//     node 1 and 4 still exist
// ============================================================================

func TestRapid_AddToBatch_PeersRemovedCleanup_NoGhostNodes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b := NewBatcher(time.Hour, 1, nil)

		// 4 fixed nodes
		nodeIDs := []types.NodeID{1, 2, 3, 4}
		for _, id := range nodeIDs {
			b.nodes.Store(id, newMultiChannelNodeConn(id, nil))
		}

		// A change with PeersChanged=[1,2] AND PeersRemoved=[2,3]
		// This creates a conflict: node 2 is both "changed" and "removed"
		ch := change.Change{
			Reason:       "conflicting-change",
			TargetNode:   0, // broadcast
			PeersChanged: []types.NodeID{1, 2},
			PeersRemoved: []types.NodeID{2, 3},
		}

		b.addToBatch(ch)

		// Verify: node 2 is REMOVED (PeersRemoved runs first in addToBatch)
		if _, exists := b.nodes.Load(types.NodeID(2)); exists {
			t.Fatal("node 2 should be removed from batcher (PeersRemoved wins over PeersChanged)")
		}

		// Verify: node 3 is REMOVED
		if _, exists := b.nodes.Load(types.NodeID(3)); exists {
			t.Fatal("node 3 should be removed from batcher")
		}

		// Verify: node 1 still exists
		if _, exists := b.nodes.Load(types.NodeID(1)); !exists {
			t.Fatal("node 1 should still exist in batcher")
		}

		// Verify: node 4 still exists
		if _, exists := b.nodes.Load(types.NodeID(4)); !exists {
			t.Fatal("node 4 should still exist in batcher")
		}

		// Verify: node 1 and 4 received the broadcast change in their pending
		// (the change should be distributed to surviving nodes)
		for _, id := range []types.NodeID{1, 4} {
			nc, _ := b.nodes.Load(id)
			nc.pendingMu.Lock()
			pending := make([]change.Change, len(nc.pending))
			copy(pending, nc.pending)
			nc.pendingMu.Unlock()

			if len(pending) == 0 {
				t.Fatalf("node %d: should have received the broadcast change, but pending is empty", id)
			}

			found := false

			for _, p := range pending {
				if p.Reason == "conflicting-change" {
					found = true
					break
				}
			}

			if !found {
				t.Fatalf("node %d: pending should contain 'conflicting-change', got %+v", id, pending)
			}
		}

		// Additional property-based variation: randomize which nodes are in each set
		b2 := NewBatcher(time.Hour, 1, nil)

		allIDs := []types.NodeID{1, 2, 3, 4, 5, 6, 7, 8}
		for _, id := range allIDs {
			b2.nodes.Store(id, newMultiChannelNodeConn(id, nil))
		}

		// Pick random subsets for PeersChanged and PeersRemoved
		peersChanged := genNodeIDSlice(4).Draw(t, "rPeersChanged")
		peersRemoved := genNodeIDSlice(4).Draw(t, "rPeersRemoved")

		ch2 := change.Change{
			Reason:       "random-conflict",
			TargetNode:   0,
			PeersChanged: peersChanged,
			PeersRemoved: peersRemoved,
		}

		b2.addToBatch(ch2)

		// All nodes in PeersRemoved should be deleted from batcher
		removedSet := make(map[types.NodeID]bool)
		for _, id := range peersRemoved {
			removedSet[id] = true
		}

		for _, id := range allIDs {
			_, exists := b2.nodes.Load(id)
			if removedSet[id] && exists {
				t.Fatalf("node %d should be removed (in PeersRemoved) but still exists", id)
			}

			if !removedSet[id] && !exists {
				t.Fatalf("node %d should still exist (not in PeersRemoved) but is missing", id)
			}
		}
	})
}
