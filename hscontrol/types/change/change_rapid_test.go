package change

import (
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
)

// --- Generators ---

// genNodeID generates a small NodeID in [1, 20].
// Zero is excluded because it serves as the "unset" sentinel for
// OriginNode and TargetNode.
func genNodeID(t *rapid.T) types.NodeID {
	return types.NodeID(rapid.Uint64Range(1, 20).Draw(t, "nodeID"))
}

// genNodeIDSlice generates a slice of 0..8 non-zero NodeIDs.
// May contain duplicates, which exercises uniqueNodeIDs deduplication.
func genNodeIDSlice(t *rapid.T) []types.NodeID {
	return rapid.SliceOfN(rapid.Map(rapid.Uint64Range(1, 20), func(v uint64) types.NodeID {
		return types.NodeID(v)
	}), 0, 8).Draw(t, "nodeIDs")
}

// genPeerPatch generates a *tailcfg.PeerChange with a random NodeID.
func genPeerPatch(t *rapid.T) *tailcfg.PeerChange {
	return &tailcfg.PeerChange{
		NodeID: tailcfg.NodeID(rapid.Uint64Range(1, 20).Draw(t, "patchNodeID")), //nolint:gosec // test with small bounded values
	}
}

// genPeerPatches generates 0..4 PeerChange pointers.
func genPeerPatches(t *rapid.T) []*tailcfg.PeerChange {
	n := rapid.IntRange(0, 4).Draw(t, "numPatches")

	patches := make([]*tailcfg.PeerChange, n)
	for i := range patches {
		patches[i] = genPeerPatch(t)
	}

	return patches
}

// genReason generates a short reason string (possibly empty).
func genReason(t *rapid.T) string {
	return rapid.SampledFrom([]string{
		"", "policy", "route change", "tag change", "DERP update", "node added",
	}).Draw(t, "reason")
}

// genChange generates a fully random Change.
func genChange(t *rapid.T) Change {
	return Change{
		Reason:                         genReason(t),
		TargetNode:                     types.NodeID(rapid.Uint64Range(0, 10).Draw(t, "targetNode")),
		OriginNode:                     types.NodeID(rapid.Uint64Range(0, 10).Draw(t, "originNode")),
		IncludeSelf:                    rapid.Bool().Draw(t, "includeSelf"),
		IncludeDERPMap:                 rapid.Bool().Draw(t, "includeDERPMap"),
		IncludeDNS:                     rapid.Bool().Draw(t, "includeDNS"),
		IncludeDomain:                  rapid.Bool().Draw(t, "includeDomain"),
		IncludePolicy:                  rapid.Bool().Draw(t, "includePolicy"),
		SendAllPeers:                   rapid.Bool().Draw(t, "sendAllPeers"),
		RequiresRuntimePeerComputation: rapid.Bool().Draw(t, "requiresRuntimePeerComputation"),
		PeersChanged:                   genNodeIDSlice(t),
		PeersRemoved:                   genNodeIDSlice(t),
		PeerPatches:                    genPeerPatches(t),
	}
}

// genBoolOnlyChange generates a Change with only boolean fields set.
// Isolates boolean algebra properties from peer/reason complications.
func genBoolOnlyChange(t *rapid.T) Change {
	return Change{
		IncludeSelf:                    rapid.Bool().Draw(t, "includeSelf"),
		IncludeDERPMap:                 rapid.Bool().Draw(t, "includeDERPMap"),
		IncludeDNS:                     rapid.Bool().Draw(t, "includeDNS"),
		IncludeDomain:                  rapid.Bool().Draw(t, "includeDomain"),
		IncludePolicy:                  rapid.Bool().Draw(t, "includePolicy"),
		SendAllPeers:                   rapid.Bool().Draw(t, "sendAllPeers"),
		RequiresRuntimePeerComputation: rapid.Bool().Draw(t, "requiresRuntimePeerComputation"),
	}
}

// --- Helpers ---

// cloneChange creates a deep copy of a Change so that Merge's append
// aliasing bug cannot corrupt subsequent uses of the original.
func cloneChange(c Change) Change {
	out := c
	if c.PeersChanged != nil {
		out.PeersChanged = make([]types.NodeID, len(c.PeersChanged))
		copy(out.PeersChanged, c.PeersChanged)
	}

	if c.PeersRemoved != nil {
		out.PeersRemoved = make([]types.NodeID, len(c.PeersRemoved))
		copy(out.PeersRemoved, c.PeersRemoved)
	}

	if c.PeerPatches != nil {
		out.PeerPatches = make([]*tailcfg.PeerChange, len(c.PeerPatches))
		copy(out.PeerPatches, c.PeerPatches)
	}

	return out
}

// boolFields extracts all 7 boolean fields as a fixed-size array for comparison.
func boolFields(c Change) [7]bool {
	return [7]bool{
		c.IncludeSelf,
		c.IncludeDERPMap,
		c.IncludeDNS,
		c.IncludeDomain,
		c.IncludePolicy,
		c.SendAllPeers,
		c.RequiresRuntimePeerComputation,
	}
}

// nodeIDSet returns a sorted, deduplicated copy of ids for set comparison.
func nodeIDSet(ids []types.NodeID) []types.NodeID {
	if len(ids) == 0 {
		return nil
	}

	s := make([]types.NodeID, len(ids))
	copy(s, ids)
	slices.Sort(s)

	return slices.Compact(s)
}

// validTypes is the complete set of values Type() may return.
var validTypes = map[string]bool{
	"full":    true,
	"self":    true,
	"policy":  true,
	"patch":   true,
	"peers":   true,
	"config":  true,
	"unknown": true,
}

// -----------------------------------------------------------------------
// Property 1: Boolean commutativity
//   a.Merge(b) and b.Merge(a) produce identical boolean fields.
// -----------------------------------------------------------------------

func TestRapid_Merge_BooleanCommutativity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)
		b := genChange(t)

		ab := cloneChange(a).Merge(cloneChange(b))
		ba := cloneChange(b).Merge(cloneChange(a))

		if boolFields(ab) != boolFields(ba) {
			t.Fatalf("boolean commutativity violated:\n  a.Merge(b) = %v\n  b.Merge(a) = %v",
				boolFields(ab), boolFields(ba))
		}
	})
}

// -----------------------------------------------------------------------
// Property 2: Boolean associativity
//   (a.Merge(b)).Merge(c) == a.Merge(b.Merge(c)) for boolean fields.
// -----------------------------------------------------------------------

func TestRapid_Merge_BooleanAssociativity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genBoolOnlyChange(t)
		b := genBoolOnlyChange(t)
		c := genBoolOnlyChange(t)

		left := a.Merge(b).Merge(c)
		right := a.Merge(b.Merge(c))

		if boolFields(left) != boolFields(right) {
			t.Fatalf("boolean associativity violated:\n  (a⊕b)⊕c = %v\n  a⊕(b⊕c) = %v",
				boolFields(left), boolFields(right))
		}
	})
}

// -----------------------------------------------------------------------
// Property 3: Identity element
//   Merging with the zero-value Change preserves all fields (modulo
//   uniqueNodeIDs normalization of peer sets).
// -----------------------------------------------------------------------

func TestRapid_Merge_IdentityElement(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)
		zero := Change{}

		// --- right identity: a ⊕ zero ---
		rightID := cloneChange(a).Merge(zero)

		if boolFields(rightID) != boolFields(a) {
			t.Fatalf("right identity violated booleans:\n  a = %v\n  a⊕0 = %v",
				boolFields(a), boolFields(rightID))
		}

		if !slices.Equal(nodeIDSet(rightID.PeersChanged), nodeIDSet(a.PeersChanged)) {
			t.Fatalf("right identity violated PeersChanged:\n  a = %v\n  a⊕0 = %v",
				a.PeersChanged, rightID.PeersChanged)
		}

		if !slices.Equal(nodeIDSet(rightID.PeersRemoved), nodeIDSet(a.PeersRemoved)) {
			t.Fatalf("right identity violated PeersRemoved:\n  a = %v\n  a⊕0 = %v",
				a.PeersRemoved, rightID.PeersRemoved)
		}

		if len(rightID.PeerPatches) != len(a.PeerPatches) {
			t.Fatalf("right identity violated PeerPatches len: a=%d, a⊕0=%d",
				len(a.PeerPatches), len(rightID.PeerPatches))
		}

		if rightID.OriginNode != a.OriginNode {
			t.Fatalf("right identity violated OriginNode: a=%d, a⊕0=%d",
				a.OriginNode, rightID.OriginNode)
		}

		if rightID.TargetNode != a.TargetNode {
			t.Fatalf("right identity violated TargetNode: a=%d, a⊕0=%d",
				a.TargetNode, rightID.TargetNode)
		}

		if a.Reason != "" && rightID.Reason != a.Reason {
			t.Fatalf("right identity violated Reason: a=%q, a⊕0=%q",
				a.Reason, rightID.Reason)
		}

		// --- left identity: zero ⊕ a ---
		leftID := zero.Merge(cloneChange(a))

		if boolFields(leftID) != boolFields(a) {
			t.Fatalf("left identity violated booleans:\n  a = %v\n  0⊕a = %v",
				boolFields(a), boolFields(leftID))
		}

		if !slices.Equal(nodeIDSet(leftID.PeersChanged), nodeIDSet(a.PeersChanged)) {
			t.Fatalf("left identity violated PeersChanged:\n  a = %v\n  0⊕a = %v",
				a.PeersChanged, leftID.PeersChanged)
		}

		if !slices.Equal(nodeIDSet(leftID.PeersRemoved), nodeIDSet(a.PeersRemoved)) {
			t.Fatalf("left identity violated PeersRemoved:\n  a = %v\n  0⊕a = %v",
				a.PeersRemoved, leftID.PeersRemoved)
		}

		if len(leftID.PeerPatches) != len(a.PeerPatches) {
			t.Fatalf("left identity violated PeerPatches len: a=%d, 0⊕a=%d",
				len(a.PeerPatches), len(leftID.PeerPatches))
		}

		if leftID.OriginNode != a.OriginNode {
			t.Fatalf("left identity violated OriginNode: a=%d, 0⊕a=%d",
				a.OriginNode, leftID.OriginNode)
		}

		if leftID.TargetNode != a.TargetNode {
			t.Fatalf("left identity violated TargetNode: a=%d, 0⊕a=%d",
				a.TargetNode, leftID.TargetNode)
		}
	})
}

// -----------------------------------------------------------------------
// Property 4: Boolean idempotence
//   a.Merge(a) preserves all boolean values (OR is idempotent).
// -----------------------------------------------------------------------

func TestRapid_Merge_BooleanIdempotence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)

		aa := cloneChange(a).Merge(cloneChange(a))

		if boolFields(aa) != boolFields(a) {
			t.Fatalf("boolean idempotence violated:\n  a      = %v\n  a⊕a = %v",
				boolFields(a), boolFields(aa))
		}
	})
}

// -----------------------------------------------------------------------
// Property 5: Peer set commutativity
//   PeersChanged and PeersRemoved are commutative (set union).
// -----------------------------------------------------------------------

func TestRapid_Merge_PeerSetCommutativity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)
		b := genChange(t)

		ab := cloneChange(a).Merge(cloneChange(b))
		ba := cloneChange(b).Merge(cloneChange(a))

		if !slices.Equal(ab.PeersChanged, ba.PeersChanged) {
			t.Fatalf("PeersChanged commutativity violated:\n  a⊕b = %v\n  b⊕a = %v",
				ab.PeersChanged, ba.PeersChanged)
		}

		if !slices.Equal(ab.PeersRemoved, ba.PeersRemoved) {
			t.Fatalf("PeersRemoved commutativity violated:\n  a⊕b = %v\n  b⊕a = %v",
				ab.PeersRemoved, ba.PeersRemoved)
		}
	})
}

// -----------------------------------------------------------------------
// Property 6: IsEmpty monotonicity
//   Once non-empty, merging can never make it empty.
// -----------------------------------------------------------------------

func TestRapid_Merge_IsEmptyMonotonicity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)
		b := genChange(t)

		merged := cloneChange(a).Merge(cloneChange(b))

		if !a.IsEmpty() && merged.IsEmpty() {
			t.Fatalf("IsEmpty monotonicity violated (left non-empty):\n  a = %+v\n  b = %+v\n  a⊕b = %+v",
				a, b, merged)
		}

		if !b.IsEmpty() && merged.IsEmpty() {
			t.Fatalf("IsEmpty monotonicity violated (right non-empty):\n  a = %+v\n  b = %+v\n  a⊕b = %+v",
				a, b, merged)
		}
	})
}

// -----------------------------------------------------------------------
// Property 7: IsFull monotonicity
//   A full update stays full after merge.
// -----------------------------------------------------------------------

func TestRapid_Merge_IsFullMonotonicity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)
		b := genChange(t)

		merged := cloneChange(a).Merge(cloneChange(b))

		if a.IsFull() && !merged.IsFull() {
			t.Fatalf("IsFull monotonicity violated (left full):\n  a = %+v\n  a⊕b = %+v", a, merged)
		}

		if b.IsFull() && !merged.IsFull() {
			t.Fatalf("IsFull monotonicity violated (right full):\n  b = %+v\n  a⊕b = %+v", b, merged)
		}
	})
}

// -----------------------------------------------------------------------
// Property 8: FullUpdate absorption
//   Merging with FullUpdate() always yields IsFull().
// -----------------------------------------------------------------------

func TestRapid_Merge_FullUpdateAbsorption(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)
		full := FullUpdate()

		right := cloneChange(a).Merge(full)
		if !right.IsFull() {
			t.Fatalf("a⊕FullUpdate is not full:\n  a = %+v\n  result = %+v", a, right)
		}

		left := full.Merge(cloneChange(a))
		if !left.IsFull() {
			t.Fatalf("FullUpdate⊕a is not full:\n  a = %+v\n  result = %+v", a, left)
		}
	})
}

// -----------------------------------------------------------------------
// Property 9: Type classification soundness
//   Type() always returns one of the 7 known values.
// -----------------------------------------------------------------------

func TestRapid_Type_ClassificationSoundness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)

		typ := a.Type()
		if !validTypes[typ] {
			t.Fatalf("Type() returned %q, not in valid set %v", typ, validTypes)
		}
	})
}

// -----------------------------------------------------------------------
// Property 10: FilterForNode / SplitTargetedAndBroadcast partition
//   - broadcast ∪ targeted == input (size invariant)
//   - broadcast changes all have TargetNode==0
//   - targeted changes all have TargetNode!=0
//   - FilterForNode returns exactly the changes whose ShouldSendToNode is true
//   - Broadcast changes pass ShouldSendToNode for every node
// -----------------------------------------------------------------------

func TestRapid_FilterForNode_Partition(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(0, 10).Draw(t, "numChanges")

		cs := make([]Change, n)
		for i := range cs {
			cs[i] = genChange(t)
		}

		broadcast, targeted := SplitTargetedAndBroadcast(cs)

		// Size invariant.
		if len(broadcast)+len(targeted) != len(cs) {
			t.Fatalf("partition size: %d + %d != %d",
				len(broadcast), len(targeted), len(cs))
		}

		// Classification invariants.
		for i, c := range broadcast {
			if c.TargetNode != 0 {
				t.Fatalf("broadcast[%d].TargetNode = %d, want 0", i, c.TargetNode)
			}
		}

		for i, c := range targeted {
			if c.TargetNode == 0 {
				t.Fatalf("targeted[%d].TargetNode = 0, want non-zero", i)
			}
		}

		// FilterForNode completeness and soundness.
		testNodeID := genNodeID(t)
		filtered := FilterForNode(testNodeID, cs)

		for i, c := range filtered {
			if !c.ShouldSendToNode(testNodeID) {
				t.Fatalf("filtered[%d] should not be included for node %d", i, testNodeID)
			}
		}

		expectedCount := 0

		for _, c := range cs {
			if c.ShouldSendToNode(testNodeID) {
				expectedCount++
			}
		}

		if len(filtered) != expectedCount {
			t.Fatalf("FilterForNode(%d): got %d, want %d", testNodeID, len(filtered), expectedCount)
		}

		// Broadcast changes should reach every node.
		probeNode := genNodeID(t)
		for _, c := range broadcast {
			if !c.ShouldSendToNode(probeNode) {
				t.Fatalf("broadcast change not sent to node %d", probeNode)
			}
		}
	})
}

// -----------------------------------------------------------------------
// Property 11: HasFull equivalence
//   HasFull(cs) ↔ any element c in cs satisfies c.IsFull()
// -----------------------------------------------------------------------

func TestRapid_HasFull_Equivalence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(0, 10).Draw(t, "numChanges")

		cs := make([]Change, n)
		for i := range cs {
			cs[i] = genChange(t)
		}

		got := HasFull(cs)
		want := slices.ContainsFunc(cs, func(c Change) bool { return c.IsFull() })

		if got != want {
			t.Fatalf("HasFull=%v, ContainsFunc=%v for %d changes", got, want, len(cs))
		}
	})
}

// -----------------------------------------------------------------------
// Property 12: uniqueNodeIDs idempotent
//   uniqueNodeIDs(uniqueNodeIDs(x)) == uniqueNodeIDs(x)
// -----------------------------------------------------------------------

func TestRapid_UniqueNodeIDs_Idempotent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		raw := genNodeIDSlice(t)

		// Work on copies because uniqueNodeIDs sorts in-place.
		ids1 := make([]types.NodeID, len(raw))
		copy(ids1, raw)
		first := uniqueNodeIDs(ids1)

		if first == nil {
			return
		}

		ids2 := make([]types.NodeID, len(first))
		copy(ids2, first)
		second := uniqueNodeIDs(ids2)

		if !slices.Equal(first, second) {
			t.Fatalf("not idempotent: first=%v, second=%v", first, second)
		}
	})
}

// -----------------------------------------------------------------------
// Property 13: uniqueNodeIDs result is always sorted
// -----------------------------------------------------------------------

func TestRapid_UniqueNodeIDs_Sorted(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		raw := genNodeIDSlice(t)

		ids := make([]types.NodeID, len(raw))
		copy(ids, raw)
		result := uniqueNodeIDs(ids)

		if result != nil && !slices.IsSorted(result) {
			t.Fatalf("not sorted: %v", result)
		}
	})
}

// -----------------------------------------------------------------------
// Property 14: uniqueNodeIDs no duplicates
// -----------------------------------------------------------------------

func TestRapid_UniqueNodeIDs_NoDuplicates(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		raw := genNodeIDSlice(t)

		ids := make([]types.NodeID, len(raw))
		copy(ids, raw)
		result := uniqueNodeIDs(ids)

		for i := 1; i < len(result); i++ {
			if result[i] == result[i-1] {
				t.Fatalf("duplicate at index %d: %v", i, result)
			}
		}
	})
}

// -----------------------------------------------------------------------
// Property 15: uniqueNodeIDs preserves all input values
//   Every value in the input appears in the output (and vice-versa).
// -----------------------------------------------------------------------

func TestRapid_UniqueNodeIDs_PreservesValues(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		raw := genNodeIDSlice(t)

		ids := make([]types.NodeID, len(raw))
		copy(ids, raw)
		result := uniqueNodeIDs(ids)

		if len(raw) == 0 {
			if result != nil {
				t.Fatalf("uniqueNodeIDs(empty) = %v, want nil", result)
			}

			return
		}

		// All input values present in output.
		resultSet := make(map[types.NodeID]bool, len(result))
		for _, id := range result {
			resultSet[id] = true
		}

		for _, id := range raw {
			if !resultSet[id] {
				t.Fatalf("input value %d dropped: input=%v, output=%v", id, raw, result)
			}
		}

		// No extra values in output.
		inputSet := make(map[types.NodeID]bool, len(raw))
		for _, id := range raw {
			inputSet[id] = true
		}

		for _, id := range result {
			if !inputSet[id] {
				t.Fatalf("output value %d not in input: input=%v, output=%v", id, raw, result)
			}
		}
	})
}

// -----------------------------------------------------------------------
// Property 16: Mutation safety (documents known bug)
//   Merge must not mutate the receiver's or argument's slices.
//
// NOTE: This test documents a known bug in the current Merge implementation.
// Merge uses append(r.PeersChanged, other.PeersChanged...) which can write
// through to the receiver's backing array when it has spare capacity,
// corrupting the receiver's slice contents. The same applies to PeersRemoved
// and PeerPatches.
//
// This test is expected to FAIL until the bug is fixed. If it passes,
// the bug has been resolved and this comment can be removed.
// -----------------------------------------------------------------------

func TestRapid_Merge_MutationSafety(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)
		b := genChange(t)

		// Snapshot all slice fields before Merge.
		aPeersChanged := make([]types.NodeID, len(a.PeersChanged))
		copy(aPeersChanged, a.PeersChanged)
		aPeersRemoved := make([]types.NodeID, len(a.PeersRemoved))
		copy(aPeersRemoved, a.PeersRemoved)
		aPeerPatches := make([]*tailcfg.PeerChange, len(a.PeerPatches))
		copy(aPeerPatches, a.PeerPatches)

		bPeersChanged := make([]types.NodeID, len(b.PeersChanged))
		copy(bPeersChanged, b.PeersChanged)
		bPeersRemoved := make([]types.NodeID, len(b.PeersRemoved))
		copy(bPeersRemoved, b.PeersRemoved)
		bPeerPatches := make([]*tailcfg.PeerChange, len(b.PeerPatches))
		copy(bPeerPatches, b.PeerPatches)

		aBools := boolFields(a)
		bBools := boolFields(b)
		aOrigin, bOrigin := a.OriginNode, b.OriginNode
		aTarget, bTarget := a.TargetNode, b.TargetNode
		aReason, bReason := a.Reason, b.Reason

		_ = a.Merge(b)

		// Verify receiver (a) not mutated.
		if boolFields(a) != aBools {
			t.Fatal("Merge mutated receiver's boolean fields")
		}

		if a.OriginNode != aOrigin || a.TargetNode != aTarget || a.Reason != aReason {
			t.Fatal("Merge mutated receiver's scalar fields")
		}

		if !slices.Equal(a.PeersChanged, aPeersChanged) {
			t.Fatalf("Merge mutated receiver's PeersChanged: before=%v, after=%v",
				aPeersChanged, a.PeersChanged)
		}

		if !slices.Equal(a.PeersRemoved, aPeersRemoved) {
			t.Fatalf("Merge mutated receiver's PeersRemoved: before=%v, after=%v",
				aPeersRemoved, a.PeersRemoved)
		}

		if !slices.Equal(a.PeerPatches, aPeerPatches) {
			t.Fatal("Merge mutated receiver's PeerPatches")
		}

		// Verify argument (b) not mutated.
		if boolFields(b) != bBools {
			t.Fatal("Merge mutated argument's boolean fields")
		}

		if b.OriginNode != bOrigin || b.TargetNode != bTarget || b.Reason != bReason {
			t.Fatal("Merge mutated argument's scalar fields")
		}

		if !slices.Equal(b.PeersChanged, bPeersChanged) {
			t.Fatalf("Merge mutated argument's PeersChanged: before=%v, after=%v",
				bPeersChanged, b.PeersChanged)
		}

		if !slices.Equal(b.PeersRemoved, bPeersRemoved) {
			t.Fatalf("Merge mutated argument's PeersRemoved: before=%v, after=%v",
				bPeersRemoved, b.PeersRemoved)
		}

		if !slices.Equal(b.PeerPatches, bPeerPatches) {
			t.Fatal("Merge mutated argument's PeerPatches")
		}
	})
}

// -----------------------------------------------------------------------
// Property 16b: Merge aliasing through uniqueNodeIDs/slices.Sort
//   When the receiver's PeersChanged or PeersRemoved has spare capacity,
//   append(r.PeersChanged, other.PeersChanged...) writes through to the
//   receiver's backing array. Then uniqueNodeIDs calls slices.Sort on the
//   combined slice, which also sorts the receiver's elements in-place.
//   This is a double corruption: the receiver's data is both extended and reordered.
//
//   This test constructs slices with known spare capacity to reliably trigger
//   the bug, rather than relying on rapid's random capacity allocation.
// -----------------------------------------------------------------------

func TestRapid_Merge_AliasingWithSpareCapacity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Create PeersChanged with deliberate spare capacity
		n := rapid.IntRange(1, 6).Draw(t, "numPeers")
		extraCap := rapid.IntRange(1, 8).Draw(t, "extraCap")

		peersChanged := make([]types.NodeID, n, n+extraCap)
		for i := range peersChanged {
			peersChanged[i] = types.NodeID(rapid.Uint64Range(1, 20).Draw(t, "peerID"))
		}

		a := Change{
			PeersChanged: peersChanged,
		}

		otherPeers := genNodeIDSlice(t)
		if len(otherPeers) == 0 {
			return // need at least one to trigger append aliasing
		}

		b := Change{
			PeersChanged: otherPeers,
		}

		// Snapshot a.PeersChanged
		snapshot := make([]types.NodeID, len(a.PeersChanged))
		copy(snapshot, a.PeersChanged)

		_ = a.Merge(b)

		// Verify a.PeersChanged was NOT mutated
		if !slices.Equal(a.PeersChanged, snapshot) {
			t.Fatalf("BUG: Merge corrupted receiver's PeersChanged through slice aliasing:\n"+
				"  before: %v\n"+
				"  after:  %v\n"+
				"  cap was: %d, len was: %d",
				snapshot, a.PeersChanged, n+extraCap, n)
		}
	})
}

// -----------------------------------------------------------------------
// Property 16c: Merge PeerPatches aliasing
//   PeerPatches uses plain append(r.PeerPatches, other.PeerPatches...)
//   without cloning. When r.PeerPatches has spare capacity, append writes
//   into the existing backing array, extending it in-place. This means
//   the receiver's PeerPatches now contains the merged data, violating
//   value semantics.
//
//   Note: unlike PeersChanged/PeersRemoved, PeerPatches doesn't go through
//   uniqueNodeIDs/slices.Sort, so the corruption is just extension, not reordering.
// -----------------------------------------------------------------------

func TestRapid_Merge_PeerPatchesAliasing(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(1, 4).Draw(t, "numPatches")
		extraCap := rapid.IntRange(1, 4).Draw(t, "extraCap")

		patches := make([]*tailcfg.PeerChange, n, n+extraCap)
		for i := range patches {
			patches[i] = genPeerPatch(t)
		}

		a := Change{PeerPatches: patches}

		// Create other patches with explicit allocation (no spare capacity)
		otherN := rapid.IntRange(1, 4).Draw(t, "otherNumPatches")

		otherPatches := make([]*tailcfg.PeerChange, otherN)
		for i := range otherPatches {
			otherPatches[i] = genPeerPatch(t)
		}

		b := Change{PeerPatches: otherPatches}

		origLen := len(a.PeerPatches)
		snapshot := make([]*tailcfg.PeerChange, origLen)
		copy(snapshot, a.PeerPatches)

		merged := a.Merge(b)

		// The merged result should have all patches
		if len(merged.PeerPatches) != origLen+otherN {
			t.Fatalf("merged PeerPatches len=%d, want %d",
				len(merged.PeerPatches), origLen+otherN)
		}

		// BUG CHECK: Inspect the backing array of a.PeerPatches beyond its length.
		// If aliasing occurred, the elements beyond len(a.PeerPatches) were overwritten.
		// We can detect this by checking that a's PeerPatches slice header still has
		// the same length (Go doesn't update the original's len, but the backing array
		// IS shared). The real issue is if someone later reslices a.PeerPatches[:cap].
		//
		// More directly: since merged := r (value copy), merged.PeerPatches initially
		// points to the SAME backing array as a.PeerPatches. Then append writes
		// other.PeerPatches into positions [n, n+otherN) of that shared array.
		// These positions are within a's capacity but beyond a's length.
		//
		// Verify a's content is unchanged at its length.
		if !slices.Equal(a.PeerPatches, snapshot) {
			t.Fatalf("BUG: Merge corrupted receiver's PeerPatches visible elements:\n"+
				"  before: %v\n  after: %v",
				snapshot, a.PeerPatches)
		}

		// Check that the backing array beyond a's length was written
		// (this is the aliasing - invisible to len() but real in memory)
		if extraCap >= otherN {
			// If there was enough spare capacity, append didn't reallocate.
			// The backing array of a.PeerPatches now has other's patches written
			// beyond a.PeerPatches's length. We can verify by reslicing.
			extendedView := a.PeerPatches[:n+otherN]
			hasOverwrite := false

			for i := n; i < n+otherN; i++ {
				if extendedView[i] == otherPatches[i-n] {
					hasOverwrite = true
					break
				}
			}

			if hasOverwrite {
				t.Logf("CONFIRMED: Merge wrote through to receiver's backing array at positions [%d:%d]",
					n, n+otherN)
				// This IS the bug - the backing array is shared.
				// While len(a.PeerPatches) is still n, the data at positions [n:n+otherN]
				// in the backing array has been overwritten. Any code that captures
				// a pointer to the array or reslices it will see corrupted data.
				t.Fatalf("BUG: Merge used shared backing array for PeerPatches append. " +
					"Receiver's backing array (beyond len) was overwritten by other's patches.")
			}
		}
	})
}

// -----------------------------------------------------------------------
// Property 17: FullUpdate constructor always produces IsFull().
// -----------------------------------------------------------------------

func TestRapid_Constructors_FullUpdateIsFull(t *testing.T) {
	// This is deterministic, but we use rapid for consistency.
	rapid.Check(t, func(t *rapid.T) {
		f := FullUpdate()
		if !f.IsFull() {
			t.Fatalf("FullUpdate() is not full: %+v", f)
		}
	})
}

// -----------------------------------------------------------------------
// Property 18: SelfUpdate constructor produces IsSelfOnly() for n > 0.
// -----------------------------------------------------------------------

func TestRapid_Constructors_SelfUpdateIsSelfOnly(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := genNodeID(t) // always > 0 since genNodeID uses [1, 20]

		s := SelfUpdate(n)
		if !s.IsSelfOnly() {
			t.Fatalf("SelfUpdate(%d) is not self-only: %+v", n, s)
		}
	})
}

// -----------------------------------------------------------------------
// Property 19: FilterForNode drops targeted changes for other nodes,
// even when the change also has PeersChanged containing the queried node.
//
// A change with TargetNode=X should ONLY be sent to node X, regardless
// of what PeersChanged, PeersRemoved, or other fields contain.
// Conversely, it MUST be sent to X.
// -----------------------------------------------------------------------

func TestRapid_FilterForNode_TargetedChangesForOtherNodesDropped(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate two distinct node IDs: the target and a bystander.
		targetID := genNodeID(t)

		bystanderID := genNodeID(t)
		for bystanderID == targetID {
			bystanderID = genNodeID(t)
		}

		// Build a change targeted at targetID, but with PeersChanged
		// that includes bystanderID — an adversarial combination.
		// Optionally add more peers to make it interesting.
		extra := genNodeIDSlice(t)

		peersChanged := make([]types.NodeID, 0, 1+len(extra))
		peersChanged = append(peersChanged, bystanderID)
		peersChanged = append(peersChanged, extra...)

		ch := Change{
			Reason:        "targeted with bystander in PeersChanged",
			TargetNode:    targetID,
			PeersChanged:  peersChanged,
			IncludeDNS:    rapid.Bool().Draw(t, "includeDNS"),
			IncludePolicy: rapid.Bool().Draw(t, "includePolicy"),
			PeersRemoved:  genNodeIDSlice(t),
			PeerPatches:   genPeerPatches(t),
		}

		// FilterForNode for the bystander: should DROP this change
		// because TargetNode != bystanderID.
		filteredForBystander := FilterForNode(bystanderID, []Change{ch})
		if len(filteredForBystander) != 0 {
			t.Fatalf("BUG: FilterForNode(%d) returned targeted change meant for node %d.\n"+
				"  Change: %+v\n"+
				"  The presence of node %d in PeersChanged should NOT override TargetNode filtering.",
				bystanderID, targetID, ch, bystanderID)
		}

		// FilterForNode for the target: should INCLUDE this change.
		filteredForTarget := FilterForNode(targetID, []Change{ch})
		if len(filteredForTarget) != 1 {
			t.Fatalf("BUG: FilterForNode(%d) dropped change targeted to itself.\n"+
				"  Change: %+v",
				targetID, ch)
		}

		// Verify the returned change is the same one (not mutated).
		got := filteredForTarget[0]
		if got.TargetNode != targetID {
			t.Fatalf("filtered change has wrong TargetNode: got %d, want %d",
				got.TargetNode, targetID)
		}
	})
}

// -----------------------------------------------------------------------
// Property 20: Filter(Merge(A,B)) == Merge(Filter(A), Filter(B))
//
// This tests a fundamental algebraic property: filtering a merged change
// should produce the same result as merging individually filtered changes.
// If this doesn't hold, the batcher could send wrong data to clients.
//
// KNOWN BUG DOCUMENTED HERE: This property does NOT hold when A and B
// have different non-zero TargetNode values. Merge keeps the first
// non-zero TargetNode, so the second change's content is silently
// associated with the wrong target. FilterForNode then either:
//   - Drops the merged change entirely for the second target's node
//   - Sends the second target's content to the first target's node
//
// Both outcomes are incorrect. The "filter then merge" path correctly
// handles each change independently.
// -----------------------------------------------------------------------

func TestRapid_Merge_ThenFilter_EquivalentTo_FilterThenMerge(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)
		b := genChange(t)
		nodeID := genNodeID(t)

		// Path 1: Merge then Filter
		merged := cloneChange(a).Merge(cloneChange(b))
		path1 := FilterForNode(nodeID, []Change{merged})

		// Path 2: Filter then Merge
		filteredA := FilterForNode(nodeID, []Change{cloneChange(a)})
		filteredB := FilterForNode(nodeID, []Change{cloneChange(b)})

		// Merge the individually filtered results.
		var path2Result Change

		switch {
		case len(filteredA) == 0 && len(filteredB) == 0:
			// Both filtered out: path1 should also be empty.
			if len(path1) != 0 {
				t.Fatalf("BUG: Merge-then-Filter returned %d changes, but Filter-then-Merge returned 0.\n"+
					"  A = %+v\n  B = %+v\n  nodeID = %d\n  merged = %+v\n  path1 = %+v",
					len(path1), a, b, nodeID, merged, path1)
			}

			return
		case len(filteredA) == 1 && len(filteredB) == 0:
			path2Result = filteredA[0]
		case len(filteredA) == 0 && len(filteredB) == 1:
			path2Result = filteredB[0]
		default:
			path2Result = filteredA[0].Merge(filteredB[0])
		}

		// Path 1 should have exactly 1 change since path 2 produced one.
		if len(path1) == 0 {
			t.Fatalf("BUG: Merge-then-Filter DROPPED content that Filter-then-Merge preserved.\n"+
				"  This means merging two changes lost data for node %d.\n"+
				"  A = %+v\n  B = %+v\n"+
				"  A.TargetNode=%d, B.TargetNode=%d\n"+
				"  Merged.TargetNode=%d\n"+
				"  FilterThenMerge result = %+v",
				nodeID, a, b, a.TargetNode, b.TargetNode, merged.TargetNode, path2Result)
		}

		p1 := path1[0]

		// Compare boolean fields.
		if boolFields(p1) != boolFields(path2Result) {
			t.Fatalf("BUG: Boolean fields differ between Merge-then-Filter and Filter-then-Merge.\n"+
				"  MergeThenFilter bools = %v\n"+
				"  FilterThenMerge bools = %v\n"+
				"  A = %+v\n  B = %+v\n  nodeID = %d",
				boolFields(p1), boolFields(path2Result), a, b, nodeID)
		}

		// Compare peer sets (as sets, ignoring order).
		if !slices.Equal(nodeIDSet(p1.PeersChanged), nodeIDSet(path2Result.PeersChanged)) {
			t.Fatalf("BUG: PeersChanged differ.\n"+
				"  MergeThenFilter = %v\n  FilterThenMerge = %v\n"+
				"  A = %+v\n  B = %+v\n  nodeID = %d",
				p1.PeersChanged, path2Result.PeersChanged, a, b, nodeID)
		}

		if !slices.Equal(nodeIDSet(p1.PeersRemoved), nodeIDSet(path2Result.PeersRemoved)) {
			t.Fatalf("BUG: PeersRemoved differ.\n"+
				"  MergeThenFilter = %v\n  FilterThenMerge = %v\n"+
				"  A = %+v\n  B = %+v\n  nodeID = %d",
				p1.PeersRemoved, path2Result.PeersRemoved, a, b, nodeID)
		}

		if len(p1.PeerPatches) != len(path2Result.PeerPatches) {
			t.Fatalf("BUG: PeerPatches count differs.\n"+
				"  MergeThenFilter = %d\n  FilterThenMerge = %d\n"+
				"  A = %+v\n  B = %+v\n  nodeID = %d",
				len(p1.PeerPatches), len(path2Result.PeerPatches), a, b, nodeID)
		}
	})
}

// -----------------------------------------------------------------------
// Property 21: SplitTargetedAndBroadcast is a perfect partition.
//
// Every input change must appear in exactly one of (broadcast, targeted).
// All targeted have TargetNode != 0, all broadcast have TargetNode == 0.
// The total count must equal the input count.
// -----------------------------------------------------------------------

func TestRapid_SplitTargetedAndBroadcast_PartitionCompleteness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(0, 15).Draw(t, "numChanges")

		cs := make([]Change, n)
		for i := range cs {
			cs[i] = genChange(t)
		}

		broadcast, targeted := SplitTargetedAndBroadcast(cs)

		// Size invariant: nothing lost, nothing created.
		if len(broadcast)+len(targeted) != len(cs) {
			t.Fatalf("Partition size mismatch: %d broadcast + %d targeted != %d input",
				len(broadcast), len(targeted), len(cs))
		}

		// Classification invariant: broadcast all have TargetNode==0.
		for i, c := range broadcast {
			if c.TargetNode != 0 {
				t.Fatalf("broadcast[%d] has TargetNode=%d, expected 0", i, c.TargetNode)
			}
		}

		// Classification invariant: targeted all have TargetNode!=0.
		for i, c := range targeted {
			if c.TargetNode == 0 {
				t.Fatalf("targeted[%d] has TargetNode=0, expected non-zero", i)
			}
		}

		// Content preservation: every input change appears in exactly one output.
		// We verify by checking that concatenating broadcast+targeted in their
		// original relative order reconstructs the input.
		// Since SplitTargetedAndBroadcast iterates in order, each output preserves
		// the relative order of its elements from the input.
		bi, ti := 0, 0

		for _, c := range cs {
			if c.TargetNode == 0 {
				if bi >= len(broadcast) {
					t.Fatalf("Ran out of broadcast changes at input with TargetNode=0")
				}
				// Verify it's the same change by checking key fields.
				got := broadcast[bi]
				if got.TargetNode != c.TargetNode ||
					got.OriginNode != c.OriginNode ||
					got.Reason != c.Reason ||
					boolFields(got) != boolFields(c) {
					t.Fatalf("broadcast[%d] doesn't match input: got %+v, want %+v", bi, got, c)
				}

				bi++
			} else {
				if ti >= len(targeted) {
					t.Fatalf("Ran out of targeted changes at input with TargetNode=%d", c.TargetNode)
				}

				got := targeted[ti]
				if got.TargetNode != c.TargetNode ||
					got.OriginNode != c.OriginNode ||
					got.Reason != c.Reason ||
					boolFields(got) != boolFields(c) {
					t.Fatalf("targeted[%d] doesn't match input: got %+v, want %+v", ti, got, c)
				}

				ti++
			}
		}

		// Verify we consumed all outputs.
		if bi != len(broadcast) {
			t.Fatalf("Extra broadcast changes: consumed %d of %d", bi, len(broadcast))
		}

		if ti != len(targeted) {
			t.Fatalf("Extra targeted changes: consumed %d of %d", ti, len(targeted))
		}
	})
}

// -----------------------------------------------------------------------
// Property 22: ShouldSendToNode is consistent with FilterForNode.
//
// ShouldSendToNode(nodeID, change) should return true if and only if
// FilterForNode(nodeID, [change]) returns a non-empty list.
// -----------------------------------------------------------------------

func TestRapid_ShouldSendToNode_ConsistentWithFilterForNode(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ch := genChange(t)
		nodeID := genNodeID(t)

		shouldSend := ch.ShouldSendToNode(nodeID)
		filtered := FilterForNode(nodeID, []Change{ch})

		filterSays := len(filtered) > 0

		if shouldSend != filterSays {
			t.Fatalf("BUG: ShouldSendToNode(%d) = %v but FilterForNode returned %d changes.\n"+
				"  Change = %+v\n"+
				"  These should always agree: ShouldSendToNode==true iff FilterForNode is non-empty.",
				nodeID, shouldSend, len(filtered), ch)
		}

		// Additional consistency: if FilterForNode returns something,
		// it should be exactly the input change (unmodified).
		if filterSays {
			if len(filtered) != 1 {
				t.Fatalf("FilterForNode returned %d changes for single input, expected 0 or 1",
					len(filtered))
			}

			got := filtered[0]
			if boolFields(got) != boolFields(ch) {
				t.Fatalf("FilterForNode modified boolean fields of the change")
			}

			if got.TargetNode != ch.TargetNode || got.OriginNode != ch.OriginNode {
				t.Fatalf("FilterForNode modified TargetNode or OriginNode")
			}
		}
	})
}

// -----------------------------------------------------------------------
// Property 23: Merge boolean OR with peer set union.
//
// When merging two changes:
// - All boolean fields are the OR of both inputs
// - PeersChanged is the union (sorted, deduped)
// - PeersRemoved is the union (sorted, deduped)
// - If either has SendAllPeers=true, the merged result does too
// -----------------------------------------------------------------------

func TestRapid_Merge_BooleanOR_WithPeerSets(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genChange(t)
		b := genChange(t)

		merged := cloneChange(a).Merge(cloneChange(b))

		// Boolean fields: merged should be OR of both.
		aBools := boolFields(a)
		bBools := boolFields(b)
		mBools := boolFields(merged)

		for i := range aBools { //nolint:gosec // aBools and bBools have same length from boolFields
			expected := aBools[i] || bBools[i]
			if mBools[i] != expected {
				names := Change{}.boolFieldNames()
				t.Fatalf("BUG: Merged boolean field %q = %v, expected %v (a=%v, b=%v)",
					names[i], mBools[i], expected, aBools[i], bBools[i])
			}
		}

		// PeersChanged: merged should be the union of both.
		expectedChanged := nodeIDSet(append(
			append([]types.NodeID{}, a.PeersChanged...),
			b.PeersChanged...,
		))

		gotChanged := nodeIDSet(merged.PeersChanged)
		if !slices.Equal(gotChanged, expectedChanged) {
			t.Fatalf("BUG: PeersChanged is not union.\n"+
				"  A.PeersChanged = %v\n  B.PeersChanged = %v\n"+
				"  Expected union = %v\n  Got = %v",
				a.PeersChanged, b.PeersChanged, expectedChanged, gotChanged)
		}

		// PeersRemoved: merged should be the union of both.
		expectedRemoved := nodeIDSet(append(
			append([]types.NodeID{}, a.PeersRemoved...),
			b.PeersRemoved...,
		))

		gotRemoved := nodeIDSet(merged.PeersRemoved)
		if !slices.Equal(gotRemoved, expectedRemoved) {
			t.Fatalf("BUG: PeersRemoved is not union.\n"+
				"  A.PeersRemoved = %v\n  B.PeersRemoved = %v\n"+
				"  Expected union = %v\n  Got = %v",
				a.PeersRemoved, b.PeersRemoved, expectedRemoved, gotRemoved)
		}

		// PeerPatches: merged should be the concatenation of both.
		expectedPatchCount := len(a.PeerPatches) + len(b.PeerPatches)
		if len(merged.PeerPatches) != expectedPatchCount {
			t.Fatalf("BUG: PeerPatches count = %d, expected %d (a=%d + b=%d)",
				len(merged.PeerPatches), expectedPatchCount,
				len(a.PeerPatches), len(b.PeerPatches))
		}

		// SendAllPeers absorption: if either has it, merged must too.
		if a.SendAllPeers && !merged.SendAllPeers {
			t.Fatal("BUG: a.SendAllPeers=true but merged.SendAllPeers=false")
		}

		if b.SendAllPeers && !merged.SendAllPeers {
			t.Fatal("BUG: b.SendAllPeers=true but merged.SendAllPeers=false")
		}

		// Specific adversarial case: verify non-trivial union behavior.
		// A = {IncludePolicy=true, PeersChanged=[1,2]}
		// B = {IncludeDNS=true, PeersChanged=[2,3]}
		advA := Change{
			IncludePolicy: true,
			PeersChanged:  []types.NodeID{1, 2},
		}
		advB := Change{
			IncludeDNS:   true,
			PeersChanged: []types.NodeID{2, 3},
		}
		advMerged := advA.Merge(advB)

		if !advMerged.IncludePolicy {
			t.Fatal("Adversarial: merged lost IncludePolicy from A")
		}

		if !advMerged.IncludeDNS {
			t.Fatal("Adversarial: merged lost IncludeDNS from B")
		}

		expectedAdv := []types.NodeID{1, 2, 3}
		if !slices.Equal(advMerged.PeersChanged, expectedAdv) {
			t.Fatalf("Adversarial: PeersChanged = %v, expected %v (sorted, deduped union)",
				advMerged.PeersChanged, expectedAdv)
		}
	})
}
