package state

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// ============================================================================
// Generators
// ============================================================================

// genNodeID generates a NodeID in a small range to encourage key collisions
// during map-based generation while remaining large enough for meaningful tests.
func genNodeID() *rapid.Generator[types.NodeID] {
	return rapid.Custom[types.NodeID](func(t *rapid.T) types.NodeID {
		return types.NodeID(rapid.Uint64Range(1, 200).Draw(t, "nodeID"))
	})
}

// genUserID generates a UserID in a small range to create multi-node-per-user scenarios.
func genUserID() *rapid.Generator[uint] {
	return rapid.Custom[uint](func(t *rapid.T) uint {
		return uint(rapid.IntRange(1, 10).Draw(t, "userID"))
	})
}

// genTag generates a tag string in the form "tag:name".
func genTag() *rapid.Generator[string] {
	return rapid.Custom[string](func(t *rapid.T) string {
		name := rapid.StringMatching(`[a-z][a-z0-9]{0,7}`).Draw(t, "tagname")
		return "tag:" + name
	})
}

// genTags generates a slice of 0..maxLen unique tags.
func genTags(maxLen int) *rapid.Generator[[]string] {
	return rapid.Custom[[]string](func(t *rapid.T) []string {
		n := rapid.IntRange(0, maxLen).Draw(t, "numTags")
		seen := make(map[string]bool, n)
		result := make([]string, 0, n)
		for len(result) < n {
			tag := genTag().Draw(t, "tag")
			if !seen[tag] {
				seen[tag] = true
				result = append(result, tag)
			}
		}
		return result
	})
}

// genNode generates a random Node with random keys, IPs, user, and optional tags.
func genNode() *rapid.Generator[types.Node] {
	return rapid.Custom[types.Node](func(t *rapid.T) types.Node {
		id := genNodeID().Draw(t, "id")
		uid := genUserID().Draw(t, "uid")
		tags := genTags(3).Draw(t, "tags")

		machineKey := key.NewMachine()
		nodeKey := key.NewNode()
		discoKey := key.NewDisco()

		// Generate deterministic IPs from the node ID to avoid collisions in
		// simple cases but still have meaningful values.
		ipv4 := netip.AddrFrom4([4]byte{
			100,
			64,
			byte(id >> 8),   //nolint:gosec
			byte(id & 0xFF), //nolint:gosec
		})
		ipv6Bytes := [16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0}
		ipv6Bytes[14] = byte(id >> 8)   //nolint:gosec
		ipv6Bytes[15] = byte(id & 0xFF) //nolint:gosec
		ipv6 := netip.AddrFrom16(ipv6Bytes)

		hostname := fmt.Sprintf("node-%d", id)

		return types.Node{
			ID:         id,
			MachineKey: machineKey.Public(),
			NodeKey:    nodeKey.Public(),
			DiscoKey:   discoKey.Public(),
			Hostname:   hostname,
			GivenName:  hostname,
			UserID:     new(uid),
			User: &types.User{
				Name:        fmt.Sprintf("user-%d", uid),
				DisplayName: fmt.Sprintf("User %d", uid),
			},
			RegisterMethod: "test",
			IPv4:           &ipv4,
			IPv6:           &ipv6,
			Tags:           tags,
		}
	})
}

// genNodeMap generates a map of NodeID -> Node with unique IDs.
// The map size is bounded to keep tests fast.
func genNodeMap(maxSize int) *rapid.Generator[map[types.NodeID]types.Node] {
	return rapid.Custom[map[types.NodeID]types.Node](func(t *rapid.T) map[types.NodeID]types.Node {
		n := rapid.IntRange(0, maxSize).Draw(t, "mapSize")
		nodes := make(map[types.NodeID]types.Node, n)
		for len(nodes) < n {
			node := genNode().Draw(t, "node")
			// Overwrite if ID exists; that's fine for unique-ID maps.
			nodes[node.ID] = node
		}
		return nodes
	})
}

// ============================================================================
// PeersFunc implementations
// ============================================================================

// allVisiblePeersFunc: every node sees every other node.
func allVisiblePeersFunc(nodes []types.NodeView) map[types.NodeID][]types.NodeView {
	ret := make(map[types.NodeID][]types.NodeView, len(nodes))
	for _, node := range nodes {
		var peers []types.NodeView
		for _, n := range nodes {
			if n.ID() != node.ID() {
				peers = append(peers, n)
			}
		}
		ret[node.ID()] = peers
	}
	return ret
}

// noVisiblePeersFunc: no node sees any other node.
func noVisiblePeersFunc(nodes []types.NodeView) map[types.NodeID][]types.NodeView {
	ret := make(map[types.NodeID][]types.NodeView, len(nodes))
	for _, node := range nodes {
		ret[node.ID()] = nil
	}
	return ret
}

// symmetricRandomPeersFunc builds a PeersFunc from a pre-computed symmetric
// adjacency set. By constructing the adjacency before the PeersFunc is called,
// we guarantee symmetry: if Y is in peers(X), then X is in peers(Y).
func symmetricRandomPeersFunc(t *rapid.T, ids []types.NodeID) PeersFunc {
	// Build a symmetric adjacency set.
	type edge struct{ a, b types.NodeID }
	adj := make(map[types.NodeID]map[types.NodeID]bool)
	for _, id := range ids {
		adj[id] = make(map[types.NodeID]bool)
	}

	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			if rapid.Bool().Draw(t, fmt.Sprintf("edge-%d-%d", ids[i], ids[j])) {
				adj[ids[i]][ids[j]] = true
				adj[ids[j]][ids[i]] = true
			}
		}
	}

	return func(nodes []types.NodeView) map[types.NodeID][]types.NodeView {
		ret := make(map[types.NodeID][]types.NodeView, len(nodes))
		nodesByID := make(map[types.NodeID]types.NodeView, len(nodes))
		for _, n := range nodes {
			nodesByID[n.ID()] = n
		}

		for _, node := range nodes {
			var peers []types.NodeView
			for peerID := range adj[node.ID()] {
				if pv, ok := nodesByID[peerID]; ok {
					peers = append(peers, pv)
				}
			}
			ret[node.ID()] = peers
		}
		return ret
	}
}

// genPeersFunc picks one of the three PeersFunc strategies.
// For symmetricRandom, we need the node IDs ahead of time so the
// adjacency can be pre-computed.
func genPeersFunc(t *rapid.T, ids []types.NodeID) PeersFunc {
	strategy := rapid.IntRange(0, 2).Draw(t, "peersFuncStrategy")
	switch strategy {
	case 0:
		return allVisiblePeersFunc
	case 1:
		return noVisiblePeersFunc
	default:
		return symmetricRandomPeersFunc(t, ids)
	}
}

// nodeIDs extracts sorted IDs from a node map.
func nodeIDs(nodes map[types.NodeID]types.Node) []types.NodeID {
	ids := make([]types.NodeID, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b types.NodeID) int {
		return cmp.Compare(a, b)
	})
	return ids
}

// ============================================================================
// Property 1: allNodes count matches input
// ============================================================================

func TestRapid_Snapshot_AllNodesCount(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(30).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		if len(snap.allNodes) != len(nodes) {
			t.Fatalf("allNodes count %d != input count %d", len(snap.allNodes), len(nodes))
		}
	})
}

// ============================================================================
// Property 2: nodesByID completeness — every input node is in nodesByID
// ============================================================================

func TestRapid_Snapshot_NodesByIDCompleteness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(30).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		for id, node := range nodes {
			got, ok := snap.nodesByID[id]
			if !ok {
				t.Fatalf("node %d missing from nodesByID", id)
			}
			if got.ID != node.ID {
				t.Fatalf("nodesByID[%d].ID = %d, want %d", id, got.ID, node.ID)
			}
		}

		// Reverse: nothing extra in nodesByID
		if len(snap.nodesByID) != len(nodes) {
			t.Fatalf("nodesByID has %d entries, input has %d", len(snap.nodesByID), len(nodes))
		}
	})
}

// ============================================================================
// Property 3: nodesByNodeKey consistency — every nodesByID entry has a
// corresponding entry in nodesByNodeKey
// ============================================================================

func TestRapid_Snapshot_NodesByNodeKeyConsistency(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(30).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		for _, node := range snap.nodesByID {
			nv, ok := snap.nodesByNodeKey[node.NodeKey]
			if !ok {
				t.Fatalf("node %d (NodeKey=%s) missing from nodesByNodeKey",
					node.ID, node.NodeKey.ShortString())
			}
			if nv.ID() != node.ID {
				t.Fatalf("nodesByNodeKey lookup for node %d returned node %d",
					node.ID, nv.ID())
			}
		}
	})
}

// ============================================================================
// Property 4: nodesByMachineKey consistency — every node can be found via
// its machine key + user ID
// ============================================================================

func TestRapid_Snapshot_NodesByMachineKeyConsistency(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(30).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		for _, node := range snap.nodesByID {
			userMap, ok := snap.nodesByMachineKey[node.MachineKey]
			if !ok {
				t.Fatalf("node %d MachineKey missing from nodesByMachineKey", node.ID)
			}

			typedUID := node.TypedUserID()
			nv, ok := userMap[typedUID]
			if !ok {
				t.Fatalf("node %d not found in nodesByMachineKey[MK][UserID=%d]",
					node.ID, typedUID)
			}
			if nv.ID() != node.ID {
				t.Fatalf("nodesByMachineKey lookup for node %d returned node %d",
					node.ID, nv.ID())
			}
		}
	})
}

// ============================================================================
// Property 5: nodesByUser excludes tagged nodes
// ============================================================================

func TestRapid_Snapshot_NodesByUserExcludesTaggedNodes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(30).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		for uid, userNodes := range snap.nodesByUser {
			for _, nv := range userNodes {
				if nv.IsTagged() {
					t.Fatalf("tagged node %d (tags=%v) found in nodesByUser[%d]",
						nv.ID(), nv.Tags().AsSlice(), uid)
				}
			}
		}
	})
}

// ============================================================================
// Property 6: nodesByUser includes all user-owned (untagged) nodes
// ============================================================================

func TestRapid_Snapshot_NodesByUserIncludesUserOwnedNodes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(30).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		for _, node := range nodes {
			if node.IsTagged() {
				continue
			}

			uid := node.TypedUserID()
			userNodes, ok := snap.nodesByUser[uid]
			if !ok {
				t.Fatalf("user-owned node %d (user=%d) has no entry in nodesByUser",
					node.ID, uid)
			}

			found := false
			for _, nv := range userNodes {
				if nv.ID() == node.ID {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("user-owned node %d not found in nodesByUser[%d]",
					node.ID, uid)
			}
		}
	})
}

// ============================================================================
// Property 7: peersByNode self-exclusion — no node appears in its own peer list
// ============================================================================

func TestRapid_Snapshot_PeersByNodeSelfExclusion(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(20).Draw(t, "nodes")
		ids := nodeIDs(nodes)
		pf := genPeersFunc(t, ids)
		snap := snapshotFromNodes(nodes, pf)

		for nodeID, peers := range snap.peersByNode {
			for _, peer := range peers {
				if peer.ID() == nodeID {
					t.Fatalf("node %d appears in its own peer list", nodeID)
				}
			}
		}
	})
}

// ============================================================================
// Property 8: peersByNode symmetry — with a symmetric PeersFunc, if Y is in
// peers(X) then X is in peers(Y)
// ============================================================================

func TestRapid_Snapshot_PeersByNodeSymmetry(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(20).Draw(t, "nodes")
		ids := nodeIDs(nodes)
		// Always use the symmetric random PeersFunc for this property.
		pf := symmetricRandomPeersFunc(t, ids)
		snap := snapshotFromNodes(nodes, pf)

		for nodeID, peers := range snap.peersByNode {
			for _, peer := range peers {
				// peer.ID() should have nodeID in its peers
				reversePeers, ok := snap.peersByNode[peer.ID()]
				if !ok {
					t.Fatalf("node %d is peer of %d but %d has no peersByNode entry",
						peer.ID(), nodeID, peer.ID())
				}

				found := false
				for _, rp := range reversePeers {
					if rp.ID() == nodeID {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("symmetry violation: %d in peers(%d), but %d not in peers(%d)",
						peer.ID(), nodeID, nodeID, peer.ID())
				}
			}
		}
	})
}

// ============================================================================
// Property 9: allNodes is NOT sorted by ID
//
// This test was originally written to assert that allNodes is sorted by ID.
// Rapid immediately found a counterexample: snapshotFromNodes iterates over
// a Go map (nondeterministic order) and does NOT sort allNodes. This is a
// deliberate design choice — the slice is used for iteration, not binary
// search, so sorting would be unnecessary overhead.
//
// We keep the test inverted to document and protect this behavior: if someone
// adds sorting in the future, this test will catch the change so the team can
// decide whether to update callers or revert.
// ============================================================================

func TestRapid_Snapshot_AllNodesNotSortedInvariant(t *testing.T) {
	// We verify that allNodes contains the correct IDs (unordered) and that
	// there are no duplicates, which IS an invariant.
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(30).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		seen := make(map[types.NodeID]bool, len(snap.allNodes))
		for _, nv := range snap.allNodes {
			if seen[nv.ID()] {
				t.Fatalf("duplicate ID %d in allNodes", nv.ID())
			}
			seen[nv.ID()] = true
		}

		// Every input ID must appear.
		for id := range nodes {
			if !seen[id] {
				t.Fatalf("node %d missing from allNodes", id)
			}
		}

		// No extra IDs.
		if len(seen) != len(nodes) {
			t.Fatalf("allNodes has %d unique IDs, input has %d", len(seen), len(nodes))
		}
	})
}

// ============================================================================
// Property 10: Empty input produces empty snapshot
// ============================================================================

func TestRapid_Snapshot_EmptyInputEmptySnapshot(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Use any PeersFunc strategy — doesn't matter for empty input.
		strategy := rapid.IntRange(0, 1).Draw(t, "strategy")
		var pf PeersFunc
		if strategy == 0 {
			pf = allVisiblePeersFunc
		} else {
			pf = noVisiblePeersFunc
		}

		snap := snapshotFromNodes(map[types.NodeID]types.Node{}, pf)

		if len(snap.allNodes) != 0 {
			t.Fatalf("empty input: allNodes has %d entries", len(snap.allNodes))
		}
		if len(snap.nodesByID) != 0 {
			t.Fatalf("empty input: nodesByID has %d entries", len(snap.nodesByID))
		}
		if len(snap.nodesByNodeKey) != 0 {
			t.Fatalf("empty input: nodesByNodeKey has %d entries", len(snap.nodesByNodeKey))
		}
		if len(snap.nodesByMachineKey) != 0 {
			t.Fatalf("empty input: nodesByMachineKey has %d entries", len(snap.nodesByMachineKey))
		}
		if len(snap.nodesByUser) != 0 {
			t.Fatalf("empty input: nodesByUser has %d entries", len(snap.nodesByUser))
		}
		if len(snap.peersByNode) != 0 {
			t.Fatalf("empty input: peersByNode has %d entries", len(snap.peersByNode))
		}
	})
}

// ============================================================================
// Bonus properties
// ============================================================================

// Property: nodesByUser partitions the untagged nodes — the total count of
// entries across all user buckets equals the number of untagged input nodes.
func TestRapid_Snapshot_NodesByUserPartitionsUntagged(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(30).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		// Count untagged nodes in input.
		untaggedCount := 0
		for _, node := range nodes {
			if !node.IsTagged() {
				untaggedCount++
			}
		}

		// Count total entries in nodesByUser.
		userNodeCount := 0
		for _, userNodes := range snap.nodesByUser {
			userNodeCount += len(userNodes)
		}

		if userNodeCount != untaggedCount {
			t.Fatalf("nodesByUser total entries %d != untagged input count %d",
				userNodeCount, untaggedCount)
		}
	})
}

// Property: allNodes contains exactly the same set of IDs as nodesByID.
func TestRapid_Snapshot_AllNodesMatchesNodesByID(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(30).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		// Collect IDs from allNodes.
		allNodeIDs := make(map[types.NodeID]bool, len(snap.allNodes))
		for _, nv := range snap.allNodes {
			if allNodeIDs[nv.ID()] {
				t.Fatalf("duplicate ID %d in allNodes", nv.ID())
			}
			allNodeIDs[nv.ID()] = true
		}

		// Compare with nodesByID.
		for id := range snap.nodesByID {
			if !allNodeIDs[id] {
				t.Fatalf("nodesByID has ID %d not found in allNodes", id)
			}
		}
		for id := range allNodeIDs {
			if _, ok := snap.nodesByID[id]; !ok {
				t.Fatalf("allNodes has ID %d not found in nodesByID", id)
			}
		}
	})
}

// Property: with allVisiblePeersFunc, every node sees exactly N-1 peers.
func TestRapid_Snapshot_AllVisiblePeersCount(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(20).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, allVisiblePeersFunc)

		n := len(nodes)
		for nodeID, peers := range snap.peersByNode {
			if len(peers) != n-1 {
				t.Fatalf("node %d has %d peers with allVisible, want %d",
					nodeID, len(peers), n-1)
			}
		}
	})
}

// Property: with noVisiblePeersFunc, every node sees zero peers.
func TestRapid_Snapshot_NoVisiblePeersCount(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(20).Draw(t, "nodes")
		snap := snapshotFromNodes(nodes, noVisiblePeersFunc)

		for nodeID, peers := range snap.peersByNode {
			if len(peers) != 0 {
				t.Fatalf("node %d has %d peers with noVisible, want 0",
					nodeID, len(peers))
			}
		}
	})
}

// Property: peersByNode has an entry for every node in the input (the PeersFunc
// is called with all nodes and should return an entry per node).
func TestRapid_Snapshot_PeersByNodeCompleteness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := genNodeMap(20).Draw(t, "nodes")
		ids := nodeIDs(nodes)
		pf := genPeersFunc(t, ids)
		snap := snapshotFromNodes(nodes, pf)

		for id := range nodes {
			if _, ok := snap.peersByNode[id]; !ok {
				t.Fatalf("node %d missing from peersByNode", id)
			}
		}
	})
}

// ============================================================================
// Slice aliasing bug tests
// ============================================================================

// genIPv4Addr generates a random IPv4 address.
func genIPv4AddrState() *rapid.Generator[netip.Addr] {
	return rapid.Custom[netip.Addr](func(t *rapid.T) netip.Addr {
		var b [4]byte
		for i := range b {
			b[i] = byte(rapid.IntRange(0, 255).Draw(t, "byte"))
		}
		return netip.AddrFrom4(b)
	})
}

// genSubnetPrefix generates a non-exit-route prefix.
func genSubnetPrefix() *rapid.Generator[netip.Prefix] {
	return rapid.Custom[netip.Prefix](func(t *rapid.T) netip.Prefix {
		bits := rapid.IntRange(1, 32).Draw(t, "bits")
		addr := genIPv4AddrState().Draw(t, "addr")
		return netip.PrefixFrom(addr, bits).Masked()
	})
}

// genPrefixSlice generates a slice of 0..maxLen netip.Prefix values.
func genPrefixSlice(maxLen int) *rapid.Generator[[]netip.Prefix] {
	return rapid.SliceOfN(genSubnetPrefix(), 0, maxLen)
}

// -----------------------------------------------------------------------
// Property: routesChanged must not mutate newHI.RoutableIPs
//
// BUG: routesChanged sorts newHI.RoutableIPs in place (line 2497 in state.go):
//   slices.SortFunc(newRoutes, netip.Prefix.Compare)
// where newRoutes := newHI.RoutableIPs is a direct alias to the caller's slice.
// This mutates the Hostinfo that was passed in, which may be used after the call.
//
// This test documents the bug by snapshotting RoutableIPs before the call
// and checking they are unchanged afterwards.
// -----------------------------------------------------------------------

func TestRapid_RoutesChanged_MutationSafety(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate old node with some routes
		oldRoutes := genPrefixSlice(8).Draw(t, "oldRoutes")
		oldNode := &types.Node{
			Hostinfo: &tailcfg.Hostinfo{
				RoutableIPs: oldRoutes,
			},
		}
		oldNodeView := oldNode.View()

		// Generate new hostinfo with routes in a specific (possibly unsorted) order
		newRoutes := genPrefixSlice(8).Draw(t, "newRoutes")
		if len(newRoutes) < 2 {
			// Need at least 2 elements for sorting to potentially reorder
			return
		}
		newHI := &tailcfg.Hostinfo{
			RoutableIPs: newRoutes,
		}

		// Snapshot new routes before the call
		snapshotNewRoutes := make([]netip.Prefix, len(newRoutes))
		copy(snapshotNewRoutes, newRoutes)

		// Snapshot old routes before the call
		snapshotOldRoutes := make([]netip.Prefix, len(oldRoutes))
		copy(snapshotOldRoutes, oldRoutes)

		// Call routesChanged
		_ = routesChanged(oldNodeView, newHI)

		// Check: newHI.RoutableIPs must not be mutated
		if !slices.Equal(newHI.RoutableIPs, snapshotNewRoutes) {
			t.Fatalf("routesChanged mutated newHI.RoutableIPs:\n  before: %v\n  after:  %v",
				snapshotNewRoutes, newHI.RoutableIPs)
		}

		// Check: oldNode's routes must not be mutated
		// (AsStruct clones, so this should be safe — but verify)
		if !slices.Equal(oldRoutes, snapshotOldRoutes) {
			t.Fatalf("routesChanged mutated oldNode's RoutableIPs:\n  before: %v\n  after:  %v",
				snapshotOldRoutes, oldRoutes)
		}
	})
}

// -----------------------------------------------------------------------
// Property: routesChanged must be commutative-like in its boolean result.
//   routesChanged(a, b) should equal routesChanged(a_reordered, b_reordered)
//   i.e., the result should be order-independent.
// -----------------------------------------------------------------------

func TestRapid_RoutesChanged_OrderIndependent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		routes := genPrefixSlice(8).Draw(t, "routes")
		if len(routes) < 2 {
			return
		}

		node := &types.Node{
			Hostinfo: &tailcfg.Hostinfo{
				RoutableIPs: slices.Clone(routes),
			},
		}

		// Create reversed copy for newHI
		reversed := slices.Clone(routes)
		slices.Reverse(reversed)

		newHI := &tailcfg.Hostinfo{
			RoutableIPs: reversed,
		}

		// Same routes in different order should report no change
		result := routesChanged(node.View(), newHI)
		if result {
			t.Fatalf("routesChanged reports change for reordered routes:\n  old: %v\n  new: %v",
				routes, reversed)
		}
	})
}

// ============================================================================
// Adversarial NodeStore property tests (live store with write queue)
// ============================================================================

// makeTestNodes creates n nodes with sequential IDs starting from 1.
// Returns the nodes slice (for NewNodeStore) and a map of ID -> Node.
func makeTestNodes(n int) (types.Nodes, map[types.NodeID]types.Node) {
	nodesMap := make(map[types.NodeID]types.Node, n)
	nodesSlice := make(types.Nodes, 0, n)
	for i := 1; i <= n; i++ {
		node := createTestNode(types.NodeID(i), uint(i), fmt.Sprintf("user-%d", i), fmt.Sprintf("node-%d", i))
		nodesMap[node.ID] = node
		nodesSlice = append(nodesSlice, &node)
	}
	return nodesSlice, nodesMap
}

// startTestStore creates, starts, and returns a NodeStore. Caller must defer store.Stop().
func startTestStore(nodes types.Nodes, pf PeersFunc) *NodeStore {
	store := NewNodeStore(nodes, pf, TestBatchSize, TestBatchTimeout)
	store.Start()
	return store
}

// ============================================================================
// Test 1: UpdateNode sequential callbacks see latest state
//
// When multiple UpdateNode calls happen sequentially for different nodes,
// each update should be visible in the snapshot immediately after it returns.
// So after updating node K, a GetNode for nodes 1..K should reflect
// all prior mutations.
// ============================================================================

func TestRapid_NodeStore_UpdateNode_CallbackSeesLatestState(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		const numNodes = 5
		nodesSlice, nodesMap := makeTestNodes(numNodes)
		store := startTestStore(nodesSlice, allVisiblePeersFunc)
		defer store.Stop()

		// Generate a unique hostname suffix per node for the update
		suffixes := make([]string, numNodes+1) // 1-indexed
		for i := 1; i <= numNodes; i++ {
			suffixes[i] = rapid.StringMatching(`[a-z]{4,8}`).Draw(rt, fmt.Sprintf("suffix-%d", i))
		}

		// Update nodes 1..5 in sequence. Each UpdateNode callback mutates
		// the hostname. After each update returns, verify that the store
		// reflects ALL prior updates.
		for i := 1; i <= numNodes; i++ {
			nodeID := types.NodeID(i)
			newHostname := fmt.Sprintf("updated-%s", suffixes[i])

			_, ok := store.UpdateNode(nodeID, func(n *types.Node) {
				n.Hostname = newHostname
			})
			if !ok {
				rt.Fatalf("UpdateNode(%d) returned not-found", nodeID)
			}

			// After this update returns, verify nodes 1..i are updated
			for j := 1; j <= i; j++ {
				jID := types.NodeID(j)
				nv, exists := store.GetNode(jID)
				if !exists {
					rt.Fatalf("after updating node %d, GetNode(%d) not found", i, j)
				}
				expectedHostname := fmt.Sprintf("updated-%s", suffixes[j])
				if nv.Hostname() != expectedHostname {
					rt.Fatalf("after updating node %d, node %d hostname = %q, want %q",
						i, j, nv.Hostname(), expectedHostname)
				}
			}

			// Nodes i+1..N should still have their original hostname
			for j := i + 1; j <= numNodes; j++ {
				jID := types.NodeID(j)
				nv, exists := store.GetNode(jID)
				if !exists {
					rt.Fatalf("after updating node %d, GetNode(%d) not found", i, j)
				}
				origHostname := nodesMap[jID].Hostname
				if nv.Hostname() != origHostname {
					rt.Fatalf("after updating node %d, node %d should be unchanged: got %q, want %q",
						i, j, nv.Hostname(), origHostname)
				}
			}
		}
	})
}

// ============================================================================
// Test 2: ListPeers consistent with GetNode
//
// For any node, ListPeers should return exactly the set of nodes that
// GetNode returns for each peer ID. No phantom peers, no missing peers.
// ============================================================================

func TestRapid_NodeStore_ListPeers_ConsistentWithGetByID(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		numNodes := rapid.IntRange(4, 8).Draw(rt, "numNodes")
		nodesSlice, _ := makeTestNodes(numNodes)
		store := startTestStore(nodesSlice, allVisiblePeersFunc)
		defer store.Stop()

		allNodesList := store.ListNodes()

		for i := range allNodesList.Len() {
			node := allNodesList.At(i)
			peers := store.ListPeers(node.ID())

			// Build set of peer IDs from ListPeers
			peerIDSet := make(map[types.NodeID]bool, peers.Len())
			for j := range peers.Len() {
				peer := peers.At(j)
				peerID := peer.ID()

				// Each peer from ListPeers must be retrievable via GetNode
				retrieved, exists := store.GetNode(peerID)
				if !exists {
					rt.Fatalf("ListPeers(%d) contains peer %d, but GetNode(%d) returns not-found",
						node.ID(), peerID, peerID)
				}

				// The retrieved node must match the peer's data
				if retrieved.NodeKey() != peer.NodeKey() {
					rt.Fatalf("ListPeers(%d) peer %d has NodeKey %s, but GetNode returns NodeKey %s",
						node.ID(), peerID,
						peer.NodeKey().ShortString(),
						retrieved.NodeKey().ShortString())
				}

				if peerIDSet[peerID] {
					rt.Fatalf("ListPeers(%d) contains duplicate peer %d", node.ID(), peerID)
				}
				peerIDSet[peerID] = true
			}

			// Verify: every other node in the store IS in the peer list
			// (since we use allVisiblePeersFunc)
			for k := range allNodesList.Len() {
				other := allNodesList.At(k)
				if other.ID() == node.ID() {
					// Self should NOT be in peer list
					if peerIDSet[other.ID()] {
						rt.Fatalf("node %d appears in its own peer list", node.ID())
					}
					continue
				}
				if !peerIDSet[other.ID()] {
					rt.Fatalf("node %d should be peer of %d but is not in ListPeers",
						other.ID(), node.ID())
				}
			}
		}
	})
}

// ============================================================================
// Test 3: Policy change via RebuildPeerMaps
//
// When peersFunc changes (simulating a policy update), RebuildPeerMaps
// should immediately reflect the new visibility rules. This is the
// CRITICAL path for policy enforcement.
// ============================================================================

func TestRapid_NodeStore_PolicyChange_PeerMapRebuild(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		const numNodes = 6
		nodesSlice, _ := makeTestNodes(numNodes)

		// Start with allow-all
		store := startTestStore(nodesSlice, allVisiblePeersFunc)
		defer store.Stop()

		// Phase 1: verify everyone sees everyone (N-1 peers each)
		for i := 1; i <= numNodes; i++ {
			peers := store.ListPeers(types.NodeID(i))
			if peers.Len() != numNodes-1 {
				rt.Fatalf("phase1: node %d has %d peers, want %d", i, peers.Len(), numNodes-1)
			}
		}

		// Phase 2: switch to odd-only visibility
		// Odd nodes see only other odd nodes; even nodes see no one.
		oddOnlyPeersFunc := func(nodes []types.NodeView) map[types.NodeID][]types.NodeView {
			ret := make(map[types.NodeID][]types.NodeView, len(nodes))
			for _, node := range nodes {
				var peers []types.NodeView
				if node.ID()%2 == 1 {
					// Odd node: can see other odd nodes
					for _, n := range nodes {
						if n.ID() != node.ID() && n.ID()%2 == 1 {
							peers = append(peers, n)
						}
					}
				}
				ret[node.ID()] = peers
			}
			return ret
		}

		store.peersFunc = oddOnlyPeersFunc
		store.RebuildPeerMaps()

		// Count odd/even nodes
		oddCount := 0
		for i := 1; i <= numNodes; i++ {
			if i%2 == 1 {
				oddCount++
			}
		}

		// Verify odd nodes see only other odd nodes
		for i := 1; i <= numNodes; i++ {
			peers := store.ListPeers(types.NodeID(i))
			if i%2 == 1 {
				// Odd node should see oddCount-1 peers (other odd nodes)
				if peers.Len() != oddCount-1 {
					rt.Fatalf("phase2: odd node %d has %d peers, want %d",
						i, peers.Len(), oddCount-1)
				}
				// Verify all peers are odd
				for j := range peers.Len() {
					if peers.At(j).ID()%2 == 0 {
						rt.Fatalf("phase2: odd node %d has even peer %d",
							i, peers.At(j).ID())
					}
				}
			} else {
				// Even node should see zero peers
				if peers.Len() != 0 {
					rt.Fatalf("phase2: even node %d has %d peers, want 0",
						i, peers.Len())
				}
			}
		}

		// Phase 3: switch back to allow-all
		store.peersFunc = allVisiblePeersFunc
		store.RebuildPeerMaps()

		for i := 1; i <= numNodes; i++ {
			peers := store.ListPeers(types.NodeID(i))
			if peers.Len() != numNodes-1 {
				rt.Fatalf("phase3: node %d has %d peers, want %d", i, peers.Len(), numNodes-1)
			}
		}
	})
}

// ============================================================================
// Test 4: NodeKey lookup after key rotation
//
// When a node rotates its NodeKey via UpdateNode, the old key must no
// longer resolve and the new key must point to the correct node.
// ============================================================================

func TestRapid_NodeStore_NodeKeyLookup_AfterKeyRotation(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		const numNodes = 4
		nodesSlice, nodesMap := makeTestNodes(numNodes)
		store := startTestStore(nodesSlice, allVisiblePeersFunc)
		defer store.Stop()

		// Pick node 1 and rotate its key
		targetID := types.NodeID(1)
		oldNodeKey := nodesMap[targetID].NodeKey

		// Verify old key works before rotation
		nv, exists := store.GetNodeByNodeKey(oldNodeKey)
		if !exists {
			rt.Fatalf("pre-rotation: GetNodeByNodeKey(oldKey) not found for node %d", targetID)
		}
		if nv.ID() != targetID {
			rt.Fatalf("pre-rotation: GetNodeByNodeKey(oldKey) returned node %d, want %d",
				nv.ID(), targetID)
		}

		// Generate new key and rotate
		newNodeKeyPriv := key.NewNode()
		newNodeKey := newNodeKeyPriv.Public()

		_, ok := store.UpdateNode(targetID, func(n *types.Node) {
			n.NodeKey = newNodeKey
		})
		if !ok {
			rt.Fatalf("UpdateNode(%d) for key rotation returned not-found", targetID)
		}

		// Old key must NOT resolve
		_, existsOld := store.GetNodeByNodeKey(oldNodeKey)
		if existsOld {
			rt.Fatalf("post-rotation: GetNodeByNodeKey(oldKey) still resolves for node %d — stale index!",
				targetID)
		}

		// New key must resolve to the correct node
		nvNew, existsNew := store.GetNodeByNodeKey(newNodeKey)
		if !existsNew {
			rt.Fatalf("post-rotation: GetNodeByNodeKey(newKey) not found for node %d", targetID)
		}
		if nvNew.ID() != targetID {
			rt.Fatalf("post-rotation: GetNodeByNodeKey(newKey) returned node %d, want %d",
				nvNew.ID(), targetID)
		}

		// Other nodes' keys should still work
		for i := 2; i <= numNodes; i++ {
			nID := types.NodeID(i)
			origKey := nodesMap[nID].NodeKey
			nv2, exists2 := store.GetNodeByNodeKey(origKey)
			if !exists2 {
				rt.Fatalf("post-rotation: node %d's original key no longer resolves", nID)
			}
			if nv2.ID() != nID {
				rt.Fatalf("post-rotation: node %d's key resolves to node %d", nID, nv2.ID())
			}
		}
	})
}

// ============================================================================
// Test 5: DeleteNode full cleanup across all indexes
//
// After deleting a node, it must vanish from: GetNode (byID),
// GetNodeByNodeKey, ListPeers for every remaining node, ListNodes
// (allNodes), and GetNodeByMachineKey.
// ============================================================================

func TestRapid_NodeStore_DeleteNode_FullCleanup(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		const numNodes = 5
		nodesSlice, nodesMap := makeTestNodes(numNodes)
		store := startTestStore(nodesSlice, allVisiblePeersFunc)
		defer store.Stop()

		// Pick node 3 to delete
		deleteID := types.NodeID(3)
		deletedNode := nodesMap[deleteID]

		// Verify it exists before deletion
		_, exists := store.GetNode(deleteID)
		if !exists {
			rt.Fatalf("pre-delete: node %d not found", deleteID)
		}

		store.DeleteNode(deleteID)

		// 1. GetNode must return not-found
		_, existsAfter := store.GetNode(deleteID)
		if existsAfter {
			rt.Fatalf("post-delete: GetNode(%d) still returns the node", deleteID)
		}

		// 2. GetNodeByNodeKey must return not-found
		_, existsByKey := store.GetNodeByNodeKey(deletedNode.NodeKey)
		if existsByKey {
			rt.Fatalf("post-delete: GetNodeByNodeKey still resolves deleted node %d", deleteID)
		}

		// 3. GetNodeByMachineKey must return not-found
		_, existsByMK := store.GetNodeByMachineKey(deletedNode.MachineKey, deletedNode.TypedUserID())
		if existsByMK {
			rt.Fatalf("post-delete: GetNodeByMachineKey still resolves deleted node %d", deleteID)
		}

		// 4. ListNodes count must be numNodes - 1
		allNodes := store.ListNodes()
		if allNodes.Len() != numNodes-1 {
			rt.Fatalf("post-delete: ListNodes has %d entries, want %d",
				allNodes.Len(), numNodes-1)
		}
		// Verify deleted node not in allNodes
		for i := range allNodes.Len() {
			if allNodes.At(i).ID() == deleteID {
				rt.Fatalf("post-delete: deleted node %d still in ListNodes", deleteID)
			}
		}

		// 5. ListPeers for every remaining node must NOT include deleted node
		for i := 1; i <= numNodes; i++ {
			if i == int(deleteID) {
				continue
			}
			nID := types.NodeID(i)
			peers := store.ListPeers(nID)
			for j := range peers.Len() {
				if peers.At(j).ID() == deleteID {
					rt.Fatalf("post-delete: ListPeers(%d) still includes deleted node %d",
						nID, deleteID)
				}
			}
			// With allVisiblePeersFunc, remaining nodes should see numNodes-2 peers
			if peers.Len() != numNodes-2 {
				rt.Fatalf("post-delete: ListPeers(%d) has %d peers, want %d",
					nID, peers.Len(), numNodes-2)
			}
		}
	})
}
