package state

import (
	"fmt"
	"maps"
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
	// announced mirrors Hostinfo.RoutableIPs — what the client says
	// it can route. The election does not look at this directly; it
	// is used to recompute the effective set whenever ApprovedRoutes
	// changes without a Hostinfo update.
	announced map[types.NodeID][]netip.Prefix
	// approved mirrors node.ApprovedRoutes — what the admin policy
	// allows. SetApprovedRoutes touches this without touching
	// announced; ConnectAdvertise / ApprovedRoutesChange touch both.
	approved map[types.NodeID][]netip.Prefix
	// prefixes is the effective per-node route set —
	// AllApprovedRoutes in the implementation, i.e. (announced ∩
	// approved) excluding exit routes. This is what the election
	// sees, and what the model uses in advertisersByPrefix.
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
		announced: map[types.NodeID][]netip.Prefix{},
		approved:  map[types.NodeID][]netip.Prefix{},
		prefixes:  map[types.NodeID][]netip.Prefix{},
		unhealthy: map[types.NodeID]bool{},
		primary:   map[netip.Prefix]types.NodeID{},
	}
}

// recomputeEffective sets m.prefixes[id] to the intersection of
// m.announced[id] and m.approved[id]. Empty intersections clear the
// node from m.prefixes entirely. Matches Node.AllApprovedRoutes /
// SubnetRoutes semantics (exit routes excluded — none of the test
// prefixes hit that branch).
func (m *primariesModel) recomputeEffective(id types.NodeID) {
	ann := m.announced[id]
	app := m.approved[id]

	if len(ann) == 0 || len(app) == 0 {
		delete(m.prefixes, id)
		return
	}

	eff := make([]netip.Prefix, 0, len(ann))
	for _, p := range ann {
		if slices.Contains(app, p) {
			eff = append(eff, p)
		}
	}

	if len(eff) == 0 {
		delete(m.prefixes, id)
	} else {
		m.prefixes[id] = eff
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

		// All-unhealthy fallback: preserve the previous primary if it
		// is still a candidate, otherwise leave the prefix unmapped.
		// Choosing any candidate would point peers at a node already
		// declared unreachable; the model mirrors that policy.
		if !found && len(nodes) >= 1 {
			if cur, ok := m.primary[p]; ok && slices.Contains(nodes, cur) {
				selected = cur
				found = true
			}
		}

		if found {
			m.primary[p] = selected
		} else {
			delete(m.primary, p)
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
// primaries map given the model. prevSnapshotPrimaries is the snapshot's
// PrimaryRoutes() reading taken before the just-applied op, used to
// catch flap regressions that move primary off a still-eligible owner.
func checkPrimariesProperties(
	rt *rapid.T,
	ns *NodeStore,
	m *primariesModel,
	nodeIDs []types.NodeID,
	prevSnapshotPrimaries map[netip.Prefix]types.NodeID,
) {
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
	// have a primary in the snapshot: a prefix silently losing its
	// primary after a disconnect/reconnect cycle would leave peers
	// without a route.
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

	// Structural invariants on the live snapshot, independent of the
	// model. These catch shapes the model alone cannot — e.g. an owner
	// that is offline but still has the prefix attributed to it.
	snapshotPrimaries := ns.PrimaryRoutes()

	// A primary that owns ≥1 prefix in `routes` must also light up
	// `isPrimaryRoute` (PrimaryRoutesForNode returns nil unless the
	// id is in that map). The inverse check — PrimaryRoutesForNode
	// returning the right prefixes — is already covered above; this
	// catches the reverse direction.
	ownersInRoutes := map[types.NodeID]bool{}
	for _, owner := range snapshotPrimaries {
		ownersInRoutes[owner] = true
	}

	for owner := range ownersInRoutes {
		if got := ns.PrimaryRoutesForNode(owner); len(got) == 0 {
			rt.Fatalf(
				"node %d owns a prefix in routes but PrimaryRoutesForNode is empty",
				owner,
			)
		}
	}

	// Per-owner structural checks: every primary must currently be
	// online and must currently advertise the prefix it owns.
	advertisersByPrefix := m.advertisersByPrefix()

	for prefix, owner := range snapshotPrimaries {
		nv, ok := ns.GetNode(owner)
		if !ok || !nv.Valid() {
			rt.Fatalf(
				"prefix %s primary %d not present in NodeStore",
				prefix, owner,
			)
		}

		// Primary is online: an offline node cannot move packets, so
		// election must never leave one as the snapshot's primary.
		online, known := nv.IsOnline().GetOk()
		if !known || !online {
			rt.Fatalf(
				"prefix %s primary %d is not online",
				prefix, owner,
			)
		}

		// Primary advertises the prefix: AllApprovedRoutes (subnet ∪
		// exit) must contain it. A primary that no longer advertises
		// is a stale assignment the snapshot rebuild failed to clear.
		approved := nv.AllApprovedRoutes()
		if !slices.Contains(approved, prefix) {
			rt.Fatalf(
				"prefix %s primary %d does not advertise it (approved=%v)",
				prefix, owner, approved,
			)
		}

		// Healthy preference: if any candidate for this prefix is
		// healthy, the elected primary must also be healthy. Leaving
		// the prefix unmapped is fine; pointing at an unhealthy
		// candidate while a healthy one was available is not.
		candidates := advertisersByPrefix[prefix]
		anyHealthy := false

		for _, c := range candidates {
			if !m.unhealthy[c] {
				anyHealthy = true
				break
			}
		}

		if anyHealthy && m.unhealthy[owner] {
			rt.Fatalf(
				"prefix %s primary %d is unhealthy but %v had a healthy candidate",
				prefix, owner, candidates,
			)
		}

		// Anti-flap: if the previous snapshot already had a primary
		// for this prefix AND that primary is still a healthy
		// candidate after the op, the election must keep it. Flapping
		// the primary for an unrelated reason violates the contract
		// the integration tests rely on (HA failover only moves on
		// loss of candidacy or health).
		if prev, hadPrev := prevSnapshotPrimaries[prefix]; hadPrev {
			stillCandidate := slices.Contains(candidates, prev)
			stillHealthy := !m.unhealthy[prev]

			if stillCandidate && stillHealthy && owner != prev {
				rt.Fatalf(
					"prefix %s flapped primary %d -> %d "+
						"while previous primary was still a healthy candidate",
					prefix, prev, owner,
				)
			}
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

// snapshotPrimariesCopy returns a defensive copy of the snapshot's
// prefix→primary map so the caller can compare against a later
// snapshot without aliasing the live map.
func snapshotPrimariesCopy(ns *NodeStore) map[netip.Prefix]types.NodeID {
	live := ns.PrimaryRoutes()

	out := make(map[netip.Prefix]types.NodeID, len(live))
	maps.Copy(out, live)

	return out
}

// TestPrimaryRoutesProperty drives NodeStore with a randomised
// sequence of high-level operations and checks that the snapshot's
// primaries map matches a reference model after every step.
//
// Op set (covers the dual-disconnect, batched-probe, and
// all-unhealthy-fallback shapes that election has to handle):
//
//   - ConnectAdvertise: online + advertise prefs, clear Unhealthy
//   - Disconnect: offline; ApprovedRoutes persists
//   - ProbeUnhealthy: set Unhealthy
//   - ProbeHealthy: clear Unhealthy
//   - ApprovedRoutesChange: change advertised prefs without touching health
//   - BatchProbeResults: apply a batch of health flips through
//     UpdateNodes so the election runs once for the cycle, matching
//     State.BatchSetNodeHealth
//   - SimultaneousDisconnect: mark multiple nodes offline atomically
//     via UpdateNodes (the dual-cable-pull shape)
//   - SetApprovedRoutes: change ApprovedRoutes while leaving
//     Hostinfo.RoutableIPs alone — exercises the asymmetry between
//     announced and approved
//   - OfflineExpiry: IsOnline=false WITHOUT clearing Unhealthy
//     (matches the Disconnect path's actual semantics versus
//     ConnectAdvertise's full reset)
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
		// nodeSubsetGen draws 1..N distinct node IDs for the batched
		// ops. SliceOfNDistinct's lower bound is inclusive, so 1 is
		// the smallest sensible batch — a zero-size batch is a no-op
		// the rapid harness should not waste shrinking cycles on.
		nodeSubsetGen := rapid.SliceOfNDistinct(
			nodeGen,
			1, numNodes,
			func(id types.NodeID) types.NodeID { return id },
		)

		opCount := rapid.IntRange(5, 200).Draw(rt, "opCount")
		for step := range opCount {
			op := rapid.IntRange(0, 8).Draw(rt, fmt.Sprintf("op_%d", step))

			// Snapshot primaries before applying the op so the
			// anti-flap invariant has a stable reference. Reading
			// after the model has already changed would compare a
			// stale snapshot to a moved model.
			prevPrimaries := snapshotPrimariesCopy(ns)

			switch op {
			case 0: // ConnectAdvertise — Connect path clears Unhealthy.
				id := nodeGen.Draw(rt, fmt.Sprintf("id_%d", step))
				prefs := prefixSubsetGen.Draw(rt, fmt.Sprintf("prefs_%d", step))

				ns.UpdateNode(id, func(n *types.Node) {
					n.IsOnline = new(true)
					n.Unhealthy = false
					n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: prefs}
					n.ApprovedRoutes = prefs
				})

				m.announced[id] = prefs
				m.approved[id] = prefs
				m.recomputeEffective(id)

				if len(prefs) == 0 {
					delete(m.connected, id)
				} else {
					m.connected[id] = true
				}

				delete(m.unhealthy, id)

			case 1: // Disconnect — IsOnline=false; ApprovedRoutes persists.
				id := nodeGen.Draw(rt, fmt.Sprintf("id_%d", step))
				ns.UpdateNode(id, func(n *types.Node) {
					n.IsOnline = new(false)
				})
				delete(m.connected, id)

			case 2: // ProbeUnhealthy — HA prober marks node bad.
				id := nodeGen.Draw(rt, fmt.Sprintf("id_%d", step))
				ns.UpdateNode(id, func(n *types.Node) {
					n.Unhealthy = true
				})
				m.unhealthy[id] = true

			case 3: // ProbeHealthy — HA prober marks node good.
				id := nodeGen.Draw(rt, fmt.Sprintf("id_%d", step))
				ns.UpdateNode(id, func(n *types.Node) {
					n.Unhealthy = false
				})
				delete(m.unhealthy, id)

			case 4: // ApprovedRoutesChange — change advertised prefs without touching health.
				id := nodeGen.Draw(rt, fmt.Sprintf("id_%d", step))
				prefs := prefixSubsetGen.Draw(rt, fmt.Sprintf("prefs_%d", step))

				ns.UpdateNode(id, func(n *types.Node) {
					n.IsOnline = new(true)
					n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: prefs}
					n.ApprovedRoutes = prefs
				})

				m.announced[id] = prefs
				m.approved[id] = prefs
				m.recomputeEffective(id)

				if len(prefs) == 0 {
					delete(m.connected, id)
				} else {
					m.connected[id] = true
				}

			case 5: // BatchProbeResults — atomic health flips per cycle.
				// Mirrors State.BatchSetNodeHealth: per-node
				// (id, unhealthy) pairs applied through UpdateNodes
				// so the election runs once on the post-batch state.
				// Per-call publication would let an intermediate
				// "one unhealthy, one healthy" snapshot re-elect off
				// the still-healthy node before the second flip
				// landed.
				ids := nodeSubsetGen.Draw(rt, fmt.Sprintf("batch_ids_%d", step))

				results := make(map[types.NodeID]bool, len(ids))
				for i, id := range ids {
					unhealthy := rapid.Bool().Draw(rt, fmt.Sprintf("batch_h_%d_%d", step, i))
					results[id] = unhealthy
				}

				fns := make(map[types.NodeID]UpdateNodeFunc, len(results))
				for id, unhealthy := range results {
					fns[id] = func(n *types.Node) {
						n.Unhealthy = unhealthy
					}
				}

				ns.UpdateNodes(fns)

				for id, unhealthy := range results {
					if unhealthy {
						m.unhealthy[id] = true
					} else {
						delete(m.unhealthy, id)
					}
				}

			case 6: // SimultaneousDisconnect — multiple offline in one batch.
				// Dual-cable-pull shape: two HA routers' poll
				// sessions both close in the same NodeStore tick.
				// Per-call Disconnect could leave the snapshot
				// momentarily pointing at an offline owner; the
				// batched form forces a single rebuild.
				ids := nodeSubsetGen.Draw(rt, fmt.Sprintf("disc_ids_%d", step))

				fns := make(map[types.NodeID]UpdateNodeFunc, len(ids))
				for _, id := range ids {
					fns[id] = func(n *types.Node) {
						n.IsOnline = new(false)
					}
				}

				ns.UpdateNodes(fns)

				for _, id := range ids {
					delete(m.connected, id)
				}

			case 7: // SetApprovedRoutes — change ApprovedRoutes only.
				// SetApprovedRoutes in production updates only
				// node.ApprovedRoutes; Hostinfo.RoutableIPs (what
				// the client announced) is set by the next
				// MapRequest. SubnetRoutes intersects the two, so
				// dropping ApprovedRoutes mid-flight shrinks the
				// advertised set immediately while announcement
				// alone never extends it.
				id := nodeGen.Draw(rt, fmt.Sprintf("setapp_id_%d", step))
				prefs := prefixSubsetGen.Draw(rt, fmt.Sprintf("setapp_prefs_%d", step))

				ns.UpdateNode(id, func(n *types.Node) {
					n.ApprovedRoutes = prefs
				})

				m.approved[id] = prefs
				m.recomputeEffective(id)

			case 8: // OfflineExpiry — IsOnline=false, KEEP Unhealthy.
				// The Disconnect path does not clear Unhealthy
				// (only ConnectAdvertise does on the way back
				// up). A probe that marks unhealthy and a grace-
				// period disconnect that lands later leaves the
				// node with a stale Unhealthy bit; the test
				// exercises that shape.
				id := nodeGen.Draw(rt, fmt.Sprintf("expire_id_%d", step))
				ns.UpdateNode(id, func(n *types.Node) {
					n.IsOnline = new(false)
				})

				delete(m.connected, id)
				// m.unhealthy[id] is intentionally NOT cleared.
			}

			m.updatePrimaries()

			checkPrimariesProperties(rt, ns, m, nodeIDs, prevPrimaries)
		}
	})
}
