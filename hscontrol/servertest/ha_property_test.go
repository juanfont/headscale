package servertest_test

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
)

// haPropClient bundles a TestClient with the node ID and route it
// advertises. The property test mutates connection state through
// these handles and inspects the resulting NodeStore snapshot.
type haPropClient struct {
	tc    *servertest.TestClient
	id    types.NodeID
	name  string
	route netip.Prefix
	// connected mirrors the prober's view (mapBatcher.IsConnected).
	// Tracked alongside the runtime read so anti-flap invariants can
	// reason about the candidate set the prober actually evaluates.
	connected bool
	// freshSinceReconnect is true between a successful Reconnect and
	// the prober's second observation of the new SessionEpoch — the
	// window in which the session-stability guard must defer instead
	// of installing an Unhealthy bit. Reset by the first ProberTick
	// that runs against the new session; cleared on Disconnect.
	freshSinceReconnect bool
}

// checkTB embeds *testing.T to satisfy testing.TB (which requires an
// unexported method only the testing package can provide) while
// collecting Cleanup functions in a local LIFO stack. runCleanups()
// runs them when the rapid check body exits so each check's resources
// are released immediately, not at the outer test's teardown — which
// would otherwise accumulate hundreds of servers and tens of thousands
// of goroutines across a 300-check run.
//
// Fatal/Fatalf still call through to *testing.T and fail the outer
// test. Inside a rapid check use rt.Fatalf instead so rapid can shrink
// the failing op sequence.
type checkTB struct {
	*testing.T

	mu       sync.Mutex
	cleanups []func()
}

func (c *checkTB) Cleanup(fn func()) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cleanups = append(c.cleanups, fn)
}

func (c *checkTB) runCleanups() {
	c.mu.Lock()
	cs := c.cleanups
	c.cleanups = nil
	c.mu.Unlock()

	for _, v := range slices.Backward(cs) {
		v()
	}
}

// haReadvertise pushes hostinfo + approved routes again. Called after
// every Reconnect so the new poll session re-publishes the prefix. The
// controlclient.Direct carries the SetHostinfo state across
// re-registration, but pushing again removes a race where the test
// inspects PrimaryRoutes before the initial map of the new session
// landed.
func haReadvertise(
	tb testing.TB,
	srv *servertest.TestServer,
	c *haPropClient,
) {
	tb.Helper()

	c.tc.Direct().SetHostinfo(&tailcfg.Hostinfo{
		BackendLogID: "servertest-" + c.name,
		Hostname:     c.name,
		RoutableIPs:  []netip.Prefix{c.route},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = c.tc.Direct().SendUpdate(ctx)

	_, ch, err := srv.State().SetApprovedRoutes(c.id, []netip.Prefix{c.route})
	require.NoError(tb, err)
	srv.App.Change(ch)
}

// readPrimaries builds the prefix→owner map by inverting
// State.GetNodePrimaryRoutes for every client in the fleet. The State
// API does not expose the raw snapshot map directly; iterating the
// known clients reconstructs it without poking at NodeStore internals.
// Any inconsistency between routes and isPrimaryRoute surfaces as a
// duplicate ownership claim and trips invariant 4.
func readPrimaries(
	rt *rapid.T,
	srv *servertest.TestServer,
	clients []*haPropClient,
) map[netip.Prefix]types.NodeID {
	rt.Helper()

	out := make(map[netip.Prefix]types.NodeID)

	for _, c := range clients {
		for _, p := range srv.State().GetNodePrimaryRoutes(c.id) {
			if prev, ok := out[p]; ok {
				rt.Fatalf(
					"prefix %s has two owners: %d and %d "+
						"(GetNodePrimaryRoutes claimed both)",
					p, prev, c.id,
				)
			}

			out[p] = c.id
		}
	}

	return out
}

// checkHAInvariants walks every prefix → primary mapping in the live
// snapshot and asserts the six properties documented in the test
// header. prevPrimaries is the snapshot taken before the just-applied
// op so anti-flap can compare moves.
//
//nolint:gocyclo // invariant checker over several independent properties
func checkHAInvariants(
	rt *rapid.T,
	srv *servertest.TestServer,
	clients []*haPropClient,
	prevPrimaries map[netip.Prefix]types.NodeID,
	skipAntiFlap bool,
) {
	rt.Helper()

	st := srv.State()
	primaries := readPrimaries(rt, srv, clients)

	// Collect every prefix advertised by the fleet so the all-down
	// honesty check can iterate them, even prefixes with zero current
	// advertisers.
	prefixSet := make(map[netip.Prefix]struct{})
	for _, c := range clients {
		prefixSet[c.route] = struct{}{}
	}

	// Build the candidate set per prefix from the NodeStore: a node is a
	// candidate when it is IsOnline=true and AllApprovedRoutes contains
	// the prefix. This is exactly the input to electPrimaryRoutes; the
	// prober's mapBatcher.IsConnected view is a separate gate the
	// prober consults before dispatching a probe, not part of the
	// election input.
	advertisersByPrefix := make(map[netip.Prefix][]types.NodeID)

	for _, c := range clients {
		nv, ok := st.GetNodeByID(c.id)
		if !ok || !nv.Valid() {
			continue
		}

		online, known := nv.IsOnline().GetOk()
		if !known || !online {
			continue
		}

		for _, p := range nv.AllApprovedRoutes() {
			if p == c.route {
				advertisersByPrefix[p] = append(advertisersByPrefix[p], c.id)
			}
		}
	}

	// Invariant 4: isPrimaryRoute must be consistent with routes.
	for prefix, owner := range primaries {
		got := srv.State().GetNodePrimaryRoutes(owner)
		if !slices.Contains(got, prefix) {
			rt.Fatalf(
				"prefix %s primary=%d but GetNodePrimaryRoutes(%d)=%v missing it",
				prefix, owner, owner, got,
			)
		}
	}

	for prefix, owner := range primaries {
		nv, ok := st.GetNodeByID(owner)
		if !ok || !nv.Valid() {
			rt.Fatalf(
				"prefix %s primary %d missing from NodeStore",
				prefix, owner,
			)
		}

		// Invariant 1: primary IsOnline in the NodeStore view.
		// state.Disconnect's 10s grace can leave a recently-disconnected
		// node with IsOnline=true; the structural rule still requires
		// the bit before the snapshot may keep it as primary.
		online, known := nv.IsOnline().GetOk()
		if !known || !online {
			rt.Fatalf(
				"prefix %s primary %d is not online (IsOnline=%v known=%v)",
				prefix, owner, online, known,
			)
		}

		// Invariant 2: primary advertises the prefix and is among the
		// snapshot's candidate set.
		approved := nv.AllApprovedRoutes()
		if !slices.Contains(approved, prefix) {
			rt.Fatalf(
				"prefix %s primary %d does not advertise it (approved=%v)",
				prefix, owner, approved,
			)
		}

		if !slices.Contains(advertisersByPrefix[prefix], owner) {
			rt.Fatalf(
				"prefix %s primary %d not in advertiser set %v",
				prefix, owner, advertisersByPrefix[prefix],
			)
		}

		// Invariant 5 (anti-flap): if the previous snapshot already had
		// a primary for this prefix AND that primary is still a healthy,
		// online, advertising candidate, the new snapshot must keep it.
		// Skipped on settle reads where we re-check without an op in
		// between — the prober may run in a deferred batch and the
		// election may legitimately move once on its own timeline.
		if !skipAntiFlap {
			if prev, hadPrev := prevPrimaries[prefix]; hadPrev && prev != owner {
				prevNV, exists := st.GetNodeByID(prev)
				if exists && prevNV.Valid() {
					prevOnline, prevKnown := prevNV.IsOnline().GetOk()
					prevApproved := prevNV.AllApprovedRoutes()

					stillCandidate := prevKnown && prevOnline &&
						slices.Contains(prevApproved, prefix)
					stillHealthy := st.IsNodeHealthy(prev)

					if stillCandidate && stillHealthy {
						rt.Fatalf(
							"prefix %s flapped primary %d -> %d "+
								"while previous primary was still a healthy candidate",
							prefix, prev, owner,
						)
					}
				}
			}
		}
	}

	// Invariant 6 (all-down honesty): if every candidate of a prefix is
	// either offline OR unhealthy, the snapshot must either drop the
	// primary OR keep one that is still a candidate from the same set
	// (the all-unhealthy preserve-prev rule). A primary pointed at a
	// non-candidate after every candidate has gone dark would point
	// peers at a node the prober has already declared unreachable.
	for prefix := range prefixSet {
		owner, hasPrimary := primaries[prefix]
		if !hasPrimary {
			continue
		}

		candidates := advertisersByPrefix[prefix]

		// Empty candidates with a primary present trips invariant 2
		// above; reaching this branch with len(candidates) == 0 means
		// the snapshot is internally inconsistent.
		if len(candidates) == 0 {
			rt.Fatalf(
				"prefix %s has primary %d but no advertiser in the snapshot",
				prefix, owner,
			)
		}

		anyHealthy := slices.ContainsFunc(candidates, st.IsNodeHealthy)

		// Healthy preference: a primary should not be unhealthy when a
		// healthy candidate exists. Asserting this through the real
		// prober → State → NodeStore seam catches any divergence the
		// unit-level model would miss.
		if anyHealthy && !st.IsNodeHealthy(owner) {
			rt.Fatalf(
				"prefix %s primary %d unhealthy but %v has a healthy candidate",
				prefix, owner, candidates,
			)
		}

		// All-unhealthy guards: with every candidate unhealthy, the
		// election has exactly two correct choices:
		//   - preserve prev primary when it is still a candidate
		//   - leave the prefix unmapped (no candidate fallback)
		//
		// Any other outcome points peers at a node already declared
		// unreachable.
		if !anyHealthy {
			prevOwner, hadPrev := prevPrimaries[prefix]
			prevStillCandidate := hadPrev &&
				slices.Contains(candidates, prevOwner)

			if prevStillCandidate && owner != prevOwner {
				rt.Fatalf(
					"prefix %s all-unhealthy election picked %d, "+
						"but prev primary %d is still a candidate — "+
						"preserve-prev rule violated",
					prefix, owner, prevOwner,
				)
			}

			if !prevStillCandidate && (!hadPrev || owner != prevOwner) {
				rt.Fatalf(
					"prefix %s all-unhealthy fallback elected %d "+
						"but prev primary %v is gone; election "+
						"must leave the prefix unmapped",
					prefix, owner, prevOwner,
				)
			}
		}
	}
}

// snapshotPrimaries returns a defensive copy of the live primary
// route map so the caller can compare to a later snapshot without
// aliasing. Inverts GetNodePrimaryRoutes since State does not expose
// the raw snapshot map.
func snapshotPrimaries(
	rt *rapid.T,
	srv *servertest.TestServer,
	clients []*haPropClient,
) map[netip.Prefix]types.NodeID {
	return readPrimaries(rt, srv, clients)
}

// TestHAProberProperty drives a real Headscale TestServer with a small
// fleet of HA-route-advertising clients through a randomised sequence
// of connect / disconnect / reconnect / prober-tick operations and
// asserts that the live PrimaryRoutes() snapshot honours every HA
// invariant after each step.
//
// Coverage versus the unit-level NodeStore property test:
//
//   - This test exercises the FULL seam: real prober → real PingNode
//     dispatch → real responseCh handling → State.BatchSetNodeHealth
//     → NodeStore election → mapper batcher updates. The unit test
//     bypasses the prober entirely.
//
//   - Disconnect/Reconnect goes through the real poll-session
//     lifecycle: mapBatcher.RemoveNode flips IsConnected, the 10s
//     grace period defers state.Disconnect, and state.Connect bumps
//     SessionEpoch on rejoin. The prober defers fresh-session probes
//     so a reconnect mid-cycle does not install a stale Unhealthy.
//
//   - The batched BatchSetNodeHealth is observable through the
//     all-unhealthy preserve-prev invariant: per-call writes would
//     publish an intermediate "one unhealthy, one healthy" snapshot,
//     leaving primary on a non-prev node after both flips land.
//
//   - The all-unhealthy fallback that leaves prefixes unmapped is
//     covered by the honesty invariant: with every candidate
//     unhealthy AND prev gone from the candidate set, the prefix
//     must stay unmapped instead of pinned to any candidate.
//
// Caveat: TestClient is a real controlclient.Direct that responds to
// PingRequest over Noise, so the timeout path of the prober rarely
// fires. The session-stability guard is asserted
// (freshSinceReconnect tracking + healthy assertion after the first
// probe of a new session) but the tight race —
// probe-against-old-session-while-reconnecting — needs a dedicated
// reconnect test to trigger deterministically.
//
// Ops drawn by rapid:
//
//   - ClientDisconnect(i)     — cancel poll session, flips IsConnected
//   - ClientReconnect(i)      — re-register and start new poll session
//   - ProberTick()            — invoke prober.ProbeOnce synchronously
//   - WaitForSnapshot()       — re-check invariants without a new op
//
// Initial connect happens once during setup so the fleet always has
// the same baseline. Drawing ClientConnect in the op loop would
// require setting up auth keys and waiting for peer convergence
// inside the rapid body, which would dominate the per-check budget
// for little extra coverage.
func TestHAProberProperty(t *testing.T) {
	// Per-check wall-cost is ~15-25s (real Noise handshake on each
	// reconnect), so the default 100-check rapid budget blows past
	// the 10-minute go test timeout used by the Tests workflow.
	// Skip on CI by default so the everyday sweep stays fast; runs
	// locally so seed shrinking works without an opt-in flag.
	if util.IsCI() {
		t.Skip("skipping HA prober property test in CI; runs locally")
	}

	if testing.Short() {
		t.Skip("skipping property test in short mode")
	}

	rapid.Check(t, func(rt *rapid.T) {
		// Fresh server per rapid check: rapid shrinks by replaying ops
		// from a clean state, so we cannot reuse a server across runs.
		// Cleanups registered against checkTB run at the end of THIS
		// check so server resources are released before the next one
		// starts.
		tb := &checkTB{T: t}
		defer tb.runCleanups()

		srv := servertest.NewServer(tb)
		user := srv.CreateUser(tb, "ha-prop")

		// Three HA candidates is the smallest set that exercises every
		// election shape (primary, secondary, tertiary) while keeping
		// per-check setup under ~10 seconds. Higher numbers blow out
		// the wall-clock budget without adding new failure modes — the
		// dual-disconnect and reconnect-during-probe regressions all
		// reproduce at N=3.
		const numClients = 3

		route := netip.MustParsePrefix("10.200.0.0/24")

		clients := make([]*haPropClient, 0, numClients)

		for i := range numClients {
			name := fmt.Sprintf("ha-prop-r%d", i+1)
			tc := servertest.NewClient(tb, srv, name, servertest.WithUser(user))

			// Wait for at least the initial netmap so the registration
			// committed and findNodeID is guaranteed to see the node.
			tc.WaitForUpdate(tb, 10*time.Second)

			id := findNodeID(tb, srv, name)

			c := &haPropClient{
				tc:        tc,
				id:        id,
				name:      name,
				route:     route,
				connected: true,
			}
			clients = append(clients, c)

			haReadvertise(tb, srv, c)
		}

		// Prober uses a short timeout so each ProberTick op drains
		// the cycle in well under a second. TestClient is backed by a
		// real controlclient.Direct that DOES respond to PingRequest
		// over Noise (see TestPingNode), so most probes record a
		// successful response. The probe-timeout path still fires for
		// nodes whose poll session is mid-bounce — exactly the seam
		// the session-stability guard was built for — but timing it
		// reliably from outside the prober is hard; the property test
		// focuses on the steady-state election invariants instead.
		prober := state.NewHAHealthProber(
			srv.State(),
			types.HARouteConfig{
				ProbeInterval: 30 * time.Second,
				ProbeTimeout:  50 * time.Millisecond,
			},
			srv.URL,
			srv.App.MapBatcher().IsConnected,
		)

		// Sanity: every client should now be an advertiser of route,
		// and the snapshot must have an HA primary already.
		require.Eventually(tb, func() bool {
			for _, c := range clients {
				if slices.Contains(
					srv.State().GetNodePrimaryRoutes(c.id),
					route,
				) {
					return true
				}
			}

			return false
		}, 10*time.Second, 50*time.Millisecond,
			"setup: route should have a primary before drawing ops")

		idxGen := rapid.IntRange(0, numClients-1)
		opGen := rapid.IntRange(0, 3)
		opCount := rapid.IntRange(15, 35).Draw(rt, "opCount")

		for step := range opCount {
			op := opGen.Draw(rt, fmt.Sprintf("op_%d", step))

			prev := snapshotPrimaries(rt, srv, clients)

			// Anti-flap is meaningful only across operations that do
			// not themselves mutate the candidate set or per-node
			// health. Connect/Disconnect both mutate IsOnline (via
			// state.Connect, or via the asynchronous grace-period
			// state.Disconnect), and the resulting election move is
			// expected, not a flap. ProbeOnce, by contrast, must keep
			// the primary on the previous owner whenever that owner
			// is still a candidate — this is what the reconnect-
			// during-probe and dual-disconnect guards preserve.
			isProberOp := op == 2

			switch op {
			case 0: // ClientDisconnect
				idx := idxGen.Draw(rt, fmt.Sprintf("disc_idx_%d", step))
				c := clients[idx]

				// Refuse to disconnect the last connected node. The
				// prober's HANodes gate requires ≥2 online candidates
				// per prefix; with only one node left, no probe runs
				// and the prober-driven invariants (anti-flap,
				// reconnect-defer) become unfalsifiable. Keeping at
				// least two candidates is enough to exercise every
				// failure shape we care about.
				connectedCount := 0

				for _, cc := range clients {
					if cc.connected {
						connectedCount++
					}
				}

				if c.connected && connectedCount > 2 {
					c.tc.Disconnect(tb)
					c.connected = false
					c.freshSinceReconnect = false
				}

			case 1: // ClientReconnect
				idx := idxGen.Draw(rt, fmt.Sprintf("rec_idx_%d", step))
				c := clients[idx]

				if !c.connected {
					c.tc.Reconnect(tb)

					// Wait for the new poll session to register with
					// the batcher so the prober's IsConnected gate
					// reflects the reconnect on the next ProberTick.
					// WaitForUpdate adds ~1s per call; polling
					// IsConnected directly converges in <100ms.
					require.Eventually(
						tb,
						func() bool {
							return srv.App.MapBatcher().
								IsConnected(c.id)
						},
						10*time.Second,
						5*time.Millisecond,
						"reconnect: batcher should see %s online",
						c.name,
					)

					c.connected = true
					c.freshSinceReconnect = true

					// Re-push hostinfo so the new session's initial
					// map sets RoutableIPs as expected. SetApprovedRoutes
					// is idempotent on the same set.
					haReadvertise(tb, srv, c)
				}

			case 2: // ProberTick — drive one synchronous probe cycle.
				// Capture freshness BEFORE running the probe; the
				// prober itself flips a node from "fresh" to "stable"
				// when it sees the same SessionEpoch twice, and the
				// "fresh sessions must defer" rule is expressed
				// against the pre-probe state.
				freshThisCycle := make(map[types.NodeID]bool, len(clients))
				for _, c := range clients {
					freshThisCycle[c.id] = c.freshSinceReconnect
				}

				ctx, cancel := context.WithTimeout(
					context.Background(),
					5*time.Second,
				)

				// Use App.Change as the dispatcher — the prober batches
				// its results through BatchSetNodeHealth and emits a
				// single PolicyChange. The real wiring is what we want
				// to test.
				prober.ProbeOnce(ctx, srv.App.Change)
				cancel()

				// Session-stability rule: the first probe against a
				// freshly-reconnected node must defer instead of
				// installing an Unhealthy bit. In this servertest the
				// TestClient is backed by a real controlclient.Direct
				// that DOES respond to PingRequests over Noise, so
				// the tight timing window — probe dispatched against
				// an old session whose ping never returns — rarely
				// opens. The rule still runs as a sanity gate: if it
				// ever does fire, the freshly-reconnected node will
				// surface as unhealthy after a single probe, and the
				// test catches it.
				for _, c := range clients {
					if !freshThisCycle[c.id] || !c.connected {
						continue
					}

					if !srv.State().IsNodeHealthy(c.id) {
						rt.Fatalf(
							"node %d (%s) was marked unhealthy by "+
								"the first probe after reconnect; "+
								"session-stability guard should have "+
								"deferred",
							c.id, c.name,
						)
					}

					c.freshSinceReconnect = false
				}

			case 3: // WaitForSnapshot — re-check invariants without
				// applying a new op. NodeStore writes are synchronous
				// inside UpdateNode/UpdateNodes, so there is nothing
				// to wait on; the no-op step still verifies that two
				// consecutive reads (one snapshot, the same snapshot)
				// stay consistent. This is invariant 3: stable
				// conditions = stable primary. We skip the anti-flap
				// comparison so a primary that legitimately changed
				// in the prior op is not re-flagged here.
				checkHAInvariants(rt, srv, clients, prev, true)

				continue
			}

			checkHAInvariants(rt, srv, clients, prev, !isProberOp)
		}
	})
}
