package servertest_test

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestConnectDisconnectRace targets the residual TOCTOU window in
// state.Disconnect: the connectGeneration check at state.go:644 is not
// atomic with the subsequent NodeStore.UpdateNode and
// primaryRoutes.SetRoutes calls. A new Connect that runs between the
// gen check and the mutations can have its effects overwritten by the
// stale Disconnect's SetRoutes(empty).
//
// The poll.go grace-period flow protects against the most common case
// (RemoveNode + stillConnected). Connect/Disconnect on State directly
// bypasses that protection and should still leave the state consistent
// — if it doesn't, that is the bug behind issue #3203.
//
// Run with -race to also catch any data race exposed.
func TestConnectDisconnectRace(t *testing.T) {
	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "race-user")

	route := netip.MustParsePrefix("10.0.0.0/24")

	// Use NewClient to get a node fully registered + Connected via the
	// real noise/poll path. After this, NodeStore + primaryRoutes already
	// have the node, and Connect has been called once.
	//
	// Only c2 advertises the route. PrimaryRoutes preserves a current
	// primary across changes (anti-flap, see primary.go), so if both
	// nodes were advertising, c1 (lower NodeID) would stay primary and
	// the test could never observe the route slipping out of c2's
	// PrimaryRoutes — it would never have been there in the first place.
	c1 := servertest.NewClient(t, srv, "race-r1", servertest.WithUser(user))
	c2 := servertest.NewClient(t, srv, "race-r2", servertest.WithUser(user))

	c1.WaitForPeers(t, 1, 10*time.Second)

	c2.Direct().SetHostinfo(&tailcfg.Hostinfo{
		BackendLogID: "servertest-race-r2",
		Hostname:     "race-r2",
		RoutableIPs:  []netip.Prefix{route},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = c2.Direct().SendUpdate(ctx)

	cancel()

	r2ID := findNodeID(t, srv, "race-r2")

	_, ch, err := srv.State().SetApprovedRoutes(r2ID, []netip.Prefix{route})
	require.NoError(t, err)
	srv.App.Change(ch)

	// Wait for advertisement + approval to be reflected as a primary
	// route assignment in PrimaryRoutes; otherwise we'd be racing the
	// initial steady-state setup, not the Connect/Disconnect window.
	require.Eventually(t, func() bool {
		return slices.Contains(srv.State().GetNodePrimaryRoutes(r2ID), route)
	}, 10*time.Second, 50*time.Millisecond,
		"primary route should be assigned to r2 before driving the race")

	// Drive the race repeatedly. Each iteration:
	//   1. Call Connect(id) to obtain a fresh gen — this stands in for
	//      a session that "owns" the node.
	//   2. Spawn a goroutine that issues Disconnect(id, gen) — the
	//      stale deferred disconnect.
	//   3. Concurrently spawn a goroutine that issues Connect(id) —
	//      the new session arriving.
	//   4. After both finish, check the state is consistent: the node
	//      should be online and primaryRoutes should hold the approved
	//      route for it.
	//
	// The two goroutines synchronise on a barrier so they start
	// approximately simultaneously, maximising the chance of hitting the
	// TOCTOU window.
	const iterations = 100

	for i := range iterations {
		// Establish a "current session" with a known gen for r2.
		_, gen := srv.State().Connect(r2ID)

		var wg sync.WaitGroup

		start := make(chan struct{})

		wg.Add(2)

		go func() {
			defer wg.Done()

			<-start

			_, _ = srv.State().Disconnect(r2ID, gen)
		}()
		go func() {
			defer wg.Done()

			<-start

			_, _ = srv.State().Connect(r2ID)
		}()

		close(start)
		wg.Wait()

		// Post-condition: the node should be ONLINE (the new Connect's
		// effect must dominate, because the stale Disconnect ran with
		// an older gen and should have been a no-op — or its effects
		// must not have overtaken the new Connect's writes).
		nv, ok := srv.State().GetNodeByID(r2ID)
		if !assert.True(t, ok, "iteration %d: node should exist", i) {
			continue
		}

		online, known := nv.IsOnline().GetOk()
		if !assert.True(t, known, "iteration %d: online status should be known", i) {
			continue
		}

		assert.True(t, online,
			"iteration %d: node should be ONLINE after concurrent Connect+Disconnect (gen=%d)",
			i, gen)

		// The approved route must still be reflected as a primary for r2.
		primary := srv.State().GetNodePrimaryRoutes(r2ID)
		assert.True(t, slices.Contains(primary, route),
			"iteration %d: r2 should hold primary for %s after concurrent Connect+Disconnect, got %v",
			i, route, primary)

		if t.Failed() {
			t.Logf("primaryRoutes state at failure:\n%s",
				srv.State().PrimaryRoutesString())

			return
		}
	}
}
