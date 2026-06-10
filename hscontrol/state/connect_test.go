package state

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// runtimePeerComputationReasons returns the Reason of every change in cs that
// carries RequiresRuntimePeerComputation. Each such change makes the batcher
// rebuild a full netmap (packet filters, SSH policy, peer serialization) for
// every connected node, so it is the expensive fan-out the issue is about.
func runtimePeerComputationReasons(cs []change.Change) []string {
	var reasons []string

	for _, c := range cs {
		if c.RequiresRuntimePeerComputation {
			reasons = append(reasons, c.Reason)
		}
	}

	return reasons
}

// hasPeerPatch reports whether any change carries a lightweight PeerChange
// patch (e.g. the online/offline indicator). This is the cheap notification a
// reconnect should produce instead of a full runtime recompute.
func hasPeerPatch(cs []change.Change) bool {
	for _, c := range cs {
		if len(c.PeerPatches) > 0 {
			return true
		}
	}

	return false
}

// forcesPeerRecompute reports whether any change makes peers rebuild a full
// netmap, whether via a full update (subnet-router path) or a runtime peer
// computation (relay/via path).
func forcesPeerRecompute(cs []change.Change) bool {
	for _, c := range cs {
		if c.IsFull() || c.RequiresRuntimePeerComputation {
			return true
		}
	}

	return false
}

// TestConnectDisconnectOrdinaryNodeNoRuntimeRecompute asserts that an ordinary
// node coming online or going offline only sends the lightweight online/offline
// peer patch and does not trigger a runtime peer recompute.
//
// State.Connect and State.Disconnect gate change.PolicyChange() (which sets
// RequiresRuntimePeerComputation, forcing the batcher to rebuild a full netmap
// for every connected node) on NodeNeedsPeerRecompute. An ordinary node is
// neither a subnet router, a relay target, nor a via target, so the gate is
// false and no recompute is emitted.
//
// Emitting that recompute unconditionally turned each reconnect into O(N) full
// netmap rebuilds (and a reconnect storm into O(N^2)), which saturated CPU
// after the v0.28 -> v0.29 upgrade.
func TestConnectDisconnectOrdinaryNodeNoRuntimeRecompute(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	t.Run("connect", func(t *testing.T) {
		cs, epoch := s.Connect(nodeID)
		require.NotZero(t, epoch, "Connect should return a session epoch")

		assert.True(t, hasPeerPatch(cs),
			"Connect should still emit a lightweight online peer patch")

		reasons := runtimePeerComputationReasons(cs)
		assert.Empty(t, reasons,
			"ordinary node connect must not trigger a runtime peer recompute; "+
				"got RequiresRuntimePeerComputation changes: %v", reasons)
	})

	t.Run("disconnect", func(t *testing.T) {
		// Connect acquired a session in the connect subtest too; drain to the
		// last release, which is the one that marks the node offline.
		_, epoch := s.Connect(nodeID)
		cs := drainSessions(t, s, nodeID, epoch)

		assert.True(t, hasPeerPatch(cs),
			"Disconnect should still emit a lightweight offline peer patch")

		reasons := runtimePeerComputationReasons(cs)
		assert.Empty(t, reasons,
			"ordinary node disconnect must not trigger a runtime peer recompute; "+
				"got RequiresRuntimePeerComputation changes: %v", reasons)
	})
}

// TestConnectDisconnectRelayTargetTriggersRecompute locks the cap/relay case:
// a relay target is not a subnet router, so the only thing that makes its
// connect/disconnect emit a runtime peer recompute is the
// NodeNeedsPeerRecompute gate. Peers must still receive that recompute so they
// drop a stale PeerRelay allocation when the relay goes offline.
func TestConnectDisconnectRelayTargetTriggersRecompute(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	// A cap/relay grant whose destination resolves to the node's owning
	// user makes the node a relay target without making it a subnet router.
	relayPolicy := `{"grants":[{"src":["*"],"dst":["persist-user@"],"app":{"tailscale.com/cap/relay":[{}]}}]}`
	_, err := s.SetPolicy([]byte(relayPolicy))
	require.NoError(t, err)

	t.Run("connect", func(t *testing.T) {
		cs, epoch := s.Connect(nodeID)
		require.NotZero(t, epoch)

		assert.NotEmpty(t, runtimePeerComputationReasons(cs),
			"relay-target node connect must trigger a runtime peer recompute")
	})

	t.Run("disconnect", func(t *testing.T) {
		_, epoch := s.Connect(nodeID)
		cs := drainSessions(t, s, nodeID, epoch)

		assert.NotEmpty(t, runtimePeerComputationReasons(cs),
			"relay-target node disconnect must trigger a runtime peer recompute")
	})
}

// TestConnectDisconnectSubnetRouterForcesRecompute guards that a subnet router
// still forces peers to recompute on connect/disconnect (primary-route
// failover changes their AllowedIPs), so the gate does not over-suppress.
func TestConnectDisconnectSubnetRouterForcesRecompute(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	route := netip.MustParsePrefix("10.0.0.0/24")
	_, ok := s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		n.ApprovedRoutes = []netip.Prefix{route}
	})
	require.True(t, ok)

	t.Run("connect", func(t *testing.T) {
		cs, epoch := s.Connect(nodeID)
		require.NotZero(t, epoch)

		assert.True(t, forcesPeerRecompute(cs),
			"subnet router connect must force a peer recompute")
	})

	t.Run("disconnect", func(t *testing.T) {
		_, epoch := s.Connect(nodeID)
		cs := drainSessions(t, s, nodeID, epoch)

		assert.True(t, forcesPeerRecompute(cs),
			"subnet router disconnect must force a peer recompute")
	})
}

// TestConnectDisconnectSubnetRouterEmitsPolicyChangeNotFull pins how a subnet
// router forces that recompute: through the gated change.PolicyChange() (a
// runtime peer recompute) and the lightweight online/offline peer patch, not a
// full update. policyChangeResponse is a strict subset of a full update yet
// still carries primary-route failover, so the heavier FullUpdate that the
// online/offline change once emitted for subnet routers is unnecessary.
func TestConnectDisconnectSubnetRouterEmitsPolicyChangeNotFull(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	route := netip.MustParsePrefix("10.0.0.0/24")
	_, ok := s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		n.ApprovedRoutes = []netip.Prefix{route}
	})
	require.True(t, ok)

	assertRecomputeNotFull := func(t *testing.T, cs []change.Change) {
		t.Helper()

		assert.NotEmpty(t, runtimePeerComputationReasons(cs),
			"subnet router must still drive a runtime peer recompute")
		assert.True(t, hasPeerPatch(cs),
			"subnet router should still emit the lightweight online/offline patch")

		for _, c := range cs {
			assert.Falsef(t, c.IsFull(),
				"subnet router recompute must be a PolicyChange, not a full update: %q", c.Reason)
		}
	}

	t.Run("connect", func(t *testing.T) {
		cs, epoch := s.Connect(nodeID)
		require.NotZero(t, epoch)

		assertRecomputeNotFull(t, cs)
	})

	t.Run("disconnect", func(t *testing.T) {
		_, epoch := s.Connect(nodeID)
		cs := drainSessions(t, s, nodeID, epoch)

		assertRecomputeNotFull(t, cs)
	})
}

// drainSessions releases poll sessions on nodeID until the node goes
// offline, returning the changes from the final release (the one that
// emits the offline notifications). Fails the test if the node is
// still online after releasing as many sessions as Connect calls could
// plausibly have acquired.
func drainSessions(t *testing.T, s *State, nodeID types.NodeID, epoch uint64) []change.Change {
	t.Helper()

	// Arbitrary upper bound: comfortably above the number of Connect
	// calls any test here makes. It only guards against looping
	// forever when the node never goes offline.
	const maxSessions = 16

	for range maxSessions {
		cs, err := s.Disconnect(nodeID, epoch)
		require.NoError(t, err)

		if len(cs) > 0 {
			return cs
		}
	}

	t.Fatalf("node %d still online after releasing %d sessions", nodeID, maxSessions)

	return nil
}

// TestDisconnectOutOfOrderSessionsCannotStrandNodeOnline reproduces the
// server side of the relogin flake at the state level: a cancelled map
// request whose handler runs late acquires a session (and the newest
// epoch) after the real session's Connect, then releases without taking
// the node offline because the real session is still live. The real
// session's release — carrying the older epoch — must still take the
// node offline. Under the old epoch-equality gate it was rejected as
// stale and the node stayed online forever.
func TestDisconnectOutOfOrderSessionsCannotStrandNodeOnline(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	_, liveGen := s.Connect(nodeID)
	_, zombieGen := s.Connect(nodeID)
	require.Greater(t, zombieGen, liveGen, "late session must hold the newer epoch")

	// The zombie session dies first; another session is live, so the node
	// must stay online and no offline changes may be emitted.
	cs, err := s.Disconnect(nodeID, zombieGen)
	require.NoError(t, err)
	assert.Empty(t, cs, "release with another live session must not emit changes")

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	online, known := nv.IsOnline().GetOk()
	require.True(t, known)
	assert.True(t, online, "node must stay online while the real session lives")

	// The real session releases last, with the older epoch. This must take
	// the node offline.
	cs, err = s.Disconnect(nodeID, liveGen)
	require.NoError(t, err)
	assert.True(t, hasPeerPatch(cs), "final release must emit the offline peer patch")

	nv, ok = s.GetNodeByID(nodeID)
	require.True(t, ok)

	online, known = nv.IsOnline().GetOk()
	require.True(t, known)
	assert.False(t, online, "node must be offline after its last session is released")
}
