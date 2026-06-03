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
		// Connect first so Disconnect's epoch check passes.
		_, epoch := s.Connect(nodeID)

		cs, err := s.Disconnect(nodeID, epoch)
		require.NoError(t, err)

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

		cs, err := s.Disconnect(nodeID, epoch)
		require.NoError(t, err)

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

		cs, err := s.Disconnect(nodeID, epoch)
		require.NoError(t, err)

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

		cs, err := s.Disconnect(nodeID, epoch)
		require.NoError(t, err)

		assertRecomputeNotFull(t, cs)
	})
}
