package state

import (
	"sync/atomic"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

// TestReloadPolicyRebuildsPeerMapOnChangeOnly covers the peer-map rebuilds
// of a policy write. The API handlers apply a policy with [State.SetPolicy],
// store it and then call [State.ReloadPolicy]; the O(n^2) rebuild must run
// once for that, not once per step. A reload that is the first to see a new
// policy (SIGHUP, a policy stored by another path) must still rebuild.
func TestReloadPolicyRebuildsPeerMapOnChangeOnly(t *testing.T) {
	const (
		denyAll  = `{"grants": []}`
		allowAll = `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}`
	)

	cfg := persistTestConfig(t.TempDir() + "/headscale.db")

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	nodes := database.CreateRegisteredNodesForTest(database.CreateUserForTest("reload-user"), 2, "reload-node")
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// Count the peer-map builds. The writer goroutine reads peersFunc only
	// while applying a batch, and none has been queued yet.
	var builds atomic.Int32

	peersFunc := s.nodeStore.peersFunc
	s.nodeStore.peersFunc = func(n []types.NodeView) (policy.ReadView, map[types.NodeID][]types.NodeID, error) {
		builds.Add(1)

		return peersFunc(n)
	}

	// write is the sequence of the SetPolicy API handlers.
	write := func(pol string) {
		t.Helper()

		_, err := s.SetPolicy([]byte(pol))
		require.NoError(t, err)

		_, err = s.SetPolicyInDB(pol)
		require.NoError(t, err)

		cs, err := s.ReloadPolicy()
		require.NoError(t, err)
		require.NotEmpty(t, cs, "a reload always reports a policy change to distribute")
	}
	peers := func() int { return s.ListPeers(nodes[0].ID).Len() }

	require.Equal(t, 1, peers(), "no policy: allow all")

	write(denyAll)
	require.EqualValues(t, 1, builds.Swap(0), "a changed policy is rebuilt once per write")
	require.Zero(t, peers())

	write(denyAll)
	require.Zero(t, builds.Swap(0), "the same policy again needs no rebuild")
	require.Zero(t, peers())

	write(allowAll)
	require.EqualValues(t, 1, builds.Swap(0))
	require.Equal(t, 1, peers())

	// A reload that finds a policy the manager has not seen yet.
	_, err = s.SetPolicyInDB(denyAll)
	require.NoError(t, err)

	_, err = s.ReloadPolicy()
	require.NoError(t, err)
	require.EqualValues(t, 1, builds.Swap(0), "a reload that changes the policy rebuilds")
	require.Zero(t, peers())

	_, err = s.ReloadPolicy()
	require.NoError(t, err)
	require.Zero(t, builds.Swap(0), "a reload of the current policy does not")
}
