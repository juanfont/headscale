package state

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

func TestGivenNameMapsToValidFQDNCheck(t *testing.T) {
	cfg := &types.Config{BaseDomain: "example.com"}

	_, _, ok := givenNameMapsToValidFQDN.check((&types.Node{ID: 1, GivenName: "valid"}).View(), cfg)
	require.True(t, ok, "a valid given name must pass the check")

	problem, fixHint, ok := givenNameMapsToValidFQDN.check((&types.Node{ID: 7, GivenName: ""}).View(), cfg)
	require.False(t, ok, "an empty given name must fail the check")
	require.NotEmpty(t, problem)
	require.Contains(t, fixHint, "rename 7", "fix hint must name the offending node")
}

// TestScanNodeHealthReportsInvalidNameWithoutMutating proves the boot scan
// reports a node whose stored name would break map generation (issue #3346)
// with an actionable fix, and that it never rewrites the stored name — the
// maintainer's decision is log-only, no silent mutation.
func TestScanNodeHealthReportsInvalidNameWithoutMutating(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("scan-user")
	bad := database.CreateRegisteredNodeForTest(user, "scan-bad")
	good := database.CreateRegisteredNodeForTest(user, "scan-good")

	require.NoError(t, database.DB.
		Model(&types.Node{}).
		Where("id = ?", bad.ID).
		Update("given_name", "").Error)
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	findings := s.scanNodeHealth()

	var badFinding *nodeHealthFinding

	for i := range findings {
		require.NotEqual(t, good.ID, findings[i].nodeID, "a valid node must not be reported")

		if findings[i].nodeID == bad.ID {
			badFinding = &findings[i]
		}
	}

	require.NotNil(t, badFinding, "a node with an invalid name must be reported")
	require.Contains(t, badFinding.fixHint, "rename", "finding must carry an actionable fix")

	// Log-only: neither the scan nor boot may rewrite the stored name.
	nv, ok := s.GetNodeByID(bad.ID)
	require.True(t, ok)
	require.Empty(t, nv.GivenName(), "boot scan must not mutate the stored name")
}

// TestBatchSetNodeHealthUnchangedSkipsWrite ensures asking for the health
// value already stored publishes no snapshot — no peersFunc invocation, no
// peer-map rebuild.
func TestBatchSetNodeHealthUnchangedSkipsWrite(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	// Use the State's nodeStore directly to confirm the node exists.
	_, exists := s.nodeStore.GetNode(nodeID)
	require.True(t, exists)

	initialSnapshot := s.nodeStore.data.Load()

	// The node starts with Unhealthy=false. Asking for "healthy=true"
	// means Unhealthy stays false — no change.
	for range 20 {
		changed := s.BatchSetNodeHealth(map[types.NodeID]bool{nodeID: true})
		require.False(t, changed,
			"unchanged health write must not report a route-primary change")
		require.Same(t, initialSnapshot, s.nodeStore.data.Load(),
			"unchanged health write must not publish a new snapshot")
	}
}
