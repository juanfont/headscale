//go:build !race

// This is a timing-sensitive performance regression test; the race detector's
// ~10x slowdown makes its wall-clock assertion meaningless, so it is excluded
// from -race builds. The concurrency correctness of the policy lock change it
// guards is covered under -race by TestPolicyManagerConcurrentReads in
// hscontrol/policy/v2.

package mapper

import (
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/derp"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// setupStormBatcher builds a real state+batcher with production-default
// NodeStore batching so the reconnect-storm contention is realistic. It mirrors
// setupBatcherWithTestData but lets the test control BatcherWorkers and the
// policy.
func setupStormBatcher(tb testing.TB, nodeCount, workers int, policy string) (*TestData, func()) {
	tb.Helper()

	tmpDir := tb.TempDir()
	prefixV4 := netip.MustParsePrefix("100.64.0.0/10")
	prefixV6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")

	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: tmpDir + "/headscale_test.db"},
		},
		PrefixV4:     &prefixV4,
		PrefixV6:     &prefixV6,
		IPAllocation: types.IPAllocationStrategySequential,
		BaseDomain:   "headscale.test",
		Policy:       types.PolicyConfig{Mode: types.PolicyModeDB},
		DERP: types.DERPConfig{
			ServerEnabled: false,
			DERPMap: &tailcfg.DERPMap{
				Regions: map[int]*tailcfg.DERPRegion{999: {RegionID: 999}},
			},
		},
		Tuning: types.Tuning{
			BatchChangeDelay: 10 * time.Millisecond,
			BatcherWorkers:   workers,
			// Production defaults: coalesce writes so the storm is not
			// exaggerated by an unrealistically small NodeStore batch.
			NodeStoreBatchSize:    100,
			NodeStoreBatchTimeout: 500 * time.Millisecond,
		},
	}

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(tb, err)

	users := database.CreateUsersForTest(1, "testuser")
	dbNodes := database.CreateRegisteredNodesForTest(users[0], nodeCount, "node")

	allNodes := make([]node, 0, nodeCount)
	for i := range dbNodes {
		allNodes = append(allNodes, node{
			n:  dbNodes[i],
			ch: make(chan *tailcfg.MapResponse, normalBufferSize),
		})
	}

	st, err := state.NewState(cfg)
	require.NoError(tb, err)

	derpMap, err := derp.GetDERPMap(cfg.DERP)
	require.NoError(tb, err)
	st.SetDERPMap(derpMap)

	_, err = st.SetPolicy([]byte(policy))
	require.NoError(tb, err)

	batcher := wrapBatcherForTest(NewBatcherAndMapper(cfg, st), st)
	batcher.Start()

	td := &TestData{
		Database: database,
		Users:    users,
		Nodes:    allNodes,
		State:    st,
		Config:   cfg,
		Batcher:  batcher,
	}

	return td, func() {
		batcher.Close()
		st.Close()
		database.Close()
	}
}

// TestInitialMapNotStarvedByReconnectStorm reproduces juanfont/headscale#3346.
//
// When every node redials at once (e.g. after a server upgrade restart), each
// connection writes the NodeStore (UpdateNodeFromMapRequest + Connect) and the
// batcher generates its initial map. All of that reads the policy through the
// PolicyManager. Before the fix the PolicyManager guarded every read with a
// single exclusive mutex, so the NodeStore writer's O(n^2) BuildPeerMap and
// every node's FilterForNode serialised against each other. On a per-node
// filter policy (autogroup:self, via, relay grants) each hold is expensive, so
// under the storm time-to-initial-map grew without bound.
//
// On the production server in #3346 this drove the batcher's per-node
// total.duration from ~4s to ~76s; tailscale clients aborted the map POST
// first and reported
//
//	PollNetMap: Post ".../machine/map": unexpected EOF
//
// then redialled, feeding the storm so it never converged. An allow-all policy
// does NOT reproduce this — BuildPeerMap is cheap there; the per-node filter
// path is what makes it expensive, matching a real deployment's ACLs.
//
// The fix makes PolicyManager reads take a shared RLock so map generation runs
// concurrently. AddNode blocks until the initial map is generated and handed to
// the node channel, so its wall-clock duration is the time-to-initial-map the
// client experiences. Without the fix this test's slowest node takes ~10s+ at
// this scale (lock-bound, and more workers do not help); with it, generation
// parallelises across workers and stays well within a client's patience.
func TestInitialMapNotStarvedByReconnectStorm(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-sensitive storm regression; skipped in -short")
	}

	const (
		nodeCount = 300

		// A per-node-filter policy: forces BuildPeerMap and FilterForNode onto
		// the slow path that recompiles filter rules per node, the same shape
		// as a real ACL using autogroup:self / via / relay grants.
		perNodeFilterPolicy = `{"acls":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:*"]}]}`

		// Deliberately roomy so it passes on CI's few-core runners, where the
		// single-writer BuildPeerMap sets the floor (~10s) whatever the reads
		// do. It still trips on a hang or a return to the ~76s serialised
		// behaviour; the fine-grained concurrency is verified separately by
		// TestPolicyManagerConcurrentReads under -race.
		maxAcceptableLatency = 30 * time.Second
	)

	// Use the real available parallelism, as production does.
	workers := runtime.NumCPU()

	td, cleanup := setupStormBatcher(t, nodeCount, workers, perNodeFilterPolicy)
	defer cleanup()

	latencies := make([]time.Duration, nodeCount)

	var wg sync.WaitGroup

	for i := range td.Nodes {
		wg.Go(func() {
			n := &td.Nodes[i]

			start := time.Now()
			err := td.Batcher.AddNode(n.n.ID, n.ch, tailcfg.CapabilityVersion(100), nil)
			latencies[i] = time.Since(start)

			assert.NoError(t, err) //nolint:testifylint // assert (not require) is correct off the test goroutine
		})
	}

	wg.Wait()

	slices.Sort(latencies)
	p50 := latencies[len(latencies)/2]
	p95 := latencies[len(latencies)*95/100]
	maxLatency := latencies[len(latencies)-1]
	t.Logf("initial-map latency over %d nodes (workers=%d): p50=%s p95=%s max=%s",
		nodeCount, workers, p50, p95, maxLatency)

	require.Less(t, maxLatency, maxAcceptableLatency,
		"slowest initial map took %s: policy reads are serialising instead of running concurrently (issue #3346)", maxLatency)
}
