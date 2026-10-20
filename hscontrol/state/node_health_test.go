package state

import (
	"context"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
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
		refreshNeeded := s.BatchSetNodeHealth(map[types.NodeID]bool{nodeID: true})
		require.False(t, refreshNeeded,
			"unchanged health write must not request a refresh")
		require.Same(t, initialSnapshot, s.nodeStore.data.Load(),
			"unchanged health write must not publish a new snapshot")
	}
}

func TestBatchSetNodeHealthRejectedOrMissingDoesNotRefresh(t *testing.T) {
	s := mapViewTestState(t, "")
	s.nodeStore.UpdateNode(2, func(n *types.Node) { n.IsOnline = new(false) })

	for _, updates := range []map[types.NodeID]bool{
		{999: false},
		{999: true},
		{2: false},
		{3: false},
	} {
		for range 2 {
			require.False(t, s.BatchSetNodeHealth(updates),
				"missing nodes and rejected unhealthy marks must not request refresh")
		}
	}

	require.True(t, s.IsNodeHealthy(2), "offline nodes reject unhealthy marks")
	require.True(t, s.IsNodeHealthy(3), "nodes without approved routes reject unhealthy marks")
}

func TestBatchSetNodeHealthNonViaRefreshOnlyOnPrimaryChange(t *testing.T) {
	s := mapViewTestState(t, `{
		"tagOwners":{"tag:via":["user1@"]},
		"grants":[{"src":["user1@"],"dst":["10.107.0.0/24"],"via":["tag:via"],"ip":["tcp:443"]}]
	}`)
	route := netip.MustParsePrefix("10.107.0.0/24")

	for _, id := range []types.NodeID{2, 3} {
		s.nodeStore.UpdateNode(id, func(n *types.Node) {
			n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
			n.ApprovedRoutes = []netip.Prefix{route}
		})
	}

	for _, step := range []struct {
		id      types.NodeID
		healthy bool
		refresh bool
		primary types.NodeID
	}{
		{3, false, false, 2},
		{3, true, false, 2},
		{2, false, true, 3},
		{2, true, false, 3},
	} {
		require.Equal(t, step.refresh, s.BatchSetNodeHealth(map[types.NodeID]bool{step.id: step.healthy}))
		require.Equal(t, step.healthy, s.IsNodeHealthy(step.id))
		require.Equal(t, step.primary, s.nodeStore.PrimaryRoutes()[route])
	}
}

func TestBatchSetNodeHealthUsesSerializedViaTarget(t *testing.T) {
	for _, tt := range []struct {
		name         string
		policyChange bool
		sameBatch    bool
	}{
		{"tag_published_before_health", false, false},
		{"policy_published_before_health", true, false},
		{"tag_changed_in_same_batch", false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			s := mapViewTestState(t, "")
			wait := func(done <-chan struct{}, operation string) {
				t.Helper()

				select {
				case <-done:
				case <-ctx.Done():
					t.Fatalf("waiting for %s: %v", operation, ctx.Err())
				}
			}
			receiveWork := func() work {
				t.Helper()

				select {
				case pending := <-s.nodeStore.writeQueue:
					return pending
				case <-ctx.Done():
					t.Fatalf("receiving queued writer work: %v", ctx.Err())
					return work{}
				}
			}
			queueWork := func(pending work) {
				t.Helper()

				select {
				case s.nodeStore.writeQueue <- pending:
				case <-ctx.Done():
					t.Fatalf("queueing writer work: %v", ctx.Err())
				}
			}

			fourth := createTestNode(4, 1, "user1", "noded")
			fourth.User.ID = 1
			fourth.IPv4 = new(netip.MustParseAddr("100.64.0.4"))
			fourth.IsOnline = new(true)
			s.nodeStore.PutNode(fourth)

			route := netip.MustParsePrefix("10.109.0.0/24")

			for _, id := range []types.NodeID{2, 3, 4} {
				s.nodeStore.UpdateNode(id, func(n *types.Node) {
					n.IPv6 = nil
					n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}

					n.ApprovedRoutes = []netip.Prefix{route}
					if id != 2 {
						n.Tags = []string{"tag:candidate"}
						n.UserID = nil

						n.User = nil
						if id == 4 {
							n.Tags = append(n.Tags, "tag:via")
						}
					}
				})
			}

			const initialPolicy = `{
				"tagOwners":{"tag:via":["user1@"],"tag:candidate":["user1@"]},
				"grants":[{"src":["user1@"],"dst":["10.109.0.0/24"],
					"via":["tag:via"],"ip":["tcp:443"]}]
			}`

			_, err := s.SetPolicy([]byte(initialPolicy))
			require.NoError(t, err)
			initial, err := s.MapView(1)
			require.NoError(t, err)

			checkOwner := func(view MapView, want types.NodeID) {
				t.Helper()

				var owners []types.NodeID

				for _, peer := range view.Peers().All() {
					addresses, err := view.NodeAddresses(peer.ID())
					require.NoError(t, err)

					hasRoute := slices.Contains(addresses.PrimaryRoutes, route)
					require.Equal(t, hasRoute, slices.Contains(addresses.AllowedIPs, route))

					if hasRoute {
						owners = append(owners, peer.ID())
					}
				}

				require.Equal(t, []types.NodeID{want}, owners)
			}
			checkOwner(initial, 4)
			require.Equal(t, types.NodeID(2), s.nodeStore.PrimaryRoutes()[route])

			if tt.sameBatch {
				var nodes types.Nodes
				for _, node := range s.nodeStore.ListNodes().All() {
					nodes = append(nodes, node.AsStruct())
				}

				s.nodeStore.Stop()
				s.nodeStore = NewNodeStore(nodes, policyPeersFunc(s.polMan), 2, time.Hour)
				s.nodeStore.Start()
				t.Cleanup(s.nodeStore.Stop)

				promotion := work{
					op: updateMulti,
					multiUpdates: map[types.NodeID]UpdateNodeFunc{
						3: func(n *types.Node) { n.Tags = []string{"tag:via"} },
					},
					result: make(chan struct{}),
				}
				queueWork(promotion)

				var refresh bool

				healthDone := make(chan struct{})
				go func() {
					defer close(healthDone)

					refresh = s.BatchSetNodeHealth(map[types.NodeID]bool{3: false})
				}()

				wait(healthDone, "same-batch health update")
				wait(promotion.result, "same-batch tag promotion")

				fresh, err := s.MapView(1)
				require.NoError(t, err)
				require.False(t, s.nodeStore.policyRecovered.Load())
				require.True(t, refresh, "health must see tags changed earlier in its writer batch")
				require.True(t, fresh.snapshot.nodeViewsByID[3].HasTag("tag:via"))
				require.False(t, s.IsNodeHealthy(3))
				require.Equal(t, types.NodeID(2), s.nodeStore.PrimaryRoutes()[route])
				checkOwner(fresh, 4)
				checkOwner(initial, 4)

				return
			}

			entered, release, blockerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})

			var heldHealth, heldPolicy *work

			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}

				defer s.nodeStore.Stop()

				cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Second)
				defer cleanupCancel()

				for _, pending := range []*work{heldPolicy, heldHealth} {
					if pending != nil {
						select {
						case s.nodeStore.writeQueue <- *pending:
						case <-cleanupCtx.Done():
							t.Errorf("restoring intercepted writer work: %v", cleanupCtx.Err())
						}
					}
				}
			}()

			go func() {
				s.nodeStore.UpdateNode(3, func(n *types.Node) {
					close(entered)

					select {
					case <-release:
					case <-ctx.Done():
					}

					if !tt.policyChange {
						n.Tags = []string{"tag:via"}
					}
				})
				close(blockerDone)
			}()

			wait(entered, "writer callback")

			var refresh bool

			healthDone := make(chan struct{})
			go func() {
				defer close(healthDone)

				refresh = s.BatchSetNodeHealth(map[types.NodeID]bool{3: false})
			}()
			// Receiving the queued work proves health captured the old snapshot.
			healthWork := receiveWork()
			heldHealth = &healthWork

			var (
				policyErr                   error
				policyChanged, policyQueued bool
				policyWork                  work
			)

			policyDone := make(chan struct{})

			if tt.policyChange {
				go func() {
					policyChanged, policyErr = s.SetPolicy([]byte(`{
						"tagOwners":{"tag:via":["user1@"],"tag:candidate":["user1@"]},
						"grants":[{"src":["user1@"],"dst":["10.109.0.0/24"],
							"via":["tag:candidate"],"ip":["tcp:443"]}]
					}`))

					close(policyDone)
				}()

				select {
				case policyWork = <-s.nodeStore.writeQueue:
					policyQueued = true
					heldPolicy = &policyWork
				case <-policyDone:
				case <-ctx.Done():
					t.Fatalf("waiting for policy rebuild: %v", ctx.Err())
				}
			}

			close(release)
			wait(blockerDone, "preceding writer update")

			beforeRebuild, beforeRebuildErr := s.MapView(1)

			if tt.policyChange {
				if policyQueued {
					queueWork(policyWork)

					heldPolicy = nil
				}

				wait(policyDone, "policy publication")
			}

			promoted, promotedErr := s.MapView(1)

			queueWork(healthWork)

			heldHealth = nil

			wait(healthDone, "health publication")

			fresh, freshErr := s.MapView(1)

			require.NoError(t, promotedErr)
			require.NoError(t, freshErr)

			if tt.policyChange {
				require.NoError(t, policyErr)
				require.True(t, policyChanged)
				require.True(t, policyQueued)
				require.NoError(t, beforeRebuildErr)
				checkOwner(beforeRebuild, 4)
			}

			require.False(t, s.nodeStore.policyRecovered.Load())
			require.True(t, refresh, "published via-target promotion must refresh after a health flip")
			require.False(t, s.IsNodeHealthy(3))
			require.Equal(t, types.NodeID(2), s.nodeStore.PrimaryRoutes()[route])
			checkOwner(promoted, 3)
			checkOwner(fresh, 4)
			checkOwner(initial, 4)
		})
	}
}

func TestHAHealthProbeInvalidPolicyKeepsRoutersHealthy(t *testing.T) {
	for _, tt := range []struct {
		name           string
		invalidAtEntry bool
		recoverPolicy  bool
	}{
		{"invalid_at_entry", true, false},
		{"recovery_at_entry", true, true},
		{"recovery_after_probes", false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := mapViewTestState(t, "")
			s.pings = newPingTracker()
			route := netip.MustParsePrefix("10.108.0.0/24")

			for _, id := range []types.NodeID{2, 3} {
				s.nodeStore.UpdateNode(id, func(n *types.Node) {
					n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
					n.ApprovedRoutes = []netip.Prefix{route}
				})
			}

			// Zero timeout and stable sessions exercise real timeout results without sleeps.
			prober := NewHAHealthProber(s, types.HARouteConfig{}, "https://example.test",
				func(types.NodeID) bool { return true })
			for _, id := range []types.NodeID{2, 3} {
				node, ok := s.GetNodeByID(id)
				require.True(t, ok)
				prober.markSessionStable(id, node.SessionEpoch())
			}

			inner := s.nodeStore.peersFunc

			var (
				fail   atomic.Bool
				builds atomic.Int32
			)

			s.nodeStore.peersFunc = func(nodes []types.NodeView) (policy.ReadView, map[types.NodeID][]types.NodeID, error) {
				builds.Add(1)

				if fail.Load() {
					return policy.ReadView{}, nil, errMapViewPolicyBuild
				}

				return inner(nodes)
			}

			invalidate := func() {
				fail.Store(true)
				s.nodeStore.UpdateNode(1, func(n *types.Node) {
					n.GivenName = "withheld"
					n.IPv4 = new(netip.MustParseAddr("100.64.0.99"))
				})
				_, err := s.MapView(1)
				require.ErrorIs(t, err, errMapViewPolicyBuild)
				fail.Store(!tt.recoverPolicy)
			}
			if tt.invalidAtEntry {
				invalidate()
			}

			var pings, policyDispatches int

			prober.ProbeOnce(t.Context(), func(cs ...change.Change) {
				for _, c := range cs {
					if c.PingRequest != nil {
						pings++
						if pings == 1 && !tt.invalidAtEntry {
							invalidate()
						}
					}

					if c.IsBroadcastPolicyChange() {
						policyDispatches++
					}
				}
			})

			require.EqualValues(t, 2, builds.Load(), "one failed publication and one retry")

			if tt.invalidAtEntry {
				require.Zero(t, pings, "invalid maps must not receive probes")
			} else {
				require.Equal(t, 2, pings)
			}

			require.Empty(t, s.pings.pending)
			require.True(t, s.IsNodeHealthy(2), "map failures must not mark routers unhealthy")
			require.True(t, s.IsNodeHealthy(3), "map failures must not mark routers unhealthy")
			require.Equal(t, types.NodeID(2), s.nodeStore.PrimaryRoutes()[route])

			view, err := s.MapView(1)
			if tt.recoverPolicy {
				require.NoError(t, err)
				require.Equal(t, "withheld", view.Viewer().GivenName())
				require.Equal(t, 1, policyDispatches)
				require.Equal(t, []change.Change{change.FullUpdate()}, s.DrainSelfRefreshes())
				require.False(t, s.BatchSetNodeHealth(nil), "consumed recovery must not dispatch again")
			} else {
				require.ErrorIs(t, err, errMapViewPolicyBuild)
				require.Zero(t, policyDispatches)
			}
		})
	}
}
