package state

import (
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/opt"
)

func TestNetInfoFromMapRequest(t *testing.T) {
	nodeID := types.NodeID(1)

	tests := []struct {
		name            string
		currentHostinfo *tailcfg.Hostinfo
		reqHostinfo     *tailcfg.Hostinfo
		expectNetInfo   *tailcfg.NetInfo
	}{
		{
			name:            "no current NetInfo - return nil",
			currentHostinfo: nil,
			reqHostinfo: &tailcfg.Hostinfo{
				Hostname: "test-node",
			},
			expectNetInfo: nil,
		},
		{
			name: "current has NetInfo, request has NetInfo - use request",
			currentHostinfo: &tailcfg.Hostinfo{
				NetInfo: &tailcfg.NetInfo{PreferredDERP: 1},
			},
			reqHostinfo: &tailcfg.Hostinfo{
				Hostname: "test-node",
				NetInfo:  &tailcfg.NetInfo{PreferredDERP: 2},
			},
			expectNetInfo: &tailcfg.NetInfo{PreferredDERP: 2},
		},
		{
			name: "current has NetInfo, request has no NetInfo - use current",
			currentHostinfo: &tailcfg.Hostinfo{
				NetInfo: &tailcfg.NetInfo{PreferredDERP: 3},
			},
			reqHostinfo: &tailcfg.Hostinfo{
				Hostname: "test-node",
			},
			expectNetInfo: &tailcfg.NetInfo{PreferredDERP: 3},
		},
		{
			name: "current has NetInfo, no request Hostinfo - use current",
			currentHostinfo: &tailcfg.Hostinfo{
				NetInfo: &tailcfg.NetInfo{PreferredDERP: 4},
			},
			reqHostinfo:   nil,
			expectNetInfo: &tailcfg.NetInfo{PreferredDERP: 4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := netInfoFromMapRequest(nodeID, tt.currentHostinfo, tt.reqHostinfo)

			if tt.expectNetInfo == nil {
				assert.Nil(t, result, "expected nil NetInfo")
			} else {
				require.NotNil(t, result, "expected non-nil NetInfo")
				assert.Equal(t, tt.expectNetInfo.PreferredDERP, result.PreferredDERP, "DERP mismatch")
			}
		})
	}
}

func TestNetInfoPreservationInRegistrationFlow(t *testing.T) {
	nodeID := types.NodeID(1)

	// This test reproduces the bug in registration flows where NetInfo was lost
	// because we used the wrong hostinfo reference when calling [netInfoFromMapRequest]
	t.Run("registration_flow_bug_reproduction", func(t *testing.T) {
		// Simulate existing node with NetInfo (before re-registration)
		existingNodeHostinfo := &tailcfg.Hostinfo{
			Hostname: "test-node",
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 5},
		}

		// Simulate new registration request (no NetInfo)
		newRegistrationHostinfo := &tailcfg.Hostinfo{
			Hostname: "test-node",
			OS:       "linux",
			// NetInfo is nil - this is what comes from the registration request
		}

		// Simulate what was happening in the bug: we passed the "current node being modified"
		// hostinfo (which has no NetInfo) instead of the existing node's hostinfo
		nodeBeingModifiedHostinfo := &tailcfg.Hostinfo{
			Hostname: "test-node",
			// NetInfo is nil because this node is being modified/reset
		}

		// BUG: Using the node being modified (no NetInfo) instead of existing node (has NetInfo)
		buggyResult := netInfoFromMapRequest(nodeID, nodeBeingModifiedHostinfo, newRegistrationHostinfo)
		assert.Nil(t, buggyResult, "Bug: Should return nil when using wrong hostinfo reference")

		// CORRECT: Using the existing node's hostinfo (has NetInfo)
		correctResult := netInfoFromMapRequest(nodeID, existingNodeHostinfo, newRegistrationHostinfo)
		assert.NotNil(t, correctResult, "Fix: Should preserve NetInfo when using correct hostinfo reference")
		assert.Equal(t, tailcfg.DERPRegionID(5), correctResult.PreferredDERP, "Should preserve the DERP region from existing node")
	})

	t.Run("new_node_creation_for_different_user_should_preserve_netinfo", func(t *testing.T) {
		// This test covers the scenario where:
		// 1. A node exists for user1 with NetInfo
		// 2. The same machine logs in as user2 (different user)
		// 3. A NEW node is created for user2 (pre-auth key flow)
		// 4. The new node should preserve NetInfo from the old node

		// Existing node for user1 with NetInfo
		existingNodeUser1Hostinfo := &tailcfg.Hostinfo{
			Hostname: "test-node",
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 7},
		}

		// New registration request for user2 (no NetInfo yet)
		newNodeUser2Hostinfo := &tailcfg.Hostinfo{
			Hostname: "test-node",
			OS:       "linux",
			// NetInfo is nil - registration request doesn't include it
		}

		// When creating a new node for user2, we should preserve NetInfo from user1's node
		result := netInfoFromMapRequest(types.NodeID(2), existingNodeUser1Hostinfo, newNodeUser2Hostinfo)
		assert.NotNil(t, result, "New node for user2 should preserve NetInfo from user1's node")
		assert.Equal(t, tailcfg.DERPRegionID(7), result.PreferredDERP, "Should preserve DERP region from existing node")
	})
}

// TestNoOpMapRequestSkipsPersist ensures an identical, no-op MapRequest does
// not issue a database UPDATE (nor the O(n) policy SetNodes scan that follows
// persistNodeAndRefreshPolicy). The node state is unchanged, so persisting is pure waste on
// the hot map-request path.
func TestNoOpMapRequestSkipsPersist(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	var nodeUpdateCount atomic.Int64

	gdb := s.DB().DB
	cbName := "noop_count_node_updates"
	err := gdb.Callback().Update().After("gorm:update").Register(cbName, func(tx *gorm.DB) {
		if tx.Statement == nil {
			return
		}

		if tx.Statement.Table == "nodes" ||
			strings.Contains(strings.ToLower(tx.Statement.SQL.String()), "update \"nodes\"") {
			nodeUpdateCount.Add(1)
		}
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = gdb.Callback().Update().Remove(cbName) })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok, "node should exist in NodeStore")

	stored := nv.AsStruct()

	req := tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
		},
	}

	// First request establishes the Hostinfo/DERP state (expected to persist).
	_, err = s.UpdateNodeFromMapRequest(nodeID, req)
	require.NoError(t, err)

	nodeUpdateCount.Store(0)

	// Second request is value-identical: a no-op.
	req2 := tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
		},
	}

	_, err = s.UpdateNodeFromMapRequest(nodeID, req2)
	require.NoError(t, err)

	require.Equalf(t, int64(0), nodeUpdateCount.Load(),
		"no-op MapRequest should not issue any nodes-table UPDATE, got %d",
		nodeUpdateCount.Load())
}

// TestNoOpMapRequestEmitsNoPeerChange ensures an identical, no-op MapRequest
// does not emit a peer-visible change.
func TestNoOpMapRequestEmitsNoPeerChange(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok, "node should exist in NodeStore")

	stored := nv.AsStruct()

	req := func() tailcfg.MapRequest {
		return tailcfg.MapRequest{
			NodeKey:  stored.NodeKey,
			DiscoKey: stored.DiscoKey,
			Hostinfo: &tailcfg.Hostinfo{
				Hostname: stored.Hostname,
				NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
			},
		}
	}

	// First request establishes the Hostinfo/DERP state.
	_, err := s.UpdateNodeFromMapRequest(nodeID, req())
	require.NoError(t, err)

	beforeSeen := mustLastSeen(t, s, nodeID)

	// Second request is value-identical: a no-op.
	c, err := s.UpdateNodeFromMapRequest(nodeID, req())
	require.NoError(t, err)

	require.Truef(t, c.IsEmpty(),
		"no-op MapRequest must not emit a change, got reason=%q type=%q peersChanged=%v",
		c.Reason, c.Type(), c.PeersChanged)

	require.True(t, mustLastSeen(t, s, nodeID).After(beforeSeen),
		"no-op request must still stamp LastSeen in the NodeStore")
}

// TestSTUNOnlyEndpointUpdateEmitsNoPeerChange ensures endpoint churn that
// endpointBroadcastWorthy suppresses stays suppressed instead of escalating
// to a whole-peer change.
func TestSTUNOnlyEndpointUpdateEmitsNoPeerChange(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok, "node should exist in NodeStore")

	stored := nv.AsStruct()

	hi := func() *tailcfg.Hostinfo {
		return &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
		}
	}

	local := netip.MustParseAddrPort("192.168.1.5:41641")

	// First request establishes the Hostinfo/DERP state and a useful
	// endpoint, so the delta below is churn on a set peers already hold
	// rather than the node's first endpoints.
	_, err := s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:       stored.NodeKey,
		DiscoKey:      stored.DiscoKey,
		Hostinfo:      hi(),
		Endpoints:     []netip.AddrPort{local},
		EndpointTypes: []tailcfg.EndpointType{tailcfg.EndpointLocal},
	})
	require.NoError(t, err)

	// Second request adds a single STUN-derived endpoint and nothing else.
	c, err := s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:       stored.NodeKey,
		DiscoKey:      stored.DiscoKey,
		Hostinfo:      hi(),
		Endpoints:     []netip.AddrPort{local, netip.MustParseAddrPort("198.51.100.7:41641")},
		EndpointTypes: []tailcfg.EndpointType{tailcfg.EndpointLocal, tailcfg.EndpointSTUN},
	})
	require.NoError(t, err)

	require.Truef(t, c.IsEmpty(),
		"suppressed STUN-only endpoint delta must not emit a change, got reason=%q type=%q peersChanged=%v",
		c.Reason, c.Type(), c.PeersChanged)

	after, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.Contains(t, after.Endpoints().AsSlice(), netip.MustParseAddrPort("198.51.100.7:41641"),
		"suppressed endpoint must still be stored")
}

// TestFirstEndpointsReachPeersEvenWhenSTUNOnly pins that the first endpoint
// set a node announces is always broadcast. Peers hold no endpoints for it
// yet, and a suppressed delta is never resent, so suppressing the first set
// leaves peers with no direct path for the life of the node.
func TestFirstEndpointsReachPeersEvenWhenSTUNOnly(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok, "node should exist in NodeStore")
	require.Empty(t, nv.Endpoints().AsSlice(), "precondition: node starts with no endpoints")

	stored := nv.AsStruct()
	stun := netip.MustParseAddrPort("198.51.100.7:41641")

	c, err := s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:       stored.NodeKey,
		DiscoKey:      stored.DiscoKey,
		Endpoints:     []netip.AddrPort{stun},
		EndpointTypes: []tailcfg.EndpointType{tailcfg.EndpointSTUN},
	})
	require.NoError(t, err)

	require.Falsef(t, c.IsEmpty(),
		"a node's first endpoints must reach peers, got reason=%q type=%q", c.Reason, c.Type())
	require.Len(t, c.PeerPatches, 1, "expected a single endpoint patch")
	require.Contains(t, c.PeerPatches[0].Endpoints, stun,
		"the patch must carry the announced endpoint")
}

// TestMapRequestDERPLatencyJitterEmitsNoPeerChange pins the wiring between
// [State.UpdateNodeFromMapRequest] and the Hostinfo comparison: DERP latency
// is transport diagnostics that no peer reads, so jitter must not reach the
// classifier as a change. hostinfoEqual covers the comparison itself; this
// covers the path.
func TestMapRequestDERPLatencyJitterEmitsNoPeerChange(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok, "node should exist in NodeStore")

	stored := nv.AsStruct()

	hi := func(latency float64) *tailcfg.Hostinfo {
		return &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			NetInfo: &tailcfg.NetInfo{
				PreferredDERP: 1,
				DERPLatency:   map[string]float64{"1-v4": latency},
			},
		}
	}

	// Establish the Hostinfo, DERP region and a first latency sample.
	_, err := s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: hi(0.010),
	})
	require.NoError(t, err)

	// Only the latency sample moves.
	c, err := s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: hi(0.025),
	})
	require.NoError(t, err)

	require.Truef(t, c.IsEmpty(),
		"DERP latency jitter must not emit a change, got reason=%q type=%q peersChanged=%v",
		c.Reason, c.Type(), c.PeersChanged)

	after, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.Equal(t, 1, int(after.Hostinfo().NetInfo().PreferredDERP()),
		"the DERP region must survive a latency-only request")
}

// TestMapRequestOmittedNetInfoIsNoChange pins that a MapRequest carrying
// Hostinfo with NetInfo omitted is compared against the preserved NetInfo, not
// against the bare request. Tailscale clients send NetInfo only when it
// changed, so classifying the omission as a Hostinfo change turns
// every routine map request into a database write, an O(n) policy rescan and a
// whole-peer broadcast.
func TestMapRequestOmittedNetInfoIsNoChange(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	var nodeUpdateCount atomic.Int64

	gdb := s.DB().DB
	cbName := "omitted_netinfo_count_node_updates"
	err := gdb.Callback().Update().After("gorm:update").Register(cbName, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "nodes" {
			nodeUpdateCount.Add(1)
		}
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = gdb.Callback().Update().Remove(cbName) })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	stored := nv.AsStruct()

	// Establish Hostinfo with NetInfo.
	_, err = s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			OS:       "linux",
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
		},
	})
	require.NoError(t, err)
	require.Positive(t, nodeUpdateCount.Load(), "first request must persist")

	nodeUpdateCount.Store(0)

	// Same Hostinfo, NetInfo omitted: the client is saying "unchanged".
	c, err := s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			OS:       "linux",
		},
	})
	require.NoError(t, err)

	require.True(t, c.IsEmpty(), "omitted NetInfo must not broadcast, got %+v", c)
	require.Equalf(t, int64(0), nodeUpdateCount.Load(),
		"omitted NetInfo must not persist, got %d updates", nodeUpdateCount.Load())

	after, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.Equal(t, tailcfg.DERPRegionID(1), hostinfoDERP(after.AsStruct().Hostinfo),
		"stored NetInfo must survive a request that omits it")
}

// TestMapRequestDERPClearToZeroIsStoredAndBroadcast pins that a node reporting
// PreferredDERP 0 has its home region cleared. tailcfg.PeerChange.DERPRegion
// zero means "unchanged" on the wire, so the clear cannot ride a patch and has
// to escalate to a whole-peer update.
func TestMapRequestDERPClearToZeroIsStoredAndBroadcast(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	var nodeUpdateCount atomic.Int64

	gdb := s.DB().DB
	cbName := "derp_clear_count_node_updates"
	err := gdb.Callback().Update().After("gorm:update").Register(cbName, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "nodes" {
			nodeUpdateCount.Add(1)
		}
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = gdb.Callback().Update().Remove(cbName) })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	stored := nv.AsStruct()

	_, err = s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
		},
	})
	require.NoError(t, err)

	nodeUpdateCount.Store(0)

	c, err := s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 0},
		},
	})
	require.NoError(t, err)

	after, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.Equal(t, tailcfg.DERPRegionID(0), hostinfoDERP(after.AsStruct().Hostinfo),
		"clearing PreferredDERP must be stored")

	require.Contains(t, c.PeersChanged, nodeID,
		"clearing PreferredDERP cannot be a patch, got %+v", c)
	require.Empty(t, c.PeerPatches,
		"clearing PreferredDERP must not emit a DERP patch, got %+v", c)
	require.Positive(t, nodeUpdateCount.Load(), "clearing PreferredDERP must be persisted")
}

// TestMapRequestDERPOnlyChangeKeepsGivenName pins that a request changing only
// PreferredDERP does not re-derive GivenName. Peers only receive a DERP patch
// for such a request, so a rename here would never reach them.
func TestMapRequestDERPOnlyChangeKeepsGivenName(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	stored := nv.AsStruct()

	req := func(derp tailcfg.DERPRegionID) tailcfg.MapRequest {
		return tailcfg.MapRequest{
			NodeKey:  stored.NodeKey,
			DiscoKey: stored.DiscoKey,
			Hostinfo: &tailcfg.Hostinfo{
				Hostname: stored.Hostname,
				NetInfo:  &tailcfg.NetInfo{PreferredDERP: derp},
			},
		}
	}

	_, err := s.UpdateNodeFromMapRequest(nodeID, req(1))
	require.NoError(t, err)

	// A collision-bumped name whose base is free again is exactly what the
	// auto-derive path rewrites.
	bumped := stored.Hostname + "-1"
	_, ok = s.nodeStore.UpdateNode(nodeID, func(n *types.Node) { n.GivenName = bumped })
	require.True(t, ok)

	c, err := s.UpdateNodeFromMapRequest(nodeID, req(2))
	require.NoError(t, err)
	require.NotEmpty(t, c.PeerPatches, "DERP-only change must be a patch, got %+v", c)

	after, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.Equal(t, bumped, after.GivenName(), "DERP-only change must not touch GivenName")
}

func TestConcurrentMapRequestDERPUsesPersistedState(t *testing.T) {
	for _, rotateKey := range []bool{false, true} {
		for _, tt := range []struct {
			name                string
			firstDERP, lastDERP tailcfg.DERPRegionID
		}{
			{name: "newer region", firstDERP: 2, lastDERP: 3},
			{name: "newer clear", firstDERP: 2, lastDERP: 0},
			{name: "superseded clear", firstDERP: 0, lastDERP: 3},
		} {
			name := tt.name
			if rotateKey {
				name += " with key rotation"
			}

			t.Run(name, func(t *testing.T) {
				_, s, nodeID := persistTestSetup(t)
				t.Cleanup(func() { _ = s.Close() })

				nv, ok := s.GetNodeByID(nodeID)
				require.True(t, ok)

				req := tailcfg.MapRequest{
					NodeKey:  nv.NodeKey(),
					DiscoKey: nv.DiscoKey(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: nv.Hostname(),
						NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
					},
				}
				_, err := s.UpdateNodeFromMapRequest(nodeID, req)
				require.NoError(t, err)

				if rotateKey {
					req.NodeKey = key.NewNode().Public()
					req.DiscoKey = key.NewDisco().Public()
				}

				// Let both requests publish their NodeStore writes before
				// either can persist. Both must then use the last region,
				// regardless of which response reaches peers first.
				s.persistMu.Lock()
				unlockPersist := sync.OnceFunc(s.persistMu.Unlock)

				var wg sync.WaitGroup

				t.Cleanup(func() {
					unlockPersist()
					wg.Wait()
				})

				type result struct {
					change change.Change
					err    error
				}

				results := make(chan result, 2)

				for _, derp := range []tailcfg.DERPRegionID{tt.firstDERP, tt.lastDERP} {
					request := req
					request.Hostinfo = req.Hostinfo.Clone()
					request.Hostinfo.NetInfo.PreferredDERP = derp

					wg.Go(func() {
						c, err := s.UpdateNodeFromMapRequest(nodeID, request)
						results <- result{change: c, err: err}
					})

					require.EventuallyWithT(t, func(c *assert.CollectT) {
						stored, exists := s.GetNodeByID(nodeID)
						require.True(c, exists)
						require.Equal(c, derp, stored.Hostinfo().NetInfo().PreferredDERP())
					}, 5*time.Second, time.Millisecond, "request must update NodeStore before persisting")
				}

				unlockPersist()
				wg.Wait()
				close(results)

				for result := range results {
					require.NoError(t, result.err)

					if tt.lastDERP == 0 {
						require.Contains(t, result.change.PeersChanged, nodeID,
							"the current region is zero, so neither response can use a DERP patch")
						require.Empty(t, result.change.PeerPatches)

						continue
					}

					require.Empty(t, result.change.PeersChanged)
					require.Len(t, result.change.PeerPatches, 1)
					require.Equal(t, tt.lastDERP, result.change.PeerPatches[0].DERPRegion,
						"neither response may restore a superseded DERP region")
				}

				persisted, err := s.DB().GetNodeByID(nodeID)
				require.NoError(t, err)
				require.Equal(t, tt.lastDERP, persisted.Hostinfo.NetInfo.PreferredDERP)

				// A resend is still a no-op; correct delivery cannot depend
				// on a future identical request repairing the peer's state.
				req.Hostinfo = req.Hostinfo.Clone()
				req.Hostinfo.NetInfo.PreferredDERP = tt.lastDERP
				c, err := s.UpdateNodeFromMapRequest(nodeID, req)
				require.NoError(t, err)
				require.True(t, c.IsEmpty())
			})
		}
	}
}

// TestMapRequestPeerInvisibleHostinfoChangeIsStoredNotBroadcast pins that
// a Hostinfo field no peer reads is stored and persisted but does not
// resend the whole node to every peer.
func TestMapRequestPeerInvisibleHostinfoChangeIsStoredNotBroadcast(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	var nodeUpdateCount atomic.Int64

	gdb := s.DB().DB
	cbName := "peer_invisible_count_node_updates"
	err := gdb.Callback().Update().After("gorm:update").Register(cbName, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "nodes" {
			nodeUpdateCount.Add(1)
		}
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = gdb.Callback().Update().Remove(cbName) })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	stored := nv.AsStruct()

	req := func(model string) tailcfg.MapRequest {
		return tailcfg.MapRequest{
			NodeKey:  stored.NodeKey,
			DiscoKey: stored.DiscoKey,
			Hostinfo: &tailcfg.Hostinfo{
				Hostname:    stored.Hostname,
				OS:          "linux",
				DeviceModel: model,
				NetInfo:     &tailcfg.NetInfo{PreferredDERP: 1},
			},
		}
	}

	_, err = s.UpdateNodeFromMapRequest(nodeID, req("a"))
	require.NoError(t, err)

	nodeUpdateCount.Store(0)

	c, err := s.UpdateNodeFromMapRequest(nodeID, req("b"))
	require.NoError(t, err)
	require.True(t, c.IsEmpty(), "peers read no DeviceModel, got %+v", c)
	require.Positive(t, nodeUpdateCount.Load(), "the new DeviceModel must be persisted")

	after, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.Equal(t, "b", after.Hostinfo().DeviceModel(), "the new DeviceModel must be stored")
}

// TestMapRequestPeerVisibleHostinfoChangeIsBroadcast pins that a Hostinfo
// field peers read still resends the whole node.
func TestMapRequestPeerVisibleHostinfoChangeIsBroadcast(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	stored := nv.AsStruct()

	req := func(os string) tailcfg.MapRequest {
		return tailcfg.MapRequest{
			NodeKey:  stored.NodeKey,
			DiscoKey: stored.DiscoKey,
			Hostinfo: &tailcfg.Hostinfo{
				Hostname: stored.Hostname,
				OS:       os,
				NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
			},
		}
	}

	_, err := s.UpdateNodeFromMapRequest(nodeID, req("linux"))
	require.NoError(t, err)

	c, err := s.UpdateNodeFromMapRequest(nodeID, req("windows"))
	require.NoError(t, err)
	require.Contains(t, c.PeersChanged, nodeID, "peers read OS, got %+v", c)
}

func mustLastSeen(t *testing.T, s *State, id types.NodeID) time.Time {
	t.Helper()

	nv, ok := s.GetNodeByID(id)
	require.True(t, ok)

	seen, ok := nv.LastSeen().GetOk()
	require.True(t, ok, "LastSeen must be stamped")

	return seen
}

func TestHostinfoEqual(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		require.True(t, hostinfoEqual(nil, nil))
	})

	t.Run("one nil", func(t *testing.T) {
		require.False(t, hostinfoEqual(&tailcfg.Hostinfo{}, nil))
		require.False(t, hostinfoEqual(nil, &tailcfg.Hostinfo{}))
	})

	t.Run("identical", func(t *testing.T) {
		a := &tailcfg.Hostinfo{Hostname: "node1", OS: "linux"}
		b := &tailcfg.Hostinfo{Hostname: "node1", OS: "linux"}
		require.True(t, hostinfoEqual(a, b))
	})

	t.Run("DERPLatency jitter is not a change", func(t *testing.T) {
		a := &tailcfg.Hostinfo{
			Hostname: "node1",
			NetInfo: &tailcfg.NetInfo{
				PreferredDERP: 1,
				DERPLatency:   map[string]float64{"1-v4": 0.010},
			},
		}
		b := &tailcfg.Hostinfo{
			Hostname: "node1",
			NetInfo: &tailcfg.NetInfo{
				PreferredDERP: 1,
				DERPLatency:   map[string]float64{"1-v4": 0.025}, // jitter
			},
		}
		require.True(t, hostinfoEqual(a, b),
			"DERPLatency jitter must not count as a change")
	})

	t.Run("PreferredDERP change is not a change here", func(t *testing.T) {
		a := &tailcfg.Hostinfo{
			Hostname: "node1",
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
		}
		b := &tailcfg.Hostinfo{
			Hostname: "node1",
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 2},
		}
		require.True(t, hostinfoEqual(a, b),
			"PreferredDERP change is tracked separately")
	})

	t.Run("hostname change", func(t *testing.T) {
		a := &tailcfg.Hostinfo{Hostname: "node1"}
		b := &tailcfg.Hostinfo{Hostname: "node2"}
		require.False(t, hostinfoEqual(a, b))
	})

	t.Run("route change", func(t *testing.T) {
		a := &tailcfg.Hostinfo{Hostname: "node1", RoutableIPs: nil}
		b := &tailcfg.Hostinfo{Hostname: "node1"}
		// RoutableIPs nil vs nil: equal
		require.True(t, hostinfoEqual(a, b))

		// Add a route.
		// (also tracked separately as routesChangedInput)
		b.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
		require.False(t, hostinfoEqual(a, b))
	})
}

func TestPeerHostinfoEqual(t *testing.T) {
	base := func() *tailcfg.Hostinfo {
		return &tailcfg.Hostinfo{
			Hostname:    "node",
			OS:          "linux",
			DeviceModel: "laptop",
			NetInfo:     &tailcfg.NetInfo{PreferredDERP: 1, WorkingUDP: opt.NewBool(true)},
		}
	}

	tests := []struct {
		name   string
		mutate func(*tailcfg.Hostinfo)
		want   bool
	}{
		{name: "no change", mutate: func(*tailcfg.Hostinfo) {}, want: true},
		{name: "device model", mutate: func(hi *tailcfg.Hostinfo) { hi.DeviceModel = "desktop" }, want: true},
		{name: "shields up", mutate: func(hi *tailcfg.Hostinfo) { hi.ShieldsUp = true }, want: true},
		{name: "ipn version", mutate: func(hi *tailcfg.Hostinfo) { hi.IPNVersion = "1.99" }, want: true},
		{name: "netinfo udp", mutate: func(hi *tailcfg.Hostinfo) { hi.NetInfo.WorkingUDP = opt.NewBool(false) }, want: true},
		{name: "netinfo dropped", mutate: func(hi *tailcfg.Hostinfo) { hi.NetInfo = nil }, want: true},
		{name: "hostname", mutate: func(hi *tailcfg.Hostinfo) { hi.Hostname = "other" }, want: false},
		{name: "os", mutate: func(hi *tailcfg.Hostinfo) { hi.OS = "windows" }, want: false},
		{
			name:   "services",
			mutate: func(hi *tailcfg.Hostinfo) { hi.Services = []tailcfg.Service{{Proto: "peerapi4", Port: 1}} },
			want:   false,
		},
		{name: "ssh host keys", mutate: func(hi *tailcfg.Hostinfo) { hi.SSH_HostKeys = []string{"ssh-ed25519 AAAA"} }, want: false},
		{name: "location", mutate: func(hi *tailcfg.Hostinfo) { hi.Location = &tailcfg.Location{Priority: 5} }, want: false},
		{name: "app connector", mutate: func(hi *tailcfg.Hostinfo) { hi.AppConnector = opt.NewBool(true) }, want: false},
		{
			name:   "routes",
			mutate: func(hi *tailcfg.Hostinfo) { hi.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")} },
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := base()
			tt.mutate(changed)
			require.Equal(t, tt.want, peerHostinfoEqual(base(), changed))
		})
	}

	require.True(t, peerHostinfoEqual(nil, nil))
	require.False(t, peerHostinfoEqual(nil, base()))
}

func TestNetInfoEqualIgnoringDERP(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		require.True(t, netInfoEqualIgnoringDERP(nil, nil))
	})

	t.Run("ignores PreferredDERP", func(t *testing.T) {
		a := &tailcfg.NetInfo{PreferredDERP: 1, WorkingUDP: opt.NewBool(true)}
		b := &tailcfg.NetInfo{PreferredDERP: 9, WorkingUDP: opt.NewBool(true)}
		require.True(t, netInfoEqualIgnoringDERP(a, b))
	})

	t.Run("ignores DERPLatency", func(t *testing.T) {
		a := &tailcfg.NetInfo{DERPLatency: map[string]float64{"1": 0.01}}
		b := &tailcfg.NetInfo{DERPLatency: map[string]float64{"1": 0.99}}
		require.True(t, netInfoEqualIgnoringDERP(a, b))
	})

	t.Run("catches WorkingUDP change", func(t *testing.T) {
		a := &tailcfg.NetInfo{WorkingUDP: opt.NewBool(true)}
		b := &tailcfg.NetInfo{WorkingUDP: opt.NewBool(false)}
		require.False(t, netInfoEqualIgnoringDERP(a, b))
	})
}

func TestHostinfoDERP(t *testing.T) {
	require.Equal(t, tailcfg.DERPRegionID(0), hostinfoDERP(nil))
	require.Equal(t, tailcfg.DERPRegionID(0), hostinfoDERP(&tailcfg.Hostinfo{}))
	require.Equal(t, tailcfg.DERPRegionID(0), hostinfoDERP(&tailcfg.Hostinfo{NetInfo: &tailcfg.NetInfo{}}))
	require.Equal(t, tailcfg.DERPRegionID(5), hostinfoDERP(&tailcfg.Hostinfo{NetInfo: &tailcfg.NetInfo{PreferredDERP: 5}}))
}

func TestBuildMapRequestChangeResponse(t *testing.T) {
	node := types.Node{
		ID:        1,
		NodeKey:   key.NewNode().Public(),
		DiscoKey:  key.NewDisco().Public(),
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:41641")},
		Hostinfo:  &tailcfg.Hostinfo{NetInfo: &tailcfg.NetInfo{PreferredDERP: 2}},
	}
	tests := []struct {
		name     string
		delta    mapRequestDelta
		nodeDERP tailcfg.DERPRegionID

		wantEmpty     bool
		wantWholePeer bool
		wantKeys      bool
		wantEndpoints bool
		wantDERP      tailcfg.DERPRegionID
	}{
		{
			name:  "nothing peer visible",
			delta: mapRequestDelta{},

			wantEmpty: true,
		},
		{
			name:  "peer visible hostinfo",
			delta: mapRequestDelta{peerHostinfoChanged: true, endpointBroadcast: true},

			wantWholePeer: true,
		},
		{
			name:  "derp clear to zero",
			delta: mapRequestDelta{derpChanged: true, oldDERP: 1, newDERP: 0},

			wantWholePeer: true,
		},
		{
			name:  "disco key and derp clear to zero",
			delta: mapRequestDelta{discoKeyChanged: true, derpChanged: true, oldDERP: 1, newDERP: 0},

			wantWholePeer: true,
		},
		{
			name:  "disco key only",
			delta: mapRequestDelta{discoKeyChanged: true},

			wantKeys:      true,
			wantEndpoints: true,
		},
		{
			name:     "disco key and derp move",
			delta:    mapRequestDelta{discoKeyChanged: true, derpChanged: true, oldDERP: 1, newDERP: 2},
			nodeDERP: 2,

			wantKeys:      true,
			wantEndpoints: true,
			wantDERP:      2,
		},
		{
			name:  "useful endpoint only",
			delta: mapRequestDelta{endpointBroadcast: true},

			wantEndpoints: true,
		},
		{
			name:     "derp move only",
			delta:    mapRequestDelta{derpChanged: true, oldDERP: 1, newDERP: 2},
			nodeDERP: 2,

			wantDERP: 2,
		},
		{
			name:     "endpoint and derp move",
			delta:    mapRequestDelta{endpointBroadcast: true, derpChanged: true, oldDERP: 1, newDERP: 2},
			nodeDERP: 2,

			wantEndpoints: true,
			wantDERP:      2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			current := node.Clone()
			current.Hostinfo.NetInfo.PreferredDERP = tt.nodeDERP
			c := buildMapRequestChangeResponse(node.ID, current.View(), tt.delta)

			if tt.wantEmpty {
				require.True(t, c.IsEmpty(), "got %+v", c)

				return
			}

			if tt.wantWholePeer {
				require.Contains(t, c.PeersChanged, node.ID, "got %+v", c)
				require.Empty(t, c.PeerPatches)

				return
			}

			require.Empty(t, c.PeersChanged, "got %+v", c)
			require.Len(t, c.PeerPatches, 1)

			patch := c.PeerPatches[0]
			require.Equal(t, tt.wantKeys, patch.Key != nil && patch.DiscoKey != nil, "keys on patch")
			require.Equal(t, tt.wantEndpoints, patch.Endpoints != nil, "endpoints on patch")
			require.Equal(t, tt.wantDERP, patch.DERPRegion, "DERP on patch")
		})
	}
}
