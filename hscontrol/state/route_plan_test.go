package state

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/policy/packetfilter"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/util/deephash"
)

var errMapViewPolicyBuild = errors.New("injected MapView policy build failure")

func mapViewTestState(tb testing.TB, pol string) *State {
	tb.Helper()

	nodes := make(types.Nodes, 3)
	for i := range nodes {
		n := createTestNode(types.NodeID(i+1), 1, "user1", "node"+string(rune('a'+i)))
		n.IPv4 = new(netip.AddrFrom4([4]byte{100, 64, 0, byte(i + 1)}))
		n.User.ID = 1
		n.IsOnline = new(true)
		nodes[i] = &n
	}

	pm, err := policy.NewPolicyManager([]byte(pol), []types.User{*nodes[0].User}, nodes.ViewSlice())
	require.NoError(tb, err)

	store := NewNodeStore(nodes, policyPeersFunc(pm), 1, time.Millisecond)
	store.Start()
	tb.Cleanup(store.Stop)

	return &State{nodeStore: store, polMan: pm, cfg: &types.Config{BaseDomain: "example.test"}}
}

func TestMapViewUsesOneSnapshot(t *testing.T) {
	s := mapViewTestState(t, "")
	before, err := s.MapView(1)
	require.NoError(t, err)
	rules, err := before.PacketRules()
	require.NoError(t, err)
	ssh, err := before.SSHPolicy("https://example.test")
	require.NoError(t, err)
	s.nodeStore.UpdateNodes(map[types.NodeID]UpdateNodeFunc{
		1: func(n *types.Node) { n.GivenName = "renamed"; *n.IPv4 = netip.MustParseAddr("100.64.0.99") },
		2: func(n *types.Node) { n.Tags = []string{"tag:new"} },
	})
	_, err = s.SetPolicy([]byte(`{"grants":[]}`))
	require.NoError(t, err)
	after, err := s.MapView(1)
	require.NoError(t, err)
	require.Equal(t, "nodea", before.Viewer().GivenName())
	require.Equal(t, "renamed", after.Viewer().GivenName())
	require.Len(t, before.PeerIDs(), 2)
	require.Empty(t, after.PeerIDs())
	require.Empty(t, before.Peers(2).At(0).Tags().AsSlice())
	require.Empty(t, before.Peers(1, 999).AsSlice())
	gotRules, err := before.PacketRules()
	require.NoError(t, err)
	require.Equal(t, packetfilter.ToTailcfg(rules), packetfilter.ToTailcfg(gotRules))

	gotSSH, err := before.SSHPolicy("https://example.test")
	require.NoError(t, err)
	require.Equal(t, ssh, gotSSH)

	ids := before.PeerIDs()
	ids[0] = 999

	require.NotContains(t, before.PeerIDs(), types.NodeID(999))
}

func TestPolicyViewRefreshesWithUnchangedAdjacency(t *testing.T) {
	s := mapViewTestState(t, `{"grants":[{"src":["*"],"dst":["*"],"ip":["tcp:80"]}]}`)
	before, err := s.MapView(1)
	require.NoError(t, err)
	_, err = s.SetPolicy([]byte(`{"grants":[{"src":["*"],"dst":["*"],"ip":["tcp:443"]}],"nodeAttrs":[{"target":["*"],"attr":["disable-ipv4"]}]}`))
	require.NoError(t, err)
	after, err := s.MapView(1)
	require.NoError(t, err)
	require.Equal(t, before.PeerIDs(), after.PeerIDs())
	oldRules, err := before.PacketRules()
	require.NoError(t, err)
	newRules, err := after.PacketRules()
	require.NoError(t, err)
	require.NotEqual(t, packetfilter.ToTailcfg(oldRules), packetfilter.ToTailcfg(newRules))
	require.NotContains(t, before.NodeCapMap(1), nodecap.Cap("disable-ipv4"))
	require.Contains(t, after.NodeCapMap(1), nodecap.Cap("disable-ipv4"))
	addresses, err := after.NodeAddresses(1)
	require.NoError(t, err)

	for _, p := range addresses.Addresses {
		require.False(t, p.Addr().Is4())
	}

	addresses.Addresses[0] = netip.MustParsePrefix("::/0")
	fresh, err := after.NodeAddresses(1)
	require.NoError(t, err)
	require.NotContains(t, fresh.Addresses, netip.MustParsePrefix("::/0"))
}

func TestMapViewCapabilityResultsAreOwned(t *testing.T) {
	s := mapViewTestState(t, `{"nodeAttrs":[{"target":["*"],"attr":["randomize-client-port","suggest-exit-node"]}]}`)
	s.nodeStore.UpdateNode(2, func(n *types.Node) {
		n.ApprovedRoutes = []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
		}
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: slices.Clone(n.ApprovedRoutes)}
	})
	view, err := s.MapView(1)
	require.NoError(t, err)

	for _, id := range []types.NodeID{1, 2} {
		caps := view.NodeCapMap(id)
		require.Contains(t, caps, nodecap.RandomizeClientPort)
		caps[nodecap.RandomizeClientPort] = []tailcfg.RawMessage{`"changed"`}
		delete(caps, nodecap.SuggestExitNode)

		fresh := view.NodeCapMap(id)
		require.Contains(t, fresh, nodecap.RandomizeClientPort)
		require.Nil(t, fresh[nodecap.RandomizeClientPort])
		require.Contains(t, fresh, nodecap.SuggestExitNode)
	}

	peer := view.PeerCapMap(2)
	require.Contains(t, peer, nodecap.SuggestExitNode)
	peer[nodecap.SuggestExitNode] = []tailcfg.RawMessage{`"changed"`}
	delete(peer, nodecap.SuggestExitNode)

	fresh := view.PeerCapMap(2)
	require.Contains(t, fresh, nodecap.SuggestExitNode)
	require.Nil(t, fresh[nodecap.SuggestExitNode])
	require.Nil(t, view.NodeCapMap(2)[nodecap.SuggestExitNode])
	require.Nil(t, view.PeerCapMap(1))
	require.Nil(t, view.PeerCapMap(999))
	require.Nil(t, view.NodeCapMap(999))
}

func TestHealthOnlySnapshotUsesFreshRoutes(t *testing.T) {
	s := mapViewTestState(t, "")
	route := netip.MustParsePrefix("10.0.0.0/24")

	for _, id := range []types.NodeID{2, 3} {
		s.nodeStore.UpdateNode(id, func(n *types.Node) {
			n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
			n.ApprovedRoutes = []netip.Prefix{route}
		})
	}

	before, err := s.MapView(1)
	require.NoError(t, err)

	var builds atomic.Int32

	inner := s.nodeStore.peersFunc
	s.nodeStore.peersFunc = func(nodes []types.NodeView) (policy.ReadView, map[types.NodeID][]types.NodeID, error) {
		builds.Add(1)
		return inner(nodes)
	}
	s.nodeStore.UpdateNode(2, func(n *types.Node) { n.Unhealthy = true })
	after, err := s.MapView(1)
	require.NoError(t, err)
	require.Zero(t, builds.Load(), "healthy snapshots may reuse policy while routes change")

	oldAddresses, err := before.NodeAddresses(2)
	require.NoError(t, err)
	newAddresses, err := after.NodeAddresses(3)
	require.NoError(t, err)
	require.Contains(t, oldAddresses.PrimaryRoutes, route)
	require.Contains(t, newAddresses.PrimaryRoutes, route)
	newAddresses, err = after.NodeAddresses(2)
	require.NoError(t, err)
	require.NotContains(t, newAddresses.PrimaryRoutes, route)
}

func TestFailedPolicyBuildPublishesFactsAndRetriesHealthUpdate(t *testing.T) {
	s := mapViewTestState(t, "")
	old, err := s.MapView(1)
	require.NoError(t, err)

	original := errMapViewPolicyBuild
	inner := s.nodeStore.peersFunc
	fail := true
	s.nodeStore.peersFunc = func(nodes []types.NodeView) (policy.ReadView, map[types.NodeID][]types.NodeID, error) {
		if fail {
			return policy.ReadView{}, nil, original
		}

		return inner(nodes)
	}
	route := netip.MustParsePrefix("10.1.0.0/24")

	s.nodeStore.UpdateNode(2, func(n *types.Node) {
		n.GivenName = "new-name"
		n.Tags = []string{"tag:new"}
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		n.ApprovedRoutes = []netip.Prefix{route}
	})
	snap := s.nodeStore.data.Load()
	require.Same(t, original, snap.policyBuildErr)
	require.False(t, snap.policy.Valid())
	require.Empty(t, snap.peersByNode)
	require.Equal(t, "new-name", snap.nodesByNodeKey[snap.nodesByID[2].NodeKey].GivenName())
	require.Equal(t, types.NodeID(2), snap.routes[route])

	_, err = s.MapView(1)
	require.Same(t, original, err)
	require.Equal(t, "nodeb", old.Peers(2).At(0).GivenName())

	fail = false

	s.nodeStore.UpdateNode(2, func(n *types.Node) { n.Unhealthy = true })
	require.NoError(t, s.nodeStore.data.Load().policyBuildErr)
	recovered, err := s.MapView(1)
	require.NoError(t, err)
	require.Equal(t, "new-name", recovered.Peers(2).At(0).GivenName())
	require.Equal(t, []change.Change{change.FullUpdate()}, s.DrainSelfRefreshes())
	require.Empty(t, s.DrainSelfRefreshes(), "recovery notification drains once")
}

func TestUnchangedInputsRecoverInvalidSnapshot(t *testing.T) {
	for _, kind := range []string{"node", "policy", "user"} {
		t.Run(kind, func(t *testing.T) {
			_, s, id := persistTestSetup(t)
			t.Cleanup(func() { _ = s.Close() })

			inner := s.nodeStore.peersFunc
			fail := true
			s.nodeStore.peersFunc = func(nodes []types.NodeView) (policy.ReadView, map[types.NodeID][]types.NodeID, error) {
				view, peers, err := inner(nodes)

				if fail {
					return policy.ReadView{}, nil, errMapViewPolicyBuild
				}

				return view, peers, err
			}
			s.nodeStore.UpdateNode(id, func(n *types.Node) {
				n.GivenName = "withheld"
				n.IPv4 = new(netip.MustParseAddr("100.64.0.99"))
			})
			_, err := s.MapView(id)
			require.Error(t, err)

			fail = false
			generation := s.polMan.NodesGeneration()
			changed, err := s.polMan.SetNodes(s.ListNodes())
			require.NoError(t, err)
			require.False(t, changed, "manager inputs must already be current before the retry")

			switch kind {
			case "node":
				_, err = s.updatePolicyManagerNodes(s.polMan.NodesGeneration())
			case "policy":
				_, err = s.SetPolicy(nil)
			case "user":
				_, err = s.updatePolicyManagerUsers()
			}

			require.NoError(t, err)
			require.Equal(t, generation, s.polMan.NodesGeneration(), "recovery must not require a generation change")
			view, err := s.MapView(id)
			require.NoError(t, err)
			require.Equal(t, "withheld", view.Viewer().GivenName())
			require.Equal(t, []change.Change{change.FullUpdate()}, s.DrainSelfRefreshes())
			require.Empty(t, s.DrainSelfRefreshes())
		})
	}
}

func TestCapturedReadViewSurvivesManagerCacheReplacement(t *testing.T) {
	s := mapViewTestState(t, "")
	captured := s.nodeStore.data.Load().policy
	viewer, _ := s.GetNodeByID(1)
	want, err := captured.PacketRulesForNode(viewer)
	require.NoError(t, err)

	for range 3 {
		_, err = s.SetPolicy([]byte(`{"grants":[]}`))
		require.NoError(t, err)
		current, err := s.MapView(1)
		require.NoError(t, err)
		_, err = current.PacketRules()
		require.NoError(t, err)
		_, err = current.SSHPolicy("https://example.test")
		require.NoError(t, err)
	}

	got, err := captured.PacketRulesForNode(viewer)
	require.NoError(t, err)
	require.Equal(t, packetfilter.ToTailcfg(want), packetfilter.ToTailcfg(got))
}

func TestMapViewConcurrentPublication(t *testing.T) {
	s := mapViewTestState(t, "")
	policies := [][]byte{
		[]byte(`{"grants":[{"src":["*"],"dst":["*"],"ip":["tcp:80"]}],"ssh":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self"],"users":["root"]}],"nodeAttrs":[{"target":["*"],"attr":["disable-ipv4"]}]}`),
		[]byte(`{"grants":[],"ssh":[]}`),
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range byte(30) {
			s.nodeStore.UpdateNodes(map[types.NodeID]UpdateNodeFunc{
				1: func(n *types.Node) {
					if i%2 == 0 {
						n.Tags = []string{"tag:a"}
					} else {
						n.Tags = nil
					}
				},
				2: func(n *types.Node) {
					n.Tags = []string{[]string{"tag:b", "tag:c"}[i%2]}
					*n.IPv4 = netip.AddrFrom4([4]byte{100, 64, 1, i + 1})
					n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, i, 0}), 24)}}
					n.ApprovedRoutes = slices.Clone(n.Hostinfo.RoutableIPs)
				},
			})

			_, err := s.SetPolicy(policies[i%2])
			if err != nil {
				t.Error(err)
				return
			}
		}
	})

	for range 50 {
		view, err := s.MapView(1)
		require.NoError(t, err)

		self := view.Viewer().AsStruct()
		peers := view.Peers().AsSlice()

		frozen := make([]*types.Node, len(peers))
		for i, peer := range peers {
			frozen[i] = peer.AsStruct()
		}

		rules, err := view.PacketRules()
		require.NoError(t, err)
		ssh, err := view.SSHPolicy("https://example.test")
		require.NoError(t, err)

		selfCaps := view.NodeCapMap(view.Viewer().ID())
		addresses, err := view.NodeAddresses(view.Viewer().ID())
		require.NoError(t, err)

		if _, disabled := selfCaps["disable-ipv4"]; disabled {
			for _, p := range addresses.Addresses {
				require.False(t, p.Addr().Is4())
			}
		}

		for i, peer := range peers {
			before, err := view.NodeAddresses(peer.ID())
			require.NoError(t, err)

			caps, peerCaps := view.NodeCapMap(peer.ID()), view.PeerCapMap(peer.ID())
			after, err := view.NodeAddresses(peer.ID())
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Equal(t, caps, view.NodeCapMap(peer.ID()))
			require.Equal(t, peerCaps, view.PeerCapMap(peer.ID()))
			require.Equal(t, frozen[i], peer.AsStruct())
		}

		gotRules, err := view.PacketRules()
		require.NoError(t, err)
		gotSSH, err := view.SSHPolicy("https://example.test")
		require.NoError(t, err)
		require.Equal(t, packetfilter.ToTailcfg(rules), packetfilter.ToTailcfg(gotRules))
		require.Equal(t, ssh, gotSSH)
		require.Equal(t, self, view.Viewer().AsStruct())
	}

	wg.Wait()
}

func TestBootstrapSnapshotRejectsMissingPolicyView(t *testing.T) {
	original := errMapViewPolicyBuild
	store := NewNodeStore(nil, func([]types.NodeView) (policy.ReadView, map[types.NodeID][]types.NodeID, error) {
		return policy.ReadView{}, nil, original
	}, 1, time.Millisecond)
	require.Same(t, original, store.data.Load().policyBuildErr)
	require.Nil(t, store.writeQueue, "bootstrap status is available before Start")
	_, err := (&State{nodeStore: store}).MapView(1)
	require.Same(t, original, err)

	store = NewNodeStore(nil, func([]types.NodeView) (policy.ReadView, map[types.NodeID][]types.NodeID, error) {
		return policy.ReadView{}, nil, nil
	}, 1, time.Millisecond)
	require.ErrorIs(t, store.data.Load().policyBuildErr, ErrInvalidPolicyView)
}

func TestNodeAddressesDisableIPv4PreservesSubnetAndExitRoutes(t *testing.T) {
	s := mapViewTestState(t, `{"nodeAttrs":[{"target":["*"],"attr":["disable-ipv4"]}],"grants":[{"src":["*"],"dst":["*"],"ip":["*"]}]}`)
	subnet := netip.MustParsePrefix("10.0.0.0/24")
	exits := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

	s.nodeStore.UpdateNode(2, func(n *types.Node) {
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: slices.Concat([]netip.Prefix{subnet}, exits)}
		n.ApprovedRoutes = slices.Clone(n.Hostinfo.RoutableIPs)
	})
	view, err := s.MapView(1)
	require.NoError(t, err)
	addresses, err := view.NodeAddresses(2)
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0::1/128")}, addresses.Addresses)
	require.NotContains(t, addresses.AllowedIPs, netip.MustParsePrefix("100.64.0.2/32"))
	require.Contains(t, addresses.AllowedIPs, subnet)
	require.Contains(t, addresses.AllowedIPs, exits[0])
	require.Contains(t, addresses.AllowedIPs, exits[1])
	require.Equal(t, []netip.Prefix{subnet}, addresses.PrimaryRoutes)
}

func TestMapViewViaGroupsAndRegularOverride(t *testing.T) {
	for _, regular := range []bool{false, true} {
		t.Run(map[bool]string{false: "independent groups", true: "regular override"}[regular], func(t *testing.T) {
			s := mapViewTestState(t, "")
			routes := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("10.0.1.0/24")}

			for i, id := range []types.NodeID{2, 3} {
				s.nodeStore.UpdateNode(id, func(n *types.Node) {
					n.Tags = []string{[]string{"tag:a", "tag:b"}[i]}
					n.UserID = nil
					n.User = nil
					n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: slices.Clone(routes)}
					n.ApprovedRoutes = slices.Clone(routes)
				})
			}

			grants := `{"tagOwners":{"tag:a":["user1@"],"tag:b":["user1@"]},"grants":[{"src":["*"],"dst":["10.0.0.0/24"],"via":["tag:a"],"ip":["*"]},{"src":["*"],"dst":["10.0.1.0/24"],"via":["tag:b"],"ip":["*"]}`
			if regular {
				grants += `,{"src":["*"],"dst":["10.0.0.0/23"],"ip":["*"]}`
			}

			_, err := s.SetPolicy([]byte(grants + `]}`))
			require.NoError(t, err)
			view, err := s.MapView(1)
			require.NoError(t, err)
			a, err := view.NodeAddresses(2)
			require.NoError(t, err)
			b, err := view.NodeAddresses(3)
			require.NoError(t, err)

			if regular {
				require.ElementsMatch(t, routes, a.PrimaryRoutes)
				require.Empty(t, b.PrimaryRoutes)
			} else {
				require.Equal(t, routes[:1], a.PrimaryRoutes)
				require.Equal(t, routes[1:], b.PrimaryRoutes)
			}
		})
	}
}

func TestHealthOnlySnapshotUpdatesViaSteering(t *testing.T) {
	s := mapViewTestState(t, "")
	route := netip.MustParsePrefix("10.0.0.0/24")

	for _, id := range []types.NodeID{2, 3} {
		s.nodeStore.UpdateNode(id, func(n *types.Node) {
			n.Tags = []string{"tag:via"}
			n.UserID = nil
			n.User = nil
			n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
			n.ApprovedRoutes = []netip.Prefix{route}
		})
	}

	_, err := s.SetPolicy([]byte(`{"tagOwners":{"tag:via":["user1@"]},"grants":[{"src":["*"],"dst":["10.0.0.0/24"],"via":["tag:via"],"ip":["*"]}]}`))
	require.NoError(t, err)
	before, err := s.MapView(1)
	require.NoError(t, err)

	oldPolicy := s.nodeStore.data.Load().policy
	s.nodeStore.UpdateNode(2, func(n *types.Node) { n.Unhealthy = true })
	after, err := s.MapView(1)
	require.NoError(t, err)
	require.Equal(t, oldPolicy, s.nodeStore.data.Load().policy)
	// Reuse the policy generation with fresh health facts for via and global HA.
	require.False(t, before.Peers(2).At(0).Unhealthy())
	require.True(t, after.Peers(2).At(0).Unhealthy())
	require.Contains(t, after.snapshot.primaryRoutesByNode[3], route)

	oldRoutes, err := before.NodeAddresses(2)
	require.NoError(t, err)
	newRoutes, err := after.NodeAddresses(2)
	require.NoError(t, err)
	require.Contains(t, oldRoutes.PrimaryRoutes, route)
	require.NotContains(t, newRoutes.PrimaryRoutes, route)
	newRoutes, err = after.NodeAddresses(3)
	require.NoError(t, err)
	require.Contains(t, newRoutes.PrimaryRoutes, route)
}

func BenchmarkMapViewRoutes(b *testing.B) {
	for _, count := range []int{0, 64, 4096} {
		b.Run(fmt.Sprintf("routes=%d", count), func(b *testing.B) {
			s := mapViewTestState(b, "")

			routes := make([]netip.Prefix, count)
			for i := range routes {
				routes[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i / 256), byte(i % 256), 0}), 24)
			}

			s.nodeStore.UpdateNode(2, func(n *types.Node) {
				n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: routes}
				n.ApprovedRoutes = slices.Clone(routes)
			})
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				view, err := s.MapView(1)
				if err != nil {
					b.Fatal(err)
				}

				_, err = view.NodeAddresses(2)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkMapViewPublication(b *testing.B) {
	policies := [][]byte{
		[]byte(`{"grants":[{"src":["*"],"dst":["*"],"ip":["tcp:80"]}]}`),
		[]byte(`{"grants":[{"src":["*"],"dst":["*"],"ip":["tcp:443"]}]}`),
	}

	for _, kind := range []string{"health", "policy", "retained-generations"} {
		b.Run(kind, func(b *testing.B) {
			s := mapViewTestState(b, string(policies[1]))
			for _, id := range []types.NodeID{2, 3} {
				s.nodeStore.UpdateNode(id, func(n *types.Node) {
					n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}
					n.ApprovedRoutes = slices.Clone(n.Hostinfo.RoutableIPs)
				})
			}

			retained := make([]MapView, 32)
			retainedHashes := make([]deephash.Sum, len(retained))

			var previousHash deephash.Sum

			b.ReportAllocs()
			b.ResetTimer()

			for i := range b.N {
				previous := s.nodeStore.data.Load()
				if kind == "health" {
					s.nodeStore.UpdateNode(2, func(n *types.Node) { n.Unhealthy = i%2 == 0 })
				} else {
					changed, err := s.SetPolicy(policies[i%len(policies)])
					if err != nil {
						b.Fatal(err)
					}

					if !changed {
						b.Fatal("alternating policies must change compiled semantics")
					}
				}

				view, err := s.MapView(1)
				if err != nil {
					b.Fatal(err)
				}

				if view.snapshot == previous {
					b.Fatal("publication did not advance the snapshot")
				}

				rules, err := view.PacketRules()
				if err != nil {
					b.Fatal(err)
				}

				if len(rules) == 0 {
					b.Fatal("publication fixture must retain a packet rule")
				}

				hash := rules[0].Hash()
				if kind != "health" && i > 0 && hash == previousHash {
					b.Fatal("alternating policies did not advance the captured generation")
				}

				previousHash = hash

				if kind == "retained-generations" {
					slot := i % len(retained)
					retained[slot], retainedHashes[slot] = view, hash
				}
			}

			b.StopTimer()

			if kind == "retained-generations" {
				count := min(b.N, len(retained))

				publications := make(map[*Snapshot]bool, count)
				for i, view := range retained[:count] {
					if publications[view.snapshot] {
						b.Fatal("retained publications must be distinct")
					}

					publications[view.snapshot] = true

					rules, err := view.PacketRules()
					if err != nil {
						b.Fatal(err)
					}

					if len(rules) == 0 || rules[0].Hash() != retainedHashes[i] {
						b.Fatal("a retained generation changed after later publication")
					}
				}
			}

			runtime.KeepAlive(retained)
		})
	}
}

func TestUnchangedHealthRetriesInvalidPolicySnapshot(t *testing.T) {
	s := mapViewTestState(t, "")
	inner := s.nodeStore.peersFunc
	fail := true
	s.nodeStore.peersFunc = func(nodes []types.NodeView) (policy.ReadView, map[types.NodeID][]types.NodeID, error) {
		if fail {
			return policy.ReadView{}, nil, errMapViewPolicyBuild
		}

		return inner(nodes)
	}
	s.nodeStore.UpdateNode(1, func(n *types.Node) {
		n.GivenName = "withheld"
		n.IPv4 = new(netip.MustParseAddr("100.64.0.99"))
	})
	_, err := s.MapView(1)
	require.Error(t, err)

	fail = false

	require.True(t, s.BatchSetNodeHealth(map[types.NodeID]bool{2: true}), "recovery must request dispatch with unchanged health and routes")
	view, err := s.MapView(1)
	require.NoError(t, err)
	require.Equal(t, "withheld", view.Viewer().GivenName())
	require.Equal(t, []change.Change{change.FullUpdate()}, s.DrainSelfRefreshes())
	require.False(t, s.BatchSetNodeHealth(map[types.NodeID]bool{2: true}))
}
