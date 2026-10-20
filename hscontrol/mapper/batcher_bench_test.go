package mapper

// Benchmarks for batcher components and full pipeline.
//
// Organized into three tiers:
// - Component benchmarks: individual functions (connectionEntry.send, computePeerDiff, etc.)
// - System benchmarks: batching mechanics (addToBatch, processBatchedChanges, broadcast)
// - Full pipeline benchmarks: end-to-end with real DB (gated behind !testing.Short())
//
// All benchmarks use sub-benchmarks with 10/100/1000 node counts for scaling analysis.

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/puzpuzpuz/xsync/v4"
	"tailscale.com/tailcfg"
)

// ============================================================================
// Component Benchmarks
// ============================================================================

// BenchmarkConnectionEntry_Send measures the throughput of sending a single
// MapResponse through a connectionEntry with a buffered channel.
func BenchmarkConnectionEntry_Send(b *testing.B) {
	ch := make(chan *tailcfg.MapResponse, b.N+1)
	entry := makeConnectionEntry("bench-conn", ch)
	data := testMapResponse()

	b.ResetTimer()

	for range b.N {
		_ = entry.send(data)
	}
}

// BenchmarkMultiChannelSend measures broadcast throughput to multiple connections.
func BenchmarkMultiChannelSend(b *testing.B) {
	for _, connCount := range []int{1, 3, 10} {
		b.Run(fmt.Sprintf("%dconn", connCount), func(b *testing.B) {
			mc := newMultiChannelNodeConn(1, nil)

			channels := make([]chan *tailcfg.MapResponse, connCount)
			for i := range channels {
				channels[i] = make(chan *tailcfg.MapResponse, b.N+1)
				mc.addConnection(makeConnectionEntry(fmt.Sprintf("conn-%d", i), channels[i]))
			}

			data := testMapResponse()

			b.ResetTimer()

			for range b.N {
				_ = mc.send(data)
			}
		})
	}
}

// BenchmarkComputePeerDiff measures the cost of computing peer diffs at scale.
func BenchmarkComputePeerDiff(b *testing.B) {
	for _, peerCount := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("%dpeers", peerCount), func(b *testing.B) {
			mc := newMultiChannelNodeConn(1, nil)

			// Populate tracked peers: 1..peerCount
			for i := 1; i <= peerCount; i++ {
				mc.lastSentPeers.Store(tailcfg.NodeID(i), struct{}{})
			}

			// Current peers: remove ~10% (every 10th peer is missing)
			current := make([]tailcfg.NodeID, 0, peerCount)
			for i := 1; i <= peerCount; i++ {
				if i%10 != 0 {
					current = append(current, tailcfg.NodeID(i))
				}
			}

			b.ResetTimer()

			for range b.N {
				_ = mc.computePeerDiff(current)
			}
		})
	}
}

// BenchmarkUpdateSentPeers measures the cost of updating peer tracking state.
func BenchmarkUpdateSentPeers(b *testing.B) {
	for _, peerCount := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("%dpeers_full", peerCount), func(b *testing.B) {
			mc := newMultiChannelNodeConn(1, nil)

			// Pre-build response with full peer list
			peerIDs := make([]tailcfg.NodeID, peerCount)
			for i := range peerIDs {
				peerIDs[i] = tailcfg.NodeID(i + 1)
			}

			resp := testMapResponseWithPeers(peerIDs...)

			b.ResetTimer()

			for range b.N {
				mc.updateSentPeers(resp)
			}
		})

		b.Run(fmt.Sprintf("%dpeers_incremental", peerCount), func(b *testing.B) {
			mc := newMultiChannelNodeConn(1, nil)

			// Pre-populate with existing peers
			for i := 1; i <= peerCount; i++ {
				mc.lastSentPeers.Store(tailcfg.NodeID(i), struct{}{})
			}

			// Build incremental response: add 10% new peers
			addCount := peerCount / 10
			if addCount == 0 {
				addCount = 1
			}

			resp := testMapResponse()

			resp.PeersChanged = make([]*tailcfg.Node, addCount)
			for i := range addCount {
				resp.PeersChanged[i] = &tailcfg.Node{ID: tailcfg.NodeID(peerCount + i + 1)}
			}

			b.ResetTimer()

			for range b.N {
				mc.updateSentPeers(resp)
			}
		})
	}
}

// ============================================================================
// System Benchmarks (no DB, batcher mechanics only)
// ============================================================================

// benchBatcher creates a lightweight batcher for benchmarks. Unlike the test
// helper, it doesn't register cleanup and suppresses logging.
func benchBatcher(nodeCount, bufferSize int) (*Batcher, map[types.NodeID]chan *tailcfg.MapResponse) {
	b := &Batcher{
		tick:    time.NewTicker(1 * time.Hour), // never fires during bench
		workers: 4,
		workCh:  make(chan work, 4*200),
		nodes:   xsync.NewMap[types.NodeID, *multiChannelNodeConn](),
		done:    make(chan struct{}),
	}

	channels := make(map[types.NodeID]chan *tailcfg.MapResponse, nodeCount)
	for i := 1; i <= nodeCount; i++ {
		id := types.NodeID(i) //nolint:gosec // benchmark with small controlled values
		mc := newMultiChannelNodeConn(id, nil)
		ch := make(chan *tailcfg.MapResponse, bufferSize)
		entry := &connectionEntry{
			id:      fmt.Sprintf("conn-%d", i),
			c:       ch,
			version: tailcfg.CapabilityVersion(100),
			created: time.Now(),
		}
		entry.lastUsed.Store(time.Now().Unix())
		mc.addConnection(entry)
		b.nodes.Store(id, mc)
		channels[id] = ch
	}

	b.totalNodes.Store(int64(nodeCount))

	return b, channels
}

// BenchmarkAddToBatch_Broadcast measures the cost of broadcasting a change
// to all nodes via addToBatch (no worker processing, just queuing).
func BenchmarkAddToBatch_Broadcast(b *testing.B) {
	for _, nodeCount := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("%dnodes", nodeCount), func(b *testing.B) {
			batcher, _ := benchBatcher(nodeCount, 10)

			defer func() {
				close(batcher.done)
				batcher.tick.Stop()
			}()

			ch := change.DERPMap()

			b.ResetTimer()

			for range b.N {
				batcher.addToBatch(ch)
				// Clear pending to avoid unbounded growth
				batcher.nodes.Range(func(_ types.NodeID, nc *multiChannelNodeConn) bool {
					nc.drainPending()
					return true
				})
			}
		})
	}
}

// BenchmarkAddToBatch_Targeted measures the cost of adding a targeted change
// to a single node.
func BenchmarkAddToBatch_Targeted(b *testing.B) {
	for _, nodeCount := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("%dnodes", nodeCount), func(b *testing.B) {
			batcher, _ := benchBatcher(nodeCount, 10)

			defer func() {
				close(batcher.done)
				batcher.tick.Stop()
			}()

			b.ResetTimer()

			for i := range b.N {
				targetID := types.NodeID(1 + (i % nodeCount)) //nolint:gosec // benchmark
				ch := change.Change{
					Reason:     "bench-targeted",
					TargetNode: targetID,
					PeerPatches: []*tailcfg.PeerChange{
						{NodeID: tailcfg.NodeID(targetID)}, //nolint:gosec // benchmark
					},
				}
				batcher.addToBatch(ch)
				// Clear pending periodically to avoid growth
				if i%100 == 99 {
					batcher.nodes.Range(func(_ types.NodeID, nc *multiChannelNodeConn) bool {
						nc.drainPending()
						return true
					})
				}
			}
		})
	}
}

// BenchmarkAddToBatch_FullUpdate measures the cost of a FullUpdate broadcast.
func BenchmarkAddToBatch_FullUpdate(b *testing.B) {
	for _, nodeCount := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("%dnodes", nodeCount), func(b *testing.B) {
			batcher, _ := benchBatcher(nodeCount, 10)

			defer func() {
				close(batcher.done)
				batcher.tick.Stop()
			}()

			b.ResetTimer()

			for range b.N {
				batcher.addToBatch(change.FullUpdate())
			}
		})
	}
}

// BenchmarkProcessBatchedChanges measures the cost of moving pending changes
// to the work queue.
func BenchmarkProcessBatchedChanges(b *testing.B) {
	for _, nodeCount := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("%dpending", nodeCount), func(b *testing.B) {
			batcher, _ := benchBatcher(nodeCount, 10)
			// Use a very large work channel to avoid blocking
			batcher.workCh = make(chan work, nodeCount*b.N+1)

			defer func() {
				close(batcher.done)
				batcher.tick.Stop()
			}()

			b.ResetTimer()

			for range b.N {
				b.StopTimer()
				// Seed pending changes
				for i := 1; i <= nodeCount; i++ {
					if nc, ok := batcher.nodes.Load(types.NodeID(i)); ok { //nolint:gosec // benchmark
						nc.appendPending(change.DERPMap())
					}
				}

				b.StartTimer()

				batcher.processBatchedChanges()
			}
		})
	}
}

// BenchmarkBroadcastToN measures end-to-end broadcast: addToBatch + processBatchedChanges
// to N nodes. Does NOT include worker processing (MapResponse generation).
func BenchmarkBroadcastToN(b *testing.B) {
	for _, nodeCount := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("%dnodes", nodeCount), func(b *testing.B) {
			batcher, _ := benchBatcher(nodeCount, 10)
			batcher.workCh = make(chan work, nodeCount*b.N+1)

			defer func() {
				close(batcher.done)
				batcher.tick.Stop()
			}()

			ch := change.DERPMap()

			b.ResetTimer()

			for range b.N {
				batcher.addToBatch(ch)
				batcher.processBatchedChanges()
			}
		})
	}
}

// BenchmarkMultiChannelBroadcast measures the cost of sending a MapResponse
// to N nodes each with varying connection counts.
func BenchmarkMultiChannelBroadcast(b *testing.B) {
	for _, nodeCount := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("%dnodes", nodeCount), func(b *testing.B) {
			batcher, _ := benchBatcher(nodeCount, b.N+1)

			defer func() {
				close(batcher.done)
				batcher.tick.Stop()
			}()

			// Add extra connections to every 3rd node
			for i := 1; i <= nodeCount; i++ {
				if i%3 == 0 {
					if mc, ok := batcher.nodes.Load(types.NodeID(i)); ok { //nolint:gosec // benchmark
						for j := range 2 {
							ch := make(chan *tailcfg.MapResponse, b.N+1)
							entry := &connectionEntry{
								id:      fmt.Sprintf("extra-%d-%d", i, j),
								c:       ch,
								version: tailcfg.CapabilityVersion(100),
								created: time.Now(),
							}
							entry.lastUsed.Store(time.Now().Unix())
							mc.addConnection(entry)
						}
					}
				}
			}

			data := testMapResponse()

			b.ResetTimer()

			for range b.N {
				batcher.nodes.Range(func(_ types.NodeID, mc *multiChannelNodeConn) bool {
					_ = mc.send(data)
					return true
				})
			}
		})
	}
}

// BenchmarkConcurrentAddToBatch measures addToBatch throughput under
// concurrent access from multiple goroutines.
func BenchmarkConcurrentAddToBatch(b *testing.B) {
	for _, nodeCount := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("%dnodes", nodeCount), func(b *testing.B) {
			batcher, _ := benchBatcher(nodeCount, 10)

			defer func() {
				close(batcher.done)
				batcher.tick.Stop()
			}()

			// Background goroutine to drain pending periodically
			drainDone := make(chan struct{})

			go func() {
				defer close(drainDone)

				for {
					select {
					case <-batcher.done:
						return
					default:
						batcher.nodes.Range(func(_ types.NodeID, nc *multiChannelNodeConn) bool {
							nc.drainPending()
							return true
						})
						time.Sleep(time.Millisecond) //nolint:forbidigo // benchmark drain loop
					}
				}
			}()

			ch := change.DERPMap()

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					batcher.addToBatch(ch)
				}
			})
			b.StopTimer()

			// Cleanup
			close(batcher.done)
			<-drainDone
			// Re-open done so the defer doesn't double-close
			batcher.done = make(chan struct{})
		})
	}
}

// BenchmarkIsConnected measures the read throughput of IsConnected checks.
func BenchmarkIsConnected(b *testing.B) {
	for _, nodeCount := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("%dnodes", nodeCount), func(b *testing.B) {
			batcher, _ := benchBatcher(nodeCount, 1)

			defer func() {
				close(batcher.done)
				batcher.tick.Stop()
			}()

			b.ResetTimer()

			for i := range b.N {
				id := types.NodeID(1 + (i % nodeCount)) //nolint:gosec // benchmark
				_ = batcher.IsConnected(id)
			}
		})
	}
}

// BenchmarkConnectedMap measures the cost of building the full connected map.
func BenchmarkConnectedMap(b *testing.B) {
	for _, nodeCount := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("%dnodes", nodeCount), func(b *testing.B) {
			batcher, channels := benchBatcher(nodeCount, 1)

			defer func() {
				close(batcher.done)
				batcher.tick.Stop()
			}()

			// Disconnect 10% of nodes for a realistic mix
			for i := 1; i <= nodeCount; i++ {
				if i%10 == 0 {
					id := types.NodeID(i) //nolint:gosec // benchmark
					if mc, ok := batcher.nodes.Load(id); ok {
						mc.removeConnectionByChannel(channels[id])
						mc.markDisconnected()
					}
				}
			}

			b.ResetTimer()

			for range b.N {
				_ = batcher.ConnectedMap()
			}
		})
	}
}

// BenchmarkConnectionChurn measures the cost of add/remove connection cycling
// which simulates client reconnection patterns.
func BenchmarkConnectionChurn(b *testing.B) {
	for _, nodeCount := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("%dnodes", nodeCount), func(b *testing.B) {
			batcher, channels := benchBatcher(nodeCount, 10)

			defer func() {
				close(batcher.done)
				batcher.tick.Stop()
			}()

			b.ResetTimer()

			for i := range b.N {
				id := types.NodeID(1 + (i % nodeCount)) //nolint:gosec // benchmark

				mc, ok := batcher.nodes.Load(id)
				if !ok {
					continue
				}

				// Remove old connection
				oldCh := channels[id]
				mc.removeConnectionByChannel(oldCh)

				// Add new connection
				newCh := make(chan *tailcfg.MapResponse, 10)
				entry := &connectionEntry{
					id:      fmt.Sprintf("churn-%d", i),
					c:       newCh,
					version: tailcfg.CapabilityVersion(100),
					created: time.Now(),
				}
				entry.lastUsed.Store(time.Now().Unix())
				mc.addConnection(entry)

				channels[id] = newCh
			}
		})
	}
}

// BenchmarkConcurrentSendAndChurn measures the combined cost of sends happening
// concurrently with connection churn - the hot path in production.
func BenchmarkConcurrentSendAndChurn(b *testing.B) {
	for _, nodeCount := range []int{10, 100} {
		b.Run(fmt.Sprintf("%dnodes", nodeCount), func(b *testing.B) {
			batcher, channels := benchBatcher(nodeCount, 100)

			var mu sync.Mutex // protect channels map

			stopChurn := make(chan struct{})
			defer close(stopChurn)

			// Background churn on 10% of nodes
			go func() {
				i := 0

				for {
					select {
					case <-stopChurn:
						return
					default:
						id := types.NodeID(1 + (i % nodeCount)) //nolint:gosec // benchmark
						if i%10 == 0 {                          // only churn 10%
							mc, ok := batcher.nodes.Load(id)
							if ok {
								mu.Lock()
								oldCh := channels[id]
								mu.Unlock()
								mc.removeConnectionByChannel(oldCh)

								newCh := make(chan *tailcfg.MapResponse, 100)
								entry := &connectionEntry{
									id:      fmt.Sprintf("churn-%d", i),
									c:       newCh,
									version: tailcfg.CapabilityVersion(100),
									created: time.Now(),
								}
								entry.lastUsed.Store(time.Now().Unix())
								mc.addConnection(entry)
								mu.Lock()
								channels[id] = newCh
								mu.Unlock()
							}
						}

						i++
					}
				}
			}()

			data := testMapResponse()

			b.ResetTimer()

			for range b.N {
				batcher.nodes.Range(func(_ types.NodeID, mc *multiChannelNodeConn) bool {
					_ = mc.send(data)
					return true
				})
			}
		})
	}
}

// ============================================================================
// Full Pipeline Benchmarks (with DB)
// ============================================================================

// BenchmarkAddNode measures the cost of adding nodes to the batcher,
// including initial MapResponse generation from a real database.
func BenchmarkAddNode(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping full pipeline benchmark in short mode")
	}

	for _, nodeCount := range []int{10, 100} {
		b.Run(fmt.Sprintf("%dnodes", nodeCount), func(b *testing.B) {
			testData, cleanup := setupBatcherWithTestData(b, NewBatcherAndMapper, 1, nodeCount, largeBufferSize)
			defer cleanup()

			batcher := testData.Batcher
			allNodes := testData.Nodes

			// Start consumers
			for i := range allNodes {
				allNodes[i].start()
			}

			defer func() {
				for i := range allNodes {
					allNodes[i].cleanup()
				}
			}()

			b.ResetTimer()

			for range b.N {
				// Connect all nodes (measuring AddNode cost)
				for i := range allNodes {
					node := &allNodes[i]
					_ = batcher.AddNode(node.n.ID, node.ch, tailcfg.CapabilityVersion(100), nil)
				}

				b.StopTimer()
				// Disconnect for next iteration
				for i := range allNodes {
					node := &allNodes[i]
					batcher.RemoveNode(node.n.ID, node.ch)
				}
				// Drain channels
				for i := range allNodes {
					for {
						select {
						case <-allNodes[i].ch:
						default:
							goto drained
						}
					}

				drained:
				}

				b.StartTimer()
			}
		})
	}
}

// BenchmarkFullPipeline measures the full pipeline cost: addToBatch → processBatchedChanges
// → worker → generateMapResponse → send, with real nodes from a database.
func BenchmarkFullPipeline(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping full pipeline benchmark in short mode")
	}

	for _, nodeCount := range []int{10, 100} {
		b.Run(fmt.Sprintf("%dnodes", nodeCount), func(b *testing.B) {
			testData, cleanup := setupBatcherWithTestData(b, NewBatcherAndMapper, 1, nodeCount, largeBufferSize)
			defer cleanup()

			batcher := testData.Batcher
			allNodes := testData.Nodes

			// Start consumers
			for i := range allNodes {
				allNodes[i].start()
			}

			defer func() {
				for i := range allNodes {
					allNodes[i].cleanup()
				}
			}()

			// Connect all nodes first
			for i := range allNodes {
				node := &allNodes[i]

				err := batcher.AddNode(node.n.ID, node.ch, tailcfg.CapabilityVersion(100), nil)
				if err != nil {
					b.Fatalf("failed to add node %d: %v", i, err)
				}
			}

			// Wait for initial maps to settle
			time.Sleep(200 * time.Millisecond) //nolint:forbidigo // benchmark coordination

			b.ResetTimer()

			for range b.N {
				batcher.AddWork(change.DERPMap())
				// Allow workers to process (the batcher tick is what normally
				// triggers processBatchedChanges, but for benchmarks we need
				// to give the system time to process)
				time.Sleep(20 * time.Millisecond) //nolint:forbidigo // benchmark coordination
			}
		})
	}
}

// BenchmarkMapResponseFromChange measures the cost of synchronous
// MapResponse generation for individual nodes.
func BenchmarkMapResponseFromChange(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping full pipeline benchmark in short mode")
	}

	for _, nodeCount := range []int{10, 100} {
		b.Run(fmt.Sprintf("%dnodes", nodeCount), func(b *testing.B) {
			testData, cleanup := setupBatcherWithTestData(b, NewBatcherAndMapper, 1, nodeCount, largeBufferSize)
			defer cleanup()

			batcher := testData.Batcher
			allNodes := testData.Nodes

			// Start consumers
			for i := range allNodes {
				allNodes[i].start()
			}

			defer func() {
				for i := range allNodes {
					allNodes[i].cleanup()
				}
			}()

			// Connect all nodes
			for i := range allNodes {
				node := &allNodes[i]

				err := batcher.AddNode(node.n.ID, node.ch, tailcfg.CapabilityVersion(100), nil)
				if err != nil {
					b.Fatalf("failed to add node %d: %v", i, err)
				}
			}

			time.Sleep(200 * time.Millisecond) //nolint:forbidigo // benchmark coordination

			ch := change.DERPMap()

			b.ResetTimer()

			for i := range b.N {
				nodeIdx := i % len(allNodes)
				_, _ = batcher.MapResponseFromChange(allNodes[nodeIdx].n.ID, ch)
			}
		})
	}
}

// BenchmarkCapturedMapResponse and its helpers are frozen for an identical
// source copy to optimized baseline 425f21263. Setup and checks are not timed.
func BenchmarkCapturedMapResponse(b *testing.B) {
	cases := []struct {
		name, shape, kind string
		routeCount        int
	}{
		{"ordinary/full", "ordinary", "full", 0},
		{"ordinary/incremental", "ordinary", "incremental", 0},
		{"self/full", "self", "full", 0},
		{"self/incremental", "self", "incremental", 0},
		{"via/full", "via", "full", 0},
		{"via/incremental", "via", "incremental", 0},
		{"policy", "ordinary", "policy", 0},
		{"route-heavy", "ordinary", "full", 4096},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			td, cleanup := setupBatcherWithTestData(b, NewBatcherAndMapper, 2, 50, largeBufferSize)
			defer cleanup()

			peer, routes := prepareCapturedMapResponseBenchmark(b, td, tc.shape, tc.routeCount)
			self := td.Nodes[0].n.ID
			mc := newMultiChannelNodeConn(self, td.Batcher.mapper)
			mc.addConnection(&connectionEntry{id: "captured-benchmark", version: 100})

			// Warm the full response and seed exactly the peers that a delivered
			// full map contains, rather than repeatedly diffing phantom peers.
			full, err := generateMapResponse(mc, td.Batcher.mapper, change.FullUpdate())
			if err != nil {
				b.Fatal(err)
			}

			checkCapturedMapResponseBenchmark(b, td, tc.shape, "full", peer, routes, full)
			mc.updateSentPeers(full[0])

			ch := change.FullUpdate()

			switch tc.kind {
			case "incremental":
				ch = change.NodeAdded(peer)
			case "policy":
				ch = change.PolicyChange()
			}

			warm, err := generateMapResponse(mc, td.Batcher.mapper, ch)
			if err != nil {
				b.Fatal(err)
			}

			checkCapturedMapResponseBenchmark(b, td, tc.shape, tc.kind, peer, routes, warm)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := generateMapResponse(mc, td.Batcher.mapper, ch)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func prepareCapturedMapResponseBenchmark(
	b *testing.B, td *TestData, shape string, routeCount int,
) (types.NodeID, []netip.Prefix) {
	b.Helper()

	peer := td.Nodes[1].n.ID

	var (
		routers []types.NodeID
		routes  []netip.Prefix
	)

	switch shape {
	case "ordinary":
		// setupBatcherWithTestData already installed the same explicit
		// allow-all ACL on both candidates, including default protocols.
		if routeCount > 0 {
			peer = td.Nodes[50].n.ID
			routers = []types.NodeID{peer}

			routes = make([]netip.Prefix, routeCount)
			for i := range routes {
				routes[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i / 256), byte(i % 256), 0}), 24)
			}
		}
	case "self":
		_, err := td.State.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:*"]}]}`))
		if err != nil {
			b.Fatal(err)
		}
	case "via":
		peer = td.Nodes[51].n.ID

		pol := fmt.Sprintf(`{"tagOwners":{"tag:benchmark-via":[%q]},"grants":[{"src":[%q],"dst":["10.33.0.0/16"],"ip":["tcp:443"],"via":["tag:benchmark-via"]}]}`,
			td.Users[1].Name+"@", td.Users[0].Name+"@")

		_, err := td.State.SetPolicy([]byte(pol))
		if err != nil {
			b.Fatal(err)
		}

		_, _, err = td.State.SetNodeTags(peer, []string{"tag:benchmark-via"})
		if err != nil {
			b.Fatal(err)
		}
		// Elect the untagged lower-ID router first. Via must select the
		// tagged router instead of falling through to this global primary.
		routers = []types.NodeID{td.Nodes[50].n.ID, peer}
		routes = []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")}
	default:
		b.Fatalf("unknown captured response policy shape %q", shape)
	}

	for _, id := range routers {
		node, ok := td.State.GetNodeByID(id)
		if !ok {
			b.Fatalf("router %d missing", id)
		}

		router := node.AsStruct()
		router.IsOnline = new(true)
		router.Hostinfo = &tailcfg.Hostinfo{Hostname: router.Hostname, RoutableIPs: slices.Clone(routes)}
		td.State.PutNodeInStoreForTest(*router)

		_, _, err := td.State.SetApprovedRoutes(id, routes)
		if err != nil {
			b.Fatal(err)
		}
	}

	if shape == "via" {
		router, ok := td.State.GetNodeByID(peer)
		if !ok || !router.IsTagged() || router.UserID().Valid() || !router.IsOnline().Valid() ||
			!router.IsOnline().Get() || router.Unhealthy() ||
			!slices.Equal(router.SubnetRoutes(), routes) {
			b.Fatal("via fixture requires a tag-owned online router with approved, announced routes")
		}

		if !slices.Contains(td.State.GetNodePrimaryRoutes(td.Nodes[50].n.ID), routes[0]) ||
			slices.Contains(td.State.GetNodePrimaryRoutes(peer), routes[0]) {
			b.Fatal("via fixture must steer away from a different global primary")
		}
	}

	return peer, routes
}

//nolint:gocyclo // Keep untimed cross-candidate response assertions together.
func checkCapturedMapResponseBenchmark(
	b *testing.B, td *TestData, shape, kind string, peerID types.NodeID,
	routes []netip.Prefix, responses []*tailcfg.MapResponse,
) {
	b.Helper()

	checkCapturedBenchmarkWireSyntax(b)

	if len(responses) != 1 || responses[0] == nil || len(responses[0].PeersRemoved) != 0 {
		b.Fatal("steady-state response fixture must emit one response without removals")
	}

	resp := responses[0]
	peers := resp.Peers

	expected := 99
	if shape == "self" {
		expected = 49
	}

	if shape == "via" {
		expected = 1
	}

	switch kind {
	case "full":
		if resp.Node == nil || resp.Peers == nil || len(resp.Peers) != expected || resp.PacketFilters == nil {
			b.Fatalf("%s full response does not exercise expected self, policy and %d peers", shape, expected)
		}
	case "incremental":
		peers = resp.PeersChanged
		if resp.Node != nil || resp.Peers != nil || len(peers) != 1 || peers[0].ID != peerID.NodeID() || resp.PacketFilters != nil {
			b.Fatalf("%s incremental response must render only its selected peer", shape)
		}
	case "policy":
		peers = resp.PeersChanged
		if resp.Node == nil || resp.Peers != nil || len(peers) != expected || resp.PacketFilters == nil {
			b.Fatal("policy response must render policy and all currently visible peers as deltas")
		}
	default:
		b.Fatalf("unknown captured response kind %q", kind)
	}

	seen := make(map[tailcfg.NodeID]*tailcfg.Node, len(peers))
	for _, peer := range peers {
		if peer.ID == td.Nodes[0].n.ID.NodeID() || seen[peer.ID] != nil {
			b.Fatal("response contains self or duplicate peers")
		}

		if shape == "self" && peer.User != td.Nodes[0].n.View().TailscaleUserID() {
			b.Fatal("autogroup:self response leaked another user's device")
		}

		if shape == "via" && peer.ID != peerID.NodeID() {
			b.Fatal("via-only response exposed an unrelated or non-via peer")
		}

		seen[peer.ID] = peer
	}

	selected := seen[peerID.NodeID()]
	if selected == nil {
		b.Fatal("response omitted the selected peer")
	}

	if len(routes) > 0 {
		allowed := make(map[netip.Prefix]bool, len(selected.AllowedIPs))
		for _, route := range selected.AllowedIPs {
			allowed[route] = true
		}

		primary := make(map[netip.Prefix]bool, len(selected.PrimaryRoutes))
		for _, route := range selected.PrimaryRoutes {
			primary[route] = true
		}

		if len(primary) != len(routes) {
			b.Fatal("response did not retain every exact prepared route")
		}

		for _, route := range routes {
			if !allowed[route] || !primary[route] {
				b.Fatalf("selected peer omitted route %s", route)
			}
		}
	}

	self, ok := td.State.GetNodeByID(td.Nodes[0].n.ID)
	if !ok {
		b.Fatal("viewer missing")
	}

	sameUser, ok := td.State.GetNodeByID(td.Nodes[1].n.ID)
	if !ok {
		b.Fatal("same-user control missing")
	}

	otherUser, ok := td.State.GetNodeByID(td.Nodes[52].n.ID)
	if !ok {
		b.Fatal("other-user control missing")
	}

	if shape == "via" {
		// The viewer is a source, so assert its selected via rule at the
		// receiving router, where recipient-reduced packet rules apply.
		nc := newMultiChannelNodeConn(peerID, td.Batcher.mapper)
		nc.addConnection(&connectionEntry{id: "captured-via-rule", version: 100})

		routerResponses, err := generateMapResponse(nc, td.Batcher.mapper, change.FullUpdate())
		if err != nil {
			b.Fatal(err)
		}

		if len(routerResponses) != 1 || routerResponses[0] == nil || routerResponses[0].PacketFilters == nil {
			b.Fatal("via router must receive its selected packet policy")
		}

		rules := routerResponses[0].PacketFilters["base"]

		destination := routes[0].Addr().Next()
		if !capturedBenchmarkAllows(rules, self.IPs()[0], destination, 443) ||
			capturedBenchmarkAllows(rules, otherUser.IPs()[0], destination, 443) ||
			capturedBenchmarkAllows(rules, self.IPs()[0], destination, 80) {
			b.Fatalf("via rule must permit only its viewer user to reach the selected subnet on TCP/443: viewer=%s other=%s destination=%s rules=%+v", self.IPs()[0], otherUser.IPs()[0], destination, rules)
		}
	} else if resp.PacketFilters != nil {
		rules := resp.PacketFilters["base"]
		if !capturedBenchmarkAllows(rules, sameUser.IPs()[0], self.IPs()[0], 443) {
			b.Fatalf("response policy omitted same-user access: source=%s destination=%s TCP/443 rules=%+v", sameUser.IPs()[0], self.IPs()[0], rules)
		}

		otherAllowed := capturedBenchmarkAllows(rules, otherUser.IPs()[0], self.IPs()[0], 443)
		if otherAllowed != (shape == "ordinary") {
			b.Fatalf("ordinary and autogroup:self policies must differ across the two users: shape=%s source=%s destination=%s TCP/443 allowed=%t rules=%+v", shape, otherUser.IPs()[0], self.IPs()[0], otherAllowed, rules)
		}
	}
}

// These untimed wire assertions accept inclusive ranges, CIDRs, host addresses
// and wildcard entries without depending on either policy model.
func capturedBenchmarkAllows(rules []tailcfg.FilterRule, source, destination netip.Addr, port uint16) bool {
	for _, rule := range rules {
		if len(rule.IPProto) > 0 && !slices.Contains(rule.IPProto, 6) {
			continue
		}

		sourceMatches := false

		for _, encoded := range rule.SrcIPs {
			if capturedBenchmarkContains(encoded, source) {
				sourceMatches = true
				break
			}
		}

		if !sourceMatches {
			continue
		}

		for _, target := range rule.DstPorts {
			if target.Ports.First <= port && port <= target.Ports.Last && capturedBenchmarkContains(target.IP, destination) {
				return true
			}
		}
	}

	return false
}

func capturedBenchmarkContains(encoded string, address netip.Addr) bool {
	if encoded == "*" {
		return true
	}

	if first, last, isRange := strings.Cut(encoded, "-"); isRange {
		from, fromErr := netip.ParseAddr(first)
		to, toErr := netip.ParseAddr(last)

		return fromErr == nil && toErr == nil && address.IsValid() &&
			from.Zone() == "" && to.Zone() == "" && address.Zone() == "" &&
			from.Is4() == to.Is4() && from.Is4() == address.Is4() &&
			from.Compare(address) <= 0 && address.Compare(to) <= 0
	}

	prefix, err := netip.ParsePrefix(encoded)
	if err == nil {
		return prefix.Contains(address)
	}

	parsed, err := netip.ParseAddr(encoded)

	return err == nil && parsed == address
}

// checkCapturedBenchmarkWireSyntax keeps the untimed oracle independent of
// either policy engine, including old range syntax and per-rule TCP matching.
func checkCapturedBenchmarkWireSyntax(b *testing.B) {
	b.Helper()

	for _, tc := range []struct {
		encoded, address string
		want             bool
	}{
		{"100.64.0.1-100.64.0.50", "100.64.0.1", true},
		{"100.64.0.1-100.64.0.50", "100.64.0.50", true},
		{"100.64.0.1-100.64.0.50", "100.64.0.51", false},
		{"fd7a::1-fd7a::32", "fd7a::20", true},
		{"fd7a::1-fd7a::32", "fd7a::33", false},
		{"100.64.0.1-100.64.0.50", "::ffff:100.64.0.2", false},
		{"::ffff:100.64.0.1-::ffff:100.64.0.50", "100.64.0.2", false},
		{"::ffff:100.64.0.1-::ffff:100.64.0.50", "::ffff:100.64.0.2", true},
		{"100.64.0.50-100.64.0.1", "100.64.0.2", false},
		{"100.64.0.1-fd7a::32", "100.64.0.2", false},
		{"100.64.0.1-invalid", "100.64.0.2", false},
	} {
		if got := capturedBenchmarkContains(tc.encoded, netip.MustParseAddr(tc.address)); got != tc.want {
			b.Fatalf("wire oracle membership: %q contains %s = %t, want %t", tc.encoded, tc.address, got, tc.want)
		}
	}

	rules := []tailcfg.FilterRule{
		{SrcIPs: []string{"100.64.0.1-100.64.0.50"}, DstPorts: []tailcfg.NetPortRange{
			{IP: "10.33.0.1-10.33.0.254", Ports: tailcfg.PortRange{First: 443, Last: 444}},
			{IP: "10.34.0.1", Ports: tailcfg.PortRange{First: 80, Last: 80}},
		}},
		{SrcIPs: []string{"100.64.0.51-100.64.0.100"}, IPProto: []int{17}, DstPorts: []tailcfg.NetPortRange{
			{IP: "10.33.0.1-10.33.0.254", Ports: tailcfg.PortRange{First: 80, Last: 80}},
		}},
	}
	for _, tc := range []struct {
		source, destination string
		port                uint16
		want                bool
	}{
		{"100.64.0.2", "10.33.0.42", 443, true},
		{"100.64.0.2", "10.33.0.42", 444, true},
		{"100.64.0.2", "10.33.0.42", 445, false},
		{"100.64.0.2", "10.33.0.42", 80, false},
		{"100.64.0.52", "10.33.0.42", 443, false},
		{"100.64.0.52", "10.33.0.42", 80, false},
	} {
		if got := capturedBenchmarkAllows(rules, netip.MustParseAddr(tc.source), netip.MustParseAddr(tc.destination), tc.port); got != tc.want {
			b.Fatalf("wire oracle TCP association: %s to %s:%d = %t, want %t", tc.source, tc.destination, tc.port, got, tc.want)
		}
	}
}
