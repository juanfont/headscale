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
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/rs/zerolog"
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
		tick:      time.NewTicker(1 * time.Hour), // never fires during bench
		workers:   4,
		workCh:    make(chan work, 4*200),
		nodes:     xsync.NewMap[types.NodeID, *multiChannelNodeConn](),
		connected: xsync.NewMap[types.NodeID, *time.Time](),
		done:      make(chan struct{}),
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
		b.connected.Store(id, nil)
		channels[id] = ch
	}

	b.totalNodes.Store(int64(nodeCount))

	return b, channels
}

// BenchmarkAddToBatch_Broadcast measures the cost of broadcasting a change
// to all nodes via addToBatch (no worker processing, just queuing).
func BenchmarkAddToBatch_Broadcast(b *testing.B) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

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
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

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
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

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
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

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
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

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
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

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
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

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
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

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
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, nodeCount := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("%dnodes", nodeCount), func(b *testing.B) {
			batcher, _ := benchBatcher(nodeCount, 1)

			defer func() {
				close(batcher.done)
				batcher.tick.Stop()
			}()

			// Disconnect 10% of nodes for a realistic mix
			for i := 1; i <= nodeCount; i++ {
				if i%10 == 0 {
					now := time.Now()
					batcher.connected.Store(types.NodeID(i), &now) //nolint:gosec // benchmark
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
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

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
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

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

	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

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

	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

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

	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

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
