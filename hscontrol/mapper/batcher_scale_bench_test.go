package mapper

// Scale benchmarks for the batcher system.
//
// These benchmarks systematically increase node counts to find scaling limits
// and identify bottlenecks. Organized into tiers:
//
// Tier 1 - O(1) operations: should stay flat regardless of node count
// Tier 2 - O(N) lightweight: batch queuing and processing (no MapResponse generation)
// Tier 3 - O(N) heavier: map building, peer diff, peer tracking
// Tier 4 - Concurrent contention: multi-goroutine access under load
//
// Node count progression: 100, 500, 1000, 2000, 5000, 10000, 20000, 50000

import (
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/rs/zerolog"
	"tailscale.com/tailcfg"
)

// scaleCounts defines the node counts used across all scaling benchmarks.
// Tier 1 (O(1)) tests up to 50k; Tier 2-4 test up to 10k-20k.
var (
	scaleCountsO1     = []int{100, 500, 1000, 2000, 5000, 10000, 20000, 50000}
	scaleCountsLinear = []int{100, 500, 1000, 2000, 5000, 10000}
	scaleCountsHeavy  = []int{100, 500, 1000, 2000, 5000, 10000}
	scaleCountsConc   = []int{100, 500, 1000, 2000, 5000}
)

// ============================================================================
// Tier 1: O(1) Operations — should scale flat
// ============================================================================

// BenchmarkScale_IsConnected tests single-node lookup at increasing map sizes.
func BenchmarkScale_IsConnected(b *testing.B) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, n := range scaleCountsO1 {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			batcher, _ := benchBatcher(n, 1)

			defer func() {
				close(batcher.done)
				batcher.tick.Stop()
			}()

			b.ResetTimer()

			for i := range b.N {
				id := types.NodeID(1 + (i % n)) //nolint:gosec
				_ = batcher.IsConnected(id)
			}
		})
	}
}

// BenchmarkScale_AddToBatch_Targeted tests single-node targeted change at
// increasing map sizes. The map size should not affect per-operation cost.
func BenchmarkScale_AddToBatch_Targeted(b *testing.B) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, n := range scaleCountsO1 {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			batcher, _ := benchBatcher(n, 10)

			defer func() {
				close(batcher.done)
				batcher.tick.Stop()
			}()

			b.ResetTimer()

			for i := range b.N {
				targetID := types.NodeID(1 + (i % n)) //nolint:gosec
				ch := change.Change{
					Reason:     "scale-targeted",
					TargetNode: targetID,
					PeerPatches: []*tailcfg.PeerChange{
						{NodeID: tailcfg.NodeID(targetID)}, //nolint:gosec
					},
				}
				batcher.addToBatch(ch)
				// Drain every 100 ops to avoid unbounded growth
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

// BenchmarkScale_ConnectionChurn tests add/remove connection cycle.
// The map size should not affect per-operation cost for a single node.
func BenchmarkScale_ConnectionChurn(b *testing.B) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, n := range scaleCountsO1 {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			batcher, channels := benchBatcher(n, 10)

			defer func() {
				close(batcher.done)
				batcher.tick.Stop()
			}()

			b.ResetTimer()

			for i := range b.N {
				id := types.NodeID(1 + (i % n)) //nolint:gosec

				mc, ok := batcher.nodes.Load(id)
				if !ok {
					continue
				}

				oldCh := channels[id]
				mc.removeConnectionByChannel(oldCh)

				newCh := make(chan *tailcfg.MapResponse, 10)
				entry := &connectionEntry{
					id:      fmt.Sprintf("sc-%d", i),
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

// ============================================================================
// Tier 2: O(N) Lightweight — batch mechanics without MapResponse generation
// ============================================================================

// BenchmarkScale_AddToBatch_Broadcast tests broadcasting a change to ALL nodes.
// Cost should scale linearly with node count.
func BenchmarkScale_AddToBatch_Broadcast(b *testing.B) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, n := range scaleCountsLinear {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			batcher, _ := benchBatcher(n, 10)

			defer func() {
				close(batcher.done)
				batcher.tick.Stop()
			}()

			ch := change.DERPMap()

			b.ResetTimer()

			for range b.N {
				batcher.addToBatch(ch)
				// Drain to avoid unbounded growth
				batcher.nodes.Range(func(_ types.NodeID, nc *multiChannelNodeConn) bool {
					nc.drainPending()
					return true
				})
			}
		})
	}
}

// BenchmarkScale_AddToBatch_FullUpdate tests FullUpdate broadcast cost.
func BenchmarkScale_AddToBatch_FullUpdate(b *testing.B) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, n := range scaleCountsLinear {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			batcher, _ := benchBatcher(n, 10)

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

// BenchmarkScale_ProcessBatchedChanges tests draining pending changes into work queue.
func BenchmarkScale_ProcessBatchedChanges(b *testing.B) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, n := range scaleCountsLinear {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			batcher, _ := benchBatcher(n, 10)
			batcher.workCh = make(chan work, n*b.N+1)

			defer func() {
				close(batcher.done)
				batcher.tick.Stop()
			}()

			b.ResetTimer()

			for range b.N {
				b.StopTimer()

				for i := 1; i <= n; i++ {
					if nc, ok := batcher.nodes.Load(types.NodeID(i)); ok { //nolint:gosec
						nc.appendPending(change.DERPMap())
					}
				}

				b.StartTimer()
				batcher.processBatchedChanges()
			}
		})
	}
}

// BenchmarkScale_BroadcastToN tests end-to-end: addToBatch + processBatchedChanges.
func BenchmarkScale_BroadcastToN(b *testing.B) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, n := range scaleCountsLinear {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			batcher, _ := benchBatcher(n, 10)
			batcher.workCh = make(chan work, n*b.N+1)

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

// BenchmarkScale_SendToAll tests raw channel send cost to N nodes (no batching).
// This isolates the multiChannelNodeConn.send() cost.
// Uses large buffered channels to avoid goroutine drain overhead.
func BenchmarkScale_SendToAll(b *testing.B) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, n := range scaleCountsLinear {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			// b.N+1 buffer so sends never block
			batcher, _ := benchBatcher(n, b.N+1)

			defer func() {
				close(batcher.done)
				batcher.tick.Stop()
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
// Tier 3: O(N) Heavier — map building, peer diff, peer tracking
// ============================================================================

// BenchmarkScale_ConnectedMap tests building the full connected/disconnected map.
func BenchmarkScale_ConnectedMap(b *testing.B) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, n := range scaleCountsHeavy {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			batcher, _ := benchBatcher(n, 1)

			defer func() {
				close(batcher.done)
				batcher.tick.Stop()
			}()

			// 10% disconnected for realism
			for i := 1; i <= n; i++ {
				if i%10 == 0 {
					now := time.Now()
					batcher.connected.Store(types.NodeID(i), &now) //nolint:gosec
				}
			}

			b.ResetTimer()

			for range b.N {
				_ = batcher.ConnectedMap()
			}
		})
	}
}

// BenchmarkScale_ComputePeerDiff tests peer diff computation at scale.
// Each node tracks N-1 peers, with 10% removed.
func BenchmarkScale_ComputePeerDiff(b *testing.B) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, n := range scaleCountsHeavy {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			mc := newMultiChannelNodeConn(1, nil)

			// Track N peers
			for i := 1; i <= n; i++ {
				mc.lastSentPeers.Store(tailcfg.NodeID(i), struct{}{})
			}

			// Current: 90% present (every 10th missing)
			current := make([]tailcfg.NodeID, 0, n)
			for i := 1; i <= n; i++ {
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

// BenchmarkScale_UpdateSentPeers_Full tests full peer list update.
func BenchmarkScale_UpdateSentPeers_Full(b *testing.B) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, n := range scaleCountsHeavy {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			mc := newMultiChannelNodeConn(1, nil)

			peerIDs := make([]tailcfg.NodeID, n)
			for i := range peerIDs {
				peerIDs[i] = tailcfg.NodeID(i + 1)
			}

			resp := testMapResponseWithPeers(peerIDs...)

			b.ResetTimer()

			for range b.N {
				mc.updateSentPeers(resp)
			}
		})
	}
}

// BenchmarkScale_UpdateSentPeers_Incremental tests incremental peer updates (10% new).
func BenchmarkScale_UpdateSentPeers_Incremental(b *testing.B) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, n := range scaleCountsHeavy {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			mc := newMultiChannelNodeConn(1, nil)

			// Pre-populate
			for i := 1; i <= n; i++ {
				mc.lastSentPeers.Store(tailcfg.NodeID(i), struct{}{})
			}

			addCount := n / 10
			if addCount == 0 {
				addCount = 1
			}

			resp := testMapResponse()

			resp.PeersChanged = make([]*tailcfg.Node, addCount)
			for i := range addCount {
				resp.PeersChanged[i] = &tailcfg.Node{ID: tailcfg.NodeID(n + i + 1)}
			}

			b.ResetTimer()

			for range b.N {
				mc.updateSentPeers(resp)
			}
		})
	}
}

// BenchmarkScale_MultiChannelBroadcast tests sending to N nodes, each with
// ~1.6 connections on average (every 3rd node has 3 connections).
// Uses large buffered channels to avoid goroutine drain overhead.
func BenchmarkScale_MultiChannelBroadcast(b *testing.B) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, n := range scaleCountsHeavy {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			// Use b.N+1 buffer so sends never block
			batcher, _ := benchBatcher(n, b.N+1)

			defer func() {
				close(batcher.done)
				batcher.tick.Stop()
			}()

			// Add extra connections to every 3rd node (also buffered)
			for i := 1; i <= n; i++ {
				if i%3 == 0 {
					if mc, ok := batcher.nodes.Load(types.NodeID(i)); ok { //nolint:gosec
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

// ============================================================================
// Tier 4: Concurrent Contention — multi-goroutine access
// ============================================================================

// BenchmarkScale_ConcurrentAddToBatch tests parallel addToBatch throughput.
func BenchmarkScale_ConcurrentAddToBatch(b *testing.B) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, n := range scaleCountsConc {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			batcher, _ := benchBatcher(n, 10)

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
						time.Sleep(time.Millisecond) //nolint:forbidigo
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

			close(batcher.done)
			<-drainDone

			batcher.done = make(chan struct{})
			batcher.tick.Stop()
		})
	}
}

// BenchmarkScale_ConcurrentSendAndChurn tests the production hot path:
// sending to all nodes while 10% of connections are churning concurrently.
// Uses large buffered channels to avoid goroutine drain overhead.
func BenchmarkScale_ConcurrentSendAndChurn(b *testing.B) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, n := range scaleCountsConc {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			batcher, channels := benchBatcher(n, b.N+1)

			var mu sync.Mutex

			stopChurn := make(chan struct{})

			go func() {
				i := 0

				for {
					select {
					case <-stopChurn:
						return
					default:
						id := types.NodeID(1 + (i % n)) //nolint:gosec
						if i%10 == 0 {
							mc, ok := batcher.nodes.Load(id)
							if ok {
								mu.Lock()
								oldCh := channels[id]
								mu.Unlock()
								mc.removeConnectionByChannel(oldCh)

								newCh := make(chan *tailcfg.MapResponse, b.N+1)
								entry := &connectionEntry{
									id:      fmt.Sprintf("sc-churn-%d", i),
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

			b.StopTimer()
			close(stopChurn)
			close(batcher.done)
			batcher.tick.Stop()
		})
	}
}

// BenchmarkScale_MixedWorkload simulates a realistic production workload:
// - 70% targeted changes (single node updates)
// - 20% DERP map changes (broadcast)
// - 10% full updates (broadcast with full map)
// All while 10% of connections are churning.
func BenchmarkScale_MixedWorkload(b *testing.B) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, n := range scaleCountsConc {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			batcher, channels := benchBatcher(n, 10)
			batcher.workCh = make(chan work, n*100+1)

			var mu sync.Mutex

			stopChurn := make(chan struct{})

			// Background churn on 10% of nodes
			go func() {
				i := 0

				for {
					select {
					case <-stopChurn:
						return
					default:
						id := types.NodeID(1 + (i % n)) //nolint:gosec
						if i%10 == 0 {
							mc, ok := batcher.nodes.Load(id)
							if ok {
								mu.Lock()
								oldCh := channels[id]
								mu.Unlock()
								mc.removeConnectionByChannel(oldCh)

								newCh := make(chan *tailcfg.MapResponse, 10)
								entry := &connectionEntry{
									id:      fmt.Sprintf("mix-churn-%d", i),
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

			// Background batch processor
			stopProc := make(chan struct{})

			go func() {
				for {
					select {
					case <-stopProc:
						return
					default:
						batcher.processBatchedChanges()
						time.Sleep(time.Millisecond) //nolint:forbidigo
					}
				}
			}()

			// Background work channel consumer (simulates workers)
			stopWorkers := make(chan struct{})

			go func() {
				for {
					select {
					case <-batcher.workCh:
					case <-stopWorkers:
						return
					}
				}
			}()

			b.ResetTimer()

			for i := range b.N {
				switch {
				case i%10 < 7: // 70% targeted
					targetID := types.NodeID(1 + (i % n)) //nolint:gosec
					batcher.addToBatch(change.Change{
						Reason:     "mixed-targeted",
						TargetNode: targetID,
						PeerPatches: []*tailcfg.PeerChange{
							{NodeID: tailcfg.NodeID(targetID)}, //nolint:gosec
						},
					})
				case i%10 < 9: // 20% DERP map broadcast
					batcher.addToBatch(change.DERPMap())
				default: // 10% full update
					batcher.addToBatch(change.FullUpdate())
				}
			}

			b.StopTimer()
			close(stopChurn)
			close(stopProc)
			close(stopWorkers)
			close(batcher.done)
			batcher.tick.Stop()
		})
	}
}

// ============================================================================
// Tier 5: DB-dependent — AddNode with real MapResponse generation
// ============================================================================

// BenchmarkScale_AddAllNodes measures the cost of connecting ALL N nodes
// to a batcher backed by a real database. Each AddNode generates an initial
// MapResponse containing all peer data, so cost is O(N) per node, O(N²) total.
func BenchmarkScale_AddAllNodes(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping full pipeline benchmark in short mode")
	}

	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, nodeCount := range []int{10, 50, 100, 200, 500} {
		b.Run(strconv.Itoa(nodeCount), func(b *testing.B) {
			testData, cleanup := setupBatcherWithTestData(b, NewBatcherAndMapper, 1, nodeCount, largeBufferSize)
			defer cleanup()

			batcher := testData.Batcher
			allNodes := testData.Nodes

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
				for i := range allNodes {
					node := &allNodes[i]
					_ = batcher.AddNode(node.n.ID, node.ch, tailcfg.CapabilityVersion(100), nil)
				}

				b.StopTimer()

				for i := range allNodes {
					node := &allNodes[i]
					batcher.RemoveNode(node.n.ID, node.ch)
				}

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

// BenchmarkScale_SingleAddNode measures the cost of adding ONE node to an
// already-populated batcher. This is the real production scenario: a new node
// joins an existing network. The cost should scale with the number of existing
// peers since the initial MapResponse includes all peer data.
func BenchmarkScale_SingleAddNode(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping full pipeline benchmark in short mode")
	}

	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, nodeCount := range []int{10, 50, 100, 200, 500, 1000} {
		b.Run(strconv.Itoa(nodeCount), func(b *testing.B) {
			testData, cleanup := setupBatcherWithTestData(b, NewBatcherAndMapper, 1, nodeCount, largeBufferSize)
			defer cleanup()

			batcher := testData.Batcher
			allNodes := testData.Nodes

			for i := range allNodes {
				allNodes[i].start()
			}

			defer func() {
				for i := range allNodes {
					allNodes[i].cleanup()
				}
			}()

			// Connect all nodes except the last one
			for i := range len(allNodes) - 1 {
				node := &allNodes[i]

				err := batcher.AddNode(node.n.ID, node.ch, tailcfg.CapabilityVersion(100), nil)
				if err != nil {
					b.Fatalf("failed to add node %d: %v", i, err)
				}
			}

			time.Sleep(200 * time.Millisecond) //nolint:forbidigo

			// Benchmark: repeatedly add and remove the last node
			lastNode := &allNodes[len(allNodes)-1]

			b.ResetTimer()

			for range b.N {
				_ = batcher.AddNode(lastNode.n.ID, lastNode.ch, tailcfg.CapabilityVersion(100), nil)

				b.StopTimer()
				batcher.RemoveNode(lastNode.n.ID, lastNode.ch)

				for {
					select {
					case <-lastNode.ch:
					default:
						goto drainDone
					}
				}

			drainDone:
				b.StartTimer()
			}
		})
	}
}

// BenchmarkScale_MapResponse_DERPMap measures MapResponse generation for a
// DERPMap change. This is a lightweight change that doesn't touch peers.
func BenchmarkScale_MapResponse_DERPMap(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping full pipeline benchmark in short mode")
	}

	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, nodeCount := range []int{10, 50, 100, 200, 500} {
		b.Run(strconv.Itoa(nodeCount), func(b *testing.B) {
			testData, cleanup := setupBatcherWithTestData(b, NewBatcherAndMapper, 1, nodeCount, largeBufferSize)
			defer cleanup()

			batcher := testData.Batcher
			allNodes := testData.Nodes

			for i := range allNodes {
				allNodes[i].start()
			}

			defer func() {
				for i := range allNodes {
					allNodes[i].cleanup()
				}
			}()

			for i := range allNodes {
				node := &allNodes[i]

				err := batcher.AddNode(node.n.ID, node.ch, tailcfg.CapabilityVersion(100), nil)
				if err != nil {
					b.Fatalf("failed to add node %d: %v", i, err)
				}
			}

			time.Sleep(200 * time.Millisecond) //nolint:forbidigo

			ch := change.DERPMap()

			b.ResetTimer()

			for i := range b.N {
				nodeIdx := i % len(allNodes)
				_, _ = batcher.MapResponseFromChange(allNodes[nodeIdx].n.ID, ch)
			}
		})
	}
}

// BenchmarkScale_MapResponse_FullUpdate measures MapResponse generation for a
// FullUpdate change. This forces full peer serialization — the primary bottleneck
// for large networks.
func BenchmarkScale_MapResponse_FullUpdate(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping full pipeline benchmark in short mode")
	}

	zerolog.SetGlobalLevel(zerolog.Disabled)
	defer zerolog.SetGlobalLevel(zerolog.DebugLevel)

	for _, nodeCount := range []int{10, 50, 100, 200, 500} {
		b.Run(strconv.Itoa(nodeCount), func(b *testing.B) {
			testData, cleanup := setupBatcherWithTestData(b, NewBatcherAndMapper, 1, nodeCount, largeBufferSize)
			defer cleanup()

			batcher := testData.Batcher
			allNodes := testData.Nodes

			for i := range allNodes {
				allNodes[i].start()
			}

			defer func() {
				for i := range allNodes {
					allNodes[i].cleanup()
				}
			}()

			for i := range allNodes {
				node := &allNodes[i]

				err := batcher.AddNode(node.n.ID, node.ch, tailcfg.CapabilityVersion(100), nil)
				if err != nil {
					b.Fatalf("failed to add node %d: %v", i, err)
				}
			}

			time.Sleep(200 * time.Millisecond) //nolint:forbidigo

			ch := change.FullUpdate()

			b.ResetTimer()

			for i := range b.N {
				nodeIdx := i % len(allNodes)
				_, _ = batcher.MapResponseFromChange(allNodes[nodeIdx].n.ID, ch)
			}
		})
	}
}
