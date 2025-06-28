package mapper

import (
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/rs/zerolog"
	"tailscale.com/tailcfg"
)

// Simple, reliable benchmark that avoids deadlocks
func BenchmarkSimpleComparison(b *testing.B) {
	// Suppress logging
	originalLevel := zerolog.GlobalLevel()
	defer zerolog.SetGlobalLevel(originalLevel)
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)

	// Much smaller test parameters to avoid timeouts
	nodeCount := 10

	b.Run("Original", func(b *testing.B) {
		factory := func(cfg *types.Config, st *state.State) Batcher {
			m := newMapper(cfg, st)
			return NewBatcherLock(10*time.Millisecond, m)
		}
		benchmarkSimpleImplementation(b, factory, nodeCount)
	})
	
	b.Run("LockFree", func(b *testing.B) {
		factory := func(cfg *types.Config, st *state.State) Batcher {
			m := newMapper(cfg, st)
			return NewLockFreeBatcher(10*time.Millisecond, m)
		}
		benchmarkSimpleImplementation(b, factory, nodeCount)
	})
	
	b.Run("Hybrid", func(b *testing.B) {
		factory := func(cfg *types.Config, st *state.State) Batcher {
			m := newMapper(cfg, st)
			return NewHybridBatcher(10*time.Millisecond, m)
		}
		benchmarkSimpleImplementation(b, factory, nodeCount)
	})
}

// benchmarkSimpleImplementation is the unified implementation for all batcher types
func benchmarkSimpleImplementation(b *testing.B, factory func(*types.Config, *state.State) Batcher, nodeCount int) {
	// Setup ONCE outside the benchmark loop
	st, cfg := createTestStateAndConfig(b)
	defer st.Close()
	
	batcher := factory(cfg, st)
	batcher.Start()
	defer batcher.Close()
	
	// Pre-setup nodes to avoid race conditions
	nodeIDs := make([]types.NodeID, nodeCount)
	channels := make([]chan []byte, nodeCount)
	for j := 0; j < nodeCount; j++ {
		nodeIDs[j] = types.NodeID(j + 1)
		channels[j] = make(chan []byte, 100)
		batcher.AddNode(nodeIDs[j], channels[j], "zstd", tailcfg.CapabilityVersion(100))
	}
	
	// Reset timer after setup
	b.ResetTimer()
	
	// The benchmark loop - this runs b.N times but only measures the operations
	b.RunParallel(func(pb *testing.PB) {
		opCount := 0
		for pb.Next() {
			nodeIdx := opCount % nodeCount
			nodeID := nodeIDs[nodeIdx]
			
			switch opCount % 4 {
			case 0, 1, 2: // 75% reads - safe operation
				batcher.IsConnected(nodeID)
			case 3: // 25% global work - safe operation
				chg := change.Change{DERPChanged: true}
				batcher.AddWork(chg)
			}
			
			opCount++
		}
	})
}