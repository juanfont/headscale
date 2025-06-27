package mapper

import (
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/rs/zerolog"
	"tailscale.com/tailcfg"
)


// Minimal benchmark to demonstrate performance differences
func BenchmarkMinimalComparison(b *testing.B) {
	// Suppress logging
	originalLevel := zerolog.GlobalLevel()
	defer zerolog.SetGlobalLevel(originalLevel)
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)

	nodeCount, goroutines, operations := 100, 20, 2000

	b.Run("Original", func(b *testing.B) {
		batcherFactory := func(cfg *types.Config, st *state.State) Batcher {
			m := newMapper(cfg, st)
			return NewBatcherLock(10*time.Millisecond, m)
		}
		benchmarkBatcherImplementation(b, batcherFactory, nodeCount, goroutines, operations)
	})

	b.Run("LockFree", func(b *testing.B) {
		batcherFactory := func(cfg *types.Config, st *state.State) Batcher {
			m := newMapper(cfg, st)
			return NewLockFreeBatcher(10*time.Millisecond, m)
		}
		benchmarkBatcherImplementation(b, batcherFactory, nodeCount, goroutines, operations)
	})

	b.Run("Hybrid", func(b *testing.B) {
		batcherFactory := func(cfg *types.Config, st *state.State) Batcher {
			m := newMapper(cfg, st)
			return NewHybridBatcher(10*time.Millisecond, m)
		}
		benchmarkBatcherImplementation(b, batcherFactory, nodeCount, goroutines, operations)
	})
}

// Generic benchmark function that works with any batcher implementation
func benchmarkBatcherImplementation(
	b *testing.B,
	batcherFactory func(*types.Config, *state.State) Batcher,
	nodeCount, goroutines, operations int,
) {
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()

		// Create test state (minimal setup)
		st, cfg := createTestStateAndConfig(b)
		batcher := batcherFactory(cfg, st)
		batcher.Start()

		// Create test node IDs
		nodeIDs := make([]types.NodeID, nodeCount)
		for j := 0; j < nodeCount; j++ {
			nodeIDs[j] = types.NodeID(j + 1)
		}

		// Pre-create channels
		channels := make([]chan []byte, nodeCount)
		for j := 0; j < nodeCount; j++ {
			channels[j] = make(chan []byte, 100)
			// Pre-add nodes to batcher
			batcher.AddNode(nodeIDs[j], channels[j], "zstd", tailcfg.CapabilityVersion(100))
		}

		b.StartTimer()

		// Run concurrent operations
		var wg sync.WaitGroup
		var totalOps atomic.Int64
		opsPerGoroutine := operations / goroutines

		start := time.Now()

		for g := 0; g < goroutines; g++ {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()

				for op := 0; op < opsPerGoroutine; op++ {
					nodeIdx := (goroutineID*opsPerGoroutine + op) % nodeCount
					nodeID := nodeIDs[nodeIdx]

					switch op % 10 {
					case 0, 1, 2, 3, 4, 5: // 60% reads
						batcher.IsConnected(nodeID)
					case 6, 7: // 20% AddWork
						chg := change.Change{DERPChanged: true}
						batcher.AddWork(chg)
					case 8, 9: // 20% AddNode (connection updates)
						// Use a unique nodeID to avoid race conditions
						// Each goroutine gets its own set of nodes for updates
						uniqueNodeID := types.NodeID(goroutineID*10000 + op)
						uniqueChannel := make(chan []byte, 10)
						batcher.AddNode(uniqueNodeID, uniqueChannel, "zstd", tailcfg.CapabilityVersion(100))
					}

					totalOps.Add(1)
				}
			}(g)
		}

		wg.Wait()
		elapsed := time.Since(start)

		b.StopTimer()
		batcher.Close()
		st.Close()

		// Report metrics for first iteration only
		if i == 0 {
			opsPerSec := float64(totalOps.Load()) / elapsed.Seconds()
			b.ReportMetric(opsPerSec, "ops/sec")
			b.ReportMetric(elapsed.Seconds()*1000, "ms")
		}
	}
}
func createTestStateAndConfig(b *testing.B) (*state.State, *types.Config) {
	tmpDir := b.TempDir()

	prefixV4 := netip.MustParsePrefix("100.64.0.0/10")
	prefixV6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")

	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:  types.DatabaseSqlite,
			Debug: false,
			Gorm: types.GormConfig{
				Debug:                 false,
				SlowThreshold:         time.Hour,
				SkipErrRecordNotFound: true,
				ParameterizedQueries:  true,
				PrepareStmt:           true,
			},
			Sqlite: types.SqliteConfig{
				Path: tmpDir + "/test.db",
			},
		},
		PrefixV4:     &prefixV4,
		PrefixV6:     &prefixV6,
		IPAllocation: types.IPAllocationStrategySequential,
		BaseDomain:   "headscale.test",
		Policy: types.PolicyConfig{
			Mode: types.PolicyModeFile,
		},
		DERP: types.DERPConfig{
			ServerEnabled: false,
			URLs:          []url.URL{},
		},
		Tuning: types.Tuning{
			BatchChangeDelay: 10 * time.Millisecond,
		},
	}

	st, err := state.NewState(cfg)
	if err != nil {
		b.Fatalf("Failed to create state: %v", err)
	}

	b.Cleanup(func() {
		st.Close()
	})

	return st, cfg
}
