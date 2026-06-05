package db

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

// TestAllocatorConcurrentNextAndBackfillNoRace exercises the registration path
// (Next) concurrently with the backfill allocation path (allocateNext4/6) on
// the same allocator. Backfill used to read prev4/prev6 in the caller's frame
// without the lock, racing Next's writes; both must now take i.mu. Run with
// -race.
func TestAllocatorConcurrentNextAndBackfillNoRace(t *testing.T) {
	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")

	alloc, err := NewIPAllocator(nil, &p4, &p6, types.IPAllocationStrategySequential)
	require.NoError(t, err)

	const iterations = 2000

	var wg sync.WaitGroup

	wg.Go(func() {
		for range iterations {
			_, _, err := alloc.Next()
			if err != nil {
				return
			}
		}
	})

	wg.Go(func() {
		for range iterations {
			_, err := alloc.allocateNext4()
			if err != nil {
				return
			}

			_, err = alloc.allocateNext6()
			if err != nil {
				return
			}
		}
	})

	wg.Wait()
}
