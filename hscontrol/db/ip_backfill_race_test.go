package db

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

// TestAllocatorConcurrentNextAndBackfillNoRace exercises the registration path
// (Next) concurrently with the backfill allocation path (allocateNext) on
// the same allocator. Backfill used to read prev4/prev6 in the caller's frame
// without the lock, racing Next's writes; both must now take i.mu. Run with
// -race.
func TestAllocatorConcurrentNextAndBackfillNoRace(t *testing.T) {
	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")

	alloc, err := NewIPAllocator(nil, &p4, &p6, types.IPAllocationStrategySequential)
	require.NoError(t, err)

	const iterations = 2000

	issued := make(chan netip.Addr, 4*iterations)
	errors := make(chan error, 2)

	released := make([]netip.Addr, 0, 2*iterations)

	for range iterations {
		v4, v6, err := alloc.Next()
		require.NoError(t, err)

		released = append(released, *v4, *v6)
	}

	var wg sync.WaitGroup

	wg.Go(func() {
		for range iterations {
			v4, v6, err := alloc.Next()
			if err != nil {
				errors <- err
				return
			}

			issued <- *v4

			issued <- *v6
		}
	})

	wg.Go(func() {
		for range iterations {
			v4, err := alloc.allocateNext(&alloc.prev4, alloc.prefix4)
			if err != nil {
				errors <- err
				return
			}

			v6, err := alloc.allocateNext(&alloc.prev6, alloc.prefix6)
			if err != nil {
				errors <- err
				return
			}

			issued <- *v4

			issued <- *v6
		}
	})
	wg.Go(func() {
		for _, ip := range released {
			alloc.FreeIPs([]netip.Addr{ip})
		}
	})

	wg.Wait()
	close(errors)
	close(issued)

	for err := range errors {
		require.NoError(t, err)
	}

	seen := make(map[netip.Addr]bool)
	for ip := range issued {
		require.False(t, seen[ip], "duplicate address: %s", ip)
		seen[ip] = true
	}

	require.Len(t, seen, 4*iterations)

	for _, ip := range released {
		require.False(
			t,
			seen[ip],
			"sequential allocation wrapped to released address: %s",
			ip,
		)
	}
}
