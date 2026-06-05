package db

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
)

// TestIPAllocatorRandomExhaustionReturnsError ensures the random allocation
// strategy terminates when its prefix is exhausted. randomNext only ever
// returns in-prefix addresses, so the allocation loop's exhaustion exit must
// not depend on producing an out-of-prefix candidate; otherwise Next() spins
// forever under the allocator mutex, wedging all registration and IP release.
//
// 100.64.0.0/30 has four addresses: .0 (network) and .3 (broadcast) are
// reserved, leaving .1 and .2. After two allocations the pool is exhausted and
// the third Next() must return ErrCouldNotAllocateIP promptly.
func TestIPAllocatorRandomExhaustionReturnsError(t *testing.T) {
	prefix4 := netip.MustParsePrefix("100.64.0.0/30")

	alloc, err := NewIPAllocator(nil, &prefix4, nil, types.IPAllocationStrategyRandom)
	if err != nil {
		t.Fatalf("NewIPAllocator: %v", err)
	}

	for i := range 2 {
		_, _, err := alloc.Next()
		if err != nil {
			t.Fatalf("Next() #%d unexpectedly failed: %v", i+1, err)
		}
	}

	done := make(chan error, 1)

	go func() {
		_, _, err := alloc.Next()
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, ErrCouldNotAllocateIP) {
			t.Fatalf("expected ErrCouldNotAllocateIP on exhausted prefix, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Next() on an exhausted random-strategy prefix did not return " +
			"within 2s; it is spinning forever under the allocator mutex")
	}
}
